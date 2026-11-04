#include "secureboot_attest.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"

#define SB_SYSTEM_SECUREBOOT_INFO_CLASS   0x91u

#define SB_TPM_ST_NO_SESSIONS             0x8001u
#define SB_TPM_CC_PCR_READ                0x0000017Eu
#define SB_TPM_ALG_SHA256                 0x000Bu
#define SB_TPM_PCR_DIGEST_SIZE_SHA256     32u

#define SB_TPM_PCR_FIRMWARE               0u
#define SB_TPM_PCR_SECUREBOOT_POLICY      7u
#define SB_TPM_PCR_BOOT_AUTHORITY         14u

#define SB_TPM_IOCTL_SUBMIT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _SB_SYSTEM_SECUREBOOT_INFO
{
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} SB_SYSTEM_SECUREBOOT_INFO, *PSB_SYSTEM_SECUREBOOT_INFO;
#pragma pack(pop)

static const GUID g_EfiGlobalVariableGuid =
{ 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } };

static SECUREBOOT_ATTEST_REPORT g_Report;
static KSPIN_LOCK               g_ReportLock;
static volatile LONG            g_Flag = 0;
static volatile LONG            g_Initialized = 0;
static volatile LONG            g_BaselineReady = 0;

static VOID SbPutBe16(UCHAR **p, USHORT v)
{
    (*p)[0] = (UCHAR)((v >> 8) & 0xFFu);
    (*p)[1] = (UCHAR)(v & 0xFFu);
    *p += 2;
}

static VOID SbPutBe32(UCHAR **p, ULONG v)
{
    (*p)[0] = (UCHAR)((v >> 24) & 0xFFu);
    (*p)[1] = (UCHAR)((v >> 16) & 0xFFu);
    (*p)[2] = (UCHAR)((v >> 8) & 0xFFu);
    (*p)[3] = (UCHAR)(v & 0xFFu);
    *p += 4;
}

static USHORT SbPeekBe16(const UCHAR *p)
{
    return (USHORT)(((ULONG)p[0] << 8) | (ULONG)p[1]);
}

static ULONG SbPeekBe32(const UCHAR *p)
{
    return ((ULONG)p[0] << 24) |
           ((ULONG)p[1] << 16) |
           ((ULONG)p[2] << 8)  |
           (ULONG)p[3];
}

static BOOLEAN SbBytesAllZero(const UCHAR *bytes, SIZE_T len)
{
    for (SIZE_T i = 0; i < len; i++)
    {
        if (bytes[i] != 0) return FALSE;
    }
    return TRUE;
}

static NTSTATUS SbOpenTpmDevice(HANDLE *outHandle)
{
    *outHandle = NULL;

    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&path, L"\\Device\\TPM");
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS s = ZwCreateFile(
        outHandle,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &oa, &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (!NT_SUCCESS(s))
    {
        RtlInitUnicodeString(&path, L"\\Device\\TCM");
        InitializeObjectAttributes(&oa, &path,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        s = ZwCreateFile(
            outHandle,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            &oa, &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
    }

    return s;
}

static NTSTATUS SbBuildPcrReadCmd(ULONG pcrIndex, UCHAR *cmdOut, ULONG *cmdLen)
{
    if (pcrIndex >= 24 || *cmdLen < 20u)
    {
        *cmdLen = 20u;
        return STATUS_BUFFER_TOO_SMALL;
    }

    UCHAR *p = cmdOut;
    SbPutBe16(&p, (USHORT)SB_TPM_ST_NO_SESSIONS);
    SbPutBe32(&p, 20u);
    SbPutBe32(&p, SB_TPM_CC_PCR_READ);

    SbPutBe32(&p, 1u);
    SbPutBe16(&p, (USHORT)SB_TPM_ALG_SHA256);
    *p++ = 3;

    UCHAR sel[3] = { 0, 0, 0 };
    sel[pcrIndex / 8] = (UCHAR)(1u << (pcrIndex % 8));
    *p++ = sel[0];
    *p++ = sel[1];
    *p++ = sel[2];

    *cmdLen = 20u;
    return STATUS_SUCCESS;
}

static NTSTATUS SbParsePcrRead(const UCHAR *rsp, ULONG rspLen, UCHAR outDigest[SB_TPM_PCR_DIGEST_SIZE_SHA256])
{
    if (!rsp || rspLen < 10) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(outDigest, SB_TPM_PCR_DIGEST_SIZE_SHA256);

    const UCHAR *p = rsp + 10;
    ULONG remaining = rspLen - 10;

    if (remaining < 4) return STATUS_DATA_ERROR;
    p += 4;
    remaining -= 4;

    if (remaining < 4) return STATUS_DATA_ERROR;
    ULONG selCount = SbPeekBe32(p);
    p += 4;
    remaining -= 4;

    for (ULONG i = 0; i < selCount; i++)
    {
        if (remaining < 6) return STATUS_DATA_ERROR;
        p += 6;
        remaining -= 6;
    }

    if (remaining < 4) return STATUS_DATA_ERROR;
    ULONG digCount = SbPeekBe32(p);
    p += 4;
    remaining -= 4;

    if (digCount == 0 || remaining < 2) return STATUS_NOT_FOUND;

    USHORT digSize = SbPeekBe16(p);
    p += 2;
    remaining -= 2;

    if (digSize != SB_TPM_PCR_DIGEST_SIZE_SHA256 || remaining < (ULONG)digSize)
        return STATUS_DATA_ERROR;

    RtlCopyMemory(outDigest, p, SB_TPM_PCR_DIGEST_SIZE_SHA256);
    return STATUS_SUCCESS;
}

static NTSTATUS SbReadPcr(HANDLE device, ULONG pcrIndex, UCHAR outDigest[SB_TPM_PCR_DIGEST_SIZE_SHA256])
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    UCHAR cmd[32];
    ULONG cmdLen = sizeof(cmd);
    NTSTATUS s = SbBuildPcrReadCmd(pcrIndex, cmd, &cmdLen);
    if (!NT_SUCCESS(s)) return s;

    UCHAR rsp[256];
    IO_STATUS_BLOCK iosb;
    RtlZeroMemory(&iosb, sizeof(iosb));

    s = ZwDeviceIoControlFile(
        device,
        NULL, NULL, NULL,
        &iosb,
        SB_TPM_IOCTL_SUBMIT,
        cmd, cmdLen,
        rsp, sizeof(rsp));
    if (!NT_SUCCESS(s)) return s;

    return SbParsePcrRead(rsp, (ULONG)iosb.Information, outDigest);
}

static NTSTATUS SbReadEfiByte(PCWSTR name, UCHAR *outValue)
{
    UNICODE_STRING un;
    RtlInitUnicodeString(&un, name);

    *outValue = 0;
    ULONG size = sizeof(UCHAR);

    NTSTATUS s = ExGetFirmwareEnvironmentVariable(
        &un,
        (LPGUID)&g_EfiGlobalVariableGuid,
        outValue,
        &size,
        NULL);

    if (!NT_SUCCESS(s)) return s;
    if (size != sizeof(UCHAR)) return STATUS_DATA_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS SbReadSysinfo(BOOLEAN *outEnabled, BOOLEAN *outCapable)
{
    *outEnabled = FALSE;
    *outCapable = FALSE;

    SB_SYSTEM_SECUREBOOT_INFO info;
    RtlZeroMemory(&info, sizeof(info));
    ULONG ret = 0;

    NTSTATUS s = ZwQuerySystemInformation(
        SB_SYSTEM_SECUREBOOT_INFO_CLASS,
        &info, sizeof(info), &ret);

    if (!NT_SUCCESS(s)) return s;
    *outEnabled = info.SecureBootEnabled;
    *outCapable = info.SecureBootCapable;
    return STATUS_SUCCESS;
}

static BOOLEAN SbReadRegistryEnabled(VOID)
{
    UNICODE_STRING keyPath;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;

    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS s = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) return FALSE;

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"UEFISecureBootEnabled");

    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG resultLength = 0;
    s = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                        buffer, sizeof(buffer), &resultLength);
    ZwClose(key);

    if (!NT_SUCCESS(s)) return FALSE;

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (info->Type != REG_DWORD || info->DataLength < sizeof(ULONG)) return FALSE;

    ULONG value = 0;
    RtlCopyMemory(&value, info->Data, sizeof(ULONG));
    return value != 0;
}

static VOID SbEmitWireReport(const SECUREBOOT_ATTEST_REPORT *rep)
{
    WIRE_SECUREBOOT_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.EfiReadable     = rep->EfiReadable;
    w.EfiEnabled      = rep->EfiEnabled;
    w.SetupMode       = rep->SetupMode;
    w.SysinfoReadable = rep->SysinfoReadable;
    w.SysinfoEnabled  = rep->SysinfoEnabled;
    w.SysinfoCapable  = rep->SysinfoCapable;
    w.RegistryEnabled = rep->RegistryEnabled;
    w.TpmPresent      = rep->TpmPresent;
    w.Pcr0Valid       = rep->Pcr0Valid;
    w.Pcr7Valid       = rep->Pcr7Valid;
    w.Pcr14Valid      = rep->Pcr14Valid;
    w.Pcr7AllZero     = rep->Pcr7AllZero;
    w.Pcr7Drift       = rep->Pcr7Drift;

    RtlCopyMemory(w.Pcr0Sha256,   rep->Pcr0Sha256,   32);
    RtlCopyMemory(w.Pcr7Sha256,   rep->Pcr7Sha256,   32);
    RtlCopyMemory(w.Pcr14Sha256,  rep->Pcr14Sha256,  32);
    RtlCopyMemory(w.Pcr7Baseline, rep->Pcr7Baseline, 32);

    (VOID)EventsReportSecureBootReport(&w);
}

static ULONG SbClassify(const SECUREBOOT_ATTEST_REPORT *rep, ULONG *outFlags)
{
    ULONG flags = *outFlags;

    const BOOLEAN efiSaysOn     = rep->EfiReadable && rep->EfiEnabled;
    const BOOLEAN sysinfoSaysOn = rep->SysinfoReadable && rep->SysinfoEnabled;
    const BOOLEAN regSaysOn     = rep->RegistryEnabled;
    const BOOLEAN anySaysOn     = efiSaysOn || sysinfoSaysOn || regSaysOn;

    BOOLEAN anyOn = FALSE, anyOff = FALSE;
    if (rep->EfiReadable)
    {
        if (rep->EfiEnabled) anyOn = TRUE; else anyOff = TRUE;
    }
    if (rep->SysinfoReadable)
    {
        if (rep->SysinfoEnabled) anyOn = TRUE; else anyOff = TRUE;
    }
    if (anyOn && anyOff) flags |= SB_FLAG_CLAIM_DISAGREEMENT;

    if (!rep->EfiReadable && !rep->SysinfoReadable && !rep->Pcr7Valid)
    {
        *outFlags = flags;
        return SB_STATE_UNSUPPORTED;
    }

    if (anySaysOn && !rep->TpmPresent)
    {
        flags |= SB_FLAG_OS_CLAIMS_NO_HARDWARE | SB_FLAG_SUSPICIOUS;
        *outFlags = flags;
        return SB_STATE_PCR_MISMATCH;
    }

    if (anySaysOn && rep->Pcr7Valid && rep->Pcr7AllZero)
    {
        flags |= SB_FLAG_SUSPICIOUS;
        *outFlags = flags;
        return SB_STATE_PCR_MISMATCH;
    }

    if (anySaysOn && rep->Pcr7Valid && !rep->Pcr7AllZero && !rep->SetupMode)
    {
        *outFlags = flags;
        return SB_STATE_ENABLED;
    }

    if (!anySaysOn && !rep->SetupMode && (rep->EfiReadable || rep->SysinfoReadable))
    {
        *outFlags = flags;
        return SB_STATE_CONFIGURED;
    }

    if (rep->SysinfoCapable || rep->EfiReadable)
    {
        *outFlags = flags;
        return anySaysOn ? SB_STATE_ENABLED : SB_STATE_CAPABLE_DISABLED;
    }

    *outFlags = flags;
    return SB_STATE_UNKNOWN;
}

static NTSTATUS SbCollect(SECUREBOOT_ATTEST_REPORT *rep, BOOLEAN captureBaseline)
{
    RtlZeroMemory(rep, sizeof(*rep));
    rep->State = SB_STATE_UNKNOWN;

    UCHAR efiSb = 0, efiSetup = 0;
    if (NT_SUCCESS(SbReadEfiByte(L"SecureBoot", &efiSb)))
    {
        rep->EfiReadable = TRUE;
        rep->EfiEnabled  = (efiSb == 1);
        rep->Flags |= SB_FLAG_EFI_READABLE;
        if (rep->EfiEnabled) rep->Flags |= SB_FLAG_EFI_ENABLED;
    }
    if (NT_SUCCESS(SbReadEfiByte(L"SetupMode", &efiSetup)))
    {
        rep->SetupMode = (efiSetup == 1);
        if (rep->SetupMode) rep->Flags |= SB_FLAG_EFI_SETUP_MODE;
    }

    BOOLEAN sysEn = FALSE, sysCap = FALSE;
    if (NT_SUCCESS(SbReadSysinfo(&sysEn, &sysCap)))
    {
        rep->SysinfoReadable = TRUE;
        rep->SysinfoEnabled  = sysEn;
        rep->SysinfoCapable  = sysCap;
        rep->Flags |= SB_FLAG_SYSINFO_READABLE;
        if (sysEn)  rep->Flags |= SB_FLAG_SYSINFO_ENABLED;
        if (sysCap) rep->Flags |= SB_FLAG_SYSINFO_CAPABLE;
    }

    if (SbReadRegistryEnabled())
    {
        rep->RegistryEnabled = TRUE;
        rep->Flags |= SB_FLAG_REGISTRY_ENABLED;
    }

    HANDLE tpm = NULL;
    NTSTATUS tpmStatus = SbOpenTpmDevice(&tpm);
    if (NT_SUCCESS(tpmStatus) && tpm)
    {
        rep->TpmPresent = TRUE;
        rep->Flags |= SB_FLAG_TPM_PRESENT;

        UCHAR digest[32];

        if (NT_SUCCESS(SbReadPcr(tpm, SB_TPM_PCR_FIRMWARE, digest)))
        {
            rep->Pcr0Valid = TRUE;
            rep->Flags |= SB_FLAG_PCR0_VALID;
            RtlCopyMemory(rep->Pcr0Sha256, digest, 32);
        }

        if (NT_SUCCESS(SbReadPcr(tpm, SB_TPM_PCR_SECUREBOOT_POLICY, digest)))
        {
            rep->Pcr7Valid = TRUE;
            rep->Flags |= SB_FLAG_PCR7_VALID;
            RtlCopyMemory(rep->Pcr7Sha256, digest, 32);
            if (SbBytesAllZero(digest, 32))
            {
                rep->Pcr7AllZero = TRUE;
                rep->Flags |= SB_FLAG_PCR7_ALL_ZERO;
            }
        }

        if (NT_SUCCESS(SbReadPcr(tpm, SB_TPM_PCR_BOOT_AUTHORITY, digest)))
        {
            rep->Pcr14Valid = TRUE;
            rep->Flags |= SB_FLAG_PCR14_VALID;
            RtlCopyMemory(rep->Pcr14Sha256, digest, 32);
            if (SbBytesAllZero(digest, 32))
            {
                rep->Flags |= SB_FLAG_BOOT_AUTHORITY_ZERO;
            }
        }

        ZwClose(tpm);
    }

    if (captureBaseline && rep->Pcr7Valid)
    {
        RtlCopyMemory(rep->Pcr7Baseline, rep->Pcr7Sha256, 32);
    }

    ULONG stateFlags = rep->Flags;
    rep->State = SbClassify(rep, &stateFlags);
    rep->Flags = stateFlags;

    return STATUS_SUCCESS;
}

NTSTATUS SecureBootAttestInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    return STATUS_SUCCESS;
}

VOID SecureBootAttestShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
}

NTSTATUS SecureBootAttestBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    SECUREBOOT_ATTEST_REPORT rep;
    NTSTATUS s = SbCollect(&rep, TRUE);
    if (!NT_SUCCESS(s)) return s;

    if (rep.Flags & SB_FLAG_SUSPICIOUS)
    {
        rep.Flags |= SB_FLAG_SUSPICIOUS;
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    SbEmitWireReport(&rep);

    if (rep.Flags & SB_FLAG_SUSPICIOUS)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_SECUREBOOT, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

NTSTATUS SecureBootAttestVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    SECUREBOOT_ATTEST_REPORT rep;
    NTSTATUS s = SbCollect(&rep, FALSE);
    if (!NT_SUCCESS(s)) return s;

    UCHAR baseline[32];
    ULONG baselineFlags;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(baseline, g_Report.Pcr7Baseline, 32);
    baselineFlags = g_Report.Flags;
    KeReleaseSpinLock(&g_ReportLock, irql);

    RtlCopyMemory(rep.Pcr7Baseline, baseline, 32);

    const BOOLEAN hadBaseline = !SbBytesAllZero(baseline, 32);
    BOOLEAN pcr7Drifted = FALSE;

    if (hadBaseline && rep.Pcr7Valid)
    {
        if (RtlCompareMemory(rep.Pcr7Sha256, baseline, 32) != 32)
        {
            pcr7Drifted = TRUE;
            rep.Pcr7Drift = TRUE;
            rep.Flags |= SB_FLAG_PCR7_DRIFT | SB_FLAG_SUSPICIOUS;
        }
    }

    const BOOLEAN newSuspicious =
        (rep.Flags & SB_FLAG_SUSPICIOUS) != 0 &&
        ((baselineFlags & SB_FLAG_SUSPICIOUS) == 0 || pcr7Drifted);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (newSuspicious)
    {
        SbEmitWireReport(&rep);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_SECUREBOOT, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

ULONG SecureBootAttestGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID SecureBootAttestClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS SecureBootAttestCopyReport(PSECUREBOOT_ATTEST_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
