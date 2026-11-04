#include "tpm_attest.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"
#include "crypto.h"
#include "secureboot_attest.h"

#define TPM_ST_NO_SESSIONS         0x8001u
#define TPM_CC_READ_PUBLIC         0x00000173u
#define TPM_CC_GET_CAPABILITY      0x0000017Au

#define TPM_CAP_TPM_PROPERTIES     0x00000006u
#define TPM_PT_MANUFACTURER        0x00000105u
#define TPM_PT_VENDOR_STRING_1     0x00000106u
#define TPM_PT_FIRMWARE_VERSION_1  0x0000010Bu
#define TPM_PT_FIRMWARE_VERSION_2  0x0000010Cu

#define TPM_EK_HANDLE_RSA2048      0x81010001u

#define TPM_IOCTL_SUBMIT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS)

static TPM_ATTEST_REPORT g_Report;
static KSPIN_LOCK        g_ReportLock;
static volatile LONG     g_Flag = 0;
static volatile LONG     g_Initialized = 0;
static volatile LONG     g_BaselineReady = 0;
static UCHAR             g_PendingNonce[TPM_ATTEST_NONCE_LEN];
static volatile LONG     g_NoncePresent = 0;

static VOID TaPutBe16(UCHAR **p, USHORT v)
{
    (*p)[0] = (UCHAR)((v >> 8) & 0xFFu);
    (*p)[1] = (UCHAR)(v & 0xFFu);
    *p += 2;
}

static VOID TaPutBe32(UCHAR **p, ULONG v)
{
    (*p)[0] = (UCHAR)((v >> 24) & 0xFFu);
    (*p)[1] = (UCHAR)((v >> 16) & 0xFFu);
    (*p)[2] = (UCHAR)((v >> 8) & 0xFFu);
    (*p)[3] = (UCHAR)(v & 0xFFu);
    *p += 4;
}

static USHORT TaPeekBe16(const UCHAR *p)
{
    return (USHORT)(((ULONG)p[0] << 8) | (ULONG)p[1]);
}

static ULONG TaPeekBe32(const UCHAR *p)
{
    return ((ULONG)p[0] << 24) |
           ((ULONG)p[1] << 16) |
           ((ULONG)p[2] << 8)  |
           (ULONG)p[3];
}

static NTSTATUS TaOpenTpm(HANDLE *outHandle)
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

static NTSTATUS TaSubmit(HANDLE tpm, const UCHAR *cmd, ULONG cmdLen,
                         UCHAR *rsp, ULONG rspCap, ULONG *rspUsed)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    IO_STATUS_BLOCK iosb;
    RtlZeroMemory(&iosb, sizeof(iosb));
    *rspUsed = 0;

    NTSTATUS s = ZwDeviceIoControlFile(
        tpm,
        NULL, NULL, NULL,
        &iosb,
        TPM_IOCTL_SUBMIT,
        (PVOID)cmd, cmdLen,
        rsp, rspCap);

    if (NT_SUCCESS(s)) *rspUsed = (ULONG)iosb.Information;
    return s;
}

static NTSTATUS TaGetTpmProperty(HANDLE tpm, ULONG property, ULONG *outValue)
{
    *outValue = 0;

    UCHAR cmd[22];
    UCHAR *p = cmd;
    TaPutBe16(&p, (USHORT)TPM_ST_NO_SESSIONS);
    TaPutBe32(&p, 22u);
    TaPutBe32(&p, TPM_CC_GET_CAPABILITY);
    TaPutBe32(&p, TPM_CAP_TPM_PROPERTIES);
    TaPutBe32(&p, property);
    TaPutBe32(&p, 1u);

    UCHAR rsp[64];
    ULONG rspUsed = 0;
    NTSTATUS s = TaSubmit(tpm, cmd, sizeof(cmd), rsp, sizeof(rsp), &rspUsed);
    if (!NT_SUCCESS(s)) return s;
    if (rspUsed < 27) return STATUS_DATA_ERROR;

    const UCHAR *q = rsp + 10;
    q += 1;
    q += 4;

    ULONG propCount = TaPeekBe32(q);
    q += 4;
    if (propCount == 0) return STATUS_NOT_FOUND;

    if ((q + 8) > (rsp + rspUsed)) return STATUS_DATA_ERROR;

    ULONG gotProp = TaPeekBe32(q);
    q += 4;
    ULONG gotValue = TaPeekBe32(q);

    if (gotProp != property) return STATUS_NOT_FOUND;
    *outValue = gotValue;
    return STATUS_SUCCESS;
}

static NTSTATUS TaReadEkPublic(HANDLE tpm,
                               UCHAR *outName, ULONG nameCap, USHORT *outNameLen,
                               UCHAR outPublicSha256[32])
{
    *outNameLen = 0;
    RtlZeroMemory(outName, nameCap);
    RtlZeroMemory(outPublicSha256, 32);

    UCHAR cmd[14];
    UCHAR *p = cmd;
    TaPutBe16(&p, (USHORT)TPM_ST_NO_SESSIONS);
    TaPutBe32(&p, 14u);
    TaPutBe32(&p, TPM_CC_READ_PUBLIC);
    TaPutBe32(&p, TPM_EK_HANDLE_RSA2048);

    UCHAR rsp[1024];
    ULONG rspUsed = 0;
    NTSTATUS s = TaSubmit(tpm, cmd, sizeof(cmd), rsp, sizeof(rsp), &rspUsed);
    if (!NT_SUCCESS(s)) return s;
    if (rspUsed < 12) return STATUS_DATA_ERROR;

    const UCHAR *q = rsp + 10;
    ULONG remaining = rspUsed - 10;

    if (remaining < 2) return STATUS_DATA_ERROR;
    USHORT publicSize = TaPeekBe16(q);
    q += 2;
    remaining -= 2;

    if (remaining < (ULONG)publicSize + 2u) return STATUS_DATA_ERROR;

    const UCHAR *publicArea = q;
    q += publicSize;
    remaining -= publicSize;

    (VOID)CryptoSha256(publicArea, publicSize, outPublicSha256);

    USHORT nameSize = TaPeekBe16(q);
    q += 2;
    remaining -= 2;

    if (nameSize == 0 || remaining < (ULONG)nameSize || (ULONG)nameSize > nameCap)
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(outName, q, nameSize);
    *outNameLen = nameSize;
    return STATUS_SUCCESS;
}

static VOID TaVendorStringFromUlong(ULONG v, CHAR out[5])
{
    out[0] = (CHAR)((v >> 24) & 0xFF);
    out[1] = (CHAR)((v >> 16) & 0xFF);
    out[2] = (CHAR)((v >> 8)  & 0xFF);
    out[3] = (CHAR)(v & 0xFF);
    out[4] = 0;
    for (int i = 0; i < 4; i++)
    {
        if (out[i] < 0x20 || out[i] >= 0x7F) out[i] = '.';
    }
}

static VOID TaEmitWireReport(const TPM_ATTEST_REPORT *rep)
{
    WIRE_TPM_ATTEST_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.Manufacturer     = rep->Manufacturer;
    w.FirmwareVersion1 = rep->FirmwareVersion1;
    w.FirmwareVersion2 = rep->FirmwareVersion2;
    w.EkNameLen = rep->EkNameLen;
    RtlCopyMemory(w.EkName,         rep->EkName,         sizeof(w.EkName));
    RtlCopyMemory(w.EkPublicSha256, rep->EkPublicSha256, 32);
    RtlCopyMemory(w.Nonce,          rep->Nonce,          TPM_ATTEST_NONCE_LEN);
    RtlCopyMemory(w.Pcr0Sha256,     rep->Pcr0Sha256,     32);
    RtlCopyMemory(w.Pcr7Sha256,     rep->Pcr7Sha256,     32);
    RtlCopyMemory(w.Pcr14Sha256,    rep->Pcr14Sha256,    32);
    RtlCopyMemory(w.BundleSha256,   rep->BundleSha256,   32);
    RtlCopyMemory(w.VendorString,   rep->VendorString,   sizeof(w.VendorString));

    (VOID)EventsReportTpmAttest(&w);
}

static NTSTATUS TaComputeBundle(TPM_ATTEST_REPORT *rep)
{
    UCHAR pcrsPresent = 0;
    if (!RtlEqualMemory(rep->Pcr0Sha256,  &pcrsPresent, 0))
    {
        for (ULONG i = 0; i < 32; i++)
        {
            if (rep->Pcr7Sha256[i] != 0) { pcrsPresent = 1; break; }
        }
    }

    const BOOLEAN havePcrs = pcrsPresent != 0;
    const BOOLEAN haveNonce = (rep->Flags & TPM_ATTEST_FLAG_NONCE_PRESENT) != 0;
    const BOOLEAN haveEk   = (rep->Flags & TPM_ATTEST_FLAG_EK_NAME_EXTRACTED) != 0;

    if (!havePcrs || !haveNonce || !haveEk) return STATUS_DEVICE_NOT_READY;

    SIZE_T bufLen = TPM_ATTEST_NONCE_LEN + rep->EkNameLen + 32 + 32 + 32 + 32;
    PUCHAR buf = (PUCHAR)CoreAlloc(bufLen, CORE_AC_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    PUCHAR w = buf;
    RtlCopyMemory(w, rep->Nonce, TPM_ATTEST_NONCE_LEN);           w += TPM_ATTEST_NONCE_LEN;
    RtlCopyMemory(w, rep->EkName, rep->EkNameLen);                w += rep->EkNameLen;
    RtlCopyMemory(w, rep->EkPublicSha256, 32);                    w += 32;
    RtlCopyMemory(w, rep->Pcr0Sha256, 32);                        w += 32;
    RtlCopyMemory(w, rep->Pcr7Sha256, 32);                        w += 32;
    RtlCopyMemory(w, rep->Pcr14Sha256, 32);

    NTSTATUS s = CryptoSha256(buf, (ULONG)bufLen, rep->BundleSha256);
    CoreFree(buf, CORE_AC_POOL_TAG);
    if (NT_SUCCESS(s)) rep->Flags |= TPM_ATTEST_FLAG_BUNDLE_READY;
    return s;
}

static NTSTATUS TaCollect(TPM_ATTEST_REPORT *rep, const UCHAR *nonce, BOOLEAN havePendingNonce)
{
    RtlZeroMemory(rep, sizeof(*rep));

    SECUREBOOT_ATTEST_REPORT sb;
    RtlZeroMemory(&sb, sizeof(sb));
    if (NT_SUCCESS(SecureBootAttestCopyReport(&sb)))
    {
        if (sb.Pcr0Valid)  RtlCopyMemory(rep->Pcr0Sha256,  sb.Pcr0Sha256,  32);
        if (sb.Pcr7Valid)  RtlCopyMemory(rep->Pcr7Sha256,  sb.Pcr7Sha256,  32);
        if (sb.Pcr14Valid) RtlCopyMemory(rep->Pcr14Sha256, sb.Pcr14Sha256, 32);
        if (sb.Pcr0Valid || sb.Pcr7Valid || sb.Pcr14Valid) rep->Flags |= TPM_ATTEST_FLAG_PCRS_PRESENT;
    }

    if (havePendingNonce && nonce)
    {
        RtlCopyMemory(rep->Nonce, nonce, TPM_ATTEST_NONCE_LEN);
        rep->Flags |= TPM_ATTEST_FLAG_NONCE_PRESENT;
    }

    HANDLE tpm = NULL;
    NTSTATUS openStatus = TaOpenTpm(&tpm);
    if (!NT_SUCCESS(openStatus) || !tpm)
    {
        rep->State = TPM_ATTEST_STATE_NO_TPM;
        rep->Flags |= TPM_ATTEST_FLAG_SUSPICIOUS;
        return STATUS_SUCCESS;
    }

    rep->Flags |= TPM_ATTEST_FLAG_TPM_PRESENT;

    ULONG manufacturer = 0;
    ULONG vendor1 = 0;
    ULONG fw1 = 0, fw2 = 0;

    NTSTATUS sProps = TaGetTpmProperty(tpm, TPM_PT_MANUFACTURER, &manufacturer);
    if (NT_SUCCESS(sProps))
    {
        rep->Manufacturer = manufacturer;
        rep->Flags |= TPM_ATTEST_FLAG_MANUFACTURER_KNOWN;

        CHAR vstr[5];
        TaVendorStringFromUlong(manufacturer, vstr);
        RtlCopyMemory(rep->VendorString, vstr, 4);
    }

    if (NT_SUCCESS(TaGetTpmProperty(tpm, TPM_PT_VENDOR_STRING_1, &vendor1)))
    {
        CHAR vs[5];
        TaVendorStringFromUlong(vendor1, vs);
        RtlCopyMemory(rep->VendorString + 4, vs, 4);
        rep->Flags |= TPM_ATTEST_FLAG_PROPS_READABLE;
    }

    if (NT_SUCCESS(TaGetTpmProperty(tpm, TPM_PT_FIRMWARE_VERSION_1, &fw1)))
    {
        rep->FirmwareVersion1 = fw1;
        rep->Flags |= TPM_ATTEST_FLAG_PROPS_READABLE;
    }
    if (NT_SUCCESS(TaGetTpmProperty(tpm, TPM_PT_FIRMWARE_VERSION_2, &fw2)))
    {
        rep->FirmwareVersion2 = fw2;
    }

    USHORT nameLen = 0;
    UCHAR ekPubHash[32];
    NTSTATUS sEk = TaReadEkPublic(tpm, rep->EkName, sizeof(rep->EkName), &nameLen, ekPubHash);
    if (NT_SUCCESS(sEk))
    {
        rep->Flags |= TPM_ATTEST_FLAG_EK_READABLE | TPM_ATTEST_FLAG_EK_NAME_EXTRACTED | TPM_ATTEST_FLAG_EK_PUBLIC_HASHED;
        rep->EkNameLen = nameLen;
        RtlCopyMemory(rep->EkPublicSha256, ekPubHash, 32);
    }

    ZwClose(tpm);

    const BOOLEAN ekReady = (rep->Flags & TPM_ATTEST_FLAG_EK_NAME_EXTRACTED) != 0;

    if (!ekReady && (rep->Flags & TPM_ATTEST_FLAG_PROPS_READABLE))
    {
        rep->State = TPM_ATTEST_STATE_PROPS_ONLY;
        rep->Flags |= TPM_ATTEST_FLAG_SUSPICIOUS;
    }
    else if (!ekReady)
    {
        rep->State = TPM_ATTEST_STATE_EK_FAILED;
        rep->Flags |= TPM_ATTEST_FLAG_SUSPICIOUS;
    }
    else
    {
        rep->State = TPM_ATTEST_STATE_EK_READY;

        if (NT_SUCCESS(TaComputeBundle(rep)))
        {
            rep->State = TPM_ATTEST_STATE_BUNDLE_READY;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS TpmAttestInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    RtlZeroMemory(g_PendingNonce, sizeof(g_PendingNonce));
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    InterlockedExchange(&g_NoncePresent, 0);
    return STATUS_SUCCESS;
}

VOID TpmAttestShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    RtlZeroMemory(g_PendingNonce, sizeof(g_PendingNonce));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    InterlockedExchange(&g_NoncePresent, 0);
}

NTSTATUS TpmAttestBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    UCHAR nonce[TPM_ATTEST_NONCE_LEN];
    BOOLEAN haveNonce = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    if (InterlockedCompareExchange(&g_NoncePresent, 0, 0))
    {
        RtlCopyMemory(nonce, g_PendingNonce, TPM_ATTEST_NONCE_LEN);
        haveNonce = TRUE;
    }
    KeReleaseSpinLock(&g_ReportLock, irql);

    TPM_ATTEST_REPORT rep;
    (VOID)TaCollect(&rep, haveNonce ? nonce : NULL, haveNonce);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    TaEmitWireReport(&rep);

    if (rep.Flags & TPM_ATTEST_FLAG_SUSPICIOUS)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_TPM_ATTEST, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

NTSTATUS TpmAttestVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    UCHAR nonce[TPM_ATTEST_NONCE_LEN];
    BOOLEAN haveNonce = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    if (InterlockedCompareExchange(&g_NoncePresent, 0, 0))
    {
        RtlCopyMemory(nonce, g_PendingNonce, TPM_ATTEST_NONCE_LEN);
        haveNonce = TRUE;
    }
    KeReleaseSpinLock(&g_ReportLock, irql);

    TPM_ATTEST_REPORT rep;
    (VOID)TaCollect(&rep, haveNonce ? nonce : NULL, haveNonce);

    UCHAR baselineEkName[TPM_ATTEST_EK_NAME_MAX];
    UCHAR baselineEkHash[32];
    UCHAR baselineBundle[32];
    USHORT baselineEkNameLen = 0;
    ULONG  baselineFlags = 0;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(baselineEkName, g_Report.EkName, TPM_ATTEST_EK_NAME_MAX);
    RtlCopyMemory(baselineEkHash, g_Report.EkPublicSha256, 32);
    RtlCopyMemory(baselineBundle, g_Report.BundleSha256, 32);
    baselineEkNameLen = g_Report.EkNameLen;
    baselineFlags = g_Report.Flags;
    KeReleaseSpinLock(&g_ReportLock, irql);

    BOOLEAN ekDrifted = FALSE;
    if (rep.EkNameLen != baselineEkNameLen ||
        RtlCompareMemory(rep.EkName, baselineEkName, rep.EkNameLen) != rep.EkNameLen ||
        RtlCompareMemory(rep.EkPublicSha256, baselineEkHash, 32) != 32)
    {
        if (baselineEkNameLen > 0)
        {
            rep.Flags |= TPM_ATTEST_FLAG_EK_DRIFTED | TPM_ATTEST_FLAG_SUSPICIOUS;
            ekDrifted = TRUE;
        }
    }

    BOOLEAN bundleDrifted = FALSE;
    if ((rep.Flags & TPM_ATTEST_FLAG_BUNDLE_READY) != 0 &&
        (baselineFlags & TPM_ATTEST_FLAG_BUNDLE_READY) != 0 &&
        RtlCompareMemory(rep.BundleSha256, baselineBundle, 32) != 32)
    {
        rep.Flags |= TPM_ATTEST_FLAG_BUNDLE_DRIFTED;
        bundleDrifted = TRUE;
    }

    const BOOLEAN newSuspicious =
        (rep.Flags & TPM_ATTEST_FLAG_SUSPICIOUS) != 0 &&
        ((baselineFlags & TPM_ATTEST_FLAG_SUSPICIOUS) == 0 || ekDrifted);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (newSuspicious || bundleDrifted)
    {
        TaEmitWireReport(&rep);
        if (newSuspicious)
        {
            (VOID)EventsReportTamper(AC_TAMPER_REASON_TPM_ATTEST, (PVOID)(ULONG_PTR)rep.State);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS TpmAttestPushNonce(const UCHAR *nonce, ULONG nonceLen)
{
    if (!nonce || nonceLen != TPM_ATTEST_NONCE_LEN) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(g_PendingNonce, nonce, TPM_ATTEST_NONCE_LEN);
    KeReleaseSpinLock(&g_ReportLock, irql);
    InterlockedExchange(&g_NoncePresent, 1);
    return STATUS_SUCCESS;
}

ULONG TpmAttestGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID TpmAttestClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS TpmAttestCopyReport(PTPM_ATTEST_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
