#include "vbs_require.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"
#include "strings.h"

#define VBS_SYS_ISOLATED_UM_INFO     165

#define IUM_BIT_SECURE_KERNEL_RUNNING   0x01
#define IUM_BIT_HVCI_ENABLED            0x02
#define IUM_BIT_HVCI_STRICT_MODE        0x04
#define IUM_BIT_DEBUG_ENABLED           0x08
#define IUM_BIT_FW_PAGE_PROTECTION      0x10
#define IUM_BIT_ENCRYPTION_KEY          0x20

typedef struct _VBS_IUM_INFO
{
    UCHAR Flags;
    UCHAR Spare0;
    UCHAR Spare1[6];
    ULONG64 Spare2;
    ULONG64 Spare3;
} VBS_IUM_INFO, *PVBS_IUM_INFO;

static VBS_REQUIRE_REPORT g_Report;
static KSPIN_LOCK         g_ReportLock;
static volatile LONG      g_Flag = 0;
static volatile LONG      g_Initialized = 0;
static volatile LONG      g_BaselineReady = 0;

static ULONG VbsFnv1a32(const void *data, SIZE_T len)
{
    const UCHAR *p = (const UCHAR *)data;
    ULONG h = 0x811c9dc5u;
    for (SIZE_T i = 0; i < len; i++)
    {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

static BOOLEAN VbsReadRegistryDword(PCWSTR keyPath, PCWSTR valueName, ULONG *outValue)
{
    *outValue = 0;

    UNICODE_STRING kp, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;

    RtlInitUnicodeString(&kp, keyPath);
    InitializeObjectAttributes(&oa, &kp,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS s = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) return FALSE;

    RtlInitUnicodeString(&vn, valueName);

    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG resultLength = 0;
    s = ZwQueryValueKey(key, &vn, KeyValuePartialInformation,
                        buffer, sizeof(buffer), &resultLength);
    ZwClose(key);

    if (!NT_SUCCESS(s)) return FALSE;

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (info->Type != REG_DWORD || info->DataLength < sizeof(ULONG)) return FALSE;

    RtlCopyMemory(outValue, info->Data, sizeof(ULONG));
    return TRUE;
}

static VOID VbsQueryHypervisor(BOOLEAN *outPresent, CHAR outVendor[13])
{
    int info[4] = { 0, 0, 0, 0 };
    outVendor[0] = 0;
    *outPresent = FALSE;

    __cpuid(info, 1);
    if ((info[2] & (1 << 31)) == 0) return;

    *outPresent = TRUE;

    RtlZeroMemory(info, sizeof(info));
    __cpuid(info, 0x40000000);

    RtlCopyMemory(outVendor + 0, &info[1], 4);
    RtlCopyMemory(outVendor + 4, &info[2], 4);
    RtlCopyMemory(outVendor + 8, &info[3], 4);
    outVendor[12] = 0;
}

static BOOLEAN VbsVendorIsMicrosoft(const CHAR *vendor)
{
    if (!vendor || vendor[0] == 0) return FALSE;
    return CoreStrCmpiA(vendor, "Microsoft Hv") == 0;
}

static NTSTATUS VbsReadIumInfo(UCHAR *outFlags)
{
    *outFlags = 0;

    VBS_IUM_INFO info;
    RtlZeroMemory(&info, sizeof(info));
    ULONG ret = 0;

    NTSTATUS s = ZwQuerySystemInformation(
        VBS_SYS_ISOLATED_UM_INFO,
        &info, sizeof(info), &ret);
    if (!NT_SUCCESS(s)) return s;
    if (ret < 1) return STATUS_DATA_ERROR;

    *outFlags = info.Flags;
    return STATUS_SUCCESS;
}

static VOID VbsEmitWireReport(const VBS_REQUIRE_REPORT *rep)
{
    WIRE_VBS_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.IumFirstByte         = rep->IumFirstByte;
    w.HypervisorVendorHash = rep->HypervisorVendorHash;
    w.CpuidHvPresent        = rep->CpuidHvPresent;
    w.HypervisorIsMicrosoft = rep->HypervisorIsMicrosoft;
    w.IumReadable           = rep->IumReadable;
    w.SecureKernelRunning   = rep->SecureKernelRunning;
    w.HvciEnabled           = rep->HvciEnabled;
    w.HvciStrictMode        = rep->HvciStrictMode;
    w.IumDebugEnabled       = rep->IumDebugEnabled;
    w.FwPageProtection      = rep->FwPageProtection;
    w.EncryptionKeyAvailable= rep->EncryptionKeyAvailable;
    w.RegVbsEnabled         = rep->RegVbsEnabled;
    w.RegVbsRequired        = rep->RegVbsRequired;
    w.RegLsaCfgEnabled      = rep->RegLsaCfgEnabled;
    w.RequiredNotMet        = rep->RequiredNotMet;
    RtlCopyMemory(w.HypervisorVendor, rep->HypervisorVendor, sizeof(w.HypervisorVendor));

    (VOID)EventsReportVbsReport(&w);
}

static ULONG VbsClassify(const VBS_REQUIRE_REPORT *rep, ULONG *outFlags)
{
    ULONG flags = *outFlags;

    if (!rep->CpuidHvPresent && !rep->RegVbsEnabled && !rep->IumReadable)
    {
        *outFlags = flags;
        return VBS_STATE_UNSUPPORTED;
    }

    if (rep->RegVbsEnabled && !rep->CpuidHvPresent)
    {
        flags |= VBS_FLAG_HV_HIDDEN_FROM_CPUID | VBS_FLAG_SUSPICIOUS;
    }

    if (rep->RegVbsEnabled != rep->SecureKernelRunning)
    {
        flags |= VBS_FLAG_CLAIM_DISAGREEMENT;
    }

    if (rep->SecureKernelRunning && rep->HvciStrictMode)
    {
        *outFlags = flags;
        return VBS_STATE_STRICT;
    }

    if (rep->SecureKernelRunning)
    {
        *outFlags = flags;
        return VBS_STATE_ENABLED;
    }

    if (rep->CpuidHvPresent || rep->RegVbsEnabled)
    {
        *outFlags = flags;
        return VBS_STATE_AVAILABLE_OFF;
    }

    *outFlags = flags;
    return VBS_STATE_UNKNOWN;
}

static NTSTATUS VbsCollect(VBS_REQUIRE_REPORT *rep)
{
    RtlZeroMemory(rep, sizeof(*rep));

    BOOLEAN hvPresent = FALSE;
    CHAR hvVendor[13] = { 0 };
    VbsQueryHypervisor(&hvPresent, hvVendor);
    if (hvPresent)
    {
        rep->CpuidHvPresent = TRUE;
        rep->Flags |= VBS_FLAG_CPUID_HV_PRESENT;
        RtlCopyMemory(rep->HypervisorVendor, hvVendor, sizeof(hvVendor));
        rep->HypervisorVendorHash = VbsFnv1a32(hvVendor, 12);

        if (VbsVendorIsMicrosoft(hvVendor))
        {
            rep->HypervisorIsMicrosoft = TRUE;
            rep->Flags |= VBS_FLAG_HV_VENDOR_MICROSOFT;
        }
        else
        {
            rep->Flags |= VBS_FLAG_HV_VENDOR_FOREIGN | VBS_FLAG_SUSPICIOUS;
        }
    }

    UCHAR iumFlags = 0;
    if (NT_SUCCESS(VbsReadIumInfo(&iumFlags)))
    {
        rep->IumReadable = TRUE;
        rep->IumFirstByte = iumFlags;
        rep->Flags |= VBS_FLAG_IUM_INFO_READABLE;

        if (iumFlags & IUM_BIT_SECURE_KERNEL_RUNNING) { rep->SecureKernelRunning = TRUE;    rep->Flags |= VBS_FLAG_SECURE_KERNEL_RUNNING; }
        if (iumFlags & IUM_BIT_HVCI_ENABLED)          { rep->HvciEnabled = TRUE;            rep->Flags |= VBS_FLAG_HVCI_RUNNING; }
        if (iumFlags & IUM_BIT_HVCI_STRICT_MODE)      { rep->HvciStrictMode = TRUE;         rep->Flags |= VBS_FLAG_HVCI_STRICT_MODE; }
        if (iumFlags & IUM_BIT_DEBUG_ENABLED)         { rep->IumDebugEnabled = TRUE;        rep->Flags |= VBS_FLAG_IUM_DEBUG_ENABLED | VBS_FLAG_SUSPICIOUS; }
        if (iumFlags & IUM_BIT_FW_PAGE_PROTECTION)    { rep->FwPageProtection = TRUE;       rep->Flags |= VBS_FLAG_FW_PAGE_PROTECTION; }
        if (iumFlags & IUM_BIT_ENCRYPTION_KEY)        { rep->EncryptionKeyAvailable = TRUE; rep->Flags |= VBS_FLAG_ENCRYPTION_KEY_AVAILABLE; }
    }

    ULONG regVbs = 0, regVbsReq = 0, regLsa = 0;
    if (VbsReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            L"EnableVirtualizationBasedSecurity",
            &regVbs) && regVbs != 0)
    {
        rep->RegVbsEnabled = TRUE;
        rep->Flags |= VBS_FLAG_REG_VBS_ENABLED;
    }

    if (VbsReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            L"RequirePlatformSecurityFeatures",
            &regVbsReq) && regVbsReq != 0)
    {
        rep->RegVbsRequired = TRUE;
        rep->Flags |= VBS_FLAG_REG_VBS_REQUIRED;
    }

    if (VbsReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            L"LsaCfgFlags",
            &regLsa) && regLsa != 0)
    {
        rep->RegLsaCfgEnabled = TRUE;
        rep->Flags |= VBS_FLAG_REG_LSA_CFG_ENABLED;
    }

    ULONG stateFlags = rep->Flags;
    rep->State = VbsClassify(rep, &stateFlags);
    rep->Flags = stateFlags;

    const BOOLEAN enforcing = (rep->State == VBS_STATE_ENABLED) || (rep->State == VBS_STATE_STRICT);
    if (!enforcing)
    {
        rep->RequiredNotMet = TRUE;
        rep->Flags |= VBS_FLAG_REQUIRED_NOT_MET | VBS_FLAG_SUSPICIOUS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS VbsRequireInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    return STATUS_SUCCESS;
}

VOID VbsRequireShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
}

NTSTATUS VbsRequireBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    VBS_REQUIRE_REPORT rep;
    (VOID)VbsCollect(&rep);

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    VbsEmitWireReport(&rep);

    if (rep.Flags & VBS_FLAG_SUSPICIOUS)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_VBS, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

NTSTATUS VbsRequireVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    VBS_REQUIRE_REPORT rep;
    (VOID)VbsCollect(&rep);

    ULONG baselineIum = 0, baselineFlags = 0, baselineState = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    baselineIum   = g_Report.IumFirstByte;
    baselineFlags = g_Report.Flags;
    baselineState = g_Report.State;
    KeReleaseSpinLock(&g_ReportLock, irql);

    BOOLEAN drifted = FALSE;
    if (rep.IumReadable && rep.IumFirstByte != baselineIum)
    {
        rep.Flags |= VBS_FLAG_STATE_DRIFT | VBS_FLAG_SUSPICIOUS;
        drifted = TRUE;
    }
    if (rep.State != baselineState)
    {
        rep.Flags |= VBS_FLAG_STATE_DRIFT | VBS_FLAG_SUSPICIOUS;
        drifted = TRUE;
    }

    const BOOLEAN newSuspicious =
        (rep.Flags & VBS_FLAG_SUSPICIOUS) != 0 &&
        ((baselineFlags & VBS_FLAG_SUSPICIOUS) == 0 || drifted);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (newSuspicious)
    {
        VbsEmitWireReport(&rep);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_VBS, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

ULONG VbsRequireGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID VbsRequireClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS VbsRequireCopyReport(PVBS_REQUIRE_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
