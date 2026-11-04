#include "hvci_require.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"
#include "strings.h"

#define HVCI_SYS_CODEINTEGRITY_INFO       103

#define CI_OPT_ENABLED                    0x0001
#define CI_OPT_TESTSIGN                   0x0002
#define CI_OPT_UMCI_ENABLED               0x0004
#define CI_OPT_DEBUGMODE_ENABLED          0x0080
#define CI_OPT_HVCI_KMCI_ENABLED          0x0400
#define CI_OPT_HVCI_KMCI_AUDITMODE        0x0800
#define CI_OPT_HVCI_KMCI_STRICTMODE       0x1000
#define CI_OPT_WHQL_ENFORCEMENT_ENABLED   0x4000

typedef struct _HVCI_CI_INFO
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} HVCI_CI_INFO, *PHVCI_CI_INFO;

static HVCI_REQUIRE_REPORT g_Report;
static KSPIN_LOCK          g_ReportLock;
static volatile LONG       g_Flag = 0;
static volatile LONG       g_Initialized = 0;
static volatile LONG       g_BaselineReady = 0;

static ULONG HvciFnv1a32(const void *data, SIZE_T len)
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

static NTSTATUS HvciReadCiOptions(ULONG *outOptions)
{
    *outOptions = 0;

    HVCI_CI_INFO info;
    RtlZeroMemory(&info, sizeof(info));
    info.Length = sizeof(info);
    ULONG ret = 0;

    NTSTATUS s = ZwQuerySystemInformation(
        HVCI_SYS_CODEINTEGRITY_INFO,
        &info, sizeof(info), &ret);

    if (!NT_SUCCESS(s)) return s;
    *outOptions = info.CodeIntegrityOptions;
    return STATUS_SUCCESS;
}

static BOOLEAN HvciReadRegistryDword(PCWSTR keyPath, PCWSTR valueName, ULONG *outValue)
{
    *outValue = 0;

    UNICODE_STRING un;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;

    RtlInitUnicodeString(&un, keyPath);
    InitializeObjectAttributes(&oa, &un,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS s = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) return FALSE;

    UNICODE_STRING vn;
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

static VOID HvciQueryHypervisor(BOOLEAN *outPresent, CHAR outVendor[13])
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

static BOOLEAN HvciVendorIsMicrosoft(const CHAR *vendor)
{
    if (!vendor || vendor[0] == 0) return FALSE;
    return CoreStrCmpiA(vendor, "Microsoft Hv") == 0;
}

static VOID HvciEmitWireReport(const HVCI_REQUIRE_REPORT *rep)
{
    WIRE_HVCI_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.CodeIntegrityOptions = rep->CodeIntegrityOptions;
    w.HypervisorVendorHash = rep->HypervisorVendorHash;
    w.CiReadable            = rep->CiReadable;
    w.CiEnabled             = rep->CiEnabled;
    w.HvciKmciEnabled       = rep->HvciKmciEnabled;
    w.HvciStrictMode        = rep->HvciStrictMode;
    w.HvciAuditMode         = rep->HvciAuditMode;
    w.HypervisorPresent     = rep->HypervisorPresent;
    w.HypervisorIsMicrosoft = rep->HypervisorIsMicrosoft;
    w.RegVbsEnabled         = rep->RegVbsEnabled;
    w.RegHvciEnabled        = rep->RegHvciEnabled;
    w.TestSigning           = rep->TestSigning;
    w.DebugMode             = rep->DebugMode;
    w.RequiredNotMet        = rep->RequiredNotMet;
    RtlCopyMemory(w.HypervisorVendor, rep->HypervisorVendor, sizeof(w.HypervisorVendor));

    (VOID)EventsReportHvciReport(&w);
}

static ULONG HvciClassify(const HVCI_REQUIRE_REPORT *rep, ULONG *outFlags)
{
    ULONG flags = *outFlags;

    if (!rep->HypervisorPresent && !rep->RegVbsEnabled && !rep->CiReadable)
    {
        *outFlags = flags;
        return HVCI_STATE_UNSUPPORTED;
    }

    if (rep->TestSigning || rep->DebugMode)
    {
        flags |= HVCI_FLAG_SUSPICIOUS;
        *outFlags = flags;
        return HVCI_STATE_TEST_SIGNING;
    }

    const BOOLEAN kernelClaimsHvci = rep->HvciKmciEnabled;
    const BOOLEAN registryClaimsHvci = rep->RegHvciEnabled;

    if (kernelClaimsHvci != registryClaimsHvci)
    {
        flags |= HVCI_FLAG_CLAIM_DISAGREEMENT;
    }

    if (rep->RegVbsEnabled && !rep->HypervisorPresent)
    {
        flags |= HVCI_FLAG_HV_HIDDEN_FROM_CPUID | HVCI_FLAG_SUSPICIOUS;
    }

    if (kernelClaimsHvci && rep->HvciStrictMode)
    {
        *outFlags = flags;
        return HVCI_STATE_STRICT;
    }

    if (kernelClaimsHvci && rep->HvciAuditMode)
    {
        flags |= HVCI_FLAG_SUSPICIOUS;
        *outFlags = flags;
        return HVCI_STATE_AUDIT_ONLY;
    }

    if (kernelClaimsHvci)
    {
        *outFlags = flags;
        return HVCI_STATE_ENFORCING;
    }

    if (rep->HypervisorPresent || rep->RegVbsEnabled)
    {
        *outFlags = flags;
        return HVCI_STATE_AVAILABLE_OFF;
    }

    *outFlags = flags;
    return HVCI_STATE_UNKNOWN;
}

static NTSTATUS HvciCollect(HVCI_REQUIRE_REPORT *rep)
{
    RtlZeroMemory(rep, sizeof(*rep));

    ULONG ciOptions = 0;
    if (NT_SUCCESS(HvciReadCiOptions(&ciOptions)))
    {
        rep->CiReadable = TRUE;
        rep->CodeIntegrityOptions = ciOptions;
        rep->Flags |= HVCI_FLAG_CI_READABLE;

        if (ciOptions & CI_OPT_ENABLED)              { rep->CiEnabled = TRUE;        rep->Flags |= HVCI_FLAG_CI_ENABLED; }
        if (ciOptions & CI_OPT_TESTSIGN)             { rep->TestSigning = TRUE;      rep->Flags |= HVCI_FLAG_CI_TEST_SIGN; }
        if (ciOptions & CI_OPT_DEBUGMODE_ENABLED)    { rep->DebugMode = TRUE;        rep->Flags |= HVCI_FLAG_CI_DEBUG_MODE; }
        if (ciOptions & CI_OPT_UMCI_ENABLED)         { rep->Flags |= HVCI_FLAG_CI_UMCI_ENABLED; }
        if (ciOptions & CI_OPT_HVCI_KMCI_ENABLED)    { rep->HvciKmciEnabled = TRUE;  rep->Flags |= HVCI_FLAG_HVCI_KMCI_ENABLED; }
        if (ciOptions & CI_OPT_HVCI_KMCI_AUDITMODE)  { rep->HvciAuditMode = TRUE;    rep->Flags |= HVCI_FLAG_HVCI_AUDIT_MODE; }
        if (ciOptions & CI_OPT_HVCI_KMCI_STRICTMODE) { rep->HvciStrictMode = TRUE;   rep->Flags |= HVCI_FLAG_HVCI_STRICT_MODE; }
        if (ciOptions & CI_OPT_WHQL_ENFORCEMENT_ENABLED) { rep->Flags |= HVCI_FLAG_WHQL_ENFORCEMENT; }
    }

    BOOLEAN hvPresent = FALSE;
    CHAR hvVendor[13] = { 0 };
    HvciQueryHypervisor(&hvPresent, hvVendor);
    if (hvPresent)
    {
        rep->HypervisorPresent = TRUE;
        rep->Flags |= HVCI_FLAG_HYPERVISOR_PRESENT;
        RtlCopyMemory(rep->HypervisorVendor, hvVendor, sizeof(hvVendor));
        rep->HypervisorVendorHash = HvciFnv1a32(hvVendor, 12);

        if (HvciVendorIsMicrosoft(hvVendor))
        {
            rep->HypervisorIsMicrosoft = TRUE;
            rep->Flags |= HVCI_FLAG_HV_VENDOR_MICROSOFT;
        }
        else
        {
            rep->Flags |= HVCI_FLAG_HV_VENDOR_FOREIGN | HVCI_FLAG_SUSPICIOUS;
        }
    }

    ULONG regVbs = 0, regHvci = 0;
    if (HvciReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            L"EnableVirtualizationBasedSecurity",
            &regVbs) && regVbs != 0)
    {
        rep->RegVbsEnabled = TRUE;
        rep->Flags |= HVCI_FLAG_REG_VBS_ENABLED;
    }

    if (HvciReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            L"Enabled",
            &regHvci) && regHvci != 0)
    {
        rep->RegHvciEnabled = TRUE;
        rep->Flags |= HVCI_FLAG_REG_HVCI_ENABLED;
    }

    ULONG stateFlags = rep->Flags;
    rep->State = HvciClassify(rep, &stateFlags);
    rep->Flags = stateFlags;

    const BOOLEAN enforcing = (rep->State == HVCI_STATE_ENFORCING) || (rep->State == HVCI_STATE_STRICT);
    if (!enforcing)
    {
        rep->RequiredNotMet = TRUE;
        rep->Flags |= HVCI_FLAG_REQUIRED_NOT_MET | HVCI_FLAG_SUSPICIOUS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HvciRequireInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    return STATUS_SUCCESS;
}

VOID HvciRequireShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
}

NTSTATUS HvciRequireBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    HVCI_REQUIRE_REPORT rep;
    (VOID)HvciCollect(&rep);

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    HvciEmitWireReport(&rep);

    if (rep.Flags & HVCI_FLAG_SUSPICIOUS)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_HVCI, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

NTSTATUS HvciRequireVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    HVCI_REQUIRE_REPORT rep;
    (VOID)HvciCollect(&rep);

    ULONG baselineCi = 0;
    ULONG baselineFlags = 0;
    ULONG baselineState = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    baselineCi    = g_Report.CodeIntegrityOptions;
    baselineFlags = g_Report.Flags;
    baselineState = g_Report.State;
    KeReleaseSpinLock(&g_ReportLock, irql);

    BOOLEAN drifted = FALSE;
    if (rep.CodeIntegrityOptions != baselineCi)
    {
        rep.Flags |= HVCI_FLAG_STATE_DRIFT | HVCI_FLAG_SUSPICIOUS;
        drifted = TRUE;
    }
    if (rep.State != baselineState)
    {
        rep.Flags |= HVCI_FLAG_STATE_DRIFT | HVCI_FLAG_SUSPICIOUS;
        drifted = TRUE;
    }

    const BOOLEAN newSuspicious =
        (rep.Flags & HVCI_FLAG_SUSPICIOUS) != 0 &&
        ((baselineFlags & HVCI_FLAG_SUSPICIOUS) == 0 || drifted);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (newSuspicious)
    {
        HvciEmitWireReport(&rep);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_HVCI, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

ULONG HvciRequireGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID HvciRequireClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS HvciRequireCopyReport(PHVCI_REQUIRE_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
