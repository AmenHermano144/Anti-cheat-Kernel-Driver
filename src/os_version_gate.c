#include "os_version_gate.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW VersionInformation);

static OS_VERSION_REPORT g_Report;
static KSPIN_LOCK        g_ReportLock;
static volatile LONG     g_Flag = 0;
static volatile LONG     g_Initialized = 0;
static volatile LONG     g_BaselineReady = 0;
static ULONG             g_MinBuildRequired = OSG_DEFAULT_MIN_BUILD;

static BOOLEAN OsgReadRegistryDword(PCWSTR keyPath, PCWSTR valueName, ULONG *outValue)
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

static VOID OsgEmitWireReport(const OS_VERSION_REPORT *rep)
{
    WIRE_OS_VERSION_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.MajorVersion         = rep->MajorVersion;
    w.MinorVersion         = rep->MinorVersion;
    w.BuildNumber          = rep->BuildNumber;
    w.Ubr                  = rep->Ubr;
    w.PlatformId           = rep->PlatformId;
    w.ServicePackMajor     = rep->ServicePackMajor;
    w.ServicePackMinor     = rep->ServicePackMinor;
    w.ProductType          = rep->ProductType;
    w.SuiteMask            = rep->SuiteMask;
    w.MinimumBuildRequired = rep->MinimumBuildRequired;
    RtlCopyMemory(w.CsdVersion, rep->CsdVersion, sizeof(w.CsdVersion));

    (VOID)EventsReportOsVersionReport(&w);
}

static ULONG OsgClassify(const OS_VERSION_REPORT *rep, ULONG *outFlags)
{
    ULONG flags = *outFlags;

    if (!(flags & OSG_FLAG_READABLE))
    {
        *outFlags = flags;
        return OSG_STATE_UNREADABLE;
    }

    if (rep->PlatformId != VER_PLATFORM_WIN32_NT)
    {
        *outFlags = flags;
        return OSG_STATE_WRONG_PLATFORM;
    }

    if (rep->BuildNumber < rep->MinimumBuildRequired)
    {
        flags |= OSG_FLAG_BELOW_MIN_BUILD;
        *outFlags = flags;
        return OSG_STATE_TOO_OLD;
    }

    flags |= OSG_FLAG_MEETS_MIN_BUILD;
    *outFlags = flags;
    return OSG_STATE_MEETS_MIN;
}

static NTSTATUS OsgCollect(OS_VERSION_REPORT *rep)
{
    RtlZeroMemory(rep, sizeof(*rep));
    rep->MinimumBuildRequired = g_MinBuildRequired;

    RTL_OSVERSIONINFOEXW info;
    RtlZeroMemory(&info, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);

    NTSTATUS s = RtlGetVersion((PRTL_OSVERSIONINFOW)&info);
    if (NT_SUCCESS(s))
    {
        rep->Flags |= OSG_FLAG_READABLE;
        rep->MajorVersion     = info.dwMajorVersion;
        rep->MinorVersion     = info.dwMinorVersion;
        rep->BuildNumber      = info.dwBuildNumber;
        rep->PlatformId       = info.dwPlatformId;
        rep->ServicePackMajor = info.wServicePackMajor;
        rep->ServicePackMinor = info.wServicePackMinor;
        rep->ProductType      = info.wProductType;
        rep->SuiteMask        = info.wSuiteMask;

        if (info.dwPlatformId == VER_PLATFORM_WIN32_NT) rep->Flags |= OSG_FLAG_IS_NT;
        if (info.wProductType == VER_NT_WORKSTATION)    rep->Flags |= OSG_FLAG_IS_WORKSTATION;
        if (info.wServicePackMajor != 0 || info.wServicePackMinor != 0) rep->Flags |= OSG_FLAG_SERVICE_PACK_PRESENT;

        ULONG copyChars = (ULONG)(sizeof(rep->CsdVersion) - 1);
        for (ULONG i = 0; i < copyChars && info.szCSDVersion[i] != 0; i++)
        {
            WCHAR wc = info.szCSDVersion[i];
            rep->CsdVersion[i] = (wc >= 0x20 && wc < 0x7F) ? (CHAR)wc : '?';
        }
    }

    ULONG ubr = 0;
    if (OsgReadRegistryDword(
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"UBR",
            &ubr))
    {
        rep->Ubr = ubr;
        rep->Flags |= OSG_FLAG_UBR_READABLE;
    }

    ULONG stateFlags = rep->Flags;
    rep->State = OsgClassify(rep, &stateFlags);
    rep->Flags = stateFlags;

    return STATUS_SUCCESS;
}

NTSTATUS OsVersionGateInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    g_MinBuildRequired = OSG_DEFAULT_MIN_BUILD;
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    return STATUS_SUCCESS;
}

VOID OsVersionGateShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
}

NTSTATUS OsVersionGateBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    OS_VERSION_REPORT rep;
    (VOID)OsgCollect(&rep);

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    OsgEmitWireReport(&rep);

    return STATUS_SUCCESS;
}

NTSTATUS OsVersionGateVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    OS_VERSION_REPORT rep;
    (VOID)OsgCollect(&rep);

    ULONG baselineBuild = 0, baselineUbr = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    baselineBuild = g_Report.BuildNumber;
    baselineUbr   = g_Report.Ubr;
    KeReleaseSpinLock(&g_ReportLock, irql);

    const BOOLEAN drifted =
        (baselineBuild != 0 && rep.BuildNumber != baselineBuild) ||
        (baselineUbr   != 0 && rep.Ubr         != baselineUbr);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (drifted)
    {
        OsgEmitWireReport(&rep);
    }

    return STATUS_SUCCESS;
}

ULONG OsVersionGateGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID OsVersionGateClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS OsVersionGateCopyReport(POS_VERSION_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
