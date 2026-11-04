#include "iommu_require.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"

#define IOMMU_SYS_DMA_PROTECTION_INFO    141

typedef struct _IOMMU_DMA_INFO
{
    BOOLEAN DmaProtectionsAvailable;
    BOOLEAN DmaProtectionsInUse;
} IOMMU_DMA_INFO, *PIOMMU_DMA_INFO;

typedef struct _IOMMU_FW_TBL_INFO
{
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} IOMMU_FW_TBL_INFO, *PIOMMU_FW_TBL_INFO;

static IOMMU_REQUIRE_REPORT g_Report;
static KSPIN_LOCK           g_ReportLock;
static volatile LONG        g_Flag = 0;
static volatile LONG        g_Initialized = 0;
static volatile LONG        g_BaselineReady = 0;

static NTSTATUS IommuReadDmaProtection(BOOLEAN *outAvailable, BOOLEAN *outInUse)
{
    *outAvailable = FALSE;
    *outInUse     = FALSE;

    IOMMU_DMA_INFO info;
    RtlZeroMemory(&info, sizeof(info));
    ULONG ret = 0;

    NTSTATUS s = ZwQuerySystemInformation(
        IOMMU_SYS_DMA_PROTECTION_INFO,
        &info, sizeof(info), &ret);
    if (!NT_SUCCESS(s)) return s;

    *outAvailable = info.DmaProtectionsAvailable;
    *outInUse     = info.DmaProtectionsInUse;
    return STATUS_SUCCESS;
}

static BOOLEAN IommuReadRegistryDword(PCWSTR keyPath, PCWSTR valueName, ULONG *outValue)
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

static BOOLEAN IommuCheckAcpiTable(ULONG tableId)
{
    IOMMU_FW_TBL_INFO query;
    RtlZeroMemory(&query, sizeof(query));
    query.ProviderSignature  = CORE_FW_PROVIDER_ACPI;
    query.Action             = CORE_FW_ACTION_GET;
    query.TableID            = tableId;
    query.TableBufferLength  = 0;

    ULONG ret = 0;
    NTSTATUS s = ZwQuerySystemInformation(
        CORE_SysFirmwareTableInformation,
        &query, sizeof(query), &ret);

    return s == STATUS_BUFFER_TOO_SMALL || NT_SUCCESS(s);
}

static VOID IommuEmitWireReport(const IOMMU_REQUIRE_REPORT *rep)
{
    WIRE_IOMMU_REPORT w;
    RtlZeroMemory(&w, sizeof(w));

    w.Flags = rep->Flags;
    w.State = rep->State;
    w.DmaInfoReadable          = rep->DmaInfoReadable;
    w.DmaProtectionsAvailable  = rep->DmaProtectionsAvailable;
    w.DmaProtectionsInUse      = rep->DmaProtectionsInUse;
    w.RegKdpEnabled            = rep->RegKdpEnabled;
    w.RegBootDmaBlock          = rep->RegBootDmaBlock;
    w.DmarTablePresent         = rep->DmarTablePresent;
    w.IvrsTablePresent         = rep->IvrsTablePresent;
    w.RequiredNotMet           = rep->RequiredNotMet;

    (VOID)EventsReportIommuReport(&w);
}

static ULONG IommuClassify(const IOMMU_REQUIRE_REPORT *rep, ULONG *outFlags)
{
    ULONG flags = *outFlags;

    const BOOLEAN hardwarePresent =
        rep->DmarTablePresent || rep->IvrsTablePresent || rep->DmaProtectionsAvailable;

    if (!hardwarePresent && !rep->DmaInfoReadable && !rep->RegKdpEnabled)
    {
        *outFlags = flags;
        return IOMMU_STATE_UNSUPPORTED;
    }

    if (rep->DmaProtectionsInUse)
    {
        *outFlags = flags;
        return IOMMU_STATE_IN_USE;
    }

    if (rep->RegKdpEnabled && !rep->DmaProtectionsInUse)
    {
        flags |= IOMMU_FLAG_CLAIM_DISAGREEMENT;
    }

    if (hardwarePresent || rep->DmaInfoReadable || rep->RegKdpEnabled)
    {
        *outFlags = flags;
        return IOMMU_STATE_AVAILABLE_OFF;
    }

    *outFlags = flags;
    return IOMMU_STATE_UNKNOWN;
}

static NTSTATUS IommuCollect(IOMMU_REQUIRE_REPORT *rep)
{
    RtlZeroMemory(rep, sizeof(*rep));

    BOOLEAN dmaAvailable = FALSE, dmaInUse = FALSE;
    if (NT_SUCCESS(IommuReadDmaProtection(&dmaAvailable, &dmaInUse)))
    {
        rep->DmaInfoReadable = TRUE;
        rep->Flags |= IOMMU_FLAG_DMA_INFO_READABLE;
        if (dmaAvailable)
        {
            rep->DmaProtectionsAvailable = TRUE;
            rep->Flags |= IOMMU_FLAG_DMA_PROT_AVAILABLE;
        }
        if (dmaInUse)
        {
            rep->DmaProtectionsInUse = TRUE;
            rep->Flags |= IOMMU_FLAG_DMA_PROT_IN_USE;
        }
    }

    ULONG regKdp = 0, regBoot = 0;
    if (IommuReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelDmaProtection",
            L"Enabled",
            &regKdp) && regKdp != 0)
    {
        rep->RegKdpEnabled = TRUE;
        rep->Flags |= IOMMU_FLAG_REG_KDP_ENABLED;
    }

    if (IommuReadRegistryDword(
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity",
            L"AllowBootDMA",
            &regBoot) && regBoot == 0)
    {
        rep->RegBootDmaBlock = TRUE;
        rep->Flags |= IOMMU_FLAG_REG_BOOT_DMA_BLOCK;
    }

    if (IommuCheckAcpiTable('DMAR'))
    {
        rep->DmarTablePresent = TRUE;
        rep->Flags |= IOMMU_FLAG_DMAR_TABLE_PRESENT;
    }
    if (IommuCheckAcpiTable('IVRS'))
    {
        rep->IvrsTablePresent = TRUE;
        rep->Flags |= IOMMU_FLAG_IVRS_TABLE_PRESENT;
    }

    ULONG stateFlags = rep->Flags;
    rep->State = IommuClassify(rep, &stateFlags);
    rep->Flags = stateFlags;

    const BOOLEAN enforcing = (rep->State == IOMMU_STATE_IN_USE);
    if (!enforcing)
    {
        rep->RequiredNotMet = TRUE;
        rep->Flags |= IOMMU_FLAG_REQUIRED_NOT_MET | IOMMU_FLAG_SUSPICIOUS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS IommuRequireInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_ReportLock);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
    return STATUS_SUCCESS;
}

VOID IommuRequireShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlZeroMemory(&g_Report, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, 0);
    InterlockedExchange(&g_BaselineReady, 0);
}

NTSTATUS IommuRequireBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    IOMMU_REQUIRE_REPORT rep;
    (VOID)IommuCollect(&rep);

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedExchange(&g_Flag, (LONG)rep.Flags);
    InterlockedExchange(&g_BaselineReady, 1);

    IommuEmitWireReport(&rep);

    if (rep.Flags & IOMMU_FLAG_SUSPICIOUS)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_IOMMU, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

NTSTATUS IommuRequireVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    IOMMU_REQUIRE_REPORT rep;
    (VOID)IommuCollect(&rep);

    ULONG baselineFlags = 0, baselineState = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    baselineFlags = g_Report.Flags;
    baselineState = g_Report.State;
    KeReleaseSpinLock(&g_ReportLock, irql);

    const BOOLEAN drifted = (rep.State != baselineState);
    if (drifted)
    {
        rep.Flags |= IOMMU_FLAG_STATE_DRIFT | IOMMU_FLAG_SUSPICIOUS;
    }

    const BOOLEAN newSuspicious =
        (rep.Flags & IOMMU_FLAG_SUSPICIOUS) != 0 &&
        ((baselineFlags & IOMMU_FLAG_SUSPICIOUS) == 0 || drifted);

    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(&g_Report, &rep, sizeof(g_Report));
    KeReleaseSpinLock(&g_ReportLock, irql);

    InterlockedOr(&g_Flag, (LONG)rep.Flags);

    if (newSuspicious)
    {
        IommuEmitWireReport(&rep);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_IOMMU, (PVOID)(ULONG_PTR)rep.State);
    }

    return STATUS_SUCCESS;
}

ULONG IommuRequireGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID IommuRequireClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

NTSTATUS IommuRequireCopyReport(PIOMMU_REQUIRE_REPORT outReport)
{
    if (!outReport) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_BaselineReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    KIRQL irql;
    KeAcquireSpinLock(&g_ReportLock, &irql);
    RtlCopyMemory(outReport, &g_Report, sizeof(*outReport));
    KeReleaseSpinLock(&g_ReportLock, irql);
    return STATUS_SUCCESS;
}
