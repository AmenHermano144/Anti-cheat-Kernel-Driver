#include "exec_region_scan.h"
#include "imports.h"
#include "events.h"
#include "kldr.h"
#include "strings.h"

#define EXEC_SCAN_MIN_SIZE          0x100
#define EXEC_SCAN_MAX_HITS_PER_PASS 32
#define EXEC_SCAN_BASELINE_CAP      1024

typedef struct _EXEC_SCAN_HIT_SIG
{
    ULONG64 Address;
    ULONG64 Size;
    ULONG   Tag;
} EXEC_SCAN_HIT_SIG, *PEXEC_SCAN_HIT_SIG;

static PEXEC_SCAN_HIT_SIG g_Baseline = NULL;
static volatile LONG g_BaselineCount = 0;
static volatile LONG g_Initialized = 0;

static BOOLEAN TagLooksSuspicious(ULONG tag)
{
    const UCHAR *b = (const UCHAR *)&tag;
    for (ULONG i = 0; i < 4; i++)
    {
        UCHAR c = b[i];
        if (c == 0) continue;
        if (c < 0x20 || c > 0x7E) return TRUE;
    }
    return FALSE;
}

static BOOLEAN BaselineContains(ULONG64 addr, ULONG64 size, ULONG tag)
{
    if (!g_Baseline) return FALSE;
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    for (LONG i = 0; i < n; i++)
    {
        if (g_Baseline[i].Address == addr &&
            g_Baseline[i].Size == size &&
            g_Baseline[i].Tag == tag) return TRUE;
    }
    return FALSE;
}

static NTSTATUS EnumBigPool(PCORE_SYSTEM_BIG_POOL_INFORMATION *outInfo, PULONG outAllocSize)
{
    *outInfo = NULL;
    *outAllocSize = 0;

    ULONG needed = 0;
    NTSTATUS s = ZwQuerySystemInformation(CORE_SysBigPoolInformation, NULL, 0, &needed);
    if (s != STATUS_INFO_LENGTH_MISMATCH || needed == 0) return s;

    ULONG allocSize = needed + 0x4000;
    PVOID buf = CoreAlloc(allocSize, CORE_AC_POOL_TAG_SCAN);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG got = 0;
    s = ZwQuerySystemInformation(CORE_SysBigPoolInformation, buf, allocSize, &got);
    if (!NT_SUCCESS(s))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return s;
    }

    *outInfo = (PCORE_SYSTEM_BIG_POOL_INFORMATION)buf;
    *outAllocSize = allocSize;
    return STATUS_SUCCESS;
}

static VOID WalkAndReport(PCORE_SYSTEM_BIG_POOL_INFORMATION info, BOOLEAN emitEvents, PEXEC_SCAN_HIT_SIG baseline, PLONG baselineCount)
{
    ULONG emitted = 0;
    for (ULONG i = 0; i < info->Count; i++)
    {
        PCORE_SYSTEM_BIG_POOL_ENTRY e = &info->AllocatedInfo[i];
        if (!(e->NonPagedBit & 1)) continue;

        ULONG_PTR addr = (ULONG_PTR)e->VirtualAddress & ~(ULONG_PTR)1;
        if (addr == 0) continue;

        ULONG_PTR size = e->SizeInBytes;
        if (size < EXEC_SCAN_MIN_SIZE) continue;

        if (KldrAddressBelongsToKnownModule((PVOID)addr)) continue;

        if (baseline && baselineCount && *baselineCount < EXEC_SCAN_BASELINE_CAP)
        {
            baseline[*baselineCount].Address = (ULONG64)addr;
            baseline[*baselineCount].Size = (ULONG64)size;
            baseline[*baselineCount].Tag = e->TagULong;
            (*baselineCount)++;
            continue;
        }

        if (!emitEvents) continue;
        if (BaselineContains((ULONG64)addr, (ULONG64)size, e->TagULong)) continue;
        if (emitted >= EXEC_SCAN_MAX_HITS_PER_PASS) continue;

        UCHAR firstBytes[64] = { 0 };
        ULONG firstLen = 0;
        if (MmIsAddressValid((PVOID)addr))
        {
            __try
            {
                SIZE_T copy = (size < sizeof(firstBytes)) ? (SIZE_T)size : sizeof(firstBytes);
                RtlCopyMemory(firstBytes, (PVOID)addr, copy);
                firstLen = (ULONG)copy;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                firstLen = 0;
            }
        }

        ULONG flags = 0;
        if (TagLooksSuspicious(e->TagULong)) flags |= 0x1;

        (VOID)EventsReportUnbackedExec((ULONG64)addr, (ULONG64)size, e->TagULong, flags,
                                        firstBytes, firstLen);
        emitted++;
    }
}

NTSTATUS ExecRegionScanInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    g_Baseline = (PEXEC_SCAN_HIT_SIG)CoreAlloc(sizeof(EXEC_SCAN_HIT_SIG) * EXEC_SCAN_BASELINE_CAP,
                                               CORE_AC_POOL_TAG_SCAN);
    if (!g_Baseline)
    {
        InterlockedExchange(&g_Initialized, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_Baseline, sizeof(EXEC_SCAN_HIT_SIG) * EXEC_SCAN_BASELINE_CAP);
    InterlockedExchange(&g_BaselineCount, 0);
    return STATUS_SUCCESS;
}

VOID ExecRegionScanShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);

    if (g_Baseline)
    {
        CoreFree(g_Baseline, CORE_AC_POOL_TAG_SCAN);
        g_Baseline = NULL;
    }
    InterlockedExchange(&g_BaselineCount, 0);
}

NTSTATUS ExecRegionScanSnapshot(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    PCORE_SYSTEM_BIG_POOL_INFORMATION info = NULL;
    ULONG allocSize = 0;
    NTSTATUS s = EnumBigPool(&info, &allocSize);
    if (!NT_SUCCESS(s)) return s;

    LONG localCount = 0;
    WalkAndReport(info, FALSE, g_Baseline, &localCount);
    InterlockedExchange(&g_BaselineCount, localCount);

    CoreFree(info, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

NTSTATUS ExecRegionScanDiff(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    PCORE_SYSTEM_BIG_POOL_INFORMATION info = NULL;
    ULONG allocSize = 0;
    NTSTATUS s = EnumBigPool(&info, &allocSize);
    if (!NT_SUCCESS(s)) return s;

    WalkAndReport(info, TRUE, NULL, NULL);

    CoreFree(info, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}
