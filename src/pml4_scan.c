#include "pml4_scan.h"
#include "physmem.h"
#include "channels.h"
#include "wire_records.h"
#include "imports.h"

typedef struct _PML4_WATCH_ENTRY
{
    volatile LONG   InUse;
    ULONG64         PhysBase;
    ULONG64         Snapshot[PML4_ENTRY_COUNT];
    HANDLE          OwnerPid;
    PEPROCESS       OwnerProcess;
} PML4_WATCH_ENTRY, *PPML4_WATCH_ENTRY;

static ULONG64 g_Pml4Snapshot[PML4_ENTRY_COUNT];
static ULONG64 g_Pml4PhysBase = 0;
static volatile LONG g_SnapshotTaken = 0;
static volatile LONG g_LastAnomalies = 0;

static KSPIN_LOCK   g_WatchLock;
static PML4_WATCH_ENTRY g_Watched[PML4_MAX_WATCHED];
static volatile LONG g_WatchInit = 0;

static ULONG64 ReadCr3Base(VOID)
{
    return (__readcr3() & ~0xFFFULL);
}

static VOID EnsureWatchInit(VOID)
{
    if (InterlockedCompareExchange(&g_WatchInit, 1, 0) == 0)
    {
        KeInitializeSpinLock(&g_WatchLock);
        RtlZeroMemory(g_Watched, sizeof(g_Watched));
    }
}

static VOID ReportAnomalies(ULONG64 physBase, const ULONG64 *cur, const ULONG64 *expected)
{
    for (ULONG i = 0; i < PML4_ENTRY_COUNT; i++)
    {
        if (cur[i] != expected[i])
        {
            WIRE_PML4_ANOMALY rec;
            rec.Index = i;
            rec.Observed = cur[i];
            rec.Expected = expected[i];
            rec.PhysicalBase = physBase;
            (VOID)ChannelEnqueueRecord(WIRE_REC_PML4_ANOMALY, &rec, sizeof(rec));
            InterlockedIncrement(&g_LastAnomalies);
        }
    }
}

NTSTATUS Pml4InitSnapshot(VOID)
{
    EnsureWatchInit();

    ULONG64 physBase = ReadCr3Base();
    UCHAR page[PAGE_SIZE];

    NTSTATUS s = PhysMemReadRaw(physBase, page, PAGE_SIZE);
    if (!NT_SUCCESS(s)) return s;

    RtlCopyMemory(g_Pml4Snapshot, page, sizeof(g_Pml4Snapshot));
    g_Pml4PhysBase = physBase;
    InterlockedExchange(&g_SnapshotTaken, 1);
    return STATUS_SUCCESS;
}

NTSTATUS Pml4Rescan(VOID)
{
    InterlockedExchange(&g_LastAnomalies, 0);

    if (InterlockedCompareExchange(&g_SnapshotTaken, 0, 0))
    {
        UCHAR page[PAGE_SIZE];
        NTSTATUS s = PhysMemReadRaw(g_Pml4PhysBase, page, PAGE_SIZE);
        if (NT_SUCCESS(s))
        {
            ReportAnomalies(g_Pml4PhysBase, (ULONG64 *)page, g_Pml4Snapshot);
        }
    }

    EnsureWatchInit();

    for (ULONG i = 0; i < PML4_MAX_WATCHED; i++)
    {
        if (!InterlockedCompareExchange(&g_Watched[i].InUse, 0, 0)) continue;

        UCHAR page[PAGE_SIZE];
        if (!NT_SUCCESS(PhysMemReadRaw(g_Watched[i].PhysBase, page, PAGE_SIZE))) continue;

        ReportAnomalies(g_Watched[i].PhysBase, (ULONG64 *)page, g_Watched[i].Snapshot);
    }

    return STATUS_SUCCESS;
}

ULONG Pml4LastAnomalyCount(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_LastAnomalies, 0, 0);
}

NTSTATUS Pml4RegisterGameProcessByPid(HANDLE pid)
{
    EnsureWatchInit();

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);
    ULONG64 cr3 = __readcr3() & ~0xFFFULL;
    KeUnstackDetachProcess(&apc);

    if (cr3 == 0 || cr3 == g_Pml4PhysBase)
    {
        ObDereferenceObject(proc);
        return STATUS_NO_MATCH;
    }

    UCHAR page[PAGE_SIZE];
    s = PhysMemReadRaw(cr3, page, PAGE_SIZE);
    if (!NT_SUCCESS(s))
    {
        ObDereferenceObject(proc);
        return s;
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_WatchLock, &irql);

    LONG slotIdx = -1;
    for (ULONG i = 0; i < PML4_MAX_WATCHED; i++)
    {
        if (g_Watched[i].InUse && g_Watched[i].OwnerPid == pid)
        {
            slotIdx = (LONG)i;
            break;
        }
    }
    if (slotIdx < 0)
    {
        for (ULONG i = 0; i < PML4_MAX_WATCHED; i++)
        {
            if (!g_Watched[i].InUse) { slotIdx = (LONG)i; break; }
        }
    }

    if (slotIdx < 0)
    {
        KeReleaseSpinLock(&g_WatchLock, irql);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PPML4_WATCH_ENTRY slot = &g_Watched[slotIdx];
    if (slot->InUse && slot->OwnerProcess)
    {
        ObDereferenceObject(slot->OwnerProcess);
    }

    slot->PhysBase = cr3;
    slot->OwnerPid = pid;
    slot->OwnerProcess = proc;
    RtlCopyMemory(slot->Snapshot, page, sizeof(slot->Snapshot));
    InterlockedExchange(&slot->InUse, 1);

    KeReleaseSpinLock(&g_WatchLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS Pml4UnregisterGameProcessByPid(HANDLE pid)
{
    EnsureWatchInit();

    KIRQL irql;
    KeAcquireSpinLock(&g_WatchLock, &irql);

    PEPROCESS toDeref = NULL;
    NTSTATUS s = STATUS_NOT_FOUND;
    for (ULONG i = 0; i < PML4_MAX_WATCHED; i++)
    {
        if (g_Watched[i].InUse && g_Watched[i].OwnerPid == pid)
        {
            toDeref = g_Watched[i].OwnerProcess;
            InterlockedExchange(&g_Watched[i].InUse, 0);
            g_Watched[i].OwnerPid = NULL;
            g_Watched[i].OwnerProcess = NULL;
            g_Watched[i].PhysBase = 0;
            s = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&g_WatchLock, irql);
    if (toDeref) ObDereferenceObject(toDeref);
    return s;
}

VOID Pml4ClearWatched(VOID)
{
    EnsureWatchInit();

    KIRQL irql;
    KeAcquireSpinLock(&g_WatchLock, &irql);

    PEPROCESS pending[PML4_MAX_WATCHED] = { 0 };
    ULONG pendingCount = 0;

    for (ULONG i = 0; i < PML4_MAX_WATCHED; i++)
    {
        if (g_Watched[i].InUse)
        {
            if (g_Watched[i].OwnerProcess) pending[pendingCount++] = g_Watched[i].OwnerProcess;
            RtlZeroMemory(&g_Watched[i], sizeof(g_Watched[i]));
        }
    }

    KeReleaseSpinLock(&g_WatchLock, irql);

    for (ULONG i = 0; i < pendingCount; i++) ObDereferenceObject(pending[i]);
}
