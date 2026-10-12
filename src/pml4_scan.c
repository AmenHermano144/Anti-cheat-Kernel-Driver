#include "pml4_scan.h"
#include "physmem.h"
#include "channels.h"
#include "wire_records.h"

static ULONG64 g_Pml4Snapshot[PML4_ENTRY_COUNT];
static ULONG64 g_Pml4PhysBase = 0;
static volatile LONG g_SnapshotTaken = 0;
static volatile LONG g_LastAnomalies = 0;

static ULONG64 ReadCr3Base(VOID)
{
    return (__readcr3() & ~0xFFFULL);
}

NTSTATUS Pml4InitSnapshot(VOID)
{
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
    if (!InterlockedCompareExchange(&g_SnapshotTaken, 0, 0)) return STATUS_SUCCESS;

    UCHAR page[PAGE_SIZE];
    NTSTATUS s = PhysMemReadRaw(g_Pml4PhysBase, page, PAGE_SIZE);
    if (!NT_SUCCESS(s)) return s;

    ULONG64 *cur = (ULONG64 *)page;
    ULONG anomalies = 0;

    for (ULONG i = 0; i < PML4_ENTRY_COUNT; i++)
    {
        if (cur[i] != g_Pml4Snapshot[i])
        {
            WIRE_PML4_ANOMALY rec;
            rec.Index = i;
            rec.Observed = cur[i];
            rec.Expected = g_Pml4Snapshot[i];
            rec.PhysicalBase = g_Pml4PhysBase;
            (VOID)ChannelEnqueueRecord(WIRE_REC_PML4_ANOMALY, &rec, sizeof(rec));
            anomalies++;
        }
    }

    InterlockedExchange(&g_LastAnomalies, (LONG)anomalies);
    return STATUS_SUCCESS;
}

ULONG Pml4LastAnomalyCount(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_LastAnomalies, 0, 0);
}
