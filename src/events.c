#include "events.h"
#include "channels.h"
#include "wire_records.h"

static volatile LONG g_EventsReady = 0;

NTSTATUS EventsInit(VOID)
{
    InterlockedExchange(&g_EventsReady, 1);
    return STATUS_SUCCESS;
}

VOID EventsShutdown(VOID)
{
    InterlockedExchange(&g_EventsReady, 0);
}

NTSTATUS EventsEmitHeartbeat(VOID)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_HEARTBEAT hb;
    hb.BootCookie = CoreBootCookie();
    hb.InitState = (ULONG)InterlockedCompareExchange(&g_Core.InitState, 0, 0);
    hb.Reserved = 0;
    return ChannelEnqueueRecord(WIRE_REC_HEARTBEAT, &hb, sizeof(hb));
}

NTSTATUS EventsReportProcessAttach(HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!CreateInfo) return STATUS_INVALID_PARAMETER;

    WIRE_PROCESS_ATTACH rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.ProcessId = (ULONG64)(ULONG_PTR)ProcessId;
    rec.ParentProcessId = (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId;

    if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer)
    {
        USHORT nb = CreateInfo->ImageFileName->Length;
        if (nb > sizeof(rec.ImagePath)) nb = sizeof(rec.ImagePath);
        rec.ImagePathLen = nb;
        RtlCopyMemory(rec.ImagePath, CreateInfo->ImageFileName->Buffer, nb);
    }
    return ChannelEnqueueRecord(WIRE_REC_PROCESS_ATTACH, &rec, sizeof(rec));
}

NTSTATUS EventsReportProcessExit(HANDLE ProcessId)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    ULONG64 pid = (ULONG64)(ULONG_PTR)ProcessId;
    return ChannelEnqueueRecord(WIRE_REC_PROCESS_EXIT, &pid, sizeof(pid));
}

NTSTATUS EventsReportTamper(ULONG reasonCode, PVOID extra)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_TAMPER t;
    t.Reason = reasonCode;
    t.CpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    t.Observed = (ULONG64)(ULONG_PTR)extra;
    t.Expected = 0;
    return ChannelEnqueueRecord(WIRE_REC_TAMPER, &t, sizeof(t));
}

NTSTATUS EventsReportTeardown(VOID)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    UCHAR z = 0;
    return ChannelEnqueueRecord(WIRE_REC_TEARDOWN, &z, 1);
}

NTSTATUS EventsReportUnbackedExec(ULONG64 address, ULONG64 size, ULONG tag, ULONG flags, const UCHAR *firstBytes, ULONG firstBytesLen)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_UNBACKED_EXEC rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.Address = address;
    rec.SizeInBytes = size;
    rec.PoolTag = tag;
    rec.Flags = flags;
    if (firstBytes && firstBytesLen > 0)
    {
        if (firstBytesLen > sizeof(rec.FirstBytes)) firstBytesLen = sizeof(rec.FirstBytes);
        RtlCopyMemory(rec.FirstBytes, firstBytes, firstBytesLen);
    }
    return ChannelEnqueueRecord(WIRE_REC_UNBACKED_EXEC, &rec, sizeof(rec));
}

NTSTATUS EventsReportInputHijack(const WIRE_INPUT_HIJACK *rec)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!rec) return STATUS_INVALID_PARAMETER;
    return ChannelEnqueueRecord(WIRE_REC_INPUT_HIJACK, rec, sizeof(*rec));
}

NTSTATUS EventsReportPiddbTamper(ULONG64 tablePtr, ULONG expectedCount, ULONG observedCount, ULONG64 expectedFnv, ULONG64 observedFnv)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_PIDDB_TAMPER rec;
    rec.TablePointer = tablePtr;
    rec.ExpectedCount = expectedCount;
    rec.ObservedCount = observedCount;
    rec.ExpectedFnv = expectedFnv;
    rec.ObservedFnv = observedFnv;
    return ChannelEnqueueRecord(WIRE_REC_PIDDB_TAMPER, &rec, sizeof(rec));
}

NTSTATUS EventsReportMmUnloadedTamper(ULONG64 tablePtr, ULONG64 expectedFnv, ULONG64 observedFnv)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_MMUNLOADED_TAMPER rec;
    rec.TablePointer = tablePtr;
    rec.ExpectedFnv = expectedFnv;
    rec.ObservedFnv = observedFnv;
    return ChannelEnqueueRecord(WIRE_REC_MMUNLOADED_TAMPER, &rec, sizeof(rec));
}

NTSTATUS EventsReportSignatureReject(HANDLE processId, ULONG64 imageBase, NTSTATUS ntstatus, const WCHAR *path, USHORT pathBytes)
{
    if (!InterlockedCompareExchange(&g_EventsReady, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_SIG_REJECT rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.ProcessId = (ULONG64)(ULONG_PTR)processId;
    rec.ImageBase = imageBase;
    rec.NtStatus = (ULONG)ntstatus;
    if (path && pathBytes > 0)
    {
        if (pathBytes > sizeof(rec.ImagePath)) pathBytes = sizeof(rec.ImagePath);
        rec.ImagePathLen = pathBytes;
        RtlCopyMemory(rec.ImagePath, path, pathBytes);
    }
    return ChannelEnqueueRecord(WIRE_REC_SIG_REJECT, &rec, sizeof(rec));
}
