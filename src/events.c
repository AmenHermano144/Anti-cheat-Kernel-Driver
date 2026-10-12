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
