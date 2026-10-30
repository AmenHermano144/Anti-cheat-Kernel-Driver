#pragma once

#include "core.h"
#include "wire_records.h"

NTSTATUS EventsInit(VOID);
VOID     EventsShutdown(VOID);

NTSTATUS EventsEmitHeartbeat(VOID);
NTSTATUS EventsReportProcessAttach(HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS EventsReportProcessExit(HANDLE ProcessId);
NTSTATUS EventsReportTamper(ULONG reasonCode, PVOID extra);
NTSTATUS EventsReportTeardown(VOID);

NTSTATUS EventsReportUnbackedExec(ULONG64 address, ULONG64 size, ULONG tag, ULONG flags, const UCHAR *firstBytes, ULONG firstBytesLen);
NTSTATUS EventsReportInputHijack(const WIRE_INPUT_HIJACK *rec);
NTSTATUS EventsReportPiddbTamper(ULONG64 tablePtr, ULONG expectedCount, ULONG observedCount, ULONG64 expectedFnv, ULONG64 observedFnv);
NTSTATUS EventsReportMmUnloadedTamper(ULONG64 tablePtr, ULONG64 expectedFnv, ULONG64 observedFnv);
NTSTATUS EventsReportSignatureReject(HANDLE processId, ULONG64 imageBase, NTSTATUS ntstatus, const WCHAR *path, USHORT pathBytes);
NTSTATUS EventsReportHookAudit(const WIRE_HOOK_AUDIT *rec);
NTSTATUS EventsReportHandleAudit(const WIRE_HANDLE_AUDIT *rec);
NTSTATUS EventsReportOverlay(const WIRE_OVERLAY_DETECT *rec);
NTSTATUS EventsReportDma(const WIRE_DMA_HIT *rec);
