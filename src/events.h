#pragma once

#include "core.h"

NTSTATUS EventsInit(VOID);
VOID     EventsShutdown(VOID);

NTSTATUS EventsEmitHeartbeat(VOID);
NTSTATUS EventsReportProcessAttach(HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS EventsReportProcessExit(HANDLE ProcessId);
NTSTATUS EventsReportTamper(ULONG reasonCode, PVOID extra);
NTSTATUS EventsReportTeardown(VOID);
