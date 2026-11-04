#pragma once

#include "core.h"

NTSTATUS MousePollingInit(VOID);
VOID     MousePollingShutdown(VOID);

NTSTATUS MousePollingDiscoverDevices(VOID);
NTSTATUS MousePollingStart(VOID);
VOID     MousePollingStop(VOID);

NTSTATUS MousePollingVerify(VOID);
