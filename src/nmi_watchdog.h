#pragma once

#include "core.h"

NTSTATUS NmiWatchdogRegister(VOID);
VOID     NmiWatchdogUnregister(VOID);
VOID     NmiWatchdogRequestCrossCpuSweep(VOID);
