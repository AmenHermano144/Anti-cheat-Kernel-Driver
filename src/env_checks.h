#pragma once

#include "core.h"

NTSTATUS EnvRunBootGates(VOID);

BOOLEAN  EnvIsSafeBoot(VOID);
BOOLEAN  EnvIsHypervisorPresent(VOID);
BOOLEAN  EnvIsKernelDebuggerAttached(VOID);
NTSTATUS EnvEnumKernelModules(PVOID *outBuffer, PULONG outCount);
