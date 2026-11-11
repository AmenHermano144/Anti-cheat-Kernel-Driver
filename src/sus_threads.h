#pragma once

#include "core.h"

NTSTATUS SusThreadsInit(VOID);
VOID     SusThreadsShutdown(VOID);

NTSTATUS SusThreadsVerify(VOID);

ULONG    SusThreadsGetFlag(VOID);
VOID     SusThreadsClearFlag(VOID);
