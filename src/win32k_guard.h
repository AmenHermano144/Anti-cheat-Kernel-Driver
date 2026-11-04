#pragma once

#include "core.h"

NTSTATUS Win32kGuardInit(VOID);
VOID     Win32kGuardShutdown(VOID);

NTSTATUS Win32kGuardBaseline(VOID);
NTSTATUS Win32kGuardVerify(VOID);
