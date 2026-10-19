#pragma once

#include "core.h"

NTSTATUS TamperRootkitInit(VOID);
VOID     TamperRootkitShutdown(VOID);

NTSTATUS TamperRootkitSnapshot(VOID);
NTSTATUS TamperRootkitVerify(VOID);
