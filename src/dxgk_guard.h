#pragma once

#include "core.h"

NTSTATUS DxgkGuardInit(VOID);
VOID     DxgkGuardShutdown(VOID);

NTSTATUS DxgkGuardBaseline(VOID);
NTSTATUS DxgkGuardVerify(VOID);

ULONG    DxgkGuardGetFlag(VOID);
VOID     DxgkGuardClearFlag(VOID);
