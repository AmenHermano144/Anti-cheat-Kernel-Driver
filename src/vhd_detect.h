#pragma once

#include "core.h"

NTSTATUS VhdDetectInit(VOID);
VOID     VhdDetectShutdown(VOID);

NTSTATUS VhdDetectSnapshot(VOID);
NTSTATUS VhdDetectVerify(VOID);

ULONG    VhdDetectGetFlag(VOID);
VOID     VhdDetectClearFlag(VOID);
