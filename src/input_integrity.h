#pragma once

#include "core.h"

NTSTATUS InputIntegrityInit(VOID);
VOID     InputIntegrityShutdown(VOID);

NTSTATUS InputIntegritySnapshot(VOID);
NTSTATUS InputIntegrityVerify(VOID);
