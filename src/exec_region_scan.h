#pragma once

#include "core.h"

NTSTATUS ExecRegionScanInit(VOID);
VOID     ExecRegionScanShutdown(VOID);

NTSTATUS ExecRegionScanSnapshot(VOID);
NTSTATUS ExecRegionScanDiff(VOID);
