#pragma once

#include "core.h"

#define PML4_ENTRY_COUNT    0x200

NTSTATUS Pml4InitSnapshot(VOID);
NTSTATUS Pml4Rescan(VOID);
ULONG    Pml4LastAnomalyCount(VOID);
