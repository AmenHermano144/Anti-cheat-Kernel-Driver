#pragma once

#include "core.h"

#define PML4_ENTRY_COUNT    0x200
#define PML4_MAX_WATCHED    8

NTSTATUS Pml4InitSnapshot(VOID);
NTSTATUS Pml4Rescan(VOID);
ULONG    Pml4LastAnomalyCount(VOID);

NTSTATUS Pml4RegisterGameProcessByPid(HANDLE pid);
NTSTATUS Pml4UnregisterGameProcessByPid(HANDLE pid);
VOID     Pml4ClearWatched(VOID);
