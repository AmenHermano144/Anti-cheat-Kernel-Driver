#pragma once

#include "core.h"

NTSTATUS PhysMemReadRaw(ULONG64 physAddress, PVOID outBuffer, SIZE_T bytes);
NTSTATUS PhysMemReadPage(ULONG64 pfn, PVOID outPage);
