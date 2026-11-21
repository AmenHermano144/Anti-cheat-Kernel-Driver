#pragma once

#include "core.h"

NTSTATUS AcAnchorInit(PDRIVER_OBJECT DriverObject);
BOOLEAN  AcAnchorIsInitialized(VOID);

BOOLEAN  AcAnchorCheckRip(ULONG_PTR rip);
BOOLEAN  AcAnchorCheckCallerRip(VOID);

ULONG_PTR AcAnchorImageStart(VOID);
ULONG     AcAnchorImageSize(VOID);
