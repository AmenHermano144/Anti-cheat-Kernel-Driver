#pragma once

#include "core.h"

NTSTATUS ImageBackingInit(VOID);
VOID     ImageBackingShutdown(VOID);

NTSTATUS ImageBackingBaseline(VOID);
NTSTATUS ImageBackingVerify(VOID);

NTSTATUS ImageBackingOnKernelImageLoad(PUNICODE_STRING fullImageName, PIMAGE_INFO imageInfo);
