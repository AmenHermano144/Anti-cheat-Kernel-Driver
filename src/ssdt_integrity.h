#pragma once

#include "core.h"

NTSTATUS SsdtIntegrityInit(VOID);
VOID     SsdtIntegrityShutdown(VOID);

NTSTATUS SsdtIntegrityBaseline(VOID);
NTSTATUS SsdtIntegrityVerify(VOID);

ULONG    SsdtIntegrityGetFlag(VOID);
VOID     SsdtIntegrityClearFlag(VOID);
