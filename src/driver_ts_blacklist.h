#pragma once

#include "core.h"

BOOLEAN DriverTsIsBlacklisted(ULONG peTimestamp);
NTSTATUS DriverTsInit(VOID);
