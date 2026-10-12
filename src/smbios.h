#pragma once

#include "core.h"

typedef struct _SMBIOS_PARSED
{
    UCHAR   BiosVendor[64];
    UCHAR   BiosVersion[64];
    UCHAR   SystemManufacturer[64];
    UCHAR   SystemProductName[64];
    UCHAR   SystemVersion[64];
    UCHAR   SystemSerial[64];
    UCHAR   SystemUuid[16];
    UCHAR   BaseboardManufacturer[64];
    UCHAR   BaseboardProduct[64];
    UCHAR   BaseboardSerial[64];
    ULONG   MemoryModuleCount;
    UCHAR   FirstMemorySerial[64];
    UCHAR   FirstMemoryManufacturer[64];
} SMBIOS_PARSED, *PSMBIOS_PARSED;

NTSTATUS SmbiosCollect(PSMBIOS_PARSED outParsed);
