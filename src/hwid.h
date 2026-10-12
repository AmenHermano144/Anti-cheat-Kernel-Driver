#pragma once

#include "core.h"
#include "smbios.h"

typedef struct _HWID_SNAPSHOT
{
    SMBIOS_PARSED   Smbios;
    UCHAR           CompositeDigest[32];
    ULONG64         CompositeFnv64;
} HWID_SNAPSHOT, *PHWID_SNAPSHOT;

NTSTATUS HwidCollectBoot(VOID);
NTSTATUS HwidGetSnapshot(PHWID_SNAPSHOT out);
NTSTATUS HwidEnumerateAcpi(VOID);
