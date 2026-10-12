#pragma once

#include "core.h"

typedef struct _KLDR_MODULE_ENTRY
{
    ULONG64 ImageBase;
    ULONG   ImageSize;
    ULONG   PeTimestamp;
    ULONG64 Fnv1a64;
    USHORT  NameOffset;
    USHORT  Reserved;
    UCHAR   FullPath[256];
} KLDR_MODULE_ENTRY, *PKLDR_MODULE_ENTRY;

NTSTATUS KldrSnapshotModules(VOID);
NTSTATUS KldrDiffScan(VOID);
NTSTATUS KldrOnKernelImageLoad(PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo);

ULONG    KldrSnapshotCount(VOID);
BOOLEAN  KldrAddressBelongsToKnownModule(PVOID address);
