#pragma once

#include "core.h"

typedef enum _PW_STATUS
{
    PwStatusSuccess              = 0,
    PwStatusNotPresent           = 1,
    PwStatusInvalidAddress       = 2,
    PwStatusPhysicalReadFailure  = 3,
    PwStatusUnsupportedPaging    = 4,
    PwStatusReservedBitViolation = 5,
    PwStatusInvalidParameter     = 6
} PW_STATUS;

typedef enum _PW_LEVEL
{
    PwLevelNone      = 0,
    PwLevelPte4Kb    = 1,
    PwLevelPde2Mb    = 2,
    PwLevelPdpte1Gb  = 3
} PW_LEVEL;

typedef struct _PW_FLAGS
{
    BOOLEAN Present;
    BOOLEAN Writable;
    BOOLEAN User;
    BOOLEAN ExecuteDisable;
    BOOLEAN Accessed;
    BOOLEAN Dirty;
    BOOLEAN Global;
    BOOLEAN WriteThrough;
    BOOLEAN CacheDisable;
    BOOLEAN Pat;
    BOOLEAN LargePage;
    BOOLEAN ReservedBitsSet;
} PW_FLAGS, *PPW_FLAGS;

typedef struct _PW_RESULT
{
    PW_STATUS   Status;
    PW_LEVEL    Level;

    ULONG64     DirectoryTableBase;
    ULONG64     VirtualAddress;

    ULONG64     Pml5e;
    ULONG64     Pml4e;
    ULONG64     Pdpte;
    ULONG64     Pde;
    ULONG64     Pte;

    ULONG64     LeafEntryPhysical;
    ULONG64     MappedPagePhysicalBase;
    ULONG64     ResolvedPhysicalAddress;
    ULONG64     PageSize;
    ULONG64     PageOffset;

    BOOLEAN     FiveLevelPaging;
    PW_FLAGS    Flags;
} PW_RESULT, *PPW_RESULT;

NTSTATUS PwInit(VOID);
BOOLEAN  PwIsInitialized(VOID);
BOOLEAN  PwUsesFiveLevelPaging(VOID);

ULONG64  PwReadCurrentCr3(VOID);
NTSTATUS PwGetSystemDtb(PULONG64 outDtb);

NTSTATUS PwWalk(ULONG64 directoryTableBase, ULONG64 virtualAddress, PPW_RESULT outResult);

NTSTATUS PwReadVirtualRange(ULONG64 directoryTableBase,
                            ULONG64 virtualAddress,
                            PVOID destination,
                            SIZE_T size,
                            PSIZE_T bytesRead,
                            PSIZE_T bytesSkipped);
