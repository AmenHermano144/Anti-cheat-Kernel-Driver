#pragma once

#include "core.h"

#define OSG_STATE_UNKNOWN          0
#define OSG_STATE_UNREADABLE       1
#define OSG_STATE_WRONG_PLATFORM   2
#define OSG_STATE_TOO_OLD          3
#define OSG_STATE_MEETS_MIN        4

#define OSG_FLAG_NONE                  0x00000000
#define OSG_FLAG_READABLE              0x00000001
#define OSG_FLAG_IS_NT                 0x00000002
#define OSG_FLAG_IS_WORKSTATION        0x00000004
#define OSG_FLAG_UBR_READABLE          0x00000008
#define OSG_FLAG_MEETS_MIN_BUILD       0x00000010
#define OSG_FLAG_BELOW_MIN_BUILD       0x00000020
#define OSG_FLAG_INSIDER_LEAK          0x00000040
#define OSG_FLAG_SERVICE_PACK_PRESENT  0x00000080
#define OSG_FLAG_SUSPICIOUS            0x00000100

#define OSG_DEFAULT_MIN_BUILD    26200

typedef struct _OS_VERSION_REPORT
{
    ULONG   Flags;
    ULONG   State;
    ULONG   MajorVersion;
    ULONG   MinorVersion;
    ULONG   BuildNumber;
    ULONG   Ubr;
    ULONG   PlatformId;
    USHORT  ServicePackMajor;
    USHORT  ServicePackMinor;
    USHORT  ProductType;
    USHORT  SuiteMask;
    ULONG   MinimumBuildRequired;
    CHAR    CsdVersion[64];
} OS_VERSION_REPORT, *POS_VERSION_REPORT;

NTSTATUS OsVersionGateInit(VOID);
VOID     OsVersionGateShutdown(VOID);

NTSTATUS OsVersionGateBaseline(VOID);
NTSTATUS OsVersionGateVerify(VOID);

ULONG    OsVersionGateGetFlag(VOID);
VOID     OsVersionGateClearFlag(VOID);
NTSTATUS OsVersionGateCopyReport(POS_VERSION_REPORT outReport);
