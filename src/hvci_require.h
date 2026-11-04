#pragma once

#include "core.h"

#define HVCI_STATE_UNKNOWN            0
#define HVCI_STATE_UNSUPPORTED        1
#define HVCI_STATE_AVAILABLE_OFF      2
#define HVCI_STATE_AUDIT_ONLY         3
#define HVCI_STATE_ENFORCING          4
#define HVCI_STATE_STRICT             5
#define HVCI_STATE_TEST_SIGNING       6

#define HVCI_FLAG_NONE                  0x00000000
#define HVCI_FLAG_CI_READABLE           0x00000001
#define HVCI_FLAG_CI_ENABLED            0x00000002
#define HVCI_FLAG_CI_TEST_SIGN          0x00000004
#define HVCI_FLAG_CI_DEBUG_MODE         0x00000008
#define HVCI_FLAG_CI_UMCI_ENABLED       0x00000010
#define HVCI_FLAG_HVCI_KMCI_ENABLED     0x00000020
#define HVCI_FLAG_HVCI_AUDIT_MODE       0x00000040
#define HVCI_FLAG_HVCI_STRICT_MODE      0x00000080
#define HVCI_FLAG_WHQL_ENFORCEMENT      0x00000100
#define HVCI_FLAG_HYPERVISOR_PRESENT    0x00000200
#define HVCI_FLAG_HV_VENDOR_MICROSOFT   0x00000400
#define HVCI_FLAG_HV_VENDOR_FOREIGN     0x00000800
#define HVCI_FLAG_REG_VBS_ENABLED       0x00001000
#define HVCI_FLAG_REG_HVCI_ENABLED      0x00002000
#define HVCI_FLAG_CLAIM_DISAGREEMENT    0x00004000
#define HVCI_FLAG_STATE_DRIFT           0x00008000
#define HVCI_FLAG_HV_HIDDEN_FROM_CPUID  0x00010000
#define HVCI_FLAG_REQUIRED_NOT_MET      0x00020000
#define HVCI_FLAG_SUSPICIOUS            0x00040000

typedef struct _HVCI_REQUIRE_REPORT
{
    ULONG   Flags;
    ULONG   State;
    ULONG   CodeIntegrityOptions;
    ULONG   HypervisorVendorHash;
    UCHAR   CiReadable;
    UCHAR   CiEnabled;
    UCHAR   HvciKmciEnabled;
    UCHAR   HvciStrictMode;
    UCHAR   HvciAuditMode;
    UCHAR   HypervisorPresent;
    UCHAR   HypervisorIsMicrosoft;
    UCHAR   RegVbsEnabled;
    UCHAR   RegHvciEnabled;
    UCHAR   TestSigning;
    UCHAR   DebugMode;
    UCHAR   RequiredNotMet;
    CHAR    HypervisorVendor[16];
} HVCI_REQUIRE_REPORT, *PHVCI_REQUIRE_REPORT;

NTSTATUS HvciRequireInit(VOID);
VOID     HvciRequireShutdown(VOID);

NTSTATUS HvciRequireBaseline(VOID);
NTSTATUS HvciRequireVerify(VOID);

ULONG    HvciRequireGetFlag(VOID);
VOID     HvciRequireClearFlag(VOID);
NTSTATUS HvciRequireCopyReport(PHVCI_REQUIRE_REPORT outReport);
