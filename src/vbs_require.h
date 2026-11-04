#pragma once

#include "core.h"

#define VBS_STATE_UNKNOWN            0
#define VBS_STATE_UNSUPPORTED        1
#define VBS_STATE_AVAILABLE_OFF      2
#define VBS_STATE_ENABLED            3
#define VBS_STATE_STRICT             4

#define VBS_FLAG_NONE                       0x00000000
#define VBS_FLAG_CPUID_HV_PRESENT           0x00000001
#define VBS_FLAG_HV_VENDOR_MICROSOFT        0x00000002
#define VBS_FLAG_HV_VENDOR_FOREIGN          0x00000004
#define VBS_FLAG_IUM_INFO_READABLE          0x00000008
#define VBS_FLAG_SECURE_KERNEL_RUNNING      0x00000010
#define VBS_FLAG_HVCI_RUNNING               0x00000020
#define VBS_FLAG_HVCI_STRICT_MODE           0x00000040
#define VBS_FLAG_IUM_DEBUG_ENABLED          0x00000080
#define VBS_FLAG_FW_PAGE_PROTECTION         0x00000100
#define VBS_FLAG_ENCRYPTION_KEY_AVAILABLE   0x00000200
#define VBS_FLAG_REG_VBS_ENABLED            0x00000400
#define VBS_FLAG_REG_VBS_REQUIRED           0x00000800
#define VBS_FLAG_REG_LSA_CFG_ENABLED        0x00001000
#define VBS_FLAG_CLAIM_DISAGREEMENT         0x00002000
#define VBS_FLAG_STATE_DRIFT                0x00004000
#define VBS_FLAG_HV_HIDDEN_FROM_CPUID       0x00008000
#define VBS_FLAG_REQUIRED_NOT_MET           0x00010000
#define VBS_FLAG_SUSPICIOUS                 0x00020000

typedef struct _VBS_REQUIRE_REPORT
{
    ULONG   Flags;
    ULONG   State;
    ULONG   IumFirstByte;
    ULONG   HypervisorVendorHash;
    UCHAR   CpuidHvPresent;
    UCHAR   HypervisorIsMicrosoft;
    UCHAR   IumReadable;
    UCHAR   SecureKernelRunning;
    UCHAR   HvciEnabled;
    UCHAR   HvciStrictMode;
    UCHAR   IumDebugEnabled;
    UCHAR   FwPageProtection;
    UCHAR   EncryptionKeyAvailable;
    UCHAR   RegVbsEnabled;
    UCHAR   RegVbsRequired;
    UCHAR   RegLsaCfgEnabled;
    UCHAR   RequiredNotMet;
    CHAR    HypervisorVendor[16];
} VBS_REQUIRE_REPORT, *PVBS_REQUIRE_REPORT;

NTSTATUS VbsRequireInit(VOID);
VOID     VbsRequireShutdown(VOID);

NTSTATUS VbsRequireBaseline(VOID);
NTSTATUS VbsRequireVerify(VOID);

ULONG    VbsRequireGetFlag(VOID);
VOID     VbsRequireClearFlag(VOID);
NTSTATUS VbsRequireCopyReport(PVBS_REQUIRE_REPORT outReport);
