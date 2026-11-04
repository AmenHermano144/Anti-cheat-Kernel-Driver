#pragma once

#include "core.h"

#define SB_STATE_UNKNOWN              0
#define SB_STATE_UNSUPPORTED          1
#define SB_STATE_CAPABLE_DISABLED     2
#define SB_STATE_CONFIGURED           3
#define SB_STATE_ENABLED              4
#define SB_STATE_PCR_MISMATCH         5

#define SB_FLAG_NONE                    0x00000000
#define SB_FLAG_EFI_READABLE            0x00000001
#define SB_FLAG_EFI_ENABLED             0x00000002
#define SB_FLAG_EFI_SETUP_MODE          0x00000004
#define SB_FLAG_SYSINFO_READABLE        0x00000008
#define SB_FLAG_SYSINFO_ENABLED         0x00000010
#define SB_FLAG_SYSINFO_CAPABLE         0x00000020
#define SB_FLAG_REGISTRY_ENABLED        0x00000040
#define SB_FLAG_TPM_PRESENT             0x00000080
#define SB_FLAG_PCR0_VALID              0x00000100
#define SB_FLAG_PCR7_VALID              0x00000200
#define SB_FLAG_PCR14_VALID             0x00000400
#define SB_FLAG_PCR7_ALL_ZERO           0x00000800
#define SB_FLAG_PCR7_DRIFT              0x00001000
#define SB_FLAG_CLAIM_DISAGREEMENT      0x00002000
#define SB_FLAG_OS_CLAIMS_NO_HARDWARE   0x00004000
#define SB_FLAG_BOOT_AUTHORITY_ZERO     0x00008000
#define SB_FLAG_SUSPICIOUS              0x00010000

typedef struct _SECUREBOOT_ATTEST_REPORT
{
    ULONG   Flags;
    ULONG   State;
    UCHAR   EfiReadable;
    UCHAR   EfiEnabled;
    UCHAR   SetupMode;
    UCHAR   SysinfoReadable;
    UCHAR   SysinfoEnabled;
    UCHAR   SysinfoCapable;
    UCHAR   RegistryEnabled;
    UCHAR   TpmPresent;
    UCHAR   Pcr0Valid;
    UCHAR   Pcr7Valid;
    UCHAR   Pcr14Valid;
    UCHAR   Pcr7AllZero;
    UCHAR   Pcr7Drift;
    UCHAR   Reserved[3];
    UCHAR   Pcr0Sha256[32];
    UCHAR   Pcr7Sha256[32];
    UCHAR   Pcr14Sha256[32];
    UCHAR   Pcr7Baseline[32];
} SECUREBOOT_ATTEST_REPORT, *PSECUREBOOT_ATTEST_REPORT;

NTSTATUS SecureBootAttestInit(VOID);
VOID     SecureBootAttestShutdown(VOID);

NTSTATUS SecureBootAttestBaseline(VOID);
NTSTATUS SecureBootAttestVerify(VOID);

ULONG    SecureBootAttestGetFlag(VOID);
VOID     SecureBootAttestClearFlag(VOID);
NTSTATUS SecureBootAttestCopyReport(PSECUREBOOT_ATTEST_REPORT outReport);
