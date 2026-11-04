#pragma once

#include "core.h"

#define TPM_ATTEST_STATE_UNKNOWN            0
#define TPM_ATTEST_STATE_NO_TPM             1
#define TPM_ATTEST_STATE_EK_FAILED          2
#define TPM_ATTEST_STATE_PROPS_ONLY         3
#define TPM_ATTEST_STATE_EK_READY           4
#define TPM_ATTEST_STATE_BUNDLE_READY       5

#define TPM_ATTEST_FLAG_NONE                 0x00000000
#define TPM_ATTEST_FLAG_TPM_PRESENT          0x00000001
#define TPM_ATTEST_FLAG_PROPS_READABLE       0x00000002
#define TPM_ATTEST_FLAG_MANUFACTURER_KNOWN   0x00000004
#define TPM_ATTEST_FLAG_EK_READABLE          0x00000008
#define TPM_ATTEST_FLAG_EK_NAME_EXTRACTED    0x00000010
#define TPM_ATTEST_FLAG_EK_PUBLIC_HASHED     0x00000020
#define TPM_ATTEST_FLAG_PCRS_PRESENT         0x00000040
#define TPM_ATTEST_FLAG_NONCE_PRESENT        0x00000080
#define TPM_ATTEST_FLAG_BUNDLE_READY         0x00000100
#define TPM_ATTEST_FLAG_BUNDLE_DRIFTED       0x00000200
#define TPM_ATTEST_FLAG_EK_DRIFTED           0x00000400
#define TPM_ATTEST_FLAG_SUSPICIOUS           0x00000800

#define TPM_ATTEST_NONCE_LEN       32
#define TPM_ATTEST_EK_NAME_MAX     68

typedef struct _TPM_ATTEST_REPORT
{
    ULONG   Flags;
    ULONG   State;
    ULONG   Manufacturer;
    ULONG   FirmwareVersion1;
    ULONG   FirmwareVersion2;
    USHORT  EkNameLen;
    USHORT  Reserved0;
    UCHAR   EkName[TPM_ATTEST_EK_NAME_MAX];
    UCHAR   EkPublicSha256[32];
    UCHAR   Nonce[TPM_ATTEST_NONCE_LEN];
    UCHAR   Pcr0Sha256[32];
    UCHAR   Pcr7Sha256[32];
    UCHAR   Pcr14Sha256[32];
    UCHAR   BundleSha256[32];
    CHAR    VendorString[8];
} TPM_ATTEST_REPORT, *PTPM_ATTEST_REPORT;

NTSTATUS TpmAttestInit(VOID);
VOID     TpmAttestShutdown(VOID);

NTSTATUS TpmAttestBaseline(VOID);
NTSTATUS TpmAttestVerify(VOID);

NTSTATUS TpmAttestPushNonce(const UCHAR *nonce, ULONG nonceLen);

ULONG    TpmAttestGetFlag(VOID);
VOID     TpmAttestClearFlag(VOID);
NTSTATUS TpmAttestCopyReport(PTPM_ATTEST_REPORT outReport);
