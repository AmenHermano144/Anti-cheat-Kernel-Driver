#pragma once

#include "core.h"

NTSTATUS CryptoInit(VOID);
VOID     CryptoShutdown(VOID);

NTSTATUS CryptoRandomBytes(PVOID buf, ULONG len);

NTSTATUS CryptoSha256(const VOID *data, ULONG len, UCHAR outDigest[32]);
NTSTATUS CryptoSha256File(const UNICODE_STRING *filePath, UCHAR outDigest[32]);

NTSTATUS CryptoHandshake(const UCHAR clientPub[32],
                        UCHAR outServerPub[32],
                        UCHAR outSharedKey[32]);

NTSTATUS CryptoSealRecord(const UCHAR *plaintext, ULONG ptLen,
                          UCHAR *ciphertext, ULONG ctCap, PULONG ctWritten,
                          UCHAR nonceOut[12]);
NTSTATUS CryptoOpenRecord(const UCHAR *ciphertext, ULONG ctLen,
                          const UCHAR nonceIn[12],
                          UCHAR *plaintext, ULONG ptCap, PULONG ptWritten);
