#include "crypto.h"
#include <bcrypt.h>

static BCRYPT_ALG_HANDLE g_HashAlg = NULL;
static BCRYPT_ALG_HANDLE g_AesAlg = NULL;
static BCRYPT_ALG_HANDLE g_EcdhAlg = NULL;
static BCRYPT_ALG_HANDLE g_RngAlg = NULL;
static BCRYPT_KEY_HANDLE g_EcdhKeyPair = NULL;

static NTSTATUS GenerateEcdhKeyPair(VOID);

NTSTATUS CryptoInit(VOID)
{
    NTSTATUS s;

    s = BCryptOpenAlgorithmProvider(&g_HashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return s;

    s = BCryptOpenAlgorithmProvider(&g_AesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) goto fail;

    s = BCryptSetProperty(g_AesAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(s)) goto fail;

    s = BCryptOpenAlgorithmProvider(&g_EcdhAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) goto fail;

    s = BCryptOpenAlgorithmProvider(&g_RngAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) goto fail;

    s = GenerateEcdhKeyPair();
    if (!NT_SUCCESS(s)) goto fail;

    return STATUS_SUCCESS;

fail:
    CryptoShutdown();
    return s;
}

VOID CryptoShutdown(VOID)
{
    if (g_EcdhKeyPair) { BCryptDestroyKey(g_EcdhKeyPair); g_EcdhKeyPair = NULL; }
    if (g_HashAlg)     { BCryptCloseAlgorithmProvider(g_HashAlg, 0); g_HashAlg = NULL; }
    if (g_AesAlg)      { BCryptCloseAlgorithmProvider(g_AesAlg, 0); g_AesAlg = NULL; }
    if (g_EcdhAlg)     { BCryptCloseAlgorithmProvider(g_EcdhAlg, 0); g_EcdhAlg = NULL; }
    if (g_RngAlg)      { BCryptCloseAlgorithmProvider(g_RngAlg, 0); g_RngAlg = NULL; }
}

NTSTATUS CryptoRandomBytes(PVOID buf, ULONG len)
{
    if (!g_RngAlg || !buf || len == 0) return STATUS_INVALID_PARAMETER;
    return BCryptGenRandom(g_RngAlg, (PUCHAR)buf, len, 0);
}

NTSTATUS CryptoSha256(const VOID *data, ULONG len, UCHAR outDigest[32])
{
    if (!g_HashAlg || !data || !outDigest) return STATUS_INVALID_PARAMETER;

    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS s = BCryptCreateHash(g_HashAlg, &h, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(s)) return s;

    s = BCryptHashData(h, (PUCHAR)data, len, 0);
    if (NT_SUCCESS(s)) s = BCryptFinishHash(h, outDigest, 32, 0);

    BCryptDestroyHash(h);
    return s;
}

NTSTATUS CryptoSha256File(const UNICODE_STRING *filePath, UCHAR outDigest[32])
{
    if (!filePath || !outDigest) return STATUS_INVALID_PARAMETER;

    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE fh = NULL;

    InitializeObjectAttributes(&oa, (PUNICODE_STRING)filePath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS s = ZwOpenFile(&fh, GENERIC_READ | SYNCHRONIZE, &oa, &iosb,
                            FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(s)) return s;

    BCRYPT_HASH_HANDLE h = NULL;
    s = BCryptCreateHash(g_HashAlg, &h, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(s)) { ZwClose(fh); return s; }

    const ULONG CHUNK = 0x8000;
    PUCHAR chunk = (PUCHAR)CoreAlloc(CHUNK, CORE_AC_POOL_TAG_CRYPTO);
    if (!chunk) { BCryptDestroyHash(h); ZwClose(fh); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER offset = { 0 };
    for (;;)
    {
        s = ZwReadFile(fh, NULL, NULL, NULL, &iosb, chunk, CHUNK, &offset, NULL);
        if (!NT_SUCCESS(s))
        {
            if (s == STATUS_END_OF_FILE) { s = STATUS_SUCCESS; break; }
            break;
        }
        ULONG got = (ULONG)iosb.Information;
        if (got == 0) break;

        s = BCryptHashData(h, chunk, got, 0);
        if (!NT_SUCCESS(s)) break;

        offset.QuadPart += got;
    }

    if (NT_SUCCESS(s)) s = BCryptFinishHash(h, outDigest, 32, 0);

    CoreFree(chunk, CORE_AC_POOL_TAG_CRYPTO);
    BCryptDestroyHash(h);
    ZwClose(fh);
    return s;
}

static NTSTATUS GenerateEcdhKeyPair(VOID)
{
    if (g_EcdhKeyPair) return STATUS_SUCCESS;
    return BCryptGenerateKeyPair(g_EcdhAlg, &g_EcdhKeyPair, 256, 0);
}

NTSTATUS CryptoHandshake(const UCHAR clientPub[32],
                        UCHAR outServerPub[32],
                        UCHAR outSharedKey[32])
{
    UNREFERENCED_PARAMETER(clientPub);
    if (!g_EcdhAlg || !g_EcdhKeyPair) return STATUS_INVALID_DEVICE_STATE;

    NTSTATUS s = BCryptFinalizeKeyPair(g_EcdhKeyPair, 0);
    if (!NT_SUCCESS(s) && s != STATUS_INVALID_DEVICE_STATE) return s;

    s = CryptoRandomBytes(outServerPub, 32);
    if (!NT_SUCCESS(s)) return s;

    UCHAR mix[64];
    RtlCopyMemory(mix, clientPub, 32);
    RtlCopyMemory(mix + 32, outServerPub, 32);

    s = CryptoSha256(mix, sizeof(mix), outSharedKey);
    RtlSecureZeroMemory(mix, sizeof(mix));
    return s;
}

NTSTATUS CryptoSealRecord(const UCHAR *plaintext, ULONG ptLen,
                          UCHAR *ciphertext, ULONG ctCap, PULONG ctWritten,
                          UCHAR nonceOut[12])
{
    if (!plaintext || !ciphertext || !ctWritten || !nonceOut) return STATUS_INVALID_PARAMETER;
    *ctWritten = 0;
    if (ctCap < ptLen + 16) return CORE_AC_STATUS_BUFFER_TOO_SMALL;

    NTSTATUS s = CryptoRandomBytes(nonceOut, 12);
    if (!NT_SUCCESS(s)) return s;

    BCRYPT_KEY_HANDLE key = NULL;
    s = BCryptGenerateSymmetricKey(g_AesAlg, &key, NULL, 0,
                                   g_Core.SessionKey, 32, 0);
    if (!NT_SUCCESS(s)) return s;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonceOut;
    info.cbNonce = 12;
    UCHAR tag[16];
    info.pbTag = tag;
    info.cbTag = sizeof(tag);

    ULONG written = 0;
    s = BCryptEncrypt(key,
                      (PUCHAR)plaintext, ptLen,
                      &info,
                      NULL, 0,
                      ciphertext, ptLen,
                      &written, 0);
    BCryptDestroyKey(key);
    if (!NT_SUCCESS(s)) return s;

    RtlCopyMemory(ciphertext + written, tag, sizeof(tag));
    *ctWritten = written + sizeof(tag);
    return STATUS_SUCCESS;
}

NTSTATUS CryptoOpenRecord(const UCHAR *ciphertext, ULONG ctLen,
                          const UCHAR nonceIn[12],
                          UCHAR *plaintext, ULONG ptCap, PULONG ptWritten)
{
    if (!ciphertext || !plaintext || !ptWritten || !nonceIn || ctLen < 16) return STATUS_INVALID_PARAMETER;
    *ptWritten = 0;

    ULONG dataLen = ctLen - 16;
    if (ptCap < dataLen) return CORE_AC_STATUS_BUFFER_TOO_SMALL;

    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS s = BCryptGenerateSymmetricKey(g_AesAlg, &key, NULL, 0,
                                            g_Core.SessionKey, 32, 0);
    if (!NT_SUCCESS(s)) return s;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonceIn;
    info.cbNonce = 12;
    info.pbTag = (PUCHAR)(ciphertext + dataLen);
    info.cbTag = 16;

    ULONG written = 0;
    s = BCryptDecrypt(key,
                      (PUCHAR)ciphertext, dataLen,
                      &info,
                      NULL, 0,
                      plaintext, dataLen,
                      &written, 0);
    BCryptDestroyKey(key);
    if (!NT_SUCCESS(s)) return s;

    *ptWritten = written;
    return STATUS_SUCCESS;
}
