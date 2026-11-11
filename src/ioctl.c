#include "ioctl.h"
#include "channels.h"
#include "crypto.h"
#include "anti_tamper.h"
#include "events.h"
#include "hwid.h"
#include "strings.h"
#include "overlay_detect.h"
#include "dma_detect.h"
#include "secureboot_attest.h"
#include "hvci_require.h"
#include "os_version_gate.h"
#include "vbs_require.h"
#include "iommu_require.h"
#include "tpm_attest.h"

typedef enum _AC_OP
{
    AC_OP_PUSH_SESSION_UUID       = 0x9A3B1C04,
    AC_OP_EVENT_POLL              = 0xC7E52F15,
    AC_OP_PUSH_MATCH              = 0x4E1D8306,
    AC_OP_MATCH_OVER              = 0x2F3A9B07,
    AC_OP_PUSH_WATCHLIST          = 0x6B48D208,
    AC_OP_PUSH_PROCESS_PATH       = 0xA1C57309,
    AC_OP_PUSH_HASH               = 0x8E9F160A,
    AC_OP_PUSH_VENDOR_CN          = 0xD2B4780B,
    AC_OP_PUSH_USB_DEVICE         = 0x5C3A610C,
    AC_OP_PUSH_U64_SET            = 0x79E8420D,
    AC_OP_DRIVER_EVENT            = 0xB8D52E0E,
    AC_OP_PUSH_CMD                = 0x4F1B9A0F,
    AC_OP_REPORT_WINDOW           = 0x38CF2D10,
    AC_OP_QUERY_OVERLAY_FLAG      = 0xE9A7B011,
    AC_OP_QUERY_DMA_FLAG          = 0x1A5F4C12,
    AC_OP_QUERY_SECUREBOOT_FLAG   = 0xC3E82F13,
    AC_OP_QUERY_SECUREBOOT_REPORT = 0x7D4A6B14,
    AC_OP_QUERY_HVCI_FLAG         = 0x95B1D715,
    AC_OP_QUERY_HVCI_REPORT       = 0x2E738A16,
    AC_OP_QUERY_OS_VERSION_FLAG   = 0xF46C5917,
    AC_OP_QUERY_OS_VERSION_REPORT = 0xB1E2A718,
    AC_OP_QUERY_VBS_FLAG          = 0x683DC419,
    AC_OP_QUERY_VBS_REPORT        = 0xDA51F11A,
    AC_OP_QUERY_IOMMU_FLAG        = 0x27A8E31B,
    AC_OP_QUERY_IOMMU_REPORT      = 0xC9F56B1C,
    AC_OP_PUSH_TPM_NONCE          = 0x4B2E981D,
    AC_OP_QUERY_TPM_ATTEST_FLAG   = 0x8F74531E,
    AC_OP_QUERY_TPM_ATTEST_REPORT = 0x63A9C21F,
} AC_OP;

typedef struct _AC_OP_VERSION_ENTRY
{
    ULONG Op;
    ULONG Version;
} AC_OP_VERSION_ENTRY;

static const AC_OP_VERSION_ENTRY g_OpVersions[] =
{
    { AC_OP_PUSH_SESSION_UUID,       0x01350015 },
    { AC_OP_EVENT_POLL,              0x01350042 },
    { AC_OP_PUSH_MATCH,              0x01350089 },
    { AC_OP_MATCH_OVER,              0x013500A7 },
    { AC_OP_PUSH_WATCHLIST,          0x013500CA },
    { AC_OP_PUSH_PROCESS_PATH,       0x013500D3 },
    { AC_OP_PUSH_HASH,               0x013500E1 },
    { AC_OP_PUSH_VENDOR_CN,          0x013500F8 },
    { AC_OP_PUSH_USB_DEVICE,         0x01350104 },
    { AC_OP_PUSH_U64_SET,            0x0135011D },
    { AC_OP_DRIVER_EVENT,            0x0135012F },
    { AC_OP_PUSH_CMD,                0x01350146 },
    { AC_OP_REPORT_WINDOW,           0x01350158 },
    { AC_OP_QUERY_OVERLAY_FLAG,      0x0135016B },
    { AC_OP_QUERY_DMA_FLAG,          0x0135017E },
    { AC_OP_QUERY_SECUREBOOT_FLAG,   0x01350194 },
    { AC_OP_QUERY_SECUREBOOT_REPORT, 0x013501A2 },
    { AC_OP_QUERY_HVCI_FLAG,         0x013501B9 },
    { AC_OP_QUERY_HVCI_REPORT,       0x013501C7 },
    { AC_OP_QUERY_OS_VERSION_FLAG,   0x013501D5 },
    { AC_OP_QUERY_OS_VERSION_REPORT, 0x013501E8 },
    { AC_OP_QUERY_VBS_FLAG,          0x013501F3 },
    { AC_OP_QUERY_VBS_REPORT,        0x01350206 },
    { AC_OP_QUERY_IOMMU_FLAG,        0x01350217 },
    { AC_OP_QUERY_IOMMU_REPORT,      0x01350229 },
    { AC_OP_PUSH_TPM_NONCE,          0x0135023B },
    { AC_OP_QUERY_TPM_ATTEST_FLAG,   0x0135024D },
    { AC_OP_QUERY_TPM_ATTEST_REPORT, 0x01350262 },
};

#define AC_MUX_INPUT_MAGIC    0x4341434Du
#define AC_MUX_OUTPUT_MAGIC   0x4D434143u
#define AC_MUX_HEADER_VERSION 0x00000001u
#define AC_MUX_BODY_MAX       0x00010000u

#pragma pack(push, 1)
typedef struct _AC_MUX_INPUT_HEADER
{
    ULONG Magic;
    ULONG HeaderVersion;
    ULONG Operation;
    ULONG OperationVersion;
    UCHAR Nonce[12];
    ULONG CiphertextLen;
} AC_MUX_INPUT_HEADER, *PAC_MUX_INPUT_HEADER;

typedef struct _AC_MUX_OUTPUT_HEADER
{
    ULONG Magic;
    ULONG HeaderVersion;
    ULONG Status;
    ULONG Reserved;
    UCHAR Nonce[12];
    ULONG CiphertextLen;
} AC_MUX_OUTPUT_HEADER, *PAC_MUX_OUTPUT_HEADER;
#pragma pack(pop)

static NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS Status, ULONG Info)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS CoreIoctlCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static BOOLEAN ValidateOpVersion(ULONG op, ULONG ver)
{
    for (ULONG i = 0; i < ARRAYSIZE(g_OpVersions); i++)
    {
        if (g_OpVersions[i].Op == op) return g_OpVersions[i].Version == ver;
    }
    return FALSE;
}

static NTSTATUS DispatchOperation(ULONG op,
                                  const UCHAR *body, ULONG bodyLen,
                                  UCHAR *resp, ULONG respCap, PULONG respLen)
{
    *respLen = 0;

    switch (op)
    {
    case AC_OP_PUSH_SESSION_UUID:
        if (!body || bodyLen < sizeof(GUID)) return STATUS_INVALID_PARAMETER;
        RtlCopyMemory(&g_Core.SessionGuid, body, sizeof(GUID));
        return STATUS_SUCCESS;

    case AC_OP_EVENT_POLL:
        if (!resp || respCap == 0) return STATUS_INVALID_PARAMETER;
        return ChannelDrainEvents(resp, respCap, respLen);

    case AC_OP_PUSH_MATCH:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_MATCH, (PVOID)body, bodyLen);

    case AC_OP_MATCH_OVER:
        (VOID)EventsReportTeardown();
        return STATUS_SUCCESS;

    case AC_OP_PUSH_WATCHLIST:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_WATCHLIST, (PVOID)body, bodyLen);

    case AC_OP_PUSH_PROCESS_PATH:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_PROCESS, (PVOID)body, bodyLen);

    case AC_OP_PUSH_HASH:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_HASH, (PVOID)body, bodyLen);

    case AC_OP_PUSH_VENDOR_CN:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_VENDOR, (PVOID)body, bodyLen);

    case AC_OP_PUSH_USB_DEVICE:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_USB, (PVOID)body, bodyLen);

    case AC_OP_PUSH_U64_SET:
    case AC_OP_PUSH_CMD:
    case AC_OP_DRIVER_EVENT:
        if (!body || bodyLen == 0) return STATUS_INVALID_PARAMETER;
        return ChannelAcceptBlob(CHANNEL_BLOB_GENERIC, (PVOID)body, bodyLen);

    case AC_OP_REPORT_WINDOW:
        if (!body || bodyLen < sizeof(OVERLAY_WINDOW_REPORT)) return STATUS_INVALID_PARAMETER;
        return OverlayDetectEvaluateReport((const OVERLAY_WINDOW_REPORT *)body);

    case AC_OP_QUERY_OVERLAY_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = OverlayDetectGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_DMA_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = DmaDetectGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_SECUREBOOT_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = SecureBootAttestGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_SECUREBOOT_REPORT:
    {
        if (respCap < sizeof(SECUREBOOT_ATTEST_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        SECUREBOOT_ATTEST_REPORT rep;
        NTSTATUS s = SecureBootAttestCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_HVCI_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = HvciRequireGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_HVCI_REPORT:
    {
        if (respCap < sizeof(HVCI_REQUIRE_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        HVCI_REQUIRE_REPORT rep;
        NTSTATUS s = HvciRequireCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_OS_VERSION_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = OsVersionGateGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_OS_VERSION_REPORT:
    {
        if (respCap < sizeof(OS_VERSION_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        OS_VERSION_REPORT rep;
        NTSTATUS s = OsVersionGateCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_VBS_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = VbsRequireGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_VBS_REPORT:
    {
        if (respCap < sizeof(VBS_REQUIRE_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        VBS_REQUIRE_REPORT rep;
        NTSTATUS s = VbsRequireCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_IOMMU_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = IommuRequireGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_IOMMU_REPORT:
    {
        if (respCap < sizeof(IOMMU_REQUIRE_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        IOMMU_REQUIRE_REPORT rep;
        NTSTATUS s = IommuRequireCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    case AC_OP_PUSH_TPM_NONCE:
        if (!body || bodyLen < TPM_ATTEST_NONCE_LEN) return STATUS_INVALID_PARAMETER;
        return TpmAttestPushNonce(body, TPM_ATTEST_NONCE_LEN);

    case AC_OP_QUERY_TPM_ATTEST_FLAG:
    {
        if (respCap < sizeof(ULONG)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        ULONG v = TpmAttestGetFlag();
        RtlCopyMemory(resp, &v, sizeof(v));
        *respLen = sizeof(v);
        return STATUS_SUCCESS;
    }

    case AC_OP_QUERY_TPM_ATTEST_REPORT:
    {
        if (respCap < sizeof(TPM_ATTEST_REPORT)) return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        TPM_ATTEST_REPORT rep;
        NTSTATUS s = TpmAttestCopyReport(&rep);
        if (!NT_SUCCESS(s)) return s;
        RtlCopyMemory(resp, &rep, sizeof(rep));
        *respLen = sizeof(rep);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS HandlePing(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(buf);
    UNREFERENCED_PARAMETER(inLen);
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS HandleBootstrap(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(buf);
    UNREFERENCED_PARAMETER(inLen);
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    return ChannelBootstrap();
}

static NTSTATUS HandleKeyExchange(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    *written = 0;
    if (inLen < 32 || outLen < 32 || !buf) return STATUS_INVALID_PARAMETER;

    HANDLE curPid = PsGetCurrentProcessId();
    ULONG pidU32 = (ULONG)(ULONG_PTR)curPid;

    UCHAR serverPub[32];
    NTSTATUS s = CryptoHandshake((const UCHAR *)buf, serverPub, pidU32);
    if (!NT_SUCCESS(s)) return s;

    RtlCopyMemory(buf, serverPub, 32);
    *written = 32;
    InterlockedExchange(&g_Core.SessionActive, 1);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleMux(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    *written = 0;
    if (!buf || inLen < sizeof(AC_MUX_INPUT_HEADER)) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_Core.SessionActive, 0, 0)) return CORE_AC_STATUS_NO_SESSION;

    AC_MUX_INPUT_HEADER hdr;
    RtlCopyMemory(&hdr, buf, sizeof(hdr));

    if (hdr.Magic != AC_MUX_INPUT_MAGIC) return STATUS_INVALID_PARAMETER;
    if (hdr.HeaderVersion != AC_MUX_HEADER_VERSION) return STATUS_INVALID_PARAMETER;
    if (hdr.CiphertextLen == 0 || hdr.CiphertextLen > AC_MUX_BODY_MAX) return STATUS_INVALID_PARAMETER;
    if (inLen < sizeof(hdr) + hdr.CiphertextLen) return STATUS_INVALID_PARAMETER;
    if (hdr.CiphertextLen < 16) return STATUS_INVALID_PARAMETER;

    if (!ValidateOpVersion(hdr.Operation, hdr.OperationVersion)) return STATUS_INVALID_PARAMETER;

    HANDLE curPid = PsGetCurrentProcessId();
    ULONG pidU32 = (ULONG)(ULONG_PTR)curPid;

    UCHAR sessionKey[32];
    NTSTATUS s = CryptoDeriveSessionKey(pidU32, sessionKey);
    if (!NT_SUCCESS(s)) return s;

    ULONG ptCap = hdr.CiphertextLen;
    PUCHAR plaintext = (PUCHAR)CoreAlloc(ptCap, CORE_AC_POOL_TAG_CRYPTO);
    if (!plaintext)
    {
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG ptLen = 0;
    s = CryptoOpenRecord(sessionKey,
                         (const UCHAR *)buf + sizeof(hdr), hdr.CiphertextLen,
                         hdr.Nonce,
                         plaintext, ptCap, &ptLen);
    if (!NT_SUCCESS(s))
    {
        RtlSecureZeroMemory(plaintext, ptCap);
        CoreFree(plaintext, CORE_AC_POOL_TAG_CRYPTO);
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        return s;
    }

    ULONG respPlainCap = AC_MUX_BODY_MAX;
    PUCHAR respPlain = (PUCHAR)CoreAlloc(respPlainCap, CORE_AC_POOL_TAG_CRYPTO);
    if (!respPlain)
    {
        RtlSecureZeroMemory(plaintext, ptCap);
        CoreFree(plaintext, CORE_AC_POOL_TAG_CRYPTO);
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG respPlainLen = 0;
    NTSTATUS opStatus = DispatchOperation(hdr.Operation, plaintext, ptLen,
                                          respPlain, respPlainCap, &respPlainLen);

    RtlSecureZeroMemory(plaintext, ptCap);
    CoreFree(plaintext, CORE_AC_POOL_TAG_CRYPTO);

    if (outLen < sizeof(AC_MUX_OUTPUT_HEADER))
    {
        RtlSecureZeroMemory(respPlain, respPlainCap);
        CoreFree(respPlain, CORE_AC_POOL_TAG_CRYPTO);
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        return CORE_AC_STATUS_BUFFER_TOO_SMALL;
    }

    PAC_MUX_OUTPUT_HEADER outHdr = (PAC_MUX_OUTPUT_HEADER)buf;
    RtlZeroMemory(outHdr, sizeof(*outHdr));
    outHdr->Magic = AC_MUX_OUTPUT_MAGIC;
    outHdr->HeaderVersion = AC_MUX_HEADER_VERSION;
    outHdr->Status = (ULONG)opStatus;

    if (respPlainLen > 0)
    {
        ULONG respCtCap = outLen - sizeof(AC_MUX_OUTPUT_HEADER);
        if (respCtCap < respPlainLen + 16)
        {
            RtlSecureZeroMemory(respPlain, respPlainCap);
            CoreFree(respPlain, CORE_AC_POOL_TAG_CRYPTO);
            RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
            return CORE_AC_STATUS_BUFFER_TOO_SMALL;
        }

        PUCHAR respCt = (PUCHAR)buf + sizeof(*outHdr);
        ULONG ctWritten = 0;
        s = CryptoSealRecord(sessionKey,
                             respPlain, respPlainLen,
                             respCt, respCtCap, &ctWritten,
                             outHdr->Nonce);
        RtlSecureZeroMemory(respPlain, respPlainCap);
        CoreFree(respPlain, CORE_AC_POOL_TAG_CRYPTO);
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        if (!NT_SUCCESS(s)) return s;

        outHdr->CiphertextLen = ctWritten;
        *written = sizeof(*outHdr) + ctWritten;
    }
    else
    {
        RtlSecureZeroMemory(respPlain, respPlainCap);
        CoreFree(respPlain, CORE_AC_POOL_TAG_CRYPTO);
        RtlSecureZeroMemory(sessionKey, sizeof(sessionKey));
        *written = sizeof(*outHdr);
    }

    return STATUS_SUCCESS;
}

NTSTATUS CoreIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = isl->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = isl->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = isl->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG written = 0;
    NTSTATUS s = STATUS_INVALID_DEVICE_REQUEST;

    (VOID)AcTamperCheckLstar();

    switch (code)
    {
    case IOCTL_AC_PING:
        s = HandlePing(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_BOOTSTRAP:
        s = HandleBootstrap(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_KEY_EXCHANGE:
        s = HandleKeyExchange(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_MUX:
        s = HandleMux(buf, inLen, outLen, &written);
        break;
    default:
        break;
    }

    return CompleteIrp(Irp, s, written);
}
