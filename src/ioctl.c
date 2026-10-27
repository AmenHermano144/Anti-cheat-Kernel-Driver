#include "ioctl.h"
#include "channels.h"
#include "crypto.h"
#include "anti_tamper.h"
#include "events.h"
#include "hwid.h"
#include "strings.h"
#include "overlay_detect.h"

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

    UCHAR serverPub[32];
    NTSTATUS s = CryptoHandshake((const UCHAR *)buf, serverPub, g_Core.SessionKey);
    if (!NT_SUCCESS(s)) return s;

    RtlCopyMemory(buf, serverPub, 32);
    *written = 32;
    InterlockedExchange(&g_Core.SessionActive, 1);
    return STATUS_SUCCESS;
}

static NTSTATUS HandlePushSessionUuid(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    if (!InterlockedCompareExchange(&g_Core.SessionActive, 0, 0)) return CORE_AC_STATUS_NO_SESSION;
    if (inLen < sizeof(GUID) || !buf) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&g_Core.SessionGuid, buf, sizeof(GUID));
    return STATUS_SUCCESS;
}

static NTSTATUS HandleEventPoll(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(inLen);
    if (!buf || outLen == 0) return STATUS_INVALID_PARAMETER;
    return ChannelDrainEvents(buf, outLen, written);
}

static NTSTATUS HandleMatchOver(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(buf); UNREFERENCED_PARAMETER(inLen); UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    (VOID)EventsReportTeardown();
    return STATUS_SUCCESS;
}

static NTSTATUS HandlePushHash(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    if (!buf || inLen == 0) return STATUS_INVALID_PARAMETER;
    return ChannelAcceptBlob(CHANNEL_BLOB_HASH, buf, inLen);
}

static NTSTATUS HandlePushWatchlist(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    if (!buf || inLen == 0) return STATUS_INVALID_PARAMETER;
    return ChannelAcceptBlob(CHANNEL_BLOB_WATCHLIST, buf, inLen);
}

static NTSTATUS HandleReportWindow(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(outLen);
    *written = 0;
    if (!buf || inLen < sizeof(OVERLAY_WINDOW_REPORT)) return STATUS_INVALID_PARAMETER;
    return OverlayDetectEvaluateReport((const OVERLAY_WINDOW_REPORT *)buf);
}

static NTSTATUS HandleQueryOverlayFlag(PVOID buf, ULONG inLen, ULONG outLen, ULONG *written)
{
    UNREFERENCED_PARAMETER(inLen);
    *written = 0;
    if (!buf || outLen < sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
    ULONG value = OverlayDetectGetFlag();
    RtlCopyMemory(buf, &value, sizeof(value));
    *written = sizeof(value);
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
    case IOCTL_AC_PUSH_SESSION_UUID:
        s = HandlePushSessionUuid(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_EVENT_POLL:
        s = HandleEventPoll(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_MATCH_OVER:
        s = HandleMatchOver(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_PUSH_HASH:
        s = HandlePushHash(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_PUSH_WATCHLIST:
        s = HandlePushWatchlist(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_PUSH_MATCH:
        if (!buf || inLen == 0) { s = STATUS_INVALID_PARAMETER; break; }
        s = ChannelAcceptBlob(CHANNEL_BLOB_MATCH, buf, inLen);
        break;
    case IOCTL_AC_PUSH_PROCESS_PATH:
        if (!buf || inLen == 0) { s = STATUS_INVALID_PARAMETER; break; }
        s = ChannelAcceptBlob(CHANNEL_BLOB_PROCESS, buf, inLen);
        break;
    case IOCTL_AC_PUSH_VENDOR_CN:
        if (!buf || inLen == 0) { s = STATUS_INVALID_PARAMETER; break; }
        s = ChannelAcceptBlob(CHANNEL_BLOB_VENDOR, buf, inLen);
        break;
    case IOCTL_AC_PUSH_USB_DEVICE:
        if (!buf || inLen == 0) { s = STATUS_INVALID_PARAMETER; break; }
        s = ChannelAcceptBlob(CHANNEL_BLOB_USB, buf, inLen);
        break;
    case IOCTL_AC_PUSH_U64_SET:
    case IOCTL_AC_PUSH_CMD:
    case IOCTL_AC_DRIVER_EVENT:
        if (!buf || inLen == 0) { s = STATUS_INVALID_PARAMETER; break; }
        s = ChannelAcceptBlob(CHANNEL_BLOB_GENERIC, buf, inLen);
        break;
    case IOCTL_AC_REPORT_WINDOW:
        s = HandleReportWindow(buf, inLen, outLen, &written);
        break;
    case IOCTL_AC_QUERY_OVERLAY_FLAG:
        s = HandleQueryOverlayFlag(buf, inLen, outLen, &written);
        break;
    default:
        break;
    }

    return CompleteIrp(Irp, s, written);
}
