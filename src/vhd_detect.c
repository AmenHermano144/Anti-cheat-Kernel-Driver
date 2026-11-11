#include "vhd_detect.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "strings.h"
#include "wire_records.h"

#define VHD_MAX_DEVICES         32
#define VHD_POOL_TAG            'dVcA'

NTKERNELAPI NTSTATUS NTAPI IoVolumeDeviceToDosName(
    PVOID           VolumeDeviceObject,
    PUNICODE_STRING DosName);

typedef struct _VHD_BASELINE_ENTRY
{
    ULONG64 DeviceObject;
} VHD_BASELINE_ENTRY, *PVHD_BASELINE_ENTRY;

static VHD_BASELINE_ENTRY g_Baseline[VHD_MAX_DEVICES];
static volatile LONG      g_BaselineCount = 0;
static volatile LONG      g_Initialized   = 0;
static volatile LONG      g_Flag          = 0;

static const WCHAR *const g_VhdDriverNames[] =
{
    L"\\Driver\\vhdmp",
    L"\\Driver\\storvsp",
    L"\\Driver\\arcsas",
    NULL
};

NTSTATUS VhdDetectInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));
    g_BaselineCount = 0;
    g_Flag = 0;
    return STATUS_SUCCESS;
}

VOID VhdDetectShutdown(VOID)
{
    if (InterlockedExchange(&g_Initialized, 0) == 0) return;
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));
    g_BaselineCount = 0;
}

ULONG VhdDetectGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID VhdDetectClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

static BOOLEAN BaselineContains(ULONG64 devPtr)
{
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    for (LONG i = 0; i < n; i++)
    {
        if (g_Baseline[i].DeviceObject == devPtr) return TRUE;
    }
    return FALSE;
}

static VOID BaselineAppend(ULONG64 devPtr)
{
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    if (n >= VHD_MAX_DEVICES) return;
    g_Baseline[n].DeviceObject = devPtr;
    InterlockedIncrement(&g_BaselineCount);
}

static VOID FillDriverName(PDRIVER_OBJECT drv, WCHAR *outBuf, USHORT outCapWchars, USHORT *outLen)
{
    *outLen = 0;
    if (!drv) return;

    PUNICODE_STRING name = &drv->DriverName;
    if (!name->Buffer || name->Length == 0) return;

    USHORT nWchars = name->Length / sizeof(WCHAR);
    if (nWchars >= outCapWchars) nWchars = outCapWchars - 1;
    RtlCopyMemory(outBuf, name->Buffer, nWchars * sizeof(WCHAR));
    outBuf[nWchars] = 0;
    *outLen = (USHORT)(nWchars * sizeof(WCHAR));
}

static VOID TryFillDosName(PDEVICE_OBJECT dev, WCHAR *outBuf, USHORT outCapWchars, USHORT *outLen)
{
    *outLen = 0;
    UNICODE_STRING dos;
    RtlZeroMemory(&dos, sizeof(dos));

    NTSTATUS s = IoVolumeDeviceToDosName(dev, &dos);
    if (!NT_SUCCESS(s)) return;

    if (dos.Buffer && dos.Length > 0)
    {
        USHORT nWchars = dos.Length / sizeof(WCHAR);
        if (nWchars >= outCapWchars) nWchars = outCapWchars - 1;
        RtlCopyMemory(outBuf, dos.Buffer, nWchars * sizeof(WCHAR));
        outBuf[nWchars] = 0;
        *outLen = (USHORT)(nWchars * sizeof(WCHAR));
    }

    if (dos.Buffer) ExFreePool(dos.Buffer);
}

static VOID EmitMount(PDEVICE_OBJECT dev, PDRIVER_OBJECT drv, BOOLEAN hotplug)
{
    WIRE_VHD_MOUNT rec;
    RtlZeroMemory(&rec, sizeof(rec));

    rec.DeviceObject = (ULONG64)(ULONG_PTR)dev;

    PDEVICE_OBJECT lower = NULL;
    __try
    {
        lower = IoGetLowerDeviceObject(dev);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        lower = NULL;
    }

    if (lower)
    {
        rec.LowerDevice = (ULONG64)(ULONG_PTR)lower;
        ObDereferenceObject(lower);
    }

    FillDriverName(drv, rec.DriverName, 64, &rec.DriverNameLen);
    TryFillDosName(dev, rec.VolumePath, 260, &rec.VolumePathLen);

    ULONG flags = hotplug ? VHD_FLAG_HOTPLUG_MOUNT : VHD_FLAG_PRESENT_AT_BOOT;
    if (rec.VolumePathLen == 0) flags |= VHD_FLAG_MISSING_DOSNAME;
    if (hotplug) flags |= VHD_FLAG_SUSPICIOUS;
    rec.Flags = flags;

    (VOID)EventsReportVhdMount(&rec);

    if (hotplug)
    {
        (VOID)EventsReportTamper(AC_TAMPER_REASON_VHD_MOUNT, (PVOID)(ULONG_PTR)dev);
    }

    InterlockedOr(&g_Flag, (LONG)flags);
}

static VOID WalkDriverDevices(const WCHAR *driverPath, BOOLEAN baselinePass)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, driverPath);

    PDRIVER_OBJECT drv = NULL;
    NTSTATUS s = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0,
                                         *IoDriverObjectType, KernelMode, NULL,
                                         (PVOID *)&drv);
    if (!NT_SUCCESS(s) || !drv) return;

    ULONG guard = 0;
    for (PDEVICE_OBJECT dev = drv->DeviceObject; dev && guard < 1024; dev = dev->NextDevice, guard++)
    {
        ULONG64 devPtr = (ULONG64)(ULONG_PTR)dev;

        if (baselinePass)
        {
            BaselineAppend(devPtr);
            EmitMount(dev, drv, FALSE);
        }
        else if (!BaselineContains(devPtr))
        {
            BaselineAppend(devPtr);
            EmitMount(dev, drv, TRUE);
        }
    }

    ObDereferenceObject(drv);
}

NTSTATUS VhdDetectSnapshot(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    for (ULONG i = 0; g_VhdDriverNames[i] != NULL; i++)
    {
        WalkDriverDevices(g_VhdDriverNames[i], TRUE);
    }
    return STATUS_SUCCESS;
}

NTSTATUS VhdDetectVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    for (ULONG i = 0; g_VhdDriverNames[i] != NULL; i++)
    {
        WalkDriverDevices(g_VhdDriverNames[i], FALSE);
    }
    return STATUS_SUCCESS;
}
