#include "core.h"
#include "imports.h"
#include "env_checks.h"
#include "anti_tamper.h"
#include "nmi_watchdog.h"
#include "ioctl.h"
#include "channels.h"
#include "events.h"
#include "crypto.h"
#include "kldr.h"
#include "byovd_scanner.h"
#include "pml4_scan.h"
#include "hwid.h"
#include "game_integrity.h"
#include "exec_region_scan.h"
#include "input_integrity.h"
#include "tamper_rootkit.h"

CORE_AC_GLOBAL g_Core;

DRIVER_UNLOAD CoreDriverUnload;

static VOID CoreImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
static VOID CoreCreateProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
static NTSTATUS CoreApplyDeviceDacl(PDEVICE_OBJECT DeviceObject);
static NTSTATUS CoreCreateDevices(VOID);
static NTSTATUS CoreStartWorker(VOID);
static VOID CorePollWorker(PVOID Context);
static NTSTATUS CoreRegisterCallbacks(VOID);
static VOID CoreUnregisterCallbacks(VOID);
static VOID CoreDeferredInit(PVOID Context);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    RtlSecureZeroMemory(&g_Core, sizeof(g_Core));
    g_Core.DriverObject = DriverObject;

    AcTamperInitBootCookie();

    status = EnvRunBootGates();
    if (!NT_SUCCESS(status))
    {
        CORE_LOG("boot gates failed: 0x%08X", status);
        return status;
    }

    InterlockedExchange(&g_Core.InitState, 1);

    DriverObject->DriverUnload = CoreDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CoreIoctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = CoreIoctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CoreIoctlDispatch;

    HANDLE deferredThread = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&deferredThread, THREAD_ALL_ACCESS, &oa, NULL, NULL,
                                  (PKSTART_ROUTINE)CoreDeferredInit, NULL);
    if (!NT_SUCCESS(status)) return status;
    ZwClose(deferredThread);

    return STATUS_SUCCESS;
}

static VOID CoreDeferredInit(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    NTSTATUS status;

    status = CoreCreateDevices();
    if (!NT_SUCCESS(status))
    {
        CORE_LOG("CreateDevices failed: 0x%08X", status);
        return;
    }

    status = ChannelInit();
    if (!NT_SUCCESS(status)) { CORE_LOG("ChannelInit failed: 0x%08X", status); goto fail; }

    status = CryptoInit();
    if (!NT_SUCCESS(status)) { CORE_LOG("CryptoInit failed: 0x%08X", status); goto fail; }

    status = EventsInit();
    if (!NT_SUCCESS(status)) { CORE_LOG("EventsInit failed: 0x%08X", status); goto fail; }

    status = AcTamperArm();
    if (!NT_SUCCESS(status)) { CORE_LOG("TamperArm failed: 0x%08X", status); goto fail; }

    status = NmiWatchdogRegister();
    if (!NT_SUCCESS(status)) { CORE_LOG("NmiWatchdog failed: 0x%08X", status); }

    status = CoreRegisterCallbacks();
    if (!NT_SUCCESS(status)) { CORE_LOG("Callbacks failed: 0x%08X", status); goto fail; }

    (VOID)KldrSnapshotModules();
    (VOID)Pml4InitSnapshot();
    (VOID)ByovdScannerInit();
    (VOID)GameIntegrityInit();
    (VOID)HwidCollectBoot();

    (VOID)ExecRegionScanInit();
    (VOID)ExecRegionScanSnapshot();

    (VOID)InputIntegrityInit();
    (VOID)InputIntegritySnapshot();

    (VOID)TamperRootkitInit();
    (VOID)TamperRootkitSnapshot();

    status = CoreStartWorker();
    if (!NT_SUCCESS(status)) { CORE_LOG("StartWorker failed: 0x%08X", status); goto fail; }

    InterlockedExchange(&g_Core.InitState, 2);
    CORE_LOG("Core_ac ready");
    return;

fail:
    InterlockedExchange(&g_Core.InitState, 3);
    CoreUnregisterCallbacks();
}

static NTSTATUS CoreCreateDevices(VOID)
{
    UNICODE_STRING devName, symName, evtName;
    RtlInitUnicodeString(&devName, CORE_AC_DEVICE_NAME);
    RtlInitUnicodeString(&symName, CORE_AC_DOSDEVICE_NAME);
    RtlInitUnicodeString(&evtName, CORE_AC_EVENT_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(g_Core.DriverObject,
                                     0, &devName,
                                     CORE_AC_DEVICE_TYPE,
                                     FILE_DEVICE_SECURE_OPEN,
                                     FALSE,
                                     &g_Core.ControlDevice);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_Core.ControlDevice);
        g_Core.ControlDevice = NULL;
        return status;
    }

    RtlCopyMemory(&g_Core.SymLink, &symName, sizeof(symName));
    g_Core.ControlDevice->Flags |= DO_BUFFERED_IO;
    g_Core.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateDevice(g_Core.DriverObject,
                            0, &evtName,
                            CORE_AC_EVENT_DEVICE_TYPE,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_Core.EventDevice);
    if (NT_SUCCESS(status))
    {
        g_Core.EventDevice->Flags |= DO_BUFFERED_IO;
        g_Core.EventDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    (VOID)CoreApplyDeviceDacl(g_Core.ControlDevice);
    if (g_Core.EventDevice) (VOID)CoreApplyDeviceDacl(g_Core.EventDevice);

    return STATUS_SUCCESS;
}

static NTSTATUS CoreApplyDeviceDacl(PDEVICE_OBJECT DeviceObject)
{
    UCHAR aclBuffer[256];
    PACL dacl = (PACL)aclBuffer;
    NTSTATUS status;

    status = RtlCreateAcl(dacl, sizeof(aclBuffer), ACL_REVISION);
    if (!NT_SUCCESS(status)) return status;

    SID systemSid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SYSTEM_RID } };
    struct
    {
        UCHAR  Revision;
        UCHAR  SubAuthorityCount;
        SID_IDENTIFIER_AUTHORITY Authority;
        ULONG  Sub[2];
    } adminSid = { SID_REVISION, 2, { SECURITY_NT_AUTHORITY },
                   { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS } };

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, &systemSid);
    if (!NT_SUCCESS(status)) return status;

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, (PSID)&adminSid);
    if (!NT_SUCCESS(status)) return status;

    UCHAR sdBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sdBuffer;

    status = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) return status;

    status = RtlSetDaclSecurityDescriptor(sd, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) return status;

    status = ObSetSecurityObjectByPointer(DeviceObject, DACL_SECURITY_INFORMATION, sd);
    return status;
}

typedef NTSTATUS (NTAPI *PFN_PsSetLoadImageNotifyRoutineEx)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine, ULONG_PTR Flags);

static NTSTATUS CoreRegisterCallbacks(VOID)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING exName;
    RtlInitUnicodeString(&exName, L"PsSetLoadImageNotifyRoutineEx");
    PFN_PsSetLoadImageNotifyRoutineEx pEx =
        (PFN_PsSetLoadImageNotifyRoutineEx)MmGetSystemRoutineAddress(&exName);

    if (pEx)
    {
        status = pEx(CoreImageLoadNotify, PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);
    }
    if (!NT_SUCCESS(status))
    {
        status = PsSetLoadImageNotifyRoutine(CoreImageLoadNotify);
        if (!NT_SUCCESS(status)) return status;
    }
    g_Core.LoadImageCookie = (PVOID)CoreImageLoadNotify;

    status = PsSetCreateProcessNotifyRoutineEx(CoreCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        PsRemoveLoadImageNotifyRoutine(CoreImageLoadNotify);
        g_Core.LoadImageCookie = NULL;
        return status;
    }
    g_Core.CreateProcessCookie = (PVOID)CoreCreateProcessNotify;
    return STATUS_SUCCESS;
}

static VOID CoreUnregisterCallbacks(VOID)
{
    if (g_Core.CreateProcessCookie)
    {
        PsSetCreateProcessNotifyRoutineEx(CoreCreateProcessNotify, TRUE);
        g_Core.CreateProcessCookie = NULL;
    }
    if (g_Core.LoadImageCookie)
    {
        PsRemoveLoadImageNotifyRoutine(CoreImageLoadNotify);
        g_Core.LoadImageCookie = NULL;
    }
}

static VOID CoreImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo) return;

    if (ImageInfo->SystemModeImage)
    {
        (VOID)ByovdScannerOnImageLoad(FullImageName, ImageInfo);
        (VOID)KldrOnKernelImageLoad(FullImageName, ImageInfo);
    }
    else
    {
        (VOID)GameIntegrityOnUserImageLoad(ProcessId, FullImageName, ImageInfo);
    }
}

static VOID CoreCreateProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo)
    {
        (VOID)EventsReportProcessAttach(ProcessId, CreateInfo);
    }
    else
    {
        (VOID)Pml4UnregisterGameProcessByPid(ProcessId);
        (VOID)EventsReportProcessExit(ProcessId);
    }
}

static NTSTATUS CoreStartWorker(VOID)
{
    KeInitializeEvent(&g_Core.WorkerWakeEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_Core.WorkerStopEvent, NotificationEvent, FALSE);
    KeInitializeTimer(&g_Core.HeartbeatTimer);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = PsCreateSystemThread(&g_Core.WorkerThreadHandle,
                                           THREAD_ALL_ACCESS,
                                           &oa, NULL, NULL,
                                           (PKSTART_ROUTINE)CorePollWorker, NULL);
    if (!NT_SUCCESS(status)) return status;

    status = ObReferenceObjectByHandle(g_Core.WorkerThreadHandle,
                                       THREAD_ALL_ACCESS, *PsThreadType,
                                       KernelMode, (PVOID *)&g_Core.WorkerThread, NULL);
    return status;
}

static VOID CorePollWorker(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER due;
    due.QuadPart = -300000000LL;
    KeSetTimer(&g_Core.HeartbeatTimer, due, NULL);

    PVOID objs[2] = { &g_Core.WorkerWakeEvent, &g_Core.HeartbeatTimer };

    while (!InterlockedCompareExchange(&g_Core.StopRequested, 0, 0))
    {
        NTSTATUS wait = KeWaitForMultipleObjects(2, objs, WaitAny, Executive,
                                                 KernelMode, FALSE, NULL, NULL);
        if (InterlockedCompareExchange(&g_Core.StopRequested, 0, 0)) break;

        if (wait == STATUS_WAIT_0)
        {
            KeClearEvent(&g_Core.WorkerWakeEvent);
            (VOID)ChannelFlushPending();
        }
        else
        {
            NmiWatchdogRequestCrossCpuSweep();

            ULONG nmiReason = 0;
            ULONG64 nmiObserved = 0;
            if (AcTamperDrainNmiFlags(&nmiReason, &nmiObserved))
            {
                (VOID)AcTamperOnViolation(nmiReason, (PVOID)nmiObserved);
            }
            (VOID)EventsEmitHeartbeat();
            (VOID)Pml4Rescan();
            (VOID)KldrDiffScan();
            (VOID)ExecRegionScanDiff();
            (VOID)InputIntegrityVerify();
            (VOID)TamperRootkitVerify();
            (VOID)ChannelFlushPending();
        }

        KeSetTimer(&g_Core.HeartbeatTimer, due, NULL);
    }

    KeCancelTimer(&g_Core.HeartbeatTimer);
    KeSetEvent(&g_Core.WorkerStopEvent, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID CoreDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    InterlockedExchange(&g_Core.InitState, 3);
    InterlockedExchange(&g_Core.StopRequested, 1);

    if (g_Core.WorkerThread)
    {
        KeSetEvent(&g_Core.WorkerWakeEvent, 0, FALSE);
        KeWaitForSingleObject(&g_Core.WorkerStopEvent, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Core.WorkerThread);
        g_Core.WorkerThread = NULL;
    }
    if (g_Core.WorkerThreadHandle)
    {
        ZwClose(g_Core.WorkerThreadHandle);
        g_Core.WorkerThreadHandle = NULL;
    }

    NmiWatchdogUnregister();
    CoreUnregisterCallbacks();
    AcTamperDisarm();
    TamperRootkitShutdown();
    InputIntegrityShutdown();
    ExecRegionScanShutdown();
    Pml4ClearWatched();
    ChannelShutdown();
    EventsShutdown();
    CryptoShutdown();

    if (g_Core.SymLink.Buffer)
    {
        IoDeleteSymbolicLink(&g_Core.SymLink);
        RtlZeroMemory(&g_Core.SymLink, sizeof(g_Core.SymLink));
    }
    if (g_Core.ControlDevice) { IoDeleteDevice(g_Core.ControlDevice); g_Core.ControlDevice = NULL; }
    if (g_Core.EventDevice)   { IoDeleteDevice(g_Core.EventDevice);   g_Core.EventDevice = NULL; }
}
