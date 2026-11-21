#include "core.h"
#include "imports.h"
#include "imports_hash.h"
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
#include "hook_audit.h"
#include "overlay_detect.h"
#include "dma_detect.h"
#include "image_backing.h"
#include "win32k_guard.h"
#include "mouse_polling.h"
#include "secureboot_attest.h"
#include "hvci_require.h"
#include "os_version_gate.h"
#include "vbs_require.h"
#include "iommu_require.h"
#include "tpm_attest.h"
#include "sus_threads.h"
#include "vhd_detect.h"
#include "handler_gate.h"
#include "ac_asm.h"
#include "ac_anchor.h"
#include "ssdt_integrity.h"
#include "dxgk_guard.h"
#include "hv_probe.h"

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

    // anchor must come before the first ioctl is ever dispatched so the
    // caller-RIP check has bounds to compare against. without bounds the
    // check short-circuits to "ok", which is still safe — but if we armed
    // anchor after import resolve we'd miss the dispatcher window.
    status = AcAnchorInit(DriverObject);
    if (!NT_SUCCESS(status))
    {
        CORE_LOG("AnchorInit failed: 0x%08X", status);
        return status;
    }

    status = AcImportsResolve(DriverObject);
    if (!NT_SUCCESS(status))
    {
        CORE_LOG("imports resolve failed: 0x%08X", status);
        return status;
    }

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

    status = HandlerGateInit();
    if (!NT_SUCCESS(status)) { CORE_LOG("HandlerGateInit failed: 0x%08X", status); goto fail; }

    g_Core.SwitcherStackBase = CoreAlloc(AC_SWITCHER_STACK_BYTES, CORE_AC_POOL_TAG);
    if (g_Core.SwitcherStackBase)
    {
        UCHAR *top = (UCHAR *)g_Core.SwitcherStackBase + AC_SWITCHER_STACK_BYTES;
        top = (UCHAR *)((ULONG_PTR)top & ~(ULONG_PTR)0xF);
        g_Core.SwitcherStackTop = top;
    }

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

    (VOID)HookAuditInit();
    (VOID)HookAuditRegisterCallbacks();

    (VOID)OverlayDetectInit();

    (VOID)DmaDetectInit();
    (VOID)DmaDetectSnapshot();

    (VOID)ImageBackingInit();
    (VOID)ImageBackingBaseline();

    (VOID)Win32kGuardInit();
    (VOID)Win32kGuardBaseline();

    (VOID)MousePollingInit();
    (VOID)MousePollingDiscoverDevices();
    (VOID)MousePollingStart();

    (VOID)SecureBootAttestInit();
    (VOID)SecureBootAttestBaseline();

    (VOID)HvciRequireInit();
    (VOID)HvciRequireBaseline();

    (VOID)OsVersionGateInit();
    (VOID)OsVersionGateBaseline();

    (VOID)VbsRequireInit();
    (VOID)VbsRequireBaseline();

    (VOID)IommuRequireInit();
    (VOID)IommuRequireBaseline();

    (VOID)TpmAttestInit();
    (VOID)TpmAttestBaseline();
    (VOID)HwidRefreshTpmBinding();

    (VOID)SusThreadsInit();

    (VOID)VhdDetectInit();
    (VOID)VhdDetectSnapshot();

    (VOID)HvProbeInit();

    // ssdt baseline needs the page walker alive (it runs its own PwInit but
    // image_backing already initialized it a few steps back) and needs
    // imports resolved so the hot nt* exports can be looked up.
    (VOID)SsdtIntegrityInit();
    (VOID)SsdtIntegrityBaseline();

    // dxgk baseline is lazy — dxgkrnl is usually not resident yet at this
    // point. init stores the name hash; baseline retries from the
    // heartbeat until the display stack comes up.
    (VOID)DxgkGuardInit();
    (VOID)DxgkGuardBaseline();

    status = CoreStartWorker();
    if (!NT_SUCCESS(status)) { CORE_LOG("StartWorker failed: 0x%08X", status); goto fail; }

    // every baseline is armed. flip the readiness xor-pair so HandleMux
    // stops rejecting post-handshake operations. kept last on purpose —
    // if StartWorker failed we never arm readiness, and the ioctl surface
    // stays in the pre-init tar-pit until shutdown.
    AcTamperSetInitComplete();

    InterlockedExchange(&g_Core.InitState, 2);
    CORE_LOG("Core_ac ready");
    return;

fail:
    InterlockedExchange(&g_Core.InitState, 3);
    HookAuditUnregisterCallbacks();
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

static NTSTATUS CoreRegisterCallbacks(VOID)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (AcPsSetLoadImageNotifyRoutineEx)
    {
        status = AcPsSetLoadImageNotifyRoutineEx(CoreImageLoadNotify,
                                                 PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);
    }
    if (!NT_SUCCESS(status))
    {
        status = AcPsSetLoadImageNotifyRoutine(CoreImageLoadNotify);
        if (!NT_SUCCESS(status)) return status;
    }
    g_Core.LoadImageCookie = (PVOID)CoreImageLoadNotify;

    status = AcPsSetCreateProcessNotifyRoutineEx(CoreCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        AcPsRemoveLoadImageNotifyRoutine(CoreImageLoadNotify);
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
        AcPsSetCreateProcessNotifyRoutineEx(CoreCreateProcessNotify, TRUE);
        g_Core.CreateProcessCookie = NULL;
    }
    if (g_Core.LoadImageCookie)
    {
        AcPsRemoveLoadImageNotifyRoutine(CoreImageLoadNotify);
        g_Core.LoadImageCookie = NULL;
    }
}

static VOID CoreImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo) return;

    if (ImageInfo->SystemModeImage)
    {
        if (HandlerGateAllowed(AC_H_BYOVD))     (VOID)ByovdScannerOnImageLoad(FullImageName, ImageInfo);
        if (HandlerGateAllowed(AC_H_KLDR))      (VOID)KldrOnKernelImageLoad(FullImageName, ImageInfo);
        if (HandlerGateAllowed(AC_H_IMAGEBACK)) (VOID)ImageBackingOnKernelImageLoad(FullImageName, ImageInfo);
    }
    else
    {
        if (HandlerGateAllowed(AC_H_GAMEINT))   (VOID)GameIntegrityOnUserImageLoad(ProcessId, FullImageName, ImageInfo);
        if (HandlerGateAllowed(AC_H_HOOKAUDIT)) (VOID)HookAuditOnUserImageLoad(ProcessId, FullImageName, ImageInfo);
    }
}

static VOID CoreCreateProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo)
    {
        (VOID)EventsReportProcessAttach(ProcessId, CreateInfo);
        OverlayDetectOnProcessCreate(ProcessId, CreateInfo->ParentProcessId);
    }
    else
    {
        (VOID)Pml4UnregisterGameProcessByPid(ProcessId);
        (VOID)GameIntegrityOnProcessExit(ProcessId);
        OverlayDetectOnProcessExit(ProcessId);
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
            if (HandlerGateAllowed(AC_H_TAMPER))
            {
                NmiWatchdogRequestCrossCpuSweep();

                ULONG nmiReason = 0;
                ULONG64 nmiObserved = 0;
                if (AcTamperDrainNmiFlags(&nmiReason, &nmiObserved))
                {
                    (VOID)AcTamperOnViolation(nmiReason, (PVOID)nmiObserved);
                }
            }

            if (HandlerGateAllowed(AC_H_HEARTBEAT))
            {
                (VOID)EventsEmitHeartbeat();
                (VOID)EventsEmitAllModuleHeartbeats();
            }
            if (HandlerGateAllowed(AC_H_PML4))       (VOID)Pml4Rescan();
            if (HandlerGateAllowed(AC_H_KLDR))       (VOID)KldrDiffScan();
            if (HandlerGateAllowed(AC_H_EXECREGION)) (VOID)ExecRegionScanDiff();
            if (HandlerGateAllowed(AC_H_INPUTINTG))  (VOID)InputIntegrityVerify();
            if (HandlerGateAllowed(AC_H_ROOTKIT))    (VOID)TamperRootkitVerify();
            if (HandlerGateAllowed(AC_H_DMA))        (VOID)DmaDetectVerify();
            if (HandlerGateAllowed(AC_H_IMAGEBACK))  (VOID)ImageBackingVerify();
            if (HandlerGateAllowed(AC_H_WIN32K))     (VOID)Win32kGuardVerify();
            if (HandlerGateAllowed(AC_H_MOUSEPOLL))  (VOID)MousePollingVerify();
            if (HandlerGateAllowed(AC_H_SECUREBOOT)) (VOID)SecureBootAttestVerify();
            if (HandlerGateAllowed(AC_H_HVCI))       (VOID)HvciRequireVerify();
            if (HandlerGateAllowed(AC_H_OSVERSION))  (VOID)OsVersionGateVerify();
            if (HandlerGateAllowed(AC_H_VBS))        (VOID)VbsRequireVerify();
            if (HandlerGateAllowed(AC_H_IOMMU))      (VOID)IommuRequireVerify();
            if (HandlerGateAllowed(AC_H_TPM))        (VOID)TpmAttestVerify();
            if (HandlerGateAllowed(AC_H_SUSTHREADS)) (VOID)SusThreadsVerify();
            if (HandlerGateAllowed(AC_H_VHD))        (VOID)VhdDetectVerify();
            if (HandlerGateAllowed(AC_H_ENV))        (VOID)HvProbeVerify();
            if (HandlerGateAllowed(AC_H_SSDT))       (VOID)SsdtIntegrityVerify();
            if (HandlerGateAllowed(AC_H_DXGK))       (VOID)DxgkGuardVerify();
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
    AcTamperClearInitComplete();
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
    HookAuditUnregisterCallbacks();
    AcTamperDisarm();
    DxgkGuardShutdown();
    SsdtIntegrityShutdown();
    VhdDetectShutdown();
    SusThreadsShutdown();
    TpmAttestShutdown();
    IommuRequireShutdown();
    VbsRequireShutdown();
    OsVersionGateShutdown();
    HvciRequireShutdown();
    SecureBootAttestShutdown();
    MousePollingShutdown();
    Win32kGuardShutdown();
    ImageBackingShutdown();
    DmaDetectShutdown();
    OverlayDetectShutdown();
    HookAuditShutdown();
    TamperRootkitShutdown();
    InputIntegrityShutdown();
    ExecRegionScanShutdown();
    GameIntegrityShutdown();
    Pml4ClearWatched();
    HvProbeShutdown();
    HandlerGateShutdown();
    ChannelShutdown();
    EventsShutdown();
    CryptoShutdown();

    if (g_Core.SwitcherStackBase)
    {
        CoreFree(g_Core.SwitcherStackBase, CORE_AC_POOL_TAG);
        g_Core.SwitcherStackBase = NULL;
        g_Core.SwitcherStackTop = NULL;
    }

    if (g_Core.SymLink.Buffer)
    {
        IoDeleteSymbolicLink(&g_Core.SymLink);
        RtlZeroMemory(&g_Core.SymLink, sizeof(g_Core.SymLink));
    }
    if (g_Core.ControlDevice) { IoDeleteDevice(g_Core.ControlDevice); g_Core.ControlDevice = NULL; }
    if (g_Core.EventDevice)   { IoDeleteDevice(g_Core.EventDevice);   g_Core.EventDevice = NULL; }
}
