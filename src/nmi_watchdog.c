#include "nmi_watchdog.h"
#include "anti_tamper.h"

NTKERNELAPI PVOID NTAPI KeRegisterNmiCallback(PNMI_CALLBACK CallbackRoutine, PVOID Context);
NTKERNELAPI NTSTATUS NTAPI KeDeregisterNmiCallback(PVOID Handle);
NTKERNELAPI VOID NTAPI HalSendNMI(KAFFINITY ProcessorMask);

static BOOLEAN NmiCallback(PVOID Context, BOOLEAN Handled);

static volatile LONG g_InSweep = 0;

NTSTATUS NmiWatchdogRegister(VOID)
{
    if (g_Core.NmiCallbackHandle) return STATUS_ALREADY_REGISTERED;

    PVOID h = KeRegisterNmiCallback(NmiCallback, NULL);
    if (!h) return STATUS_INSUFFICIENT_RESOURCES;

    g_Core.NmiCallbackHandle = h;
    return STATUS_SUCCESS;
}

VOID NmiWatchdogUnregister(VOID)
{
    if (!g_Core.NmiCallbackHandle) return;
    (VOID)KeDeregisterNmiCallback(g_Core.NmiCallbackHandle);
    g_Core.NmiCallbackHandle = NULL;
}

VOID NmiWatchdogRequestCrossCpuSweep(VOID)
{
    if (InterlockedCompareExchange(&g_InSweep, 1, 0) != 0) return;

    KAFFINITY active = KeQueryActiveProcessors();
    KAFFINITY self = (KAFFINITY)1ULL << KeGetCurrentProcessorNumberEx(NULL);
    KAFFINITY target = active & ~self;

    if (target != 0) HalSendNMI(target);

    InterlockedExchange(&g_InSweep, 0);
}

static BOOLEAN NmiCallback(PVOID Context, BOOLEAN Handled)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Handled);

    (VOID)AcTamperCheckLstarFromNmi();
    (VOID)AcTamperCheckDebugCtlFromNmi();

    return FALSE;
}
