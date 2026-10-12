#include "anti_tamper.h"
#include "events.h"

#define IA32_LSTAR_MSR          0xC0000082
#define IA32_DEBUGCTL_MSR       0x000001D9
#define IA32_DEBUGCTL_LBR_BIT   (1ULL << 0)

static ULONG64 g_StackCookieRef[2];
static volatile LONG g_Armed = 0;

static volatile LONG   g_NmiFlagsPending = 0;
static volatile LONG   g_NmiReason = 0;
static volatile LONG64 g_NmiObserved = 0;

VOID AcTamperInitBootCookie(VOID)
{
    LARGE_INTEGER perf;
    perf = KeQueryPerformanceCounter(NULL);
    g_Core.BootPerfCounter = perf;

    ULONG64 tsc = __rdtsc();
    ULONG64 seed = perf.QuadPart ^ tsc ^ ((ULONG64)PsGetCurrentProcessId() << 17);

    g_Core.BootCookie[0] = seed;
    g_Core.BootCookie[1] = ~seed;

    g_StackCookieRef[0] = tsc ^ 0xA5A5A5A5A5A5A5A5ULL;
    g_StackCookieRef[1] = ~g_StackCookieRef[0];
}

NTSTATUS AcTamperArm(VOID)
{
    ULONG64 lstar = __readmsr(IA32_LSTAR_MSR);
    g_Core.LstarReference[0] = lstar;
    g_Core.LstarReference[1] = ~lstar;
    InterlockedExchange(&g_Armed, 1);
    return STATUS_SUCCESS;
}

VOID AcTamperDisarm(VOID)
{
    InterlockedExchange(&g_Armed, 0);
    g_Core.LstarReference[0] = 0;
    g_Core.LstarReference[1] = 0;
}

BOOLEAN AcTamperCheckLstar(VOID)
{
    if (!InterlockedCompareExchange(&g_Armed, 0, 0)) return TRUE;

    ULONG64 cur = __readmsr(IA32_LSTAR_MSR);
    if (cur != g_Core.LstarReference[0])
    {
        AcTamperOnViolation(AC_TAMPER_REASON_LSTAR, (PVOID)cur);
        __writemsr(IA32_LSTAR_MSR, g_Core.LstarReference[0]);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN AcTamperCheckLstarFromNmi(VOID)
{
    if (!InterlockedCompareExchange(&g_Armed, 0, 0)) return TRUE;

    ULONG64 cur = __readmsr(IA32_LSTAR_MSR);
    if (cur != g_Core.LstarReference[0])
    {
        AcTamperOnViolationFromNmi(AC_TAMPER_REASON_LSTAR, cur);
        __writemsr(IA32_LSTAR_MSR, g_Core.LstarReference[0]);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN AcTamperCheckDebugCtlFromNmi(VOID)
{
    ULONG64 dbg = __readmsr(IA32_DEBUGCTL_MSR);
    if (dbg & IA32_DEBUGCTL_LBR_BIT)
    {
        AcTamperOnViolationFromNmi(AC_TAMPER_REASON_DEBUGCTL, dbg);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN AcTamperCheckStackCookie(VOID)
{
    ULONG64 cookie = g_StackCookieRef[0] ^ g_StackCookieRef[1];
    if (cookie != 0xFFFFFFFFFFFFFFFFULL)
    {
        AcTamperOnViolation(AC_TAMPER_REASON_STACK, (PVOID)cookie);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN AcTamperCheckDebugCtl(VOID)
{
    ULONG64 dbg = __readmsr(IA32_DEBUGCTL_MSR);
    if (dbg & IA32_DEBUGCTL_LBR_BIT)
    {
        AcTamperOnViolation(AC_TAMPER_REASON_DEBUGCTL, (PVOID)dbg);
        return FALSE;
    }
    return TRUE;
}

VOID AcTamperOnViolation(ULONG reasonCode, PVOID extra)
{
    (VOID)EventsReportTamper(reasonCode, extra);
}

VOID AcTamperOnViolationFromNmi(ULONG reasonCode, ULONG64 extra)
{
    InterlockedExchange(&g_NmiReason, (LONG)reasonCode);
    InterlockedExchange64(&g_NmiObserved, (LONG64)extra);
    InterlockedExchange(&g_NmiFlagsPending, 1);
}

BOOLEAN AcTamperDrainNmiFlags(ULONG *outReason, ULONG64 *outObserved)
{
    if (!InterlockedCompareExchange(&g_NmiFlagsPending, 0, 1)) return FALSE;
    if (outReason)   *outReason   = (ULONG)InterlockedCompareExchange(&g_NmiReason, 0, 0);
    if (outObserved) *outObserved = (ULONG64)InterlockedCompareExchange64(&g_NmiObserved, 0, 0);
    return TRUE;
}
