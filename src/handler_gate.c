#include "handler_gate.h"

typedef struct _AC_GATE_STATE
{
    KSPIN_LOCK  Lock;
    UCHAR       Flags[AC_GATE_FLAG_BYTES];
    ULONG       Epoch;
    ULONG64     LastCookie;
    volatile LONG Ready;
} AC_GATE_STATE, *PAC_GATE_STATE;

static AC_GATE_STATE g_Gate;

static VOID HandlerGateSetAllOn(UCHAR flags[AC_GATE_FLAG_BYTES])
{
    for (ULONG i = 0; i < AC_GATE_FLAG_BYTES; i++) flags[i] = 0xFF;
}

NTSTATUS HandlerGateInit(VOID)
{
    RtlZeroMemory(&g_Gate, sizeof(g_Gate));
    KeInitializeSpinLock(&g_Gate.Lock);
    HandlerGateSetAllOn(g_Gate.Flags);
    g_Gate.Epoch = 1;
    InterlockedExchange(&g_Gate.Ready, 1);
    return STATUS_SUCCESS;
}

VOID HandlerGateShutdown(VOID)
{
    InterlockedExchange(&g_Gate.Ready, 0);
}

BOOLEAN HandlerGateAllowed(AC_HANDLER_ID id)
{
    if (!InterlockedCompareExchange(&g_Gate.Ready, 0, 0)) return TRUE;
    if ((ULONG)id >= AC_HANDLER_COUNT) return TRUE;

    UCHAR bit = AC_GATE_BIT_INDEX(id);
    UCHAR b   = g_Gate.Flags[bit >> 3];
    return ((b >> (bit & 7)) & 1) != 0;
}

ULONG HandlerGateEpoch(VOID)
{
    return (ULONG)InterlockedCompareExchange((volatile LONG *)&g_Gate.Epoch, 0, 0);
}

static ULONG64 HandlerGateExpectedCookie(const AC_GATE_PUSH *p)
{
    ULONG64 h = 0xCBF29CE484222325ULL;
    const UCHAR *s = (const UCHAR *)p;
    SIZE_T n = FIELD_OFFSET(AC_GATE_PUSH, ValidationCookie);
    for (SIZE_T i = 0; i < n; i++)
    {
        h ^= s[i];
        h *= 0x100000001B3ULL;
    }
    h ^= (ULONG64)p->Magic * 0x9E3779B185EBCA87ULL;
    return h;
}

NTSTATUS HandlerGateApply(const UCHAR *blob, ULONG len)
{
    if (!blob || len < sizeof(AC_GATE_PUSH)) return STATUS_INVALID_PARAMETER;

    AC_GATE_PUSH push;
    RtlCopyMemory(&push, blob, sizeof(push));

    if (push.Magic != AC_GATE_PUSH_MAGIC) return STATUS_INVALID_PARAMETER;

    ULONG64 expected = HandlerGateExpectedCookie(&push);
    if (expected != push.ValidationCookie) return STATUS_INVALID_PARAMETER;

    KIRQL irql;
    KeAcquireSpinLock(&g_Gate.Lock, &irql);

    if (push.Epoch <= g_Gate.Epoch)
    {
        KeReleaseSpinLock(&g_Gate.Lock, irql);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(g_Gate.Flags, push.Flags, AC_GATE_FLAG_BYTES);
    g_Gate.Epoch = push.Epoch;
    g_Gate.LastCookie = push.ValidationCookie;

    KeReleaseSpinLock(&g_Gate.Lock, irql);
    return STATUS_SUCCESS;
}

VOID HandlerGateSnapshot(UCHAR flagsOut[AC_GATE_FLAG_BYTES], ULONG *epochOut)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Gate.Lock, &irql);
    if (flagsOut) RtlCopyMemory(flagsOut, g_Gate.Flags, AC_GATE_FLAG_BYTES);
    if (epochOut) *epochOut = g_Gate.Epoch;
    KeReleaseSpinLock(&g_Gate.Lock, irql);
}
