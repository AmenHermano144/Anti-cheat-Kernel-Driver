#include "mouse_polling.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"

#define MP_MAX_DEVICES              8
#define MP_WINDOW_SIZE              100
#define MP_TIMER_PERIOD_MS          1
#define MP_MIN_SAMPLES              30

#define MP_MOUCLASS_WRITE_POINTER   0x70
#define MP_MOUCLASS_READ_POINTER    0x78
#define MP_MOUCLASS_QUEUE_SIZE      0x88
#define MP_MOUCLASS_DATA_QUEUE_BASE 0x68
#define MP_MOUSE_INPUT_SIZE         24

#define MP_BURST_RATE_INJECTION_BP  2000
#define MP_BURST_RATE_SUSPECT_BP    1000
#define MP_STDDEV_INJECTION_US      15
#define MP_STDDEV_SUSPECT_US        60
#define MP_HZ_IMPOSSIBLE            10000
#define MP_MAX_PKTS_PER_TICK        20

typedef struct _MP_DEVICE
{
    BOOLEAN         Valid;
    PDEVICE_OBJECT  ClassDevice;
    PUCHAR          DevExtensionBase;
    ULONG           QueueSize;
    ULONG           LastWritePointer;
    LONG64          LastTicks;
    LONG64          LastPacketTicks;

    KSPIN_LOCK      Lock;

    LONG64          Intervals[MP_WINDOW_SIZE];
    ULONG           Head;
    ULONG           Filled;
    LONG64          WindowSum;
    ULONG           WindowBursts;
    ULONG           MaxPacketsPerTick;

    ULONG64         TotalMovePackets;
    ULONG64         TotalBursts;

    LARGE_INTEGER   InstantQueue[256];
    ULONG           InstantHead;
    ULONG           InstantFilled;
} MP_DEVICE, *PMP_DEVICE;

static MP_DEVICE          g_Devices[MP_MAX_DEVICES];
static ULONG              g_DeviceCount = 0;
static KTIMER             g_Timer;
static KDPC               g_TimerDpc;
static volatile LONG      g_TimerRunning = 0;
static volatile LONG      g_Initialized = 0;
static LARGE_INTEGER      g_PerfFreq;
static LONG64             g_BurstThresholdTicks;
static LONG64             g_OneSecondTicks;

static LONG64 MpIntSqrt(LONG64 n)
{
    if (n <= 0) return 0;
    LONG64 x = n;
    LONG64 y = (x + 1) / 2;
    while (y < x)
    {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

static LONG64 MpTicksToMicros(LONG64 t)
{
    if (g_PerfFreq.QuadPart == 0) return 0;
    return (t * 1000000LL) / g_PerfFreq.QuadPart;
}

static BOOLEAN MpSanityCheckDevice(PUCHAR devExt, ULONG *outQueueSize)
{
    *outQueueSize = 0;
    if (!devExt) return FALSE;

    __try
    {
        ULONG qs  = *(ULONG *)(devExt + MP_MOUCLASS_QUEUE_SIZE);
        ULONG wp  = *(ULONG *)(devExt + MP_MOUCLASS_WRITE_POINTER);
        ULONG rp  = *(ULONG *)(devExt + MP_MOUCLASS_READ_POINTER);
        PVOID qb  = *(PVOID *)(devExt + MP_MOUCLASS_DATA_QUEUE_BASE);

        if (qs < MP_MOUSE_INPUT_SIZE * 8)  return FALSE;
        if (qs > 0x10000)                   return FALSE;
        if ((qs % MP_MOUSE_INPUT_SIZE) != 0) return FALSE;
        if (wp >= qs) return FALSE;
        if (rp >= qs) return FALSE;
        if (!qb) return FALSE;
        if ((ULONG_PTR)qb < 0xFFFF000000000000ULL) return FALSE;

        *outQueueSize = qs;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static VOID MpResetWindow(PMP_DEVICE dev)
{
    RtlZeroMemory(dev->Intervals, sizeof(dev->Intervals));
    dev->Head = 0;
    dev->Filled = 0;
    dev->WindowSum = 0;
    dev->WindowBursts = 0;
    dev->MaxPacketsPerTick = 0;
    dev->InstantHead = 0;
    dev->InstantFilled = 0;
    dev->LastPacketTicks = 0;
}

static VOID MpPushInterval(PMP_DEVICE dev, LONG64 dtTicks, BOOLEAN burst)
{
    ULONG slot = dev->Head;
    if (dev->Filled == MP_WINDOW_SIZE)
    {
        dev->WindowSum -= dev->Intervals[slot];
    }
    else
    {
        dev->Filled++;
    }
    dev->Intervals[slot] = dtTicks;
    dev->WindowSum += dtTicks;
    if (burst)
    {
        dev->WindowBursts++;
        dev->TotalBursts++;
    }
    dev->Head = (slot + 1) % MP_WINDOW_SIZE;
}

static VOID MpPushInstant(PMP_DEVICE dev, LARGE_INTEGER ts)
{
    if (dev->InstantFilled < RTL_NUMBER_OF(dev->InstantQueue))
    {
        dev->InstantQueue[dev->InstantHead] = ts;
        dev->InstantHead = (dev->InstantHead + 1) % RTL_NUMBER_OF(dev->InstantQueue);
        dev->InstantFilled++;
    }
    else
    {
        dev->InstantQueue[dev->InstantHead] = ts;
        dev->InstantHead = (dev->InstantHead + 1) % RTL_NUMBER_OF(dev->InstantQueue);
    }
}

static ULONG MpInstantHz(PMP_DEVICE dev, LONG64 nowTicks)
{
    LONG64 cutoff = nowTicks - g_OneSecondTicks;
    ULONG count = 0;
    ULONG cap = RTL_NUMBER_OF(dev->InstantQueue);
    for (ULONG i = 0; i < dev->InstantFilled; i++)
    {
        ULONG idx = (dev->InstantHead + cap - 1 - i) % cap;
        if (dev->InstantQueue[idx].QuadPart >= cutoff) count++;
        else break;
    }
    return count;
}

static VOID MpTickDeviceAtDpc(PMP_DEVICE dev, LONG64 nowTicks)
{
    ULONG writePtr = 0;
    __try
    {
        writePtr = *(volatile ULONG *)(dev->DevExtensionBase + MP_MOUCLASS_WRITE_POINTER);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    if (writePtr >= dev->QueueSize) return;

    if (dev->LastTicks == 0)
    {
        dev->LastTicks = nowTicks;
        dev->LastWritePointer = writePtr;
        return;
    }

    if (writePtr == dev->LastWritePointer)
    {
        dev->LastTicks = nowTicks;
        return;
    }

    ULONG deltaBytes;
    if (writePtr >= dev->LastWritePointer)
    {
        deltaBytes = writePtr - dev->LastWritePointer;
    }
    else
    {
        deltaBytes = (dev->QueueSize - dev->LastWritePointer) + writePtr;
    }

    ULONG deltaPackets = deltaBytes / MP_MOUSE_INPUT_SIZE;
    if (deltaPackets == 0)
    {
        dev->LastWritePointer = writePtr;
        dev->LastTicks = nowTicks;
        return;
    }

    LONG64 dtTicks = nowTicks - dev->LastTicks;
    dev->LastTicks = nowTicks;
    dev->LastWritePointer = writePtr;

    KeAcquireSpinLockAtDpcLevel(&dev->Lock);

    if (deltaPackets > dev->MaxPacketsPerTick)
        dev->MaxPacketsPerTick = deltaPackets;

    dev->TotalMovePackets += deltaPackets;

    LONG64 perPacketTicks = (deltaPackets > 1) ? (dtTicks / (LONG64)deltaPackets) : dtTicks;

    for (ULONG i = 0; i < deltaPackets; i++)
    {
        BOOLEAN burst = (perPacketTicks < g_BurstThresholdTicks);
        MpPushInterval(dev, perPacketTicks, burst);
        LARGE_INTEGER ts; ts.QuadPart = nowTicks;
        MpPushInstant(dev, ts);
    }

    dev->LastPacketTicks = nowTicks;

    KeReleaseSpinLockFromDpcLevel(&dev->Lock);
}

static VOID MpTimerDpc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1);
    UNREFERENCED_PARAMETER(A2);

    if (!InterlockedCompareExchange(&g_TimerRunning, 0, 0)) return;

    LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
    LONG64 nowTicks = now.QuadPart;

    for (ULONG i = 0; i < g_DeviceCount; i++)
    {
        if (g_Devices[i].Valid)
            MpTickDeviceAtDpc(&g_Devices[i], nowTicks);
    }
}

static NTSTATUS MpReferenceDriver(const WCHAR *name, PDRIVER_OBJECT *outDriver)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, name);
    PDRIVER_OBJECT drv = NULL;
    NTSTATUS s = ObReferenceObjectByName(&u, OBJ_CASE_INSENSITIVE, NULL, 0,
                                         *IoDriverObjectType, KernelMode, NULL,
                                         (PVOID *)&drv);
    if (!NT_SUCCESS(s)) return s;
    *outDriver = drv;
    return STATUS_SUCCESS;
}

NTSTATUS MousePollingInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    RtlZeroMemory(g_Devices, sizeof(g_Devices));
    g_DeviceCount = 0;

    g_PerfFreq = KeQueryPerformanceCounter(NULL);
    LARGE_INTEGER freq;
    KeQueryPerformanceCounter(&freq);
    g_PerfFreq = freq;

    if (g_PerfFreq.QuadPart == 0)
    {
        InterlockedExchange(&g_Initialized, 0);
        return STATUS_NOT_SUPPORTED;
    }

    g_BurstThresholdTicks = g_PerfFreq.QuadPart / 2000LL;
    g_OneSecondTicks = g_PerfFreq.QuadPart;

    KeInitializeTimer(&g_Timer);
    KeInitializeDpc(&g_TimerDpc, MpTimerDpc, NULL);

    for (ULONG i = 0; i < MP_MAX_DEVICES; i++)
        KeInitializeSpinLock(&g_Devices[i].Lock);

    return STATUS_SUCCESS;
}

VOID MousePollingShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;

    MousePollingStop();

    InterlockedExchange(&g_Initialized, 0);
    RtlZeroMemory(g_Devices, sizeof(g_Devices));
    g_DeviceCount = 0;
}

NTSTATUS MousePollingDiscoverDevices(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    PDRIVER_OBJECT mouClass = NULL;
    NTSTATUS s = MpReferenceDriver(L"\\Driver\\MouClass", &mouClass);
    if (!NT_SUCCESS(s)) return s;

    PDEVICE_OBJECT dev = mouClass->DeviceObject;
    while (dev && g_DeviceCount < MP_MAX_DEVICES)
    {
        PUCHAR ext = (PUCHAR)dev->DeviceExtension;
        ULONG qs = 0;
        if (ext && MpSanityCheckDevice(ext, &qs))
        {
            PMP_DEVICE slot = &g_Devices[g_DeviceCount];
            slot->ClassDevice = dev;
            slot->DevExtensionBase = ext;
            slot->QueueSize = qs;

            __try
            {
                slot->LastWritePointer = *(ULONG *)(ext + MP_MOUCLASS_WRITE_POINTER);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                slot->LastWritePointer = 0;
            }

            LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
            slot->LastTicks = now.QuadPart;

            MpResetWindow(slot);
            slot->Valid = TRUE;
            g_DeviceCount++;
        }

        dev = dev->NextDevice;
    }

    ObDereferenceObject(mouClass);
    return (g_DeviceCount > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS MousePollingStart(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (g_DeviceCount == 0) return STATUS_NOT_FOUND;

    if (InterlockedCompareExchange(&g_TimerRunning, 1, 0) != 0) return STATUS_SUCCESS;

    LARGE_INTEGER due;
    due.QuadPart = -10000LL * (LONG64)MP_TIMER_PERIOD_MS;
    KeSetTimerEx(&g_Timer, due, MP_TIMER_PERIOD_MS, &g_TimerDpc);
    return STATUS_SUCCESS;
}

VOID MousePollingStop(VOID)
{
    if (InterlockedCompareExchange(&g_TimerRunning, 0, 1) != 1) return;
    KeCancelTimer(&g_Timer);
    KeFlushQueuedDpcs();
}

NTSTATUS MousePollingVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (g_DeviceCount == 0) return STATUS_NOT_FOUND;

    for (ULONG i = 0; i < g_DeviceCount; i++)
    {
        PMP_DEVICE dev = &g_Devices[i];
        if (!dev->Valid) continue;

        KIRQL irql;
        KeAcquireSpinLock(&dev->Lock, &irql);

        ULONG filled = dev->Filled;
        LONG64 sum = dev->WindowSum;
        ULONG bursts = dev->WindowBursts;
        ULONG maxPerTick = dev->MaxPacketsPerTick;
        ULONG64 total = dev->TotalMovePackets;
        ULONG64 totalBursts = dev->TotalBursts;

        LONG64 variance = 0;
        if (filled >= 2)
        {
            LONG64 avg = sum / (LONG64)filled;
            for (ULONG k = 0; k < filled; k++)
            {
                LONG64 d = dev->Intervals[k] - avg;
                variance += d * d;
            }
            variance /= (LONG64)filled;
        }

        LONG64 nowTicks = KeQueryPerformanceCounter(NULL).QuadPart;
        ULONG instantHz = MpInstantHz(dev, nowTicks);

        dev->MaxPacketsPerTick = 0;

        KeReleaseSpinLock(&dev->Lock, irql);

        if (filled < MP_MIN_SAMPLES) continue;

        LONG64 avgMicros = (filled > 0) ? MpTicksToMicros(sum / (LONG64)filled) : 0;
        LONG64 stdDevMicros = MpTicksToMicros(MpIntSqrt(variance));
        ULONG burstRateBp = (ULONG)((ULONG64)bursts * 10000ULL / (ULONG64)filled);

        ULONG flags = 0;
        ULONG verdict = MP_VERDICT_WAITING;

        if (burstRateBp >= MP_BURST_RATE_INJECTION_BP) flags |= MP_FLAG_HIGH_BURST;
        if (stdDevMicros > 0 && stdDevMicros <= (LONG64)MP_STDDEV_INJECTION_US) flags |= MP_FLAG_LOW_STDDEV;
        if (instantHz > MP_HZ_IMPOSSIBLE) flags |= MP_FLAG_SUPER_HIGH_HZ;
        if (maxPerTick > MP_MAX_PKTS_PER_TICK) flags |= MP_FLAG_MONSTER_BURST;

        if (flags)
        {
            verdict = MP_VERDICT_INJECTION;
        }
        else
        {
            ULONG suspicious = 0;
            if (burstRateBp >= MP_BURST_RATE_SUSPECT_BP) suspicious++;
            if (stdDevMicros > 0 && stdDevMicros <= (LONG64)MP_STDDEV_SUSPECT_US) suspicious++;
            if (suspicious) verdict = MP_VERDICT_SUSPICIOUS;
            else            verdict = MP_VERDICT_NATURAL;
        }

        if (verdict == MP_VERDICT_INJECTION || verdict == MP_VERDICT_SUSPICIOUS)
        {
            WIRE_MOUSE_POLLING rec;
            RtlZeroMemory(&rec, sizeof(rec));
            rec.DeviceObject = (ULONG64)dev->ClassDevice;
            rec.TotalPackets = total;
            rec.TotalBursts = totalBursts;
            rec.InstantHz = instantHz;
            rec.WindowAvgMicros = (ULONG)avgMicros;
            rec.WindowStdDevMicros = (ULONG)stdDevMicros;
            rec.WindowBurstRateBp = burstRateBp;
            rec.WindowMaxPacketsPerTick = maxPerTick;
            rec.FilledSamples = filled;
            rec.Verdict = verdict;
            rec.Flags = flags;

            (VOID)EventsReportMousePolling(&rec);

            if (verdict == MP_VERDICT_INJECTION)
            {
                (VOID)EventsReportTamper(AC_TAMPER_REASON_MOUSE_POLLING,
                                         (PVOID)(ULONG_PTR)dev->ClassDevice);
            }
        }
    }

    return STATUS_SUCCESS;
}
