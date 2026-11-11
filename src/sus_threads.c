#include "sus_threads.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "strings.h"
#include "game_integrity.h"
#include "usermod.h"
#include "wire_records.h"

#define ST_TRACK_SLOTS          256
#define ST_MOD_RANGES_MAX       128
#define ST_STUCK_STREAK_THRESH  3

typedef struct _ST_TID_SLOT
{
    ULONG64 ProcessId;
    ULONG64 ThreadId;
    ULONG   SuspendStreak;
    ULONG   LastTick;
} ST_TID_SLOT, *PST_TID_SLOT;

typedef struct _ST_MOD_RANGE
{
    ULONG_PTR Base;
    ULONG_PTR End;
} ST_MOD_RANGE, *PST_MOD_RANGE;

typedef struct _ST_MOD_CTX
{
    ST_MOD_RANGE Ranges[ST_MOD_RANGES_MAX];
    ULONG        Count;
} ST_MOD_CTX, *PST_MOD_CTX;

static ST_TID_SLOT      g_Slots[ST_TRACK_SLOTS];
static KSPIN_LOCK       g_SlotLock;
static volatile LONG    g_Initialized = 0;
static volatile LONG    g_Tick = 0;
static volatile LONG    g_Flag = 0;

NTSTATUS SusThreadsInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    RtlZeroMemory(g_Slots, sizeof(g_Slots));
    KeInitializeSpinLock(&g_SlotLock);
    g_Tick = 0;
    g_Flag = 0;
    return STATUS_SUCCESS;
}

VOID SusThreadsShutdown(VOID)
{
    if (InterlockedExchange(&g_Initialized, 0) == 0) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_SlotLock, &irql);
    RtlZeroMemory(g_Slots, sizeof(g_Slots));
    KeReleaseSpinLock(&g_SlotLock, irql);
}

ULONG SusThreadsGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Flag, 0, 0);
}

VOID SusThreadsClearFlag(VOID)
{
    InterlockedExchange(&g_Flag, 0);
}

static BOOLEAN ModIterCb(PUSERMOD_ITER_CB_CTX ctx, PVOID userCtx)
{
    PST_MOD_CTX m = (PST_MOD_CTX)userCtx;
    if (!m || m->Count >= ST_MOD_RANGES_MAX) return FALSE;
    if (!ctx->OpaqueBase || ctx->Size == 0) return TRUE;

    m->Ranges[m->Count].Base = (ULONG_PTR)ctx->OpaqueBase;
    m->Ranges[m->Count].End  = (ULONG_PTR)ctx->OpaqueBase + ctx->Size;
    m->Count++;
    return TRUE;
}

static BOOLEAN AddressBackedByModule(const ST_MOD_CTX *m, ULONG_PTR addr)
{
    if (!m || addr == 0) return FALSE;
    for (ULONG i = 0; i < m->Count; i++)
    {
        if (addr >= m->Ranges[i].Base && addr < m->Ranges[i].End) return TRUE;
    }
    return FALSE;
}

static VOID CopyImageName(PEPROCESS proc, UCHAR *dst, SIZE_T cap)
{
    const CHAR *src = PsGetProcessImageFileName(proc);
    if (!src || cap == 0) return;
    SIZE_T i = 0;
    while (i < cap - 1 && src[i] != 0)
    {
        dst[i] = (UCHAR)src[i];
        i++;
    }
    dst[i] = 0;
}

static ULONG TrackSuspend(ULONG64 pid, ULONG64 tid, ULONG tick)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SlotLock, &irql);

    LONG freeIdx = -1;
    for (LONG i = 0; i < ST_TRACK_SLOTS; i++)
    {
        if (g_Slots[i].ThreadId == tid && g_Slots[i].ProcessId == pid)
        {
            g_Slots[i].SuspendStreak++;
            g_Slots[i].LastTick = tick;
            ULONG streak = g_Slots[i].SuspendStreak;
            KeReleaseSpinLock(&g_SlotLock, irql);
            return streak;
        }
        if (freeIdx < 0 && g_Slots[i].ThreadId == 0) freeIdx = i;
    }

    if (freeIdx < 0)
    {
        ULONG oldestTick = 0xFFFFFFFF;
        for (LONG i = 0; i < ST_TRACK_SLOTS; i++)
        {
            if (g_Slots[i].LastTick < oldestTick)
            {
                oldestTick = g_Slots[i].LastTick;
                freeIdx = i;
            }
        }
    }

    g_Slots[freeIdx].ProcessId     = pid;
    g_Slots[freeIdx].ThreadId      = tid;
    g_Slots[freeIdx].SuspendStreak = 1;
    g_Slots[freeIdx].LastTick      = tick;

    KeReleaseSpinLock(&g_SlotLock, irql);
    return 1;
}

static VOID ReapSlots(ULONG tick)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SlotLock, &irql);
    for (LONG i = 0; i < ST_TRACK_SLOTS; i++)
    {
        if (g_Slots[i].ThreadId != 0 && g_Slots[i].LastTick != tick)
        {
            g_Slots[i].ThreadId      = 0;
            g_Slots[i].ProcessId     = 0;
            g_Slots[i].SuspendStreak = 0;
            g_Slots[i].LastTick      = 0;
        }
    }
    KeReleaseSpinLock(&g_SlotLock, irql);
}

static NTSTATUS QueryExtProcessInfo(PVOID *outBuf, PULONG outSize)
{
    *outBuf = NULL;
    *outSize = 0;

    ULONG needed = 0;
    NTSTATUS s = ZwQuerySystemInformation(CORE_SysExtendedProcessInformation, NULL, 0, &needed);
    if (s != STATUS_INFO_LENGTH_MISMATCH || needed == 0)
    {
        if (!NT_SUCCESS(s)) return s;
        needed = 0x10000;
    }

    ULONG cap = needed + 0x8000;
    PVOID buf = CoreAlloc(cap, CORE_AC_POOL_TAG_SCAN);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG got = 0;
    s = ZwQuerySystemInformation(CORE_SysExtendedProcessInformation, buf, cap, &got);
    if (!NT_SUCCESS(s))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return s;
    }

    *outBuf = buf;
    *outSize = cap;
    return STATUS_SUCCESS;
}

static VOID EvaluateProcess(PCORE_SYSTEM_PROCESS_INFORMATION proc, ULONG tick)
{
    HANDLE pid = proc->UniqueProcessId;
    if (!pid) return;
    if (!GameIntegrityIsProtectedPid(pid)) return;

    ST_MOD_CTX mods;
    mods.Count = 0;
    (VOID)UsermodWalkProcessModules(pid, ModIterCb, &mods);

    PEPROCESS peproc = NULL;
    (VOID)PsLookupProcessByProcessId(pid, &peproc);
    UCHAR imageName[16];
    RtlZeroMemory(imageName, sizeof(imageName));
    if (peproc) CopyImageName(peproc, imageName, sizeof(imageName));

    PCORE_SYSTEM_EXTENDED_THREAD_INFORMATION threads =
        (PCORE_SYSTEM_EXTENDED_THREAD_INFORMATION)(proc + 1);

    for (ULONG i = 0; i < proc->NumberOfThreads; i++)
    {
        PCORE_SYSTEM_EXTENDED_THREAD_INFORMATION t = &threads[i];
        ULONG64 tid = (ULONG64)(ULONG_PTR)t->ThreadInfo.ClientId.UniqueThread;
        if (!tid) continue;

        ULONG64 startAddr      = (ULONG64)(ULONG_PTR)t->ThreadInfo.StartAddress;
        ULONG64 win32StartAddr = (ULONG64)(ULONG_PTR)t->Win32StartAddress;
        ULONG   waitReason     = t->ThreadInfo.WaitReason;
        ULONG   threadState    = t->ThreadInfo.ThreadState;

        ULONG flags = 0;
        ULONG streak = 0;

        if (waitReason == CORE_WAIT_REASON_SUSPENDED)
        {
            flags |= ST_FLAG_SUSPENDED;
            streak = TrackSuspend((ULONG64)(ULONG_PTR)pid, tid, tick);
            if (streak >= ST_STUCK_STREAK_THRESH) flags |= ST_FLAG_STUCK_SUSPENDED;
        }

        if (mods.Count > 0)
        {
            ULONG_PTR check = (ULONG_PTR)(win32StartAddr ? win32StartAddr : startAddr);
            if (check != 0 && !AddressBackedByModule(&mods, check))
            {
                flags |= (win32StartAddr ? ST_FLAG_UNBACKED_WIN32 : ST_FLAG_UNBACKED_START);
            }
        }

        BOOLEAN suspicious = FALSE;
        if (flags & ST_FLAG_STUCK_SUSPENDED) suspicious = TRUE;
        if (flags & (ST_FLAG_UNBACKED_WIN32 | ST_FLAG_UNBACKED_START)) suspicious = TRUE;

        if (!suspicious) continue;

        flags |= ST_FLAG_SUSPICIOUS;

        WIRE_SUS_THREAD rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.ProcessId         = (ULONG64)(ULONG_PTR)pid;
        rec.ThreadId          = tid;
        rec.StartAddress      = startAddr;
        rec.Win32StartAddress = win32StartAddr;
        rec.CreateTime        = (ULONG64)t->ThreadInfo.CreateTime.QuadPart;
        rec.WaitReason        = waitReason;
        rec.ThreadState       = threadState;
        rec.SuspendStreak     = streak;
        rec.Flags             = flags;
        RtlCopyMemory(rec.ImageName, imageName, sizeof(rec.ImageName));

        (VOID)EventsReportSusThread(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_SUS_THREAD, (PVOID)(ULONG_PTR)tid);

        InterlockedOr(&g_Flag, (LONG)flags);
    }

    if (peproc) ObDereferenceObject(peproc);
}

NTSTATUS SusThreadsVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    PVOID buf = NULL;
    ULONG bufSize = 0;
    NTSTATUS s = QueryExtProcessInfo(&buf, &bufSize);
    if (!NT_SUCCESS(s) || !buf) return s;

    ULONG tick = (ULONG)InterlockedIncrement(&g_Tick);

    PUCHAR cursor = (PUCHAR)buf;
    ULONG guard = 0;
    while (guard++ < 65536)
    {
        PCORE_SYSTEM_PROCESS_INFORMATION proc = (PCORE_SYSTEM_PROCESS_INFORMATION)cursor;
        EvaluateProcess(proc, tick);

        if (proc->NextEntryOffset == 0) break;
        cursor += proc->NextEntryOffset;
    }

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    ReapSlots(tick);
    return STATUS_SUCCESS;
}
