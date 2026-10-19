#include "channels.h"
#include "wire_records.h"
#include "crypto.h"
#include "events.h"
#include "strings.h"

#define CHANNEL_RING_CAPACITY     256
#define CHANNEL_RECORD_MAX_SIZE   0x1000
#define CHANNEL_BLOB_SLOT_COUNT   8

typedef struct _CHANNEL_SLOT
{
    volatile LONG   InUse;
    UCHAR           Type;
    USHORT          PayloadLen;
    UCHAR           Payload[CHANNEL_RECORD_MAX_SIZE];
    ULONG64         Sequence;
    LARGE_INTEGER   Timestamp;
} CHANNEL_SLOT, *PCHANNEL_SLOT;

typedef struct _CHANNEL_RING
{
    KSPIN_LOCK      Lock;
    volatile ULONG  Head;
    volatile ULONG  Tail;
    ULONG64         SequenceCounter;
    PCHANNEL_SLOT   Slots;
} CHANNEL_RING, *PCHANNEL_RING;

typedef struct _CHANNEL_BLOB_SLOT
{
    CHANNEL_BLOB_KIND Kind;
    ULONG             Length;
    UCHAR             Data[CHANNEL_BLOB_MAX_LEN];
} CHANNEL_BLOB_SLOT, *PCHANNEL_BLOB_SLOT;

static CHANNEL_RING  g_Ring;
static volatile LONG g_ChannelReady = 0;
static KSPIN_LOCK    g_BlobLock;
static CHANNEL_BLOB_SLOT g_BlobSlots[CHANNEL_BLOB_SLOT_COUNT];
static volatile LONG g_BlobCount = 0;

NTSTATUS ChannelInit(VOID)
{
    RtlZeroMemory(&g_Ring, sizeof(g_Ring));
    KeInitializeSpinLock(&g_Ring.Lock);

    g_Ring.Slots = (PCHANNEL_SLOT)CoreAlloc(sizeof(CHANNEL_SLOT) * CHANNEL_RING_CAPACITY,
                                            CORE_AC_POOL_TAG_WIRE);
    if (!g_Ring.Slots) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring.Slots, sizeof(CHANNEL_SLOT) * CHANNEL_RING_CAPACITY);

    KeInitializeSpinLock(&g_BlobLock);
    RtlZeroMemory(g_BlobSlots, sizeof(g_BlobSlots));
    InterlockedExchange(&g_BlobCount, 0);

    InterlockedExchange(&g_ChannelReady, 1);
    return STATUS_SUCCESS;
}

VOID ChannelShutdown(VOID)
{
    InterlockedExchange(&g_ChannelReady, 0);
    if (g_Ring.Slots)
    {
        CoreFree(g_Ring.Slots, CORE_AC_POOL_TAG_WIRE);
        g_Ring.Slots = NULL;
    }
}

NTSTATUS ChannelBootstrap(VOID)
{
    if (!InterlockedCompareExchange(&g_ChannelReady, 0, 0)) return CORE_AC_STATUS_NO_SESSION;
    return STATUS_SUCCESS;
}

NTSTATUS ChannelEnqueueRecord(UCHAR recordType, const VOID *payload, ULONG payloadLen)
{
    if (!InterlockedCompareExchange(&g_ChannelReady, 0, 0)) return CORE_AC_STATUS_NO_SESSION;
    if (payloadLen > CHANNEL_RECORD_MAX_SIZE) return STATUS_BUFFER_OVERFLOW;

    KIRQL irql;
    KeAcquireSpinLock(&g_Ring.Lock, &irql);

    ULONG next = (g_Ring.Head + 1) % CHANNEL_RING_CAPACITY;
    if (next == g_Ring.Tail)
    {
        g_Ring.Tail = (g_Ring.Tail + 1) % CHANNEL_RING_CAPACITY;
    }

    PCHANNEL_SLOT slot = &g_Ring.Slots[g_Ring.Head];
    slot->Type = recordType;
    slot->PayloadLen = (USHORT)payloadLen;
    slot->Sequence = ++g_Ring.SequenceCounter;
    KeQuerySystemTimePrecise(&slot->Timestamp);

    if (payload && payloadLen) RtlCopyMemory(slot->Payload, payload, payloadLen);
    slot->InUse = 1;

    g_Ring.Head = next;

    KeReleaseSpinLock(&g_Ring.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS ChannelDrainEvents(PVOID outBuffer, ULONG outCap, PULONG written)
{
    if (!written) return STATUS_INVALID_PARAMETER;
    *written = 0;
    if (!InterlockedCompareExchange(&g_ChannelReady, 0, 0)) return CORE_AC_STATUS_NO_SESSION;

    KIRQL irql;
    KeAcquireSpinLock(&g_Ring.Lock, &irql);

    UCHAR *out = (UCHAR *)outBuffer;
    ULONG space = outCap;

    while (g_Ring.Tail != g_Ring.Head)
    {
        PCHANNEL_SLOT slot = &g_Ring.Slots[g_Ring.Tail];
        ULONG need = (ULONG)FIELD_OFFSET(WIRE_RECORD_HEADER, Payload) + slot->PayloadLen;
        if (need > space) break;

        WIRE_RECORD_HEADER *hdr = (WIRE_RECORD_HEADER *)out;
        hdr->Magic = WIRE_RECORD_MAGIC;
        hdr->Version = WIRE_RECORD_VERSION;
        hdr->Type = slot->Type;
        hdr->Flags = 0;
        hdr->Length = slot->PayloadLen;
        hdr->Sequence = slot->Sequence;
        hdr->Timestamp = slot->Timestamp.QuadPart;

        if (slot->PayloadLen)
            RtlCopyMemory(hdr->Payload, slot->Payload, slot->PayloadLen);

        slot->InUse = 0;
        g_Ring.Tail = (g_Ring.Tail + 1) % CHANNEL_RING_CAPACITY;

        out += need;
        space -= need;
        *written += need;
    }

    KeReleaseSpinLock(&g_Ring.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS ChannelFlushPending(VOID)
{
    return STATUS_SUCCESS;
}

NTSTATUS ChannelAcceptBlob(CHANNEL_BLOB_KIND kind, PVOID data, ULONG len)
{
    if (!data || len == 0 || len > CHANNEL_BLOB_MAX_LEN) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_ChannelReady, 0, 0)) return CORE_AC_STATUS_NO_SESSION;

    KIRQL irql;
    KeAcquireSpinLock(&g_BlobLock, &irql);

    PCHANNEL_BLOB_SLOT target = NULL;
    for (ULONG i = 0; i < CHANNEL_BLOB_SLOT_COUNT; i++)
    {
        if (g_BlobSlots[i].Length != 0 && g_BlobSlots[i].Kind == kind)
        {
            target = &g_BlobSlots[i];
            break;
        }
    }
    if (!target)
    {
        for (ULONG i = 0; i < CHANNEL_BLOB_SLOT_COUNT; i++)
        {
            if (g_BlobSlots[i].Length == 0) { target = &g_BlobSlots[i]; break; }
        }
    }
    if (!target)
    {
        KeReleaseSpinLock(&g_BlobLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    target->Kind = kind;
    target->Length = len;
    RtlCopyMemory(target->Data, data, len);
    if (target->Length < sizeof(target->Data))
        RtlZeroMemory(target->Data + target->Length, sizeof(target->Data) - target->Length);

    InterlockedIncrement(&g_BlobCount);
    KeReleaseSpinLock(&g_BlobLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS ChannelGetBlob(CHANNEL_BLOB_KIND kind, PVOID outBuffer, ULONG outCap, PULONG outLen)
{
    if (!outLen) return STATUS_INVALID_PARAMETER;
    *outLen = 0;

    KIRQL irql;
    KeAcquireSpinLock(&g_BlobLock, &irql);

    NTSTATUS s = STATUS_NOT_FOUND;
    for (ULONG i = 0; i < CHANNEL_BLOB_SLOT_COUNT; i++)
    {
        if (g_BlobSlots[i].Length != 0 && g_BlobSlots[i].Kind == kind)
        {
            if (!outBuffer || outCap < g_BlobSlots[i].Length)
            {
                *outLen = g_BlobSlots[i].Length;
                s = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(outBuffer, g_BlobSlots[i].Data, g_BlobSlots[i].Length);
            *outLen = g_BlobSlots[i].Length;
            s = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&g_BlobLock, irql);
    return s;
}

BOOLEAN ChannelBlobEqualsW(CHANNEL_BLOB_KIND kind, const WCHAR *candidate, SIZE_T candidateLen)
{
    if (!candidate || candidateLen == 0) return FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&g_BlobLock, &irql);

    BOOLEAN hit = FALSE;
    for (ULONG i = 0; i < CHANNEL_BLOB_SLOT_COUNT; i++)
    {
        PCHANNEL_BLOB_SLOT s = &g_BlobSlots[i];
        if (s->Length == 0 || s->Kind != kind) continue;

        const WCHAR *stored = (const WCHAR *)s->Data;
        SIZE_T storedLen = s->Length / sizeof(WCHAR);
        if (storedLen > 0 && stored[storedLen - 1] == 0) storedLen--;

        if (storedLen > candidateLen) continue;

        const WCHAR *tail = candidate + (candidateLen - storedLen);
        SIZE_T j = 0;
        while (j < storedLen)
        {
            WCHAR a = tail[j]; if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            WCHAR b = stored[j]; if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) break;
            j++;
        }
        if (j == storedLen) { hit = TRUE; break; }
    }

    KeReleaseSpinLock(&g_BlobLock, irql);
    return hit;
}
