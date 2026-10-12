#include "channels.h"
#include "wire_records.h"
#include "crypto.h"
#include "events.h"
#include "strings.h"

#define CHANNEL_RING_CAPACITY     256
#define CHANNEL_RECORD_MAX_SIZE   0x1000

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

static CHANNEL_RING g_Ring;
static volatile LONG g_ChannelReady = 0;

NTSTATUS ChannelInit(VOID)
{
    RtlZeroMemory(&g_Ring, sizeof(g_Ring));
    KeInitializeSpinLock(&g_Ring.Lock);

    g_Ring.Slots = (PCHANNEL_SLOT)CoreAlloc(sizeof(CHANNEL_SLOT) * CHANNEL_RING_CAPACITY,
                                            CORE_AC_POOL_TAG_WIRE);
    if (!g_Ring.Slots) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring.Slots, sizeof(CHANNEL_SLOT) * CHANNEL_RING_CAPACITY);

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
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(kind);
    return STATUS_SUCCESS;
}
