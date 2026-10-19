#pragma once

#include "core.h"

typedef enum _CHANNEL_BLOB_KIND
{
    CHANNEL_BLOB_GENERIC    = 0,
    CHANNEL_BLOB_HASH       = 1,
    CHANNEL_BLOB_WATCHLIST  = 2,
    CHANNEL_BLOB_VENDOR     = 3,
    CHANNEL_BLOB_MATCH      = 4,
    CHANNEL_BLOB_USB        = 5,
    CHANNEL_BLOB_PROCESS    = 6,
    CHANNEL_BLOB_HWID       = 7,
} CHANNEL_BLOB_KIND;

#define CHANNEL_BLOB_MAX_LEN       0x1000

NTSTATUS ChannelInit(VOID);
VOID     ChannelShutdown(VOID);

NTSTATUS ChannelBootstrap(VOID);
NTSTATUS ChannelAcceptBlob(CHANNEL_BLOB_KIND kind, PVOID data, ULONG len);
NTSTATUS ChannelGetBlob(CHANNEL_BLOB_KIND kind, PVOID outBuffer, ULONG outCap, PULONG outLen);
BOOLEAN  ChannelBlobEqualsW(CHANNEL_BLOB_KIND kind, const WCHAR *candidate, SIZE_T candidateLen);

NTSTATUS ChannelEnqueueRecord(UCHAR recordType, const VOID *payload, ULONG payloadLen);
NTSTATUS ChannelDrainEvents(PVOID outBuffer, ULONG outCap, PULONG written);
NTSTATUS ChannelFlushPending(VOID);
