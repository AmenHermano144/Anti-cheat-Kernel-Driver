#pragma once

#include "core.h"
#include "smbios.h"

#define HWID_HISTORY_FLAG_FIRST_SEEN   0x00000001
#define HWID_HISTORY_FLAG_CHANGED      0x00000002
#define HWID_HISTORY_FLAG_REG_FAIL     0x00000004

#pragma pack(push, 1)
typedef struct _WIRE_HWID_HISTORY
{
    ULONG   Flags;
    ULONG   Reserved;
    ULONG64 PriorFingerprint;
    ULONG64 CurrentFingerprint;
    ULONG64 BootCookie;
    ULONG   BootsSinceChange;
    ULONG   PriorSeenEpoch;
} WIRE_HWID_HISTORY, *PWIRE_HWID_HISTORY;
#pragma pack(pop)

NTSTATUS HwidHistoryEvaluate(const SMBIOS_PARSED *parsed, PWIRE_HWID_HISTORY out);
