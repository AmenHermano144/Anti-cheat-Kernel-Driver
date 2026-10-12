#include "driver_ts_blacklist.h"

static const ULONG g_BannedTimestamps[] =
{
    0x4FBF9C8E,
    0x55B98DBD,
    0x5EE22D5C,
    0x4A5BC637,
    0x5886BE49,
    0x5E92B813,
    0x5C13CF2B,
    0x60B48114,
    0x4CE7C58E,
    0x62F70B38,
};

#define TS_COUNT (sizeof(g_BannedTimestamps) / sizeof(g_BannedTimestamps[0]))

NTSTATUS DriverTsInit(VOID)
{
    return STATUS_SUCCESS;
}

BOOLEAN DriverTsIsBlacklisted(ULONG peTimestamp)
{
    for (SIZE_T i = 0; i < TS_COUNT; i++)
    {
        if (g_BannedTimestamps[i] == peTimestamp) return TRUE;
    }
    return FALSE;
}
