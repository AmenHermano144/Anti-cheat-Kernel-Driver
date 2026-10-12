#include "byovd_scanner.h"
#include "strings.h"
#include "events.h"
#include "channels.h"
#include "wire_records.h"

static const CHAR *g_ByovdSubstrings[] =
{
    "gvcidrv64",
    "bs_hwmio",
    "bs_rcio",
    "winring0",
    "alsysio",
    "ntiolib",
    "cpuz",
    "msio",
    "msio64",
    "winio",
    "phymem",
    "iqvw64",
    "iqvw64e",
    "amifldrv64",
    "etdrv",
    "rtcore64",
    "dbutil_2_3",
    "dbutildrv2",
    "capcom",
    "piddrv",
    "lha",
    "ldrvio",
    "rwdrv",
    "giveiospci",
    "atsmcdrv",
    "mhyprot2",
    "mhyprot3",
    "gdrv",
    "echo_drv",
    "truesight",
    "throttlestop",
    "ene",
    "enemsia",
    "enepci",
    "glckio2",
    "nvflash",
    "procexp152",
    "procmon23",
    "pcdsrvc",
    "driver7",
    "corsairllaccess64",
    "irisgaming",
    "ddpci",
    "amdpowerprofiler",
    "wnbios",
    "winflash64",
    "atillk64",
    "aswarpot",
    "asmmap",
    "asusnbfnctrl",
    "cmdrv",
    "cmdhlp",
    "faceit",
    "amdryzenmasterdriver",
    "zemana",
    "intelephysicaldriver",
    "nal",
    "cpuzsdk",
    "elbycdio",
    "etdctrl",
    "cmdrv_x64",
    "amdepusb",
    "amdepuip",
    "amdepusbdbg",
    "sysinternalsldr",
};

#define BYOVD_COUNT (sizeof(g_ByovdSubstrings) / sizeof(g_ByovdSubstrings[0]))

static ULONG64 g_ByovdFnv[BYOVD_COUNT];

NTSTATUS ByovdScannerInit(VOID)
{
    for (SIZE_T i = 0; i < BYOVD_COUNT; i++)
    {
        g_ByovdFnv[i] = CoreFnv1a64(g_ByovdSubstrings[i], CoreStrLenA(g_ByovdSubstrings[i]));
    }
    return STATUS_SUCCESS;
}

static BOOLEAN WideContainsAnsiLower(const WCHAR *haystack, SIZE_T hLen, const CHAR *needle)
{
    SIZE_T nLen = CoreStrLenA(needle);
    if (nLen == 0 || nLen > hLen) return FALSE;

    for (SIZE_T i = 0; i + nLen <= hLen; i++)
    {
        SIZE_T j = 0;
        while (j < nLen)
        {
            WCHAR c = haystack[i + j];
            if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
            if ((CHAR)c != needle[j]) break;
            j++;
        }
        if (j == nLen) return TRUE;
    }
    return FALSE;
}

BOOLEAN ByovdPathIsBlacklisted(const UNICODE_STRING *fullPath)
{
    if (!fullPath || !fullPath->Buffer) return FALSE;
    SIZE_T wlen = fullPath->Length / sizeof(WCHAR);

    for (SIZE_T i = 0; i < BYOVD_COUNT; i++)
    {
        if (WideContainsAnsiLower(fullPath->Buffer, wlen, g_ByovdSubstrings[i]))
            return TRUE;
    }
    return FALSE;
}

BOOLEAN ByovdFnvIsBlacklisted(ULONG64 fnv1a64)
{
    for (SIZE_T i = 0; i < BYOVD_COUNT; i++)
        if (g_ByovdFnv[i] == fnv1a64) return TRUE;
    return FALSE;
}

NTSTATUS ByovdScannerOnImageLoad(PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo || !ImageInfo->SystemModeImage) return STATUS_SUCCESS;
    if (!ByovdPathIsBlacklisted(FullImageName)) return STATUS_SUCCESS;

    WIRE_BYOVD_HIT hit;
    RtlZeroMemory(&hit, sizeof(hit));
    hit.ImageBase = (ULONG64)ImageInfo->ImageBase;
    hit.ImageSize = (ULONG)ImageInfo->ImageSize;

    const WCHAR *src = FullImageName->Buffer;
    USHORT srcBytes = FullImageName->Length;
    if (srcBytes > sizeof(hit.ImagePath)) srcBytes = sizeof(hit.ImagePath);
    hit.ImagePathLen = srcBytes;
    RtlCopyMemory(hit.ImagePath, src, srcBytes);

    hit.Fnv1a64 = CoreFnv1a64(src, srcBytes);
    return ChannelEnqueueRecord(WIRE_REC_BYOVD_HIT, &hit, sizeof(hit));
}
