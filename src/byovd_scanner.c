#include "byovd_scanner.h"
#include "strings.h"
#include "events.h"
#include "channels.h"
#include "wire_records.h"
#include "crypto.h"

// hand-curated substrings. these are drivers we've seen in the wild or wanted
// to track locally; keeping them separate from the loldrivers feed means a
// bad entry upstream never evicts a local addition and vice versa.
static const CHAR *g_ByovdManualSubstrings[] =
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

// loldrivers-derived substrings + SHA-256 fingerprints. the blob is generated
// by tools/gen_byovd_list.py from the live loldrivers.io dataset; a placeholder
// with zero entries ships in-tree so the driver builds without the generator
// having run yet.
#include "byovd_blob.inc"

#define BYOVD_MANUAL_COUNT (sizeof(g_ByovdManualSubstrings) / sizeof(g_ByovdManualSubstrings[0]))

static ULONG64 g_ByovdManualFnv[BYOVD_MANUAL_COUNT];

NTSTATUS ByovdScannerInit(VOID)
{
    for (SIZE_T i = 0; i < BYOVD_MANUAL_COUNT; i++)
    {
        g_ByovdManualFnv[i] = CoreFnv1a64(g_ByovdManualSubstrings[i],
                                          CoreStrLenA(g_ByovdManualSubstrings[i]));
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

static BOOLEAN FindManualSubstring(const WCHAR *buf, SIZE_T wlen, const CHAR **outMatch)
{
    for (SIZE_T i = 0; i < BYOVD_MANUAL_COUNT; i++)
    {
        if (WideContainsAnsiLower(buf, wlen, g_ByovdManualSubstrings[i]))
        {
            if (outMatch) *outMatch = g_ByovdManualSubstrings[i];
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN FindLolSubstring(const WCHAR *buf, SIZE_T wlen, const CHAR **outMatch)
{
#if BYOVD_LOL_SUBSTR_COUNT > 0
    for (ULONG i = 0; i < BYOVD_LOL_SUBSTR_COUNT; i++)
    {
        if (WideContainsAnsiLower(buf, wlen, g_ByovdLolSubstrings[i]))
        {
            if (outMatch) *outMatch = g_ByovdLolSubstrings[i];
            return TRUE;
        }
    }
#else
    UNREFERENCED_PARAMETER(buf);
    UNREFERENCED_PARAMETER(wlen);
    UNREFERENCED_PARAMETER(outMatch);
#endif
    return FALSE;
}

static BOOLEAN FindLolSha256(const UCHAR digest[32])
{
#if BYOVD_LOL_SHA256_COUNT > 0
    for (ULONG i = 0; i < BYOVD_LOL_SHA256_COUNT; i++)
    {
        if (RtlCompareMemory(digest, g_ByovdLolSha256[i], 32) == 32) return TRUE;
    }
#else
    UNREFERENCED_PARAMETER(digest);
#endif
    return FALSE;
}

BOOLEAN ByovdPathIsBlacklisted(const UNICODE_STRING *fullPath)
{
    if (!fullPath || !fullPath->Buffer) return FALSE;
    SIZE_T wlen = fullPath->Length / sizeof(WCHAR);

    if (FindManualSubstring(fullPath->Buffer, wlen, NULL)) return TRUE;
    if (FindLolSubstring   (fullPath->Buffer, wlen, NULL)) return TRUE;
    return FALSE;
}

BOOLEAN ByovdFnvIsBlacklisted(ULONG64 fnv1a64)
{
    for (SIZE_T i = 0; i < BYOVD_MANUAL_COUNT; i++)
        if (g_ByovdManualFnv[i] == fnv1a64) return TRUE;
    return FALSE;
}

NTSTATUS ByovdScannerOnImageLoad(PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo || !ImageInfo->SystemModeImage) return STATUS_SUCCESS;

    SIZE_T wlen = FullImageName->Length / sizeof(WCHAR);
    ULONG flags = 0;
    const CHAR *matchedSubstr = NULL;

    if (FindManualSubstring(FullImageName->Buffer, wlen, &matchedSubstr))
        flags |= BYOVD_MATCH_SUBSTRING_MANUAL;
    if (FindLolSubstring(FullImageName->Buffer, wlen,
                         matchedSubstr ? NULL : &matchedSubstr))
        flags |= BYOVD_MATCH_SUBSTRING_LOL;

    // SHA-256 pass. we hash the on-disk file rather than the mapped image —
    // loldrivers records are keyed by on-disk SHA-256, and the mapped image
    // differs after the loader applies relocations. CryptoSha256File opens
    // the FullImageName kernel path directly.
    UCHAR digest[32] = { 0 };
    BOOLEAN digestValid = FALSE;
    if (BYOVD_LOL_SHA256_COUNT > 0)
    {
        NTSTATUS hs = CryptoSha256File(FullImageName, digest);
        if (NT_SUCCESS(hs))
        {
            digestValid = TRUE;
            if (FindLolSha256(digest)) flags |= BYOVD_MATCH_SHA256_LOL;
        }
        else
        {
            flags |= BYOVD_MATCH_FILE_HASH_FAILED;
        }
    }

    if (flags == 0 || flags == BYOVD_MATCH_FILE_HASH_FAILED) return STATUS_SUCCESS;

    WIRE_BYOVD_HIT hit;
    RtlZeroMemory(&hit, sizeof(hit));
    hit.ImageBase  = (ULONG64)ImageInfo->ImageBase;
    hit.ImageSize  = (ULONG)ImageInfo->ImageSize;
    hit.MatchFlags = flags;

    const WCHAR *src = FullImageName->Buffer;
    USHORT srcBytes = FullImageName->Length;
    if (srcBytes > sizeof(hit.ImagePath)) srcBytes = sizeof(hit.ImagePath);
    hit.ImagePathLen = srcBytes;
    RtlCopyMemory(hit.ImagePath, src, srcBytes);

    if (matchedSubstr)
    {
        SIZE_T nLen = CoreStrLenA(matchedSubstr);
        if (nLen > sizeof(hit.MatchedPath)) nLen = sizeof(hit.MatchedPath);
        hit.MatchedPathLen = (USHORT)nLen;
        RtlCopyMemory(hit.MatchedPath, matchedSubstr, nLen);
    }

    if (digestValid) RtlCopyMemory(hit.ImageSha256, digest, 32);

    hit.Fnv1a64 = CoreFnv1a64(src, srcBytes);
    return ChannelEnqueueRecord(WIRE_REC_BYOVD_HIT, &hit, sizeof(hit));
}
