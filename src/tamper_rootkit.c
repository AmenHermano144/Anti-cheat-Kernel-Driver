#include "tamper_rootkit.h"
#include "imports.h"
#include "env_checks.h"
#include "strings.h"
#include "events.h"
#include "anti_tamper.h"

#define TR_MAX_UNLOADED  50

typedef struct _TR_UNLOADED_DRIVER
{
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
    ULONG64        UnloadTime;
} TR_UNLOADED_DRIVER, *PTR_UNLOADED_DRIVER;

static PVOID   g_PiDDBCacheTable = NULL;
static ULONG   g_PiDDBExpectedCount = 0;
static ULONG64 g_PiDDBExpectedFnv = 0;

static PVOID   g_MmUnloaded = NULL;
static ULONG64 g_MmUnloadedExpectedFnv = 0;

static volatile LONG g_Initialized = 0;

static PVOID FindSectionText(PVOID imageBase, PULONG outSize)
{
    *outSize = 0;
    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            CHAR *n = (CHAR *)sec[i].Name;
            if (n[0] == '.' && n[1] == 't' && n[2] == 'e' && n[3] == 'x' && n[4] == 't')
            {
                *outSize = sec[i].Misc.VirtualSize;
                return (PUCHAR)imageBase + sec[i].VirtualAddress;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return NULL;
}

static BOOLEAN PatternMatch(const UCHAR *base, const UCHAR *pattern, const CHAR *mask)
{
    for (SIZE_T i = 0; mask[i]; i++)
    {
        if (mask[i] == 'x' && base[i] != pattern[i]) return FALSE;
    }
    return TRUE;
}

static PVOID PatternScan(PVOID start, ULONG size, const UCHAR *pattern, const CHAR *mask)
{
    if (!start || size == 0) return NULL;
    SIZE_T mlen = CoreStrLenA(mask);
    if (size < mlen) return NULL;

    const UCHAR *base = (const UCHAR *)start;
    ULONG limit = size - (ULONG)mlen;
    __try
    {
        for (ULONG i = 0; i <= limit; i++)
        {
            if (PatternMatch(base + i, pattern, mask)) return (PVOID)(base + i);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return NULL;
}

static PVOID ResolveModuleBaseAnsi(const CHAR *moduleName)
{
    PVOID buf = NULL;
    ULONG count = 0;
    if (!NT_SUCCESS(EnvEnumKernelModules(&buf, &count)) || !buf) return NULL;

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;
    PVOID found = NULL;
    for (ULONG i = 0; i < count; i++)
    {
        const CHAR *name = (const CHAR *)mods->Module[i].FullPathName + mods->Module[i].OffsetToFileName;
        if (CoreStrCmpiA(name, moduleName) == 0)
        {
            found = mods->Module[i].ImageBase;
            break;
        }
    }

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return found;
}

static ULONG64 ComputeMmUnloadedFnv(PVOID table)
{
    if (!table) return 0;
    PTR_UNLOADED_DRIVER arr = *(PTR_UNLOADED_DRIVER *)table;
    if (!arr) return 0;

    ULONG64 h = 0xCBF29CE484222325ULL;
    __try
    {
        for (ULONG i = 0; i < TR_MAX_UNLOADED; i++)
        {
            if (!arr[i].Name.Buffer || arr[i].Name.Length == 0) continue;
            ULONG len = arr[i].Name.Length;
            if (len > 512) len = 512;
            const UCHAR *p = (const UCHAR *)arr[i].Name.Buffer;
            for (ULONG k = 0; k < len; k++)
            {
                h ^= p[k];
                h *= 0x100000001B3ULL;
            }
            h ^= (ULONG64)arr[i].UnloadTime;
            h *= 0x100000001B3ULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
    return h;
}

static VOID ComputePiddbSnapshot(PVOID table, PULONG outCount, PULONG64 outFnv)
{
    *outCount = 0;
    *outFnv = 0;
    if (!table) return;

    __try
    {
        PRTL_AVL_TABLE avl = (PRTL_AVL_TABLE)table;
        *outCount = avl->NumberGenericTableElements;
        *outFnv = (ULONG64)avl->NumberGenericTableElements * 0x100000001B3ULL ^
                  ((ULONG64)avl->DeleteCount << 17);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *outCount = 0;
        *outFnv = 0;
    }
}

static PVOID ResolvePiDDBCacheTable(VOID)
{
    PVOID ciBase = ResolveModuleBaseAnsi("CI.dll");
    if (!ciBase) ciBase = ResolveModuleBaseAnsi("ci.dll");
    if (!ciBase) return NULL;

    ULONG textSize = 0;
    PVOID text = FindSectionText(ciBase, &textSize);
    if (!text || textSize == 0) return NULL;

    static const UCHAR p21H1[] = {
        0x4C, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00,
        0xE9, 0x00, 0x00, 0x00, 0x00,
        0x8B, 0x84, 0x24
    };
    static const CHAR m21H1[] = "xxx????x????xxx";

    static const UCHAR p22H2[] = {
        0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
        0xEB, 0x00,
        0xF7, 0x43, 0x40,
        0x00, 0x20, 0x00, 0x00
    };
    static const CHAR m22H2[] = "xxx????x?xxxxxxx";

    PUCHAR hit = (PUCHAR)PatternScan(text, textSize, p21H1, m21H1);
    LONG relOffset = 3;
    LONG instrSize = 7;

    if (!hit)
    {
        hit = (PUCHAR)PatternScan(text, textSize, p22H2, m22H2);
        relOffset = 3;
        instrSize = 7;
    }
    if (!hit) return NULL;

    __try
    {
        LONG rip = *(PLONG)(hit + relOffset);
        return (PVOID)(hit + instrSize + rip);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }
}

static PVOID ResolveMmUnloadedDrivers(VOID)
{
    PVOID ntBase = ResolveModuleBaseAnsi("ntoskrnl.exe");
    if (!ntBase) return NULL;

    ULONG textSize = 0;
    PVOID text = FindSectionText(ntBase, &textSize);
    if (!text || textSize == 0) return NULL;

    static const UCHAR pat[] = {
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x85, 0xC0,
        0x74
    };
    static const CHAR mask[] = "xxx????xxxx";

    PUCHAR start = (PUCHAR)text;
    PUCHAR end = start + textSize;
    PUCHAR cursor = start;
    while (cursor < end)
    {
        PUCHAR hit = (PUCHAR)PatternScan(cursor, (ULONG)(end - cursor), pat, mask);
        if (!hit) return NULL;

        __try
        {
            LONG rip = *(PLONG)(hit + 3);
            PVOID candidate = (PVOID)(hit + 7 + rip);
            if (candidate != NULL) return candidate;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }

        cursor = hit + 1;
    }
    return NULL;
}

NTSTATUS TamperRootkitInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    g_PiDDBCacheTable = NULL;
    g_MmUnloaded = NULL;
    g_PiDDBExpectedCount = 0;
    g_PiDDBExpectedFnv = 0;
    g_MmUnloadedExpectedFnv = 0;
    return STATUS_SUCCESS;
}

VOID TamperRootkitShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);
}

NTSTATUS TamperRootkitSnapshot(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    if (!g_PiDDBCacheTable) g_PiDDBCacheTable = ResolvePiDDBCacheTable();
    if (!g_MmUnloaded)      g_MmUnloaded = ResolveMmUnloadedDrivers();

    if (g_PiDDBCacheTable)
    {
        ULONG count = 0;
        ULONG64 fnv = 0;
        ComputePiddbSnapshot(g_PiDDBCacheTable, &count, &fnv);
        g_PiDDBExpectedCount = count;
        g_PiDDBExpectedFnv = fnv;
    }
    if (g_MmUnloaded)
    {
        g_MmUnloadedExpectedFnv = ComputeMmUnloadedFnv(g_MmUnloaded);
    }
    return STATUS_SUCCESS;
}

NTSTATUS TamperRootkitVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    if (g_PiDDBCacheTable)
    {
        ULONG count = 0;
        ULONG64 fnv = 0;
        ComputePiddbSnapshot(g_PiDDBCacheTable, &count, &fnv);

        if (count < g_PiDDBExpectedCount || fnv != g_PiDDBExpectedFnv)
        {
            (VOID)EventsReportPiddbTamper((ULONG64)g_PiDDBCacheTable,
                                          g_PiDDBExpectedCount, count,
                                          g_PiDDBExpectedFnv, fnv);
            (VOID)EventsReportTamper(AC_TAMPER_REASON_PIDDB, g_PiDDBCacheTable);

            if (count > g_PiDDBExpectedCount)
            {
                g_PiDDBExpectedCount = count;
                g_PiDDBExpectedFnv = fnv;
            }
        }
        else if (count > g_PiDDBExpectedCount)
        {
            g_PiDDBExpectedCount = count;
            g_PiDDBExpectedFnv = fnv;
        }
    }

    if (g_MmUnloaded)
    {
        ULONG64 fnv = ComputeMmUnloadedFnv(g_MmUnloaded);
        if (fnv != 0 && fnv != g_MmUnloadedExpectedFnv)
        {
            (VOID)EventsReportMmUnloadedTamper((ULONG64)g_MmUnloaded,
                                               g_MmUnloadedExpectedFnv, fnv);
            (VOID)EventsReportTamper(AC_TAMPER_REASON_MMUNLOADED, g_MmUnloaded);
            g_MmUnloadedExpectedFnv = fnv;
        }
    }
    return STATUS_SUCCESS;
}
