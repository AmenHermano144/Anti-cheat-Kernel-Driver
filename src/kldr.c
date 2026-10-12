#include "kldr.h"
#include "imports.h"
#include "env_checks.h"
#include "strings.h"
#include "driver_ts_blacklist.h"
#include "byovd_scanner.h"
#include "events.h"
#include "channels.h"
#include "wire_records.h"

#define KLDR_MAX_ENTRIES   1024

static KSPIN_LOCK          g_KldrLock;
static PKLDR_MODULE_ENTRY  g_Snapshot = NULL;
static volatile ULONG      g_SnapshotCount = 0;

static ULONG ReadPeTimestamp(PVOID imageBase)
{
    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        return nt->FileHeader.TimeDateStamp;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

NTSTATUS KldrSnapshotModules(VOID)
{
    PVOID buf = NULL;
    ULONG count = 0;
    NTSTATUS s = EnvEnumKernelModules(&buf, &count);
    if (!NT_SUCCESS(s)) return s;
    if (!buf || count == 0) { if (buf) CoreFree(buf, CORE_AC_POOL_TAG_SCAN); return STATUS_UNSUCCESSFUL; }

    KeInitializeSpinLock(&g_KldrLock);

    SIZE_T cap = (count < KLDR_MAX_ENTRIES) ? count : KLDR_MAX_ENTRIES;
    PKLDR_MODULE_ENTRY arr = (PKLDR_MODULE_ENTRY)CoreAlloc(sizeof(KLDR_MODULE_ENTRY) * cap,
                                                          CORE_AC_POOL_TAG_SCAN);
    if (!arr) { CoreFree(buf, CORE_AC_POOL_TAG_SCAN); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlZeroMemory(arr, sizeof(KLDR_MODULE_ENTRY) * cap);

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;
    for (ULONG i = 0; i < count && i < cap; i++)
    {
        PSYSTEM_MODULE_INFORMATION_ENTRY m = &mods->Module[i];
        PKLDR_MODULE_ENTRY e = &arr[i];
        e->ImageBase = (ULONG64)m->ImageBase;
        e->ImageSize = m->ImageSize;
        e->NameOffset = m->OffsetToFileName;
        RtlCopyMemory(e->FullPath, m->FullPathName, sizeof(e->FullPath));
        e->PeTimestamp = ReadPeTimestamp(m->ImageBase);
        e->Fnv1a64 = CoreFnv1a64(m->FullPathName, CoreStrLenA((const CHAR *)m->FullPathName));
    }

    g_Snapshot = arr;
    InterlockedExchange((volatile LONG *)&g_SnapshotCount, (LONG)cap);

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

ULONG KldrSnapshotCount(VOID)
{
    return InterlockedCompareExchange((volatile LONG *)&g_SnapshotCount, 0, 0);
}

BOOLEAN KldrAddressBelongsToKnownModule(PVOID address)
{
    ULONG n = KldrSnapshotCount();
    if (!g_Snapshot || !address || n == 0) return FALSE;

    ULONG64 a = (ULONG64)address;
    for (ULONG i = 0; i < n; i++)
    {
        PKLDR_MODULE_ENTRY e = &g_Snapshot[i];
        if (a >= e->ImageBase && a < e->ImageBase + e->ImageSize) return TRUE;
    }
    return FALSE;
}

NTSTATUS KldrOnKernelImageLoad(PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo) return STATUS_SUCCESS;

    ULONG ts = ReadPeTimestamp(ImageInfo->ImageBase);
    if (DriverTsIsBlacklisted(ts))
    {
        WIRE_BYOVD_HIT hit;
        RtlZeroMemory(&hit, sizeof(hit));
        hit.ImageBase = (ULONG64)ImageInfo->ImageBase;
        hit.ImageSize = (ULONG)ImageInfo->ImageSize;
        USHORT nb = FullImageName->Length;
        if (nb > sizeof(hit.ImagePath)) nb = sizeof(hit.ImagePath);
        hit.ImagePathLen = nb;
        RtlCopyMemory(hit.ImagePath, FullImageName->Buffer, nb);
        hit.Fnv1a64 = CoreFnv1a64(FullImageName->Buffer, nb);
        (VOID)ChannelEnqueueRecord(WIRE_REC_BYOVD_HIT, &hit, sizeof(hit));
    }
    return STATUS_SUCCESS;
}

NTSTATUS KldrDiffScan(VOID)
{
    PVOID buf = NULL;
    ULONG count = 0;
    NTSTATUS s = EnvEnumKernelModules(&buf, &count);
    if (!NT_SUCCESS(s)) return s;
    if (!buf) return STATUS_UNSUCCESSFUL;

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;
    for (ULONG i = 0; i < count; i++)
    {
        PSYSTEM_MODULE_INFORMATION_ENTRY m = &mods->Module[i];
        UNICODE_STRING u;
        WCHAR tmp[260];
        SIZE_T l = CoreStrLenA((const CHAR *)m->FullPathName);
        if (l >= RTL_NUMBER_OF(tmp)) l = RTL_NUMBER_OF(tmp) - 1;
        for (SIZE_T k = 0; k < l; k++) tmp[k] = (WCHAR)m->FullPathName[k];
        tmp[l] = 0;
        u.Buffer = tmp;
        u.Length = (USHORT)(l * sizeof(WCHAR));
        u.MaximumLength = u.Length + sizeof(WCHAR);

        if (ByovdPathIsBlacklisted(&u))
        {
            WIRE_BYOVD_HIT hit;
            RtlZeroMemory(&hit, sizeof(hit));
            hit.ImageBase = (ULONG64)m->ImageBase;
            hit.ImageSize = m->ImageSize;
            USHORT nb = (USHORT)(l * sizeof(WCHAR));
            if (nb > sizeof(hit.ImagePath)) nb = (USHORT)sizeof(hit.ImagePath);
            hit.ImagePathLen = nb;
            RtlCopyMemory(hit.ImagePath, tmp, nb);
            hit.Fnv1a64 = CoreFnv1a64(tmp, nb);
            (VOID)ChannelEnqueueRecord(WIRE_REC_BYOVD_HIT, &hit, sizeof(hit));
        }
    }

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}
