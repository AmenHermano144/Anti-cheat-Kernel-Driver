#include "image_backing.h"
#include "page_walker.h"
#include "physmem.h"
#include "imports.h"
#include "env_checks.h"
#include "events.h"
#include "crypto.h"
#include "strings.h"
#include "wire_records.h"

#define IB_MAX_MODULES              1024
#define IB_TEXT_HASH_CAP            (8 * 1024 * 1024)
#define IB_HOLE_RATIO_THRESHOLD     60
#define IB_MAX_SECTIONS             96
#define IB_HEADER_READ_BYTES        0x1000
#define IB_MAX_IMAGE_SIZE           0x08000000

typedef struct _IB_SECTION
{
    CHAR    Name[9];
    ULONG   Rva;
    ULONG   VirtualSize;
    ULONG   RawSize;
    ULONG   Characteristics;
} IB_SECTION, *PIB_SECTION;

typedef struct _IB_PE_INFO
{
    BOOLEAN     Parsed;
    BOOLEAN     Is64Bit;
    USHORT      Machine;
    USHORT      SectionCount;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       TimeDateStamp;
    ULONG       EntryPointRva;
    ULONG64     OptionalImageBase;
    IB_SECTION  Sections[IB_MAX_SECTIONS];
    ULONG       FirstExecSection;
    BOOLEAN     HasExecSection;
} IB_PE_INFO, *PIB_PE_INFO;

typedef struct _IB_SCAN
{
    ULONG   Granules;
    ULONG   Present4k;
    ULONG   Present2m;
    ULONG   Present1g;
    ULONG   NotPresent;
    ULONG   Unreadable;
    ULONG   CopyFailed;
    ULONG   RwxPages;
    ULONG   WritableTextPages;
    ULONG   NxClearedTextPages;
    ULONG   MissingTextPages;
    ULONG   TextPresentPages;
    ULONG   TextTotalPages;
    BOOLEAN LargePageBacked;
    BOOLEAN HasResidentPage;
    UCHAR   TextHash[32];
    BOOLEAN TextHashValid;
} IB_SCAN, *PIB_SCAN;

typedef struct _IB_BASELINE
{
    volatile LONG   InUse;
    ULONG64         ImageBase;
    ULONG           ImageSize;
    ULONG           TextRva;
    ULONG           TextSize;
    UCHAR           TextHash[32];
    BOOLEAN         TextHashValid;
    BOOLEAN         ParsedOk;
    BOOLEAN         LargePageBacked;
    ULONG64         PathFnv;
    UCHAR           FullPath[256];
} IB_BASELINE, *PIB_BASELINE;

static IB_BASELINE   g_Baseline[IB_MAX_MODULES];
static KSPIN_LOCK    g_Lock;
static volatile LONG g_Initialized = 0;
static ULONG64       g_SystemDtb = 0;

static VOID IbCopyPath(const UCHAR *src, UCHAR *dst, SIZE_T dstCap)
{
    RtlZeroMemory(dst, dstCap);
    if (!src) return;
    SIZE_T i = 0;
    for (; i + 1 < dstCap && src[i] != 0; i++) dst[i] = src[i];
    dst[i] = 0;
}

static NTSTATUS IbReadHeaders(ULONG64 dtb, ULONG64 base, ULONG claimedSize, PIB_PE_INFO out)
{
    RtlZeroMemory(out, sizeof(*out));

    ULONG firstRead = IB_HEADER_READ_BYTES;
    if (claimedSize && claimedSize < firstRead) firstRead = claimedSize;
    if (firstRead < sizeof(IMAGE_DOS_HEADER)) return STATUS_INVALID_IMAGE_FORMAT;

    PUCHAR buf = (PUCHAR)CoreAlloc(IB_HEADER_READ_BYTES, CORE_AC_POOL_TAG_IMG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T got = 0, skipped = 0;
    NTSTATUS s = PwReadVirtualRange(dtb, base, buf, firstRead, &got, &skipped);
    if (skipped || got != firstRead)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return NT_SUCCESS(s) ? STATUS_PARTIAL_COPY : s;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        (ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > firstRead)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    USHORT optMagic = nt->OptionalHeader.Magic;
    USHORT machine  = nt->FileHeader.Machine;
    USHORT secCount = nt->FileHeader.NumberOfSections;
    USHORT optSize  = nt->FileHeader.SizeOfOptionalHeader;
    if (secCount == 0 || secCount > IB_MAX_SECTIONS)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ULONG imageSize = 0, sizeOfHeaders = 0, entryRva = 0, ts = 0;
    ULONG64 optBase = 0;
    BOOLEAN is64 = FALSE;
    ULONG secTableOff = (ULONG)dos->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + optSize;

    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        imageSize     = nt->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        entryRva      = nt->OptionalHeader.AddressOfEntryPoint;
        optBase       = nt->OptionalHeader.ImageBase;
        is64          = TRUE;
    }
    else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)(buf + dos->e_lfanew);
        imageSize     = nt32->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
        entryRva      = nt32->OptionalHeader.AddressOfEntryPoint;
        optBase       = nt32->OptionalHeader.ImageBase;
    }
    else
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    ts = nt->FileHeader.TimeDateStamp;

    if (!imageSize || imageSize > IB_MAX_IMAGE_SIZE)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)secTableOff + (SIZE_T)secCount * sizeof(IMAGE_SECTION_HEADER) > firstRead)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_IMG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(buf + secTableOff);

    out->Parsed        = TRUE;
    out->Is64Bit       = is64;
    out->Machine       = machine;
    out->SectionCount  = secCount;
    out->SizeOfImage   = imageSize;
    out->SizeOfHeaders = sizeOfHeaders;
    out->TimeDateStamp = ts;
    out->EntryPointRva = entryRva;
    out->OptionalImageBase = optBase;
    out->FirstExecSection = 0;
    out->HasExecSection = FALSE;

    for (USHORT i = 0; i < secCount; i++)
    {
        RtlCopyMemory(out->Sections[i].Name, sec[i].Name, 8);
        out->Sections[i].Name[8] = 0;
        out->Sections[i].Rva             = sec[i].VirtualAddress;
        out->Sections[i].VirtualSize     = sec[i].Misc.VirtualSize;
        out->Sections[i].RawSize         = sec[i].SizeOfRawData;
        out->Sections[i].Characteristics = sec[i].Characteristics;

        if (!out->HasExecSection && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            out->FirstExecSection = i;
            out->HasExecSection = TRUE;
        }
    }

    CoreFree(buf, CORE_AC_POOL_TAG_IMG);
    return STATUS_SUCCESS;
}

static VOID IbClassifyLeaf(PIB_SCAN scan, const PW_RESULT *w, BOOLEAN inExecSection)
{
    scan->HasResidentPage = TRUE;
    switch (w->Level)
    {
        case PwLevelPde2Mb:
            scan->Present2m++;
            scan->LargePageBacked = TRUE;
            break;
        case PwLevelPdpte1Gb:
            scan->Present1g++;
            scan->LargePageBacked = TRUE;
            break;
        default:
            scan->Present4k++;
            break;
    }

    BOOLEAN writable = w->Flags.Writable;
    BOOLEAN exec     = !w->Flags.ExecuteDisable;

    if (writable && exec) scan->RwxPages++;

    if (inExecSection)
    {
        if (writable) scan->WritableTextPages++;
        if (!exec)    scan->NxClearedTextPages++;
    }
}

static NTSTATUS IbScanImage(ULONG64 dtb, ULONG64 base, ULONG size, const IB_PE_INFO *pe,
                            PIB_SCAN outScan, PUCHAR textBuf, ULONG textBufCap, PULONG textBytesHashed)
{
    RtlZeroMemory(outScan, sizeof(*outScan));
    if (textBytesHashed) *textBytesHashed = 0;

    ULONG effectiveSize = size;
    if (pe && pe->Parsed && pe->SizeOfImage && pe->SizeOfImage < effectiveSize)
        effectiveSize = pe->SizeOfImage;
    if (!effectiveSize) return STATUS_INVALID_PARAMETER;

    ULONG64 end = base + effectiveSize;
    ULONG64 textVaStart = 0, textVaEnd = 0;
    if (pe && pe->Parsed && pe->HasExecSection)
    {
        const IB_SECTION *es = &pe->Sections[pe->FirstExecSection];
        textVaStart = base + es->Rva;
        textVaEnd   = textVaStart + es->VirtualSize;
        if (textVaEnd > end) textVaEnd = end;
        outScan->TextTotalPages = (ULONG)((textVaEnd - textVaStart + PAGE_SIZE - 1) >> PAGE_SHIFT);
    }

    ULONG64 va = base;
    while (va < end)
    {
        PW_RESULT w;
        NTSTATUS ws = PwWalk(dtb, va, &w);

        SIZE_T chunk = PAGE_SIZE - (SIZE_T)(va & (PAGE_SIZE - 1));
        ULONG64 remaining = end - va;
        if ((ULONG64)chunk > remaining) chunk = (SIZE_T)remaining;

        ULONG rva = (ULONG)(va - base);
        BOOLEAN inExec = (textVaStart && va >= textVaStart && va < textVaEnd);

        outScan->Granules++;

        if (!NT_SUCCESS(ws) || w.Status != PwStatusSuccess)
        {
            if (w.Status == PwStatusNotPresent)
            {
                outScan->NotPresent++;
                if (inExec) outScan->MissingTextPages++;
            }
            else if (w.Status == PwStatusPhysicalReadFailure)
            {
                outScan->Unreadable++;
                if (inExec) outScan->MissingTextPages++;
            }
            else
            {
                outScan->Unreadable++;
                if (inExec) outScan->MissingTextPages++;
            }

            if (inExec && textBuf && textBufCap)
            {
                ULONG off = (ULONG)(va - textVaStart);
                if (off < textBufCap)
                {
                    ULONG span = (ULONG)chunk;
                    if (off + span > textBufCap) span = textBufCap - off;
                    RtlZeroMemory(textBuf + off, span);
                }
            }

            va += chunk;
            continue;
        }

        IbClassifyLeaf(outScan, &w, inExec);

        if (inExec)
        {
            outScan->TextPresentPages++;
            if (textBuf && textBufCap)
            {
                ULONG off = (ULONG)(va - textVaStart);
                if (off < textBufCap)
                {
                    ULONG span = (ULONG)chunk;
                    if (off + span > textBufCap) span = textBufCap - off;
                    NTSTATUS cs = PhysMemReadRaw(w.ResolvedPhysicalAddress, textBuf + off, span);
                    if (!NT_SUCCESS(cs))
                    {
                        outScan->CopyFailed++;
                        RtlZeroMemory(textBuf + off, span);
                    }
                    else if (textBytesHashed)
                    {
                        ULONG endOff = off + span;
                        if (endOff > *textBytesHashed) *textBytesHashed = endOff;
                    }
                }
            }
        }

        va += chunk;
    }

    if (textBuf && textBufCap && textBytesHashed && *textBytesHashed > 0)
    {
        if (NT_SUCCESS(CryptoSha256(textBuf, *textBytesHashed, outScan->TextHash)))
            outScan->TextHashValid = TRUE;
    }

    return STATUS_SUCCESS;
}

static PIB_BASELINE IbFindOrAllocSlotLocked(ULONG64 base)
{
    PIB_BASELINE empty = NULL;
    for (ULONG i = 0; i < IB_MAX_MODULES; i++)
    {
        PIB_BASELINE e = &g_Baseline[i];
        if (e->InUse && e->ImageBase == base) return e;
        if (!e->InUse && !empty) empty = e;
    }
    return empty;
}

static PIB_BASELINE IbFindSlotLocked(ULONG64 base)
{
    for (ULONG i = 0; i < IB_MAX_MODULES; i++)
    {
        PIB_BASELINE e = &g_Baseline[i];
        if (e->InUse && e->ImageBase == base) return e;
    }
    return NULL;
}

static VOID IbStoreBaseline(ULONG64 base, ULONG size, const UCHAR *path,
                            const IB_PE_INFO *pe, const IB_SCAN *scan)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);

    PIB_BASELINE slot = IbFindOrAllocSlotLocked(base);
    if (!slot)
    {
        KeReleaseSpinLock(&g_Lock, irql);
        return;
    }

    RtlZeroMemory(slot, sizeof(*slot));
    slot->ImageBase = base;
    slot->ImageSize = (pe && pe->Parsed && pe->SizeOfImage) ? pe->SizeOfImage : size;
    slot->ParsedOk = pe ? pe->Parsed : FALSE;
    slot->LargePageBacked = scan ? scan->LargePageBacked : FALSE;

    if (pe && pe->Parsed && pe->HasExecSection)
    {
        const IB_SECTION *es = &pe->Sections[pe->FirstExecSection];
        slot->TextRva = es->Rva;
        slot->TextSize = es->VirtualSize;
    }

    if (scan && scan->TextHashValid)
    {
        RtlCopyMemory(slot->TextHash, scan->TextHash, sizeof(slot->TextHash));
        slot->TextHashValid = TRUE;
    }

    IbCopyPath(path, slot->FullPath, sizeof(slot->FullPath));
    slot->PathFnv = CoreFnv1a64(slot->FullPath, CoreStrLenA((const CHAR *)slot->FullPath));

    InterlockedExchange(&slot->InUse, 1);
    KeReleaseSpinLock(&g_Lock, irql);
}

static VOID IbEmitAnomaly(ULONG64 base, ULONG64 size, ULONG64 dtb, ULONG64 pathFnv,
                          const UCHAR *path, ULONG flags, const IB_SCAN *scan,
                          const UCHAR *baselineHash, const UCHAR *observedHash)
{
    if (!flags) return;

    WIRE_PAGE_WALK_ANOMALY rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.ImageBase = base;
    rec.ImageSize = size;
    rec.DirectoryTableBase = dtb;
    rec.Fnv1a64Path = pathFnv;
    rec.Flags = flags;

    if (scan)
    {
        rec.Granules          = scan->Granules;
        rec.Present4k         = scan->Present4k;
        rec.Present2m         = scan->Present2m;
        rec.Present1g         = scan->Present1g;
        rec.NotPresent        = scan->NotPresent;
        rec.Unreadable        = scan->Unreadable;
        rec.CopyFailed        = scan->CopyFailed;
        rec.RwxPages          = scan->RwxPages;
        rec.WritableTextPages = scan->WritableTextPages;
        rec.NxClearedTextPages = scan->NxClearedTextPages;
        rec.MissingTextPages  = scan->MissingTextPages;
    }
    if (baselineHash) RtlCopyMemory(rec.TextHashBaseline, baselineHash, 32);
    if (observedHash) RtlCopyMemory(rec.TextHashObserved, observedHash, 32);

    if (path)
    {
        SIZE_T plen = 0;
        while (plen < sizeof(rec.ImagePath) && path[plen] != 0) plen++;
        rec.ImagePathLen = (USHORT)plen;
        RtlCopyMemory(rec.ImagePath, path, plen);
    }

    (VOID)EventsReportPageWalkAnomaly(&rec);
}

static ULONG IbComputeHoleRatioPct(const IB_SCAN *scan)
{
    if (!scan || scan->TextTotalPages == 0) return 0;
    ULONG missing = scan->MissingTextPages;
    if (missing > scan->TextTotalPages) missing = scan->TextTotalPages;
    return (missing * 100) / scan->TextTotalPages;
}

NTSTATUS ImageBackingInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    KeInitializeSpinLock(&g_Lock);
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));

    NTSTATUS s = PwInit();
    if (!NT_SUCCESS(s))
    {
        InterlockedExchange(&g_Initialized, 0);
        return s;
    }

    s = PwGetSystemDtb(&g_SystemDtb);
    if (!NT_SUCCESS(s)) g_SystemDtb = PwReadCurrentCr3();

    return STATUS_SUCCESS;
}

VOID ImageBackingShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);

    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));
    KeReleaseSpinLock(&g_Lock, irql);

    g_SystemDtb = 0;
}

NTSTATUS ImageBackingBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!PwIsInitialized()) return STATUS_DEVICE_NOT_READY;
    if (!g_SystemDtb) return STATUS_INVALID_PARAMETER;

    PVOID buf = NULL;
    ULONG count = 0;
    NTSTATUS s = EnvEnumKernelModules(&buf, &count);
    if (!NT_SUCCESS(s)) return s;
    if (!buf || count == 0) { if (buf) CoreFree(buf, CORE_AC_POOL_TAG_SCAN); return STATUS_UNSUCCESSFUL; }

    PUCHAR textBuf = (PUCHAR)CoreAlloc(IB_TEXT_HASH_CAP, CORE_AC_POOL_TAG_IMG);
    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;

    for (ULONG i = 0; i < count && i < IB_MAX_MODULES; i++)
    {
        PSYSTEM_MODULE_INFORMATION_ENTRY m = &mods->Module[i];
        ULONG64 base = (ULONG64)m->ImageBase;
        ULONG size = m->ImageSize;
        if (!base || !size) continue;

        IB_PE_INFO pe;
        (VOID)IbReadHeaders(g_SystemDtb, base, size, &pe);

        IB_SCAN scan;
        ULONG bytesHashed = 0;
        ULONG capForThis = 0;
        PUCHAR capBuf = NULL;
        if (textBuf && pe.Parsed && pe.HasExecSection)
        {
            capForThis = pe.Sections[pe.FirstExecSection].VirtualSize;
            if (capForThis > IB_TEXT_HASH_CAP) capForThis = IB_TEXT_HASH_CAP;
            RtlZeroMemory(textBuf, capForThis);
            capBuf = textBuf;
        }

        (VOID)IbScanImage(g_SystemDtb, base, size, &pe, &scan, capBuf, capForThis, &bytesHashed);
        IbStoreBaseline(base, size, m->FullPathName, &pe, &scan);
    }

    if (textBuf) CoreFree(textBuf, CORE_AC_POOL_TAG_IMG);
    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

NTSTATUS ImageBackingVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!PwIsInitialized() || !g_SystemDtb) return STATUS_DEVICE_NOT_READY;

    PVOID buf = NULL;
    ULONG count = 0;
    NTSTATUS s = EnvEnumKernelModules(&buf, &count);
    if (!NT_SUCCESS(s)) return s;
    if (!buf) return STATUS_UNSUCCESSFUL;

    PUCHAR textBuf = (PUCHAR)CoreAlloc(IB_TEXT_HASH_CAP, CORE_AC_POOL_TAG_IMG);
    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;

    for (ULONG i = 0; i < count; i++)
    {
        PSYSTEM_MODULE_INFORMATION_ENTRY m = &mods->Module[i];
        ULONG64 base = (ULONG64)m->ImageBase;
        ULONG size = m->ImageSize;
        if (!base || !size) continue;

        IB_PE_INFO pe;
        (VOID)IbReadHeaders(g_SystemDtb, base, size, &pe);

        IB_SCAN scan;
        ULONG bytesHashed = 0;
        ULONG capForThis = 0;
        PUCHAR capBuf = NULL;
        if (textBuf && pe.Parsed && pe.HasExecSection)
        {
            capForThis = pe.Sections[pe.FirstExecSection].VirtualSize;
            if (capForThis > IB_TEXT_HASH_CAP) capForThis = IB_TEXT_HASH_CAP;
            RtlZeroMemory(textBuf, capForThis);
            capBuf = textBuf;
        }

        (VOID)IbScanImage(g_SystemDtb, base, size, &pe, &scan, capBuf, capForThis, &bytesHashed);

        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        PIB_BASELINE slot = IbFindSlotLocked(base);
        IB_BASELINE snapshot;
        BOOLEAN haveBaseline = FALSE;
        if (slot) { snapshot = *slot; haveBaseline = TRUE; }
        KeReleaseSpinLock(&g_Lock, irql);

        ULONG flags = 0;
        const UCHAR *baselineHash = NULL;

        if (!pe.Parsed)       flags |= PW_ANOM_PARSE_FAIL;
        if (scan.RwxPages)    flags |= PW_ANOM_RWX;
        if (scan.WritableTextPages) flags |= PW_ANOM_WRITABLE_TEXT;
        if (scan.NxClearedTextPages) flags |= PW_ANOM_NX_CLEARED_TEXT;
        if (scan.LargePageBacked) flags |= PW_ANOM_LARGE_PAGE;
        if (!scan.HasResidentPage) flags |= PW_ANOM_RACE_OR_UNMAPPED;

        if (scan.TextTotalPages > 0)
        {
            ULONG pct = IbComputeHoleRatioPct(&scan);
            if (pct >= IB_HOLE_RATIO_THRESHOLD) flags |= PW_ANOM_HOLE_RATIO_HIGH;
            if (scan.MissingTextPages > 0 && scan.MissingTextPages < scan.TextTotalPages)
                flags |= PW_ANOM_TEXT_MISSING;
        }

        if (haveBaseline)
        {
            if (snapshot.ImageSize && pe.Parsed && pe.SizeOfImage && pe.SizeOfImage < snapshot.ImageSize)
                flags |= PW_ANOM_SECTION_SHRUNK;

            if (snapshot.TextHashValid && scan.TextHashValid &&
                RtlCompareMemory(snapshot.TextHash, scan.TextHash, 32) != 32)
            {
                flags |= PW_ANOM_HASH_DRIFT;
                baselineHash = snapshot.TextHash;
            }
        }
        else
        {
            flags |= PW_ANOM_NEW_MODULE;
            IbStoreBaseline(base, size, m->FullPathName, &pe, &scan);
        }

        if (flags)
        {
            IbEmitAnomaly(base,
                          pe.Parsed && pe.SizeOfImage ? pe.SizeOfImage : size,
                          g_SystemDtb,
                          haveBaseline ? snapshot.PathFnv : CoreFnv1a64(m->FullPathName, CoreStrLenA((const CHAR *)m->FullPathName)),
                          m->FullPathName,
                          flags,
                          &scan,
                          baselineHash,
                          scan.TextHashValid ? scan.TextHash : NULL);
        }
    }

    if (textBuf) CoreFree(textBuf, CORE_AC_POOL_TAG_IMG);
    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

NTSTATUS ImageBackingOnKernelImageLoad(PUNICODE_STRING fullImageName, PIMAGE_INFO imageInfo)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_SUCCESS;
    if (!imageInfo || !imageInfo->ImageBase || !imageInfo->ImageSize) return STATUS_INVALID_PARAMETER;
    if (!PwIsInitialized() || !g_SystemDtb) return STATUS_DEVICE_NOT_READY;

    ULONG64 base = (ULONG64)imageInfo->ImageBase;
    ULONG size   = (ULONG)imageInfo->ImageSize;

    UCHAR asciiPath[260] = { 0 };
    USHORT pathBytes = 0;
    if (fullImageName && fullImageName->Buffer && fullImageName->Length > 0)
    {
        USHORT wchars = fullImageName->Length / sizeof(WCHAR);
        if (wchars >= RTL_NUMBER_OF(asciiPath)) wchars = RTL_NUMBER_OF(asciiPath) - 1;
        for (USHORT i = 0; i < wchars; i++)
        {
            WCHAR c = fullImageName->Buffer[i];
            asciiPath[i] = (c > 0 && c < 0x80) ? (UCHAR)c : (UCHAR)'?';
        }
        asciiPath[wchars] = 0;
        pathBytes = wchars;
    }

    IB_PE_INFO pe;
    (VOID)IbReadHeaders(g_SystemDtb, base, size, &pe);

    PUCHAR textBuf = (PUCHAR)CoreAlloc(IB_TEXT_HASH_CAP, CORE_AC_POOL_TAG_IMG);
    IB_SCAN scan;
    ULONG bytesHashed = 0;
    ULONG capForThis = 0;
    PUCHAR capBuf = NULL;
    if (textBuf && pe.Parsed && pe.HasExecSection)
    {
        capForThis = pe.Sections[pe.FirstExecSection].VirtualSize;
        if (capForThis > IB_TEXT_HASH_CAP) capForThis = IB_TEXT_HASH_CAP;
        RtlZeroMemory(textBuf, capForThis);
        capBuf = textBuf;
    }

    (VOID)IbScanImage(g_SystemDtb, base, size, &pe, &scan, capBuf, capForThis, &bytesHashed);

    ULONG flags = 0;
    if (!pe.Parsed) flags |= PW_ANOM_PARSE_FAIL;
    if (scan.RwxPages) flags |= PW_ANOM_RWX;
    if (scan.WritableTextPages) flags |= PW_ANOM_WRITABLE_TEXT;
    if (scan.NxClearedTextPages) flags |= PW_ANOM_NX_CLEARED_TEXT;
    if (scan.LargePageBacked) flags |= PW_ANOM_LARGE_PAGE;
    if (!scan.HasResidentPage) flags |= PW_ANOM_RACE_OR_UNMAPPED;

    IbStoreBaseline(base, size, asciiPath, &pe, &scan);

    if (flags)
    {
        IbEmitAnomaly(base,
                      pe.Parsed && pe.SizeOfImage ? pe.SizeOfImage : size,
                      g_SystemDtb,
                      CoreFnv1a64(asciiPath, pathBytes),
                      asciiPath,
                      flags | PW_ANOM_NEW_MODULE,
                      &scan,
                      NULL,
                      scan.TextHashValid ? scan.TextHash : NULL);
    }

    if (textBuf) CoreFree(textBuf, CORE_AC_POOL_TAG_IMG);
    return STATUS_SUCCESS;
}
