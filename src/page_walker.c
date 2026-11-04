#include "page_walker.h"
#include "physmem.h"
#include "imports.h"

#define PW_PTE_PRESENT          (1ULL << 0)
#define PW_PTE_WRITABLE         (1ULL << 1)
#define PW_PTE_USER             (1ULL << 2)
#define PW_PTE_PWT              (1ULL << 3)
#define PW_PTE_PCD              (1ULL << 4)
#define PW_PTE_ACCESSED         (1ULL << 5)
#define PW_PTE_DIRTY            (1ULL << 6)
#define PW_PTE_PAGE_SIZE        (1ULL << 7)
#define PW_PTE_GLOBAL           (1ULL << 8)
#define PW_PTE_PAT_LARGE        (1ULL << 12)
#define PW_PTE_NX               (1ULL << 63)

#define PW_DEFAULT_PHYS_MASK    0x000FFFFFFFFFFFFFULL
#define PW_DEFAULT_FRAME_MASK   0x000FFFFFFFFFF000ULL
#define PW_KPROCESS_DTB_OFFSET  0x28

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

typedef struct _PW_STATE
{
    BOOLEAN Initialized;
    BOOLEAN LongModeActive;
    BOOLEAN FiveLevel;
    UCHAR   MaxPhyAddr;
    ULONG64 PhysMask;
    ULONG64 FrameMask;
} PW_STATE, *PPW_STATE;

static PW_STATE g_Pw = { 0 };

static ULONG64 PwReadMsrEfer(VOID)
{
    return __readmsr(0xC0000080);
}

static BOOLEAN PwCpuHasLeaf(INT32 leaf)
{
    INT32 info[4] = { 0 };
    __cpuid(info, 0x80000000);
    return (UINT32)info[0] >= (UINT32)leaf;
}

static UCHAR PwQueryMaxPhyAddr(VOID)
{
    if (!PwCpuHasLeaf(0x80000008)) return 52;

    INT32 info[4] = { 0 };
    __cpuid(info, 0x80000008);
    UCHAR m = (UCHAR)(info[0] & 0xFF);
    if (m < 36 || m > 52) return 52;
    return m;
}

static ULONG64 PwMakePhysMask(UCHAR maxPhyAddr)
{
    if (maxPhyAddr >= 64) return ~0ULL;
    return (1ULL << maxPhyAddr) - 1ULL;
}

static BOOLEAN PwIsCanonical(ULONG64 va, BOOLEAN fiveLevel)
{
    LONG64 sva = (LONG64)va;
    if (fiveLevel)
    {
        LONG64 top = sva >> 56;
        return top == 0 || top == -1;
    }
    LONG64 top = sva >> 47;
    return top == 0 || top == -1;
}

static ULONG64 PwFrameFromEntry(ULONG64 entry)
{
    return entry & g_Pw.FrameMask;
}

static NTSTATUS PwReadTableEntry(ULONG64 tableBase, ULONG index, PULONG64 outEntry, PULONG64 outEntryPa)
{
    *outEntry = 0;
    *outEntryPa = 0;
    if (index > 511) return STATUS_INVALID_PARAMETER;

    ULONG64 ea = tableBase + (ULONG64)index * 8ULL;
    NTSTATUS s = PhysMemReadRaw(ea, outEntry, sizeof(*outEntry));
    if (!NT_SUCCESS(s)) return s;

    *outEntryPa = ea;
    return STATUS_SUCCESS;
}

static VOID PwResetResult(PPW_RESULT r, ULONG64 dtb, ULONG64 va)
{
    RtlZeroMemory(r, sizeof(*r));
    r->DirectoryTableBase = dtb;
    r->VirtualAddress = va;
    r->Status = PwStatusInvalidParameter;
    r->Level = PwLevelNone;
}

static VOID PwAccumulateNonLeaf(PPW_FLAGS flags, ULONG64 entry)
{
    flags->Present        = (entry & PW_PTE_PRESENT) != 0;
    flags->Writable       = flags->Writable && ((entry & PW_PTE_WRITABLE) != 0);
    flags->User           = flags->User && ((entry & PW_PTE_USER) != 0);
    flags->ExecuteDisable = flags->ExecuteDisable || ((entry & PW_PTE_NX) != 0);
    flags->Accessed       = flags->Accessed || ((entry & PW_PTE_ACCESSED) != 0);
}

static VOID PwApplyLeafFlags(PPW_FLAGS flags, ULONG64 entry, BOOLEAN largePage)
{
    PwAccumulateNonLeaf(flags, entry);
    flags->Dirty        = (entry & PW_PTE_DIRTY) != 0;
    flags->Global       = (entry & PW_PTE_GLOBAL) != 0;
    flags->WriteThrough = (entry & PW_PTE_PWT) != 0;
    flags->CacheDisable = (entry & PW_PTE_PCD) != 0;
    flags->LargePage    = largePage;
    flags->Pat          = largePage ? ((entry & PW_PTE_PAT_LARGE) != 0)
                                    : ((entry & PW_PTE_PAGE_SIZE) != 0);
}

static BOOLEAN PwReserved1Gb(ULONG64 entry)
{
    return (entry & 0x000000003FFFE000ULL) != 0;
}

static BOOLEAN PwReserved2Mb(ULONG64 entry)
{
    return (entry & 0x00000000001FE000ULL) != 0;
}

static NTSTATUS PwStatusToNt(PW_STATUS s)
{
    switch (s)
    {
        case PwStatusSuccess:              return STATUS_SUCCESS;
        case PwStatusNotPresent:           return STATUS_NOT_FOUND;
        case PwStatusInvalidAddress:       return STATUS_INVALID_ADDRESS;
        case PwStatusPhysicalReadFailure:  return STATUS_IN_PAGE_ERROR;
        case PwStatusUnsupportedPaging:    return STATUS_NOT_SUPPORTED;
        case PwStatusReservedBitViolation: return STATUS_ILLEGAL_INSTRUCTION;
        default:                           return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS PwFinishLeaf(PPW_RESULT r, ULONG64 entry, ULONG64 entryPa, ULONG64 pageSize, PW_LEVEL level, BOOLEAN reserved)
{
    ULONG64 pageMask = ~(pageSize - 1ULL);
    ULONG64 frame = entry & g_Pw.FrameMask & pageMask;
    ULONG64 offset = r->VirtualAddress & (pageSize - 1ULL);

    r->LeafEntryPhysical = entryPa;
    r->MappedPagePhysicalBase = frame;
    r->ResolvedPhysicalAddress = frame + offset;
    r->PageSize = pageSize;
    r->PageOffset = offset;
    r->Level = level;
    r->Flags.ReservedBitsSet = reserved;

    if (reserved)
    {
        r->Status = PwStatusReservedBitViolation;
        return PwStatusToNt(r->Status);
    }
    r->Status = PwStatusSuccess;
    return STATUS_SUCCESS;
}

NTSTATUS PwInit(VOID)
{
    PW_STATE s;
    RtlZeroMemory(&s, sizeof(s));

    ULONG64 cr0 = __readcr0();
    ULONG64 cr4 = __readcr4();
    ULONG64 efer = PwReadMsrEfer();

    BOOLEAN paging = (cr0 & (1ULL << 31)) != 0;
    BOOLEAN pae    = (cr4 & (1ULL << 5))  != 0;
    BOOLEAN lma    = (efer & (1ULL << 10)) != 0;

    if (!paging || !pae || !lma)
    {
        RtlZeroMemory(&g_Pw, sizeof(g_Pw));
        g_Pw.Initialized = TRUE;
        g_Pw.LongModeActive = FALSE;
        return STATUS_NOT_SUPPORTED;
    }

    s.Initialized = TRUE;
    s.LongModeActive = TRUE;
    s.FiveLevel = (cr4 & (1ULL << 12)) != 0;
    s.MaxPhyAddr = PwQueryMaxPhyAddr();
    s.PhysMask = PwMakePhysMask(s.MaxPhyAddr);
    s.FrameMask = s.PhysMask & ~(ULONG64)(PAGE_SIZE - 1);

    if (!s.FrameMask)
    {
        s.PhysMask = PW_DEFAULT_PHYS_MASK;
        s.FrameMask = PW_DEFAULT_FRAME_MASK;
        s.MaxPhyAddr = 52;
    }

    g_Pw = s;
    return STATUS_SUCCESS;
}

BOOLEAN PwIsInitialized(VOID)
{
    return g_Pw.Initialized;
}

BOOLEAN PwUsesFiveLevelPaging(VOID)
{
    return g_Pw.Initialized && g_Pw.FiveLevel;
}

ULONG64 PwReadCurrentCr3(VOID)
{
    return __readcr3();
}

NTSTATUS PwGetSystemDtb(PULONG64 outDtb)
{
    if (!outDtb) return STATUS_INVALID_PARAMETER;
    *outDtb = 0;

    PEPROCESS sys = PsInitialSystemProcess;
    ULONG64 dtb = 0;

    if (sys)
    {
        RtlCopyMemory(&dtb, (PUCHAR)sys + PW_KPROCESS_DTB_OFFSET, sizeof(dtb));
    }

    ULONG64 frame = dtb & (g_Pw.Initialized ? g_Pw.FrameMask : PW_DEFAULT_FRAME_MASK);
    if (!frame) dtb = PwReadCurrentCr3();

    *outDtb = dtb;
    return STATUS_SUCCESS;
}

NTSTATUS PwWalk(ULONG64 dtb, ULONG64 va, PPW_RESULT r)
{
    if (!r) return STATUS_INVALID_PARAMETER;

    PwResetResult(r, dtb, va);
    r->FiveLevelPaging = g_Pw.FiveLevel;

    if (!g_Pw.Initialized || !g_Pw.LongModeActive)
    {
        r->Status = PwStatusUnsupportedPaging;
        return PwStatusToNt(r->Status);
    }

    if (!PwIsCanonical(va, g_Pw.FiveLevel))
    {
        r->Status = PwStatusInvalidAddress;
        return PwStatusToNt(r->Status);
    }

    ULONG64 pml = dtb & g_Pw.FrameMask;
    if (!pml)
    {
        r->Status = PwStatusInvalidParameter;
        return STATUS_INVALID_PARAMETER;
    }

    PW_FLAGS flags;
    RtlZeroMemory(&flags, sizeof(flags));
    flags.Present = TRUE;
    flags.Writable = TRUE;
    flags.User = TRUE;

    ULONG64 tablePa = pml;
    ULONG64 entryPa = 0;
    NTSTATUS s;

    if (g_Pw.FiveLevel)
    {
        ULONG idx = (ULONG)((va >> 48) & 0x1FF);
        s = PwReadTableEntry(tablePa, idx, &r->Pml5e, &entryPa);
        if (!NT_SUCCESS(s))
        {
            r->Status = PwStatusPhysicalReadFailure;
            return PwStatusToNt(r->Status);
        }
        PwAccumulateNonLeaf(&flags, r->Pml5e);
        if (!(r->Pml5e & PW_PTE_PRESENT))
        {
            r->Flags = flags;
            r->Flags.Present = FALSE;
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
        if (r->Pml5e & PW_PTE_PAGE_SIZE)
        {
            r->Flags = flags;
            r->Flags.ReservedBitsSet = TRUE;
            r->Status = PwStatusReservedBitViolation;
            return PwStatusToNt(r->Status);
        }
        tablePa = PwFrameFromEntry(r->Pml5e);
        if (!tablePa)
        {
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
    }

    {
        ULONG idx = (ULONG)((va >> 39) & 0x1FF);
        s = PwReadTableEntry(tablePa, idx, &r->Pml4e, &entryPa);
        if (!NT_SUCCESS(s))
        {
            r->Status = PwStatusPhysicalReadFailure;
            return PwStatusToNt(r->Status);
        }
        PwAccumulateNonLeaf(&flags, r->Pml4e);
        if (!(r->Pml4e & PW_PTE_PRESENT))
        {
            r->Flags = flags;
            r->Flags.Present = FALSE;
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
        if (r->Pml4e & PW_PTE_PAGE_SIZE)
        {
            r->Flags = flags;
            r->Flags.ReservedBitsSet = TRUE;
            r->Status = PwStatusReservedBitViolation;
            return PwStatusToNt(r->Status);
        }
        tablePa = PwFrameFromEntry(r->Pml4e);
        if (!tablePa)
        {
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
    }

    {
        ULONG idx = (ULONG)((va >> 30) & 0x1FF);
        s = PwReadTableEntry(tablePa, idx, &r->Pdpte, &entryPa);
        if (!NT_SUCCESS(s))
        {
            r->Status = PwStatusPhysicalReadFailure;
            return PwStatusToNt(r->Status);
        }
        PwAccumulateNonLeaf(&flags, r->Pdpte);
        if (!(r->Pdpte & PW_PTE_PRESENT))
        {
            r->Flags = flags;
            r->Flags.Present = FALSE;
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
        if (r->Pdpte & PW_PTE_PAGE_SIZE)
        {
            PwApplyLeafFlags(&flags, r->Pdpte, TRUE);
            r->Flags = flags;
            return PwFinishLeaf(r, r->Pdpte, entryPa, 0x40000000ULL, PwLevelPdpte1Gb, PwReserved1Gb(r->Pdpte));
        }
        tablePa = PwFrameFromEntry(r->Pdpte);
        if (!tablePa)
        {
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
    }

    {
        ULONG idx = (ULONG)((va >> 21) & 0x1FF);
        s = PwReadTableEntry(tablePa, idx, &r->Pde, &entryPa);
        if (!NT_SUCCESS(s))
        {
            r->Status = PwStatusPhysicalReadFailure;
            return PwStatusToNt(r->Status);
        }
        PwAccumulateNonLeaf(&flags, r->Pde);
        if (!(r->Pde & PW_PTE_PRESENT))
        {
            r->Flags = flags;
            r->Flags.Present = FALSE;
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
        if (r->Pde & PW_PTE_PAGE_SIZE)
        {
            PwApplyLeafFlags(&flags, r->Pde, TRUE);
            r->Flags = flags;
            return PwFinishLeaf(r, r->Pde, entryPa, 0x200000ULL, PwLevelPde2Mb, PwReserved2Mb(r->Pde));
        }
        tablePa = PwFrameFromEntry(r->Pde);
        if (!tablePa)
        {
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }
    }

    {
        ULONG idx = (ULONG)((va >> 12) & 0x1FF);
        s = PwReadTableEntry(tablePa, idx, &r->Pte, &entryPa);
        if (!NT_SUCCESS(s))
        {
            r->Status = PwStatusPhysicalReadFailure;
            return PwStatusToNt(r->Status);
        }
        PwAccumulateNonLeaf(&flags, r->Pte);
        if (!(r->Pte & PW_PTE_PRESENT))
        {
            r->Flags = flags;
            r->Flags.Present = FALSE;
            r->Status = PwStatusNotPresent;
            return PwStatusToNt(r->Status);
        }

        PwApplyLeafFlags(&flags, r->Pte, FALSE);
        r->Flags = flags;
        return PwFinishLeaf(r, r->Pte, entryPa, PAGE_SIZE, PwLevelPte4Kb, FALSE);
    }
}

NTSTATUS PwReadVirtualRange(ULONG64 dtb, ULONG64 va, PVOID dst, SIZE_T size, PSIZE_T outRead, PSIZE_T outSkipped)
{
    if (outRead) *outRead = 0;
    if (outSkipped) *outSkipped = 0;
    if (!dst || !size) return STATUS_INVALID_PARAMETER;

    SIZE_T totalRead = 0;
    SIZE_T totalSkip = 0;
    PUCHAR d = (PUCHAR)dst;
    ULONG64 cur = va;
    SIZE_T remaining = size;

    while (remaining > 0)
    {
        PW_RESULT w;
        NTSTATUS ws = PwWalk(dtb, cur, &w);

        SIZE_T chunk = PAGE_SIZE - (SIZE_T)(cur & (PAGE_SIZE - 1));
        if (chunk > remaining) chunk = remaining;

        if (NT_SUCCESS(ws) && w.Status == PwStatusSuccess)
        {
            NTSTATUS cs = PhysMemReadRaw(w.ResolvedPhysicalAddress, d, chunk);
            if (!NT_SUCCESS(cs)) totalSkip += chunk;
            else totalRead += chunk;
        }
        else
        {
            totalSkip += chunk;
        }

        d += chunk;
        cur += chunk;
        remaining -= chunk;
    }

    if (outRead) *outRead = totalRead;
    if (outSkipped) *outSkipped = totalSkip;

    if (!totalRead) return STATUS_UNSUCCESSFUL;
    if (totalSkip)  return STATUS_PARTIAL_COPY;
    return STATUS_SUCCESS;
}
