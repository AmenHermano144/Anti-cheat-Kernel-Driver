#include "ssdt_integrity.h"
#include "imports_hash.h"
#include "page_walker.h"
#include "crypto.h"
#include "events.h"
#include "wire_records.h"
#include "anti_tamper.h"
#include "handler_gate.h"

// kernel syscall dispatcher integrity.
//
// stack-walk / frame-rewrite syscall interception is deliberately avoided
// here — it is not hvci-safe and the matching patchguard contract is
// fragile across windows builds. this module reaches the same signal
// passively: the dispatcher body and every hot nt* syscall are read
// physically via the page walker, hashed with sha-256, and compared
// against a boot baseline. a virtual-address hook can lie to any read
// that goes through the kernel's own RIP; a physical read via
// MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) returns the actual bytes the cpu
// will execute, which is what we want to verify.
//
// what this catches, concretely:
//   * KiSystemCall64 prologue rewritten (a "classic" ssdt / ssi detour)
//   * KiServiceTable entry swap landing on code with a non-vanilla prologue
//   * an inline jmp planted in the first ~64 bytes of a resolved nt* export
//
// what this does NOT catch — left here on purpose so the module stays
// tight: a hook that patches further downstream (inside the kernel but
// past our prologue window), EPT shadowing from a root-complex hypervisor
// (image_backing's full .text sweep is the tool for that), and ssdt slot
// swaps that redirect to another vanilla kernel export — those slot
// redirections need a resolved KeServiceDescriptorTable, which we don't
// chase here because the pattern varies per build.

#define LSTAR_MSR                 0xC0000082

#define SSDT_FNV64_OFFSET         0xCBF29CE484222325ULL
#define SSDT_FNV64_PRIME          0x100000001B3ULL

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

typedef struct _SSDT_EXPORT_SLOT
{
    const CHAR *Name;
    ULONG64     NameHash;
    ULONG64     ApiVa;
    UCHAR       BaselineHash[32];
    BOOLEAN     BaselineValid;
    BOOLEAN     Reserved[7];
} SSDT_EXPORT_SLOT, *PSSDT_EXPORT_SLOT;

typedef struct _SSDT_STATE
{
    volatile LONG Initialized;
    volatile LONG BaselineValid;
    volatile LONG LastFlag;

    ULONG64 LstarVa;
    UCHAR   LstarBaselineHash[32];
    BOOLEAN LstarBaselineValid;

    // KSERVICE_TABLE_DESCRIPTOR geometry recovered from KiSystemCall64.
    // KsdtVa points at the descriptor struct itself (32 bytes on x64),
    // ServiceTableVa points at the array of TableSize 32-bit entries that
    // the syscall dispatcher reads from. we hash both — the descriptor
    // layer catches a wholesale redirect to a shadow table, the array
    // layer catches a per-entry swap.
    ULONG64 KsdtVa;
    ULONG64 ServiceTableVa;
    ULONG   ServiceTableSize;
    UCHAR   KsdtBaselineHash[32];
    UCHAR   SvcTableBaselineHash[32];
    BOOLEAN KsdtBaselineValid;

    SSDT_EXPORT_SLOT Exports[SSDT_HOOK_MAX_EXPORTS];
    ULONG            ExportCount;
} SSDT_STATE, *PSSDT_STATE;

static SSDT_STATE g_Ssdt = { 0 };

static const CHAR *const kTrackedExports[SSDT_HOOK_MAX_EXPORTS] =
{
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtQueryVirtualMemory",
    "NtCreateFile",
    "NtDeviceIoControlFile",
    "NtQuerySystemInformation",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
};

static ULONG64 SsdtFnvAscii(const CHAR *s)
{
    ULONG64 h = SSDT_FNV64_OFFSET;
    while (*s)
    {
        h ^= (UCHAR)*s++;
        h *= SSDT_FNV64_PRIME;
    }
    return h;
}

static BOOLEAN SsdtPrologueLooksHooked(const UCHAR *bytes, ULONG len)
{
    if (!bytes || len < 7) return FALSE;

    // rel32 jmp at offset 0: E9 ?? ?? ?? ??
    if (bytes[0] == 0xE9) return TRUE;
    // abs ptr jmp: FF 25 ?? ?? ?? ??
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return TRUE;
    // push imm32 / ret
    if (bytes[0] == 0x68 && len >= 6 && bytes[5] == 0xC3) return TRUE;
    // mov rax, imm64 ; jmp rax  ->  48 B8 .. .. .. .. .. .. .. .. FF E0
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && len >= 13 &&
        bytes[10] == 0xFF && bytes[11] == 0xE0) return TRUE;
    // mov r10, imm64 ; jmp r10  ->  49 BA .. .. .. .. .. .. .. .. 41 FF E2
    if (bytes[0] == 0x49 && bytes[1] == 0xBA && len >= 14 &&
        bytes[10] == 0x41 && bytes[11] == 0xFF && bytes[12] == 0xE2) return TRUE;

    return FALSE;
}

static NTSTATUS SsdtPhysHashAndSample(ULONG64 va, ULONG byteLen,
                                      UCHAR outHash[32], UCHAR firstBytes[32],
                                      PULONG outFlags)
{
    *outFlags = 0;
    if (!va || byteLen == 0) return STATUS_INVALID_PARAMETER;
    if (!PwIsInitialized()) return STATUS_DEVICE_NOT_READY;

    ULONG64 dtb = 0;
    NTSTATUS st = PwGetSystemDtb(&dtb);
    if (!NT_SUCCESS(st)) return st;

    PUCHAR buf = (PUCHAR)CoreAlloc(byteLen, CORE_AC_POOL_TAG_SCAN);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buf, byteLen);

    SIZE_T read = 0, skipped = 0;
    st = PwReadVirtualRange(dtb, va, buf, byteLen, &read, &skipped);

    if (!NT_SUCCESS(st) || read == 0)
    {
        *outFlags |= SSDT_HOOK_FLAG_READ_FAILED;
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return NT_SUCCESS(st) ? STATUS_PARTIAL_COPY : st;
    }

    NTSTATUS hs = CryptoSha256(buf, (ULONG)read, outHash);
    if (!NT_SUCCESS(hs))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return hs;
    }

    if (firstBytes)
    {
        SIZE_T n = (read < 32) ? read : 32;
        RtlZeroMemory(firstBytes, 32);
        RtlCopyMemory(firstBytes, buf, n);
        if (SsdtPrologueLooksHooked(buf, (ULONG)read))
            *outFlags |= SSDT_HOOK_FLAG_JMP_PROLOGUE;
    }

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

// physical-read helper that returns the read buffer to the caller. used by
// the KiSystemCall64 scan where we need to pattern-match in the bytes, not
// just hash them. caller owns the returned buffer.
static NTSTATUS SsdtPhysReadRange(ULONG64 va, ULONG byteLen, PVOID *outBuf, PULONG outRead)
{
    *outBuf = NULL;
    *outRead = 0;
    if (!va || byteLen == 0) return STATUS_INVALID_PARAMETER;
    if (!PwIsInitialized()) return STATUS_DEVICE_NOT_READY;

    ULONG64 dtb = 0;
    NTSTATUS st = PwGetSystemDtb(&dtb);
    if (!NT_SUCCESS(st)) return st;

    PUCHAR buf = (PUCHAR)CoreAlloc(byteLen, CORE_AC_POOL_TAG_SCAN);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buf, byteLen);

    SIZE_T read = 0, skipped = 0;
    st = PwReadVirtualRange(dtb, va, buf, byteLen, &read, &skipped);
    if (!NT_SUCCESS(st) && read == 0)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return st;
    }

    *outBuf  = buf;
    *outRead = (ULONG)read;
    return STATUS_SUCCESS;
}

// resolve KeServiceDescriptorTable from KiSystemCall64. the real dispatcher
// loads the table address with a rip-relative lea; scanning for that lea
// gives us the descriptor va directly without relying on an export.
//
//   4C 8D 15 ?? ?? ?? ??    lea r10, [rip+disp32]   ; the usual one
//   4C 8D 1D ?? ?? ?? ??    lea r11, [rip+disp32]   ; shadow table
//
// we scan up to 4KB past LSTAR, pick each candidate, compute the target,
// verify it falls inside ntoskrnl, physically read 32 bytes at the target
// and sanity-check the descriptor shape (ServiceTable ptr inside nt image,
// TableSize between 100 and 1000). the first candidate that passes all
// checks wins; others are still probably valid but we only need one.
static NTSTATUS SsdtResolveKsdt(ULONG64 lstar, PVOID ntBase, ULONG ntSize,
                                ULONG64 *outKsdtVa,
                                ULONG64 *outServiceTableVa,
                                ULONG   *outServiceTableSize)
{
    *outKsdtVa = 0;
    *outServiceTableVa = 0;
    *outServiceTableSize = 0;

    if (!lstar || !ntBase || ntSize == 0) return STATUS_INVALID_PARAMETER;

    PVOID disBuf = NULL;
    ULONG disRead = 0;
    NTSTATUS st = SsdtPhysReadRange(lstar, 0x1000, &disBuf, &disRead);
    if (!NT_SUCCESS(st) || disRead < 16) { if (disBuf) CoreFree(disBuf, CORE_AC_POOL_TAG_SCAN); return STATUS_NOT_FOUND; }

    const UCHAR *bytes = (const UCHAR *)disBuf;
    ULONG64 ntLo = (ULONG64)(ULONG_PTR)ntBase;
    ULONG64 ntHi = ntLo + ntSize;

    ULONG64 ksdt = 0;

    for (ULONG i = 0; i + 7 <= disRead; i++)
    {
        // match lea r10,[rip+d] (4C 8D 15) or lea r11,[rip+d] (4C 8D 1D)
        if (bytes[i] != 0x4C) continue;
        if (bytes[i+1] != 0x8D) continue;
        UCHAR modrm = bytes[i+2];
        if (modrm != 0x15 && modrm != 0x1D) continue;

        LONG disp;
        RtlCopyMemory(&disp, &bytes[i+3], sizeof(disp));

        ULONG64 ripNext = lstar + i + 7;
        ULONG64 target  = (ULONG64)((LONG64)ripNext + (LONG64)disp);

        if (target < ntLo || target + 32 > ntHi) continue;

        // read 32 bytes at target and interpret as KSERVICE_TABLE_DESCRIPTOR
        PVOID descBuf = NULL;
        ULONG descRead = 0;
        NTSTATUS ds = SsdtPhysReadRange(target, 32, &descBuf, &descRead);
        if (!NT_SUCCESS(ds) || descRead < 32) { if (descBuf) CoreFree(descBuf, CORE_AC_POOL_TAG_SCAN); continue; }

        ULONG64 serviceTable = *(ULONG64 *)((UCHAR *)descBuf + 0);
        ULONG   tableSize    = *(ULONG   *)((UCHAR *)descBuf + 16);

        CoreFree(descBuf, CORE_AC_POOL_TAG_SCAN);

        // sanity: ServiceTable points inside ntoskrnl, TableSize is in a
        // reasonable range for a real syscall table (windows 10/11 ships
        // ~0x1E0 entries; widen generously to stay robust across builds).
        if (serviceTable < ntLo || serviceTable + ((ULONG64)tableSize * 4ULL) > ntHi) continue;
        if (tableSize < 0x80 || tableSize > 0x400) continue;

        ksdt = target;
        *outKsdtVa = target;
        *outServiceTableVa   = serviceTable;
        *outServiceTableSize = tableSize;
        break;
    }

    CoreFree(disBuf, CORE_AC_POOL_TAG_SCAN);
    return ksdt ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS SsdtIntegrityInit(VOID)
{
    RtlZeroMemory(&g_Ssdt, sizeof(g_Ssdt));

    // page walker is shared with image_backing / win32k_guard; init is
    // idempotent, so calling it here just makes the module standalone.
    NTSTATUS pwSt = PwInit();
    if (!NT_SUCCESS(pwSt)) return pwSt;

    ULONG count = 0;
    for (ULONG i = 0; i < SSDT_HOOK_MAX_EXPORTS; i++)
    {
        const CHAR *name = kTrackedExports[i];
        if (!name) continue;
        g_Ssdt.Exports[count].Name     = name;
        g_Ssdt.Exports[count].NameHash = SsdtFnvAscii(name);
        count++;
    }
    g_Ssdt.ExportCount = count;

    InterlockedExchange(&g_Ssdt.Initialized, 1);
    return STATUS_SUCCESS;
}

VOID SsdtIntegrityShutdown(VOID)
{
    InterlockedExchange(&g_Ssdt.Initialized, 0);
    InterlockedExchange(&g_Ssdt.BaselineValid, 0);
}

NTSTATUS SsdtIntegrityBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Ssdt.Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!PwIsInitialized()) return STATUS_DEVICE_NOT_READY;

    g_Ssdt.LstarVa = __readmsr(LSTAR_MSR);
    if (!g_Ssdt.LstarVa) return STATUS_NOT_FOUND;

    ULONG flags = 0;
    UCHAR firstBytes[32];
    NTSTATUS st = SsdtPhysHashAndSample(g_Ssdt.LstarVa, SSDT_HOOK_LSTAR_BYTES,
                                        g_Ssdt.LstarBaselineHash, firstBytes, &flags);
    g_Ssdt.LstarBaselineValid = NT_SUCCESS(st) && !(flags & SSDT_HOOK_FLAG_READ_FAILED);

    // if the KiSystemCall64 prologue already looks hooked at baseline time,
    // we still store the hash so the heartbeat has something to compare —
    // but we flag it immediately so the backend knows the system came up
    // tainted rather than developing a drift mid-session.
    if (g_Ssdt.LstarBaselineValid && (flags & SSDT_HOOK_FLAG_JMP_PROLOGUE))
    {
        WIRE_SSDT_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.KiSystemCall64Va = g_Ssdt.LstarVa;
        rec.LstarValue       = g_Ssdt.LstarVa;
        rec.NtoskrnlBase     = (ULONG64)(ULONG_PTR)AcImportsGetNtBase();
        rec.Flags            = flags | SSDT_HOOK_FLAG_SYSCALL_DRIFT;
        rec.ExportCount      = 0;
        RtlCopyMemory(rec.LstarBaselineHash,       g_Ssdt.LstarBaselineHash, 32);
        RtlCopyMemory(rec.LstarObservedHash,       g_Ssdt.LstarBaselineHash, 32);
        RtlCopyMemory(rec.LstarObservedFirstBytes, firstBytes,               32);
        InterlockedExchange(&g_Ssdt.LastFlag, (LONG)rec.Flags);
        (VOID)EventsReportSsdtHook(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_SSDT, (PVOID)g_Ssdt.LstarVa);
    }

    for (ULONG i = 0; i < g_Ssdt.ExportCount; i++)
    {
        PSSDT_EXPORT_SLOT s = &g_Ssdt.Exports[i];
        PVOID va = AcImportsResolveNtExportByHash(s->NameHash);
        if (!va) { s->BaselineValid = FALSE; continue; }

        s->ApiVa = (ULONG64)(ULONG_PTR)va;

        ULONG f = 0;
        UCHAR fb[32];
        NTSTATUS es = SsdtPhysHashAndSample(s->ApiVa, SSDT_HOOK_PROLOGUE_BYTES,
                                            s->BaselineHash, fb, &f);
        s->BaselineValid = NT_SUCCESS(es) && !(f & SSDT_HOOK_FLAG_READ_FAILED);
    }

    // KSDT baseline — pattern-scan KiSystemCall64 for the rip-relative lea
    // that resolves KeServiceDescriptorTable, then hash both the descriptor
    // (32 B) and the ServiceTable array (TableSize * 4 B). failure here is
    // not fatal: lstar-based prologue hashing still works, and we just raise
    // KSDT_NOT_FOUND on the next verify so the backend knows we are blind to
    // the slot-swap vector on this host.
    PVOID ntBase  = AcImportsGetNtBase();
    ULONG ntSize  = AcImportsGetNtSize();
    if (ntBase && ntSize)
    {
        ULONG64 ksdtVa = 0, stVa = 0;
        ULONG   stSize = 0;
        NTSTATUS rs = SsdtResolveKsdt(g_Ssdt.LstarVa, ntBase, ntSize,
                                      &ksdtVa, &stVa, &stSize);
        if (NT_SUCCESS(rs))
        {
            g_Ssdt.KsdtVa           = ksdtVa;
            g_Ssdt.ServiceTableVa   = stVa;
            g_Ssdt.ServiceTableSize = stSize;

            ULONG ksdtFlags = 0, stFlags = 0;
            NTSTATUS hd = SsdtPhysHashAndSample(ksdtVa, 32,
                                                g_Ssdt.KsdtBaselineHash, NULL, &ksdtFlags);
            ULONG stBytes = stSize * 4;
            NTSTATUS hs2 = SsdtPhysHashAndSample(stVa, stBytes,
                                                 g_Ssdt.SvcTableBaselineHash, NULL, &stFlags);

            g_Ssdt.KsdtBaselineValid =
                NT_SUCCESS(hd) && NT_SUCCESS(hs2) &&
                !(ksdtFlags & SSDT_HOOK_FLAG_READ_FAILED) &&
                !(stFlags   & SSDT_HOOK_FLAG_READ_FAILED);
        }
    }

    InterlockedExchange(&g_Ssdt.BaselineValid, 1);
    return STATUS_SUCCESS;
}

NTSTATUS SsdtIntegrityVerify(VOID)
{
    AC_GATE_RETURN_IF_DISABLED(AC_H_SSDT, STATUS_SUCCESS);

    if (!InterlockedCompareExchange(&g_Ssdt.Initialized, 0, 0))   return STATUS_DEVICE_NOT_READY;
    if (!InterlockedCompareExchange(&g_Ssdt.BaselineValid, 0, 0)) return STATUS_DEVICE_NOT_READY;

    WIRE_SSDT_HOOK rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.NtoskrnlBase = (ULONG64)(ULONG_PTR)AcImportsGetNtBase();

    ULONG64 liveLstar = __readmsr(LSTAR_MSR);
    rec.KiSystemCall64Va = g_Ssdt.LstarVa;
    rec.LstarValue       = liveLstar;

    ULONG combinedFlags = 0;

    if (liveLstar != g_Ssdt.LstarVa)
    {
        // LSTAR shifted after baseline — the MSR tamper detector will also
        // catch this but we fold the bit in here so the ssdt record carries
        // the full picture. the following hash compare may still succeed if
        // the new target is also vanilla, so we do not short-circuit.
        combinedFlags |= SSDT_HOOK_FLAG_LSTAR_SHIFTED;
    }

    if (g_Ssdt.LstarBaselineValid)
    {
        UCHAR obsHash[32], obsBytes[32];
        ULONG f = 0;
        NTSTATUS st = SsdtPhysHashAndSample(liveLstar, SSDT_HOOK_LSTAR_BYTES,
                                            obsHash, obsBytes, &f);
        RtlCopyMemory(rec.LstarBaselineHash, g_Ssdt.LstarBaselineHash, 32);
        RtlCopyMemory(rec.LstarObservedHash, obsHash, 32);
        RtlCopyMemory(rec.LstarObservedFirstBytes, obsBytes, 32);

        combinedFlags |= f;

        if (NT_SUCCESS(st) &&
            RtlCompareMemory(obsHash, g_Ssdt.LstarBaselineHash, 32) != 32)
        {
            combinedFlags |= SSDT_HOOK_FLAG_SYSCALL_DRIFT;
        }
    }

    // walk each tracked export and fill the report. clamp to max.
    ULONG filled = 0;
    for (ULONG i = 0; i < g_Ssdt.ExportCount && filled < SSDT_HOOK_MAX_EXPORTS; i++)
    {
        PSSDT_EXPORT_SLOT s = &g_Ssdt.Exports[i];
        if (!s->BaselineValid) continue;

        PWIRE_SSDT_EXPORT_ENTRY e = &rec.Exports[filled];
        e->ApiVa    = s->ApiVa;
        e->NameHash = s->NameHash;

        ULONG f = 0;
        UCHAR obsHash[32];
        UCHAR obsBytes[32];
        NTSTATUS st = SsdtPhysHashAndSample(s->ApiVa, SSDT_HOOK_PROLOGUE_BYTES,
                                            obsHash, obsBytes, &f);

        RtlCopyMemory(e->BaselineHash,       s->BaselineHash, 32);
        RtlCopyMemory(e->ObservedHash,       obsHash,         32);
        RtlCopyMemory(e->ObservedFirstBytes, obsBytes,        32);
        e->Flags = f;

        if (NT_SUCCESS(st) &&
            RtlCompareMemory(obsHash, s->BaselineHash, 32) != 32)
        {
            e->Flags       |= SSDT_HOOK_FLAG_EXPORT_DRIFT;
            combinedFlags  |= SSDT_HOOK_FLAG_EXPORT_DRIFT;
        }

        if (e->Flags & (SSDT_HOOK_FLAG_JMP_PROLOGUE | SSDT_HOOK_FLAG_READ_FAILED))
        {
            combinedFlags |= e->Flags &
                (SSDT_HOOK_FLAG_JMP_PROLOGUE | SSDT_HOOK_FLAG_READ_FAILED);
        }

        filled++;
    }
    rec.ExportCount                = filled;
    rec.KeServiceDescriptorTableVa = g_Ssdt.KsdtVa;
    rec.ServiceTableVa             = g_Ssdt.ServiceTableVa;
    rec.ServiceTableSize           = g_Ssdt.ServiceTableSize;

    if (g_Ssdt.KsdtBaselineValid)
    {
        UCHAR ksdtObs[32], stObs[32];
        ULONG kf = 0, sf = 0;
        NTSTATUS k1 = SsdtPhysHashAndSample(g_Ssdt.KsdtVa, 32, ksdtObs, NULL, &kf);
        NTSTATUS k2 = SsdtPhysHashAndSample(g_Ssdt.ServiceTableVa,
                                            g_Ssdt.ServiceTableSize * 4,
                                            stObs, NULL, &sf);
        RtlCopyMemory(rec.KsdtBaselineHash,     g_Ssdt.KsdtBaselineHash,     32);
        RtlCopyMemory(rec.KsdtObservedHash,     ksdtObs,                     32);
        RtlCopyMemory(rec.SvcTableBaselineHash, g_Ssdt.SvcTableBaselineHash, 32);
        RtlCopyMemory(rec.SvcTableObservedHash, stObs,                       32);

        if (NT_SUCCESS(k1) &&
            RtlCompareMemory(ksdtObs, g_Ssdt.KsdtBaselineHash, 32) != 32)
        {
            combinedFlags |= SSDT_HOOK_FLAG_KSDT_DRIFT;
        }
        if (NT_SUCCESS(k2) &&
            RtlCompareMemory(stObs, g_Ssdt.SvcTableBaselineHash, 32) != 32)
        {
            combinedFlags |= SSDT_HOOK_FLAG_SERVICETABLE_DRIFT;
        }
        combinedFlags |= (kf | sf) & SSDT_HOOK_FLAG_READ_FAILED;
    }
    else
    {
        combinedFlags |= SSDT_HOOK_FLAG_KSDT_NOT_FOUND;
    }

    rec.Flags = combinedFlags;

    InterlockedExchange(&g_Ssdt.LastFlag, (LONG)combinedFlags);

    const ULONG kTripMask =
        SSDT_HOOK_FLAG_SYSCALL_DRIFT        |
        SSDT_HOOK_FLAG_EXPORT_DRIFT         |
        SSDT_HOOK_FLAG_LSTAR_SHIFTED        |
        SSDT_HOOK_FLAG_JMP_PROLOGUE         |
        SSDT_HOOK_FLAG_KSDT_DRIFT           |
        SSDT_HOOK_FLAG_SERVICETABLE_DRIFT;

    if (combinedFlags & kTripMask)
    {
        (VOID)EventsReportSsdtHook(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_SSDT, (PVOID)liveLstar);
    }

    return STATUS_SUCCESS;
}

ULONG SsdtIntegrityGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Ssdt.LastFlag, 0, 0);
}

VOID SsdtIntegrityClearFlag(VOID)
{
    InterlockedExchange(&g_Ssdt.LastFlag, 0);
}
