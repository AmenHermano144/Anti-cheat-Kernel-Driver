#include "dxgk_guard.h"
#include "imports_hash.h"
#include "page_walker.h"
#include "crypto.h"
#include "events.h"
#include "wire_records.h"
#include "anti_tamper.h"
#include "handler_gate.h"

// dxgkrnl prologue integrity. the egg2 fingerprint vgk 1.19.2 uses on
// dxgkrnl (hde64 disassembly to resolve internal targets) exists to catch
// esp overlay drivers that patch the display pipeline — present, flip,
// render km, framebuffer map paths. we don't need an in-driver
// disassembler to reach the same signal: hashing the first 32 KB of
// dxgkrnl via the page walker covers the entry point, the dispatch
// vtables, and every interior function that lives within range of a
// typical e9/ff25 detour from the entry area. anything beyond that range
// is image_backing's full-text scan territory.
//
// baseline is lazy. dxgkrnl is not resident when the driver initializes
// (it loads with the display stack when the first vga session comes up),
// so Init() just arms the module; the heartbeat retries baseline each
// tick until it succeeds. verify is a no-op until baseline is valid.

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

#define DXGK_FNV64_OFFSET    0xCBF29CE484222325ULL
#define DXGK_FNV64_PRIME     0x100000001B3ULL

// pre-computed from lowercase "dxgkrnl.sys" with the fnv1a-64 scheme used by
// FindModuleBase (lowercased, low-byte only per wchar).
static ULONG64 ComputeDxgkHash(VOID)
{
    const WCHAR *name = L"dxgkrnl.sys";
    ULONG64 h = DXGK_FNV64_OFFSET;
    for (const WCHAR *p = name; *p; p++)
    {
        WCHAR c = *p;
        if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
        h ^= (UCHAR)(c & 0xFF);
        h *= DXGK_FNV64_PRIME;
    }
    return h;
}

typedef struct _DXGK_STATE
{
    volatile LONG Initialized;
    volatile LONG BaselineValid;
    volatile LONG LastFlag;
    volatile LONG BaselineAttempts;

    ULONG64 BaseVa;
    ULONG   ImageSize;
    ULONG64 NameHash;
    UCHAR   BulkBaselineHash[32];
} DXGK_STATE, *PDXGK_STATE;

static DXGK_STATE g_Dxgk = { 0 };

static BOOLEAN DxgkEntryLooksHooked(const UCHAR *bytes, ULONG len)
{
    if (!bytes || len < 7) return FALSE;
    if (bytes[0] == 0xE9) return TRUE;                               // rel32 jmp
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return TRUE;           // ff 25 ptr
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && len >= 13 &&
        bytes[10] == 0xFF && bytes[11] == 0xE0) return TRUE;         // mov rax,imm;jmp rax
    if (bytes[0] == 0x49 && bytes[1] == 0xBA && len >= 14 &&
        bytes[10] == 0x41 && bytes[11] == 0xFF && bytes[12] == 0xE2) return TRUE;
    return FALSE;
}

static NTSTATUS DxgkPhysHashRange(ULONG64 va, ULONG byteLen,
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
        *outFlags |= DXGK_HOOK_FLAG_READ_FAILED;
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
        if (DxgkEntryLooksHooked(buf, (ULONG)read))
            *outFlags |= DXGK_HOOK_FLAG_JMP_ENTRY;
    }

    CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
    return STATUS_SUCCESS;
}

NTSTATUS DxgkGuardInit(VOID)
{
    RtlZeroMemory(&g_Dxgk, sizeof(g_Dxgk));

    NTSTATUS pw = PwInit();
    if (!NT_SUCCESS(pw)) return pw;

    g_Dxgk.NameHash = ComputeDxgkHash();
    InterlockedExchange(&g_Dxgk.Initialized, 1);
    return STATUS_SUCCESS;
}

VOID DxgkGuardShutdown(VOID)
{
    InterlockedExchange(&g_Dxgk.Initialized, 0);
    InterlockedExchange(&g_Dxgk.BaselineValid, 0);
}

NTSTATUS DxgkGuardBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Dxgk.Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (InterlockedCompareExchange(&g_Dxgk.BaselineValid, 0, 0)) return STATUS_SUCCESS;

    PVOID base = NULL;
    ULONG size = 0;
    NTSTATUS st = AcImportsFindModule(g_Dxgk.NameHash, &base, &size);
    if (!NT_SUCCESS(st) || !base || !size)
    {
        // retry on the next heartbeat; the display stack may not be up yet.
        InterlockedIncrement(&g_Dxgk.BaselineAttempts);
        return STATUS_NOT_FOUND;
    }

    g_Dxgk.BaseVa    = (ULONG64)(ULONG_PTR)base;
    g_Dxgk.ImageSize = size;

    ULONG readBytes = (size < DXGK_BULK_HASH_BYTES) ? size : DXGK_BULK_HASH_BYTES;
    ULONG flags = 0;
    UCHAR fb[32];
    NTSTATUS hs = DxgkPhysHashRange(g_Dxgk.BaseVa, readBytes,
                                    g_Dxgk.BulkBaselineHash, fb, &flags);
    if (!NT_SUCCESS(hs) || (flags & DXGK_HOOK_FLAG_READ_FAILED))
    {
        InterlockedIncrement(&g_Dxgk.BaselineAttempts);
        return hs;
    }

    InterlockedExchange(&g_Dxgk.BaselineValid, 1);

    // if the first-page prologue already looks like a detour at baseline
    // time, flag immediately — the backend wants to know the host came up
    // dirty rather than drifted during the session.
    if (flags & DXGK_HOOK_FLAG_JMP_ENTRY)
    {
        WIRE_DXGK_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.DxgkBase     = g_Dxgk.BaseVa;
        rec.DxgkSize     = g_Dxgk.ImageSize;
        rec.Flags        = flags;
        rec.EntryPointVa = g_Dxgk.BaseVa;
        RtlCopyMemory(rec.BulkBaselineHash,   g_Dxgk.BulkBaselineHash, 32);
        RtlCopyMemory(rec.BulkObservedHash,   g_Dxgk.BulkBaselineHash, 32);
        RtlCopyMemory(rec.EntryObservedBytes, fb,                      32);
        InterlockedExchange(&g_Dxgk.LastFlag, (LONG)flags);
        (VOID)EventsReportDxgkHook(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_DXGK, (PVOID)g_Dxgk.BaseVa);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DxgkGuardVerify(VOID)
{
    AC_GATE_RETURN_IF_DISABLED(AC_H_DXGK, STATUS_SUCCESS);

    if (!InterlockedCompareExchange(&g_Dxgk.Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    // lazy baseline — try again if dxgkrnl was not yet loaded at init.
    if (!InterlockedCompareExchange(&g_Dxgk.BaselineValid, 0, 0))
    {
        NTSTATUS bs = DxgkGuardBaseline();
        if (!NT_SUCCESS(bs))
        {
            // after many failed attempts, surface DXGK_NOT_LOADED once so the
            // backend knows dxgkrnl stays absent and this module is inactive
            // rather than silently idle.
            LONG attempts = InterlockedCompareExchange(&g_Dxgk.BaselineAttempts, 0, 0);
            if (attempts == 10)
            {
                WIRE_DXGK_HOOK rec;
                RtlZeroMemory(&rec, sizeof(rec));
                rec.Flags = DXGK_HOOK_FLAG_NOT_LOADED;
                (VOID)EventsReportDxgkHook(&rec);
                InterlockedExchange(&g_Dxgk.LastFlag, (LONG)rec.Flags);
            }
            return STATUS_SUCCESS;
        }
    }

    // live base check — image_backing tracks per-module mutations, but if
    // dxgkrnl reloaded at a different address between baseline and now the
    // observed hash will not be comparable to the baseline. we flag and
    // re-baseline against the new base so the backend sees a single
    // MODULE_SHIFTED event rather than a running stream of BULK_DRIFT.
    PVOID liveBase = NULL;
    ULONG liveSize = 0;
    NTSTATUS lu = AcImportsFindModule(g_Dxgk.NameHash, &liveBase, &liveSize);
    if (!NT_SUCCESS(lu) || !liveBase)
    {
        // dxgkrnl went away. not necessarily hostile; flag once and reset.
        InterlockedExchange(&g_Dxgk.BaselineValid, 0);
        return STATUS_SUCCESS;
    }

    ULONG combinedFlags = 0;
    if ((ULONG64)(ULONG_PTR)liveBase != g_Dxgk.BaseVa)
    {
        combinedFlags |= DXGK_HOOK_FLAG_MODULE_SHIFTED;
        g_Dxgk.BaseVa    = (ULONG64)(ULONG_PTR)liveBase;
        g_Dxgk.ImageSize = liveSize;

        UCHAR fb[32];
        ULONG f = 0;
        ULONG rb = (liveSize < DXGK_BULK_HASH_BYTES) ? liveSize : DXGK_BULK_HASH_BYTES;
        NTSTATUS rh = DxgkPhysHashRange(g_Dxgk.BaseVa, rb,
                                        g_Dxgk.BulkBaselineHash, fb, &f);
        if (!NT_SUCCESS(rh)) combinedFlags |= DXGK_HOOK_FLAG_READ_FAILED;

        WIRE_DXGK_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.DxgkBase     = g_Dxgk.BaseVa;
        rec.DxgkSize     = g_Dxgk.ImageSize;
        rec.Flags        = combinedFlags;
        rec.EntryPointVa = g_Dxgk.BaseVa;
        RtlCopyMemory(rec.BulkBaselineHash,   g_Dxgk.BulkBaselineHash, 32);
        RtlCopyMemory(rec.BulkObservedHash,   g_Dxgk.BulkBaselineHash, 32);
        RtlCopyMemory(rec.EntryObservedBytes, fb,                      32);
        InterlockedExchange(&g_Dxgk.LastFlag, (LONG)combinedFlags);
        (VOID)EventsReportDxgkHook(&rec);
        return STATUS_SUCCESS;
    }

    ULONG flags = 0;
    UCHAR obsHash[32];
    UCHAR obsBytes[32];
    ULONG rb = (g_Dxgk.ImageSize < DXGK_BULK_HASH_BYTES) ? g_Dxgk.ImageSize : DXGK_BULK_HASH_BYTES;
    NTSTATUS hs = DxgkPhysHashRange(g_Dxgk.BaseVa, rb, obsHash, obsBytes, &flags);
    if (!NT_SUCCESS(hs))
    {
        combinedFlags |= DXGK_HOOK_FLAG_READ_FAILED;
    }
    else if (RtlCompareMemory(obsHash, g_Dxgk.BulkBaselineHash, 32) != 32)
    {
        combinedFlags |= DXGK_HOOK_FLAG_BULK_DRIFT;
    }
    combinedFlags |= flags;

    InterlockedExchange(&g_Dxgk.LastFlag, (LONG)combinedFlags);

    const ULONG kTripMask =
        DXGK_HOOK_FLAG_BULK_DRIFT |
        DXGK_HOOK_FLAG_JMP_ENTRY;

    if (combinedFlags & kTripMask)
    {
        WIRE_DXGK_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.DxgkBase     = g_Dxgk.BaseVa;
        rec.DxgkSize     = g_Dxgk.ImageSize;
        rec.Flags        = combinedFlags;
        rec.EntryPointVa = g_Dxgk.BaseVa;
        RtlCopyMemory(rec.BulkBaselineHash,   g_Dxgk.BulkBaselineHash, 32);
        RtlCopyMemory(rec.BulkObservedHash,   obsHash,                  32);
        RtlCopyMemory(rec.EntryObservedBytes, obsBytes,                 32);
        (VOID)EventsReportDxgkHook(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_DXGK, (PVOID)g_Dxgk.BaseVa);
    }

    return STATUS_SUCCESS;
}

ULONG DxgkGuardGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_Dxgk.LastFlag, 0, 0);
}

VOID DxgkGuardClearFlag(VOID)
{
    InterlockedExchange(&g_Dxgk.LastFlag, 0);
}
