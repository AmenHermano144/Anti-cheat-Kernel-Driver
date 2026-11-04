#include "win32k_guard.h"
#include "page_walker.h"
#include "physmem.h"
#include "crypto.h"
#include "events.h"
#include "anti_tamper.h"
#include "imports.h"
#include "strings.h"
#include "wire_records.h"

#define W32K_FN_SAMPLE_BYTES   256
#define W32K_FN_PROLOG_BYTES   16

typedef struct _SYS_PROC_INFO_HDR
{
    ULONG         NextEntryOffset;
    ULONG         NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG          BasePriority;
    HANDLE        UniqueProcessId;
    HANDLE        InheritedFromUniqueProcessId;
} SYS_PROC_INFO_HDR, *PSYS_PROC_INFO_HDR;

typedef struct _W32K_WATCH_ENTRY
{
    BOOLEAN     Valid;
    ULONG       FunctionId;
    ULONG64     FunctionAddress;
    UCHAR       BaselineHash[32];
    UCHAR       BaselineFirstBytes[W32K_FN_PROLOG_BYTES];
    ULONG       SampleBytes;
} W32K_WATCH_ENTRY, *PW32K_WATCH_ENTRY;

static W32K_WATCH_ENTRY g_Watch[4];
static ULONG            g_WatchCount = 0;
static ULONG64          g_Win32kBase = 0;
static ULONG            g_Win32kSize = 0;
static ULONG64          g_SystemDtb  = 0;
static PEPROCESS        g_SessionProc = NULL;
static volatile LONG    g_Initialized = 0;

static NTSTATUS AcquireGuiSessionProcess(PEPROCESS *outProc)
{
    *outProc = NULL;

    ULONG bytes = 0;
    NTSTATUS s = ZwQuerySystemInformation(5, NULL, 0, &bytes);
    if (bytes == 0) return STATUS_INFO_LENGTH_MISMATCH;
    bytes += 0x4000;

    PVOID buf = CoreAlloc(bytes, CORE_AC_POOL_TAG_PW);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    s = ZwQuerySystemInformation(5, buf, bytes, &bytes);
    if (!NT_SUCCESS(s))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_PW);
        return s;
    }

    UNICODE_STRING priorityNames[2];
    RtlInitUnicodeString(&priorityNames[0], L"winlogon.exe");
    RtlInitUnicodeString(&priorityNames[1], L"explorer.exe");

    PEPROCESS chosen = NULL;

    __try
    {
        for (ULONG p = 0; p < 2 && !chosen; p++)
        {
            PSYS_PROC_INFO_HDR entry = (PSYS_PROC_INFO_HDR)buf;
            while (entry)
            {
                if (entry->ImageName.Buffer && entry->ImageName.Length > 0 && entry->UniqueProcessId)
                {
                    if (RtlEqualUnicodeString(&entry->ImageName, &priorityNames[p], TRUE))
                    {
                        PEPROCESS proc = NULL;
                        if (NT_SUCCESS(PsLookupProcessByProcessId(entry->UniqueProcessId, &proc)) && proc)
                        {
                            chosen = proc;
                            break;
                        }
                    }
                }
                if (entry->NextEntryOffset == 0) break;
                entry = (PSYS_PROC_INFO_HDR)((PUCHAR)entry + entry->NextEntryOffset);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        chosen = NULL;
    }

    CoreFree(buf, CORE_AC_POOL_TAG_PW);
    if (!chosen) return STATUS_NOT_FOUND;

    *outProc = chosen;
    return STATUS_SUCCESS;
}

static NTSTATUS ResolveWin32kbaseModule(ULONG64 *outBase, ULONG *outSize)
{
    *outBase = 0;
    *outSize = 0;

    ULONG bytes = 0;
    ZwQuerySystemInformation(CORE_SysModuleInformation, NULL, 0, &bytes);
    if (bytes == 0) return STATUS_INFO_LENGTH_MISMATCH;

    PVOID buf = CoreAlloc(bytes + 0x400, CORE_AC_POOL_TAG_PW);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS s = ZwQuerySystemInformation(CORE_SysModuleInformation, buf, bytes + 0x400, &bytes);
    if (!NT_SUCCESS(s))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_PW);
        return s;
    }

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;
    NTSTATUS result = STATUS_NOT_FOUND;

    for (ULONG i = 0; i < mods->Count; i++)
    {
        const CHAR *path = (const CHAR *)mods->Module[i].FullPathName;
        const CHAR *name = path + mods->Module[i].OffsetToFileName;
        if (CoreStrCmpiA(name, "win32kbase.sys") == 0)
        {
            *outBase = (ULONG64)mods->Module[i].ImageBase;
            *outSize = mods->Module[i].ImageSize;
            result = STATUS_SUCCESS;
            break;
        }
    }

    CoreFree(buf, CORE_AC_POOL_TAG_PW);
    return result;
}

static BOOLEAN PatternMatch(const UCHAR *data, const UCHAR *pat, const UCHAR *mask, SIZE_T len)
{
    for (SIZE_T i = 0; i < len; i++)
    {
        if (mask[i] && data[i] != pat[i]) return FALSE;
    }
    return TRUE;
}

static PVOID ScanExecSectionsForPattern(PVOID base, ULONG size, const UCHAR *pat, const UCHAR *mask, SIZE_T patLen)
{
    if (!base || size < patLen) return NULL;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            PUCHAR sstart = (PUCHAR)base + sec->VirtualAddress;
            ULONG ssize = sec->Misc.VirtualSize;
            if (ssize < patLen) continue;

            ULONG end = ssize - (ULONG)patLen;
            for (ULONG off = 0; off <= end; off++)
            {
                if (PatternMatch(sstart + off, pat, mask, patLen))
                    return (PVOID)(sstart + off);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static NTSTATUS ResolveSynthesizeMouseInput(ULONG64 w32Base, ULONG w32Size, ULONG64 *outAddr)
{
    static const UCHAR pat[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
        0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x55,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
    };
    static const UCHAR mask[sizeof(pat)] = {
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1
    };

    PVOID hit = ScanExecSectionsForPattern((PVOID)w32Base, w32Size, pat, mask, sizeof(pat));
    if (!hit) return STATUS_NOT_FOUND;

    *outAddr = (ULONG64)hit;
    return STATUS_SUCCESS;
}

static NTSTATUS HashFunctionSample(ULONG64 fnAddr, ULONG sampleBytes,
                                    UCHAR outHash[32], UCHAR outFirstBytes[W32K_FN_PROLOG_BYTES])
{
    if (sampleBytes > 4096) sampleBytes = 4096;

    PUCHAR buf = (PUCHAR)CoreAlloc(sampleBytes, CORE_AC_POOL_TAG_PW);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T got = 0, skipped = 0;
    NTSTATUS s = PwReadVirtualRange(g_SystemDtb, fnAddr, buf, sampleBytes, &got, &skipped);
    if (skipped || got != sampleBytes)
    {
        CoreFree(buf, CORE_AC_POOL_TAG_PW);
        return NT_SUCCESS(s) ? STATUS_PARTIAL_COPY : s;
    }

    s = CryptoSha256(buf, sampleBytes, outHash);
    if (NT_SUCCESS(s) && outFirstBytes)
    {
        RtlCopyMemory(outFirstBytes, buf, W32K_FN_PROLOG_BYTES);
    }

    CoreFree(buf, CORE_AC_POOL_TAG_PW);
    return s;
}

static BOOLEAN FirstBytesLookLikeJmp(const UCHAR *bytes)
{
    if (bytes[0] == 0xE9) return TRUE;
    if (bytes[0] == 0xEB) return TRUE;
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return TRUE;
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) return TRUE;
    if (bytes[0] == 0x49 && bytes[1] == 0xBB) return TRUE;
    return FALSE;
}

NTSTATUS Win32kGuardInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;

    RtlZeroMemory(g_Watch, sizeof(g_Watch));
    g_WatchCount = 0;
    g_Win32kBase = 0;
    g_Win32kSize = 0;
    g_SessionProc = NULL;

    NTSTATUS s = PwInit();
    if (!NT_SUCCESS(s) && !PwIsInitialized())
    {
        InterlockedExchange(&g_Initialized, 0);
        return s;
    }

    s = PwGetSystemDtb(&g_SystemDtb);
    if (!NT_SUCCESS(s)) g_SystemDtb = PwReadCurrentCr3();

    return STATUS_SUCCESS;
}

VOID Win32kGuardShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);

    if (g_SessionProc)
    {
        ObDereferenceObject(g_SessionProc);
        g_SessionProc = NULL;
    }

    RtlZeroMemory(g_Watch, sizeof(g_Watch));
    g_WatchCount = 0;
    g_Win32kBase = 0;
    g_Win32kSize = 0;
    g_SystemDtb = 0;
}

NTSTATUS Win32kGuardBaseline(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    PEPROCESS proc = NULL;
    NTSTATUS s = AcquireGuiSessionProcess(&proc);
    if (!NT_SUCCESS(s)) return s;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    ULONG64 w32Base = 0;
    ULONG   w32Size = 0;
    s = ResolveWin32kbaseModule(&w32Base, &w32Size);

    ULONG64 synAddr = 0;
    if (NT_SUCCESS(s))
    {
        s = ResolveSynthesizeMouseInput(w32Base, w32Size, &synAddr);
    }

    KeUnstackDetachProcess(&apc);

    if (!NT_SUCCESS(s) || !synAddr)
    {
        WIRE_WIN32K_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.Win32kBase = w32Base;
        rec.Win32kSize = w32Size;
        rec.FunctionId = W32K_FN_SYNTH_MOUSE;
        rec.Flags = W32K_HOOK_FLAG_RESOLVE_FAILED;
        (VOID)EventsReportWin32kHook(&rec);
        ObDereferenceObject(proc);
        return s;
    }

    g_Win32kBase = w32Base;
    g_Win32kSize = w32Size;
    g_SessionProc = proc;

    PW32K_WATCH_ENTRY e = &g_Watch[0];
    e->FunctionId = W32K_FN_SYNTH_MOUSE;
    e->FunctionAddress = synAddr;
    e->SampleBytes = W32K_FN_SAMPLE_BYTES;

    s = HashFunctionSample(synAddr, W32K_FN_SAMPLE_BYTES, e->BaselineHash, e->BaselineFirstBytes);
    if (NT_SUCCESS(s))
    {
        e->Valid = TRUE;
        g_WatchCount = 1;
    }
    else
    {
        WIRE_WIN32K_HOOK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.FunctionAddress = synAddr;
        rec.Win32kBase = w32Base;
        rec.Win32kSize = w32Size;
        rec.FunctionId = W32K_FN_SYNTH_MOUSE;
        rec.Flags = W32K_HOOK_FLAG_READ_FAILED;
        (VOID)EventsReportWin32kHook(&rec);
    }

    return s;
}

NTSTATUS Win32kGuardVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (g_WatchCount == 0) return STATUS_NOT_FOUND;

    ULONG64 currentBase = 0;
    ULONG   currentSize = 0;

    if (g_SessionProc)
    {
        KAPC_STATE apc;
        KeStackAttachProcess(g_SessionProc, &apc);
        (VOID)ResolveWin32kbaseModule(&currentBase, &currentSize);
        KeUnstackDetachProcess(&apc);
    }

    BOOLEAN moduleShifted = (currentBase && currentBase != g_Win32kBase);

    for (ULONG i = 0; i < g_WatchCount; i++)
    {
        PW32K_WATCH_ENTRY e = &g_Watch[i];
        if (!e->Valid) continue;

        UCHAR observedHash[32];
        UCHAR observedFirst[W32K_FN_PROLOG_BYTES];
        RtlZeroMemory(observedHash, sizeof(observedHash));
        RtlZeroMemory(observedFirst, sizeof(observedFirst));

        NTSTATUS s = HashFunctionSample(e->FunctionAddress, e->SampleBytes, observedHash, observedFirst);

        ULONG flags = 0;
        if (!NT_SUCCESS(s))
        {
            flags |= W32K_HOOK_FLAG_READ_FAILED;
        }
        else
        {
            if (RtlCompareMemory(observedHash, e->BaselineHash, 32) != 32)
                flags |= W32K_HOOK_FLAG_HASH_DRIFT;
            if (FirstBytesLookLikeJmp(observedFirst))
                flags |= W32K_HOOK_FLAG_JMP_PROLOGUE;
        }
        if (moduleShifted) flags |= W32K_HOOK_FLAG_MODULE_SHIFTED;

        if (flags)
        {
            WIRE_WIN32K_HOOK rec;
            RtlZeroMemory(&rec, sizeof(rec));
            rec.FunctionAddress = e->FunctionAddress;
            rec.Win32kBase = g_Win32kBase;
            rec.Win32kSize = g_Win32kSize;
            rec.FunctionId = e->FunctionId;
            rec.Flags = flags;
            RtlCopyMemory(rec.BaselineHash, e->BaselineHash, 32);
            RtlCopyMemory(rec.ObservedHash, observedHash, 32);
            RtlCopyMemory(rec.ObservedFirstBytes, observedFirst, W32K_FN_PROLOG_BYTES);

            (VOID)EventsReportWin32kHook(&rec);
            (VOID)EventsReportTamper(AC_TAMPER_REASON_W32K_SYNTHMOUSE, (PVOID)(ULONG_PTR)e->FunctionAddress);
        }
    }

    return STATUS_SUCCESS;
}
