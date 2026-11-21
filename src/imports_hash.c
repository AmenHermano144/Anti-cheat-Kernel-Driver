#include "imports_hash.h"
#include "core.h"

AC_IMPORT_DESC g_AcImports[AC_IMP_COUNT] = { 0 };

static PVOID g_NtBase = NULL;
static ULONG g_NtSize = 0;

#define FNV64_OFFSET  0xCBF29CE484222325ULL
#define FNV64_PRIME   0x100000001B3ULL

#define AC_HASH_NTOSKRNL                            0x9BE7F70164F3DBF0ULL
#define AC_HASH_HAL                                 0xE702A4918B863EB0ULL

#define AC_HASH_ZwQuerySystemInformation            0x9B3466F6CE10AC9FULL
#define AC_HASH_ObReferenceObjectByName             0x9F6A56D86BC44FECULL
#define AC_HASH_PsSetCreateProcessNotifyRoutineEx   0x394102D5C46F1729ULL
#define AC_HASH_PsSetLoadImageNotifyRoutine         0x1266348DBB3CD2C4ULL
#define AC_HASH_PsRemoveLoadImageNotifyRoutine      0x983D615838941BDCULL
#define AC_HASH_PsSetLoadImageNotifyRoutineEx       0xAF760C3390684271ULL

#define AC_HASH_PsLookupProcessByProcessId          0x8A9495B5004B3E52ULL
#define AC_HASH_PsLookupThreadByThreadId            0x2CB28D18FD28BA7AULL
#define AC_HASH_PsGetProcessWow64Process            0xCA8DC58B141E3783ULL
#define AC_HASH_PsGetProcessImageFileName           0xF9CF74A391B379CFULL
#define AC_HASH_PsGetProcessId                      0xE3F7E2E94AD84598ULL
#define AC_HASH_PsGetProcessPeb                     0x0F05656AA822964CULL

#define AC_HASH_ObReferenceObjectByHandle           0x905061B4022A3E81ULL
#define AC_HASH_MmCopyMemory                        0x306328EE8E049A39ULL
#define AC_HASH_PsCreateSystemThread                0x139DB613C0BCE905ULL

#define AC_HASH_KeRegisterNmiCallback               0xAA520FE89918F267ULL
#define AC_HASH_KeDeregisterNmiCallback             0x6DF139B1E3A8A0C6ULL
#define AC_HASH_HalSendNMI                          0x73CF418D0F5F810CULL

#define AC_HASH_ZwOpenKey                           0x68728064A1D2D535ULL
#define AC_HASH_ZwCreateKey                         0x8DAF12FB2E3254A1ULL
#define AC_HASH_ZwSetValueKey                       0x98F5C40CC4762FEEULL
#define AC_HASH_ZwQueryValueKey                     0xE8151E4A9CFECBA2ULL

typedef struct _CORE_KLDR_ENTRY
{
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} CORE_KLDR_ENTRY, *PCORE_KLDR_ENTRY;

static ULONG64 FnvAscii(const CHAR *s)
{
    ULONG64 h = FNV64_OFFSET;
    while (*s)
    {
        h ^= (UCHAR)*s++;
        h *= FNV64_PRIME;
    }
    return h;
}

static ULONG64 FnvUnicodeI(const WCHAR *s, USHORT lenBytes)
{
    ULONG64 h = FNV64_OFFSET;
    USHORT n = lenBytes / sizeof(WCHAR);
    for (USHORT i = 0; i < n; i++)
    {
        WCHAR c = s[i];
        if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
        h ^= (UCHAR)(c & 0xFF);
        h *= FNV64_PRIME;
    }
    return h;
}

static PVOID FindModuleBase(PDRIVER_OBJECT drv, ULONG64 nameHash)
{
    if (!drv || !drv->DriverSection) return NULL;

    PCORE_KLDR_ENTRY self = (PCORE_KLDR_ENTRY)drv->DriverSection;
    PLIST_ENTRY cursor = self->InLoadOrderLinks.Flink;
    ULONG guard = 0;

    __try
    {
        while (cursor && cursor != &self->InLoadOrderLinks && guard++ < 1024)
        {
            PCORE_KLDR_ENTRY e = CONTAINING_RECORD(cursor, CORE_KLDR_ENTRY, InLoadOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0 && e->DllBase)
            {
                ULONG64 h = FnvUnicodeI(e->BaseDllName.Buffer, e->BaseDllName.Length);
                if (h == nameHash) return e->DllBase;
            }
            cursor = cursor->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static ULONG FindModuleSize(PDRIVER_OBJECT drv, ULONG64 nameHash)
{
    if (!drv || !drv->DriverSection) return 0;

    PCORE_KLDR_ENTRY self = (PCORE_KLDR_ENTRY)drv->DriverSection;
    PLIST_ENTRY cursor = self->InLoadOrderLinks.Flink;
    ULONG guard = 0;

    __try
    {
        while (cursor && cursor != &self->InLoadOrderLinks && guard++ < 1024)
        {
            PCORE_KLDR_ENTRY e = CONTAINING_RECORD(cursor, CORE_KLDR_ENTRY, InLoadOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0 && e->DllBase)
            {
                ULONG64 h = FnvUnicodeI(e->BaseDllName.Buffer, e->BaseDllName.Length);
                if (h == nameHash) return e->SizeOfImage;
            }
            cursor = cursor->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    return 0;
}

static PVOID FindExport(PVOID imgBase, ULONG64 nameHash)
{
    if (!imgBase) return NULL;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imgBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)imgBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imgBase + dir.VirtualAddress);
        PULONG  names    = (PULONG) ((PUCHAR)imgBase + exp->AddressOfNames);
        PUSHORT ordinals = (PUSHORT)((PUCHAR)imgBase + exp->AddressOfNameOrdinals);
        PULONG  funcs    = (PULONG) ((PUCHAR)imgBase + exp->AddressOfFunctions);

        for (ULONG i = 0; i < exp->NumberOfNames; i++)
        {
            const CHAR *name = (const CHAR *)((PUCHAR)imgBase + names[i]);
            if (FnvAscii(name) != nameHash) continue;

            USHORT ord = ordinals[i];
            if (ord >= exp->NumberOfFunctions) return NULL;

            ULONG rva = funcs[ord];
            if (rva == 0) return NULL;

            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) return NULL;

            return (PVOID)((PUCHAR)imgBase + rva);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

static ULONG64 DeriveXorKey(ULONG idx, ULONG64 nameHash)
{
    // per-descriptor key: mix the slot index, the name hash and the boot
    // cookie so two boots of the same build produce two completely different
    // encoded_ptr tables. the rolling_key nibble lives at the low 8 bits so
    // a byte-wise scanner that learned "+0x08 of a 24-byte row" from one
    // boot gets nothing from the next.
    ULONG64 key = CoreBootCookie();
    key ^= nameHash;
    key ^= ((ULONG64)idx * 0x9E3779B97F4A7C15ULL);
    key ^= ((ULONG64)__rdtsc() & 0xFFFFFFFFULL);
    return key;
}

static VOID InstallImport(ULONG idx, PVOID target, ULONG64 nameHash)
{
    ULONG64 key = DeriveXorKey(idx, nameHash);
    g_AcImports[idx].XorKey     = key;
    g_AcImports[idx].EncodedPtr = ((ULONG64)(ULONG_PTR)target) ^ key;
    g_AcImports[idx].Reserved   = CoreBootCookie() ^ (ULONG64)idx;
}

PVOID AcImportsGetNtBase(VOID) { return g_NtBase; }
ULONG AcImportsGetNtSize(VOID) { return g_NtSize; }

PVOID AcImportsResolveNtExportByHash(ULONG64 nameHash)
{
    return g_NtBase ? FindExport(g_NtBase, nameHash) : NULL;
}

NTSTATUS AcImportsFindModule(ULONG64 nameHash, PVOID *outBase, ULONG *outSize)
{
    if (outBase) *outBase = NULL;
    if (outSize) *outSize = 0;

    PDRIVER_OBJECT drv = g_Core.DriverObject;
    if (!drv) return STATUS_NOT_FOUND;

    PVOID base = FindModuleBase(drv, nameHash);
    if (!base) return STATUS_NOT_FOUND;

    ULONG sz = FindModuleSize(drv, nameHash);
    if (outBase) *outBase = base;
    if (outSize) *outSize = sz;
    return STATUS_SUCCESS;
}

NTSTATUS AcImportsResolve(PDRIVER_OBJECT DriverObject)
{
    PVOID ntBase  = FindModuleBase(DriverObject, AC_HASH_NTOSKRNL);
    PVOID halBase = FindModuleBase(DriverObject, AC_HASH_HAL);
    if (!ntBase) return STATUS_NOT_FOUND;

    g_NtBase = ntBase;
    g_NtSize = FindModuleSize(DriverObject, AC_HASH_NTOSKRNL);

    struct _ENTRY { ULONG idx; ULONG64 hash; PVOID base; } table[] =
    {
        { AC_IMP_ZwQuerySystemInformation,           AC_HASH_ZwQuerySystemInformation,           ntBase },
        { AC_IMP_ObReferenceObjectByName,            AC_HASH_ObReferenceObjectByName,            ntBase },
        { AC_IMP_PsSetCreateProcessNotifyRoutineEx,  AC_HASH_PsSetCreateProcessNotifyRoutineEx,  ntBase },
        { AC_IMP_PsSetLoadImageNotifyRoutine,        AC_HASH_PsSetLoadImageNotifyRoutine,        ntBase },
        { AC_IMP_PsRemoveLoadImageNotifyRoutine,     AC_HASH_PsRemoveLoadImageNotifyRoutine,     ntBase },
        { AC_IMP_PsSetLoadImageNotifyRoutineEx,      AC_HASH_PsSetLoadImageNotifyRoutineEx,      ntBase },

        { AC_IMP_PsLookupProcessByProcessId,         AC_HASH_PsLookupProcessByProcessId,         ntBase },
        { AC_IMP_PsLookupThreadByThreadId,           AC_HASH_PsLookupThreadByThreadId,           ntBase },
        { AC_IMP_PsGetProcessWow64Process,           AC_HASH_PsGetProcessWow64Process,           ntBase },
        { AC_IMP_PsGetProcessImageFileName,          AC_HASH_PsGetProcessImageFileName,          ntBase },
        { AC_IMP_PsGetProcessId,                     AC_HASH_PsGetProcessId,                     ntBase },
        { AC_IMP_PsGetProcessPeb,                    AC_HASH_PsGetProcessPeb,                    ntBase },

        { AC_IMP_ObReferenceObjectByHandle,          AC_HASH_ObReferenceObjectByHandle,          ntBase },
        { AC_IMP_MmCopyMemory,                       AC_HASH_MmCopyMemory,                       ntBase },
        { AC_IMP_PsCreateSystemThread,               AC_HASH_PsCreateSystemThread,               ntBase },

        { AC_IMP_KeRegisterNmiCallback,              AC_HASH_KeRegisterNmiCallback,              ntBase },
        { AC_IMP_KeDeregisterNmiCallback,            AC_HASH_KeDeregisterNmiCallback,            ntBase },

        { AC_IMP_ZwOpenKey,                          AC_HASH_ZwOpenKey,                          ntBase },
        { AC_IMP_ZwCreateKey,                        AC_HASH_ZwCreateKey,                        ntBase },
        { AC_IMP_ZwSetValueKey,                      AC_HASH_ZwSetValueKey,                      ntBase },
        { AC_IMP_ZwQueryValueKey,                    AC_HASH_ZwQueryValueKey,                    ntBase },
    };

    for (ULONG i = 0; i < ARRAYSIZE(table); i++)
    {
        PVOID p = FindExport(table[i].base, table[i].hash);
        InstallImport(table[i].idx, p, table[i].hash);
    }

    // HalSendNMI may live in either hal or ntoskrnl depending on the build.
    PVOID halNmi = NULL;
    if (halBase) halNmi = FindExport(halBase, AC_HASH_HalSendNMI);
    if (!halNmi) halNmi = FindExport(ntBase, AC_HASH_HalSendNMI);
    InstallImport(AC_IMP_HalSendNMI, halNmi, AC_HASH_HalSendNMI);

    if (AcResolveImport(AC_IMP_ZwQuerySystemInformation) == NULL)          return STATUS_NOT_FOUND;
    if (AcResolveImport(AC_IMP_ObReferenceObjectByName) == NULL)           return STATUS_NOT_FOUND;
    if (AcResolveImport(AC_IMP_PsSetCreateProcessNotifyRoutineEx) == NULL) return STATUS_NOT_FOUND;
    if (AcResolveImport(AC_IMP_PsSetLoadImageNotifyRoutine) == NULL)       return STATUS_NOT_FOUND;
    if (AcResolveImport(AC_IMP_PsRemoveLoadImageNotifyRoutine) == NULL)    return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}
