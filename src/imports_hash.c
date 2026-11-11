#include "imports_hash.h"
#include "core.h"

PFN_ZwQuerySystemInformation           AcZwQuerySystemInformation           = NULL;
PFN_ObReferenceObjectByName            AcObReferenceObjectByName            = NULL;
PFN_PsSetCreateProcessNotifyRoutineEx  AcPsSetCreateProcessNotifyRoutineEx  = NULL;
PFN_PsSetLoadImageNotifyRoutine        AcPsSetLoadImageNotifyRoutine        = NULL;
PFN_PsRemoveLoadImageNotifyRoutine     AcPsRemoveLoadImageNotifyRoutine     = NULL;
PFN_PsSetLoadImageNotifyRoutineEx      AcPsSetLoadImageNotifyRoutineEx      = NULL;

#define FNV64_OFFSET  0xCBF29CE484222325ULL
#define FNV64_PRIME   0x100000001B3ULL

#define AC_HASH_NTOSKRNL                            0x9BE7F70164F3DBF0ULL
#define AC_HASH_ZwQuerySystemInformation            0x9B3466F6CE10AC9FULL
#define AC_HASH_ObReferenceObjectByName             0x9F6A56D86BC44FECULL
#define AC_HASH_PsSetCreateProcessNotifyRoutineEx   0x394102D5C46F1729ULL
#define AC_HASH_PsSetLoadImageNotifyRoutine         0x1266348DBB3CD2C4ULL
#define AC_HASH_PsRemoveLoadImageNotifyRoutine      0x983D615838941BDCULL
#define AC_HASH_PsSetLoadImageNotifyRoutineEx       0xAF760C3390684271ULL

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

static PVOID FindNtoskrnlBase(PDRIVER_OBJECT drv)
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
                if (h == AC_HASH_NTOSKRNL) return e->DllBase;
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

NTSTATUS AcImportsResolve(PDRIVER_OBJECT DriverObject)
{
    PVOID ntBase = FindNtoskrnlBase(DriverObject);
    if (!ntBase) return STATUS_NOT_FOUND;

    AcZwQuerySystemInformation =
        (PFN_ZwQuerySystemInformation)FindExport(ntBase, AC_HASH_ZwQuerySystemInformation);
    AcObReferenceObjectByName =
        (PFN_ObReferenceObjectByName)FindExport(ntBase, AC_HASH_ObReferenceObjectByName);
    AcPsSetCreateProcessNotifyRoutineEx =
        (PFN_PsSetCreateProcessNotifyRoutineEx)FindExport(ntBase, AC_HASH_PsSetCreateProcessNotifyRoutineEx);
    AcPsSetLoadImageNotifyRoutine =
        (PFN_PsSetLoadImageNotifyRoutine)FindExport(ntBase, AC_HASH_PsSetLoadImageNotifyRoutine);
    AcPsRemoveLoadImageNotifyRoutine =
        (PFN_PsRemoveLoadImageNotifyRoutine)FindExport(ntBase, AC_HASH_PsRemoveLoadImageNotifyRoutine);
    AcPsSetLoadImageNotifyRoutineEx =
        (PFN_PsSetLoadImageNotifyRoutineEx)FindExport(ntBase, AC_HASH_PsSetLoadImageNotifyRoutineEx);

    if (!AcZwQuerySystemInformation)          return STATUS_NOT_FOUND;
    if (!AcObReferenceObjectByName)           return STATUS_NOT_FOUND;
    if (!AcPsSetCreateProcessNotifyRoutineEx) return STATUS_NOT_FOUND;
    if (!AcPsSetLoadImageNotifyRoutine)       return STATUS_NOT_FOUND;
    if (!AcPsRemoveLoadImageNotifyRoutine)    return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}
