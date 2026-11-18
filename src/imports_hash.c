#include "imports_hash.h"
#include "core.h"

PFN_ZwQuerySystemInformation           AcZwQuerySystemInformation           = NULL;
PFN_ObReferenceObjectByName            AcObReferenceObjectByName            = NULL;
PFN_PsSetCreateProcessNotifyRoutineEx  AcPsSetCreateProcessNotifyRoutineEx  = NULL;
PFN_PsSetLoadImageNotifyRoutine        AcPsSetLoadImageNotifyRoutine        = NULL;
PFN_PsRemoveLoadImageNotifyRoutine     AcPsRemoveLoadImageNotifyRoutine     = NULL;
PFN_PsSetLoadImageNotifyRoutineEx      AcPsSetLoadImageNotifyRoutineEx      = NULL;

PFN_PsLookupProcessByProcessId         AcPsLookupProcessByProcessId         = NULL;
PFN_PsLookupThreadByThreadId           AcPsLookupThreadByThreadId           = NULL;
PFN_PsGetProcessWow64Process           AcPsGetProcessWow64Process           = NULL;
PFN_PsGetProcessImageFileName          AcPsGetProcessImageFileName          = NULL;
PFN_PsGetProcessId                     AcPsGetProcessId                     = NULL;
PFN_PsGetProcessPeb                    AcPsGetProcessPeb                    = NULL;

PFN_ObReferenceObjectByHandle          AcObReferenceObjectByHandle          = NULL;
PFN_MmCopyMemory                       AcMmCopyMemory                       = NULL;
PFN_PsCreateSystemThread               AcPsCreateSystemThread               = NULL;

PFN_KeRegisterNmiCallback              AcKeRegisterNmiCallback              = NULL;
PFN_KeDeregisterNmiCallback            AcKeDeregisterNmiCallback            = NULL;
PFN_HalSendNMI                         AcHalSendNMI                         = NULL;

PFN_ZwOpenKey                          AcZwOpenKey                          = NULL;
PFN_ZwCreateKey                        AcZwCreateKey                        = NULL;
PFN_ZwSetValueKey                      AcZwSetValueKey                      = NULL;
PFN_ZwQueryValueKey                    AcZwQueryValueKey                    = NULL;

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
    PVOID ntBase  = FindModuleBase(DriverObject, AC_HASH_NTOSKRNL);
    PVOID halBase = FindModuleBase(DriverObject, AC_HASH_HAL);
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

    AcPsLookupProcessByProcessId =
        (PFN_PsLookupProcessByProcessId)FindExport(ntBase, AC_HASH_PsLookupProcessByProcessId);
    AcPsLookupThreadByThreadId =
        (PFN_PsLookupThreadByThreadId)FindExport(ntBase, AC_HASH_PsLookupThreadByThreadId);
    AcPsGetProcessWow64Process =
        (PFN_PsGetProcessWow64Process)FindExport(ntBase, AC_HASH_PsGetProcessWow64Process);
    AcPsGetProcessImageFileName =
        (PFN_PsGetProcessImageFileName)FindExport(ntBase, AC_HASH_PsGetProcessImageFileName);
    AcPsGetProcessId =
        (PFN_PsGetProcessId)FindExport(ntBase, AC_HASH_PsGetProcessId);
    AcPsGetProcessPeb =
        (PFN_PsGetProcessPeb)FindExport(ntBase, AC_HASH_PsGetProcessPeb);

    AcObReferenceObjectByHandle =
        (PFN_ObReferenceObjectByHandle)FindExport(ntBase, AC_HASH_ObReferenceObjectByHandle);
    AcMmCopyMemory =
        (PFN_MmCopyMemory)FindExport(ntBase, AC_HASH_MmCopyMemory);
    AcPsCreateSystemThread =
        (PFN_PsCreateSystemThread)FindExport(ntBase, AC_HASH_PsCreateSystemThread);

    AcKeRegisterNmiCallback =
        (PFN_KeRegisterNmiCallback)FindExport(ntBase, AC_HASH_KeRegisterNmiCallback);
    AcKeDeregisterNmiCallback =
        (PFN_KeDeregisterNmiCallback)FindExport(ntBase, AC_HASH_KeDeregisterNmiCallback);

    if (halBase)
        AcHalSendNMI = (PFN_HalSendNMI)FindExport(halBase, AC_HASH_HalSendNMI);
    if (!AcHalSendNMI)
        AcHalSendNMI = (PFN_HalSendNMI)FindExport(ntBase, AC_HASH_HalSendNMI);

    AcZwOpenKey       = (PFN_ZwOpenKey)      FindExport(ntBase, AC_HASH_ZwOpenKey);
    AcZwCreateKey     = (PFN_ZwCreateKey)    FindExport(ntBase, AC_HASH_ZwCreateKey);
    AcZwSetValueKey   = (PFN_ZwSetValueKey)  FindExport(ntBase, AC_HASH_ZwSetValueKey);
    AcZwQueryValueKey = (PFN_ZwQueryValueKey)FindExport(ntBase, AC_HASH_ZwQueryValueKey);

    if (!AcZwQuerySystemInformation)          return STATUS_NOT_FOUND;
    if (!AcObReferenceObjectByName)           return STATUS_NOT_FOUND;
    if (!AcPsSetCreateProcessNotifyRoutineEx) return STATUS_NOT_FOUND;
    if (!AcPsSetLoadImageNotifyRoutine)       return STATUS_NOT_FOUND;
    if (!AcPsRemoveLoadImageNotifyRoutine)    return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}
