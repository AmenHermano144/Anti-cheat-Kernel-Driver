#include "usermod.h"
#include "imports.h"

#pragma pack(push, 1)
typedef struct _CORE_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} CORE_LDR_DATA_TABLE_ENTRY, *PCORE_LDR_DATA_TABLE_ENTRY;

typedef struct _CORE_PEB_LDR_DATA
{
    ULONG      Length;
    UCHAR      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} CORE_PEB_LDR_DATA, *PCORE_PEB_LDR_DATA;

typedef struct _CORE_PEB
{
    UCHAR  Reserved1[2];
    UCHAR  BeingDebugged;
    UCHAR  Reserved2[1];
    PVOID  Reserved3[2];
    PCORE_PEB_LDR_DATA Ldr;
} CORE_PEB, *PCORE_PEB;
#pragma pack(pop)

NTSTATUS UsermodWalkProcessModules(HANDLE ProcessId, USERMOD_ITER_CB cb, PVOID userCtx)
{
    if (!cb) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(s)) return s;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    PCORE_PEB peb = (PCORE_PEB)PsGetProcessPeb(proc);
    if (!peb || !peb->Ldr)
    {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return STATUS_NOT_FOUND;
    }

    __try
    {
        PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY node = head->Flink;
        ULONG guard = 0;

        while (node && node != head && guard < 1024)
        {
            PCORE_LDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(node, CORE_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            USERMOD_ITER_CB_CTX ctx;
            ctx.OpaqueBase = e->DllBase;
            ctx.Size = e->SizeOfImage;
            ctx.NamePtr = e->BaseDllName.Buffer;
            ctx.NameLen = e->BaseDllName.Length;

            if (!cb(&ctx, userCtx)) break;

            node = node->Flink;
            guard++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}
