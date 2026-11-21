#pragma once

#include <ntifs.h>

typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS (NTAPI *PFN_ObReferenceObjectByName)(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID          *Object);

typedef NTSTATUS (NTAPI *PFN_PsSetCreateProcessNotifyRoutineEx)(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN                           Remove);

typedef NTSTATUS (NTAPI *PFN_PsSetLoadImageNotifyRoutine)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI *PFN_PsRemoveLoadImageNotifyRoutine)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI *PFN_PsSetLoadImageNotifyRoutineEx)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
    ULONG_PTR                  Flags);

typedef NTSTATUS (NTAPI *PFN_PsLookupProcessByProcessId)(
    HANDLE     ProcessId,
    PEPROCESS *Process);

typedef NTSTATUS (NTAPI *PFN_PsLookupThreadByThreadId)(
    HANDLE    ThreadId,
    PETHREAD *Thread);

typedef PVOID    (NTAPI *PFN_PsGetProcessWow64Process)(PEPROCESS Process);
typedef PCHAR    (NTAPI *PFN_PsGetProcessImageFileName)(PEPROCESS Process);
typedef HANDLE   (NTAPI *PFN_PsGetProcessId)(PEPROCESS Process);
typedef PVOID    (NTAPI *PFN_PsGetProcessPeb)(PEPROCESS Process);

typedef NTSTATUS (NTAPI *PFN_ObReferenceObjectByHandle)(
    HANDLE           Handle,
    ACCESS_MASK      DesiredAccess,
    POBJECT_TYPE     ObjectType,
    KPROCESSOR_MODE  AccessMode,
    PVOID           *Object,
    POBJECT_HANDLE_INFORMATION HandleInformation);

typedef NTSTATUS (NTAPI *PFN_MmCopyMemory)(
    PVOID                 TargetAddress,
    MM_COPY_ADDRESS       SourceAddress,
    SIZE_T                NumberOfBytes,
    ULONG                 Flags,
    PSIZE_T               NumberOfBytesTransferred);

typedef NTSTATUS (NTAPI *PFN_PsCreateSystemThread)(
    PHANDLE            ThreadHandle,
    ULONG              DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PCLIENT_ID         ClientId,
    PKSTART_ROUTINE    StartRoutine,
    PVOID              StartContext);

typedef PVOID    (NTAPI *PFN_KeRegisterNmiCallback)(PVOID CallbackRoutine, PVOID Context);
typedef NTSTATUS (NTAPI *PFN_KeDeregisterNmiCallback)(PVOID Handle);
typedef VOID     (NTAPI *PFN_HalSendNMI)(KAFFINITY ProcessorMask);

typedef NTSTATUS (NTAPI *PFN_ZwOpenKey)(
    PHANDLE            KeyHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *PFN_ZwCreateKey)(
    PHANDLE            KeyHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG              TitleIndex,
    PUNICODE_STRING    Class,
    ULONG              CreateOptions,
    PULONG             Disposition);

typedef NTSTATUS (NTAPI *PFN_ZwSetValueKey)(
    HANDLE          KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG           TitleIndex,
    ULONG           Type,
    PVOID           Data,
    ULONG           DataSize);

typedef NTSTATUS (NTAPI *PFN_ZwQueryValueKey)(
    HANDLE                       KeyHandle,
    PUNICODE_STRING              ValueName,
    KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
    PVOID                        KeyValueInformation,
    ULONG                        Length,
    PULONG                       ResultLength);

// descriptor-based import resolution. the flat pointer table we used to ship
// had every AcXxx = resolved_addr sitting in .data, where any scanner that
// knew what to look for would find our full list instantly. the vanguard vgk
// 1.19.2 writeup documented their current layout — a 240-row table of
// { byte index, qword xor_key, qword encoded_ptr } rewritten at every boot;
// a static .data scan after the fact never recovers the live pointers. this
// port keeps the interface identical (AcMmCopyMemory(...) still looks like a
// function pointer call at every call site) but moves the storage to the
// same shape: one 24-byte descriptor per api with a per-entry xor key, and a
// single accessor that xors on demand right before the indirect call.
typedef struct _AC_IMPORT_DESC
{
    ULONG64 EncodedPtr;
    ULONG64 XorKey;
    ULONG64 Reserved;
} AC_IMPORT_DESC, *PAC_IMPORT_DESC;

typedef enum _AC_IMPORT_IDX
{
    AC_IMP_ZwQuerySystemInformation          = 0,
    AC_IMP_ObReferenceObjectByName           = 1,
    AC_IMP_PsSetCreateProcessNotifyRoutineEx = 2,
    AC_IMP_PsSetLoadImageNotifyRoutine       = 3,
    AC_IMP_PsRemoveLoadImageNotifyRoutine    = 4,
    AC_IMP_PsSetLoadImageNotifyRoutineEx     = 5,

    AC_IMP_PsLookupProcessByProcessId        = 6,
    AC_IMP_PsLookupThreadByThreadId          = 7,
    AC_IMP_PsGetProcessWow64Process          = 8,
    AC_IMP_PsGetProcessImageFileName         = 9,
    AC_IMP_PsGetProcessId                    = 10,
    AC_IMP_PsGetProcessPeb                   = 11,

    AC_IMP_ObReferenceObjectByHandle         = 12,
    AC_IMP_MmCopyMemory                      = 13,
    AC_IMP_PsCreateSystemThread              = 14,

    AC_IMP_KeRegisterNmiCallback             = 15,
    AC_IMP_KeDeregisterNmiCallback           = 16,
    AC_IMP_HalSendNMI                        = 17,

    AC_IMP_ZwOpenKey                         = 18,
    AC_IMP_ZwCreateKey                       = 19,
    AC_IMP_ZwSetValueKey                     = 20,
    AC_IMP_ZwQueryValueKey                   = 21,

    AC_IMP_COUNT                             = 22
} AC_IMPORT_IDX;

extern AC_IMPORT_DESC g_AcImports[AC_IMP_COUNT];

// thunk lives in ac_asm.asm. forwarding through an external call keeps the
// xor-decode sequence in one .text location instead of being inlined into
// every caller — a scanner that learns the shape in one spot still can't
// find the next one because there isn't one. the per-call overhead vs. the
// previous __forceinline is one call + one ret, dwarfed by anything a
// resolved api actually does.
#ifdef __cplusplus
extern "C" ULONG64 AcResolveImportA(ULONG idx);
#else
ULONG64 AcResolveImportA(ULONG idx);
#endif

__forceinline PVOID AcResolveImport(ULONG idx)
{
    return (PVOID)AcResolveImportA(idx);
}

#define AcZwQuerySystemInformation          ((PFN_ZwQuerySystemInformation)         AcResolveImport(AC_IMP_ZwQuerySystemInformation))
#define AcObReferenceObjectByName           ((PFN_ObReferenceObjectByName)          AcResolveImport(AC_IMP_ObReferenceObjectByName))
#define AcPsSetCreateProcessNotifyRoutineEx ((PFN_PsSetCreateProcessNotifyRoutineEx)AcResolveImport(AC_IMP_PsSetCreateProcessNotifyRoutineEx))
#define AcPsSetLoadImageNotifyRoutine       ((PFN_PsSetLoadImageNotifyRoutine)      AcResolveImport(AC_IMP_PsSetLoadImageNotifyRoutine))
#define AcPsRemoveLoadImageNotifyRoutine    ((PFN_PsRemoveLoadImageNotifyRoutine)   AcResolveImport(AC_IMP_PsRemoveLoadImageNotifyRoutine))
#define AcPsSetLoadImageNotifyRoutineEx     ((PFN_PsSetLoadImageNotifyRoutineEx)    AcResolveImport(AC_IMP_PsSetLoadImageNotifyRoutineEx))

#define AcPsLookupProcessByProcessId        ((PFN_PsLookupProcessByProcessId)       AcResolveImport(AC_IMP_PsLookupProcessByProcessId))
#define AcPsLookupThreadByThreadId          ((PFN_PsLookupThreadByThreadId)         AcResolveImport(AC_IMP_PsLookupThreadByThreadId))
#define AcPsGetProcessWow64Process          ((PFN_PsGetProcessWow64Process)         AcResolveImport(AC_IMP_PsGetProcessWow64Process))
#define AcPsGetProcessImageFileName         ((PFN_PsGetProcessImageFileName)        AcResolveImport(AC_IMP_PsGetProcessImageFileName))
#define AcPsGetProcessId                    ((PFN_PsGetProcessId)                   AcResolveImport(AC_IMP_PsGetProcessId))
#define AcPsGetProcessPeb                   ((PFN_PsGetProcessPeb)                  AcResolveImport(AC_IMP_PsGetProcessPeb))

#define AcObReferenceObjectByHandle         ((PFN_ObReferenceObjectByHandle)        AcResolveImport(AC_IMP_ObReferenceObjectByHandle))
#define AcMmCopyMemory                      ((PFN_MmCopyMemory)                     AcResolveImport(AC_IMP_MmCopyMemory))
#define AcPsCreateSystemThread              ((PFN_PsCreateSystemThread)             AcResolveImport(AC_IMP_PsCreateSystemThread))

#define AcKeRegisterNmiCallback             ((PFN_KeRegisterNmiCallback)            AcResolveImport(AC_IMP_KeRegisterNmiCallback))
#define AcKeDeregisterNmiCallback           ((PFN_KeDeregisterNmiCallback)          AcResolveImport(AC_IMP_KeDeregisterNmiCallback))
#define AcHalSendNMI                        ((PFN_HalSendNMI)                       AcResolveImport(AC_IMP_HalSendNMI))

#define AcZwOpenKey                         ((PFN_ZwOpenKey)                        AcResolveImport(AC_IMP_ZwOpenKey))
#define AcZwCreateKey                       ((PFN_ZwCreateKey)                      AcResolveImport(AC_IMP_ZwCreateKey))
#define AcZwSetValueKey                     ((PFN_ZwSetValueKey)                    AcResolveImport(AC_IMP_ZwSetValueKey))
#define AcZwQueryValueKey                   ((PFN_ZwQueryValueKey)                  AcResolveImport(AC_IMP_ZwQueryValueKey))

NTSTATUS AcImportsResolve(PDRIVER_OBJECT DriverObject);

// gives ssdt_integrity a way to fetch the live ntoskrnl base without
// re-walking the module list on every heartbeat.
PVOID    AcImportsGetNtBase(VOID);
ULONG    AcImportsGetNtSize(VOID);
PVOID    AcImportsResolveNtExportByHash(ULONG64 nameHash);
NTSTATUS AcImportsFindModule(ULONG64 nameHash, PVOID *outBase, ULONG *outSize);
