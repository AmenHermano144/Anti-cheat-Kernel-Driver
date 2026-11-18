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

extern PFN_ZwQuerySystemInformation           AcZwQuerySystemInformation;
extern PFN_ObReferenceObjectByName            AcObReferenceObjectByName;
extern PFN_PsSetCreateProcessNotifyRoutineEx  AcPsSetCreateProcessNotifyRoutineEx;
extern PFN_PsSetLoadImageNotifyRoutine        AcPsSetLoadImageNotifyRoutine;
extern PFN_PsRemoveLoadImageNotifyRoutine     AcPsRemoveLoadImageNotifyRoutine;
extern PFN_PsSetLoadImageNotifyRoutineEx      AcPsSetLoadImageNotifyRoutineEx;

extern PFN_PsLookupProcessByProcessId         AcPsLookupProcessByProcessId;
extern PFN_PsLookupThreadByThreadId           AcPsLookupThreadByThreadId;
extern PFN_PsGetProcessWow64Process           AcPsGetProcessWow64Process;
extern PFN_PsGetProcessImageFileName          AcPsGetProcessImageFileName;
extern PFN_PsGetProcessId                     AcPsGetProcessId;
extern PFN_PsGetProcessPeb                    AcPsGetProcessPeb;

extern PFN_ObReferenceObjectByHandle          AcObReferenceObjectByHandle;
extern PFN_MmCopyMemory                       AcMmCopyMemory;
extern PFN_PsCreateSystemThread               AcPsCreateSystemThread;

extern PFN_KeRegisterNmiCallback              AcKeRegisterNmiCallback;
extern PFN_KeDeregisterNmiCallback            AcKeDeregisterNmiCallback;
extern PFN_HalSendNMI                         AcHalSendNMI;

extern PFN_ZwOpenKey                          AcZwOpenKey;
extern PFN_ZwCreateKey                        AcZwCreateKey;
extern PFN_ZwSetValueKey                      AcZwSetValueKey;
extern PFN_ZwQueryValueKey                    AcZwQueryValueKey;

NTSTATUS AcImportsResolve(PDRIVER_OBJECT DriverObject);
