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

extern PFN_ZwQuerySystemInformation           AcZwQuerySystemInformation;
extern PFN_ObReferenceObjectByName            AcObReferenceObjectByName;
extern PFN_PsSetCreateProcessNotifyRoutineEx  AcPsSetCreateProcessNotifyRoutineEx;
extern PFN_PsSetLoadImageNotifyRoutine        AcPsSetLoadImageNotifyRoutine;
extern PFN_PsRemoveLoadImageNotifyRoutine     AcPsRemoveLoadImageNotifyRoutine;
extern PFN_PsSetLoadImageNotifyRoutineEx      AcPsSetLoadImageNotifyRoutineEx;

NTSTATUS AcImportsResolve(PDRIVER_OBJECT DriverObject);
