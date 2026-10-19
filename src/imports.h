#pragma once

#include "core.h"

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI ZwQuerySecurityObject(
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Length,
    PULONG LengthNeeded);

NTSYSAPI PVOID NTAPI RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage);

NTKERNELAPI NTSTATUS NTAPI MmCopyMemory(
    PVOID                 TargetAddress,
    MM_COPY_ADDRESS       SourceAddress,
    SIZE_T                NumberOfBytes,
    ULONG                 Flags,
    PSIZE_T               NumberOfBytesTransferred);

NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
NTKERNELAPI HANDLE NTAPI PsGetProcessId(PEPROCESS Process);
NTKERNELAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define CORE_SysKernelDebuggerInformation   0x23
#define CORE_SysModuleInformation           0x0B
#define CORE_SysFirmwareTableInformation    0x4C
#define CORE_SysBigPoolInformation          0x42

typedef struct _CORE_SYSTEM_BIG_POOL_ENTRY
{
    union
    {
        PVOID       VirtualAddress;
        ULONG_PTR   NonPagedBit;
    };
    ULONG_PTR SizeInBytes;
    union
    {
        UCHAR Tag[4];
        ULONG TagULong;
    };
} CORE_SYSTEM_BIG_POOL_ENTRY, *PCORE_SYSTEM_BIG_POOL_ENTRY;

typedef struct _CORE_SYSTEM_BIG_POOL_INFORMATION
{
    ULONG Count;
    CORE_SYSTEM_BIG_POOL_ENTRY AllocatedInfo[1];
} CORE_SYSTEM_BIG_POOL_INFORMATION, *PCORE_SYSTEM_BIG_POOL_INFORMATION;

#ifndef PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE
#define PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE  0x00000001
#endif

NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING    ObjectName,
    ULONG              Attributes,
    PACCESS_STATE      AccessState,
    ACCESS_MASK        DesiredAccess,
    POBJECT_TYPE       ObjectType,
    KPROCESSOR_MODE    AccessMode,
    PVOID              ParseContext,
    PVOID              *Object);

extern POBJECT_TYPE *IoDriverObjectType;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

#define CORE_FW_ACTION_ENUMERATE        0
#define CORE_FW_ACTION_GET              1
#define CORE_FW_PROVIDER_ACPI           'ACPI'
#define CORE_FW_PROVIDER_RSMB           'RSMB'
#define CORE_FW_PROVIDER_FIRM           'FIRM'
