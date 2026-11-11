#pragma once

#include "core.h"
#include "imports_hash.h"

#define ZwQuerySystemInformation  AcZwQuerySystemInformation
#define ObReferenceObjectByName   AcObReferenceObjectByName

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
#define CORE_SysProcessInformation          0x05
#define CORE_SysExtendedProcessInformation  0x39

#define CORE_WAIT_REASON_SUSPENDED          5

typedef struct _CORE_CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CORE_CLIENT_ID, *PCORE_CLIENT_ID;

typedef struct _CORE_SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER   KernelTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   CreateTime;
    ULONG           WaitTime;
    PVOID           StartAddress;
    CORE_CLIENT_ID  ClientId;
    KPRIORITY       Priority;
    LONG            BasePriority;
    ULONG           ContextSwitches;
    ULONG           ThreadState;
    ULONG           WaitReason;
} CORE_SYSTEM_THREAD_INFORMATION, *PCORE_SYSTEM_THREAD_INFORMATION;

typedef struct _CORE_SYSTEM_EXTENDED_THREAD_INFORMATION
{
    CORE_SYSTEM_THREAD_INFORMATION  ThreadInfo;
    PVOID                           StackBase;
    PVOID                           StackLimit;
    PVOID                           Win32StartAddress;
    PVOID                           TebBase;
    ULONG_PTR                       Reserved2;
    ULONG_PTR                       Reserved3;
    ULONG_PTR                       Reserved4;
} CORE_SYSTEM_EXTENDED_THREAD_INFORMATION, *PCORE_SYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _CORE_SYSTEM_PROCESS_INFORMATION
{
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
} CORE_SYSTEM_PROCESS_INFORMATION, *PCORE_SYSTEM_PROCESS_INFORMATION;

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

extern POBJECT_TYPE *IoDriverObjectType;

NTKERNELAPI NTSTATUS NTAPI ObSetSecurityObjectByPointer(
    PVOID                Object,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor);

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

#define CORE_FW_ACTION_ENUMERATE        0
#define CORE_FW_ACTION_GET              1
#define CORE_FW_PROVIDER_ACPI           'ACPI'
#define CORE_FW_PROVIDER_RSMB           'RSMB'
#define CORE_FW_PROVIDER_FIRM           'FIRM'
