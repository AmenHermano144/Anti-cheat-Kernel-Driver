#pragma once

#include "core.h"

#define WIRE_RECORD_MAGIC       0x43416352
#define WIRE_RECORD_VERSION     0x01

#define WIRE_REC_HEARTBEAT      0x24
#define WIRE_REC_PROCESS_ATTACH 0x1E
#define WIRE_REC_PROCESS_EXIT   0x1F
#define WIRE_REC_IMAGE_LOAD     0x26
#define WIRE_REC_BYOVD_HIT      0x29
#define WIRE_REC_MODULE_VERIFY  0x2B
#define WIRE_REC_PML4_ANOMALY   0x12
#define WIRE_REC_TAMPER         0x30
#define WIRE_REC_HWID_HELLO     0x40
#define WIRE_REC_HWID_DISK      0x41
#define WIRE_REC_HWID_MEMORY    0x42
#define WIRE_REC_UNBACKED_EXEC  0x50
#define WIRE_REC_INPUT_HIJACK   0x51
#define WIRE_REC_PIDDB_TAMPER   0x52
#define WIRE_REC_MMUNLOADED_TAMPER 0x53
#define WIRE_REC_SIG_REJECT     0x55
#define WIRE_REC_HOOK_AUDIT     0x56
#define WIRE_REC_HANDLE_AUDIT   0x57
#define WIRE_REC_TEARDOWN       0x02

#define WIRE_HOOK_OP_REMOTE_THREAD   1
#define WIRE_HOOK_OP_PARASITE_DLL    2
#define WIRE_HOOK_OP_HANDLE_STRIP    3

#define WIRE_HOOK_FLAG_ALLOWED       0x0001
#define WIRE_HOOK_FLAG_STRIPPED      0x0002
#define WIRE_HOOK_FLAG_UNSIGNED      0x0004
#define WIRE_HOOK_FLAG_FOREIGN_DIR   0x0008
#define WIRE_HOOK_FLAG_NAME_MATCH    0x0010
#define WIRE_HOOK_FLAG_CROSS_PROC    0x0020

#define WIRE_HANDLE_FLAG_THREAD      0x0001
#define WIRE_HANDLE_FLAG_DUP         0x0002

#pragma pack(push, 1)
typedef struct _WIRE_RECORD_HEADER
{
    ULONG   Magic;
    UCHAR   Version;
    UCHAR   Type;
    USHORT  Flags;
    ULONG   Length;
    ULONG64 Sequence;
    ULONG64 Timestamp;
    UCHAR   Payload[1];
} WIRE_RECORD_HEADER, *PWIRE_RECORD_HEADER;

typedef struct _WIRE_HEARTBEAT
{
    ULONG64 BootCookie;
    ULONG   InitState;
    ULONG   Reserved;
} WIRE_HEARTBEAT, *PWIRE_HEARTBEAT;

typedef struct _WIRE_PROCESS_ATTACH
{
    ULONG64 ProcessId;
    ULONG64 ParentProcessId;
    USHORT  ImagePathLen;
    UCHAR   ImagePath[520];
} WIRE_PROCESS_ATTACH, *PWIRE_PROCESS_ATTACH;

typedef struct _WIRE_IMAGE_LOAD
{
    ULONG64 ProcessId;
    ULONG64 ImageBase;
    ULONG   ImageSize;
    UCHAR   SystemImage;
    UCHAR   Reserved[3];
    USHORT  ImagePathLen;
    UCHAR   ImagePath[520];
} WIRE_IMAGE_LOAD, *PWIRE_IMAGE_LOAD;

typedef struct _WIRE_BYOVD_HIT
{
    ULONG64 ImageBase;
    ULONG   ImageSize;
    ULONG64 Fnv1a64;
    USHORT  MatchedPathLen;
    UCHAR   MatchedPath[260];
    USHORT  ImagePathLen;
    UCHAR   ImagePath[520];
} WIRE_BYOVD_HIT, *PWIRE_BYOVD_HIT;

typedef struct _WIRE_PML4_ANOMALY
{
    ULONG   Index;
    ULONG64 Observed;
    ULONG64 Expected;
    ULONG64 PhysicalBase;
} WIRE_PML4_ANOMALY, *PWIRE_PML4_ANOMALY;

typedef struct _WIRE_TAMPER
{
    ULONG   Reason;
    ULONG   CpuIndex;
    ULONG64 Observed;
    ULONG64 Expected;
} WIRE_TAMPER, *PWIRE_TAMPER;

typedef struct _WIRE_HWID_HELLO
{
    UCHAR   BiosVendor[64];
    UCHAR   SystemManufacturer[64];
    UCHAR   SystemProductName[64];
    UCHAR   BaseboardSerial[64];
    UCHAR   SystemUuid[16];
    ULONG   RamModuleCount;
} WIRE_HWID_HELLO, *PWIRE_HWID_HELLO;

typedef struct _WIRE_UNBACKED_EXEC
{
    ULONG64 Address;
    ULONG64 SizeInBytes;
    ULONG   PoolTag;
    ULONG   Flags;
    UCHAR   FirstBytes[64];
} WIRE_UNBACKED_EXEC, *PWIRE_UNBACKED_EXEC;

typedef struct _WIRE_INPUT_HIJACK
{
    ULONG64 DeviceObject;
    ULONG64 SlotAddress;
    ULONG64 ExpectedCallback;
    ULONG64 ObservedCallback;
    ULONG64 ObservedCallbackModuleBase;
    UCHAR   DeviceClass;
    UCHAR   Reserved[7];
} WIRE_INPUT_HIJACK, *PWIRE_INPUT_HIJACK;

typedef struct _WIRE_PIDDB_TAMPER
{
    ULONG64 TablePointer;
    ULONG   ExpectedCount;
    ULONG   ObservedCount;
    ULONG64 ExpectedFnv;
    ULONG64 ObservedFnv;
} WIRE_PIDDB_TAMPER, *PWIRE_PIDDB_TAMPER;

typedef struct _WIRE_MMUNLOADED_TAMPER
{
    ULONG64 TablePointer;
    ULONG64 ExpectedFnv;
    ULONG64 ObservedFnv;
} WIRE_MMUNLOADED_TAMPER, *PWIRE_MMUNLOADED_TAMPER;

typedef struct _WIRE_SIG_REJECT
{
    ULONG64 ProcessId;
    ULONG64 ImageBase;
    ULONG   NtStatus;
    USHORT  ImagePathLen;
    UCHAR   ImagePath[520];
} WIRE_SIG_REJECT, *PWIRE_SIG_REJECT;

typedef struct _WIRE_HOOK_AUDIT
{
    ULONG   Operation;
    ULONG   DecisionFlags;
    ULONG64 TargetProcessId;
    ULONG64 CallerProcessId;
    ULONG64 CallerThreadId;
    ULONG64 SuspectAddress;
    ULONG64 SystemTime;
    USHORT  CallerImagePathLen;
    UCHAR   CallerImagePath[520];
    USHORT  TargetImagePathLen;
    UCHAR   TargetImagePath[520];
    UCHAR   TargetImageName[16];
} WIRE_HOOK_AUDIT, *PWIRE_HOOK_AUDIT;

typedef struct _WIRE_HANDLE_AUDIT
{
    ULONG64 CallerProcessId;
    ULONG64 TargetProcessId;
    ULONG   OriginalAccess;
    ULONG   StrippedAccess;
    ULONG   Flags;
    ULONG   Reserved;
    USHORT  CallerImagePathLen;
    UCHAR   CallerImagePath[520];
} WIRE_HANDLE_AUDIT, *PWIRE_HANDLE_AUDIT;
#pragma pack(pop)
