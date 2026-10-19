#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>

#define CORE_AC_POOL_TAG            'cAcA'
#define CORE_AC_POOL_TAG_WIRE       'rWcA'
#define CORE_AC_POOL_TAG_HWID       'hHcA'
#define CORE_AC_POOL_TAG_CRYPTO     'ocCA'
#define CORE_AC_POOL_TAG_SCAN       'cScA'
#define CORE_AC_POOL_TAG_INTG       'iIcA'
#define CORE_AC_POOL_TAG_PML        'lPcA'
#define CORE_AC_POOL_TAG_CHAN       'bCcA'

#define CORE_AC_DEVICE_NAME         L"\\Device\\CoreAC"
#define CORE_AC_DOSDEVICE_NAME      L"\\??\\CoreAC"
#define CORE_AC_EVENT_DEVICE_NAME   L"\\Device\\CoreAC_EVT"

#define CORE_AC_DEVICE_TYPE         0x8023
#define CORE_AC_EVENT_DEVICE_TYPE   0xC351

#define CORE_AC_CTL(code)           CTL_CODE(CORE_AC_DEVICE_TYPE, (code), METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CORE_AC_GLOBAL
{
    PDRIVER_OBJECT      DriverObject;
    PDEVICE_OBJECT      ControlDevice;
    PDEVICE_OBJECT      EventDevice;
    UNICODE_STRING      SymLink;

    HANDLE              WorkerThreadHandle;
    PETHREAD            WorkerThread;
    KEVENT              WorkerWakeEvent;
    KEVENT              WorkerStopEvent;
    KTIMER              HeartbeatTimer;
    volatile LONG       StopRequested;

    volatile LONG       InitState;
    LARGE_INTEGER       BootPerfCounter;
    ULONG64             BootCookie[2];
    ULONG64             LstarReference[2];

    volatile LONG       SessionActive;
    GUID                SessionGuid;
    UCHAR               SessionKey[32];

    PVOID               NmiCallbackHandle;
    PVOID               LoadImageCookie;
    PVOID               CreateProcessCookie;
} CORE_AC_GLOBAL, *PCORE_AC_GLOBAL;

extern CORE_AC_GLOBAL g_Core;

#if defined(CORE_AC_DEBUG)
#define CORE_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[core_ac] " fmt "\n", __VA_ARGS__)
#else
#define CORE_LOG(fmt, ...) ((void)0)
#endif

__forceinline PVOID CoreAlloc(SIZE_T bytes, ULONG tag)
{
    PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, tag);
    return p;
}

__forceinline VOID CoreFree(PVOID p, ULONG tag)
{
    if (p) ExFreePoolWithTag(p, tag);
}

__forceinline VOID CoreZero(PVOID p, SIZE_T bytes)
{
    RtlSecureZeroMemory(p, bytes);
}

__forceinline ULONG64 CoreBootCookie(VOID)
{
    return g_Core.BootCookie[0] ^ g_Core.BootCookie[1];
}

#define CORE_AC_STATUS_OK                   0x00000000
#define CORE_AC_STATUS_ENV_FAIL             0xC0E10001
#define CORE_AC_STATUS_TAMPER               0xC0E10002
#define CORE_AC_STATUS_BAD_HANDSHAKE        0xC0E10003
#define CORE_AC_STATUS_NO_SESSION           0xC0E10004
#define CORE_AC_STATUS_BUFFER_TOO_SMALL     0xC0E10005
