#include "ac_anchor.h"
#include "anti_tamper.h"

typedef struct _FLT_REGISTRATION FLT_REGISTRATION, *PFLT_REGISTRATION;
typedef struct _FLT_FILTER       FLT_FILTER,       *PFLT_FILTER;

__declspec(dllimport)
NTSTATUS NTAPI FltRegisterFilter(
    PDRIVER_OBJECT      Driver,
    const FLT_REGISTRATION *Registration,
    PFLT_FILTER        *RetFilter);

// decoy anchor. the address is referenced at link time so the linker keeps
// the fltmgr import, which forces fltmgr.sys to be resident before we load.
// runtime never enters the function. an analyst grepping the IAT for anything
// interesting sees exactly this one symbol and nothing else.
volatile PVOID g_FltMgrAnchor = (PVOID)(ULONG_PTR)&FltRegisterFilter;

typedef struct _CORE_KLDR_ENTRY_MIN
{
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
} CORE_KLDR_ENTRY_MIN, *PCORE_KLDR_ENTRY_MIN;

static volatile LONG g_AnchorReady = 0;

NTSTATUS AcAnchorInit(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject) return STATUS_INVALID_PARAMETER;

    // DriverObject->DriverStart / DriverSize are the authoritative bounds for
    // our own image. taking them here ties the anchor to whatever the loader
    // actually mapped, which is what _ReturnAddress() will land in.
    g_Core.DriverStart = (ULONG_PTR)DriverObject->DriverStart;
    g_Core.DriverSize  = DriverObject->DriverSize;

    if (!g_Core.DriverStart || !g_Core.DriverSize)
    {
        // some loaders zero-fill DriverStart/Size. fall back to walking the
        // kldr entry attached to DriverSection.
        if (DriverObject->DriverSection)
        {
            PCORE_KLDR_ENTRY_MIN e = (PCORE_KLDR_ENTRY_MIN)DriverObject->DriverSection;
            g_Core.DriverStart = (ULONG_PTR)e->DllBase;
            g_Core.DriverSize  = e->SizeOfImage;
        }
    }

    if (!g_Core.DriverStart || !g_Core.DriverSize) return STATUS_NOT_FOUND;

    InterlockedExchange(&g_AnchorReady, 1);
    return STATUS_SUCCESS;
}

BOOLEAN AcAnchorIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_AnchorReady, 0, 0) ? TRUE : FALSE;
}

ULONG_PTR AcAnchorImageStart(VOID) { return g_Core.DriverStart; }
ULONG     AcAnchorImageSize(VOID)  { return g_Core.DriverSize; }

BOOLEAN AcAnchorCheckRip(ULONG_PTR rip)
{
    if (!InterlockedCompareExchange(&g_AnchorReady, 0, 0)) return TRUE;
    if (!rip) return FALSE;

    ULONG_PTR start = g_Core.DriverStart;
    ULONG     size  = g_Core.DriverSize;
    if (!start || !size) return TRUE;

    ULONG_PTR end = start + size;
    if (end < start) return FALSE;

    return (rip >= start && rip < end) ? TRUE : FALSE;
}

BOOLEAN AcAnchorCheckCallerRip(VOID)
{
    // _ReturnAddress() is the RIP inside our own function's return site, which
    // sits inside our own image. we want the CALLER of this check — that is,
    // the function that invoked us, which lives in the parent frame. the WDK
    // doesn't give us a reliable kernel-mode stack walker without PerfLib, so
    // the useful observable is really "did someone redirect the call-site
    // stub out of our image?" and for that _ReturnAddress() is enough: if
    // execution goes through a relocated thunk, the return address will no
    // longer sit in our .text.
    ULONG_PTR ra = (ULONG_PTR)_ReturnAddress();
    return AcAnchorCheckRip(ra);
}
