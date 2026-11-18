#include <ntddk.h>

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
