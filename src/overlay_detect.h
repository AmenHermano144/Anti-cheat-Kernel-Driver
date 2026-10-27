#pragma once

#include "core.h"

#define OVERLAY_FLAG_NONE                 0x00000000
#define OVERLAY_FLAG_LAYERED              0x00000001
#define OVERLAY_FLAG_TRANSPARENT          0x00000002
#define OVERLAY_FLAG_TOPMOST              0x00000004
#define OVERLAY_FLAG_NOACTIVATE           0x00000008
#define OVERLAY_FLAG_TOOLWINDOW           0x00000010
#define OVERLAY_FLAG_COMPOSITED           0x00000020
#define OVERLAY_FLAG_POPUP                0x00000040
#define OVERLAY_FLAG_CLICKTHROUGH_COMBO   0x00000100
#define OVERLAY_FLAG_UNRELATED_PROCESS    0x00000200
#define OVERLAY_FLAG_FOREIGN_PARENT       0x00000400
#define OVERLAY_FLAG_KNOWN_CLASS          0x00000800
#define OVERLAY_FLAG_SUSPICIOUS           0x00001000

typedef struct _OVERLAY_WINDOW_REPORT
{
    ULONG64 ProcessId;
    ULONG64 ThreadId;
    ULONG64 WindowHandle;
    ULONG   Style;
    ULONG   ExStyle;
    USHORT  ClassNameBytes;
    USHORT  TitleBytes;
    WCHAR   ClassName[64];
    WCHAR   Title[128];
} OVERLAY_WINDOW_REPORT, *POVERLAY_WINDOW_REPORT;

NTSTATUS OverlayDetectInit(VOID);
VOID     OverlayDetectShutdown(VOID);

VOID     OverlayDetectOnProcessCreate(HANDLE pid, HANDLE parentPid);
VOID     OverlayDetectOnProcessExit(HANDLE pid);

NTSTATUS OverlayDetectEvaluateReport(const OVERLAY_WINDOW_REPORT *rec);

ULONG    OverlayDetectGetFlag(VOID);
VOID     OverlayDetectClearFlag(VOID);
