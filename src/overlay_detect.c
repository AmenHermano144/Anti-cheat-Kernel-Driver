#include "overlay_detect.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"
#include "strings.h"

#define OVL_MAX_PROCS           1024
#define OVL_MAX_PARENT_WALK     16

// window style bits (user32 defines, replicated here for kernel use)
#define OVL_WS_POPUP            0x80000000UL
#define OVL_WS_VISIBLE          0x10000000UL

#define OVL_WS_EX_TOPMOST       0x00000008UL
#define OVL_WS_EX_TRANSPARENT   0x00000020UL
#define OVL_WS_EX_TOOLWINDOW    0x00000080UL
#define OVL_WS_EX_LAYERED       0x00080000UL
#define OVL_WS_EX_NOACTIVATE    0x08000000UL
#define OVL_WS_EX_COMPOSITED    0x02000000UL

typedef struct _OVL_PROC_LINK
{
    BOOLEAN         InUse;
    HANDLE          Pid;
    HANDLE          ParentPid;
} OVL_PROC_LINK, *POVL_PROC_LINK;

static OVL_PROC_LINK g_ProcTable[OVL_MAX_PROCS];
static KSPIN_LOCK    g_TableLock;

static volatile LONG g_Initialized = 0;
static volatile LONG g_OverlayFlag = 0;

// shell/system owners that routinely draw layered + topmost windows
static const CHAR *g_WhitelistShortNames[] =
{
    "dwm.exe",
    "explorer.exe",
    "sihost.exe",
    "ctfmon.exe",
    "TextInputHost.exe",
    "ApplicationFrameHost.exe",
    "StartMenuExperienceHost.exe",
    "ShellExperienceHost.exe",
    "SearchUI.exe",
    "SearchHost.exe",
    "LockApp.exe",
    "RuntimeBroker.exe",
    "SystemSettings.exe",
    "WidgetService.exe",
    "Widgets.exe",
    "winlogon.exe",
    "csrss.exe",
    "fontdrvhost.exe",
    "nvcontainer.exe",
    "NVIDIA Share.exe",
    "NVIDIA Overlay.exe",
    "NVSphHelper64.exe",
    "RtkAudUService64.exe",
    NULL
};

// class name suffixes typical for cheat/overlay frameworks
static const WCHAR *g_SuspiciousClassSuffixes[] =
{
    L"Overlay",
    L"OVERLAY",
    L"ImGui",
    L"ImGui Platform",
    L"CEF-OSC-WIDGET",
    L"Chrome_WidgetWin_0",
    L"Chrome_WidgetWin_1",
    NULL
};

static BOOLEAN TailMatchesInsensitiveW(const WCHAR *path, SIZE_T pathWchars, const WCHAR *suffix)
{
    SIZE_T sLen = CoreStrLenW(suffix);
    if (pathWchars < sLen) return FALSE;
    const WCHAR *tail = path + (pathWchars - sLen);
    for (SIZE_T i = 0; i < sLen; i++)
    {
        WCHAR a = tail[i], b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
        if (a != b) return FALSE;
    }
    return TRUE;
}

static BOOLEAN ClassNameLooksSuspicious(const WCHAR *name, USHORT wchars)
{
    if (!name || wchars == 0) return FALSE;
    for (ULONG i = 0; g_SuspiciousClassSuffixes[i]; i++)
    {
        if (TailMatchesInsensitiveW(name, wchars, g_SuspiciousClassSuffixes[i])) return TRUE;
    }
    return FALSE;
}

static BOOLEAN ShortNameIsWhitelisted(const CHAR *name)
{
    if (!name) return FALSE;
    for (ULONG i = 0; g_WhitelistShortNames[i]; i++)
    {
        if (CoreStrCmpiA(name, g_WhitelistShortNames[i]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN ProcessImageIsWhitelistedByPid(HANDLE pid)
{
    if (!pid) return FALSE;
    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &proc)) || !proc) return FALSE;

    const CHAR *name = PsGetProcessImageFileName(proc);
    BOOLEAN hit = ShortNameIsWhitelisted(name);
    ObDereferenceObject(proc);
    return hit;
}

static HANDLE LookupParentLocked(HANDLE pid)
{
    for (ULONG i = 0; i < OVL_MAX_PROCS; i++)
    {
        if (g_ProcTable[i].InUse && g_ProcTable[i].Pid == pid)
        {
            return g_ProcTable[i].ParentPid;
        }
    }
    return NULL;
}

static HANDLE LookupParent(HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_TableLock, &irql);
    HANDLE parent = LookupParentLocked(pid);
    KeReleaseSpinLock(&g_TableLock, irql);
    return parent;
}

static BOOLEAN HasWhitelistedAncestor(HANDLE pid, ULONG maxWalk)
{
    HANDLE cursor = pid;
    for (ULONG i = 0; i < maxWalk; i++)
    {
        if (ProcessImageIsWhitelistedByPid(cursor)) return TRUE;
        HANDLE parent = LookupParent(cursor);
        if (!parent || parent == cursor) return FALSE;
        cursor = parent;
    }
    return FALSE;
}

NTSTATUS OverlayDetectInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    KeInitializeSpinLock(&g_TableLock);
    RtlZeroMemory(g_ProcTable, sizeof(g_ProcTable));
    InterlockedExchange(&g_OverlayFlag, 0);
    return STATUS_SUCCESS;
}

VOID OverlayDetectShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);

    KIRQL irql;
    KeAcquireSpinLock(&g_TableLock, &irql);
    RtlZeroMemory(g_ProcTable, sizeof(g_ProcTable));
    KeReleaseSpinLock(&g_TableLock, irql);

    InterlockedExchange(&g_OverlayFlag, 0);
}

VOID OverlayDetectOnProcessCreate(HANDLE pid, HANDLE parentPid)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    if (!pid) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_TableLock, &irql);

    LONG freeSlot = -1;
    for (ULONG i = 0; i < OVL_MAX_PROCS; i++)
    {
        if (g_ProcTable[i].InUse && g_ProcTable[i].Pid == pid)
        {
            g_ProcTable[i].ParentPid = parentPid;
            KeReleaseSpinLock(&g_TableLock, irql);
            return;
        }
        if (!g_ProcTable[i].InUse && freeSlot < 0) freeSlot = (LONG)i;
    }

    if (freeSlot >= 0)
    {
        g_ProcTable[freeSlot].InUse = TRUE;
        g_ProcTable[freeSlot].Pid = pid;
        g_ProcTable[freeSlot].ParentPid = parentPid;
    }

    KeReleaseSpinLock(&g_TableLock, irql);
}

VOID OverlayDetectOnProcessExit(HANDLE pid)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    if (!pid) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_TableLock, &irql);
    for (ULONG i = 0; i < OVL_MAX_PROCS; i++)
    {
        if (g_ProcTable[i].InUse && g_ProcTable[i].Pid == pid)
        {
            g_ProcTable[i].InUse = FALSE;
            g_ProcTable[i].Pid = NULL;
            g_ProcTable[i].ParentPid = NULL;
            break;
        }
    }
    KeReleaseSpinLock(&g_TableLock, irql);
}

static ULONG ParseStyleFlags(const OVERLAY_WINDOW_REPORT *rec)
{
    ULONG f = 0;
    if (rec->ExStyle & OVL_WS_EX_LAYERED)     f |= OVERLAY_FLAG_LAYERED;
    if (rec->ExStyle & OVL_WS_EX_TRANSPARENT) f |= OVERLAY_FLAG_TRANSPARENT;
    if (rec->ExStyle & OVL_WS_EX_TOPMOST)     f |= OVERLAY_FLAG_TOPMOST;
    if (rec->ExStyle & OVL_WS_EX_NOACTIVATE)  f |= OVERLAY_FLAG_NOACTIVATE;
    if (rec->ExStyle & OVL_WS_EX_TOOLWINDOW)  f |= OVERLAY_FLAG_TOOLWINDOW;
    if (rec->ExStyle & OVL_WS_EX_COMPOSITED)  f |= OVERLAY_FLAG_COMPOSITED;
    if (rec->Style   & OVL_WS_POPUP)          f |= OVERLAY_FLAG_POPUP;

    if ((f & (OVERLAY_FLAG_LAYERED | OVERLAY_FLAG_TRANSPARENT)) ==
        (OVERLAY_FLAG_LAYERED | OVERLAY_FLAG_TRANSPARENT))
    {
        f |= OVERLAY_FLAG_CLICKTHROUGH_COMBO;
    }
    return f;
}

static BOOLEAN LooksOverlayShaped(ULONG flags)
{
    if (flags & OVERLAY_FLAG_CLICKTHROUGH_COMBO) return TRUE;
    const ULONG topmostBag =
        OVERLAY_FLAG_TOPMOST | OVERLAY_FLAG_NOACTIVATE | OVERLAY_FLAG_TOOLWINDOW | OVERLAY_FLAG_POPUP;
    ULONG hits = 0;
    if (flags & OVERLAY_FLAG_TOPMOST)    hits++;
    if (flags & OVERLAY_FLAG_NOACTIVATE) hits++;
    if (flags & OVERLAY_FLAG_TOOLWINDOW) hits++;
    if (flags & OVERLAY_FLAG_LAYERED)    hits++;
    if (flags & OVERLAY_FLAG_POPUP)      hits++;
    (VOID)topmostBag;
    return hits >= 3;
}

NTSTATUS OverlayDetectEvaluateReport(const OVERLAY_WINDOW_REPORT *rec)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (!rec || !rec->ProcessId) return STATUS_INVALID_PARAMETER;

    ULONG flags = ParseStyleFlags(rec);
    if (!LooksOverlayShaped(flags)) return STATUS_SUCCESS;

    HANDLE ownerPid = (HANDLE)(ULONG_PTR)rec->ProcessId;

    if (ProcessImageIsWhitelistedByPid(ownerPid)) return STATUS_SUCCESS;

    if (rec->ClassNameBytes > 0)
    {
        USHORT wchars = rec->ClassNameBytes / sizeof(WCHAR);
        if (wchars > RTL_NUMBER_OF(rec->ClassName)) wchars = (USHORT)RTL_NUMBER_OF(rec->ClassName);
        if (ClassNameLooksSuspicious(rec->ClassName, wchars))
        {
            flags |= OVERLAY_FLAG_KNOWN_CLASS;
        }
    }

    HANDLE parent = LookupParent(ownerPid);
    if (!parent) flags |= OVERLAY_FLAG_FOREIGN_PARENT;

    if (!HasWhitelistedAncestor(ownerPid, OVL_MAX_PARENT_WALK))
    {
        flags |= OVERLAY_FLAG_UNRELATED_PROCESS;
    }

    BOOLEAN suspicious = FALSE;

    if ((flags & OVERLAY_FLAG_CLICKTHROUGH_COMBO) &&
        (flags & (OVERLAY_FLAG_NOACTIVATE | OVERLAY_FLAG_TOOLWINDOW | OVERLAY_FLAG_TOPMOST)))
    {
        suspicious = TRUE;
    }
    if ((flags & OVERLAY_FLAG_CLICKTHROUGH_COMBO) &&
        (flags & OVERLAY_FLAG_UNRELATED_PROCESS))
    {
        suspicious = TRUE;
    }
    if (flags & OVERLAY_FLAG_KNOWN_CLASS)
    {
        suspicious = TRUE;
    }

    if (!suspicious) return STATUS_SUCCESS;

    flags |= OVERLAY_FLAG_SUSPICIOUS;
    InterlockedOr(&g_OverlayFlag, (LONG)flags);

    WIRE_OVERLAY_DETECT wrec;
    RtlZeroMemory(&wrec, sizeof(wrec));
    wrec.ProcessId = rec->ProcessId;
    wrec.ParentProcessId = (ULONG64)(ULONG_PTR)parent;
    wrec.WindowHandle = rec->WindowHandle;
    wrec.Style = rec->Style;
    wrec.ExStyle = rec->ExStyle;
    wrec.DetectFlags = flags;

    USHORT classBytes = rec->ClassNameBytes;
    if (classBytes > sizeof(wrec.ClassName)) classBytes = sizeof(wrec.ClassName);
    wrec.ClassNameLen = classBytes;
    if (classBytes) RtlCopyMemory(wrec.ClassName, rec->ClassName, classBytes);

    USHORT titleBytes = rec->TitleBytes;
    if (titleBytes > sizeof(wrec.Title)) titleBytes = sizeof(wrec.Title);
    wrec.TitleLen = titleBytes;
    if (titleBytes) RtlCopyMemory(wrec.Title, rec->Title, titleBytes);

    (VOID)EventsReportOverlay(&wrec);
    (VOID)EventsReportTamper(AC_TAMPER_REASON_OVERLAY, (PVOID)(ULONG_PTR)ownerPid);

    return STATUS_SUCCESS;
}

ULONG OverlayDetectGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_OverlayFlag, 0, 0);
}

VOID OverlayDetectClearFlag(VOID)
{
    InterlockedExchange(&g_OverlayFlag, 0);
}
