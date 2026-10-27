#include "hook_audit.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "strings.h"
#include "game_integrity.h"

#define HOOK_PROCESS_STRIP_MASK   (0x0001u | 0x0002u | 0x0008u | 0x0020u | 0x0040u | 0x0200u | 0x0800u)
#define HOOK_THREAD_STRIP_MASK    (0x0001u | 0x0002u | 0x0010u | 0x0020u | 0x0080u | 0x0100u | 0x0200u)

#define KUSER_SHARED_SYSTEMTIME   0xFFFFF78000000014ULL

static volatile LONG  g_Initialized   = 0;
static volatile LONG  g_CbRegistered  = 0;
static PVOID          g_ObRegHandle   = NULL;
static volatile LONG  g_ThreadNotifyArmed = 0;


static VOID FillCallerImage(PEPROCESS caller, WIRE_HOOK_AUDIT *rec)
{
    PUNICODE_STRING name = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(caller, &name)) && name && name->Buffer)
    {
        USHORT nb = name->Length;
        if (nb > sizeof(rec->CallerImagePath)) nb = sizeof(rec->CallerImagePath);
        rec->CallerImagePathLen = nb;
        RtlCopyMemory(rec->CallerImagePath, name->Buffer, nb);
    }
    if (name) ExFreePool(name);
}

static VOID FillCallerImageHandle(PEPROCESS caller, WIRE_HANDLE_AUDIT *rec)
{
    PUNICODE_STRING name = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(caller, &name)) && name && name->Buffer)
    {
        USHORT nb = name->Length;
        if (nb > sizeof(rec->CallerImagePath)) nb = sizeof(rec->CallerImagePath);
        rec->CallerImagePathLen = nb;
        RtlCopyMemory(rec->CallerImagePath, name->Buffer, nb);
    }
    if (name) ExFreePool(name);
}

static ULONG64 ReadSharedSystemTime(VOID)
{
    __try
    {
        return *(volatile ULONG64 *)KUSER_SHARED_SYSTEMTIME;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LARGE_INTEGER t;
        KeQuerySystemTimePrecise(&t);
        return (ULONG64)t.QuadPart;
    }
}

static VOID ThreadNotifyCb(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (!Create) return;
    if (!GameIntegrityIsProtectedPid(ProcessId)) return;

    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == ProcessId) return;

    PEPROCESS caller = PsGetCurrentProcess();
    const CHAR *targetImgA = NULL;

    PEPROCESS target = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &target)) && target)
    {
        targetImgA = PsGetProcessImageFileName(target);
    }

    WIRE_HOOK_AUDIT rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.Operation = WIRE_HOOK_OP_REMOTE_THREAD;
    rec.DecisionFlags = WIRE_HOOK_FLAG_CROSS_PROC;
    rec.TargetProcessId = (ULONG64)(ULONG_PTR)ProcessId;
    rec.CallerProcessId = (ULONG64)(ULONG_PTR)callerPid;
    rec.CallerThreadId = (ULONG64)(ULONG_PTR)ThreadId;
    rec.SystemTime = ReadSharedSystemTime();
    FillCallerImage(caller, &rec);

    if (targetImgA)
    {
        for (ULONG i = 0; i < sizeof(rec.TargetImageName) - 1 && targetImgA[i]; i++)
        {
            rec.TargetImageName[i] = (UCHAR)targetImgA[i];
        }
    }

    (VOID)EventsReportHookAudit(&rec);
    (VOID)EventsReportTamper(AC_TAMPER_REASON_REMOTE_THREAD, (PVOID)(ULONG_PTR)callerPid);

    if (target) ObDereferenceObject(target);
}

static BOOLEAN ShouldStripForProcess(PEPROCESS caller, PEPROCESS target)
{
    if (!caller || !target) return FALSE;
    if (caller == target) return FALSE;
    HANDLE pid = PsGetProcessId(target);
    return GameIntegrityIsProtectedPid(pid);
}

static OB_PREOP_CALLBACK_STATUS ObjectPreCallback(PVOID RegistrationContext,
                                                  POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!Info || Info->KernelHandle) return OB_PREOP_SUCCESS;

    PEPROCESS caller = PsGetCurrentProcess();
    PEPROCESS target = NULL;
    BOOLEAN isThread = FALSE;
    ACCESS_MASK stripMask = 0;

    if (Info->ObjectType == *PsProcessType)
    {
        target = (PEPROCESS)Info->Object;
        stripMask = HOOK_PROCESS_STRIP_MASK;
    }
    else if (Info->ObjectType == *PsThreadType)
    {
        target = IoThreadToProcess((PETHREAD)Info->Object);
        isThread = TRUE;
        stripMask = HOOK_THREAD_STRIP_MASK;
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    if (!ShouldStripForProcess(caller, target)) return OB_PREOP_SUCCESS;

    ACCESS_MASK *desired;
    ACCESS_MASK  original;
    ULONG        flagBits = 0;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
        original = Info->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }
    else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
    {
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        original = Info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        flagBits |= WIRE_HANDLE_FLAG_DUP;
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK stripped = (*desired) & stripMask;
    if (stripped == 0) return OB_PREOP_SUCCESS;

    *desired &= ~stripMask;

    HANDLE callerPid = PsGetProcessId(caller);
    HANDLE targetPid = PsGetProcessId(target);

    WIRE_HANDLE_AUDIT hrec;
    RtlZeroMemory(&hrec, sizeof(hrec));
    hrec.CallerProcessId = (ULONG64)(ULONG_PTR)callerPid;
    hrec.TargetProcessId = (ULONG64)(ULONG_PTR)targetPid;
    hrec.OriginalAccess = (ULONG)original;
    hrec.StrippedAccess = (ULONG)stripped;
    hrec.Flags = flagBits | (isThread ? WIRE_HANDLE_FLAG_THREAD : 0);
    FillCallerImageHandle(caller, &hrec);

    (VOID)EventsReportHandleAudit(&hrec);

    WIRE_HOOK_AUDIT hk;
    RtlZeroMemory(&hk, sizeof(hk));
    hk.Operation = WIRE_HOOK_OP_HANDLE_STRIP;
    hk.DecisionFlags = WIRE_HOOK_FLAG_STRIPPED | WIRE_HOOK_FLAG_CROSS_PROC;
    hk.TargetProcessId = (ULONG64)(ULONG_PTR)targetPid;
    hk.CallerProcessId = (ULONG64)(ULONG_PTR)callerPid;
    hk.SuspectAddress = (ULONG64)stripped;
    hk.SystemTime = ReadSharedSystemTime();
    FillCallerImage(caller, &hk);

    const CHAR *targetImgA = PsGetProcessImageFileName(target);
    if (targetImgA)
    {
        for (ULONG i = 0; i < sizeof(hk.TargetImageName) - 1 && targetImgA[i]; i++)
        {
            hk.TargetImageName[i] = (UCHAR)targetImgA[i];
        }
    }
    (VOID)EventsReportHookAudit(&hk);
    (VOID)EventsReportTamper(AC_TAMPER_REASON_HANDLE_STRIP, (PVOID)(ULONG_PTR)callerPid);

    return OB_PREOP_SUCCESS;
}

NTSTATUS HookAuditInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    g_ObRegHandle = NULL;
    InterlockedExchange(&g_CbRegistered, 0);
    InterlockedExchange(&g_ThreadNotifyArmed, 0);
    return STATUS_SUCCESS;
}

VOID HookAuditShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    HookAuditUnregisterCallbacks();
    InterlockedExchange(&g_Initialized, 0);
}

NTSTATUS HookAuditRegisterCallbacks(VOID)
{
    if (InterlockedCompareExchange(&g_CbRegistered, 1, 0) != 0) return STATUS_SUCCESS;

    NTSTATUS status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCb);
    if (NT_SUCCESS(status))
    {
        InterlockedExchange(&g_ThreadNotifyArmed, 1);
    }

    OB_OPERATION_REGISTRATION ops[2];
    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = ObjectPreCallback;
    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = ObjectPreCallback;

    OB_CALLBACK_REGISTRATION reg;
    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.OperationRegistration = ops;
    reg.RegistrationContext = NULL;
    RtlInitUnicodeString(&reg.Altitude, L"320800.4210");

    NTSTATUS obs = ObRegisterCallbacks(&reg, &g_ObRegHandle);
    if (!NT_SUCCESS(obs))
    {
        g_ObRegHandle = NULL;
        CORE_LOG("ObRegisterCallbacks failed: 0x%08X", obs);
    }

    if (NT_SUCCESS(status) || NT_SUCCESS(obs)) return STATUS_SUCCESS;
    InterlockedExchange(&g_CbRegistered, 0);
    return status;
}

VOID HookAuditUnregisterCallbacks(VOID)
{
    if (!InterlockedCompareExchange(&g_CbRegistered, 0, 0)) return;

    if (g_ObRegHandle)
    {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }
    if (InterlockedCompareExchange(&g_ThreadNotifyArmed, 0, 0))
    {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCb);
        InterlockedExchange(&g_ThreadNotifyArmed, 0);
    }
    InterlockedExchange(&g_CbRegistered, 0);
}

static BOOLEAN WLowerEq(WCHAR a, WCHAR b)
{
    if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
    if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
    return a == b;
}

static BOOLEAN WContainsI(const WCHAR *hay, SIZE_T hayLen, const WCHAR *needle)
{
    SIZE_T nlen = CoreStrLenW(needle);
    if (nlen == 0 || hayLen < nlen) return FALSE;
    for (SIZE_T i = 0; i + nlen <= hayLen; i++)
    {
        BOOLEAN ok = TRUE;
        for (SIZE_T j = 0; j < nlen; j++)
        {
            if (!WLowerEq(hay[i + j], needle[j])) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

static const WCHAR *g_SystemFragments[] = {
    L"\\windows\\system32\\",
    L"\\windows\\syswow64\\",
    L"\\windows\\winsxs\\",
    L"\\windows\\assembly\\",
    L"\\windows\\microsoft.net\\",
};

static const WCHAR *g_SuspectSubstrings[] = {
    L"hook",
    L"inject",
    L"overlay",
    L"cheat",
    L"aimbot",
    L"wallhack",
    L"meeseeks",
    L"snusbase",
};

static BOOLEAN IsSystemBackedPath(const WCHAR *buf, SIZE_T wlen)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_SystemFragments); i++)
    {
        if (WContainsI(buf, wlen, g_SystemFragments[i])) return TRUE;
    }
    return FALSE;
}

static BOOLEAN HasSuspectSubstring(const WCHAR *buf, SIZE_T wlen, ULONG *outIndex)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_SuspectSubstrings); i++)
    {
        if (WContainsI(buf, wlen, g_SuspectSubstrings[i])) { *outIndex = i; return TRUE; }
    }
    return FALSE;
}

static BOOLEAN PathUnderDir(const WCHAR *path, SIZE_T pathLen, const WCHAR *dir)
{
    SIZE_T dlen = CoreStrLenW(dir);
    if (dlen == 0 || pathLen < dlen) return FALSE;
    for (SIZE_T i = 0; i < dlen; i++)
    {
        if (!WLowerEq(path[i], dir[i])) return FALSE;
    }
    return TRUE;
}

NTSTATUS HookAuditOnUserImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !FullImageName->Buffer || !ImageInfo) return STATUS_SUCCESS;
    if (!GameIntegrityIsProtectedPid(ProcessId)) return STATUS_SUCCESS;

    SIZE_T wlen = FullImageName->Length / sizeof(WCHAR);
    const WCHAR *buf = FullImageName->Buffer;

    BOOLEAN sysBacked = IsSystemBackedPath(buf, wlen);
    ULONG matchIdx = 0;
    BOOLEAN nameMatch = HasSuspectSubstring(buf, wlen, &matchIdx);

    WCHAR gameDir[GAME_INTG_PATH_WCHARS];
    gameDir[0] = 0;
    BOOLEAN hasDir = GameIntegrityGetProtectedImageDir(ProcessId, gameDir, GAME_INTG_PATH_WCHARS);
    BOOLEAN underGameDir = FALSE;
    if (hasDir && gameDir[0]) underGameDir = PathUnderDir(buf, wlen, gameDir);

    BOOLEAN unsigned_ = (ImageInfo->ImageSignatureLevel == 0 &&
                         ImageInfo->ImageSignatureType  == 0);

    if (sysBacked && !nameMatch && !unsigned_) return STATUS_SUCCESS;
    if (underGameDir && !nameMatch) return STATUS_SUCCESS;

    USHORT flags = WIRE_HOOK_FLAG_CROSS_PROC;
    if (unsigned_)  flags |= WIRE_HOOK_FLAG_UNSIGNED;
    if (nameMatch)  flags |= WIRE_HOOK_FLAG_NAME_MATCH;
    if (!sysBacked && !underGameDir) flags |= WIRE_HOOK_FLAG_FOREIGN_DIR;

    if (!(flags & (WIRE_HOOK_FLAG_UNSIGNED | WIRE_HOOK_FLAG_NAME_MATCH | WIRE_HOOK_FLAG_FOREIGN_DIR)))
    {
        return STATUS_SUCCESS;
    }

    WIRE_HOOK_AUDIT rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.Operation = WIRE_HOOK_OP_PARASITE_DLL;
    rec.DecisionFlags = flags;
    rec.TargetProcessId = (ULONG64)(ULONG_PTR)ProcessId;
    rec.CallerProcessId = (ULONG64)(ULONG_PTR)PsGetCurrentProcessId();
    rec.CallerThreadId = 0;
    rec.SuspectAddress = (ULONG64)ImageInfo->ImageBase;
    rec.SystemTime = ReadSharedSystemTime();
    FillCallerImage(PsGetCurrentProcess(), &rec);

    USHORT nb = FullImageName->Length;
    if (nb > sizeof(rec.TargetImagePath)) nb = sizeof(rec.TargetImagePath);
    rec.TargetImagePathLen = nb;
    RtlCopyMemory(rec.TargetImagePath, buf, nb);

    (VOID)EventsReportHookAudit(&rec);
    (VOID)EventsReportTamper(AC_TAMPER_REASON_HOOK_INJECT, (PVOID)(ULONG_PTR)ImageInfo->ImageBase);

    return STATUS_SUCCESS;
}
