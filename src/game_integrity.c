#include "game_integrity.h"
#include "crypto.h"
#include "channels.h"
#include "wire_records.h"
#include "strings.h"
#include "events.h"
#include "pml4_scan.h"

typedef NTSTATUS (NTAPI *CI_VALIDATE_FILE_OBJECT_FN)(
    PFILE_OBJECT FileObject,
    ULONG Arg2,
    ULONG Arg3,
    PVOID Arg4,
    PVOID Arg5,
    PVOID Arg6,
    PVOID Arg7);

typedef struct _CI_VALIDATE_FILE_OBJECT_SIG
{
    CI_VALIDATE_FILE_OBJECT_FN CiValidateFileObject;
} CI_VALIDATE_FILE_OBJECT_SIG, *PCI_VALIDATE_FILE_OBJECT_SIG;

typedef struct _GAME_PROTECTED_ENTRY
{
    volatile LONG   InUse;
    HANDLE          Pid;
    USHORT          DirLen;
    WCHAR           ImageDir[GAME_INTG_PATH_WCHARS];
} GAME_PROTECTED_ENTRY, *PGAME_PROTECTED_ENTRY;

static CI_VALIDATE_FILE_OBJECT_SIG g_CiShim;
static GAME_PROTECTED_ENTRY        g_Protected[GAME_INTG_MAX_PROTECTED];
static KSPIN_LOCK                  g_ProtectedLock;
static volatile LONG               g_ProtectedInit = 0;

static VOID EnsureProtectedInit(VOID)
{
    if (InterlockedCompareExchange(&g_ProtectedInit, 1, 0) == 0)
    {
        KeInitializeSpinLock(&g_ProtectedLock);
        RtlZeroMemory(g_Protected, sizeof(g_Protected));
    }
}

NTSTATUS GameIntegrityInit(VOID)
{
    EnsureProtectedInit();
    RtlZeroMemory(&g_CiShim, sizeof(g_CiShim));
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"CiValidateFileObject");
    g_CiShim.CiValidateFileObject = (CI_VALIDATE_FILE_OBJECT_FN)MmGetSystemRoutineAddress(&name);
    return STATUS_SUCCESS;
}

VOID GameIntegrityShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_ProtectedInit, 0, 0)) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ProtectedLock, &irql);
    RtlZeroMemory(g_Protected, sizeof(g_Protected));
    KeReleaseSpinLock(&g_ProtectedLock, irql);
}

BOOLEAN GameIntegrityVerifyPeHeader(const UCHAR *imageBase, SIZE_T imageSize)
{
    if (!imageBase || imageSize < 0x400) return FALSE;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
        LONG off = dos->e_lfanew;
        if (off < 0 || (SIZE_T)off + sizeof(IMAGE_NT_HEADERS64) > imageSize) return FALSE;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(imageBase + off);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return FALSE;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOLEAN PathMatchesWatchedProcess(PUNICODE_STRING fullImageName)
{
    if (!fullImageName || !fullImageName->Buffer) return FALSE;
    SIZE_T wlen = fullImageName->Length / sizeof(WCHAR);
    return ChannelBlobEqualsW(CHANNEL_BLOB_PROCESS, fullImageName->Buffer, wlen);
}

static USHORT ExtractImageDirectory(PUNICODE_STRING fullImageName,
                                    WCHAR *outDir, SIZE_T outCapWchars)
{
    if (!fullImageName || !fullImageName->Buffer || outCapWchars == 0) return 0;

    SIZE_T wlen = fullImageName->Length / sizeof(WCHAR);
    const WCHAR *buf = fullImageName->Buffer;
    SIZE_T lastSep = 0;
    BOOLEAN found = FALSE;
    for (SIZE_T i = 0; i < wlen; i++)
    {
        if (buf[i] == L'\\' || buf[i] == L'/')
        {
            lastSep = i;
            found = TRUE;
        }
    }
    if (!found) return 0;

    SIZE_T copyLen = lastSep + 1;
    if (copyLen > outCapWchars - 1) copyLen = outCapWchars - 1;
    for (SIZE_T i = 0; i < copyLen; i++) outDir[i] = buf[i];
    outDir[copyLen] = 0;
    return (USHORT)copyLen;
}

static VOID RegisterProtectedPid(HANDLE pid, PUNICODE_STRING fullImageName)
{
    EnsureProtectedInit();

    KIRQL irql;
    KeAcquireSpinLock(&g_ProtectedLock, &irql);

    LONG slot = -1;
    for (ULONG i = 0; i < GAME_INTG_MAX_PROTECTED; i++)
    {
        if (g_Protected[i].InUse && g_Protected[i].Pid == pid) { slot = (LONG)i; break; }
    }
    if (slot < 0)
    {
        for (ULONG i = 0; i < GAME_INTG_MAX_PROTECTED; i++)
        {
            if (!g_Protected[i].InUse) { slot = (LONG)i; break; }
        }
    }
    if (slot < 0)
    {
        KeReleaseSpinLock(&g_ProtectedLock, irql);
        return;
    }

    PGAME_PROTECTED_ENTRY e = &g_Protected[slot];
    RtlZeroMemory(e, sizeof(*e));
    e->Pid = pid;
    e->DirLen = ExtractImageDirectory(fullImageName, e->ImageDir, GAME_INTG_PATH_WCHARS);
    InterlockedExchange(&e->InUse, 1);

    KeReleaseSpinLock(&g_ProtectedLock, irql);
}

BOOLEAN GameIntegrityIsProtectedPid(HANDLE pid)
{
    if (!pid) return FALSE;
    if (!InterlockedCompareExchange(&g_ProtectedInit, 0, 0)) return FALSE;

    BOOLEAN hit = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_ProtectedLock, &irql);
    for (ULONG i = 0; i < GAME_INTG_MAX_PROTECTED; i++)
    {
        if (g_Protected[i].InUse && g_Protected[i].Pid == pid) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_ProtectedLock, irql);
    return hit;
}

VOID GameIntegrityOnProcessExit(HANDLE pid)
{
    if (!pid) return;
    if (!InterlockedCompareExchange(&g_ProtectedInit, 0, 0)) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_ProtectedLock, &irql);
    for (ULONG i = 0; i < GAME_INTG_MAX_PROTECTED; i++)
    {
        if (g_Protected[i].InUse && g_Protected[i].Pid == pid)
        {
            RtlZeroMemory(&g_Protected[i], sizeof(g_Protected[i]));
            break;
        }
    }
    KeReleaseSpinLock(&g_ProtectedLock, irql);
}

BOOLEAN GameIntegrityGetProtectedImageDir(HANDLE pid, WCHAR *outDir, SIZE_T outCapWchars)
{
    if (!pid || !outDir || outCapWchars == 0) return FALSE;
    if (!InterlockedCompareExchange(&g_ProtectedInit, 0, 0)) return FALSE;

    BOOLEAN hit = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_ProtectedLock, &irql);
    for (ULONG i = 0; i < GAME_INTG_MAX_PROTECTED; i++)
    {
        if (g_Protected[i].InUse && g_Protected[i].Pid == pid)
        {
            USHORT dl = g_Protected[i].DirLen;
            if (dl > outCapWchars - 1) dl = (USHORT)(outCapWchars - 1);
            for (USHORT j = 0; j < dl; j++) outDir[j] = g_Protected[i].ImageDir[j];
            outDir[dl] = 0;
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ProtectedLock, irql);
    return hit;
}

NTSTATUS GameIntegrityOnUserImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo) return STATUS_SUCCESS;

    WIRE_IMAGE_LOAD rec;
    RtlZeroMemory(&rec, sizeof(rec));
    rec.ProcessId = (ULONG64)(ULONG_PTR)ProcessId;
    rec.ImageBase = (ULONG64)ImageInfo->ImageBase;
    rec.ImageSize = (ULONG)ImageInfo->ImageSize;
    rec.SystemImage = (UCHAR)(ImageInfo->SystemModeImage ? 1 : 0);

    USHORT nb = FullImageName->Length;
    if (nb > sizeof(rec.ImagePath)) nb = sizeof(rec.ImagePath);
    rec.ImagePathLen = nb;
    RtlCopyMemory(rec.ImagePath, FullImageName->Buffer, nb);
    (VOID)ChannelEnqueueRecord(WIRE_REC_IMAGE_LOAD, &rec, sizeof(rec));

    if (ImageInfo->ExtendedInfoPresent && g_CiShim.CiValidateFileObject)
    {
        PIMAGE_INFO_EX ex = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
        if (ex->FileObject)
        {
            NTSTATUS vs = STATUS_SUCCESS;
            __try
            {
                vs = g_CiShim.CiValidateFileObject(ex->FileObject, 0, 0, NULL, NULL, NULL, NULL);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                vs = GetExceptionCode();
            }
            if (!NT_SUCCESS(vs))
            {
                (VOID)EventsReportSignatureReject(ProcessId, (ULONG64)ImageInfo->ImageBase,
                                                  vs, FullImageName->Buffer, nb);
            }
        }
    }

    if (PathMatchesWatchedProcess(FullImageName))
    {
        RegisterProtectedPid(ProcessId, FullImageName);
        (VOID)Pml4RegisterGameProcessByPid(ProcessId);
    }

    return STATUS_SUCCESS;
}
