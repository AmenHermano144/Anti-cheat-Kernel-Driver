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

static CI_VALIDATE_FILE_OBJECT_SIG g_CiShim;

NTSTATUS GameIntegrityInit(VOID)
{
    RtlZeroMemory(&g_CiShim, sizeof(g_CiShim));
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"CiValidateFileObject");
    g_CiShim.CiValidateFileObject = (CI_VALIDATE_FILE_OBJECT_FN)MmGetSystemRoutineAddress(&name);
    return STATUS_SUCCESS;
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
        (VOID)Pml4RegisterGameProcessByPid(ProcessId);
    }

    return STATUS_SUCCESS;
}
