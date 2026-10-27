#pragma once

#include "core.h"

#define GAME_INTG_MAX_PROTECTED  8
#define GAME_INTG_PATH_WCHARS    260

NTSTATUS GameIntegrityInit(VOID);
VOID     GameIntegrityShutdown(VOID);

NTSTATUS GameIntegrityOnUserImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo);
BOOLEAN  GameIntegrityVerifyPeHeader(const UCHAR *imageBase, SIZE_T imageSize);

BOOLEAN  GameIntegrityIsProtectedPid(HANDLE pid);
VOID     GameIntegrityOnProcessExit(HANDLE pid);
BOOLEAN  GameIntegrityGetProtectedImageDir(HANDLE pid, WCHAR *outDir, SIZE_T outCapWchars);
