#pragma once

#include "core.h"

NTSTATUS GameIntegrityInit(VOID);
NTSTATUS GameIntegrityOnUserImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo);
BOOLEAN  GameIntegrityVerifyPeHeader(const UCHAR *imageBase, SIZE_T imageSize);
