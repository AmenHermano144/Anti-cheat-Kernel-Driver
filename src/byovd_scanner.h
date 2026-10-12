#pragma once

#include "core.h"

NTSTATUS ByovdScannerInit(VOID);
NTSTATUS ByovdScannerOnImageLoad(PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo);
BOOLEAN  ByovdPathIsBlacklisted(const UNICODE_STRING *fullPath);
BOOLEAN  ByovdFnvIsBlacklisted(ULONG64 fnv1a64);
