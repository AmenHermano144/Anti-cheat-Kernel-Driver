#pragma once

#include "core.h"

SIZE_T CoreStrLenA(const CHAR *s);
SIZE_T CoreStrLenW(const WCHAR *s);

INT    CoreStrCmpA(const CHAR *a, const CHAR *b);
INT    CoreStrCmpiA(const CHAR *a, const CHAR *b);
INT    CoreStrCmpiW(const WCHAR *a, const WCHAR *b);

VOID   CoreStrCopyA(CHAR *dst, SIZE_T dstCap, const CHAR *src);
VOID   CoreStrCopyW(WCHAR *dst, SIZE_T dstCap, const WCHAR *src);

PCHAR  CoreMemFind(const VOID *haystack, SIZE_T haystackLen,
                   const VOID *needle,   SIZE_T needleLen);

ULONG64 CoreFnv1a64(const VOID *data, SIZE_T len);
ULONG32 CoreFnv1a32(const VOID *data, SIZE_T len);

VOID    CoreHexFormat(const UCHAR *bytes, SIZE_T len, CHAR *outHex, SIZE_T hexCap);

VOID    CoreLowercaseA(CHAR *s);
VOID    CoreLowercaseW(WCHAR *s);
