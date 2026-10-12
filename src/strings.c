#include "strings.h"

SIZE_T CoreStrLenA(const CHAR *s)
{
    SIZE_T n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

SIZE_T CoreStrLenW(const WCHAR *s)
{
    SIZE_T n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

INT CoreStrCmpA(const CHAR *a, const CHAR *b)
{
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *a == *b) { a++; b++; }
    return (INT)((UCHAR)*a - (UCHAR)*b);
}

static __forceinline CHAR LowerA(CHAR c)
{
    return (c >= 'A' && c <= 'Z') ? (CHAR)(c + 32) : c;
}

static __forceinline WCHAR LowerW(WCHAR c)
{
    return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + 32) : c;
}

INT CoreStrCmpiA(const CHAR *a, const CHAR *b)
{
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a)
    {
        CHAR la = LowerA(*a);
        CHAR lb = LowerA(*b);
        if (la != lb) return (INT)((UCHAR)la - (UCHAR)lb);
        a++; b++;
    }
    return (INT)((UCHAR)LowerA(*a) - (UCHAR)LowerA(*b));
}

INT CoreStrCmpiW(const WCHAR *a, const WCHAR *b)
{
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a)
    {
        WCHAR la = LowerW(*a);
        WCHAR lb = LowerW(*b);
        if (la != lb) return (INT)(la - lb);
        a++; b++;
    }
    return (INT)(LowerW(*a) - LowerW(*b));
}

VOID CoreStrCopyA(CHAR *dst, SIZE_T dstCap, const CHAR *src)
{
    if (!dst || dstCap == 0) return;
    SIZE_T i = 0;
    if (src)
    {
        while (i + 1 < dstCap && src[i])
        {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = 0;
}

VOID CoreStrCopyW(WCHAR *dst, SIZE_T dstCap, const WCHAR *src)
{
    if (!dst || dstCap == 0) return;
    SIZE_T i = 0;
    if (src)
    {
        while (i + 1 < dstCap && src[i])
        {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = 0;
}

PCHAR CoreMemFind(const VOID *haystack, SIZE_T haystackLen,
                  const VOID *needle,   SIZE_T needleLen)
{
    if (!haystack || !needle || needleLen == 0 || needleLen > haystackLen)
        return NULL;

    const UCHAR *h = (const UCHAR *)haystack;
    const UCHAR *n = (const UCHAR *)needle;
    SIZE_T limit = haystackLen - needleLen;

    for (SIZE_T i = 0; i <= limit; i++)
    {
        if (h[i] == n[0])
        {
            SIZE_T j = 1;
            while (j < needleLen && h[i + j] == n[j]) j++;
            if (j == needleLen) return (PCHAR)(h + i);
        }
    }
    return NULL;
}

#define CORE_FNV64_PRIME   0x100000001B3ULL
#define CORE_FNV64_OFFSET  0xCBF29CE484222325ULL
#define CORE_FNV32_PRIME   0x01000193U
#define CORE_FNV32_OFFSET  0x811C9DC5U

ULONG64 CoreFnv1a64(const VOID *data, SIZE_T len)
{
    const UCHAR *p = (const UCHAR *)data;
    ULONG64 h = CORE_FNV64_OFFSET;
    for (SIZE_T i = 0; i < len; i++)
    {
        h ^= p[i];
        h *= CORE_FNV64_PRIME;
    }
    return h;
}

ULONG32 CoreFnv1a32(const VOID *data, SIZE_T len)
{
    const UCHAR *p = (const UCHAR *)data;
    ULONG32 h = CORE_FNV32_OFFSET;
    for (SIZE_T i = 0; i < len; i++)
    {
        h ^= p[i];
        h *= CORE_FNV32_PRIME;
    }
    return h;
}

VOID CoreHexFormat(const UCHAR *bytes, SIZE_T len, CHAR *outHex, SIZE_T hexCap)
{
    static const CHAR tbl[] = "0123456789abcdef";
    if (!outHex || hexCap == 0) return;
    SIZE_T need = len * 2;
    if (hexCap < need + 1) { outHex[0] = 0; return; }
    for (SIZE_T i = 0; i < len; i++)
    {
        outHex[i * 2 + 0] = tbl[bytes[i] >> 4];
        outHex[i * 2 + 1] = tbl[bytes[i] & 0x0F];
    }
    outHex[need] = 0;
}

VOID CoreLowercaseA(CHAR *s)
{
    if (!s) return;
    while (*s) { *s = LowerA(*s); s++; }
}

VOID CoreLowercaseW(WCHAR *s)
{
    if (!s) return;
    while (*s) { *s = LowerW(*s); s++; }
}
