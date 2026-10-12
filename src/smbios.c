#include "smbios.h"
#include "imports.h"
#include "strings.h"

#pragma pack(push, 1)
typedef struct _SMBIOS_HEADER
{
    UCHAR  Type;
    UCHAR  Length;
    USHORT Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

typedef struct _SMBIOS_RAW_HEADER
{
    UCHAR  Used20CallingMethod;
    UCHAR  MajorVersion;
    UCHAR  MinorVersion;
    UCHAR  DmiRevision;
    ULONG  Length;
    UCHAR  TableData[1];
} SMBIOS_RAW_HEADER, *PSMBIOS_RAW_HEADER;
#pragma pack(pop)

static const CHAR *SmbiosGetString(const UCHAR *tableEnd, const UCHAR *stringsStart, UCHAR index)
{
    if (index == 0 || stringsStart >= tableEnd) return "";
    const CHAR *p = (const CHAR *)stringsStart;
    UCHAR i = 1;
    while (p < (const CHAR *)tableEnd)
    {
        if (*p == 0) return "";
        if (i == index) return p;
        while (p < (const CHAR *)tableEnd && *p) p++;
        if (p < (const CHAR *)tableEnd) p++;
        i++;
    }
    return "";
}

static VOID CopyStringField(UCHAR *dst, SIZE_T cap, const CHAR *src)
{
    if (!dst || cap == 0) return;
    SIZE_T i = 0;
    while (src && i + 1 < cap && src[i])
    {
        dst[i] = (UCHAR)src[i];
        i++;
    }
    dst[i] = 0;
}

static VOID ParseType0(PSMBIOS_HEADER hdr, const UCHAR *stringsStart, const UCHAR *tableEnd, PSMBIOS_PARSED out)
{
    const UCHAR *body = (const UCHAR *)hdr;
    CopyStringField(out->BiosVendor,  sizeof(out->BiosVendor),  SmbiosGetString(tableEnd, stringsStart, body[4]));
    CopyStringField(out->BiosVersion, sizeof(out->BiosVersion), SmbiosGetString(tableEnd, stringsStart, body[5]));
}

static VOID ParseType1(PSMBIOS_HEADER hdr, const UCHAR *stringsStart, const UCHAR *tableEnd, PSMBIOS_PARSED out)
{
    const UCHAR *body = (const UCHAR *)hdr;
    CopyStringField(out->SystemManufacturer, sizeof(out->SystemManufacturer), SmbiosGetString(tableEnd, stringsStart, body[4]));
    CopyStringField(out->SystemProductName,  sizeof(out->SystemProductName),  SmbiosGetString(tableEnd, stringsStart, body[5]));
    CopyStringField(out->SystemVersion,      sizeof(out->SystemVersion),      SmbiosGetString(tableEnd, stringsStart, body[6]));
    CopyStringField(out->SystemSerial,       sizeof(out->SystemSerial),       SmbiosGetString(tableEnd, stringsStart, body[7]));

    if (hdr->Length >= 0x19)
        RtlCopyMemory(out->SystemUuid, body + 8, 16);
}

static VOID ParseType2(PSMBIOS_HEADER hdr, const UCHAR *stringsStart, const UCHAR *tableEnd, PSMBIOS_PARSED out)
{
    const UCHAR *body = (const UCHAR *)hdr;
    CopyStringField(out->BaseboardManufacturer, sizeof(out->BaseboardManufacturer), SmbiosGetString(tableEnd, stringsStart, body[4]));
    CopyStringField(out->BaseboardProduct,      sizeof(out->BaseboardProduct),      SmbiosGetString(tableEnd, stringsStart, body[5]));
    CopyStringField(out->BaseboardSerial,       sizeof(out->BaseboardSerial),       SmbiosGetString(tableEnd, stringsStart, body[7]));
}

static VOID ParseType17(PSMBIOS_HEADER hdr, const UCHAR *stringsStart, const UCHAR *tableEnd, PSMBIOS_PARSED out)
{
    const UCHAR *body = (const UCHAR *)hdr;
    out->MemoryModuleCount++;
    if (out->MemoryModuleCount == 1)
    {
        CopyStringField(out->FirstMemoryManufacturer, sizeof(out->FirstMemoryManufacturer),
                        SmbiosGetString(tableEnd, stringsStart, body[0x17]));
        CopyStringField(out->FirstMemorySerial, sizeof(out->FirstMemorySerial),
                        SmbiosGetString(tableEnd, stringsStart, body[0x18]));
    }
}

static VOID WalkSmbiosTable(const UCHAR *table, ULONG length, PSMBIOS_PARSED out)
{
    const UCHAR *end = table + length;
    const UCHAR *p = table;

    while (p + sizeof(SMBIOS_HEADER) <= end)
    {
        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)p;
        if (hdr->Length < sizeof(SMBIOS_HEADER)) break;

        const UCHAR *strings = p + hdr->Length;
        const UCHAR *tail = strings;
        while (tail + 1 < end)
        {
            if (tail[0] == 0 && tail[1] == 0) { tail += 2; break; }
            tail++;
        }

        switch (hdr->Type)
        {
        case 0:  ParseType0(hdr, strings, end, out);  break;
        case 1:  ParseType1(hdr, strings, end, out);  break;
        case 2:  ParseType2(hdr, strings, end, out);  break;
        case 17: ParseType17(hdr, strings, end, out); break;
        default: break;
        }

        if (hdr->Type == 127) break;
        p = tail;
    }
}

NTSTATUS SmbiosCollect(PSMBIOS_PARSED outParsed)
{
    if (!outParsed) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(outParsed, sizeof(*outParsed));

    ULONG needed = 0;
    SYSTEM_FIRMWARE_TABLE_INFORMATION probe = { 0 };
    probe.ProviderSignature = CORE_FW_PROVIDER_RSMB;
    probe.Action = CORE_FW_ACTION_GET;
    probe.TableID = 0;
    probe.TableBufferLength = 0;

    NTSTATUS s = ZwQuerySystemInformation(CORE_SysFirmwareTableInformation,
                                          &probe, sizeof(probe), &needed);
    if (s != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(s)) return s;

    ULONG tableBufLen = probe.TableBufferLength;
    if (tableBufLen == 0 && needed > sizeof(probe))
        tableBufLen = needed - FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    if (tableBufLen == 0) return STATUS_UNSUCCESSFUL;

    ULONG allocSize = FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer) + tableBufLen + 0x200;
    PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)
        CoreAlloc(allocSize, CORE_AC_POOL_TAG_HWID);
    if (!info) return STATUS_INSUFFICIENT_RESOURCES;

    info->ProviderSignature = CORE_FW_PROVIDER_RSMB;
    info->Action = CORE_FW_ACTION_GET;
    info->TableID = 0;
    info->TableBufferLength = tableBufLen;

    ULONG got = 0;
    s = ZwQuerySystemInformation(CORE_SysFirmwareTableInformation,
                                 info, allocSize, &got);
    if (!NT_SUCCESS(s))
    {
        CoreFree(info, CORE_AC_POOL_TAG_HWID);
        return s;
    }

    if (info->TableBufferLength > sizeof(SMBIOS_RAW_HEADER))
    {
        PSMBIOS_RAW_HEADER raw = (PSMBIOS_RAW_HEADER)info->TableBuffer;
        if (raw->Length > 0 && raw->Length < info->TableBufferLength)
        {
            WalkSmbiosTable(raw->TableData, raw->Length, outParsed);
        }
    }

    CoreFree(info, CORE_AC_POOL_TAG_HWID);
    return STATUS_SUCCESS;
}
