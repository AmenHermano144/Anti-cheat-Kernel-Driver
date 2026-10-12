#include "hwid.h"
#include "imports.h"
#include "crypto.h"
#include "strings.h"
#include "channels.h"
#include "wire_records.h"

static HWID_SNAPSHOT g_Hwid;
static volatile LONG g_Captured = 0;

NTSTATUS HwidCollectBoot(VOID)
{
    RtlZeroMemory(&g_Hwid, sizeof(g_Hwid));

    NTSTATUS s = SmbiosCollect(&g_Hwid.Smbios);
    if (!NT_SUCCESS(s)) return s;

    (VOID)CryptoSha256(&g_Hwid.Smbios, sizeof(g_Hwid.Smbios), g_Hwid.CompositeDigest);
    g_Hwid.CompositeFnv64 = CoreFnv1a64(&g_Hwid.Smbios, sizeof(g_Hwid.Smbios));
    InterlockedExchange(&g_Captured, 1);

    WIRE_HWID_HELLO hello;
    RtlZeroMemory(&hello, sizeof(hello));
    RtlCopyMemory(hello.BiosVendor,          g_Hwid.Smbios.BiosVendor,          sizeof(hello.BiosVendor));
    RtlCopyMemory(hello.SystemManufacturer,  g_Hwid.Smbios.SystemManufacturer,  sizeof(hello.SystemManufacturer));
    RtlCopyMemory(hello.SystemProductName,   g_Hwid.Smbios.SystemProductName,   sizeof(hello.SystemProductName));
    RtlCopyMemory(hello.BaseboardSerial,     g_Hwid.Smbios.BaseboardSerial,     sizeof(hello.BaseboardSerial));
    RtlCopyMemory(hello.SystemUuid,          g_Hwid.Smbios.SystemUuid,          sizeof(hello.SystemUuid));
    hello.RamModuleCount = g_Hwid.Smbios.MemoryModuleCount;

    (VOID)ChannelEnqueueRecord(WIRE_REC_HWID_HELLO, &hello, sizeof(hello));

    (VOID)HwidEnumerateAcpi();
    return STATUS_SUCCESS;
}

NTSTATUS HwidGetSnapshot(PHWID_SNAPSHOT out)
{
    if (!out) return STATUS_INVALID_PARAMETER;
    if (!InterlockedCompareExchange(&g_Captured, 0, 0)) return STATUS_DEVICE_NOT_READY;
    RtlCopyMemory(out, &g_Hwid, sizeof(*out));
    return STATUS_SUCCESS;
}

NTSTATUS HwidEnumerateAcpi(VOID)
{
    PSYSTEM_FIRMWARE_TABLE_INFORMATION enumReq;
    ULONG enumSize = 0x2000;
    enumReq = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)CoreAlloc(enumSize, CORE_AC_POOL_TAG_HWID);
    if (!enumReq) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(enumReq, enumSize);
    enumReq->ProviderSignature = CORE_FW_PROVIDER_ACPI;
    enumReq->Action = CORE_FW_ACTION_ENUMERATE;
    enumReq->TableID = 0;
    enumReq->TableBufferLength = enumSize - FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    ULONG got = 0;
    NTSTATUS s = ZwQuerySystemInformation(CORE_SysFirmwareTableInformation,
                                          enumReq, enumSize, &got);
    if (s == STATUS_NOT_IMPLEMENTED)
    {
        CoreFree(enumReq, CORE_AC_POOL_TAG_HWID);
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(s))
    {
        CoreFree(enumReq, CORE_AC_POOL_TAG_HWID);
        return s;
    }

    CoreFree(enumReq, CORE_AC_POOL_TAG_HWID);
    return STATUS_SUCCESS;
}
