#include "hwid.h"
#include "imports.h"
#include "crypto.h"
#include "strings.h"
#include "channels.h"
#include "wire_records.h"
#include "tpm_attest.h"

static HWID_SNAPSHOT g_Hwid;
static volatile LONG g_Captured = 0;

#define HWID_MSR_IA32_BIOS_SIGN_ID   0x0000008Bu
#define HWID_PCI_CLASS_DISPLAY       0x03u
#define HWID_PCI_CLASS_NETWORK       0x02u

#define HWID_PCI_CONFIG_SPACE_BUS    1

static VOID HwidCollectCpu(PHWID_CPU_FINGERPRINT cpu)
{
    RtlZeroMemory(cpu, sizeof(*cpu));

    int info[4] = { 0, 0, 0, 0 };
    __cpuid(info, 0);
    const ULONG maxBasic = (ULONG)info[0];
    RtlCopyMemory(cpu->Vendor + 0,  &info[1], 4);
    RtlCopyMemory(cpu->Vendor + 4,  &info[3], 4);
    RtlCopyMemory(cpu->Vendor + 8,  &info[2], 4);
    cpu->Vendor[12] = 0;

    if (maxBasic >= 1)
    {
        __cpuid(info, 1);
        cpu->Signature   = (ULONG)info[0];
        cpu->FeaturesEcx = (ULONG)info[2];
        cpu->FeaturesEdx = (ULONG)info[3];
        cpu->LogicalCount = (ULONG)((info[1] >> 16) & 0xFF);
    }

    if (maxBasic >= 7)
    {
        int info7[4] = { 0, 0, 0, 0 };
        __cpuidex(info7, 7, 0);
        cpu->Features7Ebx = (ULONG)info7[1];
        cpu->Features7Ecx = (ULONG)info7[2];
    }

    __cpuid(info, 0x80000000);
    const ULONG maxExt = (ULONG)info[0];

    if (maxExt >= 0x80000004)
    {
        int b1[4], b2[4], b3[4];
        __cpuid(b1, 0x80000002);
        __cpuid(b2, 0x80000003);
        __cpuid(b3, 0x80000004);
        RtlCopyMemory(cpu->Brand + 0,  b1, 16);
        RtlCopyMemory(cpu->Brand + 16, b2, 16);
        RtlCopyMemory(cpu->Brand + 32, b3, 16);
        cpu->Brand[47] = 0;
    }

    if (maxExt >= 0x80000008)
    {
        int infoEx[4];
        __cpuid(infoEx, 0x80000008);
        cpu->AddressingBits = (ULONG)(infoEx[0] & 0xFFFF);
    }

    __try
    {
        ULONG64 msr = __readmsr(HWID_MSR_IA32_BIOS_SIGN_ID);
        cpu->MicrocodeRevision = (ULONG)(msr >> 32);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        cpu->MicrocodeRevision = 0;
    }
}

static ULONG HwidPciSlot(UCHAR dev, UCHAR fn)
{
    PCI_SLOT_NUMBER slot;
    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber   = dev & 0x1F;
    slot.u.bits.FunctionNumber = fn  & 0x07;
    return slot.u.AsULONG;
}

static BOOLEAN HwidReadPciConfig(UCHAR bus, UCHAR device, UCHAR function, UCHAR *buf, ULONG len)
{
#pragma warning(push)
#pragma warning(disable: 4996)
    ULONG got = HalGetBusDataByOffset(
        PCIConfiguration,
        bus,
        HwidPciSlot(device, function),
        buf, 0, len);
#pragma warning(pop)
    if (got != len) return FALSE;
    USHORT vendor = *(USHORT *)buf;
    if (vendor == 0xFFFFu) return FALSE;
    return TRUE;
}

static VOID HwidFillPciFingerprint(const UCHAR *cfg, UCHAR bus, UCHAR dev, UCHAR fn, PHWID_PCI_FINGERPRINT out)
{
    RtlZeroMemory(out, sizeof(*out));
    out->VendorId        = *(USHORT *)(cfg + 0x00);
    out->DeviceId        = *(USHORT *)(cfg + 0x02);
    out->Revision        = cfg[0x08];
    out->ProgIf          = cfg[0x09];
    out->SubClass        = cfg[0x0A];
    out->ClassCode       = cfg[0x0B];
    out->SubsysVendorId  = *(USHORT *)(cfg + 0x2C);
    out->SubsysDeviceId  = *(USHORT *)(cfg + 0x2E);
    out->Bus      = bus;
    out->Device   = dev;
    out->Function = fn;
}

static VOID HwidEnumeratePci(PHWID_EXTENDED_FINGERPRINT ext)
{
    UCHAR cfg[0x40];

    for (ULONG bus = 0; bus < 256; bus++)
    {
        for (UCHAR dev = 0; dev < 32; dev++)
        {
            if (!HwidReadPciConfig((UCHAR)bus, dev, 0, cfg, sizeof(cfg))) continue;

            UCHAR headerType = cfg[0x0E];
            UCHAR functions = (headerType & 0x80) ? 8 : 1;

            for (UCHAR fn = 0; fn < functions; fn++)
            {
                if (fn != 0 && !HwidReadPciConfig((UCHAR)bus, dev, fn, cfg, sizeof(cfg))) continue;

                UCHAR classCode = cfg[0x0B];
                if (classCode == HWID_PCI_CLASS_DISPLAY && ext->GpuCount < HWID_MAX_GPUS)
                {
                    HwidFillPciFingerprint(cfg, (UCHAR)bus, dev, fn, &ext->Gpus[ext->GpuCount]);
                    ext->GpuCount++;
                }
                else if (classCode == HWID_PCI_CLASS_NETWORK && ext->NicCount < HWID_MAX_NICS)
                {
                    HwidFillPciFingerprint(cfg, (UCHAR)bus, dev, fn, &ext->Nics[ext->NicCount]);
                    ext->NicCount++;
                }
            }

            if (ext->GpuCount >= HWID_MAX_GPUS && ext->NicCount >= HWID_MAX_NICS)
            {
                return;
            }
        }
    }
}

static BOOLEAN HwidReadEdidForDevice(HANDLE deviceKey, PHWID_MONITOR_FINGERPRINT mon)
{
    UNICODE_STRING sub;
    OBJECT_ATTRIBUTES oa;
    HANDLE paramKey = NULL;

    RtlInitUnicodeString(&sub, L"Device Parameters");
    InitializeObjectAttributes(&oa, &sub,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               deviceKey, NULL);

    NTSTATUS s = ZwOpenKey(&paramKey, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) return FALSE;

    UNICODE_STRING edidValue;
    RtlInitUnicodeString(&edidValue, L"EDID");

    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + HWID_EDID_BYTES];
    ULONG resultLength = 0;
    s = ZwQueryValueKey(paramKey, &edidValue, KeyValuePartialInformation,
                        buffer, sizeof(buffer), &resultLength);
    ZwClose(paramKey);

    if (!NT_SUCCESS(s)) return FALSE;

    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (info->Type != REG_BINARY || info->DataLength == 0) return FALSE;

    ULONG copy = info->DataLength < HWID_EDID_BYTES ? info->DataLength : HWID_EDID_BYTES;
    RtlCopyMemory(mon->Edid, info->Data, copy);
    (VOID)CryptoSha256(mon->Edid, HWID_EDID_BYTES, mon->EdidSha256);
    return TRUE;
}

static VOID HwidEnumerateMonitors(PHWID_EXTENDED_FINGERPRINT ext)
{
    UNICODE_STRING rootPath;
    OBJECT_ATTRIBUTES oa;
    HANDLE rootKey = NULL;

    RtlInitUnicodeString(&rootPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");
    InitializeObjectAttributes(&oa, &rootPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    if (!NT_SUCCESS(ZwOpenKey(&rootKey, KEY_READ, &oa))) return;

    UCHAR info[sizeof(KEY_BASIC_INFORMATION) + 128];
    ULONG resultLength = 0;

    for (ULONG mfgIndex = 0; ext->MonitorCount < HWID_MAX_MONITORS; mfgIndex++)
    {
        NTSTATUS s = ZwEnumerateKey(rootKey, mfgIndex, KeyBasicInformation,
                                    info, sizeof(info), &resultLength);
        if (!NT_SUCCESS(s)) break;

        PKEY_BASIC_INFORMATION mfg = (PKEY_BASIC_INFORMATION)info;
        UNICODE_STRING mfgName;
        mfgName.Buffer = mfg->Name;
        mfgName.Length = (USHORT)mfg->NameLength;
        mfgName.MaximumLength = mfgName.Length;

        OBJECT_ATTRIBUTES mfgOa;
        InitializeObjectAttributes(&mfgOa, &mfgName,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   rootKey, NULL);

        HANDLE mfgKey = NULL;
        if (!NT_SUCCESS(ZwOpenKey(&mfgKey, KEY_READ, &mfgOa))) continue;

        UCHAR instanceInfo[sizeof(KEY_BASIC_INFORMATION) + 128];
        for (ULONG instIndex = 0; ext->MonitorCount < HWID_MAX_MONITORS; instIndex++)
        {
            NTSTATUS s2 = ZwEnumerateKey(mfgKey, instIndex, KeyBasicInformation,
                                         instanceInfo, sizeof(instanceInfo), &resultLength);
            if (!NT_SUCCESS(s2)) break;

            PKEY_BASIC_INFORMATION inst = (PKEY_BASIC_INFORMATION)instanceInfo;
            UNICODE_STRING instName;
            instName.Buffer = inst->Name;
            instName.Length = (USHORT)inst->NameLength;
            instName.MaximumLength = instName.Length;

            OBJECT_ATTRIBUTES instOa;
            InitializeObjectAttributes(&instOa, &instName,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                       mfgKey, NULL);

            HANDLE instKey = NULL;
            if (!NT_SUCCESS(ZwOpenKey(&instKey, KEY_READ, &instOa))) continue;

            PHWID_MONITOR_FINGERPRINT mon = &ext->Monitors[ext->MonitorCount];
            RtlZeroMemory(mon, sizeof(*mon));

            ULONG mfgChars = mfg->NameLength / sizeof(WCHAR);
            ULONG instChars = inst->NameLength / sizeof(WCHAR);
            ULONG writeIdx = 0;

            for (ULONG i = 0; i < mfgChars && writeIdx < sizeof(mon->InstanceId) - 1; i++)
            {
                WCHAR wc = mfg->Name[i];
                mon->InstanceId[writeIdx++] = (wc >= 0x20 && wc < 0x7F) ? (CHAR)wc : '?';
            }
            if (writeIdx < sizeof(mon->InstanceId) - 1) mon->InstanceId[writeIdx++] = '\\';
            for (ULONG i = 0; i < instChars && writeIdx < sizeof(mon->InstanceId) - 1; i++)
            {
                WCHAR wc = inst->Name[i];
                mon->InstanceId[writeIdx++] = (wc >= 0x20 && wc < 0x7F) ? (CHAR)wc : '?';
            }
            mon->InstanceId[writeIdx] = 0;

            if (HwidReadEdidForDevice(instKey, mon))
            {
                ext->MonitorCount++;
            }

            ZwClose(instKey);
        }

        ZwClose(mfgKey);
    }

    ZwClose(rootKey);
}

NTSTATUS HwidRefreshTpmBinding(VOID)
{
    if (!InterlockedCompareExchange(&g_Captured, 0, 0)) return STATUS_DEVICE_NOT_READY;

    TPM_ATTEST_REPORT tpm;
    NTSTATUS s = TpmAttestCopyReport(&tpm);
    if (!NT_SUCCESS(s)) return s;

    if (!(tpm.Flags & TPM_ATTEST_FLAG_EK_PUBLIC_HASHED)) return STATUS_DEVICE_NOT_READY;

    RtlCopyMemory(g_Hwid.Extended.TpmEkHash, tpm.EkPublicSha256, 32);
    g_Hwid.Extended.TpmEkPresent = 1;

    UCHAR *buf = (UCHAR *)CoreAlloc(sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended), CORE_AC_POOL_TAG_HWID);
    if (buf)
    {
        RtlCopyMemory(buf, &g_Hwid.Smbios, sizeof(g_Hwid.Smbios));
        RtlCopyMemory(buf + sizeof(g_Hwid.Smbios), &g_Hwid.Extended, sizeof(g_Hwid.Extended));
        (VOID)CryptoSha256(buf, sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended), g_Hwid.CompositeDigest);
        g_Hwid.CompositeFnv64 = CoreFnv1a64(buf, sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended));
        CoreFree(buf, CORE_AC_POOL_TAG_HWID);
    }

    (VOID)ChannelEnqueueRecord(WIRE_REC_HWID_EXTENDED, &g_Hwid.Extended, sizeof(g_Hwid.Extended));
    return STATUS_SUCCESS;
}

NTSTATUS HwidCollectBoot(VOID)
{
    RtlZeroMemory(&g_Hwid, sizeof(g_Hwid));

    NTSTATUS s = SmbiosCollect(&g_Hwid.Smbios);
    if (!NT_SUCCESS(s)) return s;

    HwidCollectCpu(&g_Hwid.Extended.Cpu);
    HwidEnumeratePci(&g_Hwid.Extended);
    HwidEnumerateMonitors(&g_Hwid.Extended);
    (VOID)HwidRefreshTpmBinding();

    UCHAR *buf = (UCHAR *)CoreAlloc(sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended), CORE_AC_POOL_TAG_HWID);
    if (buf)
    {
        RtlCopyMemory(buf, &g_Hwid.Smbios, sizeof(g_Hwid.Smbios));
        RtlCopyMemory(buf + sizeof(g_Hwid.Smbios), &g_Hwid.Extended, sizeof(g_Hwid.Extended));
        (VOID)CryptoSha256(buf, sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended), g_Hwid.CompositeDigest);
        g_Hwid.CompositeFnv64 = CoreFnv1a64(buf, sizeof(g_Hwid.Smbios) + sizeof(g_Hwid.Extended));
        CoreFree(buf, CORE_AC_POOL_TAG_HWID);
    }
    else
    {
        (VOID)CryptoSha256(&g_Hwid.Smbios, sizeof(g_Hwid.Smbios), g_Hwid.CompositeDigest);
        g_Hwid.CompositeFnv64 = CoreFnv1a64(&g_Hwid.Smbios, sizeof(g_Hwid.Smbios));
    }

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
    (VOID)ChannelEnqueueRecord(WIRE_REC_HWID_EXTENDED, &g_Hwid.Extended, sizeof(g_Hwid.Extended));

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
