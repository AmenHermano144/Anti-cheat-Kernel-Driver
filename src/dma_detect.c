#include "dma_detect.h"
#include "imports.h"
#include "events.h"
#include "anti_tamper.h"
#include "wire_records.h"

#define DMA_MAX_DEVICES         256
#define DMA_CFG_HEADER_LEN      0x40
#define DMA_CAP_WALK_LIMIT      48
#define DMA_EXTCAP_WALK_LIMIT   64
#define DMA_EXTCAP_BASE         0x100
#define DMA_EXTCAP_SPAN_MAX     0x1000

#define DMA_CAP_ID_PCIE         0x10
#define DMA_EXT_CAP_ID_DSN      0x0003

#define DMA_CMD_BUS_MASTER      0x0004
#define DMA_STATUS_CAP_LIST     0x0010

typedef struct _DMA_SNAP_ENTRY
{
    UCHAR  Bus;
    UCHAR  Device;
    UCHAR  Function;
    UCHAR  HeaderType;
    USHORT VendorId;
    USHORT DeviceId;
    ULONG  Flags;
} DMA_SNAP_ENTRY, *PDMA_SNAP_ENTRY;

typedef struct _DMA_PDO_ENTRY
{
    UCHAR Bus;
    UCHAR Device;
    UCHAR Function;
    UCHAR Padding;
} DMA_PDO_ENTRY, *PDMA_PDO_ENTRY;

typedef struct _DMA_FINGERPRINT
{
    USHORT VendorId;
    USHORT DeviceId;
} DMA_FINGERPRINT, *PDMA_FINGERPRINT;

static DMA_SNAP_ENTRY g_Baseline[DMA_MAX_DEVICES];
static volatile LONG  g_BaselineCount = 0;

static DMA_PDO_ENTRY  g_PdoList[DMA_MAX_DEVICES];
static ULONG          g_PdoCount = 0;

static volatile LONG  g_Initialized = 0;
static volatile LONG  g_DmaFlag = 0;

static const DMA_FINGERPRINT g_KnownDmaCards[] =
{
    // Xilinx FPGA — pcileech-fpga / Screamer / LeetDMA / Captain-DMA / ZDMA default device ids
    { 0x10EE, 0x0007 },
    { 0x10EE, 0x0666 },
    { 0x10EE, 0x7011 },
    { 0x10EE, 0x7012 },
    { 0x10EE, 0x7014 },
    { 0x10EE, 0x7021 },
    { 0x10EE, 0x7022 },
    { 0x10EE, 0x7024 },
    { 0x10EE, 0x7028 },
    { 0x10EE, 0x7038 },
    { 0x10EE, 0x7A37 },
    { 0x10EE, 0x7D02 },
    { 0x10EE, 0x8011 },
    { 0x10EE, 0x8021 },
    { 0x10EE, 0x8024 },
    { 0x10EE, 0x8038 },
    { 0x10EE, 0x9011 },
    { 0x10EE, 0x9021 },
    { 0x10EE, 0x9024 },
    { 0x10EE, 0xA011 },
    { 0x10EE, 0xA021 },
    // Altera / Intel FPGA default
    { 0x1172, 0xE001 },
    { 0x1172, 0x0004 },
    // test / junk vendor:device commonly left behind in prototype firmware
    { 0x6666, 0x6666 },
    { 0x1234, 0x1234 },
    { 0x0000, 0x0000 }
};

static BOOLEAN IsKnownDmaCard(USHORT vid, USHORT did)
{
    for (ULONG i = 0; g_KnownDmaCards[i].VendorId != 0 || g_KnownDmaCards[i].DeviceId != 0; i++)
    {
        if (g_KnownDmaCards[i].VendorId == vid && g_KnownDmaCards[i].DeviceId == did) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsFpgaVendor(USHORT vid)
{
    return vid == 0x10EE   // Xilinx
        || vid == 0x1172   // Intel / Altera
        || vid == 0x1204   // Lattice
        || vid == 0x6666
        || vid == 0x1234;
}

static ULONG PciSlot(UCHAR dev, UCHAR fn)
{
    PCI_SLOT_NUMBER slot;
    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber   = dev & 0x1F;
    slot.u.bits.FunctionNumber = fn  & 0x07;
    return slot.u.AsULONG;
}

static ULONG ReadConfig(UCHAR bus, UCHAR dev, UCHAR fn, PVOID buf, ULONG off, ULONG len)
{
#pragma warning(push)
#pragma warning(disable: 4996)
    return HalGetBusDataByOffset(PCIConfiguration, bus, PciSlot(dev, fn), buf, off, len);
#pragma warning(pop)
}

static BOOLEAN ReadVidDid(UCHAR bus, UCHAR dev, UCHAR fn, USHORT *vid, USHORT *did)
{
    ULONG id = 0;
    if (ReadConfig(bus, dev, fn, &id, 0, 4) != 4) return FALSE;
    USHORT v = (USHORT)(id & 0xFFFF);
    USHORT d = (USHORT)((id >> 16) & 0xFFFF);
    if (v == 0xFFFF) return FALSE;
    *vid = v;
    *did = d;
    return TRUE;
}

static UCHAR LocatePcieCap(UCHAR bus, UCHAR dev, UCHAR fn, USHORT statusReg, UCHAR headerType)
{
    if (!(statusReg & DMA_STATUS_CAP_LIST)) return 0;

    UCHAR capPtrOffset = ((headerType & 0x7F) == 2) ? 0x14 : 0x34;
    UCHAR ptr = 0;
    if (ReadConfig(bus, dev, fn, &ptr, capPtrOffset, 1) != 1) return 0;
    ptr &= 0xFC;

    UCHAR seen = 0;
    while (ptr && seen++ < DMA_CAP_WALK_LIMIT)
    {
        UCHAR hdr[2] = { 0 };
        if (ReadConfig(bus, dev, fn, hdr, ptr, 2) != 2) return 0;
        if (hdr[0] == DMA_CAP_ID_PCIE) return ptr;
        if (hdr[1] == 0 || hdr[1] == ptr) return 0;
        ptr = hdr[1] & 0xFC;
    }
    return 0;
}

static ULONG64 ReadDeviceSerialNumber(UCHAR bus, UCHAR dev, UCHAR fn)
{
    USHORT extCap = DMA_EXTCAP_BASE;
    UCHAR seen = 0;
    while (extCap && extCap < DMA_EXTCAP_SPAN_MAX && seen++ < DMA_EXTCAP_WALK_LIMIT)
    {
        ULONG hdr = 0;
        if (ReadConfig(bus, dev, fn, &hdr, extCap, 4) != 4) return 0;
        if (hdr == 0 || hdr == 0xFFFFFFFF) return 0;

        USHORT capId   = (USHORT)(hdr & 0xFFFF);
        USHORT nextOff = (USHORT)((hdr >> 20) & 0xFFF);

        if (capId == DMA_EXT_CAP_ID_DSN)
        {
            ULONG lo = 0, hi = 0;
            if (ReadConfig(bus, dev, fn, &lo, extCap + 4, 4) != 4) return 0;
            if (ReadConfig(bus, dev, fn, &hi, extCap + 8, 4) != 4) return 0;
            return ((ULONG64)hi << 32) | lo;
        }

        if (!nextOff || nextOff == extCap) return 0;
        extCap = nextOff;
    }
    return 0;
}

static VOID BuildPdoList(VOID)
{
    g_PdoCount = 0;

    UNICODE_STRING pciName;
    RtlInitUnicodeString(&pciName, L"\\Driver\\pci");
    PDRIVER_OBJECT pci = NULL;
    NTSTATUS s = ObReferenceObjectByName(&pciName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                         *IoDriverObjectType, KernelMode, NULL,
                                         (PVOID *)&pci);
    if (!NT_SUCCESS(s) || !pci) return;

    for (PDEVICE_OBJECT dev = pci->DeviceObject; dev; dev = dev->NextDevice)
    {
        if (g_PdoCount >= DMA_MAX_DEVICES) break;

        ULONG bus = 0, addr = 0, bufLen = 0;
        if (!NT_SUCCESS(IoGetDeviceProperty(dev, DevicePropertyBusNumber,
                                            sizeof(bus), &bus, &bufLen))) continue;
        if (!NT_SUCCESS(IoGetDeviceProperty(dev, DevicePropertyAddress,
                                            sizeof(addr), &addr, &bufLen))) continue;

        g_PdoList[g_PdoCount].Bus = (UCHAR)(bus & 0xFF);
        g_PdoList[g_PdoCount].Device = (UCHAR)((addr >> 16) & 0x1F);
        g_PdoList[g_PdoCount].Function = (UCHAR)(addr & 0x07);
        g_PdoList[g_PdoCount].Padding = 0;
        g_PdoCount++;
    }

    ObDereferenceObject(pci);
}

static BOOLEAN PdoContains(UCHAR bus, UCHAR dev, UCHAR fn)
{
    for (ULONG i = 0; i < g_PdoCount; i++)
    {
        if (g_PdoList[i].Bus == bus &&
            g_PdoList[i].Device == dev &&
            g_PdoList[i].Function == fn)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN BaselineContains(UCHAR bus, UCHAR dev, UCHAR fn, USHORT vid, USHORT did)
{
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    for (LONG i = 0; i < n; i++)
    {
        if (g_Baseline[i].Bus == bus && g_Baseline[i].Device == dev && g_Baseline[i].Function == fn)
        {
            return g_Baseline[i].VendorId == vid && g_Baseline[i].DeviceId == did;
        }
    }
    return FALSE;
}

static VOID BaselineAppend(UCHAR bus, UCHAR dev, UCHAR fn, UCHAR hdr, USHORT vid, USHORT did, ULONG flags)
{
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    if (n >= DMA_MAX_DEVICES) return;
    g_Baseline[n].Bus = bus;
    g_Baseline[n].Device = dev;
    g_Baseline[n].Function = fn;
    g_Baseline[n].HeaderType = hdr;
    g_Baseline[n].VendorId = vid;
    g_Baseline[n].DeviceId = did;
    g_Baseline[n].Flags = flags;
    InterlockedIncrement(&g_BaselineCount);
}

static BOOLEAN BaselineHeaderMismatch(UCHAR bus, UCHAR dev, UCHAR fn, UCHAR hdr)
{
    LONG n = InterlockedCompareExchange(&g_BaselineCount, 0, 0);
    for (LONG i = 0; i < n; i++)
    {
        if (g_Baseline[i].Bus == bus && g_Baseline[i].Device == dev && g_Baseline[i].Function == fn)
        {
            return (g_Baseline[i].HeaderType & 0x7F) != (hdr & 0x7F);
        }
    }
    return FALSE;
}

static VOID EmitHit(UCHAR bus, UCHAR dev, UCHAR fn, const UCHAR *cfg, ULONG64 serial, ULONG flags)
{
    WIRE_DMA_HIT rec;
    RtlZeroMemory(&rec, sizeof(rec));

    rec.Bus        = bus;
    rec.Device     = dev;
    rec.Function   = fn;
    rec.HeaderType = cfg[0x0E];
    rec.VendorId   = *(USHORT *)(cfg + 0x00);
    rec.DeviceId   = *(USHORT *)(cfg + 0x02);
    rec.Command    = *(USHORT *)(cfg + 0x04);
    rec.Status     = *(USHORT *)(cfg + 0x06);
    rec.RevisionId = cfg[0x08];
    rec.ProgIf     = cfg[0x09];
    rec.SubClass   = cfg[0x0A];
    rec.ClassCode  = cfg[0x0B];

    for (ULONG i = 0; i < 6; i++)
    {
        rec.Bar[i] = *(ULONG *)(cfg + 0x10 + 4 * i);
    }

    if ((cfg[0x0E] & 0x7F) == 0)
    {
        rec.SubsysVendorId = *(USHORT *)(cfg + 0x2C);
        rec.SubsysDeviceId = *(USHORT *)(cfg + 0x2E);
    }

    rec.DetectFlags  = flags;
    rec.SerialNumber = serial;

    (VOID)EventsReportDma(&rec);

    ULONG64 locator = ((ULONG64)bus << 16) | ((ULONG64)dev << 8) | fn;
    (VOID)EventsReportTamper(AC_TAMPER_REASON_DMA, (PVOID)(ULONG_PTR)locator);

    InterlockedOr(&g_DmaFlag, (LONG)flags);
}

static VOID EvaluateFunction(UCHAR bus, UCHAR dev, UCHAR fn, BOOLEAN baselinePass)
{
    USHORT vid = 0, did = 0;
    if (!ReadVidDid(bus, dev, fn, &vid, &did)) return;

    UCHAR cfg[DMA_CFG_HEADER_LEN];
    RtlZeroMemory(cfg, sizeof(cfg));
    if (ReadConfig(bus, dev, fn, cfg, 0, DMA_CFG_HEADER_LEN) != DMA_CFG_HEADER_LEN) return;
    if (*(USHORT *)cfg == 0xFFFF) return;

    USHORT  cmdReg    = *(USHORT *)(cfg + 0x04);
    USHORT  statusReg = *(USHORT *)(cfg + 0x06);
    UCHAR   hdrType   = cfg[0x0E];
    BOOLEAN isBridge  = (hdrType & 0x7F) == 1;
    BOOLEAN busMaster = (cmdReg & DMA_CMD_BUS_MASTER) != 0;
    BOOLEAN capsSaid  = (statusReg & DMA_STATUS_CAP_LIST) != 0;

    ULONG flags = 0;
    ULONG64 serial = 0;

    if (IsKnownDmaCard(vid, did)) flags |= DMA_FLAG_KNOWN_DEVICE;
    if (IsFpgaVendor(vid))        flags |= DMA_FLAG_FPGA_VENDOR;

    if (!isBridge)
    {
        UCHAR pcieCap = LocatePcieCap(bus, dev, fn, statusReg, hdrType);
        if (pcieCap)
        {
            serial = ReadDeviceSerialNumber(bus, dev, fn);
            if ((flags & (DMA_FLAG_KNOWN_DEVICE | DMA_FLAG_FPGA_VENDOR)) && serial == 0)
            {
                flags |= DMA_FLAG_ZERO_SERIAL;
            }
        }
        else if (!capsSaid && (flags & (DMA_FLAG_KNOWN_DEVICE | DMA_FLAG_FPGA_VENDOR)))
        {
            flags |= DMA_FLAG_NO_CAPABILITIES;
        }
    }
    else
    {
        UCHAR secondaryBus = cfg[0x19];
        UCHAR subordinate  = cfg[0x1A];
        if (secondaryBus != 0 && subordinate < secondaryBus)
        {
            flags |= DMA_FLAG_BRIDGE_ANOMALY;
        }
    }

    if (!PdoContains(bus, dev, fn) && (flags & (DMA_FLAG_KNOWN_DEVICE | DMA_FLAG_FPGA_VENDOR)))
    {
        flags |= DMA_FLAG_HIDDEN_PDO;
    }

    if (baselinePass)
    {
        BaselineAppend(bus, dev, fn, hdrType, vid, did, flags);

        if (flags & DMA_FLAG_KNOWN_DEVICE)
        {
            flags |= DMA_FLAG_SUSPICIOUS;
            EmitHit(bus, dev, fn, cfg, serial, flags);
        }
        return;
    }

    if (!BaselineContains(bus, dev, fn, vid, did))
    {
        flags |= DMA_FLAG_HOTPLUG;
    }
    if (BaselineHeaderMismatch(bus, dev, fn, hdrType))
    {
        flags |= DMA_FLAG_HEADER_MISMATCH;
    }
    if ((flags & DMA_FLAG_HOTPLUG) && busMaster && !PdoContains(bus, dev, fn))
    {
        flags |= DMA_FLAG_BUSMASTER_UNCLAIMED;
    }

    BOOLEAN suspicious = FALSE;
    if (flags & DMA_FLAG_KNOWN_DEVICE) suspicious = TRUE;
    if ((flags & DMA_FLAG_FPGA_VENDOR) &&
        (flags & (DMA_FLAG_ZERO_SERIAL | DMA_FLAG_NO_CAPABILITIES |
                  DMA_FLAG_HIDDEN_PDO  | DMA_FLAG_HOTPLUG)))
    {
        suspicious = TRUE;
    }
    if ((flags & DMA_FLAG_HOTPLUG) && (flags & DMA_FLAG_HIDDEN_PDO))     suspicious = TRUE;
    if (flags & DMA_FLAG_BUSMASTER_UNCLAIMED)                             suspicious = TRUE;
    if (flags & DMA_FLAG_HEADER_MISMATCH)                                 suspicious = TRUE;

    if (!suspicious) return;

    flags |= DMA_FLAG_SUSPICIOUS;
    EmitHit(bus, dev, fn, cfg, serial, flags);
}

static VOID ScanBuses(BOOLEAN baselinePass)
{
    BuildPdoList();

    for (ULONG bus = 0; bus < 0x100; bus++)
    {
        for (ULONG devN = 0; devN < 0x20; devN++)
        {
            USHORT vid0 = 0, did0 = 0;
            if (!ReadVidDid((UCHAR)bus, (UCHAR)devN, 0, &vid0, &did0)) continue;

            UCHAR hdr = 0;
            BOOLEAN multiFn = FALSE;
            if (ReadConfig((UCHAR)bus, (UCHAR)devN, 0, &hdr, 0x0E, 1) == 1)
            {
                multiFn = (hdr & 0x80) != 0;
            }

            ULONG fns = multiFn ? 8 : 1;
            for (ULONG fn = 0; fn < fns; fn++)
            {
                EvaluateFunction((UCHAR)bus, (UCHAR)devN, (UCHAR)fn, baselinePass);
            }
        }
    }
}

NTSTATUS DmaDetectInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));
    RtlZeroMemory(g_PdoList,  sizeof(g_PdoList));
    InterlockedExchange(&g_BaselineCount, 0);
    InterlockedExchange(&g_DmaFlag, 0);
    g_PdoCount = 0;
    return STATUS_SUCCESS;
}

VOID DmaDetectShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);
    InterlockedExchange(&g_BaselineCount, 0);
    InterlockedExchange(&g_DmaFlag, 0);
    g_PdoCount = 0;
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));
    RtlZeroMemory(g_PdoList,  sizeof(g_PdoList));
}

NTSTATUS DmaDetectSnapshot(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

    InterlockedExchange(&g_BaselineCount, 0);
    RtlZeroMemory(g_Baseline, sizeof(g_Baseline));

    ScanBuses(TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS DmaDetectVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

    ScanBuses(FALSE);
    return STATUS_SUCCESS;
}

ULONG DmaDetectGetFlag(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_DmaFlag, 0, 0);
}

VOID DmaDetectClearFlag(VOID)
{
    InterlockedExchange(&g_DmaFlag, 0);
}
