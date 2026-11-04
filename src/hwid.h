#pragma once

#include "core.h"
#include "smbios.h"

#define HWID_MAX_GPUS       4
#define HWID_MAX_MONITORS   4
#define HWID_MAX_NICS       8
#define HWID_EDID_BYTES     128

#pragma pack(push, 1)
typedef struct _HWID_CPU_FINGERPRINT
{
    CHAR   Vendor[16];
    CHAR   Brand[48];
    ULONG  Signature;
    ULONG  FeaturesEcx;
    ULONG  FeaturesEdx;
    ULONG  Features7Ebx;
    ULONG  Features7Ecx;
    ULONG  MicrocodeRevision;
    ULONG  LogicalCount;
    ULONG  AddressingBits;
} HWID_CPU_FINGERPRINT, *PHWID_CPU_FINGERPRINT;

typedef struct _HWID_PCI_FINGERPRINT
{
    USHORT VendorId;
    USHORT DeviceId;
    USHORT SubsysVendorId;
    USHORT SubsysDeviceId;
    UCHAR  ClassCode;
    UCHAR  SubClass;
    UCHAR  ProgIf;
    UCHAR  Revision;
    UCHAR  Bus;
    UCHAR  Device;
    UCHAR  Function;
    UCHAR  Reserved;
} HWID_PCI_FINGERPRINT, *PHWID_PCI_FINGERPRINT;

typedef struct _HWID_MONITOR_FINGERPRINT
{
    UCHAR  Edid[HWID_EDID_BYTES];
    UCHAR  EdidSha256[32];
    CHAR   InstanceId[96];
} HWID_MONITOR_FINGERPRINT, *PHWID_MONITOR_FINGERPRINT;

typedef struct _HWID_EXTENDED_FINGERPRINT
{
    HWID_CPU_FINGERPRINT     Cpu;
    ULONG                    GpuCount;
    HWID_PCI_FINGERPRINT     Gpus[HWID_MAX_GPUS];
    ULONG                    NicCount;
    HWID_PCI_FINGERPRINT     Nics[HWID_MAX_NICS];
    ULONG                    MonitorCount;
    HWID_MONITOR_FINGERPRINT Monitors[HWID_MAX_MONITORS];
    UCHAR                    TpmEkHash[32];
    UCHAR                    TpmEkPresent;
    UCHAR                    Reserved[7];
} HWID_EXTENDED_FINGERPRINT, *PHWID_EXTENDED_FINGERPRINT;
#pragma pack(pop)

typedef struct _HWID_SNAPSHOT
{
    SMBIOS_PARSED              Smbios;
    HWID_EXTENDED_FINGERPRINT  Extended;
    UCHAR                      CompositeDigest[32];
    ULONG64                    CompositeFnv64;
} HWID_SNAPSHOT, *PHWID_SNAPSHOT;

NTSTATUS HwidCollectBoot(VOID);
NTSTATUS HwidGetSnapshot(PHWID_SNAPSHOT out);
NTSTATUS HwidEnumerateAcpi(VOID);
NTSTATUS HwidRefreshTpmBinding(VOID);
