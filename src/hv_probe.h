#pragma once

#include "core.h"

#define HV_PROBE_CPUID_SITES  4
#define HV_PROBE_PORT_SITES   2

#define HV_PROBE_FLAG_HV_BIT_SET       0x00000001
#define HV_PROBE_FLAG_VENDOR_MICROSOFT 0x00000002
#define HV_PROBE_FLAG_VENDOR_UNKNOWN   0x00000004
#define HV_PROBE_FLAG_HIGH_JITTER      0x00000008
#define HV_PROBE_FLAG_HIGH_LATENCY     0x00000010
#define HV_PROBE_FLAG_IDT_OUT_OF_RANGE 0x00000020
#define HV_PROBE_FLAG_GDT_OUT_OF_RANGE 0x00000040
#define HV_PROBE_FLAG_TSCP_MISMATCH    0x00000080

#pragma pack(push, 1)
typedef struct _HV_PROBE_CPUID_SAMPLE
{
    ULONG   Leaf;
    ULONG   SubLeaf;
    ULONG   Regs[4];
    ULONG64 TscDelta;
} HV_PROBE_CPUID_SAMPLE, *PHV_PROBE_CPUID_SAMPLE;

typedef struct _HV_PROBE_PORT_SAMPLE
{
    USHORT  Port;
    UCHAR   Width;
    UCHAR   Reserved;
    ULONG   Value;
    ULONG64 TscDelta;
} HV_PROBE_PORT_SAMPLE, *PHV_PROBE_PORT_SAMPLE;
#pragma pack(pop)

typedef struct _HV_PROBE_REPORT
{
    ULONG                 Flags;
    ULONG                 Epoch;
    ULONG64               BootCookie;

    HV_PROBE_CPUID_SAMPLE Cpuid[HV_PROBE_CPUID_SITES];

    ULONG64               Rdtsc1;
    ULONG64               Rdtsc2;
    ULONG64               RdtscpPair;
    ULONG                 RdtscpAux;

    ULONG64               IdtBase;
    USHORT                IdtLimit;
    USHORT                Reserved0;
    ULONG64               GdtBase;
    USHORT                GdtLimit;
    USHORT                Reserved1;

    HV_PROBE_PORT_SAMPLE  Port[HV_PROBE_PORT_SITES];

    CHAR                  HvVendor[16];
} HV_PROBE_REPORT, *PHV_PROBE_REPORT;

NTSTATUS HvProbeInit(VOID);
VOID     HvProbeShutdown(VOID);
NTSTATUS HvProbeRun(PHV_PROBE_REPORT out);
NTSTATUS HvProbeVerify(VOID);
