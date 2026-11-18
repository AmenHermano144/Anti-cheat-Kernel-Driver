#include "hv_probe.h"
#include "ac_asm.h"
#include "channels.h"
#include "events.h"
#include "handler_gate.h"
#include "wire_records.h"

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_REGISTER
{
    USHORT  Limit;
    ULONG64 Base;
} DESCRIPTOR_REGISTER, *PDESCRIPTOR_REGISTER;
#pragma pack(pop)

#define HV_PROBE_CPUID_HIGH_DELTA_TSC  2500ULL
#define HV_PROBE_JITTER_RATIO          4

static ULONG64 g_LastRunTsc = 0;

NTSTATUS HvProbeInit(VOID)
{
    g_LastRunTsc = 0;
    return STATUS_SUCCESS;
}

VOID HvProbeShutdown(VOID) {}

static VOID CollectCpuidSample(PHV_PROBE_CPUID_SAMPLE s, ULONG leaf, ULONG subleaf)
{
    s->Leaf    = leaf;
    s->SubLeaf = subleaf;
    AcCpuidTimed(leaf, subleaf, s->Regs, &s->TscDelta);
}

static VOID ReadIdtGdt(PHV_PROBE_REPORT out)
{
    DESCRIPTOR_REGISTER idtr = { 0 };
    DESCRIPTOR_REGISTER gdtr = { 0 };

    __sidt(&idtr);
    _sgdt(&gdtr);

    out->IdtBase  = idtr.Base;
    out->IdtLimit = idtr.Limit;
    out->GdtBase  = gdtr.Base;
    out->GdtLimit = gdtr.Limit;
}

static VOID CollectPortSample(PHV_PROBE_PORT_SAMPLE s, USHORT port, UCHAR width)
{
    s->Port     = port;
    s->Width    = width;
    s->Reserved = 0;

    ULONG64 t0 = AcRdtscSerialized();

    if (width == 1)
    {
        s->Value = __inbyte(port);
    }
    else if (width == 2)
    {
        s->Value = __inword(port);
    }
    else
    {
        s->Value = __indword(port);
    }

    ULONG64 t1 = AcRdtscSerialized();
    s->TscDelta = t1 - t0;
}

static ULONG ClassifyHvVendor(const HV_PROBE_CPUID_SAMPLE *hv0x40, CHAR vendorOut[16])
{
    ULONG flags = 0;
    ULONG ebx = hv0x40->Regs[1];
    ULONG ecx = hv0x40->Regs[2];
    ULONG edx = hv0x40->Regs[3];

    RtlZeroMemory(vendorOut, 16);
    RtlCopyMemory(vendorOut + 0, &ebx, 4);
    RtlCopyMemory(vendorOut + 4, &ecx, 4);
    RtlCopyMemory(vendorOut + 8, &edx, 4);

    if (ebx == 0x7263694D && ecx == 0x666F736F && edx == 0x76482074)
    {
        flags |= HV_PROBE_FLAG_VENDOR_MICROSOFT;
    }
    else if (ebx || ecx || edx)
    {
        flags |= HV_PROBE_FLAG_VENDOR_UNKNOWN;
    }
    return flags;
}

NTSTATUS HvProbeRun(PHV_PROBE_REPORT out)
{
    if (!out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(out, sizeof(*out));

    out->BootCookie = CoreBootCookie();
    out->Epoch      = HandlerGateEpoch();

    CollectCpuidSample(&out->Cpuid[0], 0x00000000, 0);
    CollectCpuidSample(&out->Cpuid[1], 0x00000001, 0);
    CollectCpuidSample(&out->Cpuid[2], 0x00000007, 0);
    CollectCpuidSample(&out->Cpuid[3], 0x40000000, 0);

    if (out->Cpuid[1].Regs[2] & (1u << 31))
    {
        out->Flags |= HV_PROBE_FLAG_HV_BIT_SET;
    }

    out->Flags |= ClassifyHvVendor(&out->Cpuid[3], out->HvVendor);

    out->Rdtsc1 = AcRdtscSerialized();
    out->Rdtsc2 = AcRdtscSerialized();

    out->RdtscpPair = AcRdtscpAux(&out->RdtscpAux);

    if (out->RdtscpPair < out->Rdtsc1)
    {
        out->Flags |= HV_PROBE_FLAG_TSCP_MISMATCH;
    }

    ReadIdtGdt(out);

    if (out->IdtBase < 0xFFFF800000000000ULL)
    {
        out->Flags |= HV_PROBE_FLAG_IDT_OUT_OF_RANGE;
    }
    if (out->GdtBase < 0xFFFF800000000000ULL)
    {
        out->Flags |= HV_PROBE_FLAG_GDT_OUT_OF_RANGE;
    }

    CollectPortSample(&out->Port[0], 0x92, 1);
    CollectPortSample(&out->Port[1], 0x61, 1);

    ULONG64 maxDelta = 0;
    ULONG64 minDelta = (ULONG64)-1;
    for (ULONG i = 0; i < HV_PROBE_CPUID_SITES; i++)
    {
        ULONG64 d = out->Cpuid[i].TscDelta;
        if (d > maxDelta) maxDelta = d;
        if (d < minDelta) minDelta = d;
    }

    if (maxDelta > HV_PROBE_CPUID_HIGH_DELTA_TSC)
    {
        out->Flags |= HV_PROBE_FLAG_HIGH_LATENCY;
    }
    if (minDelta > 0 && (maxDelta / (minDelta ? minDelta : 1)) > HV_PROBE_JITTER_RATIO)
    {
        out->Flags |= HV_PROBE_FLAG_HIGH_JITTER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HvProbeVerify(VOID)
{
    ULONG64 now = AcRdtscSerialized();
    ULONG64 last = g_LastRunTsc;
    if (last != 0 && (now - last) < 0x100000000ULL)
    {
        return STATUS_SUCCESS;
    }
    g_LastRunTsc = now;

    HV_PROBE_REPORT rep;
    NTSTATUS s = HvProbeRun(&rep);
    if (!NT_SUCCESS(s)) return s;

    return ChannelEnqueueRecord(WIRE_REC_HV_TIMING, &rep, sizeof(rep));
}
