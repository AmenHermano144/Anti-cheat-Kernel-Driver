#pragma once

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

ULONG64 AcStackSwitchCall(PVOID target, PVOID newStackTop, PVOID a0, PVOID a1);
ULONG64 AcSplitMix64(ULONG64 x);
ULONG64 AcRdtscSerialized(VOID);
ULONG64 AcRdtscpAux(ULONG *outAux);
VOID    AcCpuidTimed(ULONG leaf, ULONG subleaf, ULONG regs[4], ULONG64 *deltaOut);
ULONG64 AcResolveImportA(ULONG idx);

#ifdef __cplusplus
}
#endif

#define AC_SWITCHER_STACK_BYTES   0x4000
