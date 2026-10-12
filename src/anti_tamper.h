#pragma once

#include "core.h"

VOID     AcTamperInitBootCookie(VOID);
NTSTATUS AcTamperArm(VOID);
VOID     AcTamperDisarm(VOID);

BOOLEAN  AcTamperCheckLstar(VOID);
BOOLEAN  AcTamperCheckLstarFromNmi(VOID);
BOOLEAN  AcTamperCheckStackCookie(VOID);
BOOLEAN  AcTamperCheckDebugCtl(VOID);
BOOLEAN  AcTamperCheckDebugCtlFromNmi(VOID);

VOID     AcTamperOnViolation(ULONG reasonCode, PVOID extra);
VOID     AcTamperOnViolationFromNmi(ULONG reasonCode, ULONG64 extra);
BOOLEAN  AcTamperDrainNmiFlags(ULONG *outReason, ULONG64 *outObserved);

#define AC_TAMPER_REASON_LSTAR          0x1001
#define AC_TAMPER_REASON_STACK          0x1002
#define AC_TAMPER_REASON_DEBUGCTL       0x1003
#define AC_TAMPER_REASON_NMI_SKEW       0x1004
