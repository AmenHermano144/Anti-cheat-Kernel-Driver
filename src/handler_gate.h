#pragma once

#include "core.h"

typedef enum _AC_HANDLER_ID
{
    AC_H_NONE          = 0x00,
    AC_H_HWID          = 0x01,
    AC_H_DMA           = 0x02,
    AC_H_PML4          = 0x03,
    AC_H_KLDR          = 0x04,
    AC_H_BYOVD         = 0x05,
    AC_H_EXECREGION    = 0x06,
    AC_H_INPUTINTG     = 0x07,
    AC_H_ROOTKIT       = 0x08,
    AC_H_HOOKAUDIT     = 0x09,
    AC_H_OVERLAY       = 0x0A,
    AC_H_IMAGEBACK     = 0x0B,
    AC_H_WIN32K        = 0x0C,
    AC_H_MOUSEPOLL     = 0x0D,
    AC_H_SECUREBOOT    = 0x0E,
    AC_H_HVCI          = 0x0F,
    AC_H_OSVERSION     = 0x10,
    AC_H_VBS           = 0x11,
    AC_H_IOMMU         = 0x12,
    AC_H_TPM           = 0x13,
    AC_H_SUSTHREADS    = 0x14,
    AC_H_VHD           = 0x15,
    AC_H_PAGEWALK      = 0x16,
    AC_H_GAMEINT       = 0x17,
    AC_H_HEARTBEAT     = 0x18,
    AC_H_TAMPER        = 0x19,
    AC_H_ENV           = 0x1A,
    AC_H_SIGNATURES    = 0x1B,
    AC_H_SSDT          = 0x1C,
    AC_H_DXGK          = 0x1D,

    AC_HANDLER_COUNT   = 0x40,
} AC_HANDLER_ID;

#define AC_GATE_FLAG_BYTES       32
#define AC_GATE_FLAG_BITS        (AC_GATE_FLAG_BYTES * 8)

#define AC_GATE_BIT_INDEX(id)    ((UCHAR)(((ULONG)(id) * 0x3Cu ^ 0x1Fu) & (AC_GATE_FLAG_BITS - 1)))

#pragma pack(push, 1)
typedef struct _AC_GATE_PUSH
{
    ULONG   Magic;
    ULONG   Epoch;
    UCHAR   Flags[AC_GATE_FLAG_BYTES];
    ULONG64 ValidationCookie;
} AC_GATE_PUSH, *PAC_GATE_PUSH;
#pragma pack(pop)

#define AC_GATE_PUSH_MAGIC       0x47415445u

NTSTATUS HandlerGateInit(VOID);
VOID     HandlerGateShutdown(VOID);

BOOLEAN  HandlerGateAllowed(AC_HANDLER_ID id);
ULONG    HandlerGateEpoch(VOID);

NTSTATUS HandlerGateApply(const UCHAR *blob, ULONG len);
VOID     HandlerGateSnapshot(UCHAR flagsOut[AC_GATE_FLAG_BYTES], ULONG *epochOut);

#define AC_GATE_RETURN_IF_DISABLED(id, ret_val)                 \
    do {                                                        \
        if (!HandlerGateAllowed(id)) return (ret_val);          \
    } while (0)

#define AC_GATE_VOID_IF_DISABLED(id)                            \
    do {                                                        \
        if (!HandlerGateAllowed(id)) return;                    \
    } while (0)
