#pragma once

#include "core.h"

#define DMA_FLAG_NONE                 0x00000000
#define DMA_FLAG_KNOWN_DEVICE         0x00000001
#define DMA_FLAG_FPGA_VENDOR          0x00000002
#define DMA_FLAG_ZERO_SERIAL          0x00000004
#define DMA_FLAG_NO_CAPABILITIES      0x00000008
#define DMA_FLAG_HIDDEN_PDO           0x00000010
#define DMA_FLAG_HOTPLUG              0x00000020
#define DMA_FLAG_BUSMASTER_UNCLAIMED  0x00000040
#define DMA_FLAG_BRIDGE_ANOMALY       0x00000080
#define DMA_FLAG_HEADER_MISMATCH      0x00000100
#define DMA_FLAG_SUSPICIOUS           0x00001000

NTSTATUS DmaDetectInit(VOID);
VOID     DmaDetectShutdown(VOID);

NTSTATUS DmaDetectSnapshot(VOID);
NTSTATUS DmaDetectVerify(VOID);

ULONG    DmaDetectGetFlag(VOID);
VOID     DmaDetectClearFlag(VOID);
