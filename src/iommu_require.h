#pragma once

#include "core.h"

#define IOMMU_STATE_UNKNOWN          0
#define IOMMU_STATE_UNSUPPORTED      1
#define IOMMU_STATE_AVAILABLE_OFF    2
#define IOMMU_STATE_IN_USE           3

#define IOMMU_FLAG_NONE                   0x00000000
#define IOMMU_FLAG_DMA_INFO_READABLE      0x00000001
#define IOMMU_FLAG_DMA_PROT_AVAILABLE     0x00000002
#define IOMMU_FLAG_DMA_PROT_IN_USE        0x00000004
#define IOMMU_FLAG_REG_KDP_ENABLED        0x00000008
#define IOMMU_FLAG_REG_BOOT_DMA_BLOCK     0x00000010
#define IOMMU_FLAG_DMAR_TABLE_PRESENT     0x00000020
#define IOMMU_FLAG_IVRS_TABLE_PRESENT     0x00000040
#define IOMMU_FLAG_CLAIM_DISAGREEMENT     0x00000080
#define IOMMU_FLAG_STATE_DRIFT            0x00000100
#define IOMMU_FLAG_REQUIRED_NOT_MET       0x00000200
#define IOMMU_FLAG_SUSPICIOUS             0x00000400

typedef struct _IOMMU_REQUIRE_REPORT
{
    ULONG   Flags;
    ULONG   State;
    UCHAR   DmaInfoReadable;
    UCHAR   DmaProtectionsAvailable;
    UCHAR   DmaProtectionsInUse;
    UCHAR   RegKdpEnabled;
    UCHAR   RegBootDmaBlock;
    UCHAR   DmarTablePresent;
    UCHAR   IvrsTablePresent;
    UCHAR   RequiredNotMet;
} IOMMU_REQUIRE_REPORT, *PIOMMU_REQUIRE_REPORT;

NTSTATUS IommuRequireInit(VOID);
VOID     IommuRequireShutdown(VOID);

NTSTATUS IommuRequireBaseline(VOID);
NTSTATUS IommuRequireVerify(VOID);

ULONG    IommuRequireGetFlag(VOID);
VOID     IommuRequireClearFlag(VOID);
NTSTATUS IommuRequireCopyReport(PIOMMU_REQUIRE_REPORT outReport);
