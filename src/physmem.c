#include "physmem.h"
#include "imports.h"

#define CORE_MM_COPY_MEMORY_PHYSICAL 0x1

NTSTATUS PhysMemReadRaw(ULONG64 physAddress, PVOID outBuffer, SIZE_T bytes)
{
    if (!outBuffer || bytes == 0) return STATUS_INVALID_PARAMETER;

    MM_COPY_ADDRESS src = { 0 };
    src.PhysicalAddress.QuadPart = (LONGLONG)physAddress;

    SIZE_T xfer = 0;
    NTSTATUS s = MmCopyMemory(outBuffer, src, bytes, CORE_MM_COPY_MEMORY_PHYSICAL, &xfer);
    if (!NT_SUCCESS(s)) return s;
    if (xfer != bytes) return STATUS_PARTIAL_COPY;
    return STATUS_SUCCESS;
}

NTSTATUS PhysMemReadPage(ULONG64 pfn, PVOID outPage)
{
    return PhysMemReadRaw(pfn << PAGE_SHIFT, outPage, PAGE_SIZE);
}
