#include "wire_records.h"

ULONG WireRecordHeaderSize(VOID)
{
    return (ULONG)FIELD_OFFSET(WIRE_RECORD_HEADER, Payload);
}
