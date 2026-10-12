#pragma once

#include "core.h"

typedef struct _USERMOD_ITER_CB_CTX
{
    PVOID OpaqueBase;
    ULONG Size;
    PVOID NamePtr;
    USHORT NameLen;
} USERMOD_ITER_CB_CTX, *PUSERMOD_ITER_CB_CTX;

typedef BOOLEAN (*USERMOD_ITER_CB)(PUSERMOD_ITER_CB_CTX ctx, PVOID userCtx);

NTSTATUS UsermodWalkProcessModules(HANDLE ProcessId, USERMOD_ITER_CB cb, PVOID userCtx);
