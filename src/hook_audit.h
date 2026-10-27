#pragma once

#include "core.h"

NTSTATUS HookAuditInit(VOID);
VOID     HookAuditShutdown(VOID);

NTSTATUS HookAuditRegisterCallbacks(VOID);
VOID     HookAuditUnregisterCallbacks(VOID);

NTSTATUS HookAuditOnUserImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName, PIMAGE_INFO ImageInfo);
