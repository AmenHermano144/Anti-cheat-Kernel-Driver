#include "env_checks.h"
#include "imports.h"
#include "strings.h"

extern ULONG InitSafeBootMode;

NTSTATUS EnvRunBootGates(VOID)
{
    if (EnvIsSafeBoot())
        return CORE_AC_STATUS_ENV_FAIL;

    if (EnvIsKernelDebuggerAttached())
        return CORE_AC_STATUS_ENV_FAIL;

    return STATUS_SUCCESS;
}

BOOLEAN EnvIsSafeBoot(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"InitSafeBootMode");
    PULONG p = (PULONG)MmGetSystemRoutineAddress(&name);
    if (!p) return FALSE;
    return (*p != 0);
}

BOOLEAN EnvIsHypervisorPresent(VOID)
{
    int info[4] = { 0 };
    __cpuid(info, 1);
    return (info[2] & (1 << 31)) != 0;
}

BOOLEAN EnvIsKernelDebuggerAttached(VOID)
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION dbg = { 0 };
    ULONG ret = 0;
    NTSTATUS s = ZwQuerySystemInformation(CORE_SysKernelDebuggerInformation,
                                          &dbg, sizeof(dbg), &ret);
    if (!NT_SUCCESS(s)) return FALSE;
    if (dbg.KernelDebuggerEnabled && !dbg.KernelDebuggerNotPresent) return TRUE;
    return KD_DEBUGGER_ENABLED && !KD_DEBUGGER_NOT_PRESENT;
}

NTSTATUS EnvEnumKernelModules(PVOID *outBuffer, PULONG outCount)
{
    if (!outBuffer || !outCount) return STATUS_INVALID_PARAMETER;
    *outBuffer = NULL;
    *outCount = 0;

    ULONG needed = 0;
    NTSTATUS s = ZwQuerySystemInformation(CORE_SysModuleInformation, NULL, 0, &needed);
    if (s != STATUS_INFO_LENGTH_MISMATCH || needed == 0) return s;

    PVOID buf = CoreAlloc(needed + 0x200, CORE_AC_POOL_TAG_SCAN);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG got = 0;
    s = ZwQuerySystemInformation(CORE_SysModuleInformation, buf, needed + 0x200, &got);
    if (!NT_SUCCESS(s))
    {
        CoreFree(buf, CORE_AC_POOL_TAG_SCAN);
        return s;
    }

    PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)buf;
    *outBuffer = buf;
    *outCount = mods->Count;
    return STATUS_SUCCESS;
}
