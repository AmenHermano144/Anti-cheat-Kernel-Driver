#include "input_integrity.h"
#include "imports.h"
#include "events.h"
#include "kldr.h"
#include "anti_tamper.h"

#define INPUT_INTG_MAX_SLOTS   32
#define INPUT_INTG_CLASS_MOUSE 0
#define INPUT_INTG_CLASS_KBD   1

typedef struct _INPUT_CALLBACK_SLOT
{
    volatile LONG   InUse;
    UCHAR           Class;
    BOOLEAN         BaselineOutOfRange;
    PDEVICE_OBJECT  UpperDevice;
    PDEVICE_OBJECT  ClassDevice;
    PULONG_PTR      SlotAddress;
    ULONG64         ExpectedCallback;
    ULONG64         AllowedModuleStart;
    ULONG64         AllowedModuleEnd;
} INPUT_CALLBACK_SLOT, *PINPUT_CALLBACK_SLOT;

static INPUT_CALLBACK_SLOT g_Slots[INPUT_INTG_MAX_SLOTS];
static volatile LONG g_SlotsUsed = 0;
static volatile LONG g_Initialized = 0;

static NTSTATUS ReferenceClassDriver(const WCHAR *name, PDRIVER_OBJECT *outDriver)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, name);
    PDRIVER_OBJECT drv = NULL;
    NTSTATUS s = ObReferenceObjectByName(&u, OBJ_CASE_INSENSITIVE, NULL, 0,
                                         *IoDriverObjectType, KernelMode, NULL,
                                         (PVOID *)&drv);
    if (!NT_SUCCESS(s)) return s;
    *outDriver = drv;
    return STATUS_SUCCESS;
}

static VOID GetDeviceExtensionBounds(PDEVICE_OBJECT dev, PULONG_PTR *outBase, SIZE_T *outCount)
{
    *outBase = NULL;
    *outCount = 0;

    PULONG_PTR base = (PULONG_PTR)dev->DeviceExtension;
    PVOID extObj = dev->DeviceObjectExtension;
    if (!base || !extObj || (ULONG_PTR)extObj <= (ULONG_PTR)base) return;

    ULONG_PTR span = (ULONG_PTR)extObj - (ULONG_PTR)base;
    if (span > 0x4000) span = 0x4000;

    *outBase = base;
    *outCount = span / sizeof(ULONG_PTR);
}

static BOOLEAN LocateCallbackSlot(PDEVICE_OBJECT upperDevice,
                                  PDEVICE_OBJECT classDevice,
                                  PDRIVER_OBJECT classDriver,
                                  PULONG_PTR *outSlotAddr,
                                  ULONG64 *outCallback)
{
    PULONG_PTR base = NULL;
    SIZE_T count = 0;
    GetDeviceExtensionBounds(upperDevice, &base, &count);
    if (!base || count < 2) return FALSE;

    BOOLEAN found = FALSE;
    __try
    {
        for (SIZE_T i = 0; i + 1 < count; i++)
        {
            if (base[i] == (ULONG_PTR)classDevice &&
                base[i + 1] > (ULONG_PTR)classDriver)
            {
                *outSlotAddr = &base[i + 1];
                *outCallback = (ULONG64)base[i + 1];
                found = TRUE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }
    return found;
}

static VOID AddSlot(UCHAR classId,
                    PDEVICE_OBJECT upperDevice,
                    PDEVICE_OBJECT classDevice,
                    PULONG_PTR slotAddr,
                    ULONG64 callback,
                    PDRIVER_OBJECT classDriver)
{
    LONG used = InterlockedCompareExchange(&g_SlotsUsed, 0, 0);
    if (used >= INPUT_INTG_MAX_SLOTS) return;

    PINPUT_CALLBACK_SLOT slot = &g_Slots[used];
    RtlZeroMemory(slot, sizeof(*slot));
    slot->Class = classId;
    slot->UpperDevice = upperDevice;
    slot->ClassDevice = classDevice;
    slot->SlotAddress = slotAddr;
    slot->ExpectedCallback = callback;

    ULONG64 modStart = classDriver ? (ULONG64)classDriver->DriverStart : 0;
    ULONG64 modEnd   = (classDriver && classDriver->DriverSize)
                        ? modStart + (ULONG64)classDriver->DriverSize : 0;
    slot->AllowedModuleStart = modStart;
    slot->AllowedModuleEnd   = modEnd;

    BOOLEAN inRange = (modStart && modEnd && callback >= modStart && callback < modEnd);
    slot->BaselineOutOfRange = !inRange;

    if (!inRange)
    {
        WIRE_INPUT_HIJACK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.DeviceObject = (ULONG64)classDevice;
        rec.SlotAddress = (ULONG64)slotAddr;
        rec.ExpectedCallback = callback;
        rec.ObservedCallback = callback;
        rec.ObservedCallbackModuleBase = KldrAddressBelongsToKnownModule((PVOID)callback) ? callback : 0;
        rec.DeviceClass = classId;
        (VOID)EventsReportInputHijack(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_INPUT, (PVOID)(ULONG_PTR)callback);
    }

    InterlockedExchange(&slot->InUse, 1);
    InterlockedIncrement(&g_SlotsUsed);
}

static VOID DiscoverClass(const WCHAR *upperName, const WCHAR *classDriverName, UCHAR classId)
{
    PDRIVER_OBJECT upperDrv = NULL;
    PDRIVER_OBJECT classDrv = NULL;

    if (!NT_SUCCESS(ReferenceClassDriver(upperName, &upperDrv))) return;
    if (!NT_SUCCESS(ReferenceClassDriver(classDriverName, &classDrv)))
    {
        ObDereferenceObject(upperDrv);
        return;
    }

    PDEVICE_OBJECT upper = upperDrv->DeviceObject;
    while (upper)
    {
        PDEVICE_OBJECT classDevice = classDrv->DeviceObject;
        while (classDevice)
        {
            PULONG_PTR slotAddr = NULL;
            ULONG64 callback = 0;
            if (LocateCallbackSlot(upper, classDevice, classDrv, &slotAddr, &callback))
            {
                AddSlot(classId, upper, classDevice, slotAddr, callback, classDrv);
            }
            classDevice = classDevice->NextDevice;
        }
        upper = upper->AttachedDevice;
    }

    ObDereferenceObject(classDrv);
    ObDereferenceObject(upperDrv);
}

NTSTATUS InputIntegrityInit(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 1, 0) != 0) return STATUS_SUCCESS;
    RtlZeroMemory(g_Slots, sizeof(g_Slots));
    InterlockedExchange(&g_SlotsUsed, 0);
    return STATUS_SUCCESS;
}

VOID InputIntegrityShutdown(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return;
    InterlockedExchange(&g_Initialized, 0);
    InterlockedExchange(&g_SlotsUsed, 0);
    RtlZeroMemory(g_Slots, sizeof(g_Slots));
}

NTSTATUS InputIntegritySnapshot(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    InterlockedExchange(&g_SlotsUsed, 0);
    RtlZeroMemory(g_Slots, sizeof(g_Slots));

    DiscoverClass(L"\\Driver\\MouHID",   L"\\Driver\\MouClass", INPUT_INTG_CLASS_MOUSE);
    DiscoverClass(L"\\Driver\\KbdHid",   L"\\Driver\\KbdClass", INPUT_INTG_CLASS_KBD);
    DiscoverClass(L"\\Driver\\i8042prt", L"\\Driver\\MouClass", INPUT_INTG_CLASS_MOUSE);
    DiscoverClass(L"\\Driver\\i8042prt", L"\\Driver\\KbdClass", INPUT_INTG_CLASS_KBD);

    return STATUS_SUCCESS;
}

NTSTATUS InputIntegrityVerify(VOID)
{
    if (!InterlockedCompareExchange(&g_Initialized, 0, 0)) return STATUS_DEVICE_NOT_READY;

    LONG used = InterlockedCompareExchange(&g_SlotsUsed, 0, 0);
    for (LONG i = 0; i < used; i++)
    {
        PINPUT_CALLBACK_SLOT slot = &g_Slots[i];
        if (!InterlockedCompareExchange(&slot->InUse, 0, 0)) continue;

        ULONG64 observed = 0;
        __try
        {
            observed = (ULONG64)(*slot->SlotAddress);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }

        BOOLEAN drifted = (observed != slot->ExpectedCallback);
        BOOLEAN inRange = (slot->AllowedModuleStart && slot->AllowedModuleEnd &&
                           observed >= slot->AllowedModuleStart &&
                           observed <  slot->AllowedModuleEnd);

        if (!drifted && inRange) continue;
        if (!drifted && slot->BaselineOutOfRange) continue;

        BOOLEAN stillBacked = KldrAddressBelongsToKnownModule((PVOID)observed);

        WIRE_INPUT_HIJACK rec;
        RtlZeroMemory(&rec, sizeof(rec));
        rec.DeviceObject = (ULONG64)slot->ClassDevice;
        rec.SlotAddress = (ULONG64)slot->SlotAddress;
        rec.ExpectedCallback = slot->ExpectedCallback;
        rec.ObservedCallback = observed;
        rec.ObservedCallbackModuleBase = stillBacked ? observed : 0;
        rec.DeviceClass = slot->Class;

        (VOID)EventsReportInputHijack(&rec);
        (VOID)EventsReportTamper(AC_TAMPER_REASON_INPUT, (PVOID)(ULONG_PTR)observed);
    }

    return STATUS_SUCCESS;
}
