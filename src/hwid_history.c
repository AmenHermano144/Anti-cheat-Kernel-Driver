#include "hwid_history.h"
#include "imports.h"
#include "imports_hash.h"
#include "strings.h"

#define HIST_XOR 0x7Fu

static const UCHAR kEncRegPath[] = {
    0x5C^0x7F,0x52^0x7F,0x65^0x7F,0x67^0x7F,0x69^0x7F,0x73^0x7F,0x74^0x7F,0x72^0x7F,0x79^0x7F,
    0x5C^0x7F,0x4D^0x7F,0x61^0x7F,0x63^0x7F,0x68^0x7F,0x69^0x7F,0x6E^0x7F,0x65^0x7F,
    0x5C^0x7F,0x53^0x7F,0x59^0x7F,0x53^0x7F,0x54^0x7F,0x45^0x7F,0x4D^0x7F,
    0x5C^0x7F,0x43^0x7F,0x75^0x7F,0x72^0x7F,0x72^0x7F,0x65^0x7F,0x6E^0x7F,0x74^0x7F,
    0x43^0x7F,0x6F^0x7F,0x6E^0x7F,0x74^0x7F,0x72^0x7F,0x6F^0x7F,0x6C^0x7F,0x53^0x7F,0x65^0x7F,0x74^0x7F,
    0x5C^0x7F,0x53^0x7F,0x65^0x7F,0x72^0x7F,0x76^0x7F,0x69^0x7F,0x63^0x7F,0x65^0x7F,0x73^0x7F,
    0x5C^0x7F,0x43^0x7F,0x6F^0x7F,0x72^0x7F,0x65^0x7F,0x5F^0x7F,0x61^0x7F,0x63^0x7F,
    0x5C^0x7F,0x48^0x7F,0x77^0x7F,0x69^0x7F,0x64^0x7F
};
static const UCHAR kEncPrior[] = {
    0x53^0x7F,0x6D^0x7F,0x62^0x7F,0x69^0x7F,0x6F^0x7F,0x73^0x7F,0x50^0x7F,0x72^0x7F,0x69^0x7F,0x6F^0x7F,0x72^0x7F
};
static const UCHAR kEncEpoch[] = {
    0x53^0x7F,0x6D^0x7F,0x62^0x7F,0x69^0x7F,0x6F^0x7F,0x73^0x7F,0x45^0x7F,0x70^0x7F,0x6F^0x7F,0x63^0x7F,0x68^0x7F
};
static const UCHAR kEncBoots[] = {
    0x53^0x7F,0x6D^0x7F,0x62^0x7F,0x69^0x7F,0x6F^0x7F,0x73^0x7F,0x42^0x7F,0x6F^0x7F,0x6F^0x7F,0x74^0x7F,0x73^0x7F
};

static ULONG64 HwidFingerprint(const SMBIOS_PARSED *p)
{
    if (!p) return 0;

    UCHAR buf[sizeof(SMBIOS_PARSED)];
    RtlCopyMemory(buf, p, sizeof(buf));

    return CoreFnv1a64(buf, sizeof(buf));
}

static NTSTATUS OpenOrCreate(PHANDLE outKey)
{
    if (!AcZwOpenKey || !AcZwCreateKey) return STATUS_NOT_FOUND;

    WCHAR pathBuf[96];
    CoreStrDecodeW(kEncRegPath, sizeof(kEncRegPath), HIST_XOR, pathBuf, ARRAYSIZE(pathBuf));

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, pathBuf);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS s = AcZwOpenKey(outKey, KEY_READ | KEY_WRITE, &oa);
    if (NT_SUCCESS(s)) return s;

    ULONG disp = 0;
    return AcZwCreateKey(outKey, KEY_READ | KEY_WRITE, &oa, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &disp);
}

static NTSTATUS ReadQword(HANDLE key, const UCHAR *enc, SIZE_T encLen, ULONG64 *out)
{
    if (!AcZwQueryValueKey) return STATUS_NOT_FOUND;

    WCHAR name[32];
    CoreStrDecodeW(enc, encLen, HIST_XOR, name, ARRAYSIZE(name));

    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, name);

    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG64)];
    ULONG got = 0;

    NTSTATUS s = AcZwQueryValueKey(key, &vn, KeyValuePartialInformation,
                                   buf, sizeof(buf), &got);
    if (!NT_SUCCESS(s)) return s;

    PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    if (kv->Type != REG_QWORD || kv->DataLength < sizeof(ULONG64)) return STATUS_OBJECT_TYPE_MISMATCH;

    *out = *(ULONG64 *)kv->Data;
    return STATUS_SUCCESS;
}

static NTSTATUS ReadDword(HANDLE key, const UCHAR *enc, SIZE_T encLen, ULONG *out)
{
    if (!AcZwQueryValueKey) return STATUS_NOT_FOUND;

    WCHAR name[32];
    CoreStrDecodeW(enc, encLen, HIST_XOR, name, ARRAYSIZE(name));

    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, name);

    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG got = 0;

    NTSTATUS s = AcZwQueryValueKey(key, &vn, KeyValuePartialInformation,
                                   buf, sizeof(buf), &got);
    if (!NT_SUCCESS(s)) return s;

    PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    if (kv->Type != REG_DWORD || kv->DataLength < sizeof(ULONG)) return STATUS_OBJECT_TYPE_MISMATCH;

    *out = *(ULONG *)kv->Data;
    return STATUS_SUCCESS;
}

static NTSTATUS WriteQword(HANDLE key, const UCHAR *enc, SIZE_T encLen, ULONG64 v)
{
    if (!AcZwSetValueKey) return STATUS_NOT_FOUND;

    WCHAR name[32];
    CoreStrDecodeW(enc, encLen, HIST_XOR, name, ARRAYSIZE(name));

    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, name);
    return AcZwSetValueKey(key, &vn, 0, REG_QWORD, &v, sizeof(v));
}

static NTSTATUS WriteDword(HANDLE key, const UCHAR *enc, SIZE_T encLen, ULONG v)
{
    if (!AcZwSetValueKey) return STATUS_NOT_FOUND;

    WCHAR name[32];
    CoreStrDecodeW(enc, encLen, HIST_XOR, name, ARRAYSIZE(name));

    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, name);
    return AcZwSetValueKey(key, &vn, 0, REG_DWORD, &v, sizeof(v));
}

NTSTATUS HwidHistoryEvaluate(const SMBIOS_PARSED *parsed, PWIRE_HWID_HISTORY out)
{
    if (!parsed || !out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(out, sizeof(*out));

    out->CurrentFingerprint = HwidFingerprint(parsed);
    out->BootCookie         = CoreBootCookie();

    HANDLE key = NULL;
    NTSTATUS s = OpenOrCreate(&key);
    if (!NT_SUCCESS(s))
    {
        out->Flags |= HWID_HISTORY_FLAG_REG_FAIL;
        return s;
    }

    ULONG64 prior = 0;
    ULONG   boots = 0;
    ULONG   epoch = 0;

    NTSTATUS sp = ReadQword(key, kEncPrior, sizeof(kEncPrior), &prior);
    (VOID)ReadDword(key, kEncBoots, sizeof(kEncBoots), &boots);
    (VOID)ReadDword(key, kEncEpoch, sizeof(kEncEpoch), &epoch);

    if (!NT_SUCCESS(sp))
    {
        out->Flags |= HWID_HISTORY_FLAG_FIRST_SEEN;
        out->PriorFingerprint = 0;
        out->BootsSinceChange = 0;
        out->PriorSeenEpoch   = 0;

        (VOID)WriteQword(key, kEncPrior, sizeof(kEncPrior), out->CurrentFingerprint);
        (VOID)WriteDword(key, kEncBoots, sizeof(kEncBoots), 1);
        (VOID)WriteDword(key, kEncEpoch, sizeof(kEncEpoch), 1);
    }
    else
    {
        out->PriorFingerprint = prior;
        out->PriorSeenEpoch   = epoch;

        if (prior != out->CurrentFingerprint)
        {
            out->Flags |= HWID_HISTORY_FLAG_CHANGED;
            out->BootsSinceChange = 0;

            (VOID)WriteQword(key, kEncPrior, sizeof(kEncPrior), out->CurrentFingerprint);
            (VOID)WriteDword(key, kEncBoots, sizeof(kEncBoots), 1);
            (VOID)WriteDword(key, kEncEpoch, sizeof(kEncEpoch), epoch + 1);
        }
        else
        {
            out->BootsSinceChange = boots + 1;
            (VOID)WriteDword(key, kEncBoots, sizeof(kEncBoots), boots + 1);
        }
    }

    ZwClose(key);
    return STATUS_SUCCESS;
}
