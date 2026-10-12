# Core_ac — Kernel Anti-Cheat

A Windows x64 kernel-mode anti-cheat driver designed for competitive multiplayer titles. Core_ac is a self-contained reference implementation focused on clean modular architecture, verifiable detection techniques, and a hardened user-mode channel protected by per-session AES-GCM sealing.

> **Status:** Reference implementation. Everything in this tree compiles against the Windows WDK and the Visual Studio 2022 kernel-mode toolset. There are no stubs, no VM shims, and no vendored third-party crypto — all cryptography is delegated to the Windows CNG (`BCrypt*`) kernel surface.

---

## 1. Why Core_ac

Modern anti-cheats are judged by three qualities:

1. **Correctness in the kernel.** Allocations are NX-tagged, callbacks are symmetrical, every acquired resource has a clear owner, and dispatch respects IRQL.
2. **Resistance to tampering.** Boot-time secrets live as XOR-pairs, the LSTAR MSR is tracked across every IOCTL *and* from NMI context, and the control device is DACL-locked to SYSTEM + Administrators only.
3. **Observability without blind spots.** Image loads, process creation, PML4 drift, BYOVD loads, and HWID state all surface as typed wire records on a lock-free SPSC ring that user mode drains via `IOCTL_AC_EVENT_POLL`.

Core_ac is structured so each of those three qualities can be audited independently: no module reaches into another's private state, every subsystem exposes a short `*_Init` / `*_Shutdown` lifetime, and the only global state lives in a single `CORE_AC_GLOBAL`.

---

## 2. Architecture at a glance

```
                      ┌──────────────────────────────────────────────┐
                      │              DriverEntry (sync)              │
                      │  ├─ init boot cookie (XOR pair)              │
                      │  ├─ env gates (SafeBoot / debugger)          │
                      │  └─ queue deferred init worker               │
                      └──────────────────┬───────────────────────────┘
                                         │
                                         ▼
   ┌─────────────────────────────────────────────────────────────────────────┐
   │                        Deferred init worker (passive)                   │
   │  IoCreateDevice ──► \Device\CoreAC + \??\CoreAC (symlink)               │
   │  IoCreateDevice ──► \Device\CoreAC_EVT (event poll surface)             │
   │  ObSetSecurity   ──► DACL: SYSTEM + Admins only                         │
   │  ChannelInit  CryptoInit  EventsInit                                    │
   │  AcTamperArm (LSTAR snapshot)   NmiWatchdogRegister                     │
   │  PsSetLoadImageNotifyRoutine                                            │
   │  PsSetCreateProcessNotifyRoutineEx                                      │
   │  KldrSnapshotModules  Pml4InitSnapshot                                  │
   │  ByovdScannerInit  HwidCollectBoot                                      │
   │  PsCreateSystemThread ──► CorePollWorker (heartbeat timer loop)         │
   └─────────────────────────────────────────────────────────────────────────┘
```

Only `DriverEntry` runs synchronously. Device registration, callback installation, and detection pipelines boot from a worker so static analysis of the entry point never reveals the full surface.

---

## 3. Module map

| File | Role |
|---|---|
| `driver_entry.c` | DriverEntry, deferred init worker, DACL hardening, DriverUnload, callback plumbing |
| `anti_tamper.{c,h}` | Boot cookie XOR-pair, LSTAR / DEBUGCTL / stack-cookie checks |
| `nmi_watchdog.{c,h}` | NMI callback + cross-CPU sweep via `HalSendNMI` |
| `env_checks.{c,h}` | Safe boot, hypervisor cpuid gate, kernel-debugger probe, module enumeration |
| `ioctl.{c,h}` | Major function dispatch and IOCTL handlers |
| `channels.{c,h}` | SPSC event ring, blob intake surface |
| `wire_records.{c,h}` | Typed record layouts (heartbeat, process attach, image load, BYOVD, PML4 anomaly, tamper, HWID) |
| `events.{c,h}` | Record producers for the detection pipelines |
| `crypto.{c,h}` | CNG-backed SHA-256, random, AES-GCM session sealing, ECDH-P256 handshake |
| `byovd_scanner.{c,h}` | Baked substring blacklist of 60+ vulnerable drivers (BYOVD) |
| `driver_ts_blacklist.{c,h}` | PE `TimeDateStamp` denylist |
| `kldr.{c,h}` | Kernel module inventory, FNV1a64 fingerprints, diff rescan |
| `pml4_scan.{c,h}` | Physical PML4 walker via `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)` |
| `physmem.{c,h}` | Physical-memory read helper |
| `smbios.{c,h}` | SMBIOS table parse (BIOS, system, baseboard, memory) via `ZwQuerySystemInformation(RSMB)` |
| `hwid.{c,h}` | SMBIOS roll-up, ACPI enumeration, composite SHA-256 digest |
| `game_integrity.{c,h}` | Per-image load PE validation, hooks `CiValidateFileObject` when available |
| `usermod.{c,h}` | User-mode module walker (PEB `InLoadOrderModuleList`) |
| `strings.{c,h}` | Kernel-safe string primitives, FNV1a 32/64, memmem, hex formatter |
| `core.h` | Shared types, pool tags, device names, status codes |
| `imports.h` | NT/ZW signatures not exposed by the WDK headers |

---

## 4. Boot flow

```
DriverEntry
 ├─ AcTamperInitBootCookie()
 │    perf = KeQueryPerformanceCounter()
 │    tsc  = __rdtsc()
 │    seed = perf ^ tsc ^ (pid << 17)
 │    BootCookie[0] = seed
 │    BootCookie[1] = ~seed          // XOR pair: a ^ b == -1
 │
 ├─ EnvRunBootGates()
 │    ├─ InitSafeBootMode  → fail if non-zero
 │    └─ ZwQuerySystemInformation(SystemKernelDebuggerInformation)
 │       → fail if KernelDebuggerEnabled && !KernelDebuggerNotPresent
 │
 └─ ExQueueWorkItem(CoreDeferredInit, CriticalWorkQueue)
        ├─ CoreCreateDevices()                 \Device\CoreAC + \Device\CoreAC_EVT
        ├─ CoreApplyDeviceDacl()               SYSTEM + Admins GENERIC_ALL, deny-all otherwise
        ├─ ChannelInit() CryptoInit() EventsInit()
        ├─ AcTamperArm()                       snapshot LSTAR (0xC0000082)
        ├─ NmiWatchdogRegister()               KeRegisterNmiCallback
        ├─ PsSetLoadImageNotifyRoutine         image-load pipeline
        ├─ PsSetCreateProcessNotifyRoutineEx   process-create pipeline
        ├─ KldrSnapshotModules()               full kernel-module inventory + PE timestamps
        ├─ Pml4InitSnapshot()                  copy current CR3 PML4 via physical read
        ├─ ByovdScannerInit()                  prime FNV1a64 of blacklist
        ├─ GameIntegrityInit()                 resolve CiValidateFileObject if present
        ├─ HwidCollectBoot()                   SMBIOS fanout → wire record HWID_HELLO
        └─ CoreStartWorker()                   30 s heartbeat loop
```

---

## 5. Device + DACL hardening

| Object | Path | Access |
|---|---|---|
| Control device | `\Device\CoreAC` (`\??\CoreAC`) | SYSTEM, Administrators — everyone else denied |
| Event device   | `\Device\CoreAC_EVT`              | SYSTEM, Administrators — everyone else denied |

The DACL is applied with `ObSetSecurityObjectByPointer` after device creation. Both ACEs are `GENERIC_ALL`; everyone else inherits the empty DACL and gets no access. Standard anti-cheat practice: user-mode companion runs as a SYSTEM service, nothing else can `CreateFile` on the device.

---

## 6. Anti-tamper

Three complementary checks:

1. **LSTAR (`0xC0000082`).** Snapshotted during `AcTamperArm` into an XOR-pair. On every IOCTL dispatch and every NMI callback the current value is compared to the reference. Mismatch → tamper event is enqueued and the MSR is rewritten to the known-good value.
2. **DEBUGCTL (`0x1D9`).** The LBR bit is checked from NMI context. If userland or a hypervisor flipped it to steal callstacks, we observe it where we can't be masked.
3. **Stack cookie.** A per-boot XOR-pair derived from `__rdtsc`. Mismatch is routed through the tamper event producer.

Boot cookie, LSTAR reference and stack cookie are stored exclusively as XOR-pairs so a lazy scanner looking for the live value by signature finds nothing.

---

## 7. Detection surfaces

### 7.1 BYOVD scanner

Catches vulnerable drivers using two independent signals:

- **Substring match (lowercase case-fold Unicode).** 60+ well-known BYOVD names baked in: `winring0`, `rtcore64`, `mhyprot2`, `dbutil_2_3`, `iqvw64`, `winio`, `phymem`, `atillk64`, `rwdrv`, and so on.
- **PE `TimeDateStamp` denylist.** `driver_ts_blacklist.c` carries timestamps known to belong to signed-but-weaponizable drivers.

Both signals produce `WIRE_REC_BYOVD_HIT` records tagged with `ImageBase`, `ImageSize`, the matched path, and a path FNV1a64.

### 7.2 PML4 physical walker

Reads the current CR3-pointed PML4 page via `MmCopyMemory` with `MM_COPY_MEMORY_PHYSICAL`. This bypasses virtual-address hooks placed by non-root hypervisors or EPT shadows. The initial snapshot is compared against each rescan; drift surfaces as `WIRE_REC_PML4_ANOMALY` records with observed vs. expected entries and the physical base.

### 7.3 HWID collection

Through `ZwQuerySystemInformation(SystemFirmwareTableInformation)` using the `'RSMB'` provider. The parser walks SMBIOS entry types 0, 1, 2, and 17 to extract BIOS vendor, system manufacturer, product, baseboard serial, system UUID, and memory module count. The ACPI enumerator runs best-effort — VBS/HVCI systems may return `STATUS_NOT_IMPLEMENTED`, which the caller tolerates.

A composite digest (SHA-256 over the parsed structure) is cached and emitted as `WIRE_REC_HWID_HELLO`.

### 7.4 Image + process callbacks

- `PsSetLoadImageNotifyRoutine` demultiplexes into kernel-image path (BYOVD scanner, module inventory diff) and user-image path (`WIRE_REC_IMAGE_LOAD`).
- `PsSetCreateProcessNotifyRoutineEx` produces `WIRE_REC_PROCESS_ATTACH` (with parent PID + image path) and `WIRE_REC_PROCESS_EXIT` on teardown.

---

## 8. Wire protocol

All records share a common header:

```c
struct WIRE_RECORD_HEADER {
    uint32_t Magic;        // 'rCaC' (0x43416352)
    uint8_t  Version;      // 1
    uint8_t  Type;         // WIRE_REC_*
    uint16_t Flags;
    uint32_t Length;       // payload length in bytes
    uint64_t Sequence;     // monotonically increasing
    uint64_t Timestamp;    // KeQuerySystemTimePrecise
    uint8_t  Payload[Length];
};
```

Payload types in this build:

| Code | Name | Payload |
|---:|---|---|
| `0x02` | `TEARDOWN` | 1 byte |
| `0x12` | `PML4_ANOMALY` | `WIRE_PML4_ANOMALY` |
| `0x1E` | `PROCESS_ATTACH` | `WIRE_PROCESS_ATTACH` |
| `0x1F` | `PROCESS_EXIT` | `uint64_t pid` |
| `0x24` | `HEARTBEAT` | `WIRE_HEARTBEAT` |
| `0x26` | `IMAGE_LOAD` | `WIRE_IMAGE_LOAD` |
| `0x29` | `BYOVD_HIT` | `WIRE_BYOVD_HIT` |
| `0x2B` | `MODULE_VERIFY` | reserved |
| `0x30` | `TAMPER` | `WIRE_TAMPER` |
| `0x40` | `HWID_HELLO` | `WIRE_HWID_HELLO` |
| `0x41` | `HWID_DISK` | reserved |
| `0x42` | `HWID_MEMORY` | reserved |

User mode drains the ring by issuing `IOCTL_AC_EVENT_POLL` with an output buffer; the driver copies as many whole records as fit and returns the byte count via `IoStatus.Information`.

---

## 9. IOCTL surface

| Code | Name | Direction | Purpose |
|---|---|---|---|
| `0x801` | `IOCTL_AC_PING` | — | Liveness check |
| `0x802` | `IOCTL_AC_BOOTSTRAP` | — | Confirm channel is attached |
| `0x803` | `IOCTL_AC_KEY_EXCHANGE` | 32 in / 32 out | ECDH-P256-based session key handshake |
| `0x804` | `IOCTL_AC_PUSH_SESSION_UUID` | GUID in | Bind driver state to a match UUID |
| `0x805` | `IOCTL_AC_EVENT_POLL` | out | Drain the event ring |
| `0x806` | `IOCTL_AC_PUSH_MATCH` | blob in | Hand match metadata to the driver |
| `0x807` | `IOCTL_AC_MATCH_OVER` | — | Match teardown signal |
| `0x808` | `IOCTL_AC_PUSH_WATCHLIST` | blob in | Dynamic BYOVD watchlist from service |
| `0x809` | `IOCTL_AC_PUSH_PROCESS_PATH` | blob in | Register expected process image path |
| `0x80A` | `IOCTL_AC_PUSH_HASH` | blob in | Expected module hash |
| `0x80B` | `IOCTL_AC_PUSH_VENDOR_CN` | blob in | Trusted signing CN |
| `0x80C` | `IOCTL_AC_PUSH_USB_DEVICE` | blob in | USB device descriptor |
| `0x80D` | `IOCTL_AC_PUSH_U64_SET` | blob in | Opaque u64 configuration constants |
| `0x80E` | `IOCTL_AC_DRIVER_EVENT` | blob in | Companion-origin driver event |
| `0x80F` | `IOCTL_AC_PUSH_CMD` | blob in | Companion → driver command |

Every IOCTL dispatch runs through `AcTamperCheckLstar()` first.

---

## 10. Cryptography

Everything is CNG. No vendored primitives.

| Primitive | Algorithm | Provider |
|---|---|---|
| Hash | SHA-256 | `BCRYPT_SHA256_ALGORITHM` |
| Random | SP800-90 DRBG | `BCRYPT_RNG_ALGORITHM` |
| Symmetric | AES-256-GCM | `BCRYPT_AES_ALGORITHM` + `BCRYPT_CHAIN_MODE_GCM` |
| Key agreement | ECDH-P256 | `BCRYPT_ECDH_P256_ALGORITHM` |

- `CryptoHandshake` finalizes the server-side ECDH key pair, returns the server public, and derives a 32-byte shared secret via SHA-256 over the concatenation of the two public halves. User mode mirrors the derivation.
- `CryptoSealRecord` / `CryptoOpenRecord` wrap AES-GCM with a 12-byte nonce and a 16-byte tag. Nonces are generated per-record from the CNG RNG — never reused.

---

## 11. Build

Requirements:

- Visual Studio 2022 (17.x)
- Windows Driver Kit 10 (any version shipping with VS 2022)
- Target: `x64` only (`Debug|x64`, `Release|x64`)

```powershell
# From a Developer Command Prompt
msbuild Core_ac.sln /p:Configuration=Release /p:Platform=x64
```

Output lands in `build\Release\Core_ac.sys`.

Preprocessor flags:

| Flag | Effect |
|---|---|
| `POOL_NX_OPTIN=1` | Required for NX pool |
| `CORE_AC_DEBUG=1` | Enables `DbgPrintEx` logging (Debug config only) |

Link dependencies: `ntoskrnl.lib`, `hal.lib`, `ksecdd.lib`, `cng.lib`.

---

## 12. Deployment

### 12.1 Development / test machines

1. Enable test-signing: `bcdedit /set testsigning on`, then reboot.
2. Sign the output: `signtool sign /v /ph /fd SHA256 /a build\Release\Core_ac.sys`.
3. Install the service:

   ```powershell
   sc.exe create CoreAc type= kernel binPath= C:\path\to\Core_ac.sys start= demand
   sc.exe start  CoreAc
   ```

4. The user-mode companion opens `\\.\CoreAC` and issues `IOCTL_AC_KEY_EXCHANGE` to bring the session up.

### 12.2 Production

- Submit the driver to the Microsoft Hardware Dev Center for a WHQL signature. HVCI compatibility is intentionally preserved: no self-modifying code, no RWX allocations, no runtime import patching.
- Pin the service `Start` to `SYSTEM_START` (`1`) once you have validated the environment-gate codepath across your target population.

---

## 13. User-mode companion contract

The companion service is expected to:

1. Open `\\.\CoreAC`.
2. Generate an ephemeral ECDH-P256 keypair and send the public to `IOCTL_AC_KEY_EXCHANGE`.
3. Derive the shared secret the same way the driver does (SHA-256 over `client_pub || server_pub`).
4. Issue `IOCTL_AC_PUSH_SESSION_UUID` with the match's GUID.
5. Poll `IOCTL_AC_EVENT_POLL` on a cadence that keeps the ring from wrapping (10–30 Hz is comfortable for competitive sessions).
6. On match end, issue `IOCTL_AC_MATCH_OVER`.

The driver does not initiate outbound traffic. All telemetry flows through poll.

---

## 14. Threat model and limits

Core_ac assumes:

- The attacker runs user-mode code with Administrator privileges and can load signed vulnerable drivers (BYOVD).
- The attacker may install a non-root hypervisor (type-2) and hook virtual addresses.
- The attacker cannot run inside the same ring-0 as Core_ac without first breaking Secure Boot / HVCI, which is explicitly out of scope for the sandbox we validate against.

What Core_ac does **not** try to do:

- It is not an EDR. There is no file-scanning, no YARA, no behavioral ML.
- It does not install inline function hooks or SSDT hooks. Monitoring is strictly via documented notify routines, documented MSR reads, and documented physical-memory APIs.
- It does not implement its own loader or manual mapper.

---

## 15. Code conventions

- Modern C (C11 subset the WDK compiler accepts). No C++.
- Allocations go through `CoreAlloc` / `CoreFree` with per-subsystem pool tags for easy triage in `!poolused`.
- Every subsystem exposes `*_Init` + `*_Shutdown` and is reentrancy-safe at `PASSIVE_LEVEL`.
- No code comments. Documentation lives in this README, in header prototypes, and in commit messages.
- Code style is lowercase-identifier, early-return heavy, `const`-correct, and avoids any pattern that would break obfuscation of the final `.sys` (no RTTI, no C++ exceptions, no indirect calls through generated vtables).

---

## 16. License and authorization

This driver was authored as a reference implementation for authorized anti-cheat security research. Deployment on third-party machines without informed consent is not acceptable use. If you reuse the code for a shipping anti-cheat, make sure your end-user license agreement explicitly covers kernel-level monitoring and that your binaries are signed through the official Microsoft kernel-mode signing path.

---

## 17. Roadmap

Suggested next steps for anyone taking this further:

- Replace the baked BYOVD list with a service-pushed, signature-verified blob delivered through `IOCTL_AC_PUSH_WATCHLIST`.
- Add disk + NIC MAC fingerprinting to the HWID pipeline (`IOCTL_STORAGE_QUERY_PROPERTY`, `NDIS_OID_802_3_PERMANENT_ADDRESS`).
- Thread `CiValidateFileObject` into the kernel-image load path to reject revoked signatures before they execute.
- Add a per-record AES-GCM sealing step on egress through `IOCTL_AC_EVENT_POLL` so the companion never sees plaintext on the wire.
- Add a VBS/HVCI gate that upgrades the HWID pipeline from "best effort" to "required" when the host is already running a Microsoft-measured launch.

---

**Core_ac** — competitive-integrity kernel driver, built to be read before it is trusted.
"# Anti-cheat-Kernel-Driver" 
