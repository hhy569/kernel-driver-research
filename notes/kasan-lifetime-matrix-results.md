# KASAN-Verified Object-Lifetime Study of `tpm_vtpm_proxy` (Linux 6.8)

**Component:** `drivers/char/tpm/tpm_vtpm_proxy.c` (vtpmx, `/dev/vtpmx`) + TPM core
(`tpm-chip.c`, `tpm-dev-common.c`, `tpm-dev.c`, `tpmrm-dev.c`, `tpm2-cmd.c`)
**Question:** does the two-fd virtual-TPM device model (an anonymous server fd
`[vtpms]` plus the client `/dev/tpmN` raw and `/dev/tpmrmN` resource-manager nodes) hold
its object-lifetime, fd-reference, RM-space-separation and concurrent register/teardown
invariants under deterministic and stressed interleavings?
**Method:** static invariant closure → deterministic gated interleavings → concurrent
device-pool churn, executed on a **Generic KASAN** kernel (multi-shot) under QEMU/TCG.

This is a **verification / negative-result** study. No memory-safety violation was
observed in the defined interleaving space; per the research contract that is reported
as "no violation observed under these conditions", **not** as "the driver is bug-free".

## 1. Environment (reproducibility)

| Item | Value |
|---|---|
| Kernel | Linux 6.8.0, `#1 SMP PREEMPT_DYNAMIC`, built Fri Sep 18 03:07:56 UTC 2026 |
| Compiler | gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld 2.42 |
| Hypervisor | QEMU 8.2.2, TCG (no KVM in nested VirtualBox), `-m 3072 -smp 2` |
| Sanitizer | `CONFIG_KASAN=y`, `KASAN_GENERIC`, outline, `kasan-stack`, `kasan_multi_shot=1` |
| Cmdline | `console=ttyS0 nokaslr panic=-1 kasan=1 kasan_multi_shot=1 loglevel=7 autorun=1 tests=<TAG>` |
| `.config` sha256 | `664e2c41d98d9c6dacc47f227d251c647a8cb84b118c4d981aa3aaa8988cc421` |
| `bzImage` sha256 | `bea0c582b90c2856a77fb13ebf4fcdbdb298c1fd6cfa3437bd5f23944b499787` |
| Driver built-in | `CONFIG_TCG=y`, `CONFIG_TCG_VTPM_PROXY=y` (RM `tpmrm-dev.o` linked under `CONFIG_TCG_TPM=y`) |

Each test subset runs in its own isolated boot selected by `tests=<TAG>`; serial logs are
`t traces/boot_<TAG>.serial`, classified by `tools/kasan_triage.sh` (separates **KERNEL
HEALTH** — dmesg KASAN/BUG/Oops/UAF/OOB/refcount — from **HARNESS HEALTH** — PASS /
ASSERT_FAIL / ENV_ABORT / hang).

## 2. Harness inventory

| Harness | Surface |
|---|---|
| `vtpmx_probe` | Device model, fixed 20-byte ioctl, capability/flag rejection, auto-startup, node creation |
| `vtpmx_race` (v2) | 13 deterministic gated interleavings (pipe-controlled emulator scheduling) |
| `vtpmx_err` | 8 error/teardown paths |
| `vtpmx_async` | 6 NONBLOCK async-work cases incl. running-teardown cancel (R4c) and release flush (R10) |
| `vtpmx_lifetime` (v2) | L1 dup refs · L2 RM orphan across teardown · L3-Q pending/early close ×15 · L3-R running close ×3 · L4 raw+RM coexist · L5 RM multi-open A/B/C |
| `vtpmx_stress` (v2) | 6-slot / 4-worker device pool, concurrent client I/O + full register/unregister churn |
| `vtpm2_emu.h` | Shared minimal **semantic** TPM2 userspace emulator (see §3) |

Exit-code / output contract: `0 PASS`, `1 ASSERT_FAIL`, `2 ENV_ABORT`, `3 HARNESS/HANG`;
every harness emits a machine-readable `RESULT:` line.

## 3. Key engineering finding — why a "successful" fake TPM never created `/dev/tpmrmN`

A first emulator returned a 10-byte `TPM_RC_SUCCESS` to every command. The raw node
appeared, but the **resource-manager node never did**, which silently disabled every
RM test (L2/L4/L5). Root-causing this through source + runtime:

```
tpm_chip_register() -> tpm_chip_bootstrap() -> tpm_auto_startup() -> tpm2_get_cc_attrs_tbl()
  -> tpm2_get_tpm_pt(TPM_PT_TOTAL_COMMANDS)
       parses TPM2_GetCapability body; property_cnt == 0  -> -ENODATA
  -> rc<0 && rc != -ENOMEM:
       dev_warn "TPM in field failure mode, requires firmware upgrade"
       set TPM_CHIP_FLAG_FIRMWARE_UPGRADE
tpm_add_char_device():
  if (TPM2 && !tpm_is_firmware_upgrade())  tpm_devs_add(chip);   // <-- SKIPPED
```

The empty GetCapability body made `property_cnt` read as 0, flipping the
"firmware upgrade" flag and gating RM-node creation at `tpm-chip.c:426`. The fix was a
**grammar-aware** emulator (`vtpm2_emu.h`) that answers the bootstrap set — SelfTest and
GetCapability(TPM_PROPERTIES with `TPM_PT_TOTAL_COMMANDS`, COMMANDS with four `TPMA_CC`,
PCRS) — using the kernel's own response offsets (body@10: moreData u8, capability u32@11,
count u32@15, payload@19). After this, both `/dev/tpmN` (10:224+) and `/dev/tpmrmN`
(misc 253:65536+) appear and the chip registers healthy. This is a harness/modelling
result that demonstrates end-to-end understanding of the TPM chip-registration state
gates; it is not a kernel defect.

## 4. Boot matrix (Generic KASAN)

| Boot (`tests=`) | Harness result | KASAN/BUG/Oops/UAF/OOB/refcount | DONE |
|---|---|---|---|
| `boot0` | sanity only | 0 | yes |
| `probe` | PASS (uinput + vtpmx) | 0 | yes |
| `race` | PASS (13/13 gated) | 0 | yes |
| `err` | PASS (8/8) | 0 | yes |
| `async` | PASS (6/6) | 0 | yes |
| `lifetime` | **RESULT: PASS — pass=6 fail=0 env=0 hang=0** | 0 | yes |
| `stress` | **RESULT: PASS** | 0 | yes |

`kasan_triage.sh` aggregate exit status: **0** (`OVERALL: NO KERNEL MEMORY-SAFETY
FINDING IN THESE BOOTS`). Every boot shows `kasan: KernelAddressSanitizer initialized`.

### 4.1 Lifetime cases (all OK under KASAN)

- **L1** closing one `dup()` reference keeps the chip alive and serviceable through the
  other; closing the last server reference tears it down.
- **L2** an RM client held open across chip teardown issues only bounded, failing
  operations afterward (no hang / no UAF).
- **L3-Q ×15** NONBLOCK command enqueued then immediate teardown — samples the
  pending/early-running window; every client is promptly woken (the exact kernel-worker
  scheduling instant is **not** userspace-pinnable, and this is stated rather than
  claimed as a deterministic "pending").
- **L3-R ×3** deterministic **RUNNING** teardown: the emulator is gated (via pipes)
  exactly after it reads the command, parking the work in `WAIT_RESPONSE`; closing the
  server fd cancels the op and wakes the client.
- **L4** one raw and one RM client in flight together across teardown — prompt, bounded.
- **L5** RM multi-open: A/B/C opens, close A, B/C survive, close B, C survives; the chip
  stays alive until the server fd itself closes (per-open RM space isolation).

### 4.2 Concurrent churn (R7 device pool)

| Run | wall | client ops | full register/unregister cycles | unexpected errno | stray nodes |
|---|---|---|---|---|---|
| stock kernel, 45 s | 45 s | 4056 | 1719 | 0 | 0 |
| **Generic KASAN, 30 s** | 30 s | **1460** | **578** | **0** | **0** |

KASAN/TCG lowers throughput as expected; the device pool still performs hundreds of
complete create→both-nodes-ready→teardown cycles with zero unexpected error codes and
zero leftover `/dev/tpmN` / `/dev/tpmrmN` nodes each run.

## 5. Teardown invariant (static closure, dynamically corroborated)

`tpm_del_char_device()` orders: `cdev_device_del()` (blocks new opens) →
`idr_replace(... NULL)` → `down_write(ops_sem)` (waits all in-flight ops) →
`tpm2_shutdown()` → `ops = NULL` → refcount-driven free. The server-side
`fops_release -> delete_device` first stops the async work, then (if registered) calls
`tpm_chip_unregister()`. All fixed copy points use the embedded `u8 buffer[4096]` under
`buf_lock` with a 4096 check; there is no user-sized dynamic allocation, so the
integer-overflow → undersized-allocation class does not apply here. The harness teardown
ordering (FREE: stop+join emulator then close server fd; GATED-RUNNING: park emulator on
a control pipe, close server fd to cancel, then stop+join) was derived from, and matches,
the driver's own synchronization.

## 6. Scope of the conclusion

**Observed:** across fixed-ioctl boundary checks, 13 gated races, 8 error paths, 6 async
cases, 6 lifetime/RM scenarios, and 578 KASAN-instrumented register/teardown cycles (1719
on stock), no KASAN report, BUG, Oops, UAF, out-of-bounds access, refcount warning, hang,
or node leak.

**Not claimed:** exhaustive coverage of all possible schedules; correctness under
KCSAN data-race modelling; behaviour of deeper TPM2 command/state grammar beyond the
bootstrap subset; or any proof of absence of bugs. Mature syzkaller-covered drivers are
expected to pass exactly this class of fixed-surface invariant test; the contribution is
the **reproducible methodology and the registration-gate analysis**, not a new CVE.

## 7. Reproduction

```sh
# build (Generic KASAN .config as in §1), then on the research VM:
./run_qemu.sh auto traces/boot_lifetime.serial 420 lifetime
./run_qemu.sh auto traces/boot_stress.serial   420 stress
bash tools/kasan_triage.sh traces/boot_*.serial   # exit 10 => kernel finding
```

## 8. Next target (planned)

**FUSE Request Lifetime Study** (requires a lightweight rebuild with
`CONFIG_FUSE_FS=y`): focus on request-pending × abort, interrupt × original completion,
and copy-to-userspace in progress × abort (a request must not be freed while its
`fuse_req` is still referenced) — applying the same static-gate → deterministic-gated
harness → KASAN matrix pipeline used here.
