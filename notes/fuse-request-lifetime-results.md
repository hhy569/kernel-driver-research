# FUSE Request-Lifetime Study — Results

**Target:** Linux kernel **6.8.0**, `fs/fuse` in-kernel client
**Date:** 2026-09-18
**Class:** kernel object-lifetime / concurrency invariant testing
**Harness:** direct `/dev/fuse` driver, **no libfuse**
**Result:** deterministic L1/L2/L3 and probabilistic L4 interleavings all
preserve the documented request-lifetime invariants under Generic KASAN
(**92/92 instances clean**). Honest negative result within the defined scope.

---

## 1. Summary

We rebuilt the FUSE request state machine and queue topology from source and
built a userspace daemon (`fuse-lifetime/harness/`) that parks kernel requests
in specific phases and forces the teardown / interrupt / completion orderings
that `fs/fuse/dev.c` itself flags as delicate. Two orderings of the
interrupt-vs-completion race are reproduced **deterministically**, and a
locked-copy-vs-abort window is exercised probabilistically with page-fault
widening. Across the KASAN matrix there was no use-after-free, double
`fuse_request_end()`, stale interrupt entry, `fpq->io` leak /
`WARN_ON(!list_empty(io))`, refcount or list-corruption report, and no hang.

This is the second application of the same lifetime-invariant methodology in
this repository (after `tpm_vtpm_proxy`), demonstrating that the approach
transfers across unrelated kernel subsystems.

## 2. Environment (hash-pinned)

| Item | Value |
|------|-------|
| Kernel | `Linux version 6.8.0 (yhh@yhh) (gcc Ubuntu 13.3.0-6ubuntu2~24.04.1, GNU ld 2.42) #2 SMP PREEMPT_DYNAMIC Fri Sep 18 04:17:07 UTC 2026` |
| bzImage sha256 | `c0fcd8c20376a40c73d0dd62e30ac7339391854a9a240d090d511a0e687d1631` |
| `.config` sha256 | `5f8b7856839a8801a2f85fe0ee019ea5921a9ebf7c31a1042aa4cec250dd7fd8` |
| Key knobs | `CONFIG_FUSE_FS=y`, `CONFIG_KASAN=y`, `CONFIG_KASAN_GENERIC=y`, `CONFIG_VIRTIO_FS=n`, `CONFIG_FUSE_DAX=n`, `CONFIG_USERFAULTFD=n` |
| Hypervisor | QEMU 8.2.2, TCG (no nested KVM), `-m 3072 -smp 2`, `nokaslr kasan=1 kasan_multi_shot=1 loglevel=7` |
| initramfs | busybox rootfs + static harnesses, autorun per `tests=<tag>` |
| Host cross-check | same static binaries on the Ubuntu 24.04 host kernel, dynamic + static runs |

KASAN initialisation banner appears 3× per boot (per-CPU/early init), and is
grep-confirmed before any test runs.

## 3. Scenarios and what they prove

| Case | Forced state | Action | Key evidence |
|------|--------------|--------|--------------|
| L1 | `FR_PENDING`, never read | abort | `open_errno=103 (ECONNABORTED), hung=0` |
| L2 | `FR_SENT`/processing, held | abort while held | `held_op=14, open_errno=103, hung=0` |
| L3-I1 | `FR_INTERRUPTED`, interrupt consumed first | INTERRUPT→`EAGAIN`, then reply original | `saw_interrupt=1, intr_target=1, read_rc=39 (full payload), hung=0` |
| L3-I2 | original FINISHED first | reply original, then drain INTERRUPT | `saw_interrupt=0` (interrupt correctly dropped post-FINISH), `read_rc=39, hung=0` |
| L4 | `FR_LOCKED` during reply copy | concurrent abort, random 0–2.5 ms, fault-widened buffer | every iteration bounded, `hung=0`, no `WARN_ON(io)`/KASAN |

L3 is the centrepiece: a `SIGUSR1` to a blocked reader drives
`request_wait_answer()` → `queue_interrupt()`; the daemon's next read returns
the `FUSE_INTERRUPT` request first (interrupt-queue priority) with
`fuse_interrupt_in.unique == original.unique`. I1 verifies the
interrupt-then-finish ordering (EAGAIN re-queue, then successful original
completion with no data loss); I2 verifies finish-then-interrupt (the post-barrier
removal of `intr_entry`). Both are reproducible on every run, not probabilistic.

## 4. KASAN boot matrix

| Boot (`tests=`) | Contents | PASS | FAIL | HANG |
|-----------------|----------|------|------|------|
| `fuse` | smoke + L1/L2/L3-I1/L3-I2 **×10** (40) + L4 ×12 | 52 | 0 | 0 |
| `fuse_l4` | L4 locked-copy × abort **×40** | 40 | 0 | 0 |
| **Total** | | **92** | **0** | **0** |

Serial artifacts:

- `traces/fuse_boot_matrix.serial` — sha256
  `f7dbad09af67e958e3d1c7137ac8a913bbf3d034629a893cabf2c4e66976d128`
- `traces/fuse_boot_l4stress.serial` — sha256
  `9e1eed4e55d03b7cce1e6616ff1d941823d2bb53768a0b2eaadf264a7309badd`

Triage greps for `KASAN:|BUG:|Oops|use-after-free|out-of-bounds|double-free|
refcount under/overflow|list_del corruption|WARNING … fs/fuse|general protection|
kernel panic`; the only matched lines are the KASAN *initialisation* banners
and the unrelated QEMU/TCG `..MP-BIOS bug: 8254 timer not connected to
IO-APIC` virtual-hardware notice. There is **no** `fs/fuse` `WARN/BUG/KASAN`
line in either log.

### Engineering issues found and fixed in the harness (not kernel bugs)

1. Reading `/dev/fuse` before `mount(2)` associates the fd returns `EPERM`;
   the daemon now spins until connected instead of exiting.
2. FUSE **READ** replies are `fuse_out_header + raw data` (no
   `fuse_write_out`; that struct belongs to WRITE) — adding it shifted the
   payload by 8 bytes; fixed and verified against `file.c`
   (`out_numargs=1, out_args[0].size=count`).
3. On the minimal initramfs the sysfs `…/abort` control file is not usable
   (`waiting=-1`); abort is therefore also performed by releasing the last
   `/dev/fuse` fd, which runs `fuse_dev_release() → fuse_abort_conn()`. Both
   primitives are implemented and cross-checked. This also removed
   close-time hangs on gated connections in the guest.

These are recorded because reproducing the harness from scratch should not
re-derive them, and they show the wire protocol facts were verified at runtime.

## 5. Scope of the negative result

The matrix covers pending/processing/interrupted/locked-copy teardown for the
normal request path, both interrupt orderings, and a probabilistic copy/abort
window. It does **not** cover: malformed `fuse_out_header`/variable-arg length
arithmetic, `FUSE_BATCH_FORGET` × interrupt (planned L5), notifications,
background/readahead/write-back I/O, DAX/virtio-fs, or mount-option parsing.
The correct conclusion is:

> Within the explicitly defined state, teardown and interrupt interleaving
> space — and the L4 probabilistic copy window — no memory-safety or
> object-lifetime violation was observed under Generic KASAN on Linux 6.8.

No CVE is claimed, no patch is implied, and "no crash" is not reported as "no
bug".

## 6. Reproduction

```sh
# static binaries (no libfuse)
cd fuse-lifetime/harness
gcc -O2 -static -pthread -o fuse_smoke    fuse_smoke.c    fuse_session.c
gcc -O2 -static -pthread -o fuse_lifetime fuse_lifetime.c fuse_session.c
gcc -O2 -static -pthread -o fuse_l4       fuse_l4_copyabort.c fuse_session.c

# host (mount-capable shell)
sudo ./fuse_smoke; sudo ./fuse_lifetime 10; sudo ./fuse_l4 50

# KASAN matrix: place binaries + rootfs-init/init in the initramfs, then
./run_qemu.sh auto traces/boot_fuse_matrix.log 480 fuse
./run_qemu.sh auto traces/boot_fuse_l4.log    360 fuse_l4
```

## 7. Portfolio takeaway

The study demonstrates the ability to (a) reconstruct a kernel subsystem's
concurrency state machine and list topology from source, (b) reach each named
state deterministically through the documented userspace ABI, (c) drive both
orderings of a real cancellation race and a locked-copy teardown race, and
(d) report a clean, hash-pinned KASAN matrix as a precisely scoped negative
result rather than inflating it — the same evidence discipline used on the
vtpmx work.
