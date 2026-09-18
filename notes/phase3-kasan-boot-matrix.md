# Phase 3 → Kernel B (KASAN): review, boot matrix, lifetime harness

Date: 2026-09-18. Reviewer: external senior VR engineer (ChatGPT) on the Phase-3 report.
This note records the decisions that govern the KASAN empirical phase; it is the bridge between
the deterministic stock-kernel harnesses and instrumented runs.

## 1. Review verdict

The Phase-2 question was "can an ioctl input cross a bound?"; Phase-3 asks "can two individually
legal operations, combined in some ordering, violate a kernel invariant?" The static +
deterministic work on vtpmx now spans NEW_DEV → async register work → TPM auto-startup →
client registration → sync/async I/O → client close → server close → teardown. Verdict:
**stop widening the static surface; let the sanitizer answer the last layer.** Do not build
KCSAN, do not switch drivers, do not run every stress case in one boot yet.

## 2. Kernel B configuration (actual `.config`, verified)

- `CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_OUTLINE=y` (outline = smaller image,
  slower than inline — acceptable).
- `CONFIG_UNWINDER_ORC=y` + `CONFIG_STACKTRACE=y` + `CONFIG_KALLSYMS_ALL=y`. ORC (objtool-
  generated) is the native x86_64 unwinder and gives reliable KASAN stacks **without**
  `FRAME_POINTER`; no rebuild needed for that.
- `DEBUG_INFO=n` in round 1 to get a first boot fast. KASAN dmesg still prints symbol+offset via
  kallsyms. If a report lacks the precision needed for source line / GDB, build a **second**
  image with `DEBUG_INFO_DWARF4=y` rather than restarting the current build.
- Trimmed to ~1078 built-in; no disk/EFI/virtio dependency — boot is bzImage + static busybox
  initramfs + `console=ttyS0` + devtmpfs, so the dominant boot risk is the initramfs/init, not
  storage drivers.
- QEMU/TCG (nested VirtualBox has no KVM), `-smp 2 -m 3072`. Generic KASAN reserves ~1/8 of the
  address space as shadow and needs headroom; the host VM has ~5.9 GB with a resident docker
  stack, so 3 GB is the safe guest size (raise if the guest OOMs).
- Cmdline: `console=ttyS0 nokaslr panic=-1 kasan=1 kasan_multi_shot=1 loglevel=7`.
  `kasan_multi_shot=1` keeps reporting after the first invalid access (round 1 maximizes
  observation); **no** `panic_on_warn` in round 1 — an unrelated warning must not kill the run.
- Generic KASAN quarantines freed objects (delays reuse), which is exactly what the
  close→free→stale-reference lifetime cases need; KFENCE is deferred.

## 3. Timing under TCG (scale the harness, never the kernel)

TCG time is not a stable unit (host CPU contention from docker/build changes behaviour). Widen
userspace observation windows, but **do not change the driver's TPM command timeouts** — that
would test a modified kernel, not Linux 6.8. Guidance:

| class | stock | KASAN/TCG guest |
|---|---|---|
| kernel state-transition wait | ~100 ms | ~500 ms |
| emulator response wait | ~1 s | 3–5 s |
| teardown / workqueue | ~0.8 s | ~5 s |
| per-test userspace watchdog | short | 30–60 s, reaped from userspace |

## 4. Isolated boot matrix (one configuration per boot)

Do not pack every harness into a single 1200 s boot: isolation is poor and a failure cannot be
attributed. The initramfs `init` reads `tests=TAG` from /proc/cmdline; `run_qemu.sh auto
LOG SEC TAG` passes it; `wait_and_boot.sh` runs the matrix detached, each boot its own
`boot-<tag>.log`, stopping on the first KASAN memory error (preserve evidence) or the first boot
that fails to print its `DONE tests=<tag>` marker (isolate the failing layer).

| boot | TAG | content | timeout |
|---|---|---|---|
| BOOT-0 | boot0 | banner, `KernelAddressSanitizer initialized`, /dev /proc /sys, clean poweroff | 300 s |
| BOOT-1 | probe | uinput + vtpmx probe (NEW_DEV/emulator/raw/RM/teardown) | 500 s |
| BOOT-2 | race | deterministic R1/R2/R3/R5/matrix/R9 | 700 s |
| BOOT-3 err | err | E1..E4 error-path rollback | 600 s |
| BOOT-3 async | async | NONBLOCK async_work / poll / R4c / R10 / lseek | 700 s |
| BOOT-3 lifetime | lifetime | L1..L4 (see §5) — added after a stock-kernel validation pass | 700 s |
| BOOT-4 | stress | R7 device-pool, one seed per boot (e.g. 0x1337/120 s, then 0x1338) | separate boot |

Each boot is archived with serial log, dmesg summary, harness stdout, exit status, seed and the
`.config` sha1.

## 5. New lifetime / refcount harness — `harness/vtpmx_lifetime.c` (L1–L4)

Requested in review because the highest-value surface of vtpmx is shared-object lifetime:
one `struct proxy_dev` (server `[vtpms]` fd) ↔ one tpm_chip carrying both a raw `/dev/tpmN`
(single-open) and an RM `/dev/tpmrmN` (multi-open, one `file_priv`+`tpmrm_priv/space` each).

- **L1 server-fd `dup()` reference separation.** A=NEW_DEV server fd; B=dup(A); migrate the
  emulator to B; close(A). The device must stay registered and still service a client
  round-trip through B (the two fds share one open-file description; release only fires at the
  last close). Closing B must then tear the device down and remove the node. The emulator
  re-reads its serve fd every loop and ignores POLLNVAL so the A→B migration is race-free.
- **L2 RM client outlives chip teardown.** Open `/dev/tpmrmN`, then close the only server fd
  (chip unregister) while the RM fd remains open. Later RM ops must fail cleanly (EPIPE/EIO,
  never hang), `lseek` stays ESPIPE, and the final `tpmrm_release`
  (common_release + tpm2_del_space + kfree) must not touch freed memory — the open fd holds a
  chip reference that keeps the object alive.
- **L3 rapid NONBLOCK enqueue→immediate close (×30).** Statistically interleaves async work
  that is still queued vs running when `release()->flush_work()` executes; must always return
  with no hang or fd/node leak. `flush_work` waits for completion rather than cancelling, which
  is the invariant under test.
- **L4 raw+RM coexistence, last server close.** A raw and an RM client both have work in flight
  (the raw one is gated in WAIT_RESPONSE); close the last/only server fd. Both async_works and
  the RM space are torn down together; both clients must be woken with an error and close
  cleanly.

Compiles clean (dynamic + static); runtime validation is deferred until the KASAN build frees
the CPU (see CPU-starvation note in phase3-race-harness.md §4c), then it is added to BOOT-3.

## 6. TPM response model caveat (RM path)

The universal 10-byte `rc=0` response is a **transport-level positive response**, labelled
"syntactically accepted, semantically incomplete", not a valid response for every RM state.
A future refinement adds minimal response classes R0 valid-success / R1 TPM-error / R2 short /
R3 malformed-length / R4 inconsistent-header / R5 out-of-bounds, and observes
prepare/execute/commit/space-switch. It is not required for the memory-safety question and must
not be claimed as a complete TPM 2.0 emulator.

## 7. Decision tree after the KASAN matrix

- KASAN reports memory corruption → **STOP fuzzing**: root cause → deterministic reproducer →
  write primitive → exploitability assessment. Preserve the boot log.
- KASAN clean and the race harness demonstrably covers meaningful interleavings → do **not**
  build KCSAN on spec. KCSAN is a sampling data-race detector (~5× boot / ~2.8× fast-path
  overhead, documented false negatives); inside VirtualBox→TCG→KASAN its cost exceeds expected
  yield. Build Kernel C (KCSAN) **only** with a concrete hypothesis (writer without a lock,
  reader under a different lock, concurrently reachable).
- KASAN clean + deterministic races clean + no concrete race hypothesis → that is a strong
  negative result on a complex dual-fd/async/RM driver; move to a second target to demonstrate
  the methodology generalizes, rather than over-mining vtpmx.

## 8. Second-target selection standard (apply in the same 6.8 tree, no name guessing)

Score a candidate only if it is: ① userspace reachable (/dev, ioctl, sysfs, netlink, procfs);
② stateful (create/configure/use/destroy); ③ dynamic object lifetime (kzalloc/kmem_cache,
refcount, workqueue, completion, timer, waitqueue); ④ not pure-hardware-dependent (runs in
QEMU); ⑤ relatively fresh attack surface (not a simple legacy ioctl already saturated by
syzkaller); ⑥ has a clear invariant (length/index/refcount/state/ownership); ⑦ can plug into
the BIVAR variant workflow so the portfolio is a system, not scattered experiments.

Directions: (1) **software-only virtual/misc/char driver** — preferred second case, QEMU-only,
rich lifetime/state machine; (2) staging driver with a real userspace ABI (audit TODO/FIXME,
lifetime comments, error paths, recently changed code); (3) a deliberately small networking
control-plane object (netlink/setsockopt/virtual networking) — high value but easy to balloon,
so pin one tiny object model. Avoid GPU/USB/Wi-Fi now (multi-layer "octopus" scope).

### 8.1 Preliminary candidate scan (2026-09-18, preparedness only — vtpmx KASAN result has priority)

Source-level scan against the trimmed Kernel B `.config`; no second-target work begins until the
vtpmx KASAN matrix is read back and reviewed.

| candidate | node / surface | in current KASAN config? | state / lifetime richness | syzkaller saturation | notes |
|---|---|---|---|---|---|
| FUSE | `/dev/fuse`, read/write device protocol | no (`FUSE_FS` off; light reconfig) | very high: fc/fuse_dev/request/folio lifecycle, abort/umount races, connected/pending state | high but still active (fuse2, passthrough) | best method-generalization target; must pin one small object (request lifecycle or abort) to avoid octopus |
| vhost (-net/-vsock) | `/dev/vhost-net`, ioctl | no (needs NET+VHOST+TUN, heavy reconfig) | high: vdev/vq/worker, refcount + workqueue, pairs with tun | medium-high | classic software kernel component QEMU drives; heavy kernel reconfig |
| device-mapper | `/dev/mapper/control` | **yes (`BLK_DEV_DM=y`)** | medium-high: dm_table/target/device create-remove | high | zero reconfig; needs a block backend |
| loop | `/dev/loop-control`, `/dev/loopN` | **yes (`BLK_DEV_LOOP=y`)** | medium: configure fd/offset/sizelimit/blocksize, teardown | very high | zero reconfig, clean invariants but low novelty |
| uhid | `/dev/uhid` | no (UHID off; INPUT already on, light reconfig) | medium: virtual HID device create/report/destroy | medium | too similar to the Day-1 uinput case — weak differentiation |
| userfaultfd | syscall + `/dev/userfaultfd` | no (`USERFAULTFD` off) | narrow but deep: fault context lifetime, race/UAF relevance | medium | exploitation-oriented; weak link to the parser/fuzzing portfolio |
| binder | `/dev/binder*` | no (`ANDROID_BINDER_IPC` off) | textbook refcount/transaction lifetime | very high | Android-specific, large, heavily saturated |
| ALSA sequencer | `/dev/snd/seq` | no (needs SND, medium reconfig) | medium-high: client/port/subscription lifetime | medium | runs with snd-dummy; historical CVEs |

Working lean (revisit with the external reviewer after vtpmx KASAN): if a zero-reconfig second
case is wanted, device-mapper beats loop on state richness; if a small reconfig is acceptable,
**FUSE request/abort lifetime** best matches criteria ①③⑤⑥⑦ and most clearly shows the
recon→state-machine→invariant→harness method transferring off TPM. vhost is the strongest
"virtual device" story but costs a NET-heavy kernel rebuild.
