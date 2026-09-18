# Phase 3 — Deterministic Race & Error-Path Validation of `tpm_vtpm_proxy` (vtpmx)

**Target:** Linux 6.8 `drivers/char/tpm/tpm_vtpm_proxy.c` (+ `tpm-chip.c`, `tpm-interface.c`, `tpm-dev-common.c`)
**Phase goal:** answer the question *"each individual operation is legal — can two legal operations, combined in a specific ordering, violate a kernel invariant?"*
**Method:** deterministic, barrier-anchored userspace harnesses (no blind timing), first on the stock distribution kernel for logic-level validation, then re-run on a KASAN instrumented kernel for memory-safety confirmation.

> Honesty scope: a logic-level run with no hang proves correct **synchronization and error propagation**. It does **not** prove absence of use-after-free / out-of-bounds / double-free; those require KASAN (Kernel B) and, if needed, KCSAN (Kernel C). This document records both what was proven and what remains open.

---

## 1. Source-derived facts that shaped the harnesses

These were established by reading source before writing any test (see `vtpmx-state-machine.md` for the full state machine):

1. **A raw `/dev/tpmN` `write()` is a full synchronous transmit.**
   `tpm_try_transmit()` (`tpm-interface.c`) calls `tpm_op_send()` to queue the command, then — in non-IRQ mode — loops polling `tpm_op_status()` until the emulator writes a response or the ordinal timeout fires (the source comment notes timeouts "can be minutes"). `req_canceled → -ECANCELED`; timeout → `ops->cancel()` then `-ETIME`. The entire transmit runs under `tpm_try_get_ops()` → `down_read(&chip->ops_sem)`.

2. **Server-fd teardown takes the same rwsem for write.**
   `close(serverfd)` → `tpm_chip_unregister()` → `tpm_del_char_device()` (`tpm-chip.c:444-471`) → `down_write(&chip->ops_sem)`. Therefore teardown **blocks** until every in-flight client transmit releases the read lock. This is the primary object-lifetime barrier — a close that waits for an in-flight op is the design working, not a deadlock bug.

3. **Chip registration auto-sends TPM2_Startup.**
   `tpm_ops.flags = TPM_OPS_AUTO_STARTUP` means that during registration the TPM core writes a `TPM2_CC_Startup` command to the server fd. If no emulator reads+responds promptly, the register work blocks to the TPM timeout, `/dev/tpmN` never appears, and close is dragged to the timeout by `flush_work`. This single fact caused the first fork-based harness to hang wholesale.

4. **Fixed-size buffer, no user-controlled dynamic sizing.**
   The per-device buffer is an embedded `u8[TPM_BUFSIZE]` with `TPM_BUFSIZE=4096`; all four copy sites check against `sizeof(buffer)` and run under `buf_lock`. The classic "integer overflow → undersized allocation" class does not apply to vtpmx, which is why Phase 3 targets **concurrency / lifetime / rollback** rather than arithmetic.

---

## 2. Harness design — why a drain-aware, gated emulator

`harness/vtpmx_race.c` (v2) runs a dedicated **pthread TPM emulator per proxy device** with two modes:

- `EMU_FREE` — serve every command immediately (used for dup-permutation, the state×input matrix, and stress).
- `EMU_GATED` — freely serve the first `drain` commands (to absorb the auto-startup exchange), then block each subsequent command at explicit anchors:
  - **W1 / REQ anchor (`Q`)** — command is buffered in the kernel, before the server `read()`;
  - **W2 / READ anchor (`R`)** — server has consumed the command, chip is in `WAIT_RESPONSE`, before the response `write()`;
  - **W3 / RESP anchor (`P`)** — response delivered, transmit completing.

Anchors are implemented with two pipe pairs per relationship (`ctl` test→emulator, `obs` emulator→test); the test parks the emulator exactly on an anchor, performs the racing operation (usually `close(serverfd)` from a dedicated thread while timing it), then releases the gate. This turns "two threads, hope they overlap" into a **replayable, single-schedule interleaving**.

Response policies for gated commands: `RP_SERVE` (valid 10-byte TPM2 response), `RP_DELAY` (400 ms), `RP_MALFORMED` (4-byte short response), `RP_NORESP` (never respond).

The client side is a forked child that opens `/dev/tpmN`, issues one blocking synchronous `write()`, reports the resulting `errno` back over a pipe, and (unless killed) lingers holding the ops read lock. A `SIGALRM` watchdog (`_exit(99)`) turns any true deadlock into a recorded failure instead of an infinite hang.

---

## 3. Race matrix — results on the stock 6.8.0 kernel

| ID | Scenario | Orderings exercised | Result (stock kernel) |
|----|----------|--------------------|------------------------|
| **R1** | server `close` ↔ in-flight client transmit | W1 (pre-read), W2 (WAIT_RESPONSE), W3 (post-response) | No hang. At W1/W2 the in-flight client receives a fast **`-ETIME` (errno 62, report 162)** as the op is cancelled; the close thread measures **~0 ms blocking** (cancellation releases the read lock quickly, then `down_write` proceeds). W3 completes with report 200 and clean teardown. |
| **R2** | `NEW_DEV` ioctl ↔ async register work (the auto-startup itself, `drain=0`) | A immediate / B 400 ms delay / C close while startup pending / D malformed short response | All four teardown timings return in **22–549 ms**, no hang, no oops. The register work is correctly flushed/cancelled by `work_stop`. |
| **R3** | client vanishes (killed mid-transmit) ↔ server operation | pre-response and post-response anchors | Server and teardown survive the client disappearing; no crash. |
| **R5** | dup fd permutation on `/dev/tpmN` | open, dup×2, write/read across A/B/C, close B, write to closed fd, close all | Clean; write to an already-closed dup → **EBADF**; no cross-fd state corruption. |
| **matrix** | state × input on the server fd (free emulator) | unsolicited write with no queued command; poll with no pending command | Unsolicited server write → **EIO**; `poll()` with no queued command → **timeout (correct)**. |
| **R9** | repeated create/serve/destroy stress | 40 full device cycles + 64-fd allocation probe | No fd exhaustion/leak; `first tpm == last tpm == 0` (device-number reuse, expected). |

**v2 tally: 13 passed / 0 leads / 0 hangs**, completing in seconds.

### False positives eliminated while building v2 (methodological value)
- The first version reported two "suspicious" R5/matrix cases. Root cause was the harness itself: the emulator waited on a gate that the auto-startup command had already crossed, and the extra startup command polluted the gated anchor sequence. Adding the `drain` count removed both — a concrete example of distinguishing a **harness artifact** from a kernel defect.
- R1 initially looked like a teardown wake-up bug (child `exit=99` on a 6 s alarm). After moving the close to a timed background thread and reporting the client `errno` explicitly, the behavior resolved to the documented `-ETIME` cancellation path.

**Interpretation:** on the stock kernel, every race window manifests as either correct rwsem serialization or clean error propagation. The close-vs-transmit path (`down_write` waiting for `down_read`; cancelled op → `ETIME`) behaves exactly as the source predicts. Memory safety across these windows is still to be confirmed under KASAN.

---

## 4. Error-path / rollback harness — `harness/vtpmx_err.c`

Failure points were read from `create_device()` (`tpm_vtpm_proxy.c:533-586`) and `vtpmx_ioc_new_dev()` (`:624-654`). The leak oracle is `/proc/self/fd` count before/after each failing ioctl; fd-table pressure cases run in isolated forked children with their own alarm.

| Case | Injected failure | Source point | Expected | Result (stock kernel) |
|------|------------------|--------------|----------|-----------------------|
| **E1** | `arg = NULL` and `arg = 1<<40` (unmapped) | `copy_from_user` (`:637`) | `-EFAULT`, before any allocation | **PASS** |
| **E2** | `flags = 0xFFFFFFFE` and `flags = 2` (reserved bits) | flags check (`:540`) | `-EOPNOTSUPP`, before allocation; zero fd growth | **PASS** |
| **E3** | fd-table exhaustion (`setrlimit` + fill with `/dev/null`) | `get_unused_fd_flags` (`:550`) | stable `-EMFILE`; after restoring rlimit, fd count returns to baseline; a subsequent NEW_DEV still works | **PASS** — EMFILE stable across 80 attempts; post-stress create/register/teardown clean |
| **E4** | read-only arg page (mmap RW, plant `flags=1`, `mprotect` RDONLY) so `copy_in` succeeds but `copy_out` faults | `copy_to_user` (`:645`) | `-EFAULT`, zero net fd growth, bounded latency (slow rollback: `put_unused_fd`+`fput`→`delete_device`→`work_stop` flushes the never-served auto-startup) | **PASS** — EFAULT with zero fd leak and bounded delay |

**Tally: 8 passed / 0 failed.**

Notes recorded for the report:
- At the `get_unused_fd` failure point no fd has been installed yet, so an fd leak is impossible by construction; what *could* leak there is `proxy_dev`/`chip`/the tpm idr number — that is a memory question and is deferred to KASAN/kmemleak, not falsely claimed from fd counts.
- The first E3 attempt "failed" because the test itself opened `/proc/self/fd` after exhausting the table (that open also returns EMFILE). Replacing the self-defeating count-at-exhaustion with a stable-EMFILE + restore-and-recount oracle fixed the test, again separating test bug from driver bug.

---

## 4b. Async / poll / same-fd concurrency — `harness/vtpmx_async.c` (R4/R10)

`tpm_common_write()` has a second path the blocking harness never reached: with `O_NONBLOCK` it
`queue_work(tpm_dev_wq, priv->async_work)` and returns immediately; `tpm_dev_async_work()` then
takes `buffer_mutex` + the ops read lock, transmits, and `wake_up_interruptible(&async_wait)`
(the event `poll()` waits on). This harness covers that workqueue lifetime:

| Case | What it does | Result (stock kernel) |
|------|--------------|------------------------|
| **A** | `lseek(fd,4096,SEEK_SET)` negative control | **ESPIPE** — `.llseek=no_llseek`, read offset is not attacker-settable (closes the `data_buffer+off` OOB hypothesis; see call-graph doc §"Offset invariant") |
| **R4 happy** | NONBLOCK write enqueues → 2nd write before read → `poll()` EPOLLIN → read 10 B → write again | enqueue returns size; 2nd write → **EBUSY** (`command_enqueued` gate); poll wakes; read=10; re-arm works |
| **R4c** | async work parked in WAIT_RESPONSE (gated emulator), then `close(serverfd)` | teardown cancels ops, poll/read wake with an error, **825 ms**, no hang |
| **R10 m0** | client `close()` while async work in flight, emulator then responds | `release()→flush_work` returns in **106 ms**, clean |
| **R10 m1** | same but server teardown cancels ops first | returns in **864 ms**, clean |

**Tally: 6 passed / 0 leads / 0 hangs.** Combined with the blocking harness, every userspace-visible
entry path (blocking transmit, NONBLOCK async work, poll, read offset, dup, create/teardown, error
rollback) has now been driven through deterministic interleavings on the stock kernel.

---

## 4c. Concurrent create/teardown/cleanup fuzzing — `harness/vtpmx_stress.c` (R7)

The deterministic harnesses pin specific interleavings; R7 instead hammers the lifetime
barriers from six threads at once with a **fixed seed** (`argv[2]`, default `0x1234`) for
reproducibility. A first naive version (create→immediate close) produced **zero** client
operations and ~7k ENOENT: devices were torn down within ~30 ms, so clients almost never saw a
live node — a self-inflicted false negative. The corrected **device-pool model**:

- 6 proxy devices are kept alive, each with its own emulator thread, so live `/dev/tpmN` and
  `/dev/tpmrmN` nodes always exist;
- a **recycler** thread continuously tears down a random slot (`close(serverfd)` →
  `delete_device` → `tpm_chip_unregister`) and immediately creates a fresh device in that slot
  (churn every ~30–280 ms), while the other 5 slots stay live;
- 2 raw + 2 RM clients open random live slots with `O_NONBLOCK`, drive the async-work path
  (`write`→`poll`→`read`), and probe `lseek` (must stay ESPIPE); teardown deliberately races
  in-flight `tpm_dev_async_work` and opens — a randomized, multi-threaded R1/R3/R4c/R10.

Assertions (stock kernel): SIGALRM hard watchdog (no hang); open-fd count returns to baseline;
no `/dev/tpmN` node leaks after the pool is torn down; `lseek` stays ESPIPE. Benign teardown
errno (EBUSY raw single-open, ENOENT/EIO/ETIME/EPIPE) are histogrammed, not treated as findings.
Memory safety is decided by KASAN dmesg in the guest, not by this binary.

**Environment constraint (important, not a kernel bug):** TPM device registration runs an
auto-startup TPM2 command that needs the userspace emulator thread and the kernel register
work to be scheduled in a ping/pong. While the KASAN kernel build saturates the VM
(`-j4` + the resident docker stack, load ~8.7 on 4 cores), the emulator starves and
`/dev/tpmN` does not appear within the 6 s window — every create rolls back. The earlier
deterministic harnesses passed because they ran when the CPU was not yet saturated. R7 is
therefore validated only **after** the build finishes (idle stock kernel, then the KASAN
guest); running real-time emulator tests under a full build is meaningless. A SIGKILL during
the failed run left **zero** `/dev/tpmN` nodes behind (only the control `/dev/vtpmx`), itself a
data point that abnormal process death still triggers clean per-fd teardown.

---

## 5. What this phase does and does not establish

**Established on the stock kernel (logic level):**
- The `ops_sem` read/write rwsem is the effective lifetime barrier between in-flight client transmits and server-fd teardown; cancellation converts a blocked op into a prompt, correct `-ETIME` rather than a use-after-close.
- The register work (including the auto-startup round trip) is correctly drained or cancelled on teardown across all four timing cases.
- Every `NEW_DEV` error path returns the documented errno with zero net new fd and bounded latency; the driver remains healthy afterward.
- Unsolicited server I/O and closed-dup I/O are rejected with the right errors.

**Not yet established (requires instrumented kernels):**
- Absence of UAF / OOB / double-free in the `proxy_dev`/`chip` teardown and error-rollback paths → **Kernel B (KASAN)**, re-running R1/R2/R3 and E3/E4.
- Absence of a data-race on shared state (`state` flags across locks, poll/wakeup) → **Kernel C (KCSAN)** if KASAN is clean.

---

## 6. Reproduction

Stock kernel (logic validation), as root:
```sh
gcc -O2 -pthread -o vtpmx_race harness/vtpmx_race.c
gcc -O2 -pthread -o vtpmx_err  harness/vtpmx_err.c
gcc -O2 -pthread -o vtpmx_async harness/vtpmx_async.c
./vtpmx_race    # expect passed:13 leads/unexpected:0 hangs:0
./vtpmx_err     # expect passed:8 fail:0
./vtpmx_async   # expect passed:6 leads/unexpected:0 hangs:0
```
KASAN kernel (memory-safety validation): statically link all three (`-static -O2 -pthread`),
place them in the busybox initramfs (the `build_rootfs2.sh` script does this and writes an `init`
that runs probe→race→err→async→uinput then dumps the dmesg KASAN/BUG summary and powers off), boot
the KASAN `bzImage` under QEMU/TCG (`./run_qemu.sh auto qemu-serial.log 900`), and inspect the
serial log for any `KASAN:` / `BUG:` / `Oops:` / slab report across the R1–R3, R4c, R10 and E3/E4
windows. TCG has no KVM in the nested VM; the harnesses already use wide child alarms, but KASAN
slows them further.

**Stop rule for this phase:** if KASAN reports a memory error in any anchored window, minimize to a single deterministic schedule, capture the full KASAN trace, map the shadow access back to the exact `proxy_dev`/`chip` field, and only then classify. If KASAN (and subsequently KCSAN) are clean across the full matrix, record vtpmx as a **systematically validated negative result** and move to the next driver/subsystem per the pre-agreed migration criteria — a clean, instrumented, deterministic negative result with full artifacts is a portfolio result, not a failure.
