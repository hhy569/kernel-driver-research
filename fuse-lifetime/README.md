# FUSE Request-Lifetime Study

Deterministic concurrency / object-lifetime research on the **Linux 6.8 FUSE
kernel client** (`fs/fuse`), driven **directly over `/dev/fuse` with no
libfuse**.  The project constructs the exact request states the kernel
documents as racy (pending / processing / interrupted / locked-copy), forces
the interesting interleavings from userspace, and checks that the kernel's
request-lifetime invariants hold under **Generic KASAN**.

This is *not* a "run a fuzzer and hope" exercise.  Each test is a gated state
machine that parks the kernel request in a specific phase and then drives one
precise teardown / completion ordering.

---

## 1. Research question

> Across the FUSE userspace ABI, which request states can a userspace filesystem
> peer force a `fuse_req` into, and do all teardown / completion / interrupt
> orderings preserve the kernel's object-lifetime invariants
> (single `fuse_request_end()`, no UAF on `fuse_dev_release()`, no stale
> `intr_entry`, no `fpq->io` leak at device close)?

FUSE is a rich concurrency target because every VFS operation becomes a
request that is: allocated → queued → handed to a userspace process over
`/dev/fuse` → optionally signalled/interrupted → answered or aborted, with the
kernel maintaining five different lists and a nine-bit state word.

## 2. Why this target

- Open source, locally buildable, source ↔ binary ↔ runtime triad available.
- Genuine state machine with documented cancellation/abort races
  (`fs/fuse/dev.c` comments explicitly call out "aborted while locked, caller
  responsible for unlocking and ending").
- Reachable from an unprivileged-ish boundary (a FUSE mount); the lifecycle
  code is shared by every filesystem stacked on FUSE (sshfs, virtio-fs peers,
  container runtimes, overlay tools).
- Easy to instrument: Generic KASAN kernel, deterministic serial evidence.
- Methodologically it is the **cross-subsystem transfer** of the same
  lifetime-invariant approach used on the `tpm_vtpm_proxy` study in this repo.

## 3. The request state machine being tested

See [request-state.md](request-state.md) for the full map.  In short:

```
 allocate ─▶ FR_PENDING (fiq->pending)
                 │  daemon read(/dev/fuse)
                 ▼
        FR_LOCKED ─▶ FR_SENT (fpq->processing[hash])
                 │            │
   signal ─────▶ FR_INTERRUPTED (fiq->interrupts, FUSE_INTERRUPT op)
                 │            │
   abort ─────▶ FR_ABORTED     │ reply write(/dev/fuse)
                 │            ▼
                 └──────▶ FR_LOCKED (copy) ─▶ FR_FINISHED (single end)
```

Invariants under test:

1. **Single end** — `fuse_request_end()` is idempotent via
   `test_and_set_bit(FR_FINISHED)`; interrupt + original completion must never
   double-end or double-put.
2. **No locked free** — `fuse_abort_conn()` must leave `FR_LOCKED` requests on
   `fpq->io`; they are finished only after `unlock_request()`.
3. **No stale interrupt entry** — an interrupt arriving after the request
   finished must be removed from `fiq->interrupts`, never touched after free.
4. **Clean device release** — `fuse_dev_release()` `WARN_ON(!list_empty(io))`
   must not fire; closing the last `/dev/fuse` fd aborts the connection once.
5. **Bounded teardown** — aborting while a request is pending or processing
   wakes the VFS caller with a defined teardown error, never a hang.

## 4. Harness architecture

No libfuse.  A minimal wire implementation (`fuse_proto.h`, `fuse_session.c`)
speaks the FUSE 7.31 protocol:

- opens `/dev/fuse`, `mount(2)`s a private `fuse` filesystem, handshakes INIT;
- runs a daemon thread that `read(/dev/fuse)`s one request at a time;
- in **gated** mode the director decides exactly when each request is read,
  held, answered, interrupted, or aborted (`fuse_permit_read /
  fuse_wait_held / fuse_release_held / fuse_reply / fuse_conn_abort`);
- aborts through two independent primitives and cross-checks both:
  - sysfs `…/connections/<id>/abort`, and
  - releasing the last `/dev/fuse` fd → `fuse_dev_release()` →
    `fuse_abort_conn()` (the robust path on a minimal initramfs).

```
 test thread (VFS)        director            daemon thread (/dev/fuse)        kernel fs/fuse
      │                      │                       │                            │
 open/read ───────────────────────────────────────────────────────▶ alloc, PENDING │
      │              permit_read ───────────────▶ read ─▶ LOCKED,SENT(processing) │
      │                      │                       │                            │
      │   (L3) pthread_kill SIGUSR1 ───────────────────────────▶ FR_INTERRUPTED    │
      │                      │   next read returns FUSE_INTERRUPT first            │
      │                      │   EAGAIN / ENOENT / reply original (I1/I2)          │
      │   (L1/L2/L4) abort ────────────────────────────────────▶ FR_ABORTED/teardown
      │ ◀──── bounded wake (data or ECONNABORTED), never hang ──────────────────── │
```

## 5. Scenarios

| Case | State forced | Action | Invariant |
|------|--------------|--------|-----------|
| **L1** | `FR_PENDING`, daemon never read | abort connection | pending requests ended once, VFS wakes ECONNABORTED |
| **L2** | `FR_SENT` / processing, held by daemon | abort while held | processing request not freed under the daemon; bounded teardown |
| **L3-I1** | `FR_INTERRUPTED`, interrupt consumed first | reply `EAGAIN` to INTERRUPT, then complete original | no double-end; reader still gets full data |
| **L3-I2** | original completed first, then interrupt | reply original, then observe INTERRUPT | kernel drops interrupt after FINISHED; no stale `intr_entry` |
| **L4** | `FR_LOCKED` during userspace copy | abort from a second thread at a random instant | locked request not freed mid-copy; no `WARN_ON(io)` / UAF |

L4 is honestly **probabilistic** from pure userspace (we cannot stop the CPU
inside `copy_to_user`); we widen the window by replying ~1 MiB into a freshly
`mmap`'d, not-yet-faulted buffer so each page takes a demand fault while
`FR_LOCKED` is held, and randomise the abort instant across many private
mounts.  It is a window-widening stress + KASAN check, **not** claimed as a
deterministic copy interleaving.  (`CONFIG_USERFAULTFD` was deliberately not
used.)

## 6. Results (Generic KASAN, deterministic)

Kernel `Linux 6.8.0 #2 SMP PREEMPT_DYNAMIC` (`#2`, FUSE built-in),
`CONFIG_KASAN=y`, `CONFIG_KASAN_GENERIC=y`, QEMU/TCG, initramfs autorun matrix.

| Boot | Contents | Result |
|------|----------|--------|
| `tests=fuse` | smoke + L1/L2/L3-I1/L3-I2 **×10 repetitions** (40) + L4 ×12 | **52/52 PASS, 0 fail, 0 hang** |
| `tests=fuse_l4` | L4 locked-copy × abort **×40** | **40/40 PASS, 0 fail, 0 hang** |

Across **92 instances**: no KASAN report, no `BUG/Oops`, no fs/fuse `WARN_ON`,
no refcount/list-corruption splat, no hang.  L3 reproduces both documented
interrupt orderings deterministically (I1 observes the FUSE_INTERRUPT request
with `intr.unique == original.unique`; I2 observes the kernel correctly
dropping the interrupt after FINISHED).

**Honest negative result.** No memory-safety violation, refcount/list
corruption, or unexpected request-lifetime failure was observed within the
exercised state and interleaving space. This does *not* establish absence of
bugs outside the exercised request states, protocol operations, teardown
paths, and timing windows — it does not prove `fs/fuse` is bug-free. KASAN
gives high confidence on memory safety; "lifetime violation" is a broader
notion and is not collapsed into that claim. Scope and windows are documented
per case and absence of a crash is reported as exactly that.

## 7. Reproduction

```sh
# host build (direct /dev/fuse, no libfuse)
cd harness
gcc -O2 -static -pthread -Wall -Wextra -o fuse_smoke    fuse_smoke.c    fuse_session.c
gcc -O2 -static -pthread -Wall -Wextra -o fuse_lifetime fuse_lifetime.c fuse_session.c
gcc -O2 -static -pthread -Wall -Wextra -o fuse_l4       fuse_l4_copyabort.c fuse_session.c

# on a host with a FUSE mount-capable environment:
sudo ./fuse_smoke            # mount/INIT/LOOKUP/OPEN/READ/RELEASE/umount
sudo ./fuse_lifetime 10      # deterministic L1/L2/L3 x10
sudo ./fuse_l4 50            # probabilistic locked-copy x abort
```

KASAN matrix: copy the three static binaries and `rootfs-init/init` into the
initramfs, boot the Generic-KASAN bzImage with `tests=fuse` / `tests=fuse_l4`
via `../run_qemu.sh auto <log> <sec> <tag>`.  Artifacts, kernel/config hashes
and serial logs are listed in
[`../notes/fuse-request-lifetime-results.md`](../notes/fuse-request-lifetime-results.md).

## 8. Files

- `fuse_proto.h` — wire constants, packed uapi structures, opcodes, lab FS.
- `fuse_session.h/.c` — `/dev/fuse` session, gated director, abort primitives.
- `fuse_smoke.c` — AUTO-mode end-to-end mount/read/umount proof.
- `fuse_lifetime.c` — deterministic L1 / L2 / L3-I1 / L3-I2.
- `fuse_l4_copyabort.c` — probabilistic FR_LOCKED-copy × abort stress.
- [attack-surface.md](attack-surface.md), [request-state.md](request-state.md),
  [lifetime-invariants.md](lifetime-invariants.md) — static recon.

## 9. What this demonstrates to a reviewer

- Ability to read a kernel subsystem and rebuild its state machine and
  list/queue topology from source, then **reach every named state
  deterministically** from the userspace ABI.
- Precise control of cancellation/abort/completion interleavings rather than
  randomized load.
- Correct triage discipline: teardown errnos (`ECONNABORTED/ENOTCONN/EIO`) are
  protocol semantics, not bugs; a crash is not claimed without root cause; a
  clean matrix is reported as a bounded negative result, not "no bugs".
- Reproducible, hash-pinned KASAN evidence and a self-contained, libfuse-free
  tool that transfers to other file-descriptor-driven kernel interfaces.
