# Lifetime invariants and per-scenario gates

Each scenario is a **gated interleaving**, not a load test.  This file records
the hypothesis, the gates that must be observed before the action, and the
invariant that must hold afterwards.  Machine output uses the form

```
TEST=FUSE CASE=<name> STATE=<kernel state> GATE=<gate> ACTION=<action> RESULT=<PASS|FAIL> <k=v...>
```

A `RESULT=PASS` means the kernel behaved correctly (bounded, single-ended, no
corruption).  Finding no bug *is* the expected, useful result for an invariant
test; a failure would be a memory-safety/lifetime finding.

---

## L1 — pending request × connection abort

- **State forced:** request allocated and sitting on `fiq->pending`
  (`FR_PENDING`); the daemon has **never read it**.
- **Gates**
  - G1 VFS op issued (test thread blocked in `open(2)`).
  - G2 a request exists (`waiting` counter ≥ 1 when sysfs is available).
  - G3 daemon has not consumed it (no `permit_read`).
  - G4 abort issued.
  - G5 observe the blocked caller wake.
- **Action:** abort the connection (`…/abort`, then last-fd release).
- **Invariant:** `fuse_abort_conn()` ends every pending request exactly once
  with `-ECONNABORTED`; the VFS caller wakes bounded (no hang, no wait on a
  freed object).
- **Observed:** `open_errno=103 (ECONNABORTED), hung=0`.  On the minimal
  initramfs the sysfs `waiting` file is absent (`waiting=-1`); the last-fd
  abort path is what actually tears the connection down there, and it still
  yields ECONNABORTED.

## L2 — processing (FR_SENT) request × abort

- **State forced:** the daemon has read the request (`FR_LOCKED → FR_SENT`, on
  `fpq->processing[]`) and deliberately holds it without replying.
- **Gates:** LOOKUP/GETATTR auto-answered; `FUSE_OPEN` is held (`held_op=14`).
- **Action:** abort while the daemon still owns the serialized request.
- **Invariant:** a request in userspace hands is not freed out from under the
  daemon; abort moves it through `to_end` and ends it once; the caller wakes
  bounded with a teardown error; subsequent daemon writes get `-ENOENT`.
- **Observed:** `held_op=14, open_errno=103, hung=0`.

## L3 — interrupt × original completion (the documented cancellation race)

The blocking reader is parked on a held `FUSE_READ`.  A `SIGUSR1` delivered to
that thread (empty handler, **no** `SA_RESTART`) makes
`request_wait_answer()` return from its interruptible wait, set
`FR_INTERRUPTED`, and — because the request is `FR_SENT` — call
`queue_interrupt()`.  The daemon's next `read` returns the `FUSE_INTERRUPT`
request first (interrupt queue priority), whose body
`fuse_interrupt_in.unique` equals the original request's unique.

### L3-I1 — interrupt before original completion
- Reply `-EAGAIN` to INTERRUPT (daemon cannot cancel yet → kernel re-queues),
  **then** reply the original READ data.
- **Invariant:** no double `fuse_request_end()`, no UAF, no stale
  `intr_entry`; the original still completes and the reader gets the **full
  payload** (the signal does not turn into a spurious EINTR/data loss).
- **Observed:** `saw_interrupt=1, intr_target=1` (interrupt unique ==
  original), `read_rc=39` with matching payload, `hung=0`.

### L3-I2 — original completion before interrupt is consumed
- Reply the original READ first, then drain the INTERRUPT.
- **Invariant:** when the original reaches FINISHED first,
  `queue_interrupt()`'s post-barrier check removes `intr_entry`; no interrupt
  is acted on after free; the reader still returns the full payload.
- **Observed:** `saw_interrupt=0` (kernel correctly dropped the interrupt after
  FINISHED — itself the expected race outcome), `read_rc=39`, `hung=0`.

Together I1 and I2 cover both orderings of the interrupt/finish race
deterministically.

## L4 — locked userspace copy × abort (probabilistic window)

- **Research question:** does every userspace-copy path keep the `FR_LOCKED`
  lifetime invariant if the connection is aborted while a reply is being
  copied out?
- **State forced:** a large READ reply (~1 MiB negotiated; observed 4 KiB
  request granularity in the guest) written into a freshly `mmap`'d,
  not-yet-faulted user buffer, so demand page faults occur while the request
  is `FR_LOCKED` on `fpq->io`.
- **Action:** a second thread aborts at a random 0–2.5 ms instant around the
  `write(/dev/fuse)`; repeated across many private mounts.
- **Invariants:**
  - `fuse_abort_conn()` leaves a `FR_LOCKED` request on the io list; it is
    ended only after `unlock_request()`;
  - `fuse_dev_release()` never hits `WARN_ON(!list_empty(io))`;
  - no UAF/double-end across the abort/copy race;
  - the reader always wakes bounded — either data or a teardown errno — never
    hangs in `close(RELEASE)` on a dead gated connection.
- **Honest scope:** pure userspace cannot deterministically schedule inside
  `copy_to_user`; this is window-widening (page faults) + random timing +
  KASAN, **not** a deterministic interleaving.  `userfaultfd` was not used
  (`CONFIG_USERFAULTFD=n`).
- **Observed:** all iterations bounded (`hung=0`); reader returns data or a
  teardown error; no KASAN/`WARN_ON(io)`/list/refcount splat.

---

## Stop / classification rules applied

- **STOP-1** any KASAN/BUG/OOPS/WARN/refcount/list splat → halt that case.
- **STOP-2** a UAF/double-free/refcount-underflow/list-corruption → minimise,
  reproduce, root-cause, diff against upstream patches before any disclosure.
- **STOP-3** `ETIME/EINTR/EAGAIN/ENOTCONN/ECONNABORTED/EIO` alone are protocol
  /teardown semantics, not findings.
- **STOP-4** once deterministic cases are green they are repeated ×10 and L4
  stress ×40 under KASAN; random fuzzing is not extended past the observation
  window.

## What a negative result here does and does not establish

It establishes that the named states and both interrupt orderings are
reachable and that the stated invariants held across 92 KASAN-instrumented
instances.  It does **not** claim the subsystem is bug-free, nor that other
entry paths (background I/O, `FUSE_BATCH_FORGET`, notify/revoke, DAX,
virtio-fs, write-back cache) are covered.
