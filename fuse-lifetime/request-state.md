# FUSE request state machine and queue topology

Static recon of `fs/fuse` in **Linux 6.8**.  Line numbers refer to
`fs/fuse/dev.c` unless noted; state bits are defined in `fs/fuse/fuse_i.h`.

## 1. State bits (`fuse_i.h`, `enum fuse_req_flag`)

| Bit | Meaning |
|-----|---------|
| `FR_BACKGROUND` | background request (reclaim / async) |
| `FR_WAITING` | on a userspace wait list |
| `FR_ABORTED` | connection aborted; late replies rejected |
| `FR_INTERRUPTED` | a signal/INTERRUPT requested cancellation |
| `FR_LOCKED` | request is on `fpq->io`, being copied to/from userspace |
| `FR_PENDING` | on `fiq->pending`, not yet read by the daemon |
| `FR_SENT` | on `fpq->processing[]`, handed to userspace |
| `FR_FINISHED` | terminal; set once by `fuse_request_end()` |
| `FR_PRIVATE` | filesystem-private |

A request's *phase* is the combination of its bit and the list it sits on.

## 2. The five lists

| List | Holds | Producer | Consumer |
|------|-------|----------|----------|
| `fiq->pending` | new requests not yet read (`FR_PENDING`) | kernel VFS paths | `fuse_dev_read` (`do_read`) |
| `fpq->processing[hash]` | requests handed to userspace (`FR_SENT`) | `do_read` | `fuse_dev_write` / abort |
| `fpq->io` | requests actively being copied (`FR_LOCKED`) | `do_read` / `do_write` | end of copy (`unlock_request`) |
| `fiq->interrupts` | `FUSE_INTERRUPT` messages | `queue_interrupt` | `do_read` (**highest priority**) |
| `fiq->forget_list` | `FORGET` (no reply expected) | `FUSE_FORGET`/batch | `do_read` (after interrupts) |

`do_read` drain order is: **interrupts → forgets → pending**
(dev.c ~1254/1260), which is why an interrupt is delivered before any other
queued request — the property L3 relies on.

## 3. Forward path (`do_read`, dev.c ~1204)

```
fuse_dev_read
  read buffer must be >= max(8192, sizeof(in_header)+write_in+max_write)
  pop fiq->interrupts first            (~1254)
  else pop fiq->forget_list            (~1260)   (FORGET, no reply)
  else take one fiq->pending (FR_PENDING)
        └─ move to fpq->io, set FR_LOCKED          (fuse_force_req / copy-in)
           └─ move to fpq->processing[hash], set FR_SENT, clear LOCKED
              └─ if FR_INTERRUPTED already set -> queue_interrupt() (~1324)
  copy_to_user(fuse_in_header + request body)
```

## 4. Reverse path (`do_write`, dev.c ~1850)

```
fuse_dev_write
  copy_from_user fuse_out_header; validate oh.len == nbytes; error in [-512,0]
  if unique has FUSE_INT_REQ_BIT (bit 63) -> this is an INTERRUPT reply:
        -ENOSYS : mark no_interrupt (peer cannot cancel)
        -EAGAIN : queue_interrupt() again                      (~1906)
        other   : complete/forget the interrupt
  normal reply:
        locate req in processing (request_find)
        clear FR_SENT; move processing -> fpq->io; set FR_LOCKED  (~1916)
        copy_out_args (to kernel structs and user pages)
        clear FR_LOCKED                                          (~1929)
        if !connected -> -ENOENT
        list_del; fuse_request_end()
```

`FR_LOCKED` therefore brackets **every** userspace copy in both directions;
abort must not free a request while it is held.

## 5. Completion and interrupt

- **`fuse_request_end()` (~280)** — `test_and_set_bit(FR_FINISHED)` makes
  end idempotent (single-end invariant); if `FR_INTERRUPTED` it `list_del`s
  `intr_entry`; `WARN_ON` if still PENDING/SENT; wakes waiters; drops ref.
- **`queue_interrupt()` (~334)** — requires `FR_INTERRUPTED` (else `-EINVAL`);
  adds `intr_entry` to `fiq->interrupts`, issues a memory barrier, and if the
  request is already FINISHED removes it again (the I2 race); wakes the daemon.
- **`request_wait_answer()` (~364)** — the VFS caller waits
  `wait_event_interruptible(FR_FINISHED)`; a signal sets `FR_INTERRUPTED`,
  barriers, and if `FR_SENT` calls `queue_interrupt()`; non-`FORCE` calls then
  wait killable; a fatal signal while still `FR_PENDING` removes/puts and
  returns `-EINTR`, otherwise it keeps waiting for FINISHED.
- **`lock_request()` (~612 / 630)** — `FR_ABORTED` → `-ENOENT`; otherwise
  set/clear `FR_LOCKED`.  Comment ~626: *"aborted while locked, caller
  responsible for unlocking and ending."*

## 6. Teardown

### `fuse_abort_conn()` (~2125)
1. `connected = 0`.
2. Walk `fpq->io`: set `FR_ABORTED`; **only if `!FR_LOCKED`** take a ref and
   move to `to_end` — locked requests stay on the io list until unlock.
3. Splice all of `fpq->processing[]` to `to_end`.
4. Clear `FR_PENDING` and splice `fiq->pending` to `to_end`.
5. Free forgets.
6. `end_requests()`: set `-ECONNABORTED`, clear `FR_SENT`, `list_del`,
   `fuse_request_end()` for each.

### `fuse_dev_release()` (~2197)
- `WARN_ON(!list_empty(&fpq->io))` (~2208): a request still in a copy at final
  device put is a kernel bug — exactly the invariant L4 hammers.
- Splices/ends processing leftovers.
- Only the **last** `/dev/fuse` reference (`dev_count -> 0`) calls
  `fuse_abort_conn()`.  This is why closing our single fd is a correct abort
  primitive and why it is used as the robust path on a minimal initramfs.

## 7. Userspace-observable controls

- `/dev/fuse` (misc 10:229): `read` / `write` / poll; one opened fd is one
  `fuse_dev` reference.
- `/sys/fs/fuse/connections/<id>/waiting` — counts pending **and** processing
  (cannot distinguish pending alone; used only as an auxiliary signal).
- `/sys/fs/fuse/connections/<id>/abort` — write `1\n` to abort while keeping
  the daemon alive.
- Wire facts verified at runtime (Linux 6.8): `fuse_in_header`=40 B,
  `fuse_out_header`=16 B, `fuse_init_in`=64 B, `fuse_read_in`=40 B,
  `fuse_open_in`=8 B, `fuse_release_in/flush_in`=24 B; INIT negotiated to
  major 7 / minor ≤31; **READ reply is `fuse_out_header` + raw data with no
  `fuse_write_out`** (byte count inferred from header length; `fuse_write_out`
  belongs to WRITE, file.c ~1051).
