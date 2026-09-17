# vTPM Proxy (`/dev/vtpmx`) — State Machine & Object-Lifetime Reconstruction

Phase-2A static deliverable for `drivers/char/tpm/tpm_vtpm_proxy.c` (Linux 6.8).
Goal: turn the driver into an **executable state machine** and exhaustively map
object lifetime / buffer ownership before any dynamic fuzzing. Per the research
plan, LIFETIME is the primary invariant class here; a `kfree()` is never flagged
without first proving a reachable reference survives it.

---

## 1. Threat model and device model

The vTPM proxy lets a **userspace TPM emulator** implement a TPM chip that the
rest of the system consumes through the normal TPM interface. It creates a
**file-descriptor pair**, which is the crux of the attack surface:

```
 TPM emulator process (needs CAP_SYS_ADMIN)            TPM client(s)
 ─────────────────────────────────────────            ───────────────
 open("/dev/vtpmx")                                     open("/dev/tpmN")
 ioctl(NEW_DEV, &s)            ── create pair ──►        │
   s.fd  ──► anonymous "[vtpms]" server fd              │ write TPM command
   (major,minor,tpm_num) ──► /dev/tpmN  ◄────────────────┘
        │                                                       │
 server read()  ◄── tpm_op_send: buffer=cmd, req_len=count      │
 server write() ──► tpm_op_recv: resp_len=count  ──► client read gets response
        │                                                       │
 close(server fd) ──► unregister + free everything
```

Two independent fd types reference one shared kernel object (`proxy_dev`):
the **server anon fd** (owns the object's lifetime) and the **client
`/dev/tpmN` fds** (reach the object only through `chip->ops`). This split is
what makes lifetime/teardown analysis more interesting than boundary checks.

---

## 2. ioctl surface

| Cmd | Dir | Struct | Handler | User-controlled | Validation |
|---|---|---|---|---|---|
| `VTPM_PROXY_IOC_NEW_DEV` `_IOWR(0xa1,0x00, struct vtpm_proxy_new_dev)` | RW | 5×u32 = 20 B: `flags`(in), `tpm_num/fd/major/minor`(out) | `vtpmx_ioc_new_dev` [:624] | `flags` | `capable(CAP_SYS_ADMIN)`→else EPERM; fixed `copy_from_user` 20 B; `flags & ~VTPM_PROXY_FLAGS_ALL`→EOPNOTSUPP; fixed `copy_to_user` 20 B |
| anything else | — | — | `vtpmx_fops_ioctl` [:662] | — | `default: -ENOIOCTLCMD` |

`flags` only accepts `VTPM_PROXY_FLAG_TPM2 (1)`; any other bit is rejected.
There is **no length/count field** in the ioctl — the only variable-length data
moves through the server fd `read`/`write` paths (§4).

---

## 3. State machine

### 3.1 `proxy_dev.state` bit flags

| Bit | Flag | Meaning |
|---|---|---|
| 0 | `STATE_OPENED_FLAG` | server side is open (set by the simulated open, cleared by `undo_open`) |
| 1 | `STATE_WAIT_RESPONSE_FLAG` | server has `read()` a command and owes a response |
| 2 | `STATE_REGISTERED_FLAG` | async `tpm_chip_register()` succeeded |
| 3 | `STATE_DRIVER_COMMAND` | kernel itself is issuing a SET_LOCALITY command (bypasses the driver-command rejection in `send`) |

### 3.2 Creation / registration (asynchronous)

```
NEW_DEV
  ├─ CAP_SYS_ADMIN, copy_in, flags ok
  ├─ create_proxy_dev: kzalloc(proxy_dev); init wq/mutex/work;
  │                    tpm_chip_alloc(&vtpm_proxy_tpm_ops); drvdata=proxy_dev
  ├─ get_unused_fd_flags()
  ├─ anon_inode_getfile("[vtpms]", vtpm_proxy_fops, proxy_dev)
  ├─ fops_open(): state |= OPENED
  ├─ (TPM2?) chip->flags |= TPM_CHIP_FLAG_TPM2
  ├─ queue_work(vtpm_proxy_work)  ──► tpm_chip_register()
  │                                    success → state |= REGISTERED
  │                                    failure → fops_undo_open()
  ├─ fill out fd/major/minor/tpm_num ; copy_to_user
  └─ fd_install(fd)                    (server fd now live in userspace)
```

### 3. Runtime request/response loop (per command)

```
client write(/dev/tpmN)
  → tpm_op_send: count>4096? EIO
                  !DRIVER_COMMAND && is_driver_command? EFAULT
                  !OPENED? EPIPE
                  buf_lock: resp_len=0; req_len=count; memcpy(buffer,cmd,count)
                            clear WAIT_RESPONSE; wake server
server read("[vtpms]")
  → wait_event(req_len!=0 || !OPENED); !OPENED? EPIPE
    buf_lock: count<req_len || req_len>4096? EIO
              copy_to_user(server, buffer, req_len); memset; req_len=0
              set WAIT_RESPONSE
server write("[vtpms]")
  → buf_lock: !OPENED? EPIPE
              count>4096 || !WAIT_RESPONSE? EIO
              clear WAIT_RESPONSE; req_len=0
              copy_from_user(buffer, resp, count); resp_len=count; wake client
client read(/dev/tpmN)
  → tpm_op_recv: !OPENED? EPIPE
                 count<resp_len? EIO ; memcpy(client, buffer, resp_len); resp_len=0
```

### 3.4 Teardown

```
server fd close → vtpm_proxy_fops_release
   private_data=NULL
   vtpm_proxy_delete_device:
     ├─ work_stop(): fops_undo_open (clear OPENED, wake) ; flush_work()
     ├─ fops_undo_open() again (idempotent, wake)
     ├─ REGISTERED ? tpm_chip_unregister(chip)
     │     └─ tpm_del_char_device:
     │          cdev_device_del()          // no new client opens
     │          idr_replace(NULL)
     │          down_write(&chip->ops_sem) // WAIT for in-flight ops (readers)
     │          chip->ops = NULL           // new ops fail EIO
     │          up_write
     └─ delete_proxy_dev: put_device(chip) → tpm_dev_release → kfree(chip)
                          kfree(proxy_dev)
```

---

## 4. Buffer ownership (USERCOPY / SIZE / ARITHMETIC)

`proxy_dev.buffer` is a **fixed embedded array** `u8 buffer[TPM_BUFSIZE]`,
`TPM_BUFSIZE = 4096` (tpm.h:35) — there is no dynamic allocation sized by user
input, so the classic integer-overflow→undersized-alloc class does not apply.
All four copy sites are bounded against `sizeof(buffer)`:

| Path | Direction | Bound | Code |
|---|---|---|---|
| server `write` | user→kernel | `count > sizeof(buffer)` → EIO **before** copy | [:139], copy [:149] |
| server `read` | kernel→user | `count < len \|\| len > sizeof(buffer)` → EIO | [:94], copy [:101] |
| core `send` | kernel→buffer | `count > sizeof(buffer)` → EIO before `memcpy` | [:334], memcpy [:355] |
| core `recv` | buffer→kernel | `count < resp_len` → EIO before `memcpy` | [:281], memcpy [:289] |

`req_len` is only ever assigned `count` after the `send` size check, and
`resp_len` only after the server-`write` size check, so both length variables
are provably ≤ 4096 wherever they index `buffer`. All four sites run under
`buf_lock` (the core `send`/`recv` take it explicitly; the core reads
`state`/`resp_len` under it). No raw user pointer is stored: `copy_{from,to}_user`
complete inside each op while the user address is live.

---

## 5. Object-lifetime analysis (primary invariant)

### 5.1 Object table

| Object | Allocated | Owner / ref holders | Freed |
|---|---|---|---|
| `proxy_dev` | `kzalloc` in `create_proxy_dev` [:493] | server anon file `private_data`; `chip->dev` drvdata; queued `work` | `kfree` in `delete_proxy_dev` [:524], only after unregister |
| `tpm_chip` | `tpm_chip_alloc` [:501] | device refcount; client fds; in-flight ops (`get_device`) | `tpm_dev_release` → `kfree(chip)` on last put [:267] |
| server anon file | `anon_inode_getfile` [:556] | returned fd | `fput` → `vtpm_proxy_fops_release` |
| client `/dev/tpmN` | cdev during `tpm_chip_register` | client fds | `cdev_device_del` on unregister |

### 5.2 Can a reference outlive `kfree(proxy_dev)`? — four barriers

1. **`flush_work()`** in `work_stop` guarantees the asynchronous register work
   (which touches `proxy_dev->chip/state`) has completed before teardown
   proceeds.
2. **`down_write(&chip->ops_sem)`** in `tpm_del_char_device` blocks until every
   in-flight core callback releases its `down_read` (tpm-chip.c:454 vs
   `tpm_try_get_ops` tpm-chip.c:163 / `tpm_put_ops`:189).
3. **device refcount**: each core op does `get_device()` before touching the
   chip/drvdata and `put_device()` after; the chip (and the teardown that frees
   `proxy_dev`) cannot disappear underneath a running callback.
4. **`cdev_device_del()`** prevents new client opens before `ops` is nulled; new
   `tpm_try_get_ops` then see `chip->ops == NULL` and return `-EIO`.

The server `read` path that blocks in `wait_event_interruptible` holds the
file reference; the file's `.release` (which triggers deletion) cannot run until
that reference is dropped, so a woken `read` re-checking `OPENED` under
`buf_lock` still touches live memory.

**Static conclusion:** at the fixed boundary and the obvious teardown/UAF
patterns, the lifetime graph is closed on 6.8. This is recorded as a *proven-safe
invariant*, not as the absence of bugs — stateful interleavings (§7) still need
KASAN confirmation.

### 5.3 Error-path rollback audit

| Failure point | Rollback | Correct? |
|---|---|---|
| `tpm_chip_alloc` fails | `kfree(proxy_dev)` | ✅ no work queued yet |
| `get_unused_fd_flags` fails | `delete_proxy_dev` (put chip + kfree) | ✅ |
| `anon_inode_getfile` fails | `put_unused_fd` + `delete_proxy_dev` | ✅ before `queue_work` |
| `copy_to_user` of result fails [:645] | `put_unused_fd` + `fput(file)` → release → full `delete_device` | ✅ single free path, no double free |
| async register fails | work calls `fops_undo_open`; later close skips unregister (no REGISTERED) | ✅ flag-guarded |

---

## 6. Security-invariant register (Phase-2A status)

| Class | Invariant | Static | To verify dynamically |
|---|---|---|---|
| CAPABILITY | only CAP_SYS_ADMIN can create devices | hold | EPERM as non-root |
| FLAGS | `flags` subset of bit0 | hold | each unknown bit → EOPNOTSUPP |
| USERCOPY | fixed 20 B ioctl copies; 4 bounded buffer copies | hold | bad user ptr → EFAULT |
| SIZE | every r/w `count` checked vs 4096 | hold | count 0/1/4096/4097/MAX |
| STATE | server write requires WAIT_RESPONSE; ops require OPENED | hold | write-before-read; after-close |
| LIFETIME | ops_sem + refcount + flush_work + cdev_del | hold (§5) | rapid create/close vs client I/O; dup/close races |
| DRIVER-CMD | userspace cannot inject SET_LOCALITY (DRIVER_COMMAND gate) | hold | send 0x20001000 as client → EFAULT |

---

## 7. Phase-3 dynamic plan (stateful, single-variable, KASAN)

### 7.1 Legal state-transition matrix (Phase 3-1)
NEW_DEV ×N (fd leak / exhaustion) · immediate close before register work runs ·
close after REGISTERED · the full read→write command loop · write without prior
read · read twice for one command · write twice · poll before/after ·
SET_LOCALITY from client vs from kernel · emulator never responding (client
timeout/cancel) · emulator responding oversized/short.

### 7.2 Boundary mutation (Phase 3-2), one variable at a time on a legal sequence
`count ∈ {0,1,4095,4096,4097,MAX}` on server read/write; `flags ∈ {0,1,2,0xffffffff}`;
bogus user pointers; duplicate NEW_DEV; close during blocking read; close during
client transmit; multiple threads on the server fd; server-close racing client
write (the LIFETIME test §5).

### 7.3 KASAN watch list
heap-use-after-free, slab-out-of-bounds on `buffer`, double-free/invalid-free on
teardown, use-after-scope around `work`; plus BUG/WARNING/refcount (manually
triaged — a warning alone is not a vulnerability). Concurrency stress (Phase
3-4) only after the single-thread deterministic matrix is green.

### 7.4 Harness
`harness/vtpmx_probe.c` — Phase-2B: performs NEW_DEV, drives the server loop
against a minimal in-process emulator, and walks the transition matrix, logging
expected vs observed errno/state, ready to run natively and under the KASAN QEMU
guest with GDB parked on `vtpmx_ioc_new_dev`.
