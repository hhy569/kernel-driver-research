# vtpmx → TPM core call graph & locking/lifetime map (Linux 6.8)

Scope: `tpm_vtpm_proxy.c` (vtpmx control + server fd), `tpm-chip.c` (chip object & char-dev
lifecycle), `tpm-interface.c` (command transmit), `tpm-dev-common.c` + `tpm-dev.c` /
`tpmrm-dev.c` (client char-device frontend). This is a **bounded** map of the four paths the
harnesses exercise — not a full audit of the TPM subsystem.

Two independent file descriptors share **one** `struct proxy_dev` / `struct tpm_chip`:

```
   userspace TPM emulator (needs CAP_SYS_ADMIN)          client (any user)
   ─────────────────────────────────────────           ───────────────────
   open /dev/vtpmx (control, miscdevice 10:263)
   ioctl VTPM_PROXY_IOC_NEW_DEV
        │  ── returns ──► server fd  "[vtpms]" (anon_inode, vtpm_proxy_fops)
        │                  + creates /dev/tpmN (tpm_fops) and /dev/tpmrmN (tpmrm_fops)
        │                                              open /dev/tpmN  (raw, single holder)
        ▼                                              open /dev/tpmrmN (RM, multi-open)
   server read()  ◄── kernel queues command bytes
   server write() ──► kernel consumes response bytes        write()/read()/poll()
```

---

## A. Creation / registration path

```
vtpmx_fops.ioctl ──► vtpmx_ioc_new_dev()                      [tpm_vtpm_proxy.c:624]
   ├─ capable(CAP_SYS_ADMIN)              else -EPERM
   ├─ copy_from_user(&s, arg, 20)        else -EFAULT
   ├─ create_device(&s)                                    [:533]
   │     ├─ (flags & ~VTPM_PROXY_FLAG_TPM2) ? -EOPNOTSUPP
   │     ├─ create_proxy_dev()                             [:487]
   │     │     ├─ kzalloc(struct proxy_dev)                [:493]
   │     │     └─ tpm_chip_alloc(NULL, &proxy_dev->chip, &vtpmx_tpm, ...)  [:501]
   │     │           └─ chip->ops = vtpmx_tpm (send=tpm_op_send, recv=tpm_op_recv,
   │     │                      cancel=tpm_op_cancel, req_complete_mask/val,
   │     │                      flags=TPM_OPS_AUTO_STARTUP)
   │     ├─ get_unused_fd_flags(O_CLOEXEC)   err: err_delete_proxy_dev   [:550]
   │     ├─ anon_inode_getfile("[vtpms]", &vtpm_proxy_fops, proxy_dev, O_RDWR) [:556]
   │     ├─ vtpm_proxy_fops_undo_open? -> fops_open(proxy_dev)           [:565]
   │     │     └─ work_start(): queue_work(tpm_wq, proxy_dev->work)      [:570]
   │     └─ s.fd=fd; copy tpm_num/major/minor to user                    [:572]
   │           err: err_put_unused_fd -> fput -> delete_device (slow rollback)
   ├─ copy_to_user(arg,&s,20)   err -> put_unused_fd + fput (→ delete_device)  [:645]
   └─ fd_install(fd, file)                                    [:652]

proxy_dev->work = vtpm_proxy_work()                        [:451]
   └─ tpm2_startup? via tpm_chip_register():
        tpm_chip_register() (tpm-chip.c)
          ├─ (AUTO_STARTUP) tpm_startup/chip auto-init  ──► ops->send (tpm_op_send)
          │        writes TPM2_Startup to server fd; emulator MUST read+respond
          │        or register work blocks to the (minute-class) TPM timeout
          ├─ cdev_add /dev/tpmN (+ /dev/tpmrmN)
          └─ device becomes openable; idr stores chip
```

**Gate for the whole deep surface:** the emulator thread must service the auto-startup exchange
on the server fd before `/dev/tpmN` appears. This is why every harness runs a per-device pthread
emulator and `wait_dev()` polls for the node.

---

## B. Client command round-trip (blocking and async)

```
client write(/dev/tpmN, cmd, len)                        tpm_common_write() [tpm-dev-common.c:165]
   ├─ len > TPM_BUFSIZE(4096) -> -E2BIG
   ├─ mutex_lock(&priv->buffer_mutex)
   ├─ (!response_read && response_length) || command_enqueued -> -EBUSY
   ├─ copy_from_user(data_buffer, len); len<6 || len<be32(hdr.length) -> -EINVAL
   ├─ response_length=0; response_read=false
   ├─ if O_NONBLOCK:
   │     command_enqueued=true; queue_work(tpm_dev_wq, priv->async_work); return len
   │                 │  (async) tpm_dev_async_work()                [:55]
   │                 │     mutex_lock(buffer_mutex); tpm_try_get_ops()
   │                 │     tpm_dev_transmit(); tpm_put_ops()
   │                 │     response_length=ret; mod_timer(user_read_timer,120s)
   │                 │     wake_up_interruptible(&priv->async_wait) ◄── poll() waits here
   │     else (blocking):
   └─ tpm_try_get_ops(chip)  ── down_read(&chip->ops_sem); chip->ops NULL? -> -EPIPE  [:218]
        tpm_dev_transmit()                               [:24]
          ├─ tpm2_prepare_space()   (RM only; raw passes NULL space)
          └─ tpm_transmit() (tpm-interface.c)
               └─ tpm_try_transmit()
                    ├─ ops->send  = tpm_op_send()         [tpm_vtpm_proxy.c:330]
                    │     ├─ SET_LOCALITY ordinal 0x20001000 -> -EFAULT
                    │     ├─ len > TPM_BUFSIZE -> -EFAULT
                    │     ├─ mutex_lock(&proxy_dev->buf_lock); copy cmd into buffer[]
                    │     ├─ state |= WAIT_RESPONSE; wake_up_interruptible(buf_wq)
                    │     │      └──► server fops_read() unblocks, returns command bytes
                    │     └─ (non-IRQ) poll loop tpm_op_status() until response/timeout
                    │            req_canceled -> -ECANCELED ; timeout -> ops->cancel + -ETIME
                    ├─ ops->recv  = tpm_op_recv()         [:267]
                    │     └──► server fops_write() delivers response under buf_lock;
                    │         validates be32(hdr.length); len<10 or mismatch -> -EFAULT
                    └─ returns response length
        tpm_put_ops(chip) ── up_read(&ops_sem); put_device()   (may kfree chip after release)
   response_length=ret; mod_timer(120s)

client read()  tpm_common_read()                        [:125]
   mutex_lock(buffer_mutex); if response_length:
     ret_size=min(size, response_length)
     copy_to_user(buf, data_buffer + *off, ret_size)
     memset(data_buffer + *off, 0, ret_size); response_length-=ret_size; *off+=ret_size
   when response_length==0: *off=0; del_timer_sync; flush_work(timeout_work)
client poll()  tpm_common_poll()                        [:237]
   poll_wait(async_wait); response_length ? EPOLLIN : EPOLLOUT
```

**Server side of the pipe** (`vtpm_proxy_fops`, the "[vtpms]" anon inode):
```
fops_read()  [:72]  wait_event(buf_wq, state&WAIT_RESPONSE || !REGISTERED) under buf_lock;
                   copy command from proxy_dev->buffer to user; clear WAIT_RESPONSE
fops_write() [:127] copy response user->buffer under buf_lock; validate length;
                   state &= ~WAIT_RESPONSE; wake_up (tpm_op_status / req_complete)
fops_poll()  [:171] reports readable when a command is queued
```

### Offset invariant audited and closed (no bug)
`tpm_common_read()` indexes `data_buffer + *off`. `*off` is `file->f_pos`, but both `tpm_fops`
and `tpmrm_fops` set **`.llseek = no_llseek`**, so `lseek()` fails with `-ESPIPE` and userspace
cannot move the offset. `write()` resets `*off=0`, and each read maintains
`*off + response_length == total_response_len ≤ TPM_BUFSIZE` under `buffer_mutex`. The
`data_buffer[TPM_BUFSIZE]` (last field of `struct file_priv`) therefore cannot be indexed out of
bounds through the offset. Verified dynamically by case **A** of `vtpmx_async.c` (`lseek → ESPIPE`).
A negative `response_length` (async error) is caught by `ret_size <= 0`; it only yields a spurious
EPOLLIN / zero-length read, a semantic quirk, not a memory-safety issue.

---

## C. State flags (one `proxy_dev`, guarded by `buf_lock`)

```
OPENED        bit0  set on fops_open (server fd opened), cleared on undo
WAIT_RESPONSE bit1  command queued, awaiting emulator response
REGISTERED    bit2  tpm_chip_register() succeeded (controls whether unregister runs)
DRIVER_COMMAND bit3 marker for in-kernel/driver ordinal traffic
transitions driven by:  fops_read/fops_write (server), tpm_op_send/recv (kernel client),
                        register work, and close/teardown.
```

---

## D. Teardown / lifetime path (the core of the race study)

```
close(server fd) ──► vtpm_proxy_fops.release = fops_release()   [:233]
   └─ delete_device()                                        [:591]
        ├─ work_stop()                                       [:470]
        │     └─ cancel_work_sync / flush proxy_dev->work (fops_undo_open + flush_work)
        ├─ fops_undo_open()
        └─ if state&REGISTERED:
              tpm_chip_unregister()  (tpm-chip.c:669)
                └─ tpm_del_char_device()                      [:444]
                     ├─ cdev_device_del()         ◄─ blocks NEW open()/ioctl on the cdev
                     ├─ idr_replace(...,NULL)    ◄─ removes chip from idr lookup
                     ├─ down_write(&chip->ops_sem)  ◄─ WAITS for every in-flight callback
                     │      tpm_try_get_ops()  : down_read  (tpm-interface transmit / async_work)
                     │      tpm_put_ops()      : up_read + put_device()
                     ├─ chip->ops = NULL
                     └─ up_write
        delete_proxy_dev() -> put_device -> tpm_dev_release()  [:267]
              idr_remove; kfree context_buf/session_buf/allocated_banks; kfree(chip)

close(client fd) ──► tpm_release()/tpmrm_release()
   └─ tpm_common_release()        [tpm-dev-common.c:262]
        flush_work(&async_work)         ◄─ NONBLOCK in-flight transmit completes/cancels
        del_timer_sync(user_read_timer)
        flush_work(timeout_work)
   raw: clear is_open; kfree(priv)      RM: tpm2_del_space; kfree(tpmrm_priv)
```

**Four independent lifetime barriers (statically identified):**
1. `work_stop()` drains the register work before unregister.
2. `cdev_device_del()` + `idr_replace(NULL)` stop new opens/lookups before ops are torn down.
3. `down_write(&ops_sem)` in teardown excludes all in-flight `down_read` transmit/async callbacks.
4. cdev/refcount (`put_device` → `tpm_dev_release`) frees `chip` only after the last ops user
   calls `tpm_put_ops()`.

The harnesses validate these dynamically:
- **R1** (blocking transmit vs server close, W1/W2/W3): in-flight op is cancelled → client gets
  fast `-ETIME`; `down_write` then proceeds (close ~0 ms blocked once the op is cancelled).
- **R4c / R10** (NONBLOCK `async_work` vs teardown / client close): `flush_work` + `down_write`
  resolve in 0.1–0.9 s with no hang on the stock kernel.
- **R2** (NEW_DEV vs register work, four timings) and **E3/E4** (fd exhaustion / read-only arg
  rollback) exercise the creation/error paths with zero net fd growth and bounded latency.

All of the above proves **synchronization and error-propagation correctness** on the stock kernel.
The barriers make a logical UAF unlikely, but only KASAN (Kernel B) can confirm the absence of a
slab UAF/OOB across these exact interleavings; KCSAN (Kernel C) would additionally cover a data
race on `state` across the locks.

---

## E. Fixed-size buffer summary (why arithmetic fuzzing is out of scope here)

- `struct proxy_dev.buffer[u8 TPM_BUFSIZE]`, `TPM_BUFSIZE=4096`, embedded (not dynamically sized).
- All four kernel↔server copies (`tpm_op_send`, `tpm_op_recv`, `fops_read`, `fops_write`) compare
  against `sizeof(buffer)` and run under `buf_lock`; no raw user pointer is retained;
  `req_len/resp_len` are always ≤ 4096. There is no attacker-controlled allocation size, so the
  integer-overflow→undersized-allocation class used in the Assimp/FFmpeg studies does not apply;
  the high-value surface for vtpmx is concurrency/object-lifetime, which the three harnesses target.
