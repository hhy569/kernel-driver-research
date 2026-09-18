# FUSE attack surface map

FUSE inverts the usual "untrusted file vs. kernel parser" model: the kernel is
the consumer and the **userspace filesystem daemon is the untrusted peer**.
A buggy or malicious daemon feeds crafted replies back into the kernel over
`/dev/fuse`.  This study occupies that seat deliberately: the harness *is* the
daemon, so it can drive the kernel's request state machine into phases that a
random on-disk file cannot reach.

## 1. Entry points

| Boundary | Interface | Privilege in this study |
|----------|-----------|-------------------------|
| Device | `/dev/fuse` misc char device (10:229), `open/read/write/poll/release` | opened by the daemon |
| Mount | `mount(2)` fstype `fuse`, options `fd=,rootmode=,user_id=,group_id=,…` | `CAP_SYS_ADMIN` (root in the research VM / initramfs) |
| Control | `/sys/fs/fuse/connections/<id>/{waiting,abort,…}` | root |
| Teardown | last `/dev/fuse` `close()` → `fuse_dev_release()`; `umount2(MNT_DETACH)` | daemon / root |

Outside this VM, unprivileged users can reach FUSE inside a user namespace where
the distribution permits it (the device node itself is commonly world
read/writable; the gate is mount capability).  That makes the daemon→kernel
ABI a realistic local attack surface, which motivates lifetime hardening.

## 2. Data the daemon controls (kernel consumes)

```
fuse_out_header { len, error, unique }      every reply
fixed / variable args (entry_out, attr_out, open_out, write_out, …)
raw READ payload                            byte count inferred from header len
FUSE_INTERRUPT reply                        unique with bit63 set
FUSE_FORGET / BATCH_FORGET                  no reply; separate forget list
INIT negotiation                            max_write, max_pages, minor, feature flags
```

Kernel-side validation that bounds this input lives in `do_write`
(header length == nbytes, error range, `request_find` lookup, `copy_out_args`
fixed-vs-variable length arithmetic) and in each `fuse_*_args` descriptor.
Malformed lengths, mismatched `unique`, late/duplicate replies and interrupt
ordering are the natural protocol-fuzzing surface; this study instead targets
the **temporal/state** dimension on top of otherwise-valid replies.

## 3. State dimension targeted here

```
                 daemon actions (this harness)
   allocate ─▶ pending ─read▶ processing ─write(copy)▶ finished
                  │             │              │
                  └─ abort ─────┴── abort ─────┘   (L1/L2/L4)
                       signal ─▶ interrupted ◀─ INTERRUPT reply (L3)
```

- **L1** abort while pending,
- **L2** abort while the request is owned by userspace (processing),
- **L3** signal-driven interrupt racing original completion in both orders,
- **L4** abort during the locked userspace copy.

## 4. Adjacent surface explicitly *not* covered (future work)

- Malformed `fuse_out_header.len` / variable-arg length arithmetic in
  `copy_out_args` (integer truncation, short/over-long args).
- `FUSE_BATCH_FORGET` and forget-list pressure vs. abort/interrupt (**L5**).
- Unsolicited/edge notifications and `FUSE_NOTIFY_*`, poll/wake paths.
- Background I/O (`FR_BACKGROUND`), readahead, write-back cache and reclaim.
- `FUSE_DAX` / virtio-fs transport (disabled in the research config:
  `CONFIG_VIRTIO_FS=n`, `CONFIG_FUSE_DAX=n`).
- Mount-option parsing and multi-device / submount behaviour.

These are listed so the negative result's scope is unambiguous: the
conclusions apply to the request-lifetime interleavings actually exercised.

## 5. Why direct `/dev/fuse` instead of libfuse

libfuse serialises and answers requests in a way that makes pending/processing
and interrupt timing hard to pin down, and it performs its own mount/abort
handling.  Speaking the wire protocol directly gives exact control of
read-permit / hold / reply / abort per request, which is what deterministic
invariant testing requires.  The trade-off is that INIT and the lab filesystem
must be implemented by hand (done in `fuse_session.c`); the protocol facts were
verified at runtime rather than assumed.
