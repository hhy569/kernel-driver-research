# KASAN Guest Validation Matrix — vtpmx + FUSE Object-Lifetime Research

**Kernel**: Linux 6.8, Generic KASAN (`kasan=1 kasan_multi_shot=1`), QEMU/TCG (no KVM, nested), `-m 3072 -smp 2`.
**Rootfs**: static harness binaries built 2026-09-18 03:54, repacked `rootfs.cpio.gz` 05:00.
**Protocol**: one experiment per isolated boot (`tests=TAG`), autorun poweroff, serial captured to file.

## BOOT-K1 — vtpmx object-lifetime (L1-L5) on KASAN
Harness: `vtpmx_lifetime` v2 (semantic TPM2 emulator -> BOTH /dev/tpmN and /dev/tpmrmN).

| Case | Scenario | Result | Time |
|---|---|---|---|
| L1-dup | close(A) keeps chip alive via dup(B); close(last) tears down | PASS | 318 ms |
| L2-rm-teardown | RM fd held across chip teardown; orphan write bounded (errno=2, read=-1/errno=5) | PASS | 207 ms |
| L3-Q | x15 enqueue -> immediate teardown (pending/early-running window) | PASS | 1559 ms |
| L3-R | x3 deterministic RUNNING teardown; server close cancels WAIT_RESPONSE, wakes client in 12-14 ms | PASS | 1475 ms |
| L4 | raw + RM both in flight across teardown | PASS | 616 ms |
| L5 | RM multi-open ref isolation (A/B/C; close A, B/C survive) | PASS | 615 ms |

**SUMMARY**: pass=6, assertion_fail=0, env_skip=0, hang=0. RESULT: PASS.
**KASAN/BUG SUMMARY**: empty (no KASAN report, no Oops/BUG/UAF).

## BOOT-K2 — vtpmx R7 concurrent register/teardown churn on KASAN
Harness: `vtpmx_stress 30 0x1337` (pool of devices, millisecond event log).

- client_ops=1065, recreates=424, unexpected_errno=0, stray_nodes=0, rollback=0.
- All DEV0..DEV5 create/teardown complete logged (e.g. DEV3 teardown tpm2 complete).
- RESULT: PASS. **KASAN hits in whole log: 0.**

## BOOT-K3 — FUSE request-lifetime on KASAN
Harness: `fuse_lifetime` x10 deterministic + `fuse_l4` x12 probabilistic.

| Case | State / Gate | Action | Result |
|---|---|---|---|
| L1_PENDING_ABORT | FR_PENDING, daemon not read | ABORT (errno=103) | PASS x10 |
| L2_PROCESSING_ABORT | FR_SENT/PROCESSING, daemon-read-held op=14 | ABORT (errno=103) | PASS x10 |
| L3_I1 | signal-held READ, interrupt then reply-original | INTR(EAGAIN)->REPLY, saw_interrupt=1 | PASS x10 |
| L3_I2 | reply-original then interrupt (finished-before-intr) | saw_interrupt=0 | PASS x10 |
| L4_COPY_ABORT | FR_LOCKED, page-fault window, abort @243us-2353us | want=4096 write=4112 read_rc=39 hung=0 | PASS x12 |

**SUMMARY**: RESULT: PASS (both). **KASAN/BUG SUMMARY: empty.**

## Interpretation (per ChatGPT research rules)
- This is a **negative result with high methodological value**: under the *defined* deterministic interleaving space
  (L1-L5, R7 churn, FUSE L1-L4 + interrupt ordering), no memory-safety violation was observed on Generic KASAN.
- It does **NOT** prove the drivers are bug-free; it proves the invariants held on this instrumentation, this
  seed space, and this 6.8 commit. Rare scheduling windows the harness cannot pin remain open.
- Evidence boundary stated explicitly: KASAN clean != bug-free.
