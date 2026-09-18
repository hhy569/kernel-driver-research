# Kernel Object Lifetime Verification Framework

**A deterministic, KASAN-validated methodology for verifying object-lifetime and
reference-counting invariants across the user→kernel trust boundary.**

Two independent upstream subsystems were taken through the *same* closed loop:
`drivers/char/tpm/tpm_vtpm_proxy.c` and `fs/fuse/request.c`. Both ended with a
documented negative result on Generic KASAN — the value is in the methodology,
the harnesses, and the explicitly stated evidence boundary, not in a crash count.

> Local, open-source, upstream Linux 6.8 code in an isolated QEMU/TCG lab.
> No third-party systems. Crashes are evidence, never auto-labelled vulnerabilities.

---

## The framework (why two targets share one method)

```
Attack Surface Reconstruction
        │
        ▼
State-Machine Reconstruction      (objects: owner, refcount, lock, queue, abort, release)
        │
        ▼
Lifetime Invariant Extraction     (what must always hold across concurrent close/abort/unmount)
        │
        ▼
Critical Transition Identification (which interleaving window is hard to reach)
        │
        ▼
Deterministic Interleaving Harness (pin the scheduling gate in userspace, no random fuzz)
        │
        ▼
KASAN Validation                  (Generic KASAN, one experiment per isolated boot)
        │
        ▼
Negative Result / Evidence Boundary
```

```
                Kernel Object Lifetime Verification
                         │
          ┌──────────────┴──────────────┐
          ▼                            ▼
   tpm_vtpm_proxy                  FUSE
   fd / device / chip /           request / interrupt /
   ops_sem / workqueue             abort / completion
          │                            │
          └──────────────┬─────────────┘
                         ▼
              common methodology
```

---

## Target 1 — tpm_vtpm_proxy (fd / device / work lifetime)

**Why**: a misc device that creates per-emulator virtual TPM chips; the
interesting surface is **not** the ioctl itself but what happens when clients,
the RM (`/dev/tpmrmN`), and the emulator server close at different times.

**Reconstructed invariants**:
- Closing one `dup()` reference must keep the chip alive and serviceable; only the
  *last* reference tears it down.
- A `/dev/tpmrmN` client held open across chip teardown must get bounded errors,
  never a hang/UAF.
- A running command parked `WAIT_RESPONSE` must be cancelled and wake its client
  when the server fd closes (deterministic RUNNING teardown).
- Raw + RM clients in flight across teardown must both resolve promptly.
- RM multi-open references must be isolated; the chip lives until the server fd closes.

**Harnesses** (`harness/`): `vtpmx_stress` (R7 device pool churn, millisecond event
log) + `vtpmx_lifetime` v2 (semantic TPM2 emulator so **both** `/dev/tpmN` and
`/dev/tpmrmN` appear).

**KASAN result** (`notes/kasan-results.md`):

| Boot | What ran | Result |
|---|---|---|
| BOOT-K1 | L1 dup / L2 RM-teardown / L3-Q×15 / L3-R×3 running-teardown / L4 raw+RM / L5 RM multi-open | pass=6, hang=0, **KASAN report: none** |
| BOOT-K2 | R7 stress: client_ops=1065, recreates=424, stray_nodes=0, rollback=0 | **KASAN hits in whole log: 0** |

---

## Target 2 — FUSE request lifetime (request / interrupt / abort)

**Why**: FUSE requests have a rich pending→processing→completed/aborted/interrupted
state machine; the sharpest question is what happens to a request's memory when the
daemon stops reading, aborts, unmounts, or interrupts *while* the kernel is still
touching it.

**Reconstructed cases**:
- **L1** pending request × daemon close → bounded abort (errno=ECONNABORTED).
- **L2** processing request (daemon-read-held) × abort → bounded, no hang.
- **L3-I1** interrupt-then-reply and **L3-I2** reply-then-interrupt (both orderings
  of the interrupt race) — deterministic signal-held-READ gate.
- **L4** request × abort across the **page-fault / copy window** (FR_LOCKED),
  aborted @243µs–2353µs — the exact "copy userspace data in flight" window.

**Harnesses** (`fuse-lifetime/harness/`): `fuse_smoke`, `fuse_lifetime` (deterministic
L1–L3), `fuse_l4_copyabort` (probabilistic abort inside the copy).

**KASAN result**: L1/L2/L3-I1/L3-I2 PASS ×10, L4-copy-abort PASS ×12, `hung=0`
throughout — **KASAN report: none**.

---

## What a "clean" run does and does not mean

Per the research rules this project follows:

> Under the *defined* deterministic interleaving space (L1–L5, R7 churn, FUSE L1–L4
> plus both interrupt orderings), Generic KASAN did not observe a memory-safety /
> lifetime violation.

This is **not** "the drivers are safe". It means: on this 6.8 commit, this
instrumentation, and this pinned scheduling gate, the invariants held. Rare
scheduling windows the userspace harness cannot pin remain open. A documented
negative result with an explicit boundary is a valid deliverable.

---

## Repository layout

```
├── README.md                  # this file (the framework view)
├── harness/                   # vtpmx probes / race / err / async / stress / lifetime
├── fuse-lifetime/
│   ├── attack-surface.md      # fuse_conn / fuse_dev / fuse_req / fuse_mount object graph
│   ├── request-state.md       # NEW→PENDING→PROCESSING→COMPLETED/ABORTED/INTERRUPTED
│   ├── lifetime-invariants.md
│   └── harness/               # fuse_smoke / fuse_lifetime / fuse_l4_copyabort / session
├── notes/
│   ├── vtpmx-call-graph.md    # create/delete_device, work_stop, teardown order
│   ├── vtpmx-state-machine.md
│   ├── kernel-lifetime-test-matrix.md
│   ├── kasan-results.md       # BOOT-K1/K2/K3 numbers (this round)
│   └── ...
├── src-ref/                   # vendored upstream 6.8 sources (tpm + fuse) for line refs
├── tools/kasan_triage.sh     # serial-log KASAN classifier
├── rootfs-init/               # initramfs init, tests=TAG dispatch
└── traces/                    # serial logs for every boot
```

## Reproducing

```bash
# build KASAN kernel (already done: bzImage #1), then per-boot:
./run_qemu.sh auto k1.log 400 lifetime   # vtpmx L1-L5
./run_qemu.sh auto k2.log 400 stress     # R7 churn
./run_qemu.sh auto k3.log 500 fuse       # FUSE L1-L4 + interrupt
```

Each boot is isolated, autoruns its subset, poweroffs, and the init prints a
`KASAN / BUG SUMMARY`. See `notes/environment.md`.

## Integrity rules

- Crash ≠ vulnerability; known/duplicate upstream issues are labelled as such and
  never claimed as novel CVEs.
- No claim of "no bug" — only "no violation observed in the tested space".
