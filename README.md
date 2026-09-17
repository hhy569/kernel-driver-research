# Linux Driver Attack-Surface & Invariant Research

A from-scratch reconstruction of a real Linux kernel character/misc-device
`ioctl()` attack surface, following the same security-invariant methodology
developed in the BIVAR variant-hunting work — ported from userspace parsers to
the **user → kernel boundary**.

> Scope: local, open-source, upstream Linux code in an isolated QEMU/VM lab.
> No third-party systems. Phase 1 is attack-surface reconstruction, not bug
> hunting; crashes are triaged as evidence, never auto-labelled vulnerabilities.

## Why this project

`ioctl()` is the densest user→kernel trust boundary in Linux: userspace passes
a command plus an arbitrary pointer/length, and the driver must correctly
`copy_from_user`, validate indices/lengths, size allocations, and manage object
lifetimes. A single broken invariant is a kernel memory-safety bug. This project
proves the ability to:

1. reconstruct the full attack surface of a **real upstream driver** with no
   source assumed (works from the stripped `.ko` too),
2. trace one user-controlled byte from syscall to kernel sink,
3. express the required safety properties as explicit **invariants**, and
4. validate them dynamically with a userspace harness, GDB, and KASAN.

## Invariants (ported from BIVAR)

| Class | Kernel invariant |
|---|---|
| USERCOPY | `copy_size <= destination_size`; user pointer never dereferenced directly |
| BOUNDS | `index < object_count` before every array access |
| SIZE | allocation size `>= required`; no 32-bit wrap/truncation |
| ARITHMETIC | `count * elem` computed in `size_t`; signed/unsigned checked |
| LIFETIME | object stays allocated/registered until last dereference (no UAF/race) |

## Phases

- **Phase 1 — Attack Surface Reconstruction.** `/dev` node → `file_operations`
  → `.unlocked_ioctl` → per-command handlers → argument structs → kernel
  objects. Deliverables: `notes/attack-surface.md`, `notes/ioctl-map.md`.
- **Phase 2 — Invariant-Guided Audit.** Each handler mapped to USERCOPY /
  BOUNDS / SIZE / ARITHMETIC / LIFETIME checks and gaps.
- **Phase 3 — Dynamic Validation.** Minimal C harness → boundary/MAX/negative
  mutations → KASAN + GDB → root-cause and primitive characterization.

## Repository layout

```
kernel-driver-research/
├── README.md
├── notes/
│   ├── attack-surface.md      # device, fops, objects, trust boundary
│   └── ioctl-map.md           # cmd, direction, struct, handler, controlled fields
├── harness/
│   └── ioctl_probe.c          # minimal open()/ioctl() fuzzer/harness
├── traces/                    # GDB / KASAN / dmesg captures
└── findings/                  # any confirmed issue + root cause (or negative result)
```

## Environment

- Target: upstream Linux 6.8 (`drivers/misc`, miscdevice + `ioctl`, no physical
  hardware required, loadable in QEMU x86_64).
- Debug kernel config: `KASAN`, `KCOV`, `DEBUG_INFO_DWARF4`, `GDB_SCRIPTS`,
  `KALLSYMS_ALL`, `FRAME_POINTER`.
- Day-1 acceptance (per research plan): kernel builds / QEMU boots / GDB
  attaches / KASAN active / module loads; device node + fops + ioctl table
  recovered; harness reaches a handler; one user-controlled field traced to a
  sink.

## Integrity rules

- A crash is not a vulnerability until reproduced, minimized, root-caused, and
  matched against upstream issues/commits.
- Known/duplicate issues are labelled as such and used only for reproduction and
  variant analysis — never claimed as novel CVEs.
- A documented negative result with evidence (invariant holds under dynamic
  test) is a valid outcome.
