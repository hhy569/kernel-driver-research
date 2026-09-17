# Linux Driver Attack-Surface Reconstruction — Phase 1

Target family: upstream Linux **6.8** misc/char device `ioctl()` handlers.
Lab: Ubuntu 24.04.3 guest (kernel 6.8.0-134), QEMU 8.2.2 available, local only.
Method: reconstruct the user→kernel trust boundary from source first, then
prove reachability and each safety invariant with a userspace harness. A crash
is never assumed to be a vulnerability.

This document is the Phase-1 deliverable: how the target was chosen, the device
model, the trust boundary, and the first end-to-end data-flow trace.

---

## 1. Target selection (evidence-driven, not "pick a famous driver")

The brief was: a `miscdevice` exposing `.unlocked_ioctl`, directly openable from
userspace, requiring **no physical hardware**, loadable on x86_64/QEMU, with a
non-trivial attack surface and a fast build loop.

### 1.1 Systematic enumeration of `drivers/misc`

Every `.c` under `drivers/misc` defining `.unlocked_ioctl`/`.compat_ioctl` was
enumerated and classified by its hardware dependency:

| File | misc node | ioctl | Hardware gate | Reachable without HW? |
|---|---|---|---|---|
| bcm-vk/bcm_vk_dev.c | bcm-vk | yes | `module_pci_driver` (Broadcom PCIe) | No |
| cxl/file.c, flash.c | cxl | yes (+compat) | IBM CAPI/OpenCAPI accelerator | No |
| fastrpc.c | fastrpc-* | yes (+compat) | Qualcomm platform/RPMSG (`qcom,fastrpc`) | No |
| genwqe/card_dev.c | genwqe | yes (+compat) | IBM GenWQE PCIe card | No |
| ibmvmc.c | ibmvmc | yes | IBM PowerVM (PPC) | No |
| mei/main.c | mei | yes (+compat) | Intel ME PCI function | No |
| nsm.c | nsm | yes (+compat) | platform (NSM hwrng) | No |
| ocxl/file.c | ocxl | yes (+compat) | IBM OpenCAPI | No |
| pci_endpoint_test.c | endpoint test | yes | PCI endpoint function | No |
| phantom.c | phantom | yes (+compat) | `depends on PCI`, Sensable PHANToM | No |
| sgi-gru/grufile.c | gru | yes | SGI UV (`X86_UV`) | No |
| tps6594-pfsm.c | pfsm-* | yes (+compat) | TI PMIC, platform/I2C | No |
| uacce/uacce.c | uacce | yes (+compat) | accelerator queue hardware | No |
| vmw_vmci/vmci_host.c | vmci | yes (+compat) | VMware hypervisor only | No (VirtualBox/QEMU) |
| xilinx_sdfec.c | xsdfec | yes (+compat) | Xilinx platform FEC | No |

**Finding (negative, but decisive): every ioctl-bearing driver in `drivers/misc`
is bound to a PCI/platform/I2C/PPC/hypervisor device.** On a generic x86 VM with
no such hardware, `insmod` succeeds but no `/dev` node and no probe path is
created, so the ioctl attack surface is unreachable. Selecting one anyway would
violate the "no hardware / fast build loop" requirement and turn the project
into an environment exercise.

### 1.2 Relaxing the *directory* while keeping the *criteria*

The requirement's substance is "**miscdevice + ioctl + no hardware + userspace
reachable**", not literally the `drivers/misc/` path. Three software-only
miscdevices are present and openable on the running VM itself:

| Device (source) | node | ioctl surface | HW needed | Reachable now? |
|---|---|---|---|---|
| `drivers/char/hpet.c` | `/dev/hpet` (10,228) | 6 commands + `mmap` + IRQ | HPET (provided by every x86 VM) | node yes; **0 free user timers on VirtualBox** (see §4) |
| `drivers/input/misc/uinput.c` | `/dev/uinput` (10,223) | ~20 commands incl. **variable-size** + force-feedback | none (virtual device) | **yes, fully** |
| `drivers/char/tpm/tpm_vtpm_proxy.c` | `/dev/vtpmx` (10,263) | 1 command (`NEW_DEV`) + buffer r/w | none (software vTPM factory) | yes (after `modprobe`) |

**Primary Phase-1 target: `uinput`.** It is a `miscdevice`
(`module_misc_device`), needs zero hardware, is openable on the current VM, and
has the richest reachable surface: fixed and variable-size ioctls, user-supplied
bitmaps, device-name/phys strings, abs-axis ranges, and a force-feedback
upload/erase state machine. `hpet` is carried as a second, fully statically
reconstructed case with an interesting environmental reachability gate;
`vtpmx` is the documented follow-up (newer, less fuzzed, TPM/security adjacent).

---

## 2. uinput device model and trust boundary

`uinput` lets a privileged userspace process **create a virtual input device**
and inject events into the input subsystem. The trust boundary is the ioctl
call that turns attacker-supplied bytes into kernel `struct input_dev` state,
allocated bitmaps, a name, abs-axis parameters, and force-feedback effect slots.

```
userspace process (root / CAP)
   │  open("/dev/uinput", O_RDWR)
   ▼
uinput_misc (minor 223) ── file_operations uinput_fops
   │  .unlocked_ioctl = uinput_ioctl ──► uinput_ioctl_handler()   [uinput.c:873]
   │
   ├─ UI_DEV_SETUP            copy_from_user(sizeof uinput_setup)
   │                            name ──► kstrndup(name, UINPUT_MAX_NAME_SIZE)
   │                            ff_effects_max ──► stored, used at CREATE
   ├─ UI_SET_{EV,KEY,REL,ABS,MSC,LED,SND,FF,SW,PROP}BIT
   │                            arg = bit index ──► uinput_set_bit macro
   │                            BOUNDS: arg > *_MAX ? -EINVAL : set_bit()
   ├─ UI_ABS_SETUP (var len)  size=_IOC_SIZE(cmd); size>sizeof? -E2BIG
   │                            copy_from_user(size); code>ABS_MAX? -ERANGE
   │                            validate_absinfo(min/max/flat)
   ├─ UI_SET_PHYS             strndup_user(p, 1024)
   ├─ UI_BEGIN/END_FF_UPLOAD/ERASE   request_id lookup + fixed copy
   ├─ UI_GET_SYSNAME (var)    copy_to_user bounded, NUL-terminated
   ├─ UI_DEV_CREATE           ──► input_register_device()
   │                            ff_effects_max ──► input_ff_create()
   └─ UI_DEV_DESTROY          ──► input_unregister_device() / teardown
            │
            ▼  (CREATE only)
   kernel input core: dev->evbit/keybit/absbit/... , dev->absinfo[],
                      dev->ff->effects[] / effect_owners[]   [ff-core.c]
```

### State machine (a gate the harness exercises)

`UIST_INIT → (UI_DEV_SETUP) → UIST_SETUP_COMPLETE → (UI_DEV_CREATE) →
UIST_CREATED`. After `UI_DEV_CREATE`, all mutating setup/bit ioctls return
`-EINVAL`, closing the "configure an already-live device" hole.

---

## 3. First end-to-end data-flow trace (user-controlled count → allocation → index)

The highest-value chain in this driver is the force-feedback effect count,
because it is the one place a user scalar sizes a kernel array that is later
indexed by a user-supplied id. This is the BIVAR "count → allocation → indexing"
invariant, ported to the kernel.

```
struct uinput_setup.ff_effects_max        (u32, fully user controlled)
   │  UI_DEV_SETUP: copy_from_user → udev->ff_effects_max      [uinput.c:464]
   ▼
UI_DEV_CREATE → uinput_create_device()
   │  if (ff_effects_max) input_ff_create(dev, ff_effects_max) [uinput.c:343-344]
   ▼
input_ff_create(max_effects)                                [ff-core.c:302]
   │  if (!max_effects)                         -> -EINVAL     [:308]
   │  if (max_effects > FF_MAX_EFFECTS)         -> -EINVAL     [:313]  (SIZE cap)
   │  size = sizeof(ff_device) + max_effects*sizeof(file*)
   │  if (size < max_effects) /* overflow */     -> error       [:320]  (ARITHMETIC)
   │  kzalloc(size);  kcalloc(max_effects, sizeof(ff_effect))  [:323-327]
   ▼
runtime indexing
   │  check_effect_access(ff, effect_id, file):
   │     effect_id < 0 || effect_id >= ff->max_effects -> -EINVAL [:24]  (BOUNDS)
   │  input_ff_upload: id==-1 → first free slot, id>=max -> -ENOSPC [:127]
   │                     else check_effect_access() before effects[id] [:136-142]
   ▼
ff->effects[id] / ff->effect_owners[id]      (index provably within allocation)
```

**Static conclusion:** the chain is closed at every link — an upper cap
(`FF_MAX_EFFECTS`), a multiplication-overflow check, `kcalloc`, and an
exclusive `[0,max_effects)` index check on every access. The harness confirms
the cap dynamically (`ff_effects_max=UINT32_MAX` → `UI_DEV_CREATE` rejected with
`EINVAL`).

---

## 4. HPET case and the environmental reachability gate

`hpet.c` is a miscdevice (`/dev/hpet`) with six ioctls (`HPET_IE_ON/OFF`,
`HPET_INFO`, `HPET_EPI/DPI`, `HPET_IRQFREQ`), `read`/`poll`, `fasync`, and
`mmap`. Static reconstruction is complete:

- `HPET_INFO` → fixed `sizeof(struct hpet_info)` `copy_to_user`; bogus pointer →
  `EFAULT` (verified).
- `HPET_IRQFREQ` is the only scalar-controlled command: `arg==0 → EINVAL`
  (prevents div-by-zero in `hpet_time_div`), `arg > hpet_max_freq` requires
  `CAP_SYS_RESOURCE`; arithmetic is 64-bit `div64_ul`.
- `hpet_mmap` maps only the HPET MMIO page; `vm_iomap_memory()` enforces
  `start+len` overflow, `vm_pgoff`, and `vm_len<=pages` checks
  (`mm/memory.c:2557`), so a larger/offset mmap cannot extend the mapping.
- Timer index used in `1 << (devp - hp_dev)` and `sprintf(hd_name,...)` derives
  from internal enumeration, not user input; `hp_dev[]` is annotated
  `__counted_by(hp_ntimer)`.

**Reachability gate (dynamic finding):** on this VirtualBox guest,
`open("/dev/hpet", O_RDONLY)` returns `EBUSY` for **all** opens — zero
user-available comparators. In `hpet_alloc()`, platform-reserved timers are
pre-flagged `HPET_OPEN` via the `hd_state` bitmask (`hpet.c:877-881`); the
VirtualBox HPET exposes only the timers the platform keeps for clockevents.
`O_RDWR` is correctly rejected with `EINVAL` (verified). QEMU's emulated HPET
exposes 32 comparators, so the ioctl paths become reachable under a QEMU/KASAN
guest (Phase 3); they are not reachable in this particular VirtualBox host.
This is exactly the kind of "device node exists but the handler is not
reachable" state that must be proven at runtime rather than assumed.

---

## 5. Phase-1 acceptance status

| Acceptance item | Status | Evidence |
|---|---|---|
| Source tree obtained for the target version | ✅ | linux-6.8 tarball extracted |
| Device node + major/minor | ✅ | `/dev/uinput` 10:223, `/dev/hpet` 10:228, `/dev/vtpmx` 10:263 |
| `file_operations` recovered | ✅ | `uinput_fops`, `hpet_fops` (§2, ioctl-map.md) |
| ioctl entry + full command table | ✅ | `uinput_ioctl_handler` switch; `hpet_ioctl_common` |
| Argument structs recovered | ✅ | uapi: `uinput_setup/abs_setup/ff_*`, `hpet_info` |
| Harness opens device and reaches handlers | ✅ | device created, `UI_GET_SYSNAME`→`input9` |
| One user-controlled field traced to kernel sink | ✅ | ff_effects_max → alloc → index (§3) |
| Boundary invariants dynamically confirmed | ✅ | 23/23 uinput checks pass (`traces/uinput_probe.txt`) |
| QEMU available for Phase-3 KASAN guest | ✅ | QEMU 8.2.2 installed |
| Kernel builds / GDB attaches / KASAN active | ⏳ Phase 3 | needs debug kernel build (LVM has +29G free) |

**Honest result:** at the fixed-command boundary of these mature,
syzkaller-covered drivers, all five invariant classes (USERCOPY / BOUNDS / SIZE
/ ARITHMETIC / LIFETIME) currently hold under static audit and boundary probing;
no defect is claimed. The value of Phase 1 is the reconstructed attack surface,
a reusable harness, proven reachability, and a precise map of where a bug could
and could not be. Deeper defects (slab/lifetime/race, post-validation state
machines) require the KASAN instrumented guest and stateful fuzzing in Phase 3.
