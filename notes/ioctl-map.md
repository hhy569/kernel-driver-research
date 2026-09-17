# IOCTL Map — uinput (primary) and hpet (secondary)

Columns: **Cmd** (encoded number) · **Dir** · **Arg struct** · **Handler** ·
**User-controlled fields** · **Validation observed in source** · **Invariant** ·
**Dynamic result** from the harness (`traces/`). Invariant classes:
U=USERCOPY, B=BOUNDS, S=SIZE, A=ARITHMETIC, L=LIFETIME/state.

---

## A. uinput — `/dev/uinput` (misc 10:223), entry `uinput_ioctl_handler` [uinput.c:873]

| Cmd (nr) | Dir | Arg / struct | Handler | User-controlled fields | Validation (source) | Inv. | Harness result |
|---|---|---|---|---|---|---|---|
| UI_DEV_CREATE (1) | none | — | `uinput_create_device` | prior setup state | EV_FF set ⇒ ff_effects_max≠0; `input_ff_create` caps/overflow | S,A,L | success; UINT32_MAX ff count ⇒ EINVAL |
| UI_DEV_DESTROY (2) | none | — | `uinput_destroy_device` | — | teardown + state reset | L | success |
| UI_DEV_SETUP (3) | W | `struct uinput_setup` (id.bustype/vendor/product/version, name[80], ff_effects_max) | `uinput_dev_setup` [:446] | entire struct; name; ff count | state≠CREATED; `copy_from_user` sizeof; `name[0]!=0`; `kstrndup(name, UINPUT_MAX_NAME_SIZE=80)` | U,L | empty name⇒EINVAL; bogus ptr⇒EFAULT; valid⇒ok |
| UI_ABS_SETUP (4) | W | `struct uinput_abs_setup` (code, input_absinfo value/min/max/fuzz/flat/res) **variable size** | `uinput_abs_setup` [:472] | code; all absinfo ints | `size>sizeof⇒E2BIG`; zero-init local; `code>ABS_MAX⇒ERANGE`; `validate_absinfo`: max<min⇒EINVAL, `check_sub_overflow` + flat>range⇒EINVAL | U,B,S,A | valid ok; bad code ERANGE; max<min EINVAL; flat>range EINVAL; oversize E2BIG |
| UI_SET_EVBIT (100) | W | int bit | macro `uinput_set_bit` [:837] | bit index | state≠CREATED; `arg>EV_MAX⇒EINVAL` else `set_bit` | B,L | EV_KEY ok; EV_MAX+1 EINVAL; after-CREATE EINVAL |
| UI_SET_KEYBIT (101) | W | int | macro | bit index | `arg>KEY_MAX⇒EINVAL` | B | KEY_A ok; KEY_MAX+1 EINVAL |
| UI_SET_RELBIT (102) | W | int | macro | bit index | `arg>REL_MAX` | B | (same macro) |
| UI_SET_ABSBIT (103) | W | int | macro | bit index | `arg>ABS_MAX` | B | ABS_X ok; ABS_MAX+1 EINVAL |
| UI_SET_MSCBIT (104) | W | int | macro | bit index | `arg>MSC_MAX` | B | — |
| UI_SET_LEDBIT (105) | W | int | macro | bit index | `arg>LED_MAX` | B | — |
| UI_SET_SNDBIT (106) | W | int | macro | bit index | `arg>SND_MAX` | B | — |
| UI_SET_FFBIT (107) | W | int | macro | bit index | `arg>FF_MAX` | B | FF_RUMBLE ok |
| UI_SET_PHYS (108) | W | char* NUL string | case [:957] | phys string | state≠CREATED; `strndup_user(p,1024)` (bounded) | U,S | — |
| UI_SET_SWBIT (109) | W | int | macro | bit index | `arg>SW_MAX` | B | — |
| UI_SET_PROPBIT (110) | W | int | macro | bit index | `arg>INPUT_PROP_MAX` | B | PROP_MAX+1 EINVAL |
| UI_BEGIN_FF_UPLOAD (200) | RW | `struct uinput_ff_upload` (request_id, retval, ff_effect, old) | `uinput_ff_upload_from_user` + case [:975] | request_id, effect | `copy_from_user` sizeof; `uinput_request_find`: `id>=UINPUT_NUM_REQUESTS⇒NULL⇒EINVAL`; must be a pending UPLOAD with effect | U,B | EINVAL with no pending request |
| UI_END_FF_UPLOAD (201) | W | `uinput_ff_upload` | case [:1018] | request_id, retval | same lookup + type check; `complete(&req->done)` | B,L | — |
| UI_BEGIN_FF_ERASE (202) | RW | `struct uinput_ff_erase` | case [:989] | request_id, effect_id | fixed `copy_from_user`; request lookup/type; fixed `copy_to_user` | U,B | — |
| UI_END_FF_ERASE (203) | W | `uinput_ff_erase` | case [:1030] | request_id, retval | lookup/type; complete | B,L | — |
| UI_GET_SYSNAME (44) | R | char[len] **variable** | `uinput_str_to_user` [:857] | output buffer len = `_IOC_SIZE` | `maxlen==0⇒EINVAL`; `len=strlen+1`, capped to maxlen; `copy_to_user`; force NUL at `p+len-1` | U,S | len 256 ⇒ `input9` (ret 7); len 0 ⇒ EINVAL |
| UI_GET_VERSION (45) | R | unsigned int | case | — | fixed copyout | U | — |
| unknown / other | — | — | default | — | falls through to `-EINVAL` | — | cmd 0x7e ⇒ EINVAL |

**Legacy `write()` path** (`uinput_setup_device_legacy` [:513]): requires
`count == sizeof(struct uinput_user_dev)` exactly, then `memdup_user` of that
fixed size — a strict SIZE gate before any field is consumed.

### Force-feedback cross-file indexing (input core, `drivers/input/ff-core.c`)

| Function | Line | Check |
|---|---|---|
| `input_ff_create(max)` | 308/313/320/327 | `max==0` reject; `max>FF_MAX_EFFECTS` reject; `sizeof+max*elem` overflow reject; `kcalloc` |
| `check_effect_access` | 24 | `effect_id<0 \|\| effect_id>=max_effects` ⇒ EINVAL; owner match ⇒ EACCES |
| `input_ff_upload` | 122-142 | id `-1`→first free, `id>=max⇒ENOSPC`; else access check before `effects[id]` |
| `input_ff_flush` | 242 | loop bounded by `max_effects` |

Harness: **23/23 boundary checks returned the expected errno, 0 unexpected**
(`traces/uinput_probe.txt`). Two first-run "failures" were harness encoding bugs
(used nr 0x40 instead of 4; treated `UI_GET_SYSNAME` positive length return as
failure), corrected and re-verified — they were not driver defects.

---

## B. hpet — `/dev/hpet` (misc 10:228), entry `hpet_ioctl` → `hpet_ioctl_common` [hpet.c:540]

| Cmd (nr) | Dir | Arg | Handler | User-controlled | Validation (source) | Inv. | Dynamic result |
|---|---|---|---|---|---|---|---|
| HPET_IE_ON (1) | none | — | `hpet_ioctl_ieon` [:419] | — (uses stored freq) | needs `hd_ireqfreq≠0` else EIO; already IE ⇒ EBUSY; `request_irq` failure unwinds flag | L | open gate EBUSY on VirtualBox (no free timer) |
| HPET_IE_OFF (2) | none | — | common [:567] | — | only if IE set; `free_irq`; clears flag | L | — |
| HPET_INFO (3) | R | `struct hpet_info` (ulong freq, ulong flags, u16 hpet, u16 timer) | common [:578] + `copy_to_user` | output only | memset then fixed sizeof copyout; timer index = internal pointer diff | U | O_RDWR⇒EINVAL verified; INFO blocked behind open gate on VBox |
| HPET_EPI (4) | none | — | common [:591] | — | periodic-capable bit else ENXIO; sets PERIODIC | — | — |
| HPET_DPI (5) | none | — | common [:601] | — | capability check; clears PERIODIC | — | — |
| HPET_IRQFREQ (6) | W | unsigned long Hz | common [:612] | **arg (frequency)** | `arg>hpet_max_freq && !CAP_SYS_RESOURCE⇒EACCES`; `arg==0⇒EINVAL` (no div-by-zero); `hpet_time_div`: 64-bit `div64_ul(tick_freq+(arg>>1), arg)` | A | logic verified by source; runtime behind open gate |
| `read()` | — | user buf, count | `hpet_read` [:258] | count | `count<sizeof(unsigned long)⇒EINVAL`; single `put_user` | U,S | — |
| `mmap()` | — | vma | `hpet_mmap` [:345] | vma len/pgoff | maps internal HPET phys page; `vm_iomap_memory` rejects overflow / pgoff>pages / len>one page | S | to be confirmed under QEMU |

**Reachability note:** `/dev/hpet` exists but every `open(O_RDONLY)` returns
`EBUSY` on VirtualBox because all comparators are platform-reserved
(`hd_state`/`HPET_OPEN` in `hpet_alloc`, hpet.c:877). The ioctl table is fully
reconstructed from source; the runtime ioctl cases will be exercised in the
QEMU/KASAN guest (32 comparators) in Phase 3.

---

## C. Candidate follow-up: tpm_vtpm_proxy — `/dev/vtpmx` (misc 10:263)

| Cmd | Dir | Struct | Handler | Notes |
|---|---|---|---|---|
| VTPM_PROXY_IOC_NEW_DEV | W/R | `vtpm_proxy_new_dev` (flags, tpm_version, major/minor out) | `vtpmx_ioc_new_dev` [:624] | `copy_from_user` then `copy_to_user`; creates a paired vTPM device; buffer r/w via `proxy_dev->buffer` with `copy_{from,to}_user` at [:149]/[:101] |

Software-only, node confirmed after `modprobe tpm_vtpm_proxy`; newer and less
fuzzed than uinput — queued for the next attack-surface pass.
