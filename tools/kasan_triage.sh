#!/bin/bash
# kasan_triage.sh -- classify one or more KASAN boot serial logs.
#
# Separates two independent questions (per review guidance):
#   KERNEL HEALTH  : did the KERNEL emit a memory-safety/BUG report?  (dmesg is authoritative)
#   HARNESS HEALTH : did the userspace test complete, assert-fail, or env-abort?
# A userspace abort under TCG/CPU starvation (device pool never fills, TPM auto-startup not
# scheduled) is an ENVIRONMENT event, never a vulnerability.
#
# Harness stdout convention (the harnesses print a machine-readable final line):
#   RESULT: PASS | ASSERT_FAIL | ENV_ABORT | HARNESS_ERROR
# Harness process exit-code convention:
#   0 PASS   1 TEST ASSERTION FAILURE   2 ENVIRONMENT/SCHEDULING ABORT   3 HARNESS INTERNAL ERROR
#
# Usage: kasan_triage.sh SERIAL.log [SERIAL2.log ...]
# This script's own exit status: 0 = no kernel finding in any log; 10 = >=1 kernel finding.

finding=0
for f in "$@"; do
  echo "==================== $f ===================="
  if [ ! -f "$f" ]; then echo "LOG_MISSING"; echo; continue; fi

  done_marker=$(grep -oE "DONE tests=[A-Za-z0-9]+" "$f" | tail -1)
  echo "DONE_MARKER : ${done_marker:-MISSING (boot/harness layer did not finish -- isolate)}"

  # ---- kernel health (counts; patterns kept specific to avoid benign noise) ----
  kasan=$(grep -cE "KASAN:" "$f")
  bug=$(grep -cE "kernel BUG at|(^|[[:space:]])BUG: " "$f")
  oops=$(grep -cE "Oops:" "$f")
  gpf=$(grep -cE "general protection fault|unable to handle kernel" "$f")
  panic=$(grep -cE "Kernel panic|not syncing:" "$f")
  uaf=$(grep -cE "use-after-free|use-after-scope" "$f")
  slab=$(grep -cE "slab-out-of-bounds|heap-out-of-bounds|stack-out-of-bounds|global-out-of-bounds|vmalloc-out-of-bounds|user-copy" "$f")
  refc=$(grep -cE "refcount_t:|refcount bug|refcount underflow|refcount overflow" "$f")
  warn=$(grep -cE "WARNING: CPU:" "$f")
  echo "KERNEL      : kasan=$kasan bug=$bug oops=$oops gpf/unable=$gpf uaf=$uaf bounds=$slab refcount=$refc panic=$panic | warn(informational)=$warn"

  # ---- harness health ----
  echo "HARNESS blocks:"
  grep -oE "BEGIN [A-Za-z0-9_ #=.]+" "$f" | sed 's/^/  START /'
  grep -oE "END [A-Za-z0-9_]+ rc=-?[0-9]+" "$f" | sed 's/^/  /'
  grep -E "RESULT: " "$f" | sed 's/^/  /'
  hangs=$(grep -cE "\[HANG\]|global watchdog fired" "$f")
  echo "  hangs(watchdog)=$hangs"

  # ---- verdict ----
  hard=$((kasan+bug+oops+gpf+panic+uaf+slab+refc))
  if [ "$hard" -gt 0 ]; then
    echo "KERNEL_RESULT: FINDING  <-- STOP, preserve log, root-cause"
    echo "--- first kernel-report context ---"
    grep -nE "KASAN:|BUG:|Oops:|use-after|out-of-bounds|general protection|refcount|Call Trace|RIP: 0010|Allocated by task|Freed by task" "$f" | head -30
    finding=10
  else
    if [ "$warn" -gt 0 ]; then
      echo "KERNEL_RESULT: PASS-for-memory-safety, but $warn WARNING lines need human review:"
      grep -nE "WARNING: CPU:" "$f" | head -10
    else
      echo "KERNEL_RESULT: PASS (no KASAN/BUG/Oops/UAF/OOB/refcount report in this boot)"
    fi
    echo "SCOPE NOTE  : PASS means no memory-safety violation was OBSERVED in this boot's defined"
    echo "              interleaving space; it is not a proof the driver is bug-free."
  fi
  echo
done
echo "==================== SUMMARY ===================="
if [ "$finding" -eq 10 ]; then echo "OVERALL: KERNEL FINDING DETECTED"; else echo "OVERALL: NO KERNEL MEMORY-SAFETY FINDING IN THESE BOOTS"; fi
exit "$finding"
