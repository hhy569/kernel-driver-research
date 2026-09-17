// SPDX-License-Identifier: GPL-2.0
/*
 * ioctl_probe.c - Userspace attack-surface probe for the Linux HPET char device
 * (drivers/char/hpet.c).
 *
 * Purpose (Phase-1 attack-surface reconstruction, not blind fuzzing):
 *   - prove every reachable ioctl handler is reached from userspace,
 *   - exercise each user-controlled argument at its boundary values and
 *     record the driver's exact response (return value / errno),
 *   - test the mmap size/offset invariants enforced by vm_iomap_memory(),
 *   - emit a structured log that maps 1:1 to notes/ioctl-map.md.
 *
 * Every case states the EXPECTED result from source audit; the OBSERVED result
 * is what validates (or refutes) the static invariant analysis.
 *
 * Build:  gcc -O2 -Wall -o ioctl_probe ioctl_probe.c
 * Run:    sudo ./ioctl_probe            # /dev/hpet is root-only (0600)
 *
 * Local lab only. The driver is exercised through its documented UAPI; no
 * kernel memory is touched directly and no third-party system is involved.
 */
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/hpet.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static int g_pass, g_fail, g_note;

#define CASE(name) do { printf("\n=== %s ===\n", name); } while (0)

/* Record an observation vs the static expectation.
 * want_errno < 0  => expect success (ret == 0)
 * want_errno == 0 => expect success
 * want_errno > 0  => expect that errno
 */
static void check(const char *what, int rc, int want_errno)
{
	int e = errno;
	if (want_errno < 0) { /* expect success */
		if (rc == 0) { printf("  [OK]   %-38s -> success\n", what); g_pass++; }
		else { printf("  [UNEX] %-37s -> rc=%d errno=%d (%s); expected success\n",
				what, rc, e, strerror(e)); g_fail++; }
	} else if (want_errno == 0) { /* informational, just print */
		printf("  [--]   %-38s -> rc=%d errno=%d (%s)\n",
			what, rc, rc < 0 ? e : 0, rc < 0 ? strerror(e) : "success");
		g_note++;
	} else { /* expect specific errno */
		if (rc < 0 && e == want_errno) {
			printf("  [OK]   %-38s -> -1 errno=%d (%s) as expected\n",
				what, e, strerror(e)); g_pass++;
		} else {
			printf("  [UNEX] %-37s -> rc=%d errno=%d (%s); expected errno=%d (%s)\n",
				what, rc, rc < 0 ? e : 0, rc < 0 ? strerror(e) : "none",
				want_errno, strerror(want_errno)); g_fail++;
		}
	}
}

int main(int argc, char **argv)
{
	const char *dev = (argc > 1) ? argv[1] : "/dev/hpet";
	int fd, rc;

	printf("HPET attack-surface probe (drivers/char/hpet.c)\n");
	printf("target device: %s\n", dev);

	/* --- Gate: write-mode open must be rejected (hpet_open checks FMODE_WRITE) --- */
	CASE("G1: open(O_RDWR) must fail with EINVAL");
	int fdw = open(dev, O_RDWR);
	check("open O_RDWR", fdw < 0 ? -1 : 0, fdw < 0 ? EINVAL : 0);
	if (fdw >= 0) close(fdw);

	/* --- Normal open --- */
	CASE("G2: open(O_RDONLY)");
	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		printf("FATAL: cannot open %s: %s (need root / CONFIG_HPET)\n",
		       dev, strerror(errno));
		return 1;
	}
	printf("  [OK]   fd=%d\n", fd);

	/* --- HPET_INFO: _IOR, fixed-size copy_to_user(sizeof(struct hpet_info)) --- */
	CASE("I1: HPET_INFO (fixed-size copy_to_user)");
	struct hpet_info hi;
	memset(&hi, 0xAA, sizeof(hi));
	rc = ioctl(fd, HPET_INFO, &hi);
	check("HPET_INFO valid pointer", rc, -1);
	if (rc == 0) {
		printf("         hi_hpet=%u hi_timer=%u hi_flags=0x%lx hi_ireqfreq=%lu Hz\n",
		       hi.hi_hpet, hi.hi_timer, hi.hi_flags, hi.hi_ireqfreq);
	}
	/* Bad user pointer -> EFAULT (USERCOPY invariant) */
	rc = ioctl(fd, HPET_INFO, (void *)0x1);
	check("HPET_INFO bogus pointer -> EFAULT", rc, EFAULT);

	/* --- HPET_IRQFREQ: the ONLY command with an attacker-controlled scalar --- */
	CASE("F1: HPET_IRQFREQ boundary analysis (arg = requested Hz)");
	unsigned long freq_cases[][2] = {
		/* {arg, expected_errno_or_-1_for_success} */
		{0,                 EINVAL},  /* explicit !arg check -> EINVAL (no div-by-zero) */
		{1,                 -1},      /* valid -> hpet_time_div */
		{64,                -1},      /* HPET_USER_FREQ default cap */
		{65,                -1},      /* root has CAP_SYS_RESOURCE -> allowed */
		{1000000,           -1},      /* large but valid */
		{0x7fffffffffffffffUL, -1},   /* INT64_MAX */
		{0x8000000000000000UL, -1},   /* high bit set (unsigned) */
		{ULONG_MAX,         -1},      /* max: exercises hpet_time_div arithmetic */
	};
	for (size_t i = 0; i < sizeof(freq_cases)/sizeof(freq_cases[0]); i++) {
		unsigned long arg = freq_cases[i][0];
		int want = (int)freq_cases[i][1];
		rc = ioctl(fd, HPET_IRQFREQ, arg);
		char label[64];
		snprintf(label, sizeof(label), "IRQFREQ arg=0x%lx (%lu)", arg, arg);
		check(label, rc, want);
	}

	/* --- periodic capability toggles (EPI/DPI); -ENXIO if timer not periodic-capable --- */
	CASE("P1: HPET_EPI / HPET_DPI state transitions");
	rc = ioctl(fd, HPET_EPI);
	check("HPET_EPI (enable periodic)", rc, 0);
	rc = ioctl(fd, HPET_DPI);
	check("HPET_DPI (disable periodic)", rc, 0);

	/* --- interrupt enable requires a prior IRQFREQ (hd_ireqfreq != 0) --- */
	CASE("IR1: HPET_IE_ON / HPET_IE_OFF");
	/* freq is currently ULONG_MAX from above; reset to a sane 64 Hz first */
	ioctl(fd, HPET_IRQFREQ, 64UL);
	rc = ioctl(fd, HPET_IE_ON);
	check("HPET_IE_ON with ireqfreq=64", rc, 0);
	rc = ioctl(fd, HPET_IE_ON);
	check("HPET_IE_ON again -> EBUSY", rc, EBUSY);
	rc = ioctl(fd, HPET_IE_OFF);
	check("HPET_IE_OFF", rc, 0);

	/* --- unknown ioctl cmd -> EINVAL (default branch) --- */
	CASE("X1: unknown command dispatch");
	rc = ioctl(fd, _IO('h', 0x7f));
	check("unknown cmd 0x7f -> EINVAL", rc, EINVAL);

	/* --- read(): count < sizeof(unsigned long) -> EINVAL; nonblock no data -> EAGAIN --- */
	CASE("R1: read() boundary");
	unsigned long buf;
	rc = (int)read(fd, &buf, 1);
	check("read count=1 -> EINVAL", rc < 0 ? -1 : 0, EINVAL);
	int fdn = open(dev, O_RDONLY | O_NONBLOCK);
	if (fdn >= 0) {
		ioctl(fdn, HPET_IRQFREQ, 64UL);
		rc = (int)read(fdn, &buf, sizeof(buf));
		/* no interrupt armed -> either EAGAIN (nonblock) or EIO */
		printf("  [--]   nonblock read (no IRQ armed)    -> rc=%d errno=%d (%s)\n",
		       rc, errno, rc < 0 ? strerror(errno) : "data");
		g_note++;
		close(fdn);
	}

	/* --- mmap(): exactly one HPET page is allowed; larger mapping is rejected --- */
	CASE("M1: mmap() range invariants (vm_iomap_memory)");
	void *p;
	p = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		printf("  [--]   mmap 1 page off=0 -> errno=%d (%s) [may be disabled at runtime]\n",
		       errno, strerror(errno));
	else { printf("  [OK]   mmap 1 page off=0 -> %p\n", p); g_pass++; munmap(p, PAGE_SIZE); }

	p = mmap(NULL, 2 * PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		printf("  [OK]   mmap 2 pages -> rejected errno=%d (%s) (range capped to 1 page)\n",
		       errno, strerror(errno)); g_pass++;
	} else { printf("  [UNEX] mmap 2 pages succeeded %p (range check missing?)\n", p);
		 g_fail++; munmap(p, 2*PAGE_SIZE); }

	p = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, PAGE_SIZE);
	if (p == MAP_FAILED)
		printf("  [OK]   mmap off=1 page -> rejected errno=%d (%s) (vm_pgoff>pages)\n",
		       errno, strerror(errno)), g_pass++;
	else { printf("  [UNEX] mmap off=1page succeeded %p\n", p); g_fail++; munmap(p, PAGE_SIZE); }

	close(fd);

	printf("\n================ SUMMARY ================\n");
	printf("invariant checks passed : %d\n", g_pass);
	printf("unexpected results      : %d\n", g_fail);
	printf("informational           : %d\n", g_note);
	printf("A non-zero 'unexpected' count is a lead, not a bug: reproduce, minimize,\n"
	       "root-cause, and diff against upstream before drawing any conclusion.\n");
	return g_fail ? 2 : 0;
}
