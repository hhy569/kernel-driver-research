// SPDX-License-Identifier: GPL-2.0
/*
 * uinput_probe.c - Attack-surface probe for the Linux virtual input device
 * (drivers/input/misc/uinput.c), a miscdevice (/dev/uinput) with ~20 ioctls
 * including variable-size commands and force-feedback upload/erase.
 *
 * Phase-1 goal: reach every handler from userspace and confirm (or refute) the
 * static invariant analysis by feeding boundary / over-size / out-of-range /
 * wrong-state arguments and recording the exact errno.
 *
 * Build: gcc -O2 -Wall -o uinput_probe uinput_probe.c
 * Run:   sudo ./uinput_probe
 *
 * The harness creates and destroys a virtual input device only; it leaves no
 * node behind on clean exit. Local lab use only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/uinput.h>
#include <linux/input.h>

#ifndef UI_ABS_SETUP
#define UI_ABS_SETUP _IOW('U', 0x40, struct uinput_abs_setup)
#endif

static int g_pass, g_fail, g_note;

static void expect(const char *what, int rc, int want)
{
	int e = errno;
	if (want < 0) {			/* expect success */
		if (rc == 0) { printf("  [OK]   %-52s success\n", what); g_pass++; }
		else { printf("  [UNEX] %-51s rc=%d errno=%d(%s); want success\n",
				what, rc, e, strerror(e)); g_fail++; }
	} else {
		if (rc < 0 && e == want) {
			printf("  [OK]   %-52s errno=%d(%s)\n", what, e, strerror(e));
			g_pass++;
		} else {
			printf("  [UNEX] %-51s rc=%d errno=%d(%s); want %d(%s)\n",
				what, rc, rc < 0 ? e : 0, rc < 0 ? strerror(e) : "-",
				want, strerror(want));
			g_fail++;
		}
	}
}

static int open_ui(void)
{
	int fd = open("/dev/uinput", O_RDWR);
	if (fd < 0)
		printf("FATAL open /dev/uinput: %s (need root)\n", strerror(errno));
	return fd;
}

int main(void)
{
	int rc, fd = open_ui();
	if (fd < 0) return 1;
	printf("uinput attack-surface probe (drivers/input/misc/uinput.c)\n");

	/* ---- UI_DEV_SETUP: fixed-size, name must be non-empty ---- */
	printf("\n=== S1: UI_DEV_SETUP name validation ===\n");
	struct uinput_setup s;
	memset(&s, 0, sizeof(s));
	rc = ioctl(fd, UI_DEV_SETUP, &s);
	expect("empty name -> EINVAL", rc, EINVAL);

	memset(&s, 0, sizeof(s));
	strncpy(s.name, "bivar-probe-kbd", UINPUT_MAX_NAME_SIZE);
	s.id.bustype = BUS_USB;
	s.ff_effects_max = 0;
	rc = ioctl(fd, UI_DEV_SETUP, &s);
	expect("valid setup -> success", rc, -1);

	rc = ioctl(fd, UI_DEV_SETUP, (void *)0x1);
	expect("UI_DEV_SETUP bogus pointer -> EFAULT", rc, EFAULT);

	/* ---- UI_SET_*BIT: BOUNDS invariant (arg <= *_MAX) ---- */
	printf("\n=== B1: UI_SET_*BIT bitmap index bounds ===\n");
	rc = ioctl(fd, UI_SET_EVBIT, EV_KEY);
	expect("UI_SET_EVBIT EV_KEY (valid)", rc, -1);
	rc = ioctl(fd, UI_SET_EVBIT, EV_MAX + 1);
	expect("UI_SET_EVBIT EV_MAX+1 -> EINVAL", rc, EINVAL);
	rc = ioctl(fd, UI_SET_KEYBIT, KEY_A);
	expect("UI_SET_KEYBIT KEY_A (valid)", rc, -1);
	rc = ioctl(fd, UI_SET_KEYBIT, KEY_MAX + 1);
	expect("UI_SET_KEYBIT KEY_MAX+1 -> EINVAL", rc, EINVAL);
	rc = ioctl(fd, UI_SET_ABSBIT, ABS_X);
	expect("UI_SET_ABSBIT ABS_X (valid)", rc, -1);
	rc = ioctl(fd, UI_SET_ABSBIT, ABS_MAX + 1);
	expect("UI_SET_ABSBIT ABS_MAX+1 -> EINVAL", rc, EINVAL);
	rc = ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_MAX + 1);
	expect("UI_SET_PROPBIT PROP_MAX+1 -> EINVAL", rc, EINVAL);

	/* ---- UI_ABS_SETUP: variable-size + range validation ---- */
	printf("\n=== V1: UI_ABS_SETUP variable size / absinfo range ===\n");
	struct uinput_abs_setup a;
	memset(&a, 0, sizeof(a));
	a.code = ABS_X;
	a.absinfo.minimum = 0;
	a.absinfo.maximum = 1024;
	rc = ioctl(fd, UI_ABS_SETUP, &a);
	expect("valid abs setup -> success", rc, -1);

	memset(&a, 0, sizeof(a));
	a.code = ABS_MAX + 1;
	rc = ioctl(fd, UI_ABS_SETUP, &a);
	expect("abs code > ABS_MAX -> ERANGE", rc, ERANGE);

	memset(&a, 0, sizeof(a));
	a.code = ABS_Y;
	a.absinfo.minimum = 100;
	a.absinfo.maximum = 10;		/* max < min */
	rc = ioctl(fd, UI_ABS_SETUP, &a);
	expect("abs max<min -> EINVAL", rc, EINVAL);

	memset(&a, 0, sizeof(a));
	a.code = ABS_Y;
	a.absinfo.minimum = 0;
	a.absinfo.maximum = 10;
	a.absinfo.flat = 100;		/* flat > (max-min) */
	rc = ioctl(fd, UI_ABS_SETUP, &a);
	expect("abs flat>range -> EINVAL", rc, EINVAL);

	/* over-size variable command: UI_ABS_SETUP is nr=4; same type/nr, IOC
	 * size larger than the kernel struct -> uinput_abs_setup() returns E2BIG */
	unsigned long badsize_cmd =
		_IOC(_IOC_WRITE, 'U', 4, sizeof(struct uinput_abs_setup) + 8);
	rc = ioctl(fd, badsize_cmd, &a);
	expect("UI_ABS_SETUP oversize -> E2BIG", rc, E2BIG);

	/* ---- create the device (state -> UIST_CREATED) ---- */
	printf("\n=== C1: UI_DEV_CREATE state machine ===\n");
	rc = ioctl(fd, UI_DEV_CREATE);
	expect("UI_DEV_CREATE -> success", rc, -1);

	/* after CREATED, mutating setup/bits must be rejected */
	rc = ioctl(fd, UI_SET_EVBIT, EV_ABS);
	expect("UI_SET_EVBIT after CREATE -> EINVAL", rc, EINVAL);
	memset(&s, 0, sizeof(s));
	strncpy(s.name, "x", UINPUT_MAX_NAME_SIZE);
	rc = ioctl(fd, UI_DEV_SETUP, &s);
	expect("UI_DEV_SETUP after CREATE -> EINVAL", rc, EINVAL);

	/* ---- UI_GET_SYSNAME: variable-length readback ---- */
	printf("\n=== G1: UI_GET_SYSNAME variable-length copyout ===\n");
	char namebuf[256];
	memset(namebuf, 0, sizeof(namebuf));
	unsigned long getcmd = _IOC(_IOC_READ, 'U', 0x2c, sizeof(namebuf));
	rc = ioctl(fd, getcmd, namebuf);
	if (rc >= 0) {
		printf("  [OK]   %-52s sysname=%s (ret len=%d)\n",
		       "UI_GET_SYSNAME(256)", namebuf, rc);
		g_pass++;
	} else {
		printf("  [--]   UI_GET_SYSNAME rc=%d errno=%d(%s)\n", rc, errno, strerror(errno));
		g_note++;
	}
	/* zero-length buffer: strlen+1 > maxlen path */
	unsigned long get0 = _IOC(_IOC_READ, 'U', 0x2c, 0);
	rc = ioctl(fd, get0, namebuf);
	expect("UI_GET_SYSNAME size=0 -> EINVAL", rc, EINVAL);

	/* ---- unknown command -> EINVAL ---- */
	printf("\n=== X1: unknown command ===\n");
	rc = ioctl(fd, _IO('U', 0x7e));
	expect("unknown cmd 0x7e -> EINVAL", rc, EINVAL);

	/* ---- force-feedback: oversized ff_effects_max at create time ---- */
	printf("\n=== F1: force-feedback ff_effects_max SIZE invariant ===\n");
	int fd2 = open_ui();
	if (fd2 >= 0) {
		struct uinput_setup fs;
		memset(&fs, 0, sizeof(fs));
		strncpy(fs.name, "bivar-ff", UINPUT_MAX_NAME_SIZE);
		fs.id.bustype = BUS_USB;
		ioctl(fd2, UI_DEV_SETUP, &fs);
		ioctl(fd2, UI_SET_EVBIT, EV_FF);
		ioctl(fd2, UI_SET_FFBIT, FF_RUMBLE);
		/* ff_effects_max is consumed by input_ff_create() at CREATE;
		 * an excessive value must be rejected (FF_MAX_EFFECTS / overflow). */
		fs.ff_effects_max = 0xffffffffu;
		ioctl(fd2, UI_DEV_SETUP, &fs);
		rc = ioctl(fd2, UI_DEV_CREATE);
		if (rc < 0) {
			printf("  [OK]   %-52s CREATE rejected errno=%d(%s)\n",
			       "ff_effects_max=UINT32_MAX", errno, strerror(errno));
			g_pass++;
		} else {
			printf("  [NOTE] ff_effects_max=UINT32_MAX CREATE succeeded (capped?) - inspect\n");
			g_note++;
			ioctl(fd2, UI_DEV_DESTROY);
		}
		close(fd2);
	}

	rc = ioctl(fd, UI_DEV_DESTROY);
	expect("UI_DEV_DESTROY -> success", rc, -1);
	close(fd);

	printf("\n================ SUMMARY ================\n");
	printf("invariant checks passed : %d\n", g_pass);
	printf("unexpected results      : %d\n", g_fail);
	printf("informational           : %d\n", g_note);
	printf("Any UNEX/NOTE is a lead to reproduce + root-cause under KASAN, not a\n"
	       "confirmed bug. Static audit: BOUNDS/SIZE/USERCOPY/ARITHMETIC hold here.\n");
	return g_fail ? 2 : 0;
}
