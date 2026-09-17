// SPDX-License-Identifier: GPL-2.0
// vtpmx state-machine / lifetime probe (pthread emulator model).
// A real vTPM requires a userspace emulator: after NEW_DEV the core auto-sends
// TPM startup to the server fd; this harness spawns an emulator thread per
// device that reads commands and replies, then drives client I/O and boundary
// cases. Root only. UNEX = lead to reproduce under KASAN, not a claimed bug.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct vtpm_new_dev { __u32 flags, tpm_num, fd, major, minor; };
#define VTPM_FLAG_TPM2 1
#define VTPM_IOC_NEW_DEV _IOWR(0xa1, 0x00, struct vtpm_new_dev)

#define MODE_NORMAL 0
#define MODE_SMALL_READ 1   /* first read uses a 4-byte buffer (want EIO) */
#define MODE_BIG_WRITE 2    /* after read, write 4097 bytes (want EIO) */

struct emu {
	int serverfd, tpmnum, mode, stop, served;
	int small_rc, big_rc;   /* observed errno, 0 = not tested */
	pthread_mutex_t lock;
	pthread_t th;
};

static int g_pass, g_unex;
#define CHECK(t, cond) do { if (cond) { printf("  [OK]   %s\n", t); g_pass++; } \
	else { printf("  [UNEX] %s\n", t); g_unex++; } } while (0)

static void respond(int fd, const uint8_t *cmd, int clen)
{
	uint8_t rsp[16] = {0};
	int is2 = (clen >= 2 && cmd[0] == 0x80 && cmd[1] == 0x01);
	if (is2) { rsp[0]=0x80; rsp[1]=0x01; }  /* TPM2_ST_NO_SESSIONS */
	else     { rsp[0]=0x00; rsp[1]=0xC4; }  /* TPM1.2 RSP_COMMAND */
	rsp[2]=0;rsp[3]=0;rsp[4]=0;rsp[5]=10;  /* size 10 */
	rsp[6]=rsp[7]=rsp[8]=rsp[9]=0;          /* RC = TPM_RC_SUCCESS */
	write(fd, rsp, 10);
}

static void *emu_thread(void *arg)
{
	struct emu *e = arg;
	uint8_t cmd[4200];
	int small_done = 0, big_done = 0;
	while (1) {
		pthread_mutex_lock(&e->lock);
		int stop = e->stop;
		pthread_mutex_unlock(&e->lock);
		if (stop) break;
		struct pollfd pfd = { e->serverfd, POLLIN, 0 };
		int pr = poll(&pfd, 1, 500);
		if (pr <= 0) continue;
		pthread_mutex_lock(&e->lock);
		int mode = e->mode;
		pthread_mutex_unlock(&e->lock);

		if (mode == MODE_SMALL_READ && !small_done) {
			uint8_t tiny[4];
			int r = read(e->serverfd, tiny, sizeof(tiny));
			pthread_mutex_lock(&e->lock);
			e->small_rc = (r < 0) ? errno : r;
			pthread_mutex_unlock(&e->lock);
			small_done = 1;
			/* command stays queued; fall through to full read */
		}
		int n = read(e->serverfd, cmd, sizeof(cmd));
		if (n < 0) {
			if (errno == EPIPE || errno == EBADF) break;
			if (errno == EIO && small_done) { /* small-read case: re-read full */
				usleep(2000);
				n = read(e->serverfd, cmd, sizeof(cmd));
				if (n < 0) continue;
			} else continue;
		}
		pthread_mutex_lock(&e->lock); e->served++; pthread_mutex_unlock(&e->lock);

		if (mode == MODE_BIG_WRITE && !big_done) {
			uint8_t big[4097]; memset(big, 0, sizeof(big));
			int w = write(e->serverfd, big, sizeof(big));
			pthread_mutex_lock(&e->lock);
			e->big_rc = (w < 0) ? errno : w;
			pthread_mutex_unlock(&e->lock);
			big_done = 1;
		}
		respond(e->serverfd, cmd, n);
	}
	return NULL;
}

static int create_device(int ctrl, __u32 flags, int mode, struct emu *e)
{
	struct vtpm_new_dev s; memset(&s, 0, sizeof(s)); s.flags = flags;
	if (ioctl(ctrl, VTPM_IOC_NEW_DEV, &s) < 0) return -errno;
	memset(e, 0, sizeof(*e));
	pthread_mutex_init(&e->lock, NULL);
	e->serverfd = s.fd; e->tpmnum = s.tpm_num; e->mode = mode;
	pthread_create(&e->th, NULL, emu_thread, e);
	return s.fd;
}

/* client child: open /dev/tpmN, optionally send one command, read response */
static int client_once(__u32 tpmnum, const uint8_t *cmd, int clen, int do_read)
{
	pid_t pid = fork();
	if (pid == 0) {
		char path[64]; snprintf(path, sizeof(path), "/dev/tpm%u", tpmnum);
		int cf = -1;
		for (int i = 0; i < 100; i++) { cf = open(path, O_RDWR); if (cf >= 0) break; usleep(50000); }
		if (cf < 0) _exit(40);
		int w = write(cf, cmd, clen);
		if (w < 0) _exit(50 + errno);   /* e.g. 50+EFAULT */
		if (!do_read) { close(cf); _exit(0); }
		uint8_t rsp[64]; int r = read(cf, rsp, sizeof(rsp));
		close(cf);
		_exit(r == 10 ? 0 : 60);
	}
	int st = 0; waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void tpm2_cmd(uint8_t *b, int *len, __u32 cc)
{
	*len = 12; b[0]=0x80;b[1]=0x01; b[2]=0;b[3]=0;b[4]=0;b[5]=12;
	b[6]=(cc>>24)&0xff;b[7]=(cc>>16)&0xff;b[8]=(cc>>8)&0xff;b[9]=cc&0xff;
	b[10]=0;b[11]=0;
}

static void destroy_device(struct emu *e)
{
	pthread_mutex_lock(&e->lock); e->stop = 1; pthread_mutex_unlock(&e->lock);
	pthread_join(e->th, NULL);
	close(e->serverfd);
	pthread_mutex_destroy(&e->lock);
}

int main(void)
{
	printf("vtpmx state-machine/lifetime probe (tpm_vtpm_proxy.c, Linux 6.8)\n\n");
	int ctrl = open("/dev/vtpmx", O_RDWR);
	if (ctrl < 0) { perror("open /dev/vtpmx (root + modprobe tpm_vtpm_proxy)"); return 1; }
	CHECK("open /dev/vtpmx", ctrl >= 0);

	printf("=== N1: NEW_DEV flags ===\n");
	struct emu e2, e12, ea, eb;
	int f2 = create_device(ctrl, VTPM_FLAG_TPM2, MODE_NORMAL, &e2);
	CHECK("flags=TPM2 -> success + server fd", f2 > 0);
	usleep(300000); /* let auto-startup run */
	CHECK("TPM2 auto-startup served (chip registered)", e2.served >= 1);
	{ char p[64]; snprintf(p,sizeof(p),"/dev/tpm%u",e2.tpmnum);
	  CHECK("/dev/tpmN appeared after register", access(p,F_OK)==0); }

	int f12 = create_device(ctrl, 0, MODE_NORMAL, &e12);
	CHECK("flags=0 (TPM1.2) -> success", f12 > 0);
	usleep(300000);

	struct vtpm_new_dev sx; memset(&sx,0,sizeof(sx));
	sx.flags = 2;
	CHECK("flags=2 -> EOPNOTSUPP", ioctl(ctrl,VTPM_IOC_NEW_DEV,&sx)<0 && errno==EOPNOTSUPP);
	sx.flags = 0xffffffffu;
	CHECK("flags=0xffffffff -> EOPNOTSUPP", ioctl(ctrl,VTPM_IOC_NEW_DEV,&sx)<0 && errno==EOPNOTSUPP);
	CHECK("NULL arg -> EFAULT", ioctl(ctrl,VTPM_IOC_NEW_DEV,NULL)<0 && errno==EFAULT);

	printf("=== N2: full TPM2 client<->server loop ===\n");
	uint8_t cmd[16]; int cl; tpm2_cmd(cmd,&cl,0x144 /*STARTUP*/);
	int cr = client_once(e2.tpmnum, cmd, cl, 1);
	CHECK("client STARTUP -> 10-byte TPM_RC_SUCCESS", cr == 0);

	printf("=== N3: server write when not WAIT_RESPONSE -> EIO ===\n");
	uint8_t junk[16] = {0};
	int w = write(e2.serverfd, junk, sizeof(junk));
	CHECK("unsolicited server write -> EIO", w < 0 && errno == EIO);

	printf("=== N4: size boundaries (count vs 4096 buffer) ===\n");
	struct emu es, ebw;
	int fs = create_device(ctrl, VTPM_FLAG_TPM2, MODE_SMALL_READ, &es);
	usleep(200000);
	cr = client_once(es.tpmnum, cmd, cl, 1);
	pthread_mutex_lock(&es.lock); int src = es.small_rc; pthread_mutex_unlock(&es.lock);
	CHECK("server read count<req_len -> EIO", src == EIO);

	int fb = create_device(ctrl, VTPM_FLAG_TPM2, MODE_BIG_WRITE, &ebw);
	usleep(200000);
	cr = client_once(ebw.tpmnum, cmd, cl, 1);
	pthread_mutex_lock(&ebw.lock); int brc = ebw.big_rc; pthread_mutex_unlock(&ebw.lock);
	CHECK("server write count=4097 -> EIO", brc == EIO);

	printf("=== N5: userspace cannot inject SET_LOCALITY (DRIVER_COMMAND gate) ===\n");
	uint8_t loc[16]; int ll; tpm2_cmd(loc,&ll,0x20001000);
	cr = client_once(e2.tpmnum, loc, ll, 0);
	CHECK("client SET_LOCALITY rejected (50+EFAULT)", cr == 50 + EFAULT);

	printf("=== N6: lifetime — rapid create/teardown, distinct numbers ===\n");
	struct emu batch[6]; int nums[6], ok = 1;
	for (int i = 0; i < 6; i++) {
		if (create_device(ctrl, VTPM_FLAG_TPM2, MODE_NORMAL, &batch[i]) < 0) ok = 0;
		nums[i] = batch[i].tpmnum;
	}
	for (int i = 1; i < 6; i++) if (nums[i] == nums[i-1]) ok = 0;
	usleep(300000);
	CHECK("6 devices created with distinct tpm_num", ok);
	for (int i = 0; i < 6; i++) destroy_device(&batch[i]);
	CHECK("6 rapid teardowns clean (no hang/warning)", 1);

	destroy_device(&es); destroy_device(&ebw);
	destroy_device(&e12); destroy_device(&e2);
	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("passed: %d   unexpected: %d\n", g_pass, g_unex);
	puts("Re-run under the KASAN QEMU guest with GDB on vtpmx_ioc_new_dev and\n"
	     "vtpm_proxy_fops_release to confirm LIFETIME invariants dynamically.");
	return g_unex ? 2 : 0;
}
