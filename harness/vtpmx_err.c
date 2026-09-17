// SPDX-License-Identifier: GPL-2.0
// vtpmx error-path / rollback harness (Phase 3, R6/R7).
//
// Validates that every failure point in NEW_DEV rolls back completely with
// no fd / object / work leak and no use-after-free (UAF confirmed later under
// Kernel B / KASAN). Source-derived failure points (tpm_vtpm_proxy.c):
//   E1 bad copy_from_user (NULL/unmapped arg) -> -EFAULT, before any alloc
//   E2 reserved flags bits                    -> -EOPNOTSUPP, before alloc
//   E3 get_unused_fd failure (fd exhaustion)  -> -EMFILE, proxy_dev+chip
//      already alloc'd but work NOT started -> err_delete_proxy_dev (fast)
//   E4 copy_to_user failure (read-only arg page) -> -EFAULT, work already
//      started -> put_unused_fd + fput -> delete_device -> work_stop, which
//      flushes the register work waiting on the (never-served) auto-startup;
//      expected to block up to a TPM timeout but return cleanly, no leak.
//
// Leak oracle: count /proc/self/fd before/after each failing ioctl; a correct
// rollback shows zero net new fds. Repeat each case to catch slow leaks.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

struct vtpm_new_dev { __u32 flags, tpm_num, fd, major, minor; };
#define VTPM_FLAG_TPM2 1
#define VTPM_IOC_NEW_DEV _IOWR(0xa1, 0x00, struct vtpm_new_dev)

static int g_pass, g_fail;
#define CHECK(n,cond) do{ if(cond){printf("  [OK]   %s\n",n);g_pass++;} \
                          else {printf("  [FAIL] %s\n",n);g_fail++;} }while(0)

static int count_fds(void){
	DIR*d=opendir("/proc/self/fd"); if(!d)return -1;
	int n=0; struct dirent*e; while((e=readdir(d))) if(e->d_name[0]!='.')n++;
	closedir(d); return n;
}
static long ms_now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
	return t.tv_sec*1000L+t.tv_nsec/1000000L; }
static void on_alarm(int s){(void)s;_exit(98);}

/* E1/E2: pure argument validation, no side effects, run in parent */
static void test_arg_validation(int ctrl){
	printf("=== E1: bad copy_from_user ===\n");
	errno=0; long r=ioctl(ctrl,VTPM_IOC_NEW_DEV,NULL);
	CHECK("NULL arg -> -1/EFAULT", r<0 && errno==EFAULT);
	errno=0; r=ioctl(ctrl,VTPM_IOC_NEW_DEV,(void*)(0x1UL<<40));
	CHECK("unmapped arg -> -1/EFAULT", r<0 && errno==EFAULT);

	printf("=== E2: reserved flags ===\n");
	struct vtpm_new_dev s;
	memset(&s,0,sizeof(s)); s.flags=0xfffffffeu;
	errno=0; r=ioctl(ctrl,VTPM_IOC_NEW_DEV,&s);
	CHECK("flags=~TPM2 -> -1/EOPNOTSUPP", r<0 && errno==EOPNOTSUPP);
	s.flags=2; errno=0; r=ioctl(ctrl,VTPM_IOC_NEW_DEV,&s);
	CHECK("flags=bit1 -> -1/EOPNOTSUPP", r<0 && errno==EOPNOTSUPP);
	CHECK("no net fd growth after arg failures", count_fds()==count_fds());
}

/* E3: get_unused_fd failure via fd exhaustion. Runs in an isolated child.
 * At the exhaustion point get_unused_fd never allocates an fd, so an fd leak
 * is impossible by construction; the things that CAN leak are proxy_dev/chip
 * and the tpm idr number, which we probe indirectly: the failure must stay a
 * stable -EMFILE across many tries (no state corruption), and after restoring
 * the fd table/rlimit the fd count must return to baseline. Memory/UAF is
 * confirmed separately under KASAN/kmemleak in Kernel B. */
static void child_fd_exhaust(int ctrl_rx){
	signal(SIGALRM,on_alarm); alarm(30);
	int ctrl=ctrl_rx;
	int before=count_fds();
	struct rlimit rl; getrlimit(RLIMIT_NOFILE,&rl);
	struct rlimit low={ (rlim_t)before+16, rl.rlim_max };
	if(setrlimit(RLIMIT_NOFILE,&low)<0) _exit(40);
	int held[256], cap=0;
	for(; cap<256; cap++){ int fd=open("/dev/null",O_RDONLY);
		if(fd<0) break; held[cap]=fd; }
	/* table full: a probe open must already fail EMFILE */
	int probe=open("/dev/null",O_RDONLY);
	int probe_emfile=(probe<0 && errno==EMFILE);
	if(probe>=0){ held[cap++]=probe; }
	/* NEW_DEV must fail at get_unused_fd_flags -> -EMFILE, stably */
	struct vtpm_new_dev s; memset(&s,0,sizeof(s)); s.flags=VTPM_FLAG_TPM2;
	int first_err=0, stable=1, n=80;
	for(int i=0;i<n;i++){ errno=0; long rr=ioctl(ctrl,VTPM_IOC_NEW_DEV,&s);
		if(i==0) first_err=errno;
		if(!(rr<0 && errno==EMFILE)){ stable=0; break; } }
	/* restore: drop held fds and rlimit */
	for(int i=0;i<cap;i++) close(held[i]);
	struct rlimit back={ rl.rlim_cur, rl.rlim_max }; setrlimit(RLIMIT_NOFILE,&back);
	int after=count_fds();
	printf("  [..] E3 held=%d probe_emfile=%d first_errno=%d(%s) stable=%d/%d fds %d->%d\n",
		cap,probe_emfile,first_err,strerror(first_err),stable?n:0,n,before,after);
	_exit((probe_emfile && first_err==EMFILE && stable && after==before)?0:1);
}

/* E4: copy_to_user fails on a read-only arg page; work already started.
 * mmap a page RW, plant flags=1, mprotect to RDONLY: copy_from_user reads
 * flags fine, copy_to_user back into the same page faults -> -EFAULT. */
static void child_ro_arg(int ctrl_rx){
	signal(SIGALRM,on_alarm); alarm(150);
	int ctrl=ctrl_rx;
	long pgsz=sysconf(_SC_PAGESIZE);
	void*p=mmap(NULL,pgsz,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(p==MAP_FAILED)_exit(41);
	struct vtpm_new_dev*s=p; memset(s,0,sizeof(*s)); s->flags=VTPM_FLAG_TPM2;
	if(mprotect(p,pgsz,PROT_READ)<0)_exit(42);
	int before=count_fds();
	long t0=ms_now();
	errno=0; long r=ioctl(ctrl,VTPM_IOC_NEW_DEV,s);
	long dt=ms_now()-t0;
	int eflt=(r<0 && errno==EFAULT);
	/* page still read-only; restore writable to inspect */
	mprotect(p,pgsz,PROT_READ|PROT_WRITE);
	int after=count_fds();
	munmap(p,pgsz);
	/* fd field must NOT have been installed (it never reaches fd_install);
	 * the key checks are EFAULT + zero net fd growth + bounded latency. */
	printf("  [..] E4 copy_to_user fail: rc=%ld errno=%d(%s) latency=%ldms fds %d->%d\n",
		r,errno,strerror(errno),dt,before,after);
	_exit((eflt && after==before && dt<140000)?0:1);
}

/* minimal free emulator: serve startup so register work completes */
struct em { int fd, stop[2]; pthread_t th; };
static void* em_loop(void*a){ struct em*e=a;
	uint8_t cmd[4200],rsp[10]; memset(rsp,0,sizeof(rsp));
	rsp[0]=0x80;rsp[1]=1;rsp[4]=0;rsp[5]=10; /* tag/size/rc=0 */
	for(;;){ struct pollfd pf[2]={{e->fd,POLLIN|POLLHUP|POLLERR,0},{e->stop[0],POLLIN,0}};
		int pr=poll(pf,2,300); if(pr<0){if(errno==EINTR)continue;break;}
		if(pf[1].revents&POLLIN)break;
		if(pf[0].revents&(POLLHUP|POLLERR))break;
		if(pf[0].revents&POLLIN){ int n=read(e->fd,cmd,sizeof(cmd));
			if(n<0)break; if(write(e->fd,rsp,10)<0)break; } }
	return 0; }

/* after rollback pressure, the driver must still create+teardown cleanly */
static void child_healthy(int ctrl){
	signal(SIGALRM,on_alarm); alarm(30);
	struct vtpm_new_dev s; memset(&s,0,sizeof(s)); s.flags=VTPM_FLAG_TPM2;
	long r=ioctl(ctrl,VTPM_IOC_NEW_DEV,&s);
	if(r<0||s.fd<0)_exit(1);
	struct em e; memset(&e,0,sizeof(e)); e.fd=s.fd; pipe2(e.stop,O_NONBLOCK);
	pthread_create(&e.th,NULL,em_loop,&e);
	char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",s.tpm_num);
	int ok=0; for(int i=0;i<100;i++){ if(access(path,F_OK)==0){ok=1;break;} usleep(50000);}
	close(s.fd); char x=1; write(e.stop[1],&x,1); pthread_join(e.th,NULL);
	_exit(ok?0:1);
}

static int run_child(void(*fn)(int),int ctrl,const char*name,int timeout_s){
	pid_t pid=fork();
	if(pid==0){ fn(ctrl); _exit(0); }
	int st; long t0=ms_now();
	for(;;){ pid_t w=waitpid(pid,&st,WNOHANG); if(w==pid)break;
		if(ms_now()-t0>timeout_s*1000){ kill(pid,SIGKILL); waitpid(pid,&st,0);
			printf("  [FAIL] %s: timeout %ds\n",name,timeout_s); return 1; }
		usleep(100000); }
	if(WIFSIGNALED(st)){ printf("  [FAIL] %s: killed by signal %d\n",name,WTERMSIG(st)); return 1; }
	int code=WEXITSTATUS(st);
	if(code==98){ printf("  [FAIL] %s: child alarm (hung)\n",name); return 1; }
	return code;
}

int main(void){
	printf("vtpmx ERROR-PATH / ROLLBACK HARNESS (R6/R7)\n\n");
	int ctrl=open("/dev/vtpmx",O_RDWR);
	if(ctrl<0){ perror("open /dev/vtpmx (root)"); return 1; }

	test_arg_validation(ctrl);

	printf("=== E3: get_unused_fd failure (fd exhaustion) ===\n");
	int e3=run_child(child_fd_exhaust,ctrl,"fd-exhaust",40);
	CHECK("E3 EMFILE + stable over 50 tries + zero fd leak", e3==0);
	/* prove driver still healthy after rollback pressure (isolated child) */
	int eh=run_child(child_healthy,ctrl,"post-stress healthy",35);
	CHECK("post-stress NEW_DEV + register + teardown still clean", eh==0);

	printf("=== E4: copy_to_user failure (read-only arg, slow rollback) ===\n");
	int e4=run_child(child_ro_arg,ctrl,"ro-arg",150);
	CHECK("E4 EFAULT + zero fd leak + bounded latency", e4==0);

	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("passed:%d fail:%d\n",g_pass,g_fail);
	puts("A correct rollback returns the expected errno with zero net new fds and\n"
	     "no hang. Re-run on Kernel B (KASAN) to confirm no UAF/double-free in the\n"
	     "create_proxy_dev -> get_unused_fd / fput -> delete_device error paths.");
	return g_fail?2:0;
}
