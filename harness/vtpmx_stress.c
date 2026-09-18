// SPDX-License-Identifier: GPL-2.0
// vtpmx R7 concurrent create/teardown/cleanup stress (v2, semantic emulator).
//
// Device-pool model that matches the real vTPM lifecycle: every slot is a NEW_DEV
// server fd + its own TPM2 emulator thread (vtpm2_emu.h), registered into BOTH
// /dev/tpmN and /dev/tpmrmN. Worker threads either run a NONBLOCK client exchange on a
// slot or tear down + recreate a whole slot (concurrent register/unregister). All slot
// access is serialized by a per-slot mutex so the harness itself never touches a closed
// fd; the point is to stress the kernel's register/cdev/ops/refcount teardown paths and
// let KASAN watch for UAF/OOB, not to race our own userspace.
//
// Exit codes: 0 clean (all threads joined, every node torn down, no unexpected errno),
// 1 assertion (stray node / unexpected errno), 2 environment, 3 watchdog/harness hang.
// Root required. argv1=duration_s (default 60), argv2=seed (default 0x1337).
#define _GNU_SOURCE
#include "vtpm2_emu.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <time.h>

#define SLOTS 6
#define WORKERS 4

static const uint8_t CMD12[12]={0x80,0x01,0,0,0,0x0c,0,0,0x01,0x44,0,0};

struct slot { pthread_mutex_t lock; struct vrel *r; __u32 tn;
	char raw[64], rm[64]; int alive; };
static struct slot G[SLOTS];
static pthread_mutex_t g_log = PTHREAD_MUTEX_INITIALIZER;
static long g_t0;
static int g_stop;
static unsigned long g_client, g_recreate, g_baderrno;
static int g_duration=60;
static unsigned int g_seed=0x1337;

static long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
	return t.tv_sec*1000L+t.tv_nsec/1000000L; }
static void ev(const char *fmt,...){
	char b[256]; va_list ap; va_start(ap,fmt); vsnprintf(b,sizeof b,fmt,ap); va_end(ap);
	pthread_mutex_lock(&g_log); printf("[%06ld] %s\n",now_ms()-g_t0,b); fflush(stdout);
	pthread_mutex_unlock(&g_log); }

/* benign errnos during teardown/concurrency: resource gone / busy / canceled */
static int benign(int e){
	return e==EAGAIN||e==EBUSY||e==ENODEV||e==ECANCELED||e==EINTR||e==EPIPE||
	       e==EACCES||e==EPERM||e==EBADF||e==ENOENT||e==EOPNOTSUPP; }

static int ctrl_fd;
static int do_create(int i){
	struct slot *s=&G[i];
	struct vrel *r=vrel_start(ctrl_fd,V_MODE_FREE,0,&s->tn);
	if(!r){ ev("DEV%d create FAILED errno=%d",i,errno); return -1; }
	s->r=r; vrel_paths(s->tn,s->raw,sizeof s->raw,s->rm,sizeof s->rm);
	ev("DEV%d create tpm%d",i,s->tn);
	if(!vwait(s->raw,20000)||!vwait(s->rm,20000)){ ev("DEV%d ROLLBACK node never appeared",i);
		vrel_stop(r); vrel_close(r); s->r=NULL; return -1; }
	s->alive=1; ev("DEV%d ready (raw+rm)",i);
	return 0;
}
static void do_teardown(int i){
	struct slot *s=&G[i];
	if(!s->r) return;
	__u32 tn=s->tn; struct vrel *r=s->r; s->r=NULL; s->alive=0;
	vrel_stop(r); close(r->serverfd); r->serverfd=-1;
	vwait_gone(s->raw,8000); vwait_gone(s->rm,8000);
	vrel_close(r);
	ev("DEV%d teardown tpm%d complete",i,tn);
}

static void client_xchg(int i){
	struct slot *s=&G[i];
	if(!s->alive||!s->r) return;
	int fd=open(s->raw,O_RDWR|O_NONBLOCK);
	if(fd<0){ if(!benign(errno)){ ev("DEV%d client open errno=%d",i,errno); g_baderrno++; } return; }
	ssize_t w=write(fd,CMD12,sizeof CMD12);
	if(w==sizeof CMD12){ struct pollfd p={fd,POLLIN,0}; poll(&p,1,2000);
		uint8_t rsp[64]; read(fd,rsp,sizeof rsp); }
	else if(w<0 && !benign(errno)){ ev("DEV%d client write errno=%d",i,errno); g_baderrno++; }
	close(fd);
	g_client++;
	if((g_client%32)==0) ev("client ops=%lu (sample on DEV%d)",g_client,i);
}

static void *worker(void *a){
	long id=(long)a; unsigned int rs=g_seed^(unsigned)(id*2654435761u)+1;
	while(!g_stop){
		int i=rand_r(&rs)%SLOTS;
		pthread_mutex_lock(&G[i].lock);
		int act=rand_r(&rs)%10;
		if(act<7 || !G[i].alive){ client_xchg(i); usleep(500); }
		else { ev("DEV%d recreate begin",i); do_teardown(i);
			if(do_create(i)==0){ g_recreate++; ev("DEV%d recreated",i);} }
		pthread_mutex_unlock(&G[i].lock);
		usleep(1000+rand_r(&rs)%2000);
	}
	return NULL;
}
static void on_alarm(int s){ (void)s; write(2,"WATCHDOG_HANG\n",13); _exit(3); }

int main(int argc,char**argv){
	if(argc>1) g_duration=atoi(argv[1]);
	if(argc>2) g_seed=(unsigned int)strtoul(argv[2],NULL,0);
	ctrl_fd=open("/dev/vtpmx",O_RDWR);
	if(ctrl_fd<0){ perror("open /dev/vtpmx");
		printf("RESULT: ENV_ABORT (root + modprobe tpm_vtpm_proxy)\n"); return 2; }
	signal(SIGALRM,on_alarm); alarm(g_duration+120);
	g_t0=now_ms();
	printf("vtpmx R7 concurrent create/teardown/cleanup stress v2 (semantic emu)\n");
	printf("duration=%ds seed=0x%x slots=%d workers=%d\n",g_duration,g_seed,SLOTS,WORKERS);
	for(int i=0;i<SLOTS;i++){ pthread_mutex_init(&G[i].lock,NULL); G[i].r=NULL; G[i].alive=0; }
	ev("filling device pool");
	for(int i=0;i<SLOTS;i++){ pthread_mutex_lock(&G[i].lock);
		if(do_create(i)!=0){ pthread_mutex_unlock(&G[i].lock);
			printf("RESULT: ENV_ABORT (pool fill failed, CPU starvation?)\n"); return 2; }
		pthread_mutex_unlock(&G[i].lock); }
	ev("pool full, starting workers");
	pthread_t wt[WORKERS];
	for(long i=0;i<WORKERS;i++) pthread_create(&wt[i],NULL,worker,(void*)i);
	sleep(g_duration);
	g_stop=1; ev("duration reached, stopping workers");
	for(int i=0;i<WORKERS;i++) pthread_join(wt[i],NULL);
	ev("tearing down all slots");
	for(int i=0;i<SLOTS;i++){ pthread_mutex_lock(&G[i].lock); do_teardown(i);
		pthread_mutex_unlock(&G[i].lock); pthread_mutex_destroy(&G[i].lock); }
	close(ctrl_fd);
	usleep(500000);
	/* verify no stray tpm/tpmrm nodes (vtpmx misc node 10:263 is expected) */
	int stray=0;
	for(int n=0;n<32;n++){ char p[40]; snprintf(p,sizeof p,"/dev/tpm%d",n);
		if(access(p,F_OK)==0) stray++; snprintf(p,sizeof p,"/dev/tpmrm%d",n);
		if(access(p,F_OK)==0) stray++; }
	printf("\n================ SUMMARY ================\n");
	printf("client_ops=%lu recreates=%lu unexpected_errno=%lu stray_nodes=%d\n",
		g_client,g_recreate,g_baderrno,stray);
	int rc = (stray||g_baderrno)?1:0;
	printf("RESULT: %s\n", rc? "ASSERT_FAIL":"PASS");
	puts("Logic run validates concurrent register/teardown cleanup. Re-run on the KASAN");
	puts("guest: any KASAN/UAF report during create/teardown is a memory-safety lead.");
	return rc;
}
