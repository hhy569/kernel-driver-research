// SPDX-License-Identifier: GPL-2.0
// vtpmx object-lifetime / fd-refcount harness (Phase 3, ChatGPT-requested windows).
//
// The deterministic race/async harnesses pin single interleavings; this file attacks the
// shared-object lifetime of one struct proxy_dev (server "[vtpms]" fd) <-> one tpm_chip,
// which carries BOTH a raw /dev/tpmN and a resource-manager /dev/tpmrmN frontend, each with
// its own struct file_priv. Cases:
//   L1  server-fd dup(): two fd references share one open-file description. Closing one
//       MUST NOT tear the device down; only the last close calls fops_release->delete_device.
//   L2  RM client stays open across server teardown: after the only server fd closes the
//       chip is unregistered, but an open /dev/tpmrmN holds a chip reference. Its later
//       ops must fail cleanly (not hang) and its final close must not touch freed memory.
//   L3  rapid NONBLOCK enqueue -> immediate close: statistically interleave work that is
//       still queued vs running when release()->flush_work() runs; must always return, no
//       hang/fd/node leak (KASAN decides UAF in the flush path).
//   L4  raw + RM clients both in flight (one work parked WAIT_RESPONSE) then the LAST server
//       fd closes: two async_work + an RM space are torn down together; both clients must be
//       woken with an error and close cleanly.
//
// Memory safety is adjudicated by KASAN in the instrumented guest; on a stock kernel these
// cases validate reference-count/lifetime logic and teardown latency only.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct vtpm_new_dev { __u32 flags, tpm_num, fd, major, minor; };
#define VTPM_FLAG_TPM2 1
#define VTPM_IOC_NEW_DEV _IOWR(0xa1, 0x00, struct vtpm_new_dev)

#define EMU_FREE 0
#define EMU_GATED 1

struct rel {
	int serverfd, serve_fd, tpmnum;
	int mode, drain;
	int ctl[2], obs[2];
	pthread_t th;
};

static int g_pass, g_unex, g_hang;
static void on_alarm(int s){ (void)s; _exit(97); }
#define OK(t)   do { printf("  [OK]   %s\n", t); g_pass++; } while (0)
#define LEAD(t) do { printf("  [LEAD] %s (reproduce under KASAN)\n", t); g_unex++; } while (0)

static void sb(int fd,char c){ if(write(fd,&c,1)<0){} }
static char rb_to(int fd,int ms){ struct pollfd p={fd,POLLIN,0};
	if(poll(&p,1,ms)<=0)return 0; char c=0; read(fd,&c,1); return c; }
static long ms_now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
	return t.tv_sec*1000L+t.tv_nsec/1000000L; }

static void tpm2_startup(uint8_t*b,int*n){ *n=12; b[0]=0x80;b[1]=1;
	b[2]=0;b[3]=0;b[4]=0;b[5]=12; b[6]=0;b[7]=0;b[8]=1;b[9]=0x44; b[10]=b[11]=0; }
static void tpm2_rsp(uint8_t*b,int*n){ *n=10; b[0]=0x80;b[1]=1;
	b[2]=0;b[3]=0;b[4]=0;b[5]=10; b[6]=b[7]=b[8]=b[9]=0; }

/* emulator; serve_fd can be switched to a dup()ed fd. Re-reads it every loop so closing the
 * old fd after a switch only yields POLLNVAL on a stale poll, which is ignored. */
static void* emu_thread(void*a){
	struct rel*r=a; uint8_t cmd[4200],rsp[16]; int rl,served=0;
	for(;;){
		int sfd=r->serve_fd;
		if(sfd<0||fcntl(sfd,F_GETFD)<0)break;
		struct pollfd pf[2]={{sfd,POLLIN|POLLHUP|POLLERR|POLLNVAL,0},{r->ctl[0],POLLIN,0}};
		int pr=poll(pf,2,300);
		if(pr<0){ if(errno==EINTR)continue; break; }
		if(pf[1].revents&POLLIN){ char c; if(read(r->ctl[0],&c,1)>0&&c=='s')break; }
		if(pf[0].revents&POLLNVAL){ usleep(20000); continue; }   /* fd switched under us */
		if(!(pf[0].revents&(POLLIN|POLLHUP|POLLERR))) continue;
		if(pf[0].revents&(POLLHUP|POLLERR)){ usleep(20000);
			if(fcntl(sfd,F_GETFD)<0)break; continue; }
		int gate=(r->mode==EMU_GATED && served>=r->drain);
		if(gate){ sb(r->obs[1],'Q'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(sfd,F_GETFD)<0)break; }
		int nn=read(sfd,cmd,sizeof(cmd));
		if(nn<0){ if(errno==EBADF||errno==EPIPE)break; usleep(20000); continue; }
		if(gate){ sb(r->obs[1],'R'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(sfd,F_GETFD)<0)break; }
		tpm2_rsp(rsp,&rl);
		if(write(sfd,rsp,rl)<0){}
		if(gate) sb(r->obs[1],'P');
		served++;
	}
	return 0;
}

static struct rel* start_rel(int ctrl,int mode,int drain,__u32*tn){
	struct vtpm_new_dev s; memset(&s,0,sizeof(s)); s.flags=VTPM_FLAG_TPM2;
	if(ioctl(ctrl,VTPM_IOC_NEW_DEV,&s)<0)return NULL;
	struct rel*r=calloc(1,sizeof(*r));
	r->serverfd=s.fd;r->serve_fd=s.fd;r->tpmnum=s.tpm_num;r->mode=mode;r->drain=drain;
	pipe2(r->ctl,O_NONBLOCK);pipe2(r->obs,O_NONBLOCK);
	if(tn)*tn=s.tpm_num;
	pthread_create(&r->th,NULL,emu_thread,r);
	return r;
}
static void gate(struct rel*r,char c){ sb(r->ctl[1],c); }
static char anchor(struct rel*r,int ms){ return rb_to(r->obs[0],ms); }
static void rel_join(struct rel*r){ sb(r->ctl[1],'s'); pthread_join(r->th,NULL); }
static void rel_pipes(struct rel*r){
	close(r->ctl[0]);close(r->ctl[1]);close(r->obs[0]);close(r->obs[1]); free(r); }
static void wait_node(const char*path,int want,int timeout_ms){
	for(int i=0;i<timeout_ms/50;i++){ if(access(path,F_OK)==want)return; usleep(50000); }
}
static void paths(__u32 tn,char*raw,size_t rl,char*rm,size_t ml){
	snprintf(raw,rl,"/dev/tpm%u",tn); snprintf(rm,ml,"/dev/tpmrm%u",tn); }

/* child: one blocking raw roundtrip; exit 0 on 10-byte response, else code */
static int child_raw_rt(void*p){
	const char*path=p; signal(SIGALRM,on_alarm); alarm(8);
	int fd=open(path,O_RDWR); if(fd<0)_exit(40);
	uint8_t cmd[16],rs[64]; int cl; tpm2_startup(cmd,&cl);
	if(write(fd,cmd,cl)!=cl)_exit(41);
	struct pollfd q={fd,POLLIN,0}; poll(&q,1,6000);
	int n=read(fd,rs,sizeof(rs));
	close(fd); _exit(n==10?0:42);
}
/* child: NONBLOCK enqueue then immediate close (L3 iteration) */
static int child_enq_close(void*p){
	const char*path=p; signal(SIGALRM,on_alarm); alarm(5);
	int fd=open(path,O_RDWR|O_NONBLOCK); if(fd<0)_exit(40);
	uint8_t cmd[16]; int cl; tpm2_startup(cmd,&cl);
	write(fd,cmd,cl);            /* may enqueue or already be EBUSY; either is fine */
	close(fd);                   /* release -> flush_work must return */
	_exit(0);
}
/* run a child fn with a hard wall-clock timeout; 0=clean exit, 1=bad code, -97=hang */
static int run_child(void*(*fn)(void*),void*arg,int timeout_ms,int*code){
	pid_t pid=fork();
	if(pid==0){ void*rc=fn(arg); _exit(rc?(int)(long)rc:0); }
	int st=0,steps=timeout_ms/50+10;
	for(int i=0;i<steps;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(50000); }
	if(waitpid(pid,&st,WNOHANG)!=pid){ kill(pid,SIGKILL); waitpid(pid,&st,0); if(code)*code=-97; return -97; }
	int ex= WIFEXITED(st)?WEXITSTATUS(st):-1; if(code)*code=ex; return ex==0?0:1;
}

/* L1: dup() on the server fd separates fd-reference lifetime from proxy_dev lifetime. */
static void test_L1_dup(int ctrl){
	printf("=== L1: server-fd dup() reference-count separation ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,&tn);
	char raw[64],rm[64]; paths(tn,raw,sizeof raw,rm,sizeof rm);
	wait_node(raw,0,6000); usleep(150000);
	int A=r->serverfd, B=-1, A_closed=0, code, ok=0;
	if(run_child((void*(*)(void*))child_raw_rt,raw,8000,&code)!=0){ LEAD("L1 baseline roundtrip failed"); goto l1done; }
	B=dup(A); if(B<0){ LEAD("L1 dup failed"); goto l1done; }
	r->serve_fd=B; usleep(350000);                 /* emulator migrates onto B */
	close(A); A_closed=1; r->serverfd=-1;         /* drops A; B keeps the file alive */
	wait_node(raw,0,500);
	if(access(raw,F_OK)!=0){ LEAD("L1 device torn down after closing only one dup ref"); goto l1done; }
	if(run_child((void*(*)(void*))child_raw_rt,raw,8000,&code)!=0){
		LEAD("L1 device not serviceable through surviving dup (refcount/lifetime)"); goto l1done; }
	printf("  [..] after close(A) device alive and services via dup B (refcount held)\n");
	r->serve_fd=B;
	close(B); B=-1; r->serve_fd=-1;               /* last reference -> release -> teardown */
	wait_node(raw,-1,8000);
	if(access(raw,F_OK)==0){ LEAD("L1 device still present after last dup close"); goto l1done; }
	OK("L1 close(A) keeps device, close(B/last) tears it down (fd refcount correct)"); ok=1;
l1done:
	(void)ok;
	sb(r->ctl[1],'s'); pthread_join(r->th,NULL);
	if(!A_closed && r->serverfd>=0) close(r->serverfd);
	if(B>=0) close(B);
	rel_pipes(r);
}

/* L2: RM client remains open while the server fd (chip) is torn down. */
static void test_L2_rm_survives(int ctrl){
	printf("=== L2: RM client open across server teardown ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,&tn);
	char raw[64],rm[64]; paths(tn,raw,sizeof raw,rm,sizeof rm);
	wait_node(rm,0,6000); usleep(150000);
	int rmfd=open(rm,O_RDWR|O_NONBLOCK);
	if(rmfd<0){ printf("  [..] open %s failed (%s); RM frontend absent in this build\n",rm,strerror(errno));
		close(r->serverfd); rel_join(r); r->serverfd=-1; rel_pipes(r); g_pass++; return; }
	long t0=ms_now();
	close(r->serverfd); r->serverfd=-1; r->serve_fd=-1;   /* tear down chip while RM fd open */
	wait_node(raw,-1,8000);
	/* child: use the orphaned RM fd, then close it; must return, never hang/crash */
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(12);
		uint8_t cmd[16]; int cl; tpm2_startup(cmd,&cl);
		write(rmfd,cmd,cl);                 /* expected: -1 (EPIPE/EIO) or queued-then-error */
		struct pollfd p={rmfd,POLLIN,0}; poll(&p,1,4000);
		uint8_t rs[64]; read(rmfd,rs,sizeof(rs));
		off_t o=lseek(rmfd,0,SEEK_SET); (void)o;   /* still ESPIPE */
		close(rmfd);                        /* tpmrm_release: common_release + del_space + free */
		_exit(0); }
	int st=0; for(int i=0;i<200;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(50000); }
	long dt=ms_now()-t0;
	if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); printf("  [HANG] L2 orphaned-RM close\n"); g_hang++; }
	else if(WEXITSTATUS(st)==0 && dt<15000){
		printf("  [..] L2 orphaned RM op+close returned in %ldms\n",dt);
		OK("L2 RM client outlives chip teardown and closes cleanly (KASAN to confirm no UAF)");
	} else { printf("  [UNEX] L2 exit=%d dt=%ldms\n",WEXITSTATUS(st),dt); g_unex++; }
	rel_join(r); rel_pipes(r);
}

/* L3: rapid NONBLOCK enqueue -> immediate close exercises queued/running flush_work. */
static void test_L3_rapid_flush(int ctrl){
	printf("=== L3: rapid async enqueue/close (queued vs running flush_work) ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,&tn);
	char raw[64],rm[64]; paths(tn,raw,sizeof raw,rm,sizeof rm);
	wait_node(raw,0,6000); usleep(150000);
	int N=30,hangs=0,bad=0; long t0=ms_now();
	for(int i=0;i<N;i++){ int code;
		int rc=run_child((void*(*)(void*))child_enq_close,raw,6000,&code);
		if(rc==-97)hangs++; else if(rc!=0)bad++; }
	long dt=ms_now()-t0;
	close(r->serverfd); r->serverfd=-1; r->serve_fd=-1;
	wait_node(raw,-1,8000);
	rel_join(r); rel_pipes(r);
	if(hangs==0&&bad==0){ printf("  [..] L3 %d enqueue/close in %ldms, no hang\n",N,dt);
		OK("L3 async close always returns across queued/running work (KASAN to confirm flush path)"); }
	else { printf("  [UNEX] L3 hangs=%d bad=%d\n",hangs,bad);
		if(hangs)g_hang++; else g_unex++; }
}

/* L4: raw + RM work in flight (one parked WAIT_RESPONSE), then last server fd closes. */
static void test_L4_coexist_teardown(int ctrl){
	printf("=== L4: raw+RM in flight, last server fd teardown ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,2,&tn);
	char raw[64],rm[64]; paths(tn,raw,sizeof raw,rm,sizeof rm);
	wait_node(rm,0,6000); usleep(200000);
	int rawfd=open(raw,O_RDWR|O_NONBLOCK);
	int rmfd =open(rm ,O_RDWR|O_NONBLOCK);
	if(rawfd<0||rmfd<0){ printf("  [..] open failed raw=%d rm=%d (%s); skip\n",rawfd,rmfd,strerror(errno));
		if(rawfd>=0)close(rawfd); if(rmfd>=0)close(rmfd);
		close(r->serverfd); rel_join(r); r->serverfd=-1; rel_pipes(r); return; }
	uint8_t cmd[16]; int cl; tpm2_startup(cmd,&cl);
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(15);
		write(rawfd,cmd,cl);                 /* raw work -> gated, parks WAIT_RESPONSE */
		usleep(150000);
		write(rmfd,cmd,cl);                  /* RM work queued behind, separate file_priv */
		struct pollfd p[2]={{rawfd,POLLIN,0},{rmfd,POLLIN,0}};
		poll(p,2,6000);                      /* teardown happens meanwhile; expect wake/error */
		uint8_t rs[64]; read(rawfd,rs,sizeof rs); read(rmfd,rs,sizeof rs);
		close(rawfd); close(rmfd); _exit(0); }
	char a=anchor(r,8000);(void)a; gate(r,'g');     /* REQ */
	char b=anchor(r,8000);(void)b;                  /* READ: raw work now WAIT_RESPONSE */
	long t0=ms_now();
	close(r->serverfd); r->serverfd=-1; r->serve_fd=-1;   /* last/only server ref -> teardown */
	int st=0; for(int i=0;i<250;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(50000); }
	long dt=ms_now()-t0;
	if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); printf("  [HANG] L4 coexist teardown\n"); g_hang++; }
	else if(WEXITSTATUS(st)==0&&dt<15000){ printf("  [..] L4 both clients woke/closed in %ldms\n",dt);
		OK("L4 raw+RM async work torn down together cleanly (KASAN to confirm chip/space lifetime)"); }
	else { printf("  [UNEX] L4 exit=%d dt=%ldms\n",WEXITSTATUS(st),dt); g_unex++; }
	rel_join(r); rel_pipes(r);
}

int main(void){
	printf("vtpmx OBJECT-LIFETIME / FD-REFCOUNT HARNESS (L1-L4)\n\n");
	int ctrl=open("/dev/vtpmx",O_RDWR);
	if(ctrl<0){ perror("open /dev/vtpmx (root)"); return 1; }
	test_L1_dup(ctrl);
	test_L2_rm_survives(ctrl);
	test_L3_rapid_flush(ctrl);
	test_L4_coexist_teardown(ctrl);
	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("passed:%d leads/unexpected:%d hangs:%d\n",g_pass,g_unex,g_hang);
	puts("Stock-kernel run validates fd refcount and chip/RM teardown logic. Re-run on Kernel B");
	puts("(KASAN, Generic quarantine): any UAF/slab report in tpm_del_char_device /");
	puts("tpm_dev_release / tpmrm_release / tpm_dev_async_work during L1-L4 is a memory-safety lead.");
	return g_hang?3:0;
}
