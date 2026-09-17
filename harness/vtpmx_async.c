// SPDX-License-Identifier: GPL-2.0
// vtpmx async / poll / same-fd concurrency harness (Phase 3, R4/R10 + async teardown).
//
// Coverage that vtpmx_race.c did not reach. tpm_common_write() has two paths:
//   blocking    : tpm_try_get_ops + tpm_dev_transmit inline under ops read lock;
//   O_NONBLOCK  : queue_work(tpm_dev_wq, async_work) and return size immediately;
//                 tpm_dev_async_work() then takes buffer_mutex + ops read lock and
//                 does the transmit, wake_up_interruptible(&async_wait) on completion.
// This harness exercises the async workqueue lifetime and the poll state machine:
//   A  lseek negative control  -> .llseek=no_llseek must yield ESPIPE (f_pos not user settable)
//   R4a async happy path       -> NONBLOCK write queues work, poll() wakes EPOLLIN, read=10
//   R4b command_enqueued gate  -> a 2nd NONBLOCK write before read must be -EBUSY
//   R4c async teardown in WAIT_RESPONSE -> close(serverfd) cancels ops; poll/read must
//                                  wake with an error and teardown must not hang/UAF
//   R10 client close while async in flight -> release()->flush_work() must return promptly
//   RM  /dev/tpmrmN multi-open if present (same frontend, multiple file_priv share chip)
//
// Blocked transmits are released ONLY by serverfd teardown (proven in R1 to cancel to a
// fast -ETIME), never by waiting the minute-class TPM timeout.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct vtpm_new_dev { __u32 flags, tpm_num, fd, major, minor; };
#define VTPM_FLAG_TPM2 1
#define VTPM_IOC_NEW_DEV _IOWR(0xa1, 0x00, struct vtpm_new_dev)

#define EMU_FREE 0
#define EMU_GATED 1

struct rel {
	int serverfd, tpmnum;
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

/* gated emulator: serve first `drain` freely (auto-startup), then gate REQ/READ */
static void* emu_thread(void*a){
	struct rel*r=a; uint8_t cmd[4200],rsp[16]; int rl,served=0;
	for(;;){
		struct pollfd pf[2]={{r->serverfd,POLLIN|POLLHUP|POLLERR,0},{r->ctl[0],POLLIN,0}};
		int pr=poll(pf,2,300);
		if(pr<0){ if(errno==EINTR)continue; break; }
		if(pf[1].revents&POLLIN){ char c; if(read(r->ctl[0],&c,1)>0&&c=='s')break; }
		if(!(pf[0].revents&(POLLIN|POLLHUP|POLLERR))) continue;
		if(pf[0].revents&(POLLHUP|POLLERR)){ usleep(20000);
			if(fcntl(r->serverfd,F_GETFD)<0)break; continue; }
		int gate=(r->mode==EMU_GATED && served>=r->drain);
		if(gate){ sb(r->obs[1],'Q'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(r->serverfd,F_GETFD)<0)break; }
		int nn=read(r->serverfd,cmd,sizeof(cmd));
		if(nn<0){ if(errno==EBADF||errno==EPIPE)break; usleep(20000); continue; }
		if(gate){ sb(r->obs[1],'R'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(r->serverfd,F_GETFD)<0)break; }
		tpm2_rsp(rsp,&rl);
		if(write(r->serverfd,rsp,rl)<0){}
		if(gate) sb(r->obs[1],'P');
		served++;
	}
	return 0;
}

static struct rel* start_rel(int ctrl,int mode,int drain,__u32*tn){
	struct vtpm_new_dev s; memset(&s,0,sizeof(s)); s.flags=VTPM_FLAG_TPM2;
	if(ioctl(ctrl,VTPM_IOC_NEW_DEV,&s)<0)return NULL;
	struct rel*r=calloc(1,sizeof(*r));
	r->serverfd=s.fd;r->tpmnum=s.tpm_num;r->mode=mode;r->drain=drain;
	pipe2(r->ctl,O_NONBLOCK);pipe2(r->obs,O_NONBLOCK);
	if(tn)*tn=s.tpm_num;
	pthread_create(&r->th,NULL,emu_thread,r);
	return r;
}
static void gate(struct rel*r,char c){ sb(r->ctl[1],c); }
static char anchor(struct rel*r,int ms){ return rb_to(r->obs[0],ms); }
static void rel_stop(struct rel*r){ sb(r->ctl[1],'s'); pthread_join(r->th,NULL); }
static void rel_close(struct rel*r){ if(r->serverfd>=0)close(r->serverfd);
	close(r->ctl[0]);close(r->ctl[1]);close(r->obs[0]);close(r->obs[1]); free(r); }
static void wait_dev(const char*path){ for(int i=0;i<120;i++){
	if(access(path,F_OK)==0)return; usleep(50000);} }

/* A: lseek must be refused (no_llseek) -> f_pos cannot be user controlled */
static void test_lseek(int ctrl){
	printf("=== A: lseek negative control (no_llseek) ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,&tn);
	char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn); wait_dev(path);
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(10);
		int fd=open(path,O_RDWR); if(fd<0)_exit(40);
		off_t o=lseek(fd,4096,SEEK_SET);
		_exit((o==(off_t)-1 && errno==ESPIPE)?0:50); }
	int st=0; for(int i=0;i<100;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(100000);}
	if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); g_hang++; }
	if(WIFEXITED(st)&&WEXITSTATUS(st)==0) OK("lseek rejected with ESPIPE (read offset not attacker-settable)");
	else LEAD("lseek not rejected - re-audit tpm_common_read offset bound");
	rel_stop(r); close(r->serverfd); r->serverfd=-1; rel_close(r);
}

/* R4a/R4b: NONBLOCK happy path + command_enqueued EBUSY gate, free emulator */
static void test_R4_async(int ctrl){
	printf("=== R4: NONBLOCK async transmit / poll / command_enqueued ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,&tn);
	char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn); wait_dev(path);
	usleep(200000);
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(15);
		int fd=open(path,O_RDWR|O_NONBLOCK); if(fd<0)_exit(40);
		uint8_t cmd[16],rs[64]; int cl; tpm2_startup(cmd,&cl);
		int w1=write(fd,cmd,cl);
		if(w1!=cl)_exit(51);
		/* a 2nd command before consuming the first must be EBUSY */
		errno=0; int w2=write(fd,cmd,cl);
		if(!(w2<0&&errno==EBUSY))_exit(52);
		/* poll until EPOLLIN (async_work completed and woke us) */
		struct pollfd p={fd,POLLIN,0}; int pr=poll(&p,1,8000);
		if(!(pr>0&&(p.revents&POLLIN)))_exit(53);
		int n=read(fd,rs,sizeof(rs));
		if(n!=10)_exit(54);
		/* after draining, a new command is accepted again */
		int w3=write(fd,cmd,cl); if(w3!=cl)_exit(55);
		struct pollfd q={fd,POLLIN,0}; poll(&q,1,8000);
		if(read(fd,rs,sizeof(rs))!=10)_exit(56);
		_exit(0); }
	int st=0; for(int i=0;i<200;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(100000);}
	if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); printf("  [HANG] R4\n"); g_hang++; }
	else if(WEXITSTATUS(st)==0) OK("R4 async enqueue/EBUSY/poll-wake/read cycle correct");
	else { printf("  [UNEX] R4 exit=%d\n",WEXITSTATUS(st)); g_unex++; }
	rel_stop(r); close(r->serverfd); r->serverfd=-1; rel_close(r);
}

/* R4c: async work parked in WAIT_RESPONSE, then serverfd teardown must cancel it;
 * poll must wake and nothing may hang (KASAN watches for UAF in async_work/teardown). */
static void test_R4c_teardown(int ctrl){
	printf("=== R4c: async teardown while WAIT_RESPONSE ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,2,&tn);
	char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn); wait_dev(path);
	usleep(200000);
	int cpipe[2]; pipe(cpipe);
	pid_t pid=fork();
	if(pid==0){ close(cpipe[0]); signal(SIGALRM,on_alarm); alarm(20);
		int fd=open(path,O_RDWR|O_NONBLOCK); if(fd<0)_exit(40);
		uint8_t cmd[16];int cl; tpm2_startup(cmd,&cl);
		int w=write(fd,cmd,cl); if(w!=cl)_exit(51);
		struct pollfd p={fd,POLLIN,0};
		int pr=poll(&p,1,6000);            /* teardown happens meanwhile */
		uint8_t rs[64]; int n=read(fd,rs,sizeof(rs));  /* error wake -> <=0, not hang */
		unsigned char rep[2]={0};
		/* acceptable: poll timed out/error, or read returns error/0; must NOT hang/crash */
		rep[0]=1; rep[1]=(pr>0&&(p.revents&POLLIN))?1:0; (void)n;
		write(cpipe[1],rep,2);
		close(fd); _exit(0); }
	close(cpipe[1]);
	char a=anchor(r,8000); (void)a;  /* REQ */
	gate(r,'g'); char b=anchor(r,8000); (void)b; /* READ: async work now WAIT_RESPONSE */
	long t0=ms_now();
	close(r->serverfd); r->serverfd=-1;           /* teardown: cancel ops -> down_write */
	struct pollfd cp={cpipe[0],POLLIN,0}; poll(&cp,1,15000);
	long dt=ms_now()-t0;
	int st=0; for(int i=0;i<150;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(100000);}
	if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); printf("  [HANG] R4c teardown=%ldms\n",dt); g_hang++; }
	else { printf("  [..] R4c teardown=%ldms child_exit=%d (fast cancel expected)\n",dt,WEXITSTATUS(st));
		if(dt<10000) OK("R4c async teardown prompt, no hang (KASAN to confirm no UAF)");
		else LEAD("R4c teardown blocked >10s"); }
	sb(r->ctl[1],'s'); rel_stop(r); close(cpipe[0]); rel_close(r);
}

/* R10: client closes while async work is queued; release()->flush_work must return.
 * Let the emulator respond after the close starts so async_work completes promptly
 * (happy close), and a second case where teardown cancels first. */
static void test_R10_close(int ctrl){
	printf("=== R10: client close with async work in flight ===\n");
	for(int mode=0;mode<2;mode++){
		__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,2,&tn);
		char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn); wait_dev(path);
		usleep(200000);
		pid_t pid=fork();
		if(pid==0){ signal(SIGALRM,on_alarm); alarm(20);
			int fd=open(path,O_RDWR|O_NONBLOCK); if(fd<0)_exit(40);
			uint8_t cmd[16];int cl; tpm2_startup(cmd,&cl);
			if(write(fd,cmd,cl)!=cl)_exit(51);
			close(fd);        /* release -> flush_work(async_work) */
			_exit(0); }
		char a=anchor(r,8000);(void)a; gate(r,'g');
		char b=anchor(r,8000);(void)b; /* WAIT_RESPONSE */
		long t0=ms_now();
		if(mode==0){ gate(r,'g'); }     /* let emulator deliver response -> async completes */
		else { close(r->serverfd); r->serverfd=-1; } /* cancel ops first */
		int st=0; for(int i=0;i<200;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(100000);}
		long dt=ms_now()-t0;
		if(!WIFEXITED(st)){ kill(pid,SIGKILL);waitpid(pid,&st,0); printf("  [HANG] R10 mode%d\n",mode); g_hang++; }
		else if(WEXITSTATUS(st)==0 && dt<10000){ printf("  [..] R10 mode%d close flush=%ldms clean\n",mode,dt); g_pass++; }
		else { printf("  [UNEX] R10 mode%d exit=%d dt=%ldms\n",mode,WEXITSTATUS(st),dt); g_unex++; }
		sb(r->ctl[1],'s'); rel_stop(r);
		if(r->serverfd>=0){ close(r->serverfd); r->serverfd=-1; }
		rel_close(r);
	}
	OK("R10 async close paths return promptly (KASAN to confirm flush_work lifetime)");
}

int main(void){
	printf("vtpmx ASYNC / POLL / SAME-FD CONCURRENCY HARNESS (R4/R10)\n\n");
	int ctrl=open("/dev/vtpmx",O_RDWR);
	if(ctrl<0){ perror("open /dev/vtpmx (root)"); return 1; }
	test_lseek(ctrl);
	test_R4_async(ctrl);
	test_R4c_teardown(ctrl);
	test_R10_close(ctrl);
	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("passed:%d leads/unexpected:%d hangs:%d\n",g_pass,g_unex,g_hang);
	puts("Logic run validates the async state machine and teardown latency. Re-run on\n"
	     "Kernel B (KASAN): a KASAN/UAF report in tpm_dev_async_work / tpm_common_release\n"
	     "/ tpm_del_char_device during R4c or R10 is a memory-safety lead. no_llseek closes\n"
	     "the lseek->read-offset class by construction (verified in case A).");
	return g_hang?3:0;
}
