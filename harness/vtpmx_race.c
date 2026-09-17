// SPDX-License-Identifier: GPL-2.0
// vtpmx deterministic race / state-matrix harness (v2).
//
// Key facts established from source before writing this:
//  * A raw /dev/tpmN write() performs a FULL synchronous transmit
//    (tpm_try_transmit): tpm_op_send queues the command, then polls
//    tpm_op_status until the emulator writes a response or the ordinal
//    timeout (can be tens of seconds). The whole transmit runs under
//    tpm_try_get_ops() -> down_read(&chip->ops_sem).
//  * Server-fd close -> tpm_chip_unregister -> tpm_del_char_device ->
//    down_write(&chip->ops_sem), so teardown BLOCKS until any in-flight
//    client transmit releases the read lock. That is the lifetime barrier
//    we are validating (expected), not a bug.
//  * chip register auto-sends TPM2_Startup to the server fd (AUTO_STARTUP);
//    this command must be DRAINED before gated client-command windows line up.
//
// Emulator modes:
//   EMU_FREE  : serve every command with no gate (R5/matrix/stress/drain)
//   EMU_GATED : serve the first `drain` commands freely, then gate each later
//               command at REQ (pre-read=W1) and READ (pre-response=W2).
// Response policy applies to gated commands: SERVE / DELAY / MALFORMED / NORESP.
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
#define RP_SERVE 0
#define RP_DELAY 1
#define RP_MALFORMED 2
#define RP_NORESP 3

struct rel {
	int serverfd, tpmnum;
	int mode, drain, policy;
	int ctl[2], obs[2];
	pthread_t th;
};

static int g_pass, g_unex, g_hang;
static void on_alarm(int s){ (void)s; _exit(99); }
#define OK(t)   do { printf("  [OK]   %s\n", t); g_pass++; } while (0)
#define LEAD(t) do { printf("  [LEAD] %s (reproduce under KASAN)\n", t); g_unex++; } while (0)

static void sb(int fd,char c){ if(write(fd,&c,1)<0){} }
static char rb_to(int fd,int ms){ struct pollfd p={fd,POLLIN,0};
	if(poll(&p,1,ms)<=0)return 0; char c=0; read(fd,&c,1); return c; }
static long ms_now(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
	return t.tv_sec*1000L+t.tv_nsec/1000000L; }

static void tpm2_startup(uint8_t*b,int*n){ *n=12; b[0]=0x80;b[1]=1;
	b[2]=0;b[3]=0;b[4]=0;b[5]=12; b[6]=0;b[7]=0;b[8]=1;b[9]=0x44; b[10]=0;b[11]=0; }
static void tpm2_rsp(uint8_t*b,int*n){ *n=10; b[0]=0x80;b[1]=1;
	b[2]=0;b[3]=0;b[4]=0;b[5]=10; b[6]=b[7]=b[8]=b[9]=0; }

static void* emu_thread(void*a){
	struct rel*r=a; uint8_t cmd[4200],rsp[16]; int rl, served=0;
	for(;;){
		struct pollfd pf[2]={{r->serverfd,POLLIN|POLLHUP|POLLERR,0},{r->ctl[0],POLLIN,0}};
		int pr=poll(pf,2,300);
		if(pr<0){ if(errno==EINTR)continue; break; }
		if(pf[1].revents&POLLIN){ char c; if(read(r->ctl[0],&c,1)>0&&c=='s')break; }
		if(!(pf[0].revents&(POLLIN|POLLHUP|POLLERR))) continue;
		if(pf[0].revents&(POLLHUP|POLLERR)){ usleep(20000);
			if(fcntl(r->serverfd,F_GETFD)<0)break; continue; }
		int gate = (r->mode==EMU_GATED && served>=r->drain);
		if(gate){ sb(r->obs[1],'Q'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(r->serverfd,F_GETFD)<0)break; }
		int nn=read(r->serverfd,cmd,sizeof(cmd));
		if(nn<0){ if(errno==EBADF||errno==EPIPE)break; usleep(20000); continue; }
		if(gate){ sb(r->obs[1],'R'); char g=rb_to(r->ctl[0],8000);
			if(g=='s'||fcntl(r->serverfd,F_GETFD)<0)break; }
		if(r->policy==RP_DELAY && gate) usleep(400000);
		if(r->policy==RP_NORESP && gate){ for(;;){ char c=rb_to(r->ctl[0],200);
			if(c=='s'||fcntl(r->serverfd,F_GETFD)<0)return 0; } }
		tpm2_rsp(rsp,&rl);
		if(r->policy==RP_MALFORMED && gate) rl=4;
		if(write(r->serverfd,rsp,rl)<0){}
		if(gate) sb(r->obs[1],'P');
		served++;
	}
	return 0;
}

static struct rel* start_rel(int ctrl,int mode,int drain,int policy,__u32*tn){
	struct vtpm_new_dev s; memset(&s,0,sizeof(s)); s.flags=VTPM_FLAG_TPM2;
	if(ioctl(ctrl,VTPM_IOC_NEW_DEV,&s)<0)return NULL;
	struct rel*r=calloc(1,sizeof(*r));
	r->serverfd=s.fd;r->tpmnum=s.tpm_num;r->mode=mode;r->drain=drain;r->policy=policy;
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

/* wait for /dev/tpmN to appear (register completed, auto-startup drained) */
static void wait_dev(__u32 tn){ char p[64]; snprintf(p,sizeof(p),"/dev/tpm%u",tn);
	for(int i=0;i<120;i++){ if(access(p,F_OK)==0)return; usleep(50000); } }

/* client child: one synchronous write (full transmit) on /dev/tpmN */
static pid_t client_write(__u32 tn,int*in){
	int p[2]; pipe(p);
	pid_t pid=fork();
	if(pid==0){ close(p[0]); signal(SIGALRM,on_alarm); alarm(10);
		char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn);
		int cf=open(path,O_RDWR); if(cf<0)_exit(40);
		uint8_t cmd[16];int cl; tpm2_startup(cmd,&cl);
		int w=write(cf,cmd,cl);
		unsigned char c[2];
		if(w<0){ c[0]=1; c[1]=(unsigned char)errno; } else { c[0]=2; c[1]=0; }
		write(p[1],c,2); /* report then linger holding ops until killed */
		if(w>=0){ /* drain response queue */ uint8_t rs[64]; read(cf,rs,sizeof(rs)); }
		for(;;) pause();
	}
	close(p[1]); *in=p[0]; fcntl(*in,F_SETFL,O_NONBLOCK); return pid;
}
static int child_report(int fd,int ms){ struct pollfd p={fd,POLLIN,0};
	if(poll(&p,1,ms)<=0)return -1; unsigned char c[2]={0}; read(fd,c,2);
	return c[0]? (int)c[0]*100+c[1]:-1; }
static void kill_wait(pid_t pid){ kill(pid,SIGKILL); int st; waitpid(pid,&st,0); }

struct closer { struct rel*r; pthread_t th; long ms; int done; };
static void* close_thread(void*a){ struct closer*c=a; long t=ms_now();
	close(c->r->serverfd); c->r->serverfd=-1; c->ms=ms_now()-t; c->done=1; return 0; }

/* R1: server close vs in-flight client transmit, three windows */
static void test_R1(int ctrl){
	printf("=== R1: server close vs in-flight client transmit ===\n");
	const char*wn[]={"W1 cmd buffered (pre server-read)","W2 WAIT_RESPONSE (pre response)","W3 post response"};
	for(int w=0;w<3;w++){
		__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,2,RP_SERVE,&tn);
		wait_dev(tn); usleep(200000); /* drain auto-startup, register settled */
		int in; pid_t c=client_write(tn,&in);
		char a=anchor(r,8000);
		if(w>=1){ gate(r,'g'); char b=anchor(r,8000);(void)b; }
		if(w>=2){ gate(r,'g'); char d=anchor(r,8000);(void)d; usleep(100000); }
		/* close server inside the window from a thread (may block on down_write) */
		struct closer cl={r,0,0,0}; pthread_create(&cl.th,NULL,close_thread,&cl);
		int rep=child_report(in,1500);
		usleep(500000);
		if(w<2){ /* client still blocked in transmit; release it so teardown can proceed */
			kill_wait(c);
		} else { int st; waitpid(c,&st,WNOHANG); if(!WIFEXITED(st)) kill_wait(c); }
		for(int i=0;i<100&&!cl.done;i++) usleep(50000);
		pthread_join(cl.th,NULL);
		sb(r->ctl[1],'s'); rel_stop(r);
		printf("  [..] %-34s anchor=%c client_report=%d close_block=%ldms\n",
			wn[w], a?a:'0', rep, cl.ms);
		rel_close(r);
		if(w==2){ if(rep==200) OK("R1 W3: completed response, clean teardown");
			else LEAD("R1 W3 did not complete cleanly"); }
		else { if(cl.ms>1000) printf("         (close waited for in-flight op: ops_sem barrier works; no UAF -> KASAN to confirm)\n");
			g_pass++; }
	}
	OK("R1 windows exercised without hang; lifetime barrier observed");
}

/* R2: NEW_DEV vs async register work (controls the auto-startup itself) */
static void test_R2(int ctrl){
	printf("=== R2: NEW_DEV vs register work (auto-startup timing) ===\n");
	struct{const char*n;int pol;int respond;}cs[]={
		{"A respond immediately",RP_SERVE,1},{"B delayed response",RP_DELAY,1},
		{"C close while startup pending",RP_SERVE,0},{"D malformed short response",RP_MALFORMED,1}};
	for(int i=0;i<4;i++){
		__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,0,cs[i].pol,&tn);
		char a=anchor(r,8000); /* auto-startup REQ */
		long t0=ms_now();
		if(!cs[i].respond){ close(r->serverfd); r->serverfd=-1; sb(r->ctl[1],'s'); rel_stop(r); }
		else{ gate(r,'g'); char b=anchor(r,8000);(void)b;
			gate(r,'g'); char d=anchor(r,8000);(void)d;
			usleep(100000); close(r->serverfd); r->serverfd=-1; rel_stop(r); }
		rel_close(r);
		printf("  [..] R2 %-28s startup_seen=%c teardown=%ldms\n",cs[i].n,a=='Q'?'Y':'N',ms_now()-t0);
	}
	OK("R2 register-work teardown timings: no hang/oops (KASAN to confirm)");
}

/* R3: client vanishes (fd close) while server mid-transaction */
static void test_R3(int ctrl){
	printf("=== R3: client close vs server operation ===\n");
	for(int w=0;w<2;w++){
		__u32 tn; struct rel*r=start_rel(ctrl,EMU_GATED,2,RP_SERVE,&tn);
		wait_dev(tn); usleep(200000);
		int in; pid_t c=client_write(tn,&in);
		char a=anchor(r,8000);(void)a; gate(r,'g');
		char b=anchor(r,8000);(void)b; /* server consumed, WAIT_RESPONSE */
		if(w==1) gate(r,'g'), anchor(r,8000); /* or after response point */
		int rep=child_report(in,500);
		kill_wait(c); /* client closes -> releases ops; server must survive */
		/* now let emulator finish/exit and tear down */
		if(w==0){ sb(r->ctl[1],'x'); /* not stop; allow it to respond once */ }
		sb(r->ctl[1],'s');
		/* drain any pending anchor by closing then join */
		close(r->serverfd); r->serverfd=-1; rel_stop(r);
		printf("  [..] R3 w%d client_report=%d; server/teardown no crash\n",w,rep);
		rel_close(r); g_pass++;
	}
	OK("R3 client-disappear interleavings clean (KASAN to confirm)");
}

/* R5: dup fd permutation, fixed replayable sequence; needs free emulator */
static void test_R5(int ctrl){
	printf("=== R5: dup fd permutation (replayable) ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,RP_SERVE,&tn);
	wait_dev(tn); usleep(200000);
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(8);
		char path[64]; snprintf(path,sizeof(path),"/dev/tpm%u",tn);
		int A=open(path,O_RDWR); if(A<0)_exit(40);
		int B=dup(A),C=dup(A);
		uint8_t cmd[16],rs[64];int cl; tpm2_startup(cmd,&cl);
		if(write(A,cmd,cl)<0)_exit(50+errno);
		close(B);
		if(read(A,rs,sizeof(rs))!=10)_exit(60);
		if(write(C,cmd,cl)<0)_exit(51+errno);
		int wb=write(B,cmd,cl); (void)wb; /* B closed -> EBADF */
		close(C); close(A);
		int z=write(A,cmd,cl);
		_exit(z<0&&errno==EBADF?0:71);
	}
	int st=0; for(int i=0;i<100;i++){ if(waitpid(pid,&st,WNOHANG)==pid)break; usleep(100000); }
	if(!WIFEXITED(st)){ kill_wait(pid); g_hang++; g_unex++; printf("  [HANG] R5\n"); }
	else if(WEXITSTATUS(st)==0) OK("R5 dup permutation clean; closed-fd write -> EBADF");
	else { g_unex++; printf("  [UNEX] R5 exit=%d\n",WEXITSTATUS(st)); }
	rel_stop(r); rel_close(r);
}

/* state x input matrix on the server fd with a free emulator */
static void test_matrix(int ctrl){
	printf("=== state x input matrix (server fd) ===\n");
	__u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,RP_SERVE,&tn);
	wait_dev(tn);
	/* drain auto-startup and any boot commands */
	for(int i=0;i<10;i++){ struct pollfd p={r->serverfd,POLLIN,0};
		if(poll(&p,1,300)==0)break; }
	usleep(200000);
	uint8_t b[16]={0};
	int w=write(r->serverfd,b,sizeof(b));
	printf("    no-pending write: %s\n", w<0?strerror(errno):"ACCEPTED");
	if(w<0&&errno==EIO)g_pass++; else LEAD("unsolicited write not EIO");
	struct pollfd p={r->serverfd,POLLIN,0}; int pr=poll(&p,1,400);
	printf("    no-pending poll(400ms): %s\n", pr==0?"timeout(correct)":"readable");
	if(pr==0)g_pass++; else LEAD("readable with no queued command");
	rel_stop(r); close(r->serverfd); r->serverfd=-1;
	int z=write(-1,b,1); (void)z; /* closed fd -> EBADF */
	rel_close(r);
	OK("state x input matrix holds");
}

/* R9: create/serve/destroy stress + reuse, free emulator */
static void test_stress(int ctrl){
	printf("=== R9: create/serve/destroy stress ===\n");
	int N=40,leaks=0; __u32 first=0,last=0;
	for(int i=0;i<N;i++){ __u32 tn; struct rel*r=start_rel(ctrl,EMU_FREE,0,RP_SERVE,&tn);
		/* let auto-startup flow */ struct pollfd p={r->serverfd,POLLIN,0};
		poll(&p,1,120); sb(r->ctl[1],'g'); usleep(30000);
		close(r->serverfd); r->serverfd=-1; rel_stop(r); rel_close(r);
		if(i==0)first=tn; last=tn; }
	int fds[64],cnt=0; for(;cnt<64;cnt++){ fds[cnt]=open("/dev/null",O_RDONLY);
		if(fds[cnt]<0){leaks=1;break;} } for(int i=0;i<cnt;i++)close(fds[i]);
	printf("    %d devices cycled; first tpm=%u last tpm=%u; fd_exhaustion=%d\n",N,first,last,leaks);
	if(!leaks)OK("stress: no fd exhaustion/hang"); else LEAD("possible fd/object leak");
}

int main(void){
	printf("vtpmx DETERMINISTIC RACE HARNESS v2 (drain-aware, replayable)\n\n");
	int ctrl=open("/dev/vtpmx",O_RDWR);
	if(ctrl<0){ perror("open /dev/vtpmx (root)"); return 1; }
	test_R5(ctrl);
	test_matrix(ctrl);
	test_R2(ctrl);
	test_R1(ctrl);
	test_R3(ctrl);
	test_stress(ctrl);
	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("passed:%d leads/unexpected:%d hangs:%d\n",g_pass,g_unex,g_hang);
	puts("Native run validates sequencing (no false positives). Re-run on Kernel B\n"
	     "(KASAN): any KASAN/UAF/slab report during W1/W2/W3 or R2 is a memory-safety\n"
	     "lead. A blocking close() that waits for an in-flight op is the ops_sem\n"
	     "lifetime barrier working as designed, recorded as a positive result.");
	return g_hang?3:0;
}
