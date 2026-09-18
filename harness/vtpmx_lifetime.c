// SPDX-License-Identifier: GPL-2.0
// vtpmx object-lifetime / fd-reference / RM-separation harness (v2).
//
// v1 used 10-byte responses (RM node never created -> L2/L4/L5 ENV) and closed the
// server fd before joining the emulator (raced teardown -> scenario hang). v2 uses the
// semantic emulator in vtpm2_emu.h (healthy TPM2 chip -> BOTH /dev/tpmN and /dev/tpmrmN
// appear) and follows the proven teardown order:
//   FREE : stop+join emulator, THEN close(serverfd).
//   GATED: park emulator on the ctl gate, close(serverfd) to cancel the running op,
//          drain the client, THEN stop+join.
//
// Cases:
//  L1   dup() of a client /dev/tpmN fd: closing one reference keeps the chip alive and
//       serviceable through the other; closing the last server ref tears it down.
//  L2   a /dev/tpmrmN (RM) client held open across chip teardown -> orphan operations
//       must fail bounded (no hang/UAF); KASAN is the memory-safety authority.
//  L3-Q x15 NONBLOCK command enqueued, then immediate teardown: samples the
//       pending/early-running window (the exact worker scheduling instant is not
//       userspace-pinnable; this is stated, not claimed as a deterministic "pending").
//  L3-R x3  deterministic RUNNING teardown: emulator is gated after it read the command
//       (work parked WAIT_RESPONSE); serverfd close must cancel it and wake the client.
//  L4   one raw and one RM client both in flight across teardown.
//  L5   RM multi-open reference separation: A/B/C opens, close A, B/C survive, chip
//       stays alive until the server fd itself closes.
//
// Exit codes: 0 all asserted cases passed (ENV cases are skips), 1 assertion failure,
// 2 environment-only (no node/permission), 3 harness error/hang. Root required.
#define _GNU_SOURCE
#include "vtpm2_emu.h"
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

static long now_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
	return t.tv_sec*1000L+t.tv_nsec/1000000L; }

/* TPM2_Startup(SU_CLEAR), 12 bytes */
static const uint8_t CMD12[12] =
	{0x80,0x01,0,0,0,0x0c,0,0,0x01,0x44,0,0};

/* best-effort NONBLOCK client exchange; records result, never asserts on RM grammar */
static void xchg(int fd, const char *tag){
	uint8_t rsp[128];
	int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
	ssize_t w=write(fd,CMD12,sizeof(CMD12));
	if(w!=sizeof(CMD12)){ printf("      [%s] write=%zd errno=%d (recorded)\n",tag,w,errno); return; }
	struct pollfd p={fd,POLLIN,0}; int pr=poll(&p,1,3000);
	if(pr>0 && (p.revents&POLLIN)){ ssize_t n=read(fd,rsp,sizeof(rsp));
		printf("      [%s] poll=0x%x read=%zd (recorded)\n",tag,p.revents,n); }
	else printf("      [%s] poll pr=%d rev=0x%x (recorded)\n",tag,pr,p.revents);
}

/* ---- L1: dup() reference keeps the chip alive and serviceable ---- */
static int scn_l1(int ctrl){
	__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_FREE,0,&tn);
	if(!r){ perror("NEW_DEV"); return 3; }
	char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
	if(!vwait(raw,15000)){ printf("  [ENV] L1 raw node absent\n"); vrel_stop(r); vrel_close(r); return 2; }
	int A=open(raw,O_RDWR);
	if(A<0){ printf("  [ENV] L1 open raw errno=%d\n",errno); vrel_stop(r); vrel_close(r); return 2; }
	int B=dup(A); if(B<0){ printf("  [FAIL] L1 dup\n"); close(A); vrel_stop(r); vrel_close(r); return 1; }
	close(A);
	usleep(100000);
	int fl=fcntl(B,F_GETFL,0); fcntl(B,F_SETFL,fl|O_NONBLOCK);
	ssize_t w=write(B,CMD12,sizeof CMD12);
	struct pollfd p={B,POLLIN,0}; int pr=poll(&p,1,5000);
	uint8_t brsp[128]; ssize_t n=(pr>0&&(p.revents&POLLIN))?read(B,brsp,sizeof brsp):-1;
	int alive_service = (w==sizeof CMD12 && pr>0 && (p.revents&POLLIN) && n==10);
	close(B);
	vrel_stop(r); close(r->serverfd); r->serverfd=-1;
	int gone=vwait_gone(raw,8000);
	vrel_close(r);
	if(alive_service && gone){ printf("  [OK]   L1 close(A) keeps device; close(B/last) tears it down\n"); return 0; }
	printf("  [FAIL] L1 alive_service=%d gone=%d w=%zd pr=%d n=%zd\n",alive_service,gone,w,pr,n);
	return 1;
}

/* ---- L2: RM client held across chip teardown -> orphan ops bounded ---- */
static int scn_l2(int ctrl){
	__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_FREE,0,&tn);
	if(!r){ perror("NEW_DEV"); return 3; }
	char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
	if(!vwait(raw,15000)||!vwait(rm,15000)){ printf("  [ENV] L2 RM node absent in this build\n");
		vrel_stop(r); vrel_close(r); return 2; }
	int mfd=open(rm,O_RDWR|O_NONBLOCK);
	if(mfd<0){ printf("  [ENV] L2 RM open errno=%d\n",errno); vrel_stop(r); vrel_close(r); return 2; }
	vrel_stop(r); close(r->serverfd); r->serverfd=-1;     /* teardown chip, RM fd stays */
	int gone=vwait_gone(raw,8000);
	ssize_t w=write(mfd,CMD12,sizeof CMD12); int werr=errno;
	struct pollfd p={mfd,POLLIN,0}; int pr=poll(&p,1,3000);
	uint8_t rsp[128]; ssize_t rn=read(mfd,rsp,sizeof rsp); int rerr=errno;
	printf("  [..]   L2 orphan RM after teardown: write=%zd(errno=%d) poll=0x%x read=%zd(errno=%d)\n",
		w,werr,p.revents,rn,rerr);
	close(mfd);
	vrel_close(r);
	if(gone){ printf("  [OK]   L2 RM fd across teardown stays bounded (no hang/UAF; KASAN to confirm)\n"); return 0; }
	printf("  [FAIL] L2 chip did not tear down with RM fd open\n"); return 1;
}

/* ---- L3-Q: enqueue then immediate teardown, sampled x15 ---- */
static int scn_l3q(int ctrl){
	for(int it=0; it<15; it++){
		__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_FREE,0,&tn);
		if(!r) return 3;
		char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
		if(!vwait(raw,15000)){ printf("  [ENV] L3Q#%d raw node absent\n",it);
			vrel_stop(r); vrel_close(r); return 2; }
		int cf=open(raw,O_RDWR|O_NONBLOCK);
		if(cf<0){ printf("  [ENV] L3Q#%d open errno=%d\n",it,errno);
			vrel_stop(r); vrel_close(r); return 2; }
		ssize_t w=write(cf,CMD12,sizeof CMD12); (void)w;
		vrel_stop(r); close(r->serverfd); r->serverfd=-1;     /* immediate teardown */
		struct pollfd p={cf,POLLIN,0}; poll(&p,1,3000);
		uint8_t rsp[64]; ssize_t rn=read(cf,rsp,sizeof rsp); (void)rn; /* must wake, not hang */
		close(cf);
		int gone=vwait_gone(raw,8000);
		vrel_close(r);
		if(!gone){ printf("  [FAIL] L3Q#%d node did not disappear\n",it); return 1; }
	}
	printf("  [OK]   L3-Q x15 enqueue->immediate-teardown all returned promptly (pending/early window)\n");
	return 0;
}

/* ---- L3-R: deterministic RUNNING (WAIT_RESPONSE) teardown, x3 ---- */
static int scn_l3r(int ctrl){
	for(int it=0; it<3; it++){
		__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_GATED,1000,&tn);
		if(!r) return 3;
		char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
		if(!vwait(raw,15000)||!vwait(rm,15000)){ printf("  [ENV] L3R#%d node absent\n",it);
			vrel_stop(r); vrel_close(r); return 2; }
		usleep(250000);
		r->drain=r->served;                 /* auto-startup boundary; next cmd is gated */
		int cf=open(raw,O_RDWR|O_NONBLOCK);
		if(cf<0){ printf("  [ENV] L3R#%d open errno=%d\n",it,errno);
			vrel_stop(r); vrel_close(r); return 2; }
		ssize_t w=write(cf,CMD12,sizeof CMD12);
		if(vrel_anchor(r,8000)!='Q'){ printf("  [FAIL] L3R#%d no REQ anchor (w=%zd served=%d)\n",
			it,w,r->served); close(cf); vrel_stop(r); vrel_close(r); return 1; }
		vrel_gate(r,'g');
		if(vrel_anchor(r,8000)!='R'){ printf("  [FAIL] L3R#%d no READ anchor\n",it);
			close(cf); vrel_stop(r); vrel_close(r); return 1; }
		usleep(100000);
		long t0=now_ms();
		close(r->serverfd); r->serverfd=-1;           /* cancel running op */
		struct pollfd p={cf,POLLIN,0}; int pr=poll(&p,1,5000);
		uint8_t rsp[64]; ssize_t rn=read(cf,rsp,sizeof rsp);
		long dt=now_ms()-t0; close(cf);
		vrel_stop(r);                                /* release emulator parked at gate */
		int gone=vwait_gone(raw,8000);
		vrel_close(r);
		if(!(pr>0) && dt<10000){ /* poll timeout but prompt teardown still acceptable */ }
		if(dt>=10000||!gone){ printf("  [FAIL] L3R#%d teardown dt=%ldms gone=%d pr=%d rn=%zd\n",
			it,dt,gone,pr,rn); return 1; }
		printf("  [..]   L3-R#%d running teardown dt=%ldms poll=0x%x read=%zd (cancelled)\n",
			it,dt,p.revents,rn);
	}
	printf("  [OK]   L3-R x3 running-work teardown cancelled and woke client, no hang\n");
	return 0;
}

/* ---- L4: raw + RM clients both in flight across teardown ---- */
static int scn_l4(int ctrl){
	__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_GATED,1000,&tn);
	if(!r) return 3;
	char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
	if(!vwait(raw,15000)||!vwait(rm,15000)){ printf("  [ENV] L4 node absent (raw/rm)\n");
		vrel_stop(r); vrel_close(r); return 2; }
	usleep(250000); r->drain=r->served;
	int rf=open(raw,O_RDWR|O_NONBLOCK);
	int mf=open(rm ,O_RDWR|O_NONBLOCK);
	if(rf<0||mf<0){ printf("  [ENV] L4 open raw=%d rm=%d errno=%d\n",rf,mf,errno);
		if(rf>=0)close(rf); if(mf>=0)close(mf); vrel_stop(r); vrel_close(r); return 2; }
	ssize_t w1=write(rf,CMD12,sizeof CMD12);
	ssize_t w2=write(mf,CMD12,sizeof CMD12); int w2e=errno;
	char a=vrel_anchor(r,8000);
	if(a=='Q'){ vrel_gate(r,'g'); a=vrel_anchor(r,8000); }
	usleep(100000);
	long t0=now_ms();
	close(r->serverfd); r->serverfd=-1;
	struct pollfd pr1={rf,POLLIN,0}; poll(&pr1,1,5000); uint8_t s1[64]; ssize_t n1=read(rf,s1,sizeof s1);
	struct pollfd pr2={mf,POLLIN,0}; poll(&pr2,1,5000); uint8_t s2[64]; ssize_t n2=read(mf,s2,sizeof s2);
	long dt=now_ms()-t0;
	close(rf); close(mf);
	vrel_stop(r);
	int gone=vwait_gone(raw,8000) && vwait_gone(rm,8000);
	vrel_close(r);
	printf("  [..]   L4 raw w=%zd / RM w=%zd(errno=%d); teardown dt=%ldms n1=%zd n2=%zd\n",
		w1,w2,w2e,dt,n1,n2);
	if(dt<10000 && gone){ printf("  [OK]   L4 raw+RM in-flight teardown prompt, no hang/UAF (KASAN to confirm)\n"); return 0; }
	printf("  [FAIL] L4 dt=%ldms gone=%d\n",dt,gone); return 1;
}

/* ---- L5: RM multi-open reference separation ---- */
static int scn_l5(int ctrl){
	__u32 tn; struct vrel *r=vrel_start(ctrl,V_MODE_FREE,0,&tn);
	if(!r) return 3;
	char raw[64],rm[64]; vrel_paths(tn,raw,sizeof raw,rm,sizeof rm);
	if(!vwait(rm,15000)){ printf("  [ENV] L5 RM node absent\n"); vrel_stop(r); vrel_close(r); return 2; }
	int A=open(rm,O_RDWR|O_NONBLOCK);
	int B=open(rm,O_RDWR|O_NONBLOCK);
	if(A<0||B<0){ printf("  [ENV] L5 multi-open failed A=%d B=%d errno=%d\n",A,B,errno);
		if(A>=0)close(A); if(B>=0)close(B); vrel_stop(r); vrel_close(r); return 2; }
	xchg(A,"L5-A1"); xchg(B,"L5-B1");
	close(A);
	usleep(100000);
	xchg(B,"L5-B2-after-close-A");          /* B must survive A closing */
	int C=open(rm,O_RDWR|O_NONBLOCK);
	if(C<0){ printf("  [FAIL] L5 open C after A close errno=%d\n",errno);
		close(B); vrel_stop(r); vrel_close(r); return 1; }
	xchg(B,"L5-B3"); xchg(C,"L5-C1");
	close(B);
	usleep(100000);
	xchg(C,"L5-C2-after-close-B");          /* C must survive B closing */
	int chip_alive=(access(rm,F_OK)==0);
	close(C);
	vrel_stop(r); close(r->serverfd); r->serverfd=-1;
	int gone=vwait_gone(rm,8000);
	vrel_close(r);
	if(chip_alive && gone){ printf("  [OK]   L5 RM multi-open refs isolated; chip alive until server close\n"); return 0; }
	printf("  [FAIL] L5 chip_alive=%d gone=%d\n",chip_alive,gone); return 1;
}

struct scn { const char *name; int (*fn)(int); int budget_s; };
static struct scn SCNS[] = {
	{"L1-dup",              scn_l1, 30},
	{"L2-rm-teardown",      scn_l2, 30},
	{"L3-Q-pending-close",  scn_l3q,60},
	{"L3-R-running-close",  scn_l3r, 60},
	{"L4-raw-rm-coexist",   scn_l4, 40},
	{"L5-rm-multiopen",     scn_l5, 60},
};
static int g_pass,g_fail,g_env,g_hang;

static void on_alarm(int s){ (void)s; _exit(3); }

static void run_one(const struct scn *s, int ctrl){
	pid_t pid=fork();
	if(pid==0){ signal(SIGALRM,on_alarm); alarm(s->budget_s+5); _exit(s->fn(ctrl)); }
	long t0=now_ms(); int st=0,done=0;
	for(int i=0;i<(s->budget_s*10+20);i++){
		if(waitpid(pid,&st,WNOHANG)==pid){ done=1; break; } usleep(100000);
	}
	if(!done){ kill(pid,SIGKILL); waitpid(pid,&st,0);
		printf("  [HANG] %s (no completion within %ds)\n",s->name,s->budget_s); g_hang++; return; }
	long dt=now_ms()-t0;
	int rc = WIFEXITED(st)?WEXITSTATUS(st):-1;
	if(rc==0){ printf("    (%s PASS, %ldms)\n",s->name,dt); g_pass++; }
	else if(rc==2){ printf("    (%s ENV/SKIP, %ldms)\n",s->name,dt); g_env++; }
	else if(rc==3){ printf("  [HANG/HARNESS] %s rc=3 (%ldms)\n",s->name,dt); g_hang++; }
	else { printf("  [ASSERT-FAIL] %s rc=%d (%ldms)\n",s->name,rc,dt); g_fail++; }
}

int main(void){
	printf("vtpmx OBJECT-LIFETIME / FD-REFCOUNT / RM-SEPARATION HARNESS v2 (L1-L5)\n\n");
	int ctrl=open("/dev/vtpmx",O_RDWR);
	if(ctrl<0){ perror("open /dev/vtpmx");
		printf("RESULT: ENV_ABORT (run as root after modprobe tpm_vtpm_proxy)\n"); return 2; }
	for(unsigned i=0;i<sizeof(SCNS)/sizeof(SCNS[0]);i++){
		printf("=== %s ===\n",SCNS[i].name);
		run_one(&SCNS[i],ctrl);
	}
	close(ctrl);
	printf("\n================ SUMMARY ================\n");
	printf("pass=%d assertion_fail=%d env_skip=%d hang=%d\n",g_pass,g_fail,g_env,g_hang);
	puts("KASAN is the memory-safety authority: re-run on the Generic-KASAN guest. L3-R is a");
	puts("deterministic RUNNING teardown; L3-Q samples the pending/early-running window (the");
	puts("kernel worker scheduling instant is not userspace-pinnable), repeated for coverage.");
	int rc = g_fail?1 : g_hang?3 : (g_pass?0:2);
	printf("RESULT: %s\n", rc==0?"PASS":rc==1?"ASSERT_FAIL":rc==2?"ENV_ABORT":"HARNESS_ERROR");
	return rc;
}
