// SPDX-License-Identifier: GPL-2.0
// vtpm2_emu.h - minimal *semantic* TPM2 userspace emulator for /dev/vtpmx harnesses.
//
// A bare 10-byte TPM_RC_SUCCESS on every command lets the raw /dev/tpmN node appear,
// but tpm2_auto_startup()->tpm2_get_cc_attrs_tbl() then reads TPM_PT_TOTAL_COMMANDS
// from an empty GetCapability response (property_cnt=0 -> -ENODATA) and sets
// TPM_CHIP_FLAG_FIRMWARE_UPGRADE; tpm-chip.c:426 then SKIPS tpm_devs_add(), so the
// /dev/tpmrmN resource-manager node is never created. This emulator answers the
// bootstrap command set (SelfTest + GetCapability[TPM_PROPERTIES/COMMANDS/PCRS]) with
// just enough well-formed body that the chip is registered HEALTHY and BOTH nodes
// appear. Response offsets follow the kernel's own parser (body starts at byte 10:
// body[0]=moreData u8, body[1..4]=capability u32, body[5..8]=count u32, body[9..]=
// payload). Everything else gets TPM_RC_SUCCESS.
//
// Teardown contract (proven clean by vtpmx_probe N6 and vtpmx_async R4c/R10):
//   FREE  normal : vrel_stop() (signal 's' + join emulator) THEN close(serverfd).
//   GATED running: with the emulator parked on the ctl gate (not touching serverfd),
//                  close(serverfd) first to cancel the in-flight op, drain the client,
//                  THEN vrel_stop(). Closing serverfd while the emulator is blocked in
//                  poll()/read() on it races and can hang; the ctl gate avoids that.
#ifndef VTPM2_EMU_H
#define VTPM2_EMU_H
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct vnd { __u32 flags, tpm_num, fd, major, minor; };
#define V_IOC_NEW_DEV _IOWR(0xa1, 0, struct vnd)
#define V_FLAG_TPM2   1
#define V_MODE_FREE   0
#define V_MODE_GATED  1

#define V_CC_GETCAP        0x17A
#define V_CAP_COMMANDS     2
#define V_CAP_PCRS         5
#define V_CAP_TPM_PROPS    6
#define V_PT_TOTAL_COMMANDS 0x129
#define V_NCMDS            4

static inline uint32_t v_rd32(const uint8_t *p){
	return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static inline void v_wr32(uint8_t *p, uint32_t v){
	p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
/* cc low-16 in bits 0..15; bit20 = TPMA_CC commandHandles for FLUSH_CONTEXT */
static const uint32_t v_cmd_attrs[V_NCMDS] =
	{ 0x00000143, 0x00000144, 0x0000017A, (1u<<20)|0x0165 };

/* Build a TPM2 response; returns response length. */
static int v_respond(const uint8_t *cmd, int n, uint8_t *rsp){
	memset(rsp, 0, 4096);
	rsp[0]=0x80; rsp[1]=0x01; v_wr32(rsp+6, 0);      /* NO_SESSIONS, RC=SUCCESS */
	if (n < 10){ v_wr32(rsp+2,10); return 10; }
	uint32_t cc = v_rd32(cmd+6);
	if (cc == V_CC_GETCAP && n >= 22){
		uint32_t cap = v_rd32(cmd+10), prop = v_rd32(cmd+14);
		if (cap == V_CAP_TPM_PROPS){
			v_wr32(rsp+2,27); rsp[10]=0; v_wr32(rsp+11,cap); v_wr32(rsp+15,1);
			v_wr32(rsp+19,prop);
			v_wr32(rsp+23,(prop==V_PT_TOTAL_COMMANDS)?V_NCMDS:0);
			return 27;
		} else if (cap == V_CAP_COMMANDS){
			int L = 10+9+4*V_NCMDS; v_wr32(rsp+2,L); rsp[10]=0;
			v_wr32(rsp+11,cap); v_wr32(rsp+15,V_NCMDS);
			for (int i=0;i<V_NCMDS;i++) v_wr32(rsp+19+4*i, v_cmd_attrs[i]);
			return L;
		} else { /* PCRS or any other capability: well-formed empty list */
			v_wr32(rsp+2,19); rsp[10]=0; v_wr32(rsp+11,cap); v_wr32(rsp+15,0);
			return 19;
		}
	}
	v_wr32(rsp+2,10); return 10; /* Startup / SelfTest / Shutdown / ... */
}

struct vrel {
	int serverfd, tpmnum, mode, drain;
	volatile int served;
	int ctl[2], obs[2];
	pthread_t th;
};
static inline void v_sb(int fd, char c){ if(write(fd,&c,1)<0){} }
static inline char v_rb(int fd, int ms){
	struct pollfd p={fd,POLLIN,0}; if(poll(&p,1,ms)<=0) return 0;
	char c=0; if(read(fd,&c,1)<=0) return 0; return c; }

static void *v_emu(void *a){
	struct vrel *r = a;
	uint8_t cmd[4096], rsp[4096];
	for(;;){
		struct pollfd pf[2] = {
			{ r->serverfd, POLLIN|POLLHUP|POLLERR, 0 },
			{ r->ctl[0],   POLLIN, 0 } };
		int pr = poll(pf, 2, 300);
		if (pr < 0){ if(errno==EINTR) continue; break; }
		if (pf[1].revents & POLLIN){ char c; if(read(r->ctl[0],&c,1)>0 && c=='s') break; }
		if (!(pf[0].revents & (POLLIN|POLLHUP|POLLERR))) continue;
		if (pf[0].revents & (POLLHUP|POLLERR)){ usleep(20000);
			if(fcntl(r->serverfd,F_GETFD)<0) break; continue; }
		int gate = (r->mode==V_MODE_GATED && r->served >= r->drain);
		if (gate){ v_sb(r->obs[1],'Q'); char g=v_rb(r->ctl[0],8000);
			if(g=='s' || fcntl(r->serverfd,F_GETFD)<0) break; }
		int nn = read(r->serverfd, cmd, sizeof(cmd));
		if (nn < 0){ if(errno==EBADF||errno==EPIPE) break; usleep(20000); continue; }
		if (gate){ v_sb(r->obs[1],'R'); char g=v_rb(r->ctl[0],8000);
			if(g=='s' || fcntl(r->serverfd,F_GETFD)<0) break; }
		int L = v_respond(cmd, nn, rsp);
		if (write(r->serverfd, rsp, L) < 0){}
		if (gate) v_sb(r->obs[1],'P');
		r->served++;
	}
	return NULL;
}

/* GATED callers pass drain=1000 to free-serve the whole auto-startup, wait for both
 * nodes, then set r->drain=r->served so the next (client) command is the first gated. */
static struct vrel *vrel_start(int ctrl, int mode, int drain, __u32 *tn){
	struct vnd s; memset(&s,0,sizeof(s)); s.flags=V_FLAG_TPM2;
	if(ioctl(ctrl,V_IOC_NEW_DEV,&s)<0) return NULL;
	struct vrel *r = calloc(1,sizeof(*r));
	r->serverfd=s.fd; r->tpmnum=s.tpm_num; r->mode=mode; r->drain=drain; r->served=0;
	pipe2(r->ctl,O_NONBLOCK); pipe2(r->obs,O_NONBLOCK);
	if(tn) *tn=s.tpm_num;
	pthread_create(&r->th,NULL,v_emu,r);
	return r;
}
static inline void vrel_gate(struct vrel *r,char c){ v_sb(r->ctl[1],c); }
static inline char vrel_anchor(struct vrel *r,int ms){ return v_rb(r->obs[0],ms); }
static inline void vrel_stop(struct vrel *r){ v_sb(r->ctl[1],'s'); pthread_join(r->th,NULL); }
static inline void vrel_close(struct vrel *r){
	if(r->serverfd>=0) close(r->serverfd);
	close(r->ctl[0]); close(r->ctl[1]); close(r->obs[0]); close(r->obs[1]); free(r); }
static inline void vrel_paths(__u32 tn,char *raw,size_t rl,char *rm,size_t ml){
	snprintf(raw,rl,"/dev/tpm%u",tn); snprintf(rm,ml,"/dev/tpmrm%u",tn); }
/* returns 1 if path appears within ms */
static inline int vwait(const char *p,int ms){
	for(int elapsed=0; elapsed<=ms; elapsed+=50){ if(access(p,F_OK)==0) return 1; usleep(50000);}
	return 0; }
static inline int vwait_gone(const char *p,int ms){
	for(int elapsed=0; elapsed<=ms; elapsed+=50){ if(access(p,F_OK)!=0) return 1; usleep(50000);}
	return 0; }
#endif
