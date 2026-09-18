// SPDX-License-Identifier: GPL-2.0
/*
 * vtpmx_stress.c - R7: concurrent create / teardown / error-cleanup fuzzing.
 *
 * Device-pool model (fixes the "client never sees a live device" false-negative):
 *   - A pool of NSLOTS proxy devices is kept alive, each with its own emulator thread,
 *     so clients always have live /dev/tpmN and /dev/tpmrmN nodes to operate on.
 *   - A recycler thread continuously tears down a random slot (close serverfd ->
 *     delete_device -> tpm_chip_unregister) and immediately creates a fresh device in
 *     the same slot, so register / steady-state / unregister constantly churn while
 *     the rest of the pool stays live.
 *   - raw and RM clients hammer random live slots with O_NONBLOCK async
 *     write/poll/read/close and an lseek(ESPIPE) check; teardown deliberately races
 *     in-flight async_work and opens (randomized R1/R3/R4c/R10 across many threads).
 *
 * Fixed seed -> reproducible. Stock kernel asserts: no hang (SIGALRM watchdog),
 * fd count returns to baseline, no /dev/tpmN node leaks, lseek stays ESPIPE.
 * Benign errno (EBUSY raw single-open, ENOENT/EIO/ETIME/EPIPE during teardown) are
 * tallied, not treated as bugs. Memory safety is decided by KASAN dmesg in the guest.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

struct vtpm_nd { uint32_t flags, tpm_num, fd, major, minor; };
#define VTPMX_NEW_DEV _IOWR(0xa1, 0, struct vtpm_nd)
#define VTPMX_PATH "/dev/vtpmx"
#define NSLOTS 6

static volatile int g_stop = 0;
static unsigned long g_creates=0,g_teardowns=0,g_rawops=0,g_rmops=0,g_unexpected=0;
static unsigned long g_err[512];
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_seed = 0x1234;

struct slot { pthread_mutex_t m; int active; int serverfd; unsigned devnum; pthread_t emu; };
static struct slot g_slots[NSLOTS];

static void on_alarm(int sig){(void)sig;const char x[]="\n[HANG] global watchdog fired\n";write(2,x,sizeof(x)-1);_exit(97);}
static unsigned int rnd(unsigned int *s){return rand_r(s);}
static void tally(int e){ if (e>=0 && e<512) g_err[e]++; }

static void *emu_thread(void *arg) {
    int sfd=(int)(long)arg;
    uint8_t resp[10]={0x80,0x01,0,0,0,0x0a,0,0,0,0};
    for(;;){
        struct pollfd p={sfd,POLLIN,0};
        int pr=poll(&p,1,200);
        if(pr<0){ if(errno==EINTR) continue; break; }
        if(pr==0){ if(fcntl(sfd,F_GETFD)<0) break; continue; }
        if(p.revents&(POLLERR|POLLHUP|POLLNVAL)) break;
        if(!(p.revents&POLLIN)){ if(fcntl(sfd,F_GETFD)<0) break; continue; }
        uint8_t hdr[10]; ssize_t n=read(sfd,hdr,10);
        if(n<=0) break;
        if(n>=8){
            uint32_t len=((uint32_t)hdr[4]<<24)|((uint32_t)hdr[5]<<16)|((uint32_t)hdr[6]<<8)|hdr[7];
            if(len>10 && len<=4096){ uint32_t rem=len-10; uint8_t body[4096];
                while(rem){ struct pollfd q={sfd,POLLIN,0};
                    if(poll(&q,1,500)<=0 || (q.revents&(POLLERR|POLLHUP|POLLNVAL))) break;
                    ssize_t r=read(sfd,body,rem<4096?rem:4096);
                    if(r<=0) break; rem-=r; } }
        }
        if(write(sfd,resp,10)<=0) break;
    }
    return NULL;
}

static int node_exists(const char*p){struct stat st;return stat(p,&st)==0;}

/* create a fresh device into slot i; returns 0 on success */
static int create_into(int i, int ctrl) {
    struct vtpm_nd nd; memset(&nd,0,sizeof(nd)); nd.flags=1;
    if(ioctl(ctrl,VTPMX_NEW_DEV,&nd)<0){ tally(errno); return -1; }
    int sfd=(int)nd.fd;
    pthread_t et;
    if(pthread_create(&et,NULL,emu_thread,(void*)(long)sfd)!=0){ close(sfd); return -1; }
    char path[40]; snprintf(path,sizeof(path),"/dev/tpm%u",nd.tpm_num);
    int appeared=0;
    for(int w=0; w<300; w++){ if(node_exists(path)){appeared=1;break;} usleep(20000); } /* up to 6s */
    if(!appeared){ fprintf(stderr,"[warn] slot %d dev tpm%u node never appeared, rolling back\n",i,nd.tpm_num);
                   close(sfd); pthread_join(et,NULL); return -1; }
    pthread_mutex_lock(&g_slots[i].m);
    g_slots[i].active=1; g_slots[i].serverfd=sfd; g_slots[i].devnum=nd.tpm_num; g_slots[i].emu=et;
    pthread_mutex_unlock(&g_slots[i].m);
    pthread_mutex_lock(&g_mtx); g_creates++; pthread_mutex_unlock(&g_mtx);
    return 0;
}

static void teardown_slot(int i) {
    pthread_mutex_lock(&g_slots[i].m);
    if(!g_slots[i].active){ pthread_mutex_unlock(&g_slots[i].m); return; }
    int sfd=g_slots[i].serverfd; pthread_t et=g_slots[i].emu;
    g_slots[i].active=0; g_slots[i].serverfd=-1;
    pthread_mutex_unlock(&g_slots[i].m);
    close(sfd);
    pthread_join(et,NULL);
    pthread_mutex_lock(&g_mtx); g_teardowns++; pthread_mutex_unlock(&g_mtx);
}

static void *recycler_thread(void *arg) {
    int ctrl=open(VTPMX_PATH,O_RDWR);
    unsigned int s=g_seed+999;
    if(ctrl<0) return NULL;
    while(!g_stop){
        int i=rnd(&s)%NSLOTS;
        teardown_slot(i);
        if(g_stop) break;
        create_into(i,ctrl);
        usleep(30000 + rnd(&s)%250000);   /* churn a slot every ~30-280 ms */
    }
    close(ctrl);
    return NULL;
}

static void client_cycle(int use_rm, unsigned int *s) {
    int i=rnd(s)%NSLOTS;
    unsigned devnum;
    pthread_mutex_lock(&g_slots[i].m);
    if(!g_slots[i].active){ pthread_mutex_unlock(&g_slots[i].m); usleep(500); return; }
    devnum=g_slots[i].devnum;
    pthread_mutex_unlock(&g_slots[i].m);
    char path[40]; snprintf(path,sizeof(path),use_rm?"/dev/tpmrm%u":"/dev/tpm%u",devnum);
    int fd=open(path,O_RDWR|O_NONBLOCK);
    if(fd<0){ tally(errno); return; }
    uint8_t cmd[12]={0x80,0x01,0,0,0,12,0,0,0x01,0x44,0,0};
    long w=write(fd,cmd,sizeof(cmd));
    if(w==(long)sizeof(cmd)){ struct pollfd p={fd,POLLIN,0}; poll(&p,1,400); uint8_t r[64];
        ssize_t rr=read(fd,r,sizeof(r)); (void)rr; }
    else if(w<0) tally(errno);
    if((rnd(s)&7)==0){ if(lseek(fd,0,SEEK_SET)>=0 || errno!=ESPIPE) g_unexpected++; }
    close(fd);
    pthread_mutex_lock(&g_mtx);
    if(use_rm) g_rmops++; else g_rawops++;
    pthread_mutex_unlock(&g_mtx);
}
static void *raw_client(void*arg){int id=(int)(long)arg;unsigned int s=g_seed+101u+(unsigned)id*104729u;
    while(!g_stop){client_cycle(0,&s);usleep(rnd(&s)%600);}return NULL;}
static void *rm_client(void*arg){int id=(int)(long)arg;unsigned int s=g_seed+202u+(unsigned)id*131071u;
    while(!g_stop){client_cycle(1,&s);usleep(rnd(&s)%600);}return NULL;}

static int count_fds(void){int n=0;DIR*d=opendir("/proc/self/fd");if(!d)return -1;
    struct dirent*e;while((e=readdir(d)))if(e->d_name[0]!='.')n++;closedir(d);return n;}
static int count_tpm_nodes(void){int n=0;DIR*d=opendir("/dev");if(!d)return -1;struct dirent*e;
    while((e=readdir(d))){ if(!strncmp(e->d_name,"tpm",3)){
        char c=e->d_name[3]; if(c=='r') c=e->d_name[4]; if(isdigit((unsigned char)c)) n++; } }
    closedir(d);return n;}

int main(int argc,char**argv){
    int duration=(argc>1)?atoi(argv[1]):45;
    if(argc>2) g_seed=(unsigned)strtoul(argv[2],NULL,0);
    signal(SIGALRM,on_alarm); alarm(duration+180);

    if(!node_exists(VTPMX_PATH)){fprintf(stderr,"%s missing\n",VTPMX_PATH);return 2;}
    int fd_base=count_fds(), node_base=count_tpm_nodes();
    printf("vtpmx R7 concurrent create/teardown/cleanup stress (device-pool model)\n");
    printf("duration=%ds seed=0x%x slots=%d fd_baseline=%d tpm_nodes_baseline=%d\n",
           duration,g_seed,NSLOTS,fd_base,node_base);
    fflush(stdout);
    for(int i=0;i<NSLOTS;i++){ pthread_mutex_init(&g_slots[i].m,NULL); g_slots[i].active=0; g_slots[i].serverfd=-1; }

    int ctrl=open(VTPMX_PATH,O_RDWR);
    if(ctrl<0){perror("open vtpmx");return 2;}
    fprintf(stderr,"[stage] filling device pool (%d devices)...\n",NSLOTS);
    int filled=0;
    for(int i=0;i<NSLOTS;i++){ for(int tries=0; tries<5 && create_into(i,ctrl)!=0; tries++) usleep(100000);
                               if(g_slots[i].active){filled++; fprintf(stderr,"[stage] slot %d live (%d/%d)\n",i,filled,NSLOTS);} }
    close(ctrl);
    if(filled<2){ fprintf(stderr,"[abort] only %d devices came up (environment too starved)\n",filled);
                  for(int i=0;i<NSLOTS;i++) teardown_slot(i); return 2; }

    pthread_t rec,cl[4]; int nc=0;
    pthread_create(&rec,NULL,recycler_thread,NULL);
    pthread_create(&cl[nc++],NULL,raw_client,(void*)0L);
    pthread_create(&cl[nc++],NULL,raw_client,(void*)1L);
    pthread_create(&cl[nc++],NULL,rm_client,(void*)0L);
    pthread_create(&cl[nc++],NULL,rm_client,(void*)1L);

    struct timespec ts={.tv_sec=duration,.tv_nsec=0}; nanosleep(&ts,NULL);
    fprintf(stderr,"[stage] time window done, stopping clients...\n"); fflush(stderr);
    g_stop=1;
    pthread_join(rec,NULL);
    fprintf(stderr,"[stage] recycler joined, joining clients...\n"); fflush(stderr);
    for(int i=0;i<nc;i++) pthread_join(cl[i],NULL);
    fprintf(stderr,"[stage] tearing down pool...\n"); fflush(stderr);
    for(int i=0;i<NSLOTS;i++) teardown_slot(i);
    fprintf(stderr,"[stage] pool down, settling...\n"); fflush(stderr);
    usleep(1500000);

    int fd_after=count_fds(), node_after=count_tpm_nodes();
    printf("\n================ R7 STRESS SUMMARY ================\n");
    printf("creates=%lu teardowns=%lu raw_ops=%lu rm_ops=%lu\n",g_creates,g_teardowns,g_rawops,g_rmops);
    printf("fd: baseline=%d after=%d delta=%d\n",fd_base,fd_after,fd_after-fd_base);
    printf("tpm nodes: baseline=%d after=%d delta=%d\n",node_base,node_after,node_after-node_base);
    printf("unexpected (lseek!=ESPIPE) = %lu\n",g_unexpected);
    printf("benign errno histogram:\n");
    const char*nm[]={[EBUSY]="EBUSY",[ENOENT]="ENOENT",[EIO]="EIO",[ETIME]="ETIME",
                     [EPIPE]="EPIPE",[EINVAL]="EINVAL",[ENODEV]="ENODEV",[EACCES]="EACCES"};
    for(int i=1;i<512;i++) if(g_err[i])
        printf("  errno %d %-7s: %lu\n",i,(i<(int)(sizeof(nm)/sizeof(nm[0]))&&nm[i])?nm[i]:"?",g_err[i]);
    int fail=0;
    if(fd_after-fd_base>4){printf("[LEAD] fd leak delta=%d\n",fd_after-fd_base);fail=1;}
    if(node_after-node_base>0){printf("[LEAD] tpm nodes leaked=%d\n",node_after-node_base);fail=1;}
    if(g_unexpected){printf("[LEAD] invariant violations=%lu\n",g_unexpected);fail=1;}
    if(g_rawops+g_rmops<200){printf("[WARN] only %lu client ops (environment too slow?)\n",g_rawops+g_rmops);}
    printf(fail?"RESULT: FAIL (inspect dmesg/KASAN)\n"
               :"RESULT: PASS (no hang/fd leak/node leak; KASAN dmesg is the memory-safety authority)\n");
    printf("===================================================\n");
    return fail;
}
