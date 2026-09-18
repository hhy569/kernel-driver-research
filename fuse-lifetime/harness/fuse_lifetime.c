/*
 * fuse_lifetime.c - deterministic FUSE request-lifetime interleavings.
 *
 * Drives /dev/fuse directly (no libfuse) with the gated daemon in
 * fuse_session.c.  Each scenario runs in a forked child with its own
 * private mount; output is machine readable:
 *
 *   TEST=FUSE CASE=<name> STATE=<...> GATE=<...> ACTION=<...> RESULT=<PASS|FAIL>
 *
 * Scenarios (ChatGPT FUSE Request Lifetime Study):
 *   L1 PENDING     x ABORT      request still in fiq->pending, daemon never read
 *   L2 PROCESSING  x ABORT      daemon read (FR_SENT/processing), held, then abort
 *   L3 INTERRUPT   x ORIGINAL COMPLETION
 *        I1 interrupt delivered before original reply
 *        I2 original reply before interrupt is consumed
 *
 * L4 (locked-copy x abort) is probabilistic and lives in a separate harness;
 * L5 (forget x interrupt) is the second-round combination test.
 *
 * Build: gcc -O2 -Wall -pthread -o fuse_lifetime fuse_lifetime.c fuse_session.c
 */
#define _GNU_SOURCE
#include "fuse_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>

/* ---------------- tiny test threads ---------------- */

struct targ {
    char path[300];
    int open_rc, open_errno;
    ssize_t read_rc;
    int read_errno;
    char buf[256];
};

static void *t_open(void *p)
{
    struct targ *t = p;
    int fd = open(t->path, O_RDONLY);
    t->open_rc = fd;
    t->open_errno = errno;
    return NULL;
}

static void *t_open_read(void *p)
{
    struct targ *t = p;
    int fd = open(t->path, O_RDONLY);
    t->open_rc = fd;
    t->open_errno = errno;
    if (fd < 0) return NULL;
    memset(t->buf, 0, sizeof(t->buf));
    ssize_t n = read(fd, t->buf, sizeof(t->buf) - 1);
    t->read_rc = n;
    t->read_errno = errno;
    close(fd);
    return NULL;
}

static int join_bounded(pthread_t th, unsigned ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    int rc = pthread_timedjoin_np(th, NULL, &ts);
    if (rc == ETIMEDOUT) { pthread_cancel(th); return -1; } /* hang */
    return 0;
}

/* drain_until is provided by fuse_session.c as fuse_drain_until */
#define drain_until(s, t, m) fuse_drain_until(s, t, m)

static void rep(const char *cs, const char *state, const char *gate,
                const char *action, int ok, const char *extra)
{
    printf("TEST=FUSE CASE=%s STATE=%s GATE=%s ACTION=%s RESULT=%s %s\n",
           cs, state, gate, action, ok ? "PASS" : "FAIL", extra ? extra : "");
    fflush(stdout);
}

static int teardown_errno(int e)
{
    /* STOP-3: these are protocol/teardown semantics, not memory bugs */
    return e == ECONNABORTED || e == ENOTCONN || e == EIO ||
           e == ENODEV || e == ENOENT || e == EINTR;
}

/* ---------------- L1: PENDING x ABORT ---------------- */

static int l1(const char *mp)
{
    struct fuse_sess s;
    if (fuse_sess_open(&s, mp, 1) != 0) return 2;
    if (fuse_sess_mount(&s) != 0) { fuse_sess_close(&s, 0); return 2; }

    struct targ t; memset(&t, 0, sizeof(t));
    snprintf(t.path, sizeof(t.path), "%s/%s", mp, LAB_FILE_NAME);
    pthread_t th; pthread_create(&th, NULL, t_open, &t);

    usleep(200000);                 /* request queued, daemon never read */
    int waiting = fuse_conn_waiting(s.conn_id);
    fuse_conn_abort(&s);
    int hung = join_bounded(th, 5000);

    int bounded = (hung == 0) && (t.open_rc < 0) && teardown_errno(t.open_errno);
    char extra[160];
    snprintf(extra, sizeof(extra),
             "waiting=%d open_errno=%d(%s) hung=%d",
             waiting, t.open_errno, t.open_rc < 0 ? strerror(t.open_errno) : "-", hung);
    rep("L1_PENDING_ABORT", "FR_PENDING", "G3-daemon-not-read", "ABORT",
        bounded, extra);

    fuse_sess_close(&s, 0);
    return bounded ? 0 : 1;
}

/* ---------------- L2: PROCESSING x ABORT ---------------- */

static int l2(const char *mp)
{
    struct fuse_sess s;
    if (fuse_sess_open(&s, mp, 1) != 0) return 2;
    if (fuse_sess_mount(&s) != 0) { fuse_sess_close(&s, 0); return 2; }

    struct targ t; memset(&t, 0, sizeof(t));
    snprintf(t.path, sizeof(t.path), "%s/%s", mp, LAB_FILE_NAME);
    pthread_t th; pthread_create(&th, NULL, t_open, &t);

    /* answer LOOKUP/GETATTR, hold OPEN in processing (FR_SENT) */
    int op = drain_until(&s, FUSE_OPEN, 5000);
    int reached = (op == FUSE_OPEN);
    usleep(100000);
    fuse_conn_abort(&s);
    fuse_release_held(&s);          /* let daemon observe the dead conn */
    int hung = join_bounded(th, 5000);

    int bounded = reached && (hung == 0) && (t.open_rc < 0) &&
                  teardown_errno(t.open_errno);
    char extra[160];
    snprintf(extra, sizeof(extra),
             "held_op=%d open_errno=%d(%s) hung=%d",
             op, t.open_errno, t.open_rc < 0 ? strerror(t.open_errno) : "-", hung);
    rep("L2_PROCESSING_ABORT", "FR_SENT/PROCESSING", "daemon-read-held",
        "ABORT", bounded, extra);

    fuse_sess_close(&s, 0);
    return bounded ? 0 : 1;
}

/* ---------------- L3: INTERRUPT x ORIGINAL COMPLETION ---------------- */

static int l3(const char *mp, int i2)
{
    const char *cs = i2 ? "L3_I2_REPLY_THEN_INTERRUPT"
                        : "L3_I1_INTERRUPT_THEN_REPLY";
    struct fuse_sess s;
    if (fuse_sess_open(&s, mp, 1) != 0) return 2;
    if (fuse_sess_mount(&s) != 0) { fuse_sess_close(&s, 0); return 2; }

    struct targ t; memset(&t, 0, sizeof(t));
    snprintf(t.path, sizeof(t.path), "%s/%s", mp, LAB_FILE_NAME);
    pthread_t th; pthread_create(&th, NULL, t_open_read, &t);

    /* hold the original READ request in processing */
    int op = drain_until(&s, FUSE_READ, 5000);
    int reached = (op == FUSE_READ);
    uint64_t orig = s.held.h.unique;
    size_t dlen = sizeof(LAB_FILE_DATA) - 1;

    /* interrupt the blocked reader: kernel queues FUSE_INTERRUPT */
    pthread_kill(th, SIGUSR1);
    usleep(150000);

    int saw_intr = 0, intr_target_ok = 0;
    uint64_t intr_unique = 0;

    if (!i2) {
        /* I1: consume INTERRUPT first, reply EAGAIN, then answer original */
        fuse_release_held(&s);           /* release the held READ slot */
        int iop = drain_until(&s, FUSE_INTERRUPT, 3000);
        if (iop == FUSE_INTERRUPT) {
            saw_intr = 1;
            intr_unique = s.held.h.unique;
            struct fuse_interrupt_in *ii =
                (struct fuse_interrupt_in *)(s.held.body +
                                             sizeof(struct fuse_in_header));
            intr_target_ok = (ii->unique == orig);
            /* EAGAIN: daemon cannot interrupt yet; kernel re-queues */
            fuse_reply_err(s.fd, intr_unique, -EAGAIN);
            fuse_release_held(&s);
        }
        /* now complete the original READ */
        ssize_t wr = fuse_reply(s.fd, orig, LAB_FILE_DATA, dlen);
        if (wr < 0) { /* original may already be gone */ }
        /* best-effort drain of a re-queued interrupt after completion */
        int x = drain_until(&s, FUSE_INTERRUPT, 500);
        if (x == FUSE_INTERRUPT) {
            fuse_reply_err(s.fd, s.held.h.unique, -ENOENT);
            fuse_release_held(&s);
        }
    } else {
        /* I2: complete original first, then consume/observe INTERRUPT */
        fuse_release_held(&s);
        ssize_t wr = fuse_reply(s.fd, orig, LAB_FILE_DATA, dlen);
        (void)wr;
        int x = drain_until(&s, FUSE_INTERRUPT, 800);
        if (x == FUSE_INTERRUPT) {
            saw_intr = 1;
            intr_unique = s.held.h.unique;
            struct fuse_interrupt_in *ii =
                (struct fuse_interrupt_in *)(s.held.body +
                                             sizeof(struct fuse_in_header));
            intr_target_ok = (ii->unique == orig);
            /* original already FINISHED: kernel returns ENOENT for this */
            fuse_reply_err(s.fd, intr_unique, 0);
            fuse_release_held(&s);
        }
        /* if no interrupt is delivered, the kernel correctly dropped it
         * after FINISHED (queue_interrupt removes intr_entry) - also valid */
    }

    int hung = join_bounded(th, 5000);
    int ok = reached && (hung == 0) && (t.read_rc == (ssize_t)dlen) &&
             memcmp(t.buf, LAB_FILE_DATA, dlen) == 0;
    char extra[220];
    snprintf(extra, sizeof(extra),
             "held_op=%d saw_interrupt=%d intr_target=%d read_rc=%zd hung=%d",
             op, saw_intr, intr_target_ok, t.read_rc, hung);
    rep(cs, i2 ? "FINISHED-before-INTR" : "FR_INTERRUPTED-then-FINISH",
        "signal-held-READ", i2 ? "REPLY_ORIGINAL->INTR" : "INTR(EAGAIN)->REPLY_ORIG",
        ok, extra);

    fuse_sess_close(&s, 0);
    return ok ? 0 : 1;
}

/* ---------------- driver ---------------- */

static void noop_handler(int sig) { (void)sig; }

struct case_def { const char *name; int kind; };

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = noop_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* no SA_RESTART */
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t all; sigemptyset(&all); sigaddset(&all, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &all, NULL);

    struct case_def cases[] = {
        {"L1", 1}, {"L2", 2}, {"L3-I1", 31}, {"L3-I2", 32},
    };
    int n = sizeof(cases) / sizeof(cases[0]);
    int reps = argc > 1 ? atoi(argv[1]) : 1;
    int pass = 0, fail = 0, env = 0, hang = 0;

    for (int rep = 0; rep < reps; rep++) {
      if (reps > 1) printf("==== deterministic repetition %d/%d ====\n", rep+1, reps);
      for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(40);
            char mp[128];
            snprintf(mp, sizeof(mp), "/tmp/fuse-lab-%s-%d-%d",
                     cases[i].name, rep, getpid());
            int rc = 2;
            switch (cases[i].kind) {
            case 1: rc = l1(mp); break;
            case 2: rc = l2(mp); break;
            case 31: rc = l3(mp, 0); break;
            case 32: rc = l3(mp, 1); break;
            }
            _exit(rc);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("TEST=FUSE CASE=%s rep=%d RESULT=HARNESS_HANG sig=%d\n",
                   cases[i].name, rep, WTERMSIG(status));
            hang++;
        } else {
            int rc = WEXITSTATUS(status);
            if (rc == 0) pass++;
            else if (rc == 2) env++;
            else fail++;
        }
      }
    }
    printf("pass=%d assertion_fail=%d env_skip=%d hang=%d\n",
           pass, fail, env, hang);
    printf("RESULT: %s\n", (fail == 0 && hang == 0 && env == 0) ? "PASS" :
           (env ? "ENV_ABORT" : "FAIL"));
    return (fail == 0 && hang == 0 && env == 0) ? 0 : (env ? 2 : 1);
}
