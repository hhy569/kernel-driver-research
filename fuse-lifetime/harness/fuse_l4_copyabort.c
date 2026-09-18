/*
 * fuse_l4_copyabort.c - FUSE-L4: locked userspace-copy x connection abort.
 *
 * Research question (from the FUSE study):
 *   "Does every userspace-copy path preserve the FR_LOCKED lifetime
 *    invariant against connection abort?"
 *
 * While a READ reply is being copied out (do_write moves the request to
 * fpq->io and sets FR_LOCKED around copy_out_args / user-page copies),
 * another thread aborts the connection.  The kernel must NOT free a request
 * whose copy is in progress: abort_conn leaves FR_LOCKED requests on the io
 * list and finishes them only after unlock; fuse_dev_release WARN_ON()s if
 * the io list is non-empty at release.
 *
 * Honest scope: from pure userspace we cannot deterministically stop the CPU
 * inside copy_to_user().  We widen the window by replying ~1 MiB into a
 * freshly mmap'd, not-yet-faulted user buffer (each page takes a demand fault
 * while FR_LOCKED is held), and randomise the abort instant across many
 * private mounts.  This is a probabilistic window + (in the guest) KASAN; it
 * is NOT claimed as a deterministic copy interleaving.
 *
 * PASS criterion: every iteration's reader wakes bounded (data or a teardown
 * errno), no hang, and - in the KASAN guest - no KASAN/BUG/WARN/refcount/
 * list-corruption report.
 *
 * Build: gcc -O2 -Wall -pthread -o fuse_l4 fuse_l4_copyabort.c fuse_session.c
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
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>

#define BIGSZ (2u * 1024u * 1024u)

#define drain_until(s, t, m) fuse_drain_until(s, t, m)

struct bt {
    char path[300];
    char *map;
    size_t bsz;
    int fd;
    ssize_t rc;
    int err;
};

static void *t_bigread(void *p)
{
    struct bt *b = p;
    b->map = mmap(NULL, b->bsz, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    b->fd = open(b->path, O_RDONLY);
    b->err = errno;
    if (b->fd < 0) return NULL;
    b->rc = read(b->fd, b->map, b->bsz);
    b->err = errno;
    close(b->fd);
    return NULL;
}

struct abort_arg { struct fuse_sess *s; unsigned us; };
static void *aborter(void *p)
{
    struct abort_arg *a = p;
    usleep(a->us);
    fuse_conn_abort(a->s);
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
    if (rc == ETIMEDOUT) { pthread_cancel(th); return -1; }
    return 0;
}

static int teardown_errno(int e)
{
    return e == ECONNABORTED || e == ENOTCONN || e == EIO ||
           e == ENODEV || e == ENOENT || e == EINTR || e == EAGAIN;
}

static int l4_one(const char *mp, unsigned seed)
{
    srand(seed);
    struct fuse_sess s;
    if (fuse_sess_open(&s, mp, 1) != 0) return 2;
    if (fuse_sess_mount(&s) != 0) { fuse_sess_close(&s, 0); return 2; }

    struct bt b; memset(&b, 0, sizeof(b));
    b.bsz = BIGSZ;
    snprintf(b.path, sizeof(b.path), "%s/%s", mp, LAB_FILE_NAME);
    pthread_t th; pthread_create(&th, NULL, t_bigread, &b);

    int op = drain_until(&s, FUSE_READ, 6000);
    if (op != FUSE_READ) {
        fuse_sess_close(&s, 1);
        join_bounded(th, 3000);
        printf("TEST=FUSE CASE=L4_COPY_ABORT iter=%u RESULT=ENV no-read-held op=%d\n",
               seed, op);
        return 2;
    }
    const struct fuse_read_in *ri =
        (const struct fuse_read_in *)(s.held.body +
                                      sizeof(struct fuse_in_header));
    uint32_t want = ri->size;
    if (want > FUSE_MAX_WRITE) want = FUSE_MAX_WRITE;
    uint64_t orig = s.held.h.unique;

    size_t plen = sizeof(struct fuse_out_header) + want;
    struct fuse_out_header *pkt = malloc(plen);
    if (!pkt) { fuse_sess_close(&s, 1); return 2; }
    pkt->len = (uint32_t)plen;
    pkt->error = 0;
    pkt->unique = orig;
    memset((char *)pkt + sizeof(*pkt), 0x41, want);

    /* random abort instant: some before, some during the locked copy */
    struct abort_arg aa = { &s, (unsigned)(rand() % 2500) };
    pthread_t at; pthread_create(&at, NULL, aborter, &aa);

    fuse_release_held(&s);
    ssize_t wr = write(s.fd, pkt, plen);   /* enters FR_LOCKED copy region */
    pthread_join(at, NULL);
    free(pkt);

    int hung = join_bounded(th, 6000);
    int reader_ok = (hung == 0) &&
                    (b.rc >= 0 || (b.fd >= 0 && teardown_errno(b.err)) ||
                     b.fd < 0);
    int ok = reader_ok;
    printf("TEST=FUSE CASE=L4_COPY_ABORT iter=%u STATE=FR_LOCKED "
           "GATE=page-fault-window ACTION=ABORT@%uus RESULT=%s "
           "want=%u write=%zd read_rc=%zd read_errno=%d hung=%d\n",
           seed, aa.us, ok ? "PASS" : "FAIL", want, wr, b.rc, b.err, hung);

    fuse_sess_close(&s, 0);
    if (b.map && b.map != MAP_FAILED) munmap(b.map, b.bsz);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    int iters = argc > 1 ? atoi(argv[1]) : 100;
    int pass = 0, fail = 0, env = 0, hang = 0;
    for (int i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(25);
            char mp[128];
            snprintf(mp, sizeof(mp), "/tmp/fuse-lab-L4-%d", getpid());
            _exit(l4_one(mp, 0x9000 + i));
        }
        int st = 0; waitpid(pid, &st, 0);
        if (WIFSIGNALED(st)) {
            printf("TEST=FUSE CASE=L4_COPY_ABORT iter=%d RESULT=HARNESS_HANG sig=%d\n",
                   i, WTERMSIG(st));
            hang++;
        } else {
            int rc = WEXITSTATUS(st);
            if (rc == 0) pass++;
            else if (rc == 2) env++;
            else fail++;
        }
    }
    printf("pass=%d assertion_fail=%d env_skip=%d hang=%d\n",
           pass, fail, env, hang);
    printf("RESULT: %s\n", (fail == 0 && hang == 0 && env == 0) ? "PASS"
           : (env && !fail && !hang ? "ENV_ABORT" : "FAIL"));
    return (fail == 0 && hang == 0 && env == 0) ? 0 : (env && !fail && !hang) ? 2 : 1;
}
