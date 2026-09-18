/*
 * fuse_session.c - direct /dev/fuse session implementation.
 * See fuse_session.h.  Linux 6.8 wire protocol.
 */
#define _GNU_SOURCE
#include "fuse_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <linux/limits.h>

/* SIGUSR1 is used only to interrupt a blocked /dev/fuse read during abort */
static void fuse_noop_sig(int sig) { (void)sig; }
static void fuse_install_sig(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fuse_noop_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* no SA_RESTART: read returns EINTR */
    sigaction(SIGUSR1, &sa, NULL);
}

static int fuse_dbg(void) { static int v = -1; if (v < 0) v = getenv("FUSE_DEBUG") ? 1 : 0; return v; }
#define DBG(...) do { if (fuse_dbg()) fprintf(stderr, __VA_ARGS__); } while (0)

/* ---------------- low level wire ---------------- */

ssize_t fuse_send(int fd, const void *buf, size_t len)
{
    const char *p = buf; size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        off += n;
    }
    return (ssize_t)off;
}

ssize_t fuse_reply_err(int fd, uint64_t unique, int err)
{
    struct fuse_out_header oh;
    memset(&oh, 0, sizeof(oh));
    oh.len = sizeof(oh);
    oh.error = err;
    oh.unique = unique;
    return fuse_send(fd, &oh, sizeof(oh));
}

ssize_t fuse_reply(int fd, uint64_t unique, const void *arg, size_t argsize)
{
    struct fuse_out_header oh;
    memset(&oh, 0, sizeof(oh));
    oh.len = sizeof(oh) + (uint32_t)argsize;
    oh.error = 0;
    oh.unique = unique;
    if (arg && argsize) {
        struct iovec iov[2];
        iov[0].iov_base = &oh; iov[0].iov_len = sizeof(oh);
        iov[1].iov_base = (void *)arg; iov[1].iov_len = argsize;
        ssize_t total = 0, n;
        /* writev delivers header+payload as one message */
        n = writev(fd, iov, 2);
        if (n < 0) return n;
        total = n;
        return total;
    }
    return fuse_send(fd, &oh, sizeof(oh));
}

/* ---------------- tiny lab filesystem ---------------- */

static void fill_attr(struct fuse_attr *a, uint64_t ino, uint32_t mode, uint64_t size)
{
    memset(a, 0, sizeof(*a));
    a->ino = ino;
    a->size = size;
    a->blocks = 1;
    a->atime = a->mtime = a->ctime = 1700000000;
    a->mode = mode;
    a->nlink = S_ISDIR(mode) ? 2 : 1;
    a->uid = 0; a->gid = 0;
    a->blksize = 4096;
}

static const uint32_t MODE_DIR  = S_IFDIR | 0755;
static const uint32_t MODE_FILE = S_IFREG | 0444;

void fuse_lab_answer(int fd, const struct fuse_in_header *h,
                     const unsigned char *body, size_t total)
{
    const unsigned char *in = body + sizeof(struct fuse_in_header);
    size_t inlen = total - sizeof(struct fuse_in_header);

    switch (h->opcode) {
    case FUSE_INIT: {
        const struct fuse_init_in *ii = (const struct fuse_init_in *)in;
        struct fuse_init_out o;
        memset(&o, 0, sizeof(o));
        o.major = FUSE_KERNEL_VERSION;
        o.minor = ii->minor < FUSE_DAEMON_MINOR ? ii->minor : FUSE_DAEMON_MINOR;
        o.max_readahead = ii->max_readahead;
        o.flags = 0;                 /* negotiate no optional features */
        o.flags2 = 0;
        o.max_background = 16;
        o.congestion_threshold = 12;
        o.max_write = FUSE_MAX_WRITE;
        o.time_gran = 1;
        o.max_pages = 32;
        fuse_reply(fd, h->unique, &o, sizeof(o));
        break;
    }
    case FUSE_LOOKUP: {
        char name[256] = {0};
        size_t nl = inlen; if (nl >= sizeof(name)) nl = sizeof(name) - 1;
        memcpy(name, in, nl);
        struct fuse_entry_out e;
        memset(&e, 0, sizeof(e));
        if (strcmp(name, LAB_FILE_NAME) == 0) {
            e.nodeid = LAB_FILE_INO;
            e.generation = 1;
            e.entry_valid = e.attr_valid = 1;
            fill_attr(&e.attr, LAB_FILE_INO, MODE_FILE,
                      sizeof(LAB_FILE_DATA) - 1);
            fuse_reply(fd, h->unique, &e, sizeof(e));
        } else {
            fuse_reply_err(fd, h->unique, -ENOENT);
        }
        break;
    }
    case FUSE_GETATTR: {
        struct fuse_attr_out o;
        memset(&o, 0, sizeof(o));
        o.attr_valid = 1;
        if (h->nodeid == LAB_ROOT_INO)
            fill_attr(&o.attr, LAB_ROOT_INO, MODE_DIR, 0);
        else if (h->nodeid == LAB_FILE_INO)
            fill_attr(&o.attr, LAB_FILE_INO, MODE_FILE,
                      sizeof(LAB_FILE_DATA) - 1);
        else { fuse_reply_err(fd, h->unique, -ENOENT); break; }
        fuse_reply(fd, h->unique, &o, sizeof(o));
        break;
    }
    case FUSE_OPEN: {
        if (h->nodeid != LAB_FILE_INO) { fuse_reply_err(fd, h->unique, -ENOENT); break; }
        struct fuse_open_out o;
        memset(&o, 0, sizeof(o));
        o.fh = LAB_FILE_FH;
        fuse_reply(fd, h->unique, &o, sizeof(o));
        break;
    }
    case FUSE_READ: {
        /* READ reply is fuse_out_header followed directly by raw data;
         * the byte count is inferred from out header length (short read). */
        const struct fuse_read_in *ri = (const struct fuse_read_in *)in;
        size_t dlen = sizeof(LAB_FILE_DATA) - 1;
        uint64_t off = ri->offset;
        uint32_t want = ri->size;
        if (off >= dlen) { fuse_reply(fd, h->unique, "", 0); break; }
        size_t avail = dlen - off;
        size_t give = want < avail ? want : avail;
        ssize_t wr = fuse_reply(fd, h->unique, LAB_FILE_DATA + off, give);
        DBG("[lab] READ off=%lu want=%u give=%zu write=%zd\n",
            (unsigned long)off, want, give, wr);
        break;
    }
    case FUSE_RELEASE:
    case FUSE_FLUSH:
    case FUSE_SETATTR:
    case FUSE_DESTROY:
    case FUSE_BATCH_FORGET:
        fuse_reply_err(fd, h->unique, 0);
        break;
    case FUSE_FORGET:
        /* no reply for FORGET */
        break;
    default:
        fuse_reply_err(fd, h->unique, -ENOSYS);
        break;
    }
}

/* ---------------- daemon ---------------- */

static void *fuse_daemon(void *arg)
{
    struct fuse_sess *s = arg;
    static unsigned char buf[FUSE_READ_BUF];

    for (;;) {
        if (s->gated && s->init_done) {
            pthread_mutex_lock(&s->mtx);
            while (!s->read_permit && !s->stop)
                pthread_cond_wait(&s->gate_cv, &s->mtx);
            s->read_permit = 0;
            pthread_mutex_unlock(&s->mtx);
            if (s->stop) return NULL;
        }

        ssize_t n = read(s->fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (s->stop) return NULL;
            /* before mount(2) associates the fd with a connection, reads
             * return EPERM/EAGAIN; spin until connected. */
            if (errno == EPERM || errno == EAGAIN) { usleep(2000); continue; }
            /* after INIT, abort/umount tears the connection down */
            if (s->init_done && (errno == ENODEV || errno == ECONNABORTED)) {
                if (s->gated) {
                    pthread_mutex_lock(&s->mtx);
                    s->held.ready = -1;
                    pthread_cond_signal(&s->held_cv);
                    pthread_mutex_unlock(&s->mtx);
                }
                return NULL;
            }
            usleep(2000);
            continue;
        }
        if (n < (ssize_t)sizeof(struct fuse_in_header)) continue;

        struct fuse_in_header h;
        memcpy(&h, buf, sizeof(h));
        DBG("[daemon] n=%zd op=%u unique=%lu node=%lu\n",
            n, h.opcode, (unsigned long)h.unique, (unsigned long)h.nodeid);
        s->req_seen++;
        if (h.opcode == FUSE_INTERRUPT) s->interrupt_seen++;

        if (h.opcode == FUSE_INIT) {
            fuse_lab_answer(s->fd, &h, buf, n);
            s->init_done = 1;
            continue;
        }

        if (s->gated) {
            pthread_mutex_lock(&s->mtx);
            memcpy(s->held.body, buf, n);
            s->held.total = n;
            memcpy(&s->held.h, buf, sizeof(h));
            s->held.ready = 1;
            pthread_cond_signal(&s->held_cv);
            while (s->held.ready == 1 && !s->stop)
                pthread_cond_wait(&s->held_cv, &s->mtx);
            int do_stop = s->stop;
            pthread_mutex_unlock(&s->mtx);
            if (do_stop) return NULL;
            continue;
        }
        fuse_lab_answer(s->fd, &h, buf, n);
    }
}

/* ---------------- gated director helpers ---------------- */

/* Answer everything the gated daemon captures until `target` is held.
 * Non-target requests are served by the lab filesystem; the target (and any
 * INTERRUPT) is left held for the caller. Returns the held opcode, <0 on
 * timeout/error. */
int fuse_drain_until(struct fuse_sess *s, uint32_t target, unsigned total_ms)
{
    struct timespec end, now;
    clock_gettime(CLOCK_REALTIME, &end);
    end.tv_sec += total_ms / 1000;
    end.tv_nsec += (total_ms % 1000) * 1000000L;
    if (end.tv_nsec >= 1000000000L) { end.tv_sec++; end.tv_nsec -= 1000000000L; }
    for (;;) {
        fuse_permit_read(s);
        int op = fuse_wait_held(s, 3000);
        if (op < 0) return op;
        if (s->held.h.opcode == target || s->held.h.opcode == FUSE_INTERRUPT)
            return op;
        fuse_lab_answer(s->fd, &s->held.h, s->held.body, s->held.total);
        fuse_release_held(s);
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec > end.tv_sec ||
            (now.tv_sec == end.tv_sec && now.tv_nsec > end.tv_nsec))
            return -3;
    }
}

/* ---------------- lifecycle ---------------- */

int fuse_sess_open(struct fuse_sess *s, const char *mp, int gated)
{
    memset(s, 0, sizeof(*s));
    fuse_install_sig();
    s->fd = -1;
    s->gated = gated;
    snprintf(s->mp, sizeof(s->mp), "%s", mp);
    pthread_mutex_init(&s->mtx, NULL);
    pthread_cond_init(&s->gate_cv, NULL);
    pthread_cond_init(&s->held_cv, NULL);

    s->fd = open("/dev/fuse", O_RDWR);
    if (s->fd < 0) {
        fprintf(stderr, "open /dev/fuse: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int fuse_sess_mount(struct fuse_sess *s)
{
    mkdir(s->mp, 0755);
    if (pthread_create(&s->thr, NULL, fuse_daemon, s) != 0)
        return -1;

    char opts[256];
    snprintf(opts, sizeof(opts),
             "fd=%d,rootmode=40000,user_id=0,group_id=0", s->fd);
    int rc = mount("fuse-lifetime-lab", s->mp, "fuse",
                   MS_NOSUID | MS_NODEV, opts);
    DBG("[mount] fd=%d rc=%d errno=%d(%s) opts=%s\n",
        s->fd, rc, errno, rc ? strerror(errno) : "-", opts);
    if (rc != 0) {
        fprintf(stderr, "mount fuse at %s: %s\n", s->mp, strerror(errno));
        s->stop = 1;
        close(s->fd);
        return -1;
    }
    /* wait for INIT to be serviced */
    for (int i = 0; i < 200 && !s->init_done; i++) usleep(10000);
    s->conn_id = fuse_conn_scan();
    return s->init_done ? 0 : -1;
}

void fuse_permit_read(struct fuse_sess *s)
{
    pthread_mutex_lock(&s->mtx);
    s->read_permit = 1;
    pthread_cond_signal(&s->gate_cv);
    pthread_mutex_unlock(&s->mtx);
}

int fuse_wait_held(struct fuse_sess *s, unsigned timeout_ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&s->mtx);
    int rc = 0;
    while (!s->held.ready && !s->stop) {
        rc = pthread_cond_timedwait(&s->held_cv, &s->mtx, &ts);
        if (rc == ETIMEDOUT) break;
    }
    int opcode = -1, ready = s->held.ready;
    if (ready == 1) opcode = (int)s->held.h.opcode;
    pthread_mutex_unlock(&s->mtx);
    return ready == 1 ? opcode : (ready == -1 ? -2 : -1);
}

void fuse_release_held(struct fuse_sess *s)
{
    pthread_mutex_lock(&s->mtx);
    s->held.ready = 0;
    s->held.total = 0;
    pthread_cond_signal(&s->held_cv);
    pthread_mutex_unlock(&s->mtx);
}

void fuse_sess_close(struct fuse_sess *s, int abort_first)
{
    if (abort_first) {
        fuse_conn_abort(s);
    } else {
        s->stop = 1;
        pthread_mutex_lock(&s->mtx);
        s->read_permit = 1;
        pthread_cond_signal(&s->gate_cv);
        s->held.ready = -1;
        pthread_cond_signal(&s->held_cv);
        pthread_mutex_unlock(&s->mtx);

        umount2(s->mp, MNT_DETACH);   /* VFS teardown aborts outstanding reqs */

        if (s->thr) {
            pthread_kill(s->thr, SIGUSR1);
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 3;
            if (pthread_timedjoin_np(s->thr, NULL, &ts) == ETIMEDOUT)
                pthread_detach(s->thr);
            s->thr = 0;
        }
        if (s->fd >= 0) close(s->fd);
    }

    umount2(s->mp, MNT_DETACH);       /* idempotent; covers abort_first path */
    rmdir(s->mp);
    pthread_mutex_destroy(&s->mtx);
    pthread_cond_destroy(&s->gate_cv);
    pthread_cond_destroy(&s->held_cv);
}

/* ---------------- connection control via sysfs ---------------- */

unsigned long fuse_conn_scan(void)
{
    DIR *d = opendir("/sys/fs/fuse/connections");
    unsigned long best = 0;
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        char *end;
        unsigned long v = strtoul(de->d_name, &end, 10);
        if (*end == '\0' && v > best) best = v;
    }
    closedir(d);
    return best;
}

static int conn_write(unsigned long id, const char *file, const char *val)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/fs/fuse/connections/%lu/%s", id, file);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n >= 0 ? 0 : -1;
}

int fuse_conn_abort_id(unsigned long id)
{
    return conn_write(id, "abort", "1\n");
}

int fuse_conn_abort(struct fuse_sess *s)
{
    int sysr = -1;
    if (!s->conn_id) s->conn_id = fuse_conn_scan();
    if (s->conn_id) sysr = fuse_conn_abort_id(s->conn_id);

    /* Robust fallback (and primary path on a minimal initramfs where the
     * sysfs control files may be missing): releasing the LAST /dev/fuse fd
     * runs fuse_dev_release() -> fuse_abort_conn(), waking every pending and
     * processing request with ECONNABORTED.  First stop the daemon thread and
     * interrupt its blocked read so close() is the final reference put. */
    s->stop = 1;
    pthread_mutex_lock(&s->mtx);
    s->read_permit = 1;
    pthread_cond_signal(&s->gate_cv);
    s->held.ready = -1;
    pthread_cond_signal(&s->held_cv);
    pthread_mutex_unlock(&s->mtx);

    if (s->fd >= 0) {
        if (s->thr) {
            pthread_kill(s->thr, SIGUSR1);   /* EINTR the blocked read */
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 3;
            if (pthread_timedjoin_np(s->thr, NULL, &ts) == ETIMEDOUT)
                pthread_cancel(s->thr);
            s->thr = 0;
        }
        int fd = s->fd;
        s->fd = -1;
        close(fd);                           /* last fd -> fuse_abort_conn */
    }
    return sysr;
}

int fuse_conn_waiting(unsigned long id)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/fs/fuse/connections/%lu/waiting", id);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char b[32] = {0};
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    return n > 0 ? atoi(b) : -1;
}
