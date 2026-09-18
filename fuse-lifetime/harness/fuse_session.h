/*
 * fuse_session.h - minimal direct-/dev/fuse session with an explicitly
 * schedulable userspace daemon (no libfuse).
 *
 * Two modes:
 *   AUTO  - daemon answers every request using the tiny lab filesystem
 *           (used by the smoke test).
 *   GATED - after INIT the daemon blocks until the director permits one
 *           read, then hands the captured request to the director and
 *           waits for it to reply/abort.  This gives deterministic control
 *           over the pending -> processing -> locked-copy transitions.
 */
#ifndef FUSE_SESSION_H
#define FUSE_SESSION_H

#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include "fuse_proto.h"

struct fuse_held {
    struct fuse_in_header h;
    unsigned char body[FUSE_READ_BUF];
    size_t total;          /* total bytes read including header */
    int ready;
};

struct fuse_sess {
    int fd;
    char mp[256];
    unsigned long conn_id;
    int gated;
    volatile int stop;
    volatile int init_done;

    pthread_t thr;
    pthread_mutex_t mtx;
    pthread_cond_t gate_cv;   /* daemon waits for read permission */
    int read_permit;
    pthread_cond_t held_cv;   /* director waits for a captured request */
    struct fuse_held held;

    /* stats */
    volatile unsigned long req_seen;
    volatile unsigned long interrupt_seen;
};

/* lifecycle */
int fuse_sess_open(struct fuse_sess *s, const char *mp, int gated);
int fuse_sess_mount(struct fuse_sess *s); /* starts daemon, mounts */
void fuse_sess_close(struct fuse_sess *s, int abort_first);

/* gated director API */
void fuse_permit_read(struct fuse_sess *s);
int  fuse_wait_held(struct fuse_sess *s, unsigned timeout_ms); /* returns opcode, -1 */
void fuse_release_held(struct fuse_sess *s);

/* raw reply helpers (write to /dev/fuse) */
ssize_t fuse_send(int fd, const void *buf, size_t len);
ssize_t fuse_reply_err(int fd, uint64_t unique, int err);
ssize_t fuse_reply(int fd, uint64_t unique, const void *arg, size_t argsize);

/* connection control */
unsigned long fuse_conn_scan(void);
int fuse_conn_abort_id(unsigned long id);
int fuse_conn_abort(struct fuse_sess *s);
int fuse_conn_waiting(unsigned long id);

/* tiny lab filesystem answer (used by AUTO daemon; exposed for reuse) */
void fuse_lab_answer(int fd, const struct fuse_in_header *h,
                     const unsigned char *body, size_t total);

/* answer non-target requests until target (or INTERRUPT) is held */
int fuse_drain_until(struct fuse_sess *s, uint32_t target, unsigned total_ms);

#endif
