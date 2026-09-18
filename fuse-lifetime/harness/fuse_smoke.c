/*
 * fuse_smoke.c - prove the direct-/dev/fuse minimal session works.
 * AUTO daemon; stat/open/read the lab trigger file; clean umount.
 * Build: gcc -O2 -Wall -o fuse_smoke fuse_smoke.c fuse_session.c -lpthread
 */
#define _GNU_SOURCE
#include "fuse_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [OK]   %s\n", msg); } \
    else { printf("  [FAIL] %s\n", msg); fails++; } } while (0)

int main(void)
{
    struct fuse_sess s;
    char mp[128];
    snprintf(mp, sizeof(mp), "/tmp/fuse-lab-smoke-%d", getpid());

    printf("SMOUNT open /dev/fuse + mount AUTO at %s\n", mp);
    if (fuse_sess_open(&s, mp, 0) != 0) { printf("ENV_ABORT open\n"); return 2; }
    if (fuse_sess_mount(&s) != 0) { printf("ENV_ABORT mount/init\n"); return 2; }
    printf("  conn_id=%lu init_done=%d\n", s.conn_id, s.init_done);

    char path[200];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", mp, LAB_FILE_NAME);

    int r = stat(path, &st);
    CHECK(r == 0 && S_ISREG(st.st_mode), "LOOKUP+GETATTR trigger -> regular file");
    if (r == 0)
        printf("         size=%ld mode=%o ino=%lu\n", (long)st.st_size,
               st.st_mode & 07777, (unsigned long)st.st_ino);

    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "OPEN trigger");

    char buf[256] = {0};
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
    if (n < 0) printf("         read errno=%d(%s)\n", errno, strerror(errno));
    else printf("         n=%zd buf0=%02x\n", n, (unsigned char)buf[0]);
    CHECK(n == (ssize_t)sizeof(LAB_FILE_DATA) - 1 &&
          strcmp(buf, LAB_FILE_DATA) == 0, "READ returns lab payload");
    if (n > 0) printf("         data=%s", buf);
    if (fd >= 0) close(fd);

    /* negative lookup must cleanly ENOENT, not crash */
    snprintf(path, sizeof(path), "%s/nope-%d", mp, getpid());
    r = stat(path, &st);
    CHECK(r < 0 && errno == ENOENT, "negative LOOKUP -> ENOENT");

    fuse_sess_close(&s, 0);
    printf("  req_seen=%lu\n", s.req_seen);

    if (fails) { printf("RESULT: FAIL fails=%d\n", fails); return 1; }
    printf("RESULT: PASS\n");
    return 0;
}
