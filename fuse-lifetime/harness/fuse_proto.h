/*
 * fuse_proto.h - minimal, self-contained FUSE wire protocol definitions.
 *
 * Extracted (only what the lifetime harness needs) from Linux uapi
 * include/uapi/linux/fuse.h (Linux 6.8).  Structures are byte-packed because
 * the FUSE channel is a serialized wire format; this matches the kernel's
 * natural layout for these all-fixed-width records.
 *
 * No libfuse: the harness drives /dev/fuse directly so that request
 * scheduling (pending / processing / interrupt / locked-copy) stays under
 * explicit test control.
 */
#ifndef FUSE_PROTO_H
#define FUSE_PROTO_H

#include <stdint.h>

#define FUSE_KERNEL_VERSION 7
#define FUSE_DAEMON_MINOR   31   /* negotiate no higher than 7.31 */

#define FUSE_MAX_WRITE      (1024u * 1024u)   /* kernel cap FUSE_MAX_MAXWRITE */
#define FUSE_MAX_READ       (1024u * 1024u)
#define FUSE_READ_BUF       (FUSE_MIN_READ_BUFFER + FUSE_MAX_WRITE)
#define FUSE_MIN_READ_BUFFER 8192

/* opcodes used by this harness */
enum {
    FUSE_LOOKUP      = 1,
    FUSE_FORGET      = 2,   /* no reply */
    FUSE_GETATTR     = 3,
    FUSE_SETATTR     = 4,
    FUSE_READLINK    = 5,
    FUSE_OPEN        = 14,
    FUSE_READ        = 15,
    FUSE_WRITE       = 16,
    FUSE_RELEASE     = 18,
    FUSE_FLUSH       = 25,
    FUSE_INIT        = 26,
    FUSE_INTERRUPT   = 36,
    FUSE_DESTROY     = 38,
    FUSE_BATCH_FORGET = 42,
};

#define FUSE_INT_REQ_BIT (1ULL << 63)

#pragma pack(push, 1)

struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint16_t total_extlen;
    uint16_t padding;
};

struct fuse_out_header {
    uint32_t len;
    int32_t  error;
    uint64_t unique;
};

struct fuse_init_in {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint32_t flags2;
    uint32_t unused[11];
};

struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t unused[7];
};

struct fuse_attr {
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t blksize;
    uint32_t flags;
};

struct fuse_entry_out {
    uint64_t nodeid;
    uint64_t generation;
    uint64_t entry_valid;
    uint64_t attr_valid;
    uint32_t entry_valid_nsec;
    uint32_t attr_valid_nsec;
    struct fuse_attr attr;
};

struct fuse_attr_out {
    uint64_t attr_valid;
    uint32_t attr_valid_nsec;
    uint32_t dummy;
    struct fuse_attr attr;
};

struct fuse_open_in {
    uint32_t flags;
    uint32_t open_flags;
};

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    uint32_t padding;
};

struct fuse_read_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_write_out {
    uint32_t size;
    uint32_t padding;
};

struct fuse_release_in {
    uint64_t fh;
    uint32_t flags;
    uint32_t release_flags;
    uint64_t lock_owner;
};

struct fuse_interrupt_in {
    uint64_t unique;
};

struct fuse_forget_in {
    uint64_t nlookup;
};

#pragma pack(pop)

/* fixed inode layout of the tiny lab filesystem */
#define LAB_ROOT_INO    1ULL
#define LAB_FILE_INO    2ULL
#define LAB_FILE_FH     2ULL
#define LAB_FILE_NAME   "trigger"
static const char LAB_FILE_DATA[] = "FUSE-LIFETIME-LAB trigger file payload\n";

#endif /* FUSE_PROTO_H */
