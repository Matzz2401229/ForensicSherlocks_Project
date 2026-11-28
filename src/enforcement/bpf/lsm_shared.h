#ifndef PORTWATCHMAN_LSM_SHARED_H
#define PORTWATCHMAN_LSM_SHARED_H
#define PW_MAX_TARGETS 128
/* Processes allowed through the guard (the service's own response stage). */
#define PW_MAX_EXEMPT 8
struct target_identity {
    __u32 major;
    __u32 minor;
    __u64 inode;
};
struct target_stats {
    __u64 denied_opens;
    __u64 denied_changes; /* refused delete, replace or truncate */
};
_Static_assert(sizeof(struct target_identity) == 16, "BPF/user-space key ABI mismatch");
_Static_assert(sizeof(struct target_stats) == 16, "BPF/user-space counter ABI mismatch");
#endif
