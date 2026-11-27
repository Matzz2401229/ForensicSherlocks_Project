#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lsm_shared.h"

/* Presence means restricted; remove an entry to unrestrict that identity. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PW_MAX_TARGETS);
    __type(key, struct target_identity);
    __type(value, struct target_stats);
} target_map SEC(".maps");

static __always_inline struct target_stats *target_of(struct inode *inode)
{
    struct target_identity key = {};
    struct super_block *sb;
    __u32 dev;
    if (!inode || !(sb = BPF_CORE_READ(inode, i_sb)))
        return NULL;
    key.inode = BPF_CORE_READ(inode, i_ino);
    dev = BPF_CORE_READ(sb, s_dev);
    key.major = dev >> 20;
    key.minor = dev & 0xfffff;
    return bpf_map_lookup_elem(&target_map, &key);
}

static __always_inline int deny_change(struct dentry *dentry)
{
    struct target_stats *stats = dentry ? target_of(BPF_CORE_READ(dentry, d_inode)) : NULL;
    if (!stats)
        return 0;
    __sync_fetch_and_add(&stats->denied_changes, 1);
    return -13; /* EACCES */
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file, int ret)
{
    struct target_stats *stats;
    /* Preserve the preceding BPF-LSM program's denial. */
    if (ret)
        return ret;
    stats = file ? target_of(BPF_CORE_READ(file, f_inode)) : NULL;
    if (!stats)
        return 0;
    __sync_fetch_and_add(&stats->denied_opens, 1);
    return -13; /* EACCES; no libc errno headers needed in the BPF build. */
}

/* Deleting, replacing or truncating a protected file would destroy it without opening it. */
SEC("lsm/inode_unlink")
int BPF_PROG(restrict_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    return ret ? ret : deny_change(dentry);
}

/* Only the destination is checked: moving the protected file keeps its protection. */
SEC("lsm/inode_rename")
int BPF_PROG(restrict_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    return ret ? ret : deny_change(new_dentry);
}

SEC("lsm/path_truncate")
int BPF_PROG(restrict_truncate, struct path *path, int ret)
{
    return ret ? ret : deny_change(path ? BPF_CORE_READ(path, dentry) : NULL);
}
char LICENSE[] SEC("license") = "GPL";
