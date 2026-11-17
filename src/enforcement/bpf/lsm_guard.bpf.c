
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

/* Identity of a file to restrict. */
struct target_identity {
    __u32 major;
    __u32 minor;
    __u64 inode;
};

/*
 * Hash map containing multiple protected file identities.
 * Each identity is a key; value 1 indicates an active target.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct target_identity);
    __type(value, __u8);
} target_map SEC(".maps");

/* BPF-LSM hook: called when a file is opened. */
SEC("lsm/file_open")
int BPF_PROG(restrict_file_open,
             struct file *file,
             int ret)
{
    struct inode *inode;
    struct super_block *sb;
    struct target_identity identity = {};
    __u8 *target;

    __u32 dev;

    /* Preserve a denial made by an earlier LSM. */
    if (ret != 0)
        return ret;

    if (!file)
        return 0;

    /* Obtain the inode associated with the file. */
    inode = BPF_CORE_READ(file, f_inode);

    if (!inode)
        return 0;

    /* Obtain the filesystem information. */
    sb = BPF_CORE_READ(inode, i_sb);

    if (!sb)
        return 0;

    identity.inode = BPF_CORE_READ(inode, i_ino);
    dev = (__u32)BPF_CORE_READ(sb, s_dev);

    /* Decode the kernel device number. */
    identity.major = dev >> 20;
    identity.minor = dev & 0xFFFFF;

    /* Check whether this exact file is registered. */
    target = bpf_map_lookup_elem(&target_map, &identity);

    if (target)
        return -EACCES;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
