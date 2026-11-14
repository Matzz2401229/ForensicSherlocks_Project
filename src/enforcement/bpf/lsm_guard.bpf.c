
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

/* Identity of the file we want to restrict. */
struct target_identity {
    __u32 major;
    __u32 minor;
    __u64 inode;
};

/* A single-entry map containing the target identity. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct target_identity);
} target_map SEC(".maps");

/* BPF-LSM hook: called when a file is opened. */
SEC("lsm/file_open")
int BPF_PROG(restrict_file_open,
             struct file *file,
             int ret)
{
    struct inode *inode;
    struct super_block *sb;
    struct target_identity *target;

    __u32 key = 0;
    __u32 dev;
    __u32 dev_major;
    __u32 dev_minor;
    __u64 inode_number;

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

    inode_number = BPF_CORE_READ(inode, i_ino);
    dev = (__u32)BPF_CORE_READ(sb, s_dev);

    /* Decode the kernel device number. */
    dev_major = dev >> 20;
    dev_minor = dev & 0xFFFFF;

    /* Retrieve the configured target identity. */
    target = bpf_map_lookup_elem(&target_map, &key);

    if (!target)
        return 0;

    /* Deny access only when all three identifiers match. */
    if (dev_major == target->major &&
        dev_minor == target->minor &&
        inode_number == target->inode) {
        return -EACCES; /* -EACCES: Permission denied */
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
