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

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file, int ret)
{
    struct target_identity key = {};
    struct inode *inode;
    struct super_block *sb;
    struct target_stats *stats;
    __u32 dev;
    /* Preserve the preceding BPF-LSM program's denial. */
    if (ret)
        return ret;
    if (!file || !(inode = BPF_CORE_READ(file, f_inode)) ||
        !(sb = BPF_CORE_READ(inode, i_sb)))
        return 0;
    key.inode = BPF_CORE_READ(inode, i_ino);
    dev = BPF_CORE_READ(sb, s_dev);
    key.major = dev >> 20;
    key.minor = dev & 0xfffff;
    stats = bpf_map_lookup_elem(&target_map, &key);
    if (!stats)
        return 0;
    __sync_fetch_and_add(&stats->denied_opens, 1);
    return -13; /* EACCES; no libc errno headers needed in the BPF build. */
}
char LICENSE[] SEC("license") = "GPL";
