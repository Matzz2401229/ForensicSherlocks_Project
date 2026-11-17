
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf.h>

#include "build/lsm_guard.skel.h"

/* Must match the value structure in lsm_guard.bpf.c. */
struct target_identity {
    __u32 major;
    __u32 minor;
    __u64 inode;
};

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

/* Confirm that the target file resides on a loop device. */
static int verify_loopback(unsigned int dev_major,
                           unsigned int dev_minor)
{
    char sysfs_path[128];
    char resolved_path[PATH_MAX];
    char *device_name;
    int length;

    length = snprintf(sysfs_path, sizeof(sysfs_path),
                      "/sys/dev/block/%u:%u",
                      dev_major, dev_minor);

    if (length < 0 || (size_t)length >= sizeof(sysfs_path)) {
        fprintf(stderr, "Error: sysfs path is too long.\n");
        return -1;
    }

    if (realpath(sysfs_path, resolved_path) == NULL) {
        perror("Failed to resolve block device in sysfs");
        return -1;
    }

    device_name = strrchr(resolved_path, '/');
    device_name = device_name ? device_name + 1 : resolved_path;

    if (strncmp(device_name, "loop", 4) != 0) {
        fprintf(stderr,
                "Error: target filesystem is not on a loop device.\n");
        return -1;
    }

    return 0;
}

/* Resolve and inspect the target file. */
static int inspect_target(const char *path,
                          struct target_identity *identity)
{
    struct stat st;
    char *resolved_path;

    resolved_path = realpath(path, NULL);

    if (resolved_path == NULL) {
        perror("Failed to resolve target path");
        return -1;
    }

    if (stat(resolved_path, &st) != 0) {
        perror("Failed to inspect target file");
        free(resolved_path);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr,
                "Error: target must be a regular file.\n");
        free(resolved_path);
        return -1;
    }

    identity->major = major(st.st_dev);
    identity->minor = minor(st.st_dev);
    identity->inode = st.st_ino;

    if (verify_loopback(identity->major, identity->minor) != 0) {
        free(resolved_path);
        return -1;
    }

    printf("\nTarget file information\n");
    printf("-----------------------\n");
    printf("Path       : %s\n", resolved_path);
    printf("Major      : %u\n", identity->major);
    printf("Minor      : %u\n", identity->minor);
    printf("Inode      : %llu\n",
           (unsigned long long)identity->inode);
    printf("Device     : Loopback (test mode)\n");

    free(resolved_path);
    return 0;
}

int main(int argc, char **argv)
{
    struct target_identity identity = {0};
    struct lsm_guard_bpf *skel = NULL;
    struct sigaction action = {0};

    int map_fd;
    int err;

    if (argc != 3 || strcmp(argv[1], "--test-loopback") != 0) {
        fprintf(stderr,
                "Usage: sudo %s --test-loopback <target-file-path>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (inspect_target(argv[2], &identity) != 0) {
        return EXIT_FAILURE;
    }

    /* Prepare signal handling for clean shutdown. */
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        perror("Failed to configure signal handlers");
        return EXIT_FAILURE;
    }

    /* Load the BPF program into the kernel. */
    printf("\nLoading BPF-LSM program...\n");

    skel = lsm_guard_bpf__open_and_load();

    if (!skel) {
        perror("Failed to load BPF program");
        return EXIT_FAILURE;
    }

    /* Obtain the file descriptor for target_map. */
    map_fd = bpf_map__fd(skel->maps.target_map);

    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to obtain target map FD.\n");
        lsm_guard_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    /* Insert the target identity into the BPF hash map. */
    __u8 target_value = 1;

    if (bpf_map_update_elem(map_fd, &identity,
                            &target_value, BPF_ANY) != 0) {
        perror("Failed to update BPF target map");
        lsm_guard_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    printf("Target identity inserted into BPF map.\n");

    /* Attach the program to the file_open LSM hook. */
    printf("Attaching BPF-LSM hook...\n");

    err = lsm_guard_bpf__attach(skel);

    if (err != 0) {
        fprintf(stderr,
                "Failed to attach BPF-LSM hook: %s\n",
                strerror(-err));
        lsm_guard_bpf__destroy(skel);
        return EXIT_FAILURE;
    }

    printf("\nPortWatchman BPF-LSM enforcement is active.\n");
    printf("Restricted file: %s\n", argv[2]);
    printf("Press Ctrl+C to stop enforcement.\n\n");

    /* Keep the attachment alive until SIGINT or SIGTERM. */
    while (!stop_requested) {
        sleep(1);
    }

    printf("\nStopping BPF-LSM enforcement...\n");

    lsm_guard_bpf__destroy(skel);

    printf("BPF-LSM resources released.\n");

    return EXIT_SUCCESS;
}
