#ifndef PORTWATCHMAN_LSM_TARGETS_H
#define PORTWATCHMAN_LSM_TARGETS_H
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <linux/types.h>
#include <sys/stat.h>
#include "lsm_shared.h"

struct pw_target {
    struct target_identity key;
    uint64_t id, mount_id;
    int fd, node_fd;
    bool used, mapped;
    struct stat node_stat;
    char path[PATH_MAX], node[PATH_MAX], usb_id[64];
    char connection_id[256];
    unsigned device_address;
};
int pw_target_open(const char *path, bool loop, struct pw_target *out, char error[256]);
bool pw_target_alive(const struct pw_target *target, char reason[64]);
void pw_target_close(struct pw_target *target);
#endif
