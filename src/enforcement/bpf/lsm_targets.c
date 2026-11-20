#define _GNU_SOURCE
#include "lsm_targets.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>

static bool same_node(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int usb_address(int directory)
{
    char text[16];
    int fd = openat(directory, "devnum", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t count = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (count <= 0)
        return -1;
    text[count] = '\0';
    char *end;
    long address = strtol(text, &end, 10);
    if (end == text || (*end && strcmp(end, "\n")) || address < 1 || address > 127)
        return -1;
    return (int)address;
}

static int mount_present(uint64_t mount_id)
{
    FILE *source = fopen("/proc/self/mountinfo", "re");
    char *line = NULL;
    size_t size = 0;
    int found = 0;
    if (!source)
        return -1;
    while (getline(&line, &size, source) >= 0) {
        unsigned long long id;
        if (sscanf(line, "%llu", &id) == 1 && id == mount_id) {
            found = 1;
            break;
        }
    }
    if (ferror(source))
        found = -1;
    free(line);
    fclose(source);
    return found;
}

void pw_target_close(struct pw_target *target)
{
    if (target->fd >= 0)
        close(target->fd);
    if (target->node_fd >= 0)
        close(target->node_fd);
    target->fd = target->node_fd = -1;
    target->used = target->mapped = false;
}

int pw_target_open(const char *path, bool loop, struct pw_target *out, char error[256])
{
    struct stat file_stat, after, root_stat;
    struct statx extended;
    char block[128], resolved[PATH_MAX], probe[PATH_MAX], subsystem[PATH_MAX];
    int saved;
    memset(out, 0, sizeof(*out));
    out->fd = out->node_fd = -1;
    if (!path || !*path || strlen(path) >= PATH_MAX) {
        snprintf(error, 256, "Missing or oversized target path");
        return -1;
    }
    /* O_PATH keeps this inode/mount alive without opening it for data access.
     * A final symlink is rejected; parent aliases resolve to the opened object. */
    out->fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (out->fd < 0 || fstat(out->fd, &file_stat))
        goto system_error;
    if (!S_ISREG(file_stat.st_mode) || file_stat.st_nlink == 0) {
        snprintf(error, 256, "Target must be a linked regular file, not a directory or symlink");
        goto invalid;
    }
    if (stat("/", &root_stat))
        goto system_error;
    if (file_stat.st_dev == root_stat.st_dev) {
        snprintf(error, 256, "Refusing a target on the guest root filesystem");
        goto invalid;
    }
    if (statx(out->fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &extended) ||
        !(extended.stx_mask & STATX_MNT_ID)) {
        snprintf(error, 256, "Cannot establish target mount identity (STATX_MNT_ID required)");
        goto invalid;
    }
    out->mount_id = extended.stx_mnt_id;
    out->key.major = major(file_stat.st_dev);
    out->key.minor = minor(file_stat.st_dev);
    out->key.inode = file_stat.st_ino;
    snprintf(block, sizeof(block), "/sys/dev/block/%u:%u", out->key.major, out->key.minor);
    if (!realpath(block, resolved))
        goto system_error;
    if (loop) {
        const char *name = strrchr(resolved, '/');
        const char *digit = name ? name + 1 : resolved;
        if (strncmp(digit, "loop", 4)) {
            snprintf(error, 256, "Explicit test mode accepts only loop-backed filesystems");
            goto invalid;
        }
        digit += 4;
        if (!*digit || strspn(digit, "0123456789") != strlen(digit)) {
            snprintf(error, 256, "Invalid loop device identity");
            goto invalid;
        }
        snprintf(out->node, sizeof(out->node), "%s", resolved);
    } else {
        /* Find the physical USB device ancestor, not merely a USB interface. */
        for (;;) {
            if (snprintf(probe, sizeof(probe), "%s/subsystem", resolved) >= (int)sizeof(probe))
                goto no_usb;
            if (realpath(probe, subsystem) && !strcmp(subsystem, "/sys/bus/usb")) {
                if (snprintf(probe, sizeof(probe), "%s/idVendor", resolved) >= (int)sizeof(probe))
                    goto no_usb;
                if (access(probe, R_OK) == 0) {
                    const char *name = strrchr(resolved, '/');
                    name = name ? name + 1 : resolved;
                    size_t name_length = strlen(name);
                    if (name_length >= sizeof(out->usb_id))
                        goto no_usb;
                    snprintf(out->node, sizeof(out->node), "%s", resolved);
                    memcpy(out->usb_id, name, name_length + 1);
                    break;
                }
            }
            char *slash = strrchr(resolved, '/');
            if (!slash || slash == resolved)
                goto no_usb;
            *slash = '\0';
        }
    }
    out->node_fd = open(out->node, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (out->node_fd < 0 || fstat(out->node_fd, &out->node_stat) || stat(out->node, &after))
        goto system_error;
    if (!same_node(&out->node_stat, &after)) {
        snprintf(error, 256, "Device changed during validation");
        goto invalid;
    }
    if (!loop) {
        int address = usb_address(out->node_fd);
        if (address < 0) {
            snprintf(error, 256, "Cannot establish USB device address");
            goto invalid;
        }
        out->device_address = (unsigned)address;
    }
    snprintf(probe, sizeof(probe), "/proc/self/fd/%d", out->fd);
    ssize_t count = readlink(probe, out->path, sizeof(out->path) - 1);
    if (count < 0)
        goto system_error;
    if (count >= (ssize_t)sizeof(out->path) - 1) {
        snprintf(error, 256, "Resolved target path exceeds the supported bound");
        goto invalid;
    }
    out->path[count] = '\0';
    char reason[64];
    if (!pw_target_alive(out, reason)) {
        snprintf(error, 256, "Target changed during validation: %s", reason);
        goto invalid;
    }
    out->used = true;
    return 0;
no_usb:
    snprintf(error, 256, "Target is not on a verified USB-backed filesystem");
    goto invalid;
system_error:
    saved = errno;
    snprintf(error, 256, "Cannot validate target: %s", strerror(saved));
invalid:
    pw_target_close(out);
    return -1;
}

bool pw_target_alive(const struct pw_target *target, char reason[64])
{
    struct stat file_stat, node_stat;
    const char *why = NULL;
    if (fstat(target->fd, &file_stat))
        why = "target_unavailable";
    else if (file_stat.st_nlink == 0)
        why = "target_unlinked";
    else if (major(file_stat.st_dev) != target->key.major ||
             minor(file_stat.st_dev) != target->key.minor || file_stat.st_ino != target->key.inode)
        why = "target_changed";
    else if (stat(target->node, &node_stat) || !same_node(&target->node_stat, &node_stat))
        why = "device_disconnected";
    else if (*target->usb_id && usb_address(target->node_fd) != (int)target->device_address)
        why = "device_changed";
    else if (mount_present(target->mount_id) != 1)
        why = "mount_unavailable";
    if (why) {
        snprintf(reason, 64, "%s", why);
        return false;
    }
    return true;
}
