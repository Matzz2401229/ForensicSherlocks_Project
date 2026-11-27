#define _GNU_SOURCE
#include "lsm_targets.h"
#include <errno.h>
#include <dirent.h>
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

/* Inspect block ancestry and stacked-device slaves. Unknown backing fails closed;
 * local mode never silently becomes a way to enrol USB or loopback targets. */
static bool local_backing(const char *node, unsigned depth)
{
    char ancestor[PATH_MAX], probe[PATH_MAX], resolved[PATH_MAX];
    if (depth > 8 || strlen(node) >= sizeof(ancestor))
        return false;
    const char *name = strrchr(node, '/');
    if (name && !strncmp(name + 1, "loop", 4))
        return false;
    snprintf(ancestor, sizeof(ancestor), "%s", node);
    for (;;) {
        if (snprintf(probe, sizeof(probe), "%s/subsystem", ancestor) >= (int)sizeof(probe))
            return false;
        if (realpath(probe, resolved) && !strcmp(resolved, "/sys/bus/usb"))
            return false;
        char *slash = strrchr(ancestor, '/');
        if (!slash || slash == ancestor)
            break;
        *slash = '\0';
    }
    if (snprintf(probe, sizeof(probe), "%s/slaves", node) >= (int)sizeof(probe))
        return false;
    DIR *slaves = opendir(probe);
    if (!slaves)
        return errno == ENOENT; /* Partitions have no slaves directory. */
    bool valid = true;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(slaves))) {
        if (entry->d_name[0] == '.')
            continue;
        if (snprintf(probe, sizeof(probe), "%s/slaves/%s", node, entry->d_name) >= (int)sizeof(probe) ||
            !realpath(probe, resolved) || !local_backing(resolved, depth + 1)) {
            valid = false;
            break;
        }
        errno = 0;
    }
    if (!entry && errno)
        valid = false;
    closedir(slaves);
    return valid;
}

/* Resolve each local component through held directory descriptors. Parent
 * symlinks and traversal are rejected as well as a final symlink. */
static int open_local(const char *path)
{
    if (path[0] != '/' || path[1] == '/' || path[strlen(path) - 1] == '/') {
        errno = EINVAL;
        return -1;
    }
    char parts[PATH_MAX];
    snprintf(parts, sizeof(parts), "%s", path + 1);
    int fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    char *part = parts;
    while (fd >= 0 && part && *part) {
        char *next = strchr(part, '/');
        if (next)
            *next++ = '\0';
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..")) {
            close(fd);
            errno = EINVAL;
            return -1;
        }
        int child = openat(fd, part, O_PATH | O_NOFOLLOW | O_CLOEXEC | (next ? O_DIRECTORY : 0));
        int saved = errno;
        close(fd);
        fd = child;
        errno = saved;
        part = next;
    }
    return fd;
}

int pw_target_open(const char *path, enum pw_target_mode mode, struct pw_target *out, char error[256])
{
    bool loop = mode == PW_LOOPBACK, local = mode == PW_LOCAL;
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
    out->fd = local ? open_local(path) : open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (out->fd < 0 || fstat(out->fd, &file_stat))
        goto system_error;
    if (!S_ISREG(file_stat.st_mode) || file_stat.st_nlink == 0) {
        snprintf(error, 256, "Target must be a linked regular file, not a directory or symlink");
        goto invalid;
    }
    if (stat("/", &root_stat))
        goto system_error;
    if (!local && file_stat.st_dev == root_stat.st_dev) {
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
    if (local) {
        if (!local_backing(resolved, 0)) {
            snprintf(error, 256, "Local mode requires an internal block-backed filesystem, excluding USB and loop devices");
            goto invalid;
        }
        snprintf(out->node, sizeof(out->node), "%s", resolved);
    } else if (loop) {
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
    if (!loop && !local) {
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
