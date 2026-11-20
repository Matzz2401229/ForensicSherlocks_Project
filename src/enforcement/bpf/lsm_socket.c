#define _GNU_SOURCE
#include "lsm_socket.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}

static void close_client(struct pw_socket_client *client)
{
    if (client->fd >= 0)
        close(client->fd);
    free(client->output);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}

static bool secure_ancestors(const char *path)
{
    char current[PATH_MAX], canonical[PATH_MAX];
    struct stat st;
    if (!realpath(path, canonical) || strcmp(path, canonical))
        return false;
    snprintf(current, sizeof(current), "%s", path);
    for (;;) {
        if (lstat(current, &st) || !S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022))
            return false;
        if (!strcmp(current, "/"))
            return true;
        char *slash = strrchr(current, '/');
        if (slash == current)
            current[1] = '\0';
        else
            *slash = '\0';
    }
}

void pw_socket_close(struct pw_socket_server *server)
{
    struct stat st;
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
        close_client(&server->clients[i]);
    if (server->fd >= 0)
        close(server->fd);
    server->fd = -1;
    /* Never remove a path that has been replaced by another owner/instance. */
    if (server->owns_path && !lstat(server->path, &st) && S_ISSOCK(st.st_mode) &&
        st.st_dev == server->owner.st_dev && st.st_ino == server->owner.st_ino)
        unlink(server->path);
    server->owns_path = false;
}

int pw_socket_open(struct pw_socket_server *server, const char *path, char error[256])
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct stat st;
    char parent[108], ancestor[108];
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
        server->clients[i].fd = -1;
    if (!path || path[0] != '/' || strlen(path) >= sizeof(address.sun_path)) {
        snprintf(error, 256, "Socket requires an absolute pathname shorter than 108 bytes");
        return -1;
    }
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash == parent || !slash[1] || !strcmp(slash + 1, ".") || !strcmp(slash + 1, "..")) {
        snprintf(error, 256, "Use a private socket directory, e.g. /run/portwatchman");
        return -1;
    }
    *slash = '\0';
    snprintf(ancestor, sizeof(ancestor), "%s", parent);
    slash = strrchr(ancestor, '/');
    if (slash == ancestor)
        ancestor[1] = '\0';
    else
        *slash = '\0';
    if (!secure_ancestors(ancestor)) {
        snprintf(error, 256, "Socket ancestors must be canonical, root-owned and not writable by other users");
        return -1;
    }
    if (mkdir(parent, 0700) && errno != EEXIST)
        goto failed;
    if (!secure_ancestors(parent) || lstat(parent, &st) || (st.st_mode & 0777) != 0700) {
        snprintf(error, 256, "Socket directory must be a root-owned directory with mode 0700");
        return -1;
    }
    if (!lstat(path, &st) || errno != ENOENT) {
        snprintf(error, 256, "Socket path already exists or cannot be inspected; it was not removed");
        return -1;
    }
    server->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (server->fd < 0)
        goto failed;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    mode_t previous = umask(077);
    int result = bind(server->fd, (struct sockaddr *)&address, sizeof(address));
    int saved = errno;
    umask(previous);
    errno = saved;
    if (result)
        goto failed;
    snprintf(server->path, sizeof(server->path), "%s", path);
    if (lstat(path, &server->owner))
        goto failed;
    server->owns_path = true;
    if (chmod(path, 0600) || listen(server->fd, PW_SOCKET_CLIENTS))
        goto failed;
    return 0;
failed:
    snprintf(error, 256, "Cannot create socket: %s", strerror(errno));
    pw_socket_close(server);
    return -1;
}

static void reject_client(int fd, const char *reason)
{
    char response[256];
    int length = snprintf(response, sizeof(response),
        "{\"schema_version\":1,\"type\":\"lsm_error\",\"reason\":\"%s\",\"ok\":false}\n", reason);
    /* Rejections are bounded and never wait on an untrusted peer. */
    (void)send(fd, response, (size_t)length, MSG_NOSIGNAL);
    close(fd);
}

int pw_socket_poll(struct pw_socket_server *server, int timeout_ms, pw_socket_command command)
{
    struct pollfd fds[PW_SOCKET_CLIENTS + 1];
    fds[0] = (struct pollfd){.fd = server->fd, .events = POLLIN};
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++) {
        struct pw_socket_client *client = &server->clients[i];
        fds[i + 1] = (struct pollfd){.fd = client->fd,
            .events = client->output ? POLLOUT : POLLIN};
    }
    if (poll(fds, PW_SOCKET_CLIENTS + 1, timeout_ms) < 0)
        return errno == EINTR ? 0 : -1;
    if (server->fd >= 0 && (fds[0].revents & POLLIN)) {
        for (int attempt = 0; attempt < PW_SOCKET_CLIENTS; attempt++) {
            int fd = accept4(server->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EAGAIN || errno == EINTR)
                    break;
                return -1;
            }
            struct ucred peer;
            socklen_t length = sizeof(peer);
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
                length != sizeof(peer) || peer.uid != 0) {
                server->rejected_clients++;
                reject_client(fd, "unauthorized_client");
                continue;
            }
            int slot = -1;
            for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
                if (server->clients[i].fd < 0) { slot = i; break; }
            if (slot < 0) {
                server->rejected_clients++;
                reject_client(fd, "server_busy");
            } else {
                server->clients[slot].fd = fd;
                server->clients[slot].deadline = now() + 3;
            }
        }
    }
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++) {
        struct pw_socket_client *client = &server->clients[i];
        short events = fds[i + 1].revents;
        if (client->fd < 0)
            continue;
        if (now() > client->deadline || (events & (POLLERR | POLLNVAL))) {
            server->rejected_requests++;
            close_client(client);
            continue;
        }
        if (!client->output && (events & (POLLIN | POLLHUP))) {
            ssize_t count = recv(client->fd, client->input + client->used,
                                 sizeof(client->input) - 1 - client->used, 0);
            if (count <= 0) {
                if (count == 0 || (errno != EAGAIN && errno != EINTR))
                    close_client(client);
                continue;
            }
            client->used += count;
            char *end = memchr(client->input, '\n', client->used);
            if (memchr(client->input, '\0', client->used) ||
                (!end && client->used == sizeof(client->input) - 1)) {
                server->rejected_requests++;
                reject_client(client->fd, "invalid_frame");
                client->fd = -1;
                close_client(client);
                continue;
            }
            if (end) {
                client->output = command(client->input, (size_t)(end - client->input) + 1);
                if (!client->output || strlen(client->output) > 4 * 1024 * 1024) {
                    close_client(client);
                    continue;
                }
                client->length = strlen(client->output);
                client->deadline = now() + 3;
            }
        }
        if (client->output && (events & POLLOUT)) {
            ssize_t count = send(client->fd, client->output + client->sent,
                                 client->length - client->sent, MSG_NOSIGNAL);
            if (count > 0) {
                client->sent += count;
                if (client->sent == client->length)
                    close_client(client);
            } else if (count == 0 || (errno != EAGAIN && errno != EINTR)) {
                close_client(client);
            }
        }
    }
    return 0;
}

void pw_socket_drain(struct pw_socket_server *server)
{
    if (server->fd >= 0)
        close(server->fd);
    server->fd = -1;
    /* No new commands after STOP. Finish only already queued replies. */
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
        if (!server->clients[i].output)
            close_client(&server->clients[i]);
    double deadline = now() + 1;
    while (now() < deadline) {
        bool pending = false;
        for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
            pending |= server->clients[i].fd >= 0;
        if (!pending || pw_socket_poll(server, 25, NULL))
            break;
    }
}
