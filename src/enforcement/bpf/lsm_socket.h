#ifndef PORTWATCHMAN_LSM_SOCKET_H
#define PORTWATCHMAN_LSM_SOCKET_H
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#define PW_SOCKET_CLIENTS 8
struct pw_socket_client {
    int fd;
    char input[65537];
    size_t used, sent, length;
    char *output;
    double deadline;
};
struct pw_socket_server {
    int fd;
    char path[108];
    struct stat owner;
    bool owns_path;
    unsigned rejected_clients, rejected_requests;
    struct pw_socket_client clients[PW_SOCKET_CLIENTS];
};
typedef char *(*pw_socket_command)(char *line, size_t length);
int pw_socket_open(struct pw_socket_server *, const char *path, char error[256]);
int pw_socket_poll(struct pw_socket_server *, int timeout_ms, pw_socket_command);
void pw_socket_drain(struct pw_socket_server *);
void pw_socket_close(struct pw_socket_server *);
#endif
