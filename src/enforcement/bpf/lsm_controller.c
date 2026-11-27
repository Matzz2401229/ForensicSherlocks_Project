#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <json-c/json.h>
#include "lsm_guard.skel.h"
#include "lsm_targets.h"
#include "lsm_socket.h"

static struct pw_target targets[PW_MAX_TARGETS];
static struct lsm_guard_bpf *skel;
static int map_fd = -1;
static enum pw_target_mode target_mode = PW_USB;
static bool attached, output_failed;
static unsigned failures;
static uint64_t next_id = 1, retired_denials;
static volatile sig_atomic_t stop_requested, status_requested;
static struct json_object *request_id, *current_request, *socket_reply;
static bool socket_request, serving;
static char controller_id[128];
static struct pw_socket_server server;
/* Bounded recent intentional-release markers; connection IDs are never port IDs. */
static char prepared_connections[PW_MAX_TARGETS][256];
static unsigned next_prepared;
static const char *string_field(struct json_object *, const char *);

static const char *mode_name(void)
{
    return target_mode == PW_LOCAL ? "local-files" :
           target_mode == PW_LOOPBACK ? "test-loopback" : "usb";
}

static bool connection_prepared(const char *connection)
{
    if (!connection || !*connection)
        return false;
    for (unsigned i = 0; i < PW_MAX_TARGETS; i++)
        if (!strcmp(connection, prepared_connections[i]))
            return true;
    return false;
}

static void signal_handler(int sig)
{
    if (sig == SIGUSR1)
        status_requested = 1;
    else
        stop_requested = 1;
}

static struct json_object *record(const char *type)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "schema_version", json_object_new_int(1));
    json_object_object_add(obj, "type", json_object_new_string(type));
    json_object_object_add(obj, "controller_pid", json_object_new_int(getpid()));
    json_object_object_add(obj, "timestamp_ns", json_object_new_int64(
        (int64_t)now.tv_sec * 1000000000LL + now.tv_nsec));
    json_object_object_add(obj, "clock", json_object_new_string("monotonic"));
    json_object_object_add(obj, "controller_id", json_object_new_string(controller_id));
    if (request_id)
        json_object_object_add(obj, "command_id", json_object_get(request_id));
    return obj;
}

static void emit(struct json_object *obj)
{
    if (socket_request && !socket_reply)
        socket_reply = json_object_get(obj);
    if (!output_failed && (puts(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN)) < 0 ||
                          fflush(stdout) == EOF)) {
        output_failed = true;
        stop_requested = 1;
        failures++;
    }
    json_object_put(obj);
}

static void error_record(const char *reason, const char *message, uint64_t id)
{
    struct json_object *obj = record("lsm_error");
    failures++;
    json_object_object_add(obj, "reason", json_object_new_string(reason));
    json_object_object_add(obj, "message", json_object_new_string(message));
    if (id)
        json_object_object_add(obj, "target_id", json_object_new_int64(id));
    emit(obj);
}

static void prepared_reply(const char *connection, unsigned removed, bool already)
{
    struct json_object *obj = record("lsm_connection_prepared");
    json_object_object_add(obj, "connection_id", json_object_new_string(connection));
    json_object_object_add(obj, "removed_targets", json_object_new_int64(removed));
    json_object_object_add(obj, "already_prepared", json_object_new_boolean(already));
    json_object_object_add(obj, "protection_complete", json_object_new_boolean(false));
    emit(obj);
}

static struct json_object *describe(const struct pw_target *target, uint64_t denials)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "target_id", json_object_new_int64(target->id));
    json_object_object_add(obj, "path", json_object_new_string(target->path));
    json_object_object_add(obj, "major", json_object_new_int64(target->key.major));
    json_object_object_add(obj, "minor", json_object_new_int64(target->key.minor));
    json_object_object_add(obj, "inode", json_object_new_int64(target->key.inode));
    json_object_object_add(obj, "mount_id", json_object_new_int64(target->mount_id));
    json_object_object_add(obj, "usb_id", *target->usb_id ? json_object_new_string(target->usb_id) : NULL);
    json_object_object_add(obj, "denied_opens", json_object_new_int64(denials));
    json_object_object_add(obj, "connection_id", *target->connection_id ? json_object_new_string(target->connection_id) : NULL);
    json_object_object_add(obj, "device_address", json_object_new_int64(target->device_address));
    return obj;
}

static bool read_count(struct pw_target *target, uint64_t *count)
{
    struct target_stats stats = {0};
    *count = 0;
    if (target->mapped && bpf_map_lookup_elem(map_fd, &target->key, &stats)) {
        error_record("counter_read_failed", strerror(errno), target->id);
        stop_requested = 1;
        return false;
    }
    *count = stats.denied_opens;
    return true;
}

static void target_event(const char *type, struct pw_target *target, const char *reason, uint64_t count)
{
    struct json_object *obj = record(type);
    json_object_object_add(obj, "target", describe(target, count));
    json_object_object_add(obj, "enforcement_active", json_object_new_boolean(attached));
    if (reason)
        json_object_object_add(obj, "reason", json_object_new_string(reason));
    emit(obj);
}

static bool bind_request(struct pw_target *target)
{
    if (!current_request)
        return true;
    struct json_object *value;
    if (target_mode == PW_LOCAL &&
        (json_object_object_get_ex(current_request, "expected_usb_id", &value) ||
         json_object_object_get_ex(current_request, "expected_address", &value)))
        return false;
    const char *connection = string_field(current_request, "connection_id");
    if (json_object_object_get_ex(current_request, "connection_id", &value)) {
        if (!connection || !*connection || strlen(connection) >= sizeof(target->connection_id))
            return false;
        for (const char *c = connection; *c; c++)
            if ((unsigned char)*c < 32 || *c == 127)
                return false;
        memcpy(target->connection_id, connection, strlen(connection) + 1);
    }
    const char *names[] = {"expected_major", "expected_minor", "expected_inode", "expected_mount_id"};
    uint64_t actual[] = {target->key.major, target->key.minor, target->key.inode, target->mount_id};
    for (unsigned i = 0; i < 4; i++) {
        if (!json_object_object_get_ex(current_request, names[i], &value)) {
            if (connection)
                return false;
        } else if (!json_object_is_type(value, json_type_int) || json_object_get_int64(value) < 0 ||
                   json_object_get_uint64(value) != actual[i]) {
            return false;
        }
    }
    if (*target->usb_id) {
        const char *usb = string_field(current_request, "expected_usb_id");
        bool has_address = json_object_object_get_ex(current_request, "expected_address", &value);
        if (connection && (!usb || !has_address))
            return false;
        if (usb && strcmp(usb, target->usb_id))
            return false;
        if (has_address && (!json_object_is_type(value, json_type_int) ||
            json_object_get_int64(value) != target->device_address))
            return false;
    }
    return true;
}

static int add_target(const char *path)
{
    const char *connection = current_request ? string_field(current_request, "connection_id") : NULL;
    if (connection_prepared(connection)) {
        /* A pending bridge ADD may race PREPARE_REMOVE. Do not reopen or re-enrol it. */
        prepared_reply(connection, 0, true);
        return 0;
    }
    struct pw_target candidate;
    char message[256], reason[64];
    int slot = -1;
    if (pw_target_open(path, target_mode, &candidate, message)) {
        error_record("invalid_target", message, 0);
        return -1;
    }
    if (!bind_request(&candidate)) {
        pw_target_close(&candidate);
        error_record("target_context_mismatch", "Target no longer matches the expected connection/file identity", 0);
        return -1;
    }
    for (int i = 0; i < PW_MAX_TARGETS; i++) {
        if (!targets[i].used) {
            if (slot < 0)
                slot = i;
        } else if (!memcmp(&targets[i].key, &candidate.key, sizeof(candidate.key))) {
            pw_target_close(&candidate);
            error_record("duplicate_target", "That file identity is already restricted", targets[i].id);
            return -1;
        }
    }
    if (slot < 0) {
        pw_target_close(&candidate);
        error_record("target_limit", "At most 128 active targets are supported", 0);
        return -1;
    }
    candidate.id = next_id++;
    if (map_fd >= 0) {
        struct target_stats stats = {0};
        if (!pw_target_alive(&candidate, reason)) {
            pw_target_close(&candidate);
            error_record("target_changed", reason, 0);
            return -1;
        }
        if (bpf_map_update_elem(map_fd, &candidate.key, &stats, BPF_NOEXIST)) {
            snprintf(message, sizeof(message), "%s", strerror(errno));
            pw_target_close(&candidate);
            error_record("map_update_failed", message, 0);
            return -1;
        }
        candidate.mapped = true;
        if (!pw_target_alive(&candidate, reason)) {
            if (bpf_map_delete_elem(map_fd, &candidate.key)) {
                /* Retain references until the program is detached if rollback fails. */
                targets[slot] = candidate;
                error_record("map_rollback_failed", strerror(errno), candidate.id);
                stop_requested = 1;
                return -1;
            }
            pw_target_close(&candidate);
            error_record("target_changed", reason, 0);
            return -1;
        }
    }
    targets[slot] = candidate;
    if (attached)
        target_event("lsm_target_added", &targets[slot], NULL, 0);
    return 0;
}

static bool remove_target(struct pw_target *target, const char *reason)
{
    uint64_t count;
    if (!read_count(target, &count))
        return false;
    if (target->mapped && bpf_map_delete_elem(map_fd, &target->key)) {
        error_record("map_delete_failed", strerror(errno), target->id);
        stop_requested = 1;
        return false;
    }
    retired_denials += count;
    target_event("lsm_target_removed", target, reason, count);
    pw_target_close(target); /* Drop the rule before releasing its inode/mount reference. */
    return true;
}

static void prepare_remove(const char *connection)
{
    if (!connection || !*connection || strlen(connection) >= sizeof(prepared_connections[0])) {
        error_record("invalid_command", "PREPARE_REMOVE requires a nonempty connection_id shorter than 256 bytes", 0);
        return;
    }
    for (const char *c = connection; *c; c++) {
        if ((unsigned char)*c < 32 || *c == 127) {
            error_record("invalid_command", "Invalid connection_id", 0);
            return;
        }
    }
    if (connection_prepared(connection)) {
        prepared_reply(connection, 0, true);
        return;
    }
    unsigned matched = 0, removed = 0;
    for (unsigned i = 0; i < PW_MAX_TARGETS; i++)
        matched += targets[i].used && !strcmp(targets[i].connection_id, connection);
    if (!matched) {
        error_record("unknown_connection", "No active targets belong to that connection", 0);
        return;
    }
    /* Publish intent before releasing references. Serialize one socket summary reply;
     * individual removals still appear on the controller's stdout audit stream. */
    snprintf(prepared_connections[next_prepared], sizeof(prepared_connections[0]), "%s", connection);
    next_prepared = (next_prepared + 1) % PW_MAX_TARGETS;
    bool capture_reply = socket_request, ok = true;
    socket_request = false;
    for (unsigned i = 0; i < PW_MAX_TARGETS; i++) {
        if (targets[i].used && !strcmp(targets[i].connection_id, connection)) {
            if (!remove_target(&targets[i], "prepared_for_removal")) {
                ok = false;
                break;
            }
            removed++;
        }
    }
    socket_request = capture_reply;
    if (!ok)
        error_record("prepare_remove_failed", "Could not release all targets; controller is stopping", 0);
    else
        prepared_reply(connection, removed, false);
}

static void expire_targets(void)
{
    char reason[64];
    for (int i = 0; i < PW_MAX_TARGETS && !stop_requested; i++) {
        if (targets[i].used && !pw_target_alive(&targets[i], reason)) {
            /* A departed device/mount is ordinary lifecycle cleanup. The bridge
             * detects an unexpected missing registration while still connected. */
            if (strcmp(reason, "device_disconnected") && strcmp(reason, "device_changed") &&
                strcmp(reason, "mount_unavailable"))
                error_record("target_expired", reason, targets[i].id);
            remove_target(&targets[i], reason);
        }
    }
}

static void status(void)
{
    struct json_object *obj = record("lsm_status");
    struct json_object *items = json_object_new_array();
    uint64_t total = retired_denials;
    for (int i = 0; i < PW_MAX_TARGETS; i++) {
        uint64_t count;
        if (!targets[i].used)
            continue;
        if (!read_count(&targets[i], &count)) {
            json_object_put(items);
            json_object_put(obj);
            return;
        }
        total += count;
        json_object_array_add(items, describe(&targets[i], count));
    }
    json_object_object_add(obj, "targets", items);
    struct json_object *prepared = json_object_new_array();
    for (unsigned i = 0; i < PW_MAX_TARGETS; i++)
        if (*prepared_connections[i])
            json_object_array_add(prepared, json_object_new_string(prepared_connections[i]));
    json_object_object_add(obj, "prepared_connections", prepared);
    json_object_object_add(obj, "enforcement_active", json_object_new_boolean(attached));
    json_object_object_add(obj, "denied_opens", json_object_new_int64(total));
    json_object_object_add(obj, "failures", json_object_new_int(failures));
    json_object_object_add(obj, "rejected_clients", json_object_new_int(server.rejected_clients));
    json_object_object_add(obj, "rejected_requests", json_object_new_int(server.rejected_requests));
    json_object_object_add(obj, "mode", json_object_new_string(mode_name()));
    emit(obj);
}

static const char *string_field(struct json_object *obj, const char *name)
{
    struct json_object *value;
    if (!json_object_object_get_ex(obj, name, &value) ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    const char *text = json_object_get_string(value);
    return strlen(text) == (size_t)json_object_get_string_len(value) ? text : NULL;
}

static void command(char *line, size_t length)
{
    struct json_tokener *parser = json_tokener_new_ex(16);
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *obj = json_tokener_parse_ex(parser, line, (int)length);
    bool valid = json_tokener_get_error(parser) == json_tokener_success && obj &&
                 json_object_is_type(obj, json_type_object);
    size_t end = json_tokener_get_parse_end(parser);
    for (size_t i = end; i < length; i++)
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '\n')
            valid = false;
    json_tokener_free(parser);
    if (!valid) {
        if (obj)
            json_object_put(obj);
        error_record("invalid_command", "Expected one complete UTF-8 JSON object", 0);
        return;
    }
    struct json_object *id, *target_id;
    const char *op = string_field(obj, "command");
    if (json_object_object_get_ex(obj, "command_id", &id)) {
        if (json_object_is_type(id, json_type_int) ||
            (json_object_is_type(id, json_type_string) &&
             string_field(obj, "command_id") && json_object_get_string_len(id) <= 128))
            request_id = id;
        else
            op = NULL;
    }
    current_request = obj;
    const char *expected_controller = string_field(obj, "expected_controller_id");
    if (json_object_object_get_ex(obj, "expected_controller_id", &target_id) &&
        (!expected_controller || strcmp(expected_controller, controller_id))) {
        error_record("controller_changed", "Request belongs to a different controller instance", 0);
        request_id = current_request = NULL;
        json_object_put(obj);
        return;
    }
    json_object_object_foreach(obj, key, value) {
        (void)value;
        if (strcmp(key, "command") && strcmp(key, "command_id") &&
            strcmp(key, "path") && strcmp(key, "target_id") && strcmp(key, "connection_id") &&
            strcmp(key, "expected_controller_id") && strcmp(key, "expected_usb_id") &&
            strcmp(key, "expected_address") && strcmp(key, "expected_major") &&
            strcmp(key, "expected_minor") && strcmp(key, "expected_inode") && strcmp(key, "expected_mount_id"))
            op = NULL;
    }
    if (!op) {
        error_record("invalid_command", "Missing command or invalid fields", 0);
    } else if (!strcmp(op, "STATUS") || !strcmp(op, "LIST") || !strcmp(op, "status")) {
        status();
    } else if (!strcmp(op, "STOP") || !strcmp(op, "stop")) {
        struct json_object *ack = record("lsm_stop_requested");
        emit(ack);
        stop_requested = 1;
    } else if (!strcmp(op, "PREPARE_REMOVE")) {
        if (target_mode == PW_LOCAL)
            error_record("unsupported_command", "Local files are independent of USB removal; stop the owning service to release them", 0);
        else
            prepare_remove(string_field(obj, "connection_id"));
    } else if (!strcmp(op, "ADD") || !strcmp(op, "restrict")) {
        const char *path = string_field(obj, "path");
        if (!path)
            error_record("invalid_command", "restrict requires a path string", 0);
        else
            add_target(path);
    } else if ((!strcmp(op, "REMOVE") || !strcmp(op, "unrestrict")) &&
               json_object_object_get_ex(obj, "target_id", &target_id) &&
               json_object_is_type(target_id, json_type_int) && json_object_get_int64(target_id) > 0) {
        bool found = false;
        for (int i = 0; i < PW_MAX_TARGETS; i++) {
            if (targets[i].used && targets[i].id == (uint64_t)json_object_get_int64(target_id)) {
                const char *connection = string_field(obj, "connection_id");
                if (json_object_object_get_ex(obj, "connection_id", &id) &&
                    (!connection || strcmp(connection, targets[i].connection_id)))
                    error_record("connection_mismatch", "Restriction belongs to another connection", targets[i].id);
                else
                    remove_target(&targets[i], "requested");
                found = true;
                break;
            }
        }
        if (!found) {
            struct json_object *absent = record("lsm_target_absent");
            json_object_object_add(absent, "target_id", json_object_get(target_id));
            emit(absent);
        }
    } else {
        error_record("invalid_command", "Use ADD, REMOVE, LIST, STATUS, PREPARE_REMOVE, or STOP", 0);
    }
    request_id = current_request = NULL;
    json_object_put(obj);
}

static char *socket_command(char *line, size_t length)
{
    if (stop_requested)
        return strdup("{\"schema_version\":1,\"type\":\"lsm_error\",\"reason\":\"controller_stopping\"}\n");
    socket_request = true;
    socket_reply = NULL;
    command(line, length);
    socket_request = false;
    if (!socket_reply)
        return NULL;
    const char *text = json_object_to_json_string_ext(socket_reply, JSON_C_TO_STRING_PLAIN);
    size_t size = strlen(text);
    char *reply = malloc(size + 2);
    if (reply) {
        memcpy(reply, text, size);
        reply[size] = '\n';
        reply[size + 1] = '\0';
    }
    json_object_put(socket_reply);
    socket_reply = NULL;
    return reply;
}

static bool prerequisites(void)
{
    char list[2048];
    FILE *source = fopen("/sys/kernel/security/lsm", "re");
    if (!source || !fgets(list, sizeof(list), source)) {
        if (source)
            fclose(source);
        error_record("lsm_unavailable", "Cannot read active LSMs; run the check with sudo", 0);
        return false;
    }
    fclose(source);
    bool bpf = false;
    char *save, *name = strtok_r(list, ",\n", &save);
    while (name) {
        if (!strcmp(name, "bpf"))
            bpf = true;
        name = strtok_r(NULL, ",\n", &save);
    }
    if (!bpf || access("/sys/kernel/btf/vmlinux", R_OK)) {
        error_record("prerequisite_failed", "Active BPF-LSM and readable kernel BTF are required", 0);
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    bool check = false, inspect = false, control = false, mode_selected = false;
    const char *socket_path = "/run/portwatchman/lsm_controller.sock";
    char input[65537];
    size_t used = 0;
    int option, result = EXIT_FAILURE, stdin_flags = -1;
    static const struct option options[] = {
        {"usb", no_argument, NULL, 'u'}, {"test-loopback", no_argument, NULL, 'l'},
        {"local-files", no_argument, NULL, 'L'},
        {"control-stdin", no_argument, NULL, 'c'}, {"check", no_argument, NULL, 'k'},
        {"serve", no_argument, NULL, 'S'}, {"socket", required_argument, NULL, 's'},
        {"inspect", no_argument, NULL, 'i'}, {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}
    };
    server.fd = -1;
    for (int i = 0; i < PW_SOCKET_CLIENTS; i++)
        server.clients[i].fd = -1;
    for (int i = 0; i < PW_MAX_TARGETS; i++)
        targets[i].fd = targets[i].node_fd = -1;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'u': case 'l': case 'L':
            if (mode_selected) {
                fputs("Choose exactly one target mode\n", stderr);
                return 2;
            }
            mode_selected = true;
            target_mode = option == 'L' ? PW_LOCAL : option == 'l' ? PW_LOOPBACK : PW_USB;
            break;
        case 'c': control = true; break;
        case 'S': serving = true; break;
        case 's': serving = true; socket_path = optarg; break;
        case 'k': check = true; break;
        case 'i': inspect = true; break;
        case 'h':
            puts("Usage: lsm_controller [--local-files|--usb|--test-loopback] --serve [--socket PATH] [FILE...]\n"
                 "       lsm_controller [--local-files|--usb|--test-loopback] [--control-stdin] FILE...\n"
                 "       lsm_controller --inspect [--local-files|--usb|--test-loopback] FILE\n"
                 "       lsm_controller --check\n"
                 "SIGUSR1 requests status; SIGINT/SIGTERM stop and detach.");
            return 0;
        default: return 2;
        }
    }
    char boot[64];
    FILE *boot_source = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!boot_source || !fgets(boot, sizeof(boot), boot_source)) {
        if (boot_source)
            fclose(boot_source);
        error_record("identity_unavailable", "Cannot establish controller boot identity", 0);
        return 1;
    }
    fclose(boot_source);
    boot[strcspn(boot, "\r\n")] = '\0';
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);
    snprintf(controller_id, sizeof(controller_id), "%s:%ld:%lld", boot, (long)getpid(),
             (long long)started.tv_sec * 1000000000LL + started.tv_nsec);
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGUSR1, &action, NULL) || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        error_record("signal_setup_failed", strerror(errno), 0);
        return 1;
    }
    if (check) {
        if (argc != optind || inspect || control || serving || !prerequisites())
            return 1;
        emit(record("lsm_preflight_passed"));
        return output_failed ? 1 : 0;
    }
    if (argc - optind > PW_MAX_TARGETS || (argc == optind && !control && !serving) ||
        (control && serving) || (inspect && (argc - optind != 1 || control || serving))) {
        error_record("invalid_arguments", "Supply up to 128 files, or use --control-stdin", 0);
        return 2;
    }
    for (int i = optind; i < argc; i++)
        if (add_target(argv[i]))
            goto done;
    if (inspect) {
        target_event("lsm_target_inspected", &targets[0], NULL, 0);
        result = 0;
        goto done;
    }
    if (geteuid() != 0 || !prerequisites()) {
        if (geteuid() != 0)
            error_record("privileges_required", "Loading the guard requires sudo in this prototype", 0);
        goto done;
    }
    if (serving) {
        char message[256];
        if (pw_socket_open(&server, socket_path, message)) {
            error_record("socket_setup_failed", message, 0);
            goto done;
        }
    }
    skel = lsm_guard_bpf__open_and_load();
    if (!skel) {
        error_record("load_failed", strerror(errno), 0);
        goto done;
    }
    map_fd = bpf_map__fd(skel->maps.target_map);
    if (map_fd < 0) {
        error_record("map_unavailable", "Cannot obtain target_map", 0);
        goto done;
    }
    for (int i = 0; i < PW_MAX_TARGETS; i++) {
        if (!targets[i].used)
            continue;
        struct target_stats stats = {0};
        char reason[64];
        if (!pw_target_alive(&targets[i], reason)) {
            error_record("target_changed", reason, targets[i].id);
            goto done;
        }
        if (bpf_map_update_elem(map_fd, &targets[i].key, &stats, BPF_NOEXIST)) {
            error_record("map_update_failed", strerror(errno), targets[i].id);
            goto done;
        }
        targets[i].mapped = true;
    }
    int err = lsm_guard_bpf__attach(skel);
    if (err) {
        error_record("attach_failed", strerror(-err), 0);
        goto done;
    }
    attached = true;
    for (int i = 0; i < PW_MAX_TARGETS; i++)
        if (targets[i].used)
            target_event("lsm_target_added", &targets[i], NULL, 0);
    struct json_object *ready = record("lsm_ready");
    json_object_object_add(ready, "mode", json_object_new_string(mode_name()));
    json_object_object_add(ready, "scope", json_object_new_string("new data opens of selected file identities"));
    if (serving)
        json_object_object_add(ready, "socket_path", json_object_new_string(server.path));
    emit(ready);
    if (control) {
        stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
        if (stdin_flags < 0 || fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK)) {
            error_record("control_setup_failed", strerror(errno), 0);
            goto done;
        }
    }
    while (!stop_requested) {
        expire_targets();
        if (status_requested) {
            status_requested = 0;
            status();
        }
        if (stop_requested)
            break;
        if (serving) {
            if (pw_socket_poll(&server, 250, socket_command)) {
                error_record("socket_poll_failed", strerror(errno), 0);
                break;
            }
            continue;
        }
        struct pollfd fd = {.fd = STDIN_FILENO, .events = POLLIN};
        int polled = poll(control ? &fd : NULL, control ? 1 : 0, 250);
        if (polled < 0) {
            if (errno == EINTR)
                continue;
            error_record("control_read_failed", strerror(errno), 0);
            break;
        }
        if (!control || polled == 0)
            continue;
        ssize_t count = read(STDIN_FILENO, input + used, sizeof(input) - 1 - used);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            error_record("control_read_failed", strerror(errno), 0);
            break;
        }
        if (count == 0) {
            error_record("unexpected_end_of_input", "Control stream closed without a stop command", 0);
            break;
        }
        used += count;
        size_t consumed = 0;
        for (size_t i = 0; i < used && !stop_requested; i++) {
            if (input[i] == '\0') {
                error_record("invalid_command", "NUL bytes are not accepted", 0);
                stop_requested = 1;
                break;
            }
            if (input[i] == '\n') {
                input[i] = '\n';
                command(input + consumed, i + 1 - consumed);
                consumed = i + 1;
            }
        }
        memmove(input, input + consumed, used - consumed);
        used -= consumed;
        if (used == sizeof(input) - 1) {
            error_record("oversized_command", "Control lines must be shorter than 64 KiB", 0);
            break;
        }
    }
    result = failures ? 1 : 0;
done:
    if (serving) {
        pw_socket_drain(&server);
        pw_socket_close(&server);
    }
    if (stdin_flags >= 0 && fcntl(STDIN_FILENO, F_SETFL, stdin_flags))
        error_record("control_cleanup_failed", strerror(errno), 0);
    /* Detach before releasing target inode/mount references or destroying maps. */
    if (attached) {
        lsm_guard_bpf__detach(skel);
        attached = false;
        status();
    }
    if (skel)
        lsm_guard_bpf__destroy(skel);
    for (int i = 0; i < PW_MAX_TARGETS; i++)
        pw_target_close(&targets[i]);
    if (!inspect) {
        struct json_object *stopped = record("lsm_stopped");
        json_object_object_add(stopped, "ok", json_object_new_boolean(result == 0 && failures == 0));
        json_object_object_add(stopped, "failures", json_object_new_int(failures));
        emit(stopped);
    }
    return failures || output_failed ? 1 : result;
}
