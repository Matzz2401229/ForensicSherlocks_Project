#!/usr/bin/env python3
"""Root-only NDJSON client for the native BPF-LSM Unix socket controller."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import struct
import sys
import time
import uuid

DEFAULT_SOCKET = "/run/portwatchman/lsm_controller.sock"
MAX_REQUEST = 65535
MAX_REPLY = 4 * 1024 * 1024


class LsmClientError(RuntimeError):
    pass


class ControllerChanged(LsmClientError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LsmClientError(f"Duplicate response key: {key}")
        result[key] = value
    return result


def validate_socket_path(value):
    if not isinstance(value, str):
        raise LsmClientError("Socket path must be a string")
    path = PurePosixPath(value)
    if (not isinstance(value, str) or not path.is_absolute() or ".." in path.parts
            or "\0" in value or len(os.fsencode(value)) >= 108
            or str(path) != value):
        raise LsmClientError("Use a canonical absolute Unix socket path shorter than 108 bytes")
    return value


def verify_socket_files(path):
    socket_path = Path(path)
    parent = socket_path.parent
    if parent.resolve(strict=True) != parent:
        raise LsmClientError("Socket directory must not use symlink aliases")
    for directory in (parent, *parent.parents):
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise LsmClientError("Socket ancestors must be root-owned and not writable by other users")
    if stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise LsmClientError("Socket directory must have mode 0700")
    metadata = socket_path.lstat()
    if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise LsmClientError("Expected a root-owned socket with mode 0600")


class LsmClient:
    def __init__(self, path=DEFAULT_SOCKET, timeout=3.0):
        self.path = validate_socket_path(path)
        if not 0.1 <= timeout <= 30:
            raise LsmClientError("Socket timeout must be between 0.1 and 30 seconds")
        self.timeout = timeout
        self.controller_id = None

    def request(self, command, **fields):
        command = command.upper()
        if command not in {"ADD", "REMOVE", "LIST", "STATUS", "EXEMPT", "PREPARE_REMOVE", "STOP"}:
            raise LsmClientError("Unknown controller command")
        if any(key in fields for key in ("command", "command_id", "expected_controller_id")):
            raise LsmClientError("Reserved protocol fields cannot be overridden")
        if command not in {"STATUS", "LIST"} and self.controller_id is None:
            self.status()
        command_id = uuid.uuid4().hex
        payload = {"command": command, "command_id": command_id, **fields}
        if self.controller_id is not None:
            payload["expected_controller_id"] = self.controller_id
        data = (json.dumps(payload, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
        if len(data) > MAX_REQUEST:
            raise LsmClientError("Controller request exceeds 64 KiB")
        if sys.platform != "linux":
            raise LsmClientError("Live BPF-LSM socket control requires Linux")
        try:
            verify_socket_files(self.path)
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.path)
                peer = connection.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), 12)
                pid, uid, _gid = struct.unpack("3i", peer)
                if uid != 0 or pid <= 0:
                    raise LsmClientError("Controller peer must be root")
                connection.sendall(data)
                reply = bytearray()
                while b"\n" not in reply:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LsmClientError("Controller response deadline exceeded")
                    connection.settimeout(remaining)
                    chunk = connection.recv(min(65536, MAX_REPLY + 1 - len(reply)))
                    if not chunk:
                        raise LsmClientError("Controller closed the socket before a complete response")
                    reply.extend(chunk)
                    if len(reply) > MAX_REPLY:
                        raise LsmClientError("Controller response exceeds 4 MiB")
            line, trailing = bytes(reply).split(b"\n", 1)
            if trailing.strip():
                raise LsmClientError("Unexpected additional response data")
            result = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object,
                                parse_constant=lambda value: (_ for _ in ()).throw(LsmClientError(value)))
        except (OSError, UnicodeError, ValueError) as error:
            raise LsmClientError(f"BPF-LSM socket request failed: {error}") from error
        if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
                or result["schema_version"] != 1 or result.get("command_id") != command_id):
            raise LsmClientError("Invalid schema or response command correlation")
        instance = result.get("controller_id")
        if not isinstance(instance, str) or not 1 <= len(instance) <= 128:
            raise LsmClientError("Missing controller instance identity")
        if self.controller_id is not None and instance != self.controller_id:
            raise ControllerChanged("BPF-LSM controller restarted; old registrations must not be reused")
        if result.get("type") == "lsm_error":
            raise LsmClientError(f"{result.get('reason')}: {result.get('message', '')}")
        self.controller_id = instance
        return result

    def status(self):
        result = self.request("STATUS")
        if result.get("type") != "lsm_status" or result.get("enforcement_active") is not True:
            raise LsmClientError("BPF-LSM controller is not actively enforcing")
        if not isinstance(result.get("targets"), list):
            raise LsmClientError("Invalid target inventory")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("LIST", "STATUS", "STOP"):
        sub.add_parser(name)
    add = sub.add_parser("ADD")
    add.add_argument("path")
    remove = sub.add_parser("REMOVE")
    remove.add_argument("target_id", type=int)
    remove.add_argument("--connection-id")
    prepare = sub.add_parser("PREPARE_REMOVE", help="Release one connection's targets before normal unmount")
    prepare.add_argument("connection_id")
    args = parser.parse_args()
    fields = {}
    if args.command == "ADD":
        fields["path"] = args.path
    if args.command == "REMOVE":
        fields["target_id"] = args.target_id
        if args.connection_id:
            fields["connection_id"] = args.connection_id
    if args.command == "PREPARE_REMOVE":
        fields["connection_id"] = args.connection_id
    try:
        print(json.dumps(LsmClient(args.socket).request(args.command, **fields)))
        return 0
    except LsmClientError as error:
        print(json.dumps({"schema_version": 1, "type": "lsm_client_error", "message": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
