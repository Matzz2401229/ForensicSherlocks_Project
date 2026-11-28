"""Service-owned protection of explicit VM files, independent of USB events.

Only O_PATH descriptors are used for inspection. The native controller remains
the authority for filesystem eligibility and installs the actual BPF map entries.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
import uuid

from lsm_client import LsmClient, LsmClientError, unique_object, validate_socket_path


class LocalGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class LocalGuardConfig:
    socket_path: str
    protected_paths: tuple[str, ...]


def load_local_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise LocalGuardError("Local-file LSM config exceeds 64 KiB")
    try:
        document = json.loads(raw, object_pairs_hook=unique_object,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if not isinstance(document, dict) or set(document) != {"schema_version", "socket_path", "protected_paths"}:
            raise LocalGuardError("Local-file LSM config needs schema_version, socket_path and protected_paths only")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise LocalGuardError("Local-file LSM schema_version must be integer 1")
        socket_path = validate_socket_path(document["socket_path"])
        paths = document["protected_paths"]
        if not isinstance(paths, list) or not 1 <= len(paths) <= 128:
            raise LocalGuardError("Configure between 1 and 128 VM files")
        for value in paths:
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) >= 4096:
                raise LocalGuardError("Invalid VM file path")
            path = PurePosixPath(value)
            if (not path.is_absolute() or str(path) != value or path.anchor != "/"
                    or value == "/" or ".." in path.parts or "\\" in value
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise LocalGuardError("Use canonical absolute Linux paths for individual VM files")
        if len(set(paths)) != len(paths):
            raise LocalGuardError("Duplicate VM file path")
        return LocalGuardConfig(socket_path, tuple(paths))
    except (ValueError, TypeError, LsmClientError) as error:
        raise LocalGuardError(f"Invalid local-file LSM config: {error}") from error


def inspect_file(value):
    """Return a held descriptor and identity without opening the file for data."""
    descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = PurePosixPath(value).parts[1:]
        for index, part in enumerate(parts):
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if index < len(parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink == 0:
            raise LocalGuardError("VM target must be a linked regular file, without symlink aliases")
        mount_id = None
        for row in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines():
            if row.startswith("mnt_id:"):
                mount_id = int(row.split()[1])
        if mount_id is None:
            raise LocalGuardError("Cannot establish VM target mount identity")
        fields = {"expected_major": os.major(info.st_dev), "expected_minor": os.minor(info.st_dev),
                  "expected_inode": info.st_ino, "expected_mount_id": mount_id}
        return descriptor, fields
    except BaseException:
        os.close(descriptor)
        raise


class LocalFileGuard:
    """Registers the configured VM files and checks that they stay guarded.

    The service's response stage is exempted through the controller, so a delete
    response can destroy guarded files. A guarded file that has gone (its entry
    dropped by the controller and its path absent) is reported as lost rather than
    treated as a failure, and a file already missing at start-up is skipped, so the
    rest of the files and USB blocking keep working.
    """

    def __init__(self, config, *, client=None, inspect=inspect_file, clock=time.monotonic,
                 exists=os.path.lexists):
        self.config = config
        self.client = client or LsmClient(config.socket_path)
        self.inspect = inspect
        self.clock = clock
        self.exists = exists
        # The protocol calls this connection_id; here it owns a service generation,
        # never a USB connection. USB lifecycle events do not touch these entries.
        self.owner_id = "local:" + uuid.uuid4().hex
        self.targets = {}
        self.missing = []
        self.lost = []
        self.next_check = 0

    def _state(self):
        state = self.client.status()
        if state.get("mode") != "local-files" or state.get("failures") != 0:
            raise LocalGuardError("Expected a healthy local-files controller")
        return state

    def start(self, *, deadline=None):
        if self.targets:
            raise LocalGuardError("VM files already registered")
        if self._state()["targets"]:
            raise LocalGuardError("Local-file controller must start with an empty registry")
        held = []
        identities = set()
        self.missing = [value for value in self.config.protected_paths if not self.exists(value)]
        try:
            # Inspect the entire set before changing the map. Hold references
            # through ADD so path replacement cannot reuse a checked inode.
            for value in self.config.protected_paths:
                if value in self.missing:
                    continue  # e.g. destroyed by a response before the last shutdown
                if deadline is not None and self.clock() >= deadline:
                    raise LocalGuardError("VM-file registration startup deadline exceeded")
                descriptor, fields = self.inspect(value)
                held.append((value, descriptor, fields))
                identity = tuple(fields[name] for name in ("expected_major", "expected_minor", "expected_inode"))
                if identity in identities:
                    raise LocalGuardError("Configured VM paths refer to the same file identity")
                identities.add(identity)
            for value, _descriptor, fields in held:
                if deadline is not None and self.clock() >= deadline:
                    raise LocalGuardError("VM-file registration startup deadline exceeded")
                reply = self.client.request("ADD", path=value, connection_id=self.owner_id, **fields)
                target = reply.get("target", {})
                target_id = target.get("target_id")
                if (reply.get("type") != "lsm_target_added" or type(target_id) is not int or target_id <= 0
                        or target_id in self.targets or target.get("connection_id") != self.owner_id
                        or target.get("usb_id") is not None
                        or any(target.get(name.removeprefix("expected_")) != expected for name, expected in fields.items())):
                    raise LocalGuardError("Controller did not confirm the expected VM file identity")
                self.targets[target_id] = dict(target, configured_path=value)
            self.verify()
            if deadline is not None and self.clock() >= deadline:
                raise LocalGuardError("VM-file registration startup deadline exceeded")
        finally:
            for _value, descriptor, _fields in held:
                os.close(descriptor)
        return {"schema_version": 1, "type": "lsm_local_registered", "mode": "local-files",
                "controller_id": self.client.controller_id, "owner_id": self.owner_id,
                "target_ids": list(self.targets),
                "protected_paths": [target["configured_path"] for target in self.targets.values()],
                "missing_paths": list(self.missing), "protection_complete": True}

    def exempt(self, pid):
        """Let one process (the response stage) through the guard until it exits."""
        reply = self.client.request("EXEMPT", pid=pid)
        if reply.get("type") != "lsm_exempted" or reply.get("pid") != pid:
            raise LocalGuardError("Controller did not confirm the response-stage exemption")
        return {"schema_version": 1, "type": "lsm_local_exempted", "pid": pid}

    def verify(self):
        """Check every registered file; return the paths newly found destroyed."""
        inventory = {row.get("target_id"): row for row in self._state()["targets"]}
        lost = []
        for target_id, expected in list(self.targets.items()):
            row = inventory.get(target_id)
            if row is None and not self.exists(expected["configured_path"]):
                # The controller drops an entry only when the file is unlinked, which the
                # guard allows for the exempted response stage alone.
                del self.targets[target_id]
                lost.append(expected["configured_path"])
                continue
            if any((row or {}).get(key) != expected.get(key) for key in
                   ("connection_id", "major", "minor", "inode", "mount_id", "usb_id")):
                raise LocalGuardError("A required VM-file guard entry disappeared or changed")
        self.lost.extend(lost)
        self.next_check = self.clock() + 1
        return lost

    def tick(self):
        if self.clock() >= self.next_check:
            return self.verify()
        return []
