"""Optional selected-file bridge between USB authorisation and the native guard.

This is asynchronous registration after authorisation, not an atomic USB gate.
Only `enforce --lsm-config FILE` enables it. No files are created on a USB.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from lsm_client import LsmClient, LsmClientError, validate_socket_path, unique_object


class BridgeError(RuntimeError):
    pass


class TargetPending(BridgeError):
    """A mounted filesystem or configured file has not appeared yet."""


@dataclass(frozen=True)
class BridgeConfig:
    socket_path: str
    registration_timeout_seconds: float
    on_error: str
    rules: dict


def load_bridge_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise BridgeError("LSM config exceeds 64 KiB")
    try:
        document = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(document, dict) or set(document) != {
                "schema_version", "socket_path", "registration_timeout_seconds", "on_error", "rules"}:
            raise BridgeError("LSM config has missing or unknown fields")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise BridgeError("LSM config schema_version must be 1")
        path = validate_socket_path(document["socket_path"])
        timeout = document["registration_timeout_seconds"]
        if type(timeout) not in (int, float) or not 1 <= timeout <= 120:
            raise BridgeError("registration_timeout_seconds must be between 1 and 120")
        if document["on_error"] not in ("report", "deauthorize"):
            raise BridgeError("Choose on_error explicitly: report or deauthorize")
        if not isinstance(document["rules"], list) or not 1 <= len(document["rules"]) <= 128:
            raise BridgeError("LSM rules must contain between 1 and 128 entries")
        rules = {}
        count = 0
        for rule in document["rules"]:
            if not isinstance(rule, dict) or set(rule) != {"allowlist_rule", "protected_paths"}:
                raise BridgeError("Each rule needs allowlist_rule and protected_paths")
            name, paths = rule["allowlist_rule"], rule["protected_paths"]
            if not isinstance(name, str) or not 1 <= len(name) <= 128 or name in rules:
                raise BridgeError("Allowlist rule names must be unique nonempty strings")
            if not isinstance(paths, list) or not paths:
                raise BridgeError("protected_paths must be a nonempty list")
            for value in paths:
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) >= 4096:
                    raise BridgeError("Invalid protected path")
                relative = PurePosixPath(value)
                if (relative.is_absolute() or str(relative) != value or ".." in relative.parts
                        or value == "." or "\\" in value or any(ord(c) < 32 for c in value)):
                    raise BridgeError("Use canonical relative paths inside a USB filesystem")
            if len(set(paths)) != len(paths):
                raise BridgeError("Duplicate protected path")
            rules[name] = tuple(paths)
            count += len(paths)
        if count > 128:
            raise BridgeError("At most 128 protected paths can be configured")
        return BridgeConfig(path, float(timeout), document["on_error"], rules)
    except (ValueError, TypeError, LsmClientError) as error:
        raise BridgeError(f"Invalid LSM config: {error}") from error


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


@dataclass
class HeldTarget:
    path: str
    fields: dict
    fd: int

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class UsbTargetResolver:
    """Resolve one unambiguous mounted volume; hold O_PATH references through ADD."""

    def mounts(self, usb_id):
        found = set()
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split()
            if len(fields) < 7 or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2]):
                continue
            try:
                node = Path("/sys/dev/block", fields[2]).resolve(strict=True)
            except FileNotFoundError:
                continue
            for ancestor in (node, *node.parents):
                if ancestor.name != usb_id:
                    continue
                try:
                    if ((ancestor / "subsystem").resolve(strict=True) == Path("/sys/bus/usb")
                            and (ancestor / "idVendor").is_file()):
                        found.add(unescape_mount(fields[4]))
                except FileNotFoundError:
                    pass
        return sorted(found)

    def resolve(self, usb_id, relative_paths):
        mounts = self.mounts(usb_id)
        if not mounts:
            raise TargetPending("Waiting for the approved USB filesystem to be mounted")
        if len(mounts) != 1:
            raise BridgeError("Multiple mounts found; selected-file mapping is ambiguous")
        mount = Path(mounts[0])
        targets = []
        try:
            for relative in relative_paths:
                # Refuse every symlink component, including an alias to a different volume.
                descriptor = os.open(mount, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    for index, part in enumerate(PurePosixPath(relative).parts):
                        flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
                        if index < len(PurePosixPath(relative).parts) - 1:
                            flags |= os.O_DIRECTORY
                        child = os.open(part, flags, dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = child
                    metadata = os.fstat(descriptor)
                    mount_device = mount.stat().st_dev
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_dev != mount_device or metadata.st_nlink == 0:
                        raise BridgeError("Protected path must be a linked regular file on the selected USB mount")
                    mount_id = None
                    for line in Path(f"/proc/self/fdinfo/{descriptor}").read_text().splitlines():
                        if line.startswith("mnt_id:"):
                            mount_id = int(line.split()[1])
                    if mount_id is None:
                        raise BridgeError("Cannot establish target mount identity")
                    fields = {"expected_major": os.major(metadata.st_dev),
                              "expected_minor": os.minor(metadata.st_dev),
                              "expected_inode": metadata.st_ino, "expected_mount_id": mount_id}
                    targets.append(HeldTarget(str(mount / relative), fields, descriptor))
                    descriptor = -1
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            identities = {(t.fields["expected_major"], t.fields["expected_minor"], t.fields["expected_inode"])
                          for t in targets}
            if len(identities) != len(targets):
                raise BridgeError("Configured paths refer to duplicate file identities")
            return targets
        except BaseException as error:
            for target in targets:
                target.close()
            if isinstance(error, FileNotFoundError):
                raise TargetPending("Waiting for a configured protected file") from error
            raise


@dataclass
class Registration:
    connection_id: str
    usb_id: str
    device: dict
    paths: tuple
    deadline: float
    target_ids: list = field(default_factory=list)
    ready: bool = False
    failed: bool = False


class LsmBridge:
    def __init__(self, config, reader, revoke, *, apply=True, client=None, resolver=None, clock=time.monotonic):
        self.config, self.reader, self.revoke = config, reader, revoke
        self.apply, self.clock = apply, clock
        self.client = client or LsmClient(config.socket_path)
        self.resolver = resolver or UsbTargetResolver()
        self.registrations = {}
        self.failures = 0
        self.faulted = False

    def start(self):
        if self.apply:
            state = self.client.status()
            if state.get("mode") != "usb" or state.get("failures") != 0:
                raise BridgeError("Start a healthy USB-mode controller before enabling the bridge")
        return {"type": "lsm_bridge_started", "apply": self.apply, "on_error": self.config.on_error,
                "controller_id": self.client.controller_id, "rule_names": list(self.config.rules)}

    def _event(self, kind, registration, **fields):
        return {"type": kind, "usb_id": registration.usb_id,
                "connection_id": registration.connection_id, "controller_id": self.client.controller_id, **fields}

    def _current(self, registration):
        device = self.reader.read(registration.usb_id, expected_address=registration.device["device_address"])
        for field in ("device_address", "vendor_id", "product_id", "serial"):
            if device.get(field) != registration.device.get(field):
                raise BridgeError("USB connection identity changed")
        if device.get("kernel_authorized") is not True:
            raise BridgeError("USB is no longer authorised")

    def _remove(self, registration):
        for target_id in list(registration.target_ids):
            reply = self.client.request("REMOVE", target_id=target_id, connection_id=registration.connection_id)
            if reply.get("type") not in ("lsm_target_removed", "lsm_target_absent"):
                raise BridgeError("Controller did not acknowledge restriction removal")
            registration.target_ids.remove(target_id)

    def _failure(self, registration, error):
        if registration.failed:
            return []
        registration.failed = True
        self.failures += 1
        self.faulted = True
        events = [self._event("lsm_bridge_error", registration, message=str(error),
                              protection_complete=False, on_error=self.config.on_error)]
        # Leave any partial guard entries in place. Never silently turn them off on error.
        if self.config.on_error == "deauthorize" and self.apply:
            try:
                self._current(registration)
                result = self.revoke(registration.usb_id, registration.device)
                events.append(self._event("lsm_bridge_revoke_result", registration, result=result))
            except Exception as revoke_error:
                events.append(self._event("lsm_bridge_error", registration,
                                          message=f"Deauthorisation failed: {revoke_error}", protection_complete=False))
        return events

    def handle(self, incoming, result):
        events = []
        if incoming.get("type") == "policy_skipped" and incoming.get("reason") == "usb_disconnect_started":
            connection = incoming.get("connection_id")
            registration = self.registrations.get(connection)
            if registration and registration.usb_id == incoming.get("usb_id"):
                try:
                    self._remove(registration)
                    del self.registrations[connection]
                    events.append(self._event("lsm_bridge_disconnected", registration))
                except Exception as error:
                    events.extend(self._failure(registration, error))
        if not result or result.get("type") != "enforcement_result" or result.get("action") != "allow":
            return events
        paths = self.config.rules.get(result.get("matched_rule"))
        if not paths:
            return events
        connection = result.get("connection_id")
        device = result.get("device")
        if (not isinstance(connection, str) or not 1 <= len(connection.encode()) < 256
                or any(ord(c) < 32 for c in connection) or not isinstance(device, dict)
                or type(device.get("device_address")) is not int):
            self.failures += 1
            self.faulted = True
            return events + [{"type": "lsm_bridge_error", "message": "Missing valid connection context",
                              "protection_complete": False}]
        if connection in self.registrations:
            return events
        registration = Registration(connection, result["usb_id"], device.copy(), paths,
                                    self.clock() + self.config.registration_timeout_seconds)
        if not self.apply:
            return events + [self._event("lsm_bridge_plan", registration, protected_paths=list(paths), applied=False)]
        try:
            if self.faulted:
                raise BridgeError("Bridge is degraded; restart after inspecting its retained guard entries")
            if len(self.registrations) >= 128:
                raise BridgeError("Bridge connection registry is full")
            for old_connection, old in list(self.registrations.items()):
                if old.usb_id == registration.usb_id:
                    self._remove(old)
                    del self.registrations[old_connection]
            self.registrations[connection] = registration
            events.append(self._event("lsm_bridge_pending", registration, protected_paths=list(paths)))
        except Exception as error:
            events.extend(self._failure(registration, error))
        return events

    def tick(self):
        events = []
        if not self.apply or not self.registrations or self.faulted:
            return events
        # Detect loss/restart of the guard and missing entries after registration.
        # Calls are paced by the upstream monitor (normally one heartbeat / 5 s).
        try:
            state = self.client.status()
            if state.get("mode") != "usb" or state.get("failures") != 0:
                raise BridgeError("Controller is degraded")
            inventory = {(t.get("target_id"), t.get("connection_id")) for t in state["targets"]}
            for registration in self.registrations.values():
                if registration.ready:
                    self._current(registration)
                    if any((i, registration.connection_id) not in inventory for i in registration.target_ids):
                        raise BridgeError("A required guard entry disappeared")
        except Exception as error:
            for registration in self.registrations.values():
                events.extend(self._failure(registration, error))
            return events
        for registration in list(self.registrations.values()):
            if registration.ready or self.faulted:
                continue
            targets = []
            try:
                self._current(registration)
                if self.clock() > registration.deadline:
                    raise BridgeError("Timed out waiting for selected-file registration")
                targets = self.resolver.resolve(registration.usb_id, registration.paths)
                for target in targets:
                    self._current(registration)
                    reply = self.client.request("ADD", path=target.path, connection_id=registration.connection_id,
                                                expected_usb_id=registration.usb_id,
                                                expected_address=registration.device["device_address"], **target.fields)
                    row = reply.get("target", {})
                    target_id = row.get("target_id")
                    if (reply.get("type") != "lsm_target_added" or type(target_id) is not int or target_id <= 0
                            or row.get("connection_id") != registration.connection_id):
                        raise BridgeError("Controller did not confirm the owned registration")
                    registration.target_ids.append(target_id)
                registration.ready = True
                events.append(self._event("lsm_bridge_registered", registration,
                                          target_ids=list(registration.target_ids), protection_complete=True))
            except TargetPending:
                if self.clock() >= registration.deadline:
                    events.extend(self._failure(registration, BridgeError("Registration deadline exceeded")))
            except Exception as error:
                events.extend(self._failure(registration, error))
            finally:
                for target in targets:
                    target.close()
        if self.faulted:
            for registration in self.registrations.values():
                if not registration.failed:
                    events.extend(self._failure(registration, BridgeError("Bridge became degraded")))
        return events

    def close(self, clean):
        events = []
        # Unexpected upstream termination or registration failure retains restrictions.
        if not clean or self.failures:
            return [{"type": "lsm_bridge_retained", "connections": list(self.registrations),
                     "message": "Inspect controller STATUS; restrictions remain until REMOVE/STOP"}]
        for connection, registration in list(self.registrations.items()):
            try:
                self._remove(registration)
                del self.registrations[connection]
                events.append(self._event("lsm_bridge_released", registration))
            except Exception as error:
                events.extend(self._failure(registration, error))
        return events
