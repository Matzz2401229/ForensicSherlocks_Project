#!/usr/bin/env python3
"""Enforce USB access control with Linux USB authorisation (step 5).

Keeps new USB devices blocked until approved, then authorises permitted devices:
- Bus level: ``arm`` sets ``authorized_default=0`` on managed buses so new devices
  start blocked; ``restore`` puts the saved originals back; ``status`` reports them.
- Device level: ``authorize`` re-validates one device and writes ``authorized=1`` only
  if it still matches the policy; ``revoke`` writes ``authorized=0``.
- ``enforce`` reads the policy watcher's decisions on stdin and acts on each one;
  ``reconcile`` handles devices that were connected before the service started.

Design notes:
- The sysfs root is injectable so the logic is unit-testable without real hardware.
- Every write command is a dry run unless ``--apply`` is given (``enforce`` writes
  unless ``--dry-run``). Real writes need root on a live system.
- Original ``authorized_default`` values are saved before any bus is changed and are
  never overwritten by a re-arm, so ``restore`` always returns the true originals.
- ``auto`` mode arms every bus because a device can enumerate on a different
  controller across reconnects.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "enforcement.json"
DEFAULT_POLICY = REPO_ROOT / "config" / "allowlist.json"
USB_ROOT = Path("/sys/bus/usb/devices")
ROOT_ID = re.compile(r"usb([1-9][0-9]*)\Z")
MAX_CONFIG_BYTES = 65536
# A decision older than this (guest monotonic clock) is refused rather than enforced.
MAX_DECISION_AGE_NS = 2_000_000_000

# Reuse the policy component's sysfs reader and evaluator so the enforcement gate
# validates devices against exactly the same logic that produced the decision.
_POLICY_DIR = REPO_ROOT / "src" / "policy"
if str(_POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(_POLICY_DIR))
from device_policy import (DeviceError, DeviceReader, PolicyError,  # noqa: E402
                           evaluate, identifier, load_policy)


class EnforcementError(RuntimeError):
    pass


def emit(record):
    """Print one record as a single schema-tagged JSON line (the shared NDJSON format)."""
    print(json.dumps({"schema_version": SCHEMA_VERSION, **record}, separators=(",", ":")), flush=True)


def require_linux():
    if sys.platform != "linux":
        raise EnforcementError("Live USB authorisation runs inside the Ubuntu VM")


def bus_number(bus):
    """Bus number of a root-hub name such as usb2."""
    return int(ROOT_ID.fullmatch(bus)[1])


def _list_entries(root):
    try:
        return list(root.iterdir())
    except OSError as error:
        raise EnforcementError(f"Cannot list USB root {root}: {error}") from error


def _write_flag(path, value, what):
    """Write a sysfs 0/1 flag, refusing any other value."""
    if value not in ("0", "1"):
        raise EnforcementError(f"Refusing to write invalid {what}: {value!r}")
    try:
        with path.open("w", encoding="utf-8") as handle:
            handle.write(value + "\n")
    except OSError as error:
        raise EnforcementError(f"Cannot write {what}: {error}") from error


@dataclass
class Config:
    managed_buses: object  # "auto" or a tuple of bus names such as ("usb2", "usb3")
    state_file: Path


def _parse_json(raw, what):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise EnforcementError(f"Invalid JSON in {what}: {error}") from error


def load_config(path):
    """Read and validate the enforcement config, returning a normalised Config."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EnforcementError(f"Cannot read config: {error}") from error
    if len(raw) > MAX_CONFIG_BYTES:
        raise EnforcementError("Config exceeds the 64 KiB limit")
    document = _parse_json(raw, "config")
    if not isinstance(document, dict):
        raise EnforcementError("Config must be a JSON object")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise EnforcementError("Config schema_version must be 1")

    buses = document.get("managed_buses", "auto")
    if buses != "auto":
        if not isinstance(buses, list) or not buses:
            raise EnforcementError('managed_buses must be "auto" or a non-empty list of bus names')
        seen = set()
        normalised = []
        for name in buses:
            if not isinstance(name, str) or not ROOT_ID.fullmatch(name):
                raise EnforcementError(f"Invalid bus name (expected usbN such as usb2): {name!r}")
            if name in seen:
                raise EnforcementError(f"Duplicate bus name: {name}")
            seen.add(name)
            normalised.append(name)
        buses = tuple(normalised)

    state_file = document.get("state_file", "logs/enforcement-state.json")
    if not isinstance(state_file, str) or not state_file:
        raise EnforcementError("state_file must be a non-empty string")
    state_path = Path(state_file)
    if not state_path.is_absolute():
        state_path = REPO_ROOT / state_path

    extra = set(document) - {"schema_version", "managed_buses", "state_file"}
    if extra:
        raise EnforcementError(f"Unknown config fields: {', '.join(sorted(extra))}")
    return Config(buses, state_path)


class BusManager:
    """Read and write per-bus authorized_default under an injectable sysfs root."""

    def __init__(self, config, root=USB_ROOT):
        self.config = config
        self.root = Path(root)

    def _default_path(self, bus):
        return self.root / bus / "authorized_default"

    def has_bus(self, bus):
        return self._default_path(bus).exists()

    def discover(self):
        """Return the sorted list of managed bus names that exist on this host."""
        if self.config.managed_buses == "auto":
            found = [p.name for p in _list_entries(self.root)
                     if ROOT_ID.fullmatch(p.name) and self.has_bus(p.name)]
            if not found:
                raise EnforcementError(f"No USB buses with authorized_default under {self.root}")
            return sorted(found, key=bus_number)
        missing = [bus for bus in self.config.managed_buses if not self.has_bus(bus)]
        if missing:
            raise EnforcementError(f"Configured buses not found on this host: {', '.join(missing)}")
        return sorted(self.config.managed_buses, key=bus_number)

    def read_default(self, bus):
        try:
            value = self._default_path(bus).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise EnforcementError(f"Cannot read authorized_default for {bus}: {error}") from error
        if value not in ("0", "1"):
            raise EnforcementError(f"Unexpected authorized_default for {bus}: {value!r}")
        return value

    def write_default(self, bus, value):
        _write_flag(self._default_path(bus), value, f"authorized_default for {bus}")


def _write_state_atomic(path, document):
    """Write the state file via a temp file and os.replace so it is never half-written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".enforcement-",
                                         suffix=".tmp", delete=False) as handle:
            tmp = Path(handle.name)
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # NamedTemporaryFile creates the file 0600, so after a root arm a non-root `status`
        # could not read it. It holds only bus names and 0/1 values, so make it world-readable.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()


def load_state(path):
    """Return the saved arm state, or None if the buses have not been armed."""
    path = Path(path)
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8")
    document = _parse_json(raw, "state file")
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION \
            or not isinstance(document.get("buses"), dict):
        raise EnforcementError("Malformed enforcement state file")
    return document


def arm(manager, state_path, apply=False):
    """Save original defaults (first time only) and set authorized_default=0.

    With apply=False (the default) nothing is written; the planned actions are returned.
    """
    buses = manager.discover()
    state = load_state(state_path) or {"schema_version": SCHEMA_VERSION, "buses": {}}
    saved = state["buses"]
    actions = []
    for bus in buses:
        current = manager.read_default(bus)
        already_saved = bus in saved
        original = saved[bus]["original_default"] if already_saved else current
        actions.append({"bus": bus, "current_default": current, "original_default": original,
                        "will_set": "0", "already_blocking": current == "0",
                        "original_recorded": already_saved})
    if apply:
        # Record every original before changing any bus, so a write that fails part-way
        # still leaves restore able to put back the buses that were already changed.
        for action in actions:
            saved.setdefault(action["bus"], {"original_default": action["original_default"]})
        state["armed_at"] = time.time()
        _write_state_atomic(Path(state_path), state)
        for action in actions:
            manager.write_default(action["bus"], "0")
    return {"type": "enforcement_arm", "applied": apply, "dry_run": not apply,
            "state_file": str(state_path), "buses": actions}


def restore(manager, state_path, apply=False):
    """Write saved original defaults back and clear the state file."""
    state = load_state(state_path)
    if state is None:
        return {"type": "enforcement_restore", "applied": apply, "dry_run": not apply,
                "state_file": str(state_path), "buses": [],
                "message": "No state file; nothing to restore"}
    actions = []
    for bus, record in sorted(state["buses"].items(), key=lambda item: bus_number(item[0])):
        original = record.get("original_default")
        if original not in ("0", "1"):
            raise EnforcementError(f"State file has invalid original_default for {bus}: {original!r}")
        present = manager.has_bus(bus)
        current = manager.read_default(bus) if present else None
        actions.append({"bus": bus, "current_default": current, "restore_to": original,
                        "present": present})
    if apply:
        for action in actions:
            if action["present"]:
                manager.write_default(action["bus"], action["restore_to"])
        Path(state_path).unlink(missing_ok=True)
    return {"type": "enforcement_restore", "applied": apply, "dry_run": not apply,
            "state_file": str(state_path), "buses": actions}


def status(manager, state_path):
    """Report each managed bus's current default-authorisation and whether it is armed."""
    buses = manager.discover()
    state = load_state(state_path)
    saved = state["buses"] if state else {}
    rows = []
    for bus in buses:
        current = manager.read_default(bus)
        rows.append({"bus": bus, "current_default": current,
                     "blocking_new_devices": current == "0",
                     "original_recorded": bus in saved,
                     "original_default": saved.get(bus, {}).get("original_default")})
    return {"type": "enforcement_status", "state_file": str(state_path),
            "armed": state is not None, "buses": rows}


class DeviceHandle:
    """One device instance, fixed when the handle is opened; writes reach it or fail.

    A USB port path such as 2-1 is reused when a device is replaced, so validating by
    path and then writing by path can authorise a different device. The handle records
    the device directory's (st_dev, st_ino) and opens its ``authorized`` attribute before
    the identity is read. Every check and write then refers to that instance: a changed
    directory is refused, and on Linux a held sysfs file of a removed device rejects the
    write (ENODEV) instead of reaching the new occupant of the port.
    """

    def __init__(self, root, usb_id, writable):
        try:
            identifier(usb_id)  # rejects paths such as ../ before any filesystem access
        except ValueError as error:
            raise DeviceError("invalid_usb_id", str(error)) from error
        self.usb_id = usb_id
        self.directory = Path(root) / usb_id
        self.instance = self._current_instance()
        try:
            self.file = (self.directory / "authorized").open("r+b" if writable else "rb")
        except FileNotFoundError as error:
            raise DeviceError("device_unavailable", f"Device {usb_id} is not present") from error
        except OSError as error:
            raise DeviceError("device_read_error", f"Cannot open authorized for {usb_id}: {error}") from error

    def _current_instance(self):
        try:
            stat = os.stat(self.directory)
        except FileNotFoundError as error:
            raise DeviceError("device_unavailable", f"Device {self.usb_id} is not present") from error
        except OSError as error:
            raise DeviceError("device_read_error", f"Cannot stat {self.usb_id}: {error}") from error
        return stat.st_dev, stat.st_ino

    def check(self):
        """Raise device_changed unless the port still holds the instance bound at open."""
        if self._current_instance() != self.instance:
            raise DeviceError("device_changed", f"A different device now occupies {self.usb_id}")

    def write(self, value):
        if value not in ("0", "1"):
            raise EnforcementError(f"Refusing to write invalid authorized value: {value!r}")
        self.check()
        try:
            self.file.seek(0)
            self.file.write(value.encode("ascii") + b"\n")
            self.file.flush()
        except OSError as error:
            raise EnforcementError(f"Cannot write authorized for {self.usb_id}: {error}") from error

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


class DeviceController:
    """Read a device's identity and write its per-device ``authorized`` flag.

    Shares the sysfs root with BusManager and reuses the policy component's
    DeviceReader, so identity reads here match those used to make the decision.
    """

    def __init__(self, root=USB_ROOT):
        self.root = Path(root)
        self.reader = DeviceReader(str(self.root))

    def _authorized_path(self, usb_id):
        return self.root / usb_id / "authorized"

    def bind(self, usb_id, writable):
        """Open a DeviceHandle; read and validate the device only after this call."""
        return DeviceHandle(self.root, usb_id, writable)

    def read(self, usb_id, expected_address=None):
        return self.reader.read(usb_id, expected_address=expected_address)

    def set_authorized(self, usb_id, value, handle):
        """Write through ``handle`` so the write reaches the validated instance or fails."""
        handle.write(value)

    def managed_device_ids(self, buses):
        """Non-root devices currently present on the given managed buses, sorted."""
        bus_numbers = {bus_number(bus) for bus in buses}
        found = []
        for entry in _list_entries(self.root):
            try:
                bus, is_root = identifier(entry.name)
            except ValueError:
                continue
            if is_root or bus not in bus_numbers:
                continue
            if self._authorized_path(entry.name).exists():
                found.append(entry.name)
        return sorted(found, key=lambda name: (identifier(name)[0], name))


def _result(action, usb_id, device, *, applied, reason, **extra):
    return {"type": "enforcement_result", "action": action, "usb_id": usb_id,
            "enforcement_applied": applied, "reason": reason, "device": device, **extra}


def _identity_mismatch(device, expected):
    """Return the first identity field that disagrees with the decision, or None."""
    for field in ("vendor_id", "product_id", "serial"):
        if field in expected and device.get(field) != expected.get(field):
            return field
    return None


def authorize_device(controller, usb_id, policy_path, expected=None, apply=True):
    """Re-validate a device against the current policy, then authorise it if still allowed.

    ``expected`` is the device identity from the decision, if any. The device instance
    is bound first, then re-read from sysfs, its identity confirmed against ``expected``,
    and the policy reloaded and re-evaluated. The write goes through the bound handle, so
    a device that replaced the validated one is never authorised (DeviceError instead).
    """
    expected_address = expected.get("device_address") if expected else None
    with controller.bind(usb_id, writable=apply) as handle:
        device = controller.read(usb_id, expected_address=expected_address)
        handle.check()  # the record we read describes the instance the handle holds
        if device["is_root_hub"]:
            return _result("ignore", usb_id, device, applied=False, reason="root_hub")
        if expected:
            mismatch = _identity_mismatch(device, expected)
            if mismatch:
                return _result("block", usb_id, device, applied=False,
                               reason="identity_mismatch", mismatch_field=mismatch)
        policy = load_policy(policy_path)
        decision = evaluate(device, policy)
        if decision["action"] != "allow":
            return _result("block", usb_id, device, applied=False, reason=decision["reason"],
                           matched_rule=decision.get("matched_rule"),
                           policy_revision=policy.revision)
        if apply:
            controller.set_authorized(usb_id, "1", handle)
    return _result("allow", usb_id, device, applied=apply, reason="allowlist_match",
                   matched_rule=decision["matched_rule"], policy_revision=policy.revision)


def revoke_device(controller, usb_id, apply=True):
    """Block a device by writing authorized=0, whatever the policy says."""
    with controller.bind(usb_id, writable=apply) as handle:
        try:
            device = controller.read(usb_id)
        except DeviceError:
            device = None  # still block it: an unreadable device must not stay authorised
        if apply:
            controller.set_authorized(usb_id, "0", handle)  # refuses a replaced device
    return _result("block", usb_id, device, applied=apply, reason="revoked")


class DeviceEnforcer:
    """Act on the policy component's decisions: authorise allowed devices, keep others blocked.

    Also tracks the upstream pipeline's lifecycle and any failed writes, so the stream
    can end with an exit status that reflects what happened (see ``outcome``).
    """

    def __init__(self, controller, policy_path, clock=time.monotonic_ns,
                 max_age_ns=MAX_DECISION_AGE_NS, apply=True, managed_buses=None):
        self.controller = controller
        self.policy_path = policy_path
        self.clock = clock
        self.max_age_ns = max_age_ns
        self.apply = apply
        # None manages every bus; otherwise only devices on these bus numbers are touched.
        self.managed_buses = None if managed_buses is None else {bus_number(bus) for bus in managed_buses}
        self.monitor_healthy = None
        self.upstream_stopped = False
        self.upstream_degraded = False
        self.upstream_close_reason = None
        self.failures = 0
        self.input_errors = 0

    def _monitor_status(self, record):
        """Track the monitor's lifecycle; report health only when it changes, to avoid heartbeat noise."""
        monitor_type = record.get("monitor_type")
        if monitor_type == "monitor_starting":  # a new monitor session clears the previous one
            self.upstream_stopped = False
            self.upstream_degraded = record.get("reason") == "invalid_monitor_context"
        if monitor_type in ("monitor_stopped", "monitor_backend_stopped"):
            self.upstream_stopped = True
        if record.get("degraded") is True:
            self.upstream_degraded = True
        healthy = record.get("healthy")
        if type(healthy) is not bool or healthy == self.monitor_healthy:
            return None
        self.monitor_healthy = healthy
        return {"type": "enforcement_monitor_status", "healthy": healthy,
                "degraded": record.get("degraded"), "monitor_type": monitor_type,
                "session_id": record.get("session_id")}

    def outcome(self, interrupted):
        """Return (closing reason, ok). Only a deliberate or clean stop with no failures is ok."""
        if interrupted:
            reason = "requested_stop"
        elif self.upstream_close_reason == "requested_stop":
            reason = "upstream_requested_stop"
        elif self.upstream_stopped and not self.upstream_degraded:
            reason = "upstream_stopped"
        elif self.upstream_close_reason is not None:
            reason = "upstream_failed"
        else:
            reason = "unexpected_end_of_input"
        clean_stop = reason in ("requested_stop", "upstream_requested_stop", "upstream_stopped")
        return reason, clean_stop and not self.failures and not self.input_errors

    def _ensure_blocked(self, usb_id, expected):
        with self.controller.bind(usb_id, writable=self.apply) as handle:
            device = self.controller.read(usb_id, expected_address=expected["device_address"])
            handle.check()
            if device["is_root_hub"]:
                return _result("ignore", usb_id, device, applied=False, reason="root_hub")
            if device.get("kernel_authorized"):
                if self.apply:
                    self.controller.set_authorized(usb_id, "0", handle)
                return _result("block", usb_id, device, applied=self.apply, reason="revoked_unauthorised")
        return _result("block", usb_id, device, applied=False, reason="already_blocked")

    def _not_applied(self, kind, record, reason, context, **extra):
        """A record for a decision that changed nothing, keeping its device and connection context."""
        out = {"type": kind, "reason": reason, "usb_id": record.get("usb_id"),
               "requested_action": record.get("action"), "enforcement_applied": False,
               **extra, **context}
        if record.get("reason") is not None:
            out["policy_reason"] = record["reason"]
        return out

    def handle(self, record):
        if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
            self.input_errors += 1
            return {"type": "enforcement_input_error", "message": "Expected policy schema_version 1"}
        kind = record.get("type")
        if kind == "policy_monitor_status":
            return self._monitor_status(record)
        if kind == "policy_input_error":
            self.upstream_degraded = True  # the watcher received bad input; mirrors its own exit status
            return None
        if kind == "policy_stream_closed":
            self.upstream_close_reason = record.get("reason")
            return None
        if kind != "policy_decision":
            return None  # policy_skipped: not ours to act on
        usb_id = record.get("usb_id")
        context = {"connection_id": record.get("connection_id"), "session_id": record.get("session_id")}
        action = record.get("action")
        if action not in ("allow", "block"):
            return self._not_applied("enforcement_skipped", record, action or "unknown", context)
        try:
            bus, _ = identifier(usb_id)
        except ValueError:
            return self._not_applied("enforcement_skipped", record, "invalid_usb_id", context)
        if self.managed_buses is not None and bus not in self.managed_buses:
            return self._not_applied("enforcement_skipped", record, "unmanaged_bus", context)
        expected = record.get("device")
        address = expected.get("device_address") if isinstance(expected, dict) else None
        timestamp = record.get("decision_timestamp_ns")
        # Without a decision time and the device address, the decision cannot be tied to the
        # connection now on the port (a newer device may be there), so it must not drive any
        # write, block included. Newly connected devices stay blocked by default-deny.
        if type(timestamp) is not int or type(address) is not int:
            return self._not_applied("enforcement_skipped", record, "uncorrelated_decision", context)
        if not 0 <= self.clock() - timestamp <= self.max_age_ns:
            return self._not_applied("enforcement_skipped", record, "stale_decision", context)
        try:
            if action == "allow":
                result = authorize_device(self.controller, usb_id, self.policy_path,
                                          expected=expected, apply=self.apply)
            else:
                result = self._ensure_blocked(usb_id, expected)
        except DeviceError as error:
            # Device gone, replaced or unreadable: nothing was written, so claim no state.
            return self._not_applied("enforcement_skipped", record, error.code, context,
                                     message=str(error))
        except PolicyError as error:
            return self._not_applied("enforcement_skipped", record, "invalid_policy", context,
                                     message=str(error))
        except EnforcementError as error:
            self.failures += 1  # a sysfs write failed: report it with context and fail the stream
            return self._not_applied("enforcement_error", record, "sysfs_write_failed", context,
                                     message=str(error))
        event_timestamp = record.get("event_timestamp_ns")
        if type(event_timestamp) is int:
            result["enforcement_latency_ns"] = self.clock() - event_timestamp
        if record.get("reason") is not None:
            result["policy_reason"] = record["reason"]  # why the policy decided, for the audit trail
        result.update(context)
        return result


def reconcile(controller, bus_manager, policy_path, apply=True):
    """Evaluate devices already present on managed buses and authorise the allowed ones.

    Non-allowed devices are never revoked, so existing input devices and hubs are not cut
    off. One that is still blocked is reported as ``block``; one that is already authorised
    is reported as ``unchanged``, so a consumer cannot mistake it for a device that was blocked.
    This covers devices connected before the service.
    """
    buses = bus_manager.discover()
    results = []
    failures = 0
    for usb_id in controller.managed_device_ids(buses):
        try:
            result = authorize_device(controller, usb_id, policy_path, expected=None, apply=apply)
            device = result["device"]
            if result["action"] == "block" and device and device.get("kernel_authorized"):
                result.update(action="unchanged", policy_reason=result["reason"],
                              reason="not_allowlisted_left_unchanged")
            results.append(result)
        except DeviceError as error:
            results.append(_result("block", usb_id, None, applied=False, reason=error.code))
        except PolicyError as error:
            results.append(_result("block", usb_id, None, applied=False,
                                   reason="invalid_policy", message=str(error)))
        except EnforcementError as error:
            failures += 1  # keep sweeping the other devices, but report this one as failed
            results.append({"type": "enforcement_error", "usb_id": usb_id, "requested_action": "allow",
                            "enforcement_applied": False, "reason": "sysfs_write_failed",
                            "message": str(error)})
    return {"type": "enforcement_reconcile", "applied": apply, "dry_run": not apply,
            "buses": buses, "failures": failures, "devices": results}


def process_stream(enforcer, stream):
    """Enforce each NDJSON line from ``stream`` and end with an enforcement_stream_closed record.

    Returns 0 only for a deliberate stop (Ctrl+C here or upstream) or a clean upstream
    stop with no failed writes or bad input; otherwise 1, so a lost or failed pipeline
    is visible to whatever runs this stage.
    """
    interrupted = False
    try:
        for line in stream:
            if not line.strip():
                continue
            try:
                record = enforcer.handle(_parse_json(line, "decision stream"))
            except EnforcementError as error:  # only unparseable input reaches here
                enforcer.input_errors += 1
                record = {"type": "enforcement_input_error", "message": str(error)}
            if record is not None:
                emit(record)
    except KeyboardInterrupt:
        interrupted = True  # Ctrl+C is a deliberate stop, not an error
    reason, ok = enforcer.outcome(interrupted)
    emit({"type": "enforcement_stream_closed", "reason": reason, "ok": ok,
          "failures": enforcer.failures, "input_errors": enforcer.input_errors})
    return 0 if ok else 1


def enforce(controller, bus_manager, policy_path, apply=True):
    """Read policy decisions as NDJSON on stdin and enforce each one on the managed buses."""
    require_linux()
    if sys.stdin.isatty():
        raise EnforcementError("Pipe the policy watcher's JSON into enforce; see docs/STEP5-TESTING.md")
    policy = load_policy(policy_path)
    buses = bus_manager.discover()
    # Enforcement relies on default-deny to keep new devices blocked; flag any bus not armed.
    unarmed = [bus for bus in buses if bus_manager.read_default(bus) != "0"]
    enforcer = DeviceEnforcer(controller, policy_path, apply=apply, managed_buses=buses)
    emit({"type": "enforcement_started", "apply": apply, "policy_revision": policy.revision,
          "managed_buses": buses, "unarmed_buses": unarmed})
    return process_stream(enforcer, sys.stdin)


def make_parser():
    """Build the CLI: global --config/--usb-root/--policy plus the enforcement subcommands."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Enforcement config JSON")
    parser.add_argument("--usb-root", type=Path, default=USB_ROOT,
                        help="sysfs USB device root (for testing)")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY,
                        help="Allowlist policy JSON used for re-validation")
    sub = parser.add_subparsers(dest="command", required=True)
    arm_parser = sub.add_parser("arm", help="Set default-deny on managed buses (dry run unless --apply)")
    arm_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    restore_parser = sub.add_parser("restore", help="Restore saved original defaults (dry run unless --apply)")
    restore_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    sub.add_parser("status", help="Show current and recorded default-authorisation per bus")
    authorize_parser = sub.add_parser(
        "authorize", help="Re-validate one device and authorise it if allowed (dry run unless --apply)")
    authorize_parser.add_argument("usb_id")
    authorize_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    revoke_parser = sub.add_parser("revoke", help="Block one device (dry run unless --apply)")
    revoke_parser.add_argument("usb_id")
    revoke_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    reconcile_parser = sub.add_parser(
        "reconcile", help="Evaluate devices already present on managed buses (dry run unless --apply)")
    reconcile_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    enforce_parser = sub.add_parser("enforce", help="Read policy decisions on stdin and enforce them")
    enforce_parser.add_argument("--dry-run", action="store_true", help="Decide and report without writing")
    return parser


def main(argv=None):
    """Dispatch one CLI command and emit its JSON result; return a process exit code."""
    args = make_parser().parse_args(argv)
    try:
        if args.command in ("arm", "restore", "status", "reconcile", "enforce"):
            # Commands that are scoped to the managed buses need the enforcement config.
            config = load_config(args.config)
            manager = BusManager(config, root=args.usb_root)
        if args.command == "arm":
            emit(arm(manager, config.state_file, apply=args.apply))
        elif args.command == "restore":
            emit(restore(manager, config.state_file, apply=args.apply))
        elif args.command == "status":
            emit(status(manager, config.state_file))
        else:
            require_linux()
            controller = DeviceController(root=args.usb_root)
            if args.command == "authorize":
                emit(authorize_device(controller, args.usb_id, args.policy, apply=args.apply))
            elif args.command == "revoke":
                emit(revoke_device(controller, args.usb_id, apply=args.apply))
            elif args.command == "reconcile":
                result = reconcile(controller, manager, args.policy, apply=args.apply)
                emit(result)
                return 1 if result["failures"] else 0
            else:
                return enforce(controller, manager, args.policy, apply=not args.dry_run)
        return 0
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
        return 1
    except (EnforcementError, PolicyError, DeviceError, ValueError, OSError) as error:
        emit({"type": "enforcement_error", "message": str(error)})
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
