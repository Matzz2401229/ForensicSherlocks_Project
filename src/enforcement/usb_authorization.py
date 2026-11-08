#!/usr/bin/env python3
"""Arm and restore USB default-deny on managed buses (step 5, slice 1).

This module manages the per-bus ``authorized_default`` flag in sysfs so that newly
connected USB devices start blocked. It deliberately does NOT yet make per-device
allow/block decisions or write per-device ``authorized`` flags -- that is slice 2.

Design notes:
- The sysfs root is injectable so the logic is unit-testable without real hardware.

- ``arm`` defaults to a dry run: it prints what it would write and changes nothing.
  Real writes require ``--apply`` (and root privileges on a live system).

- Original ``authorized_default`` values are saved to a state file on the first arm
  and are never overwritten by a re-arm, so ``restore`` always puts back the true
  pre-PortWatchman values even if ``arm`` is run several times.
  
- The multi-controller finding (a device can enumerate on different buses across
  reconnects) is why ``auto`` mode arms every bus, not a single controller.
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

    def discover(self):
        """Return the sorted list of managed bus names that exist on this host."""
        if self.config.managed_buses == "auto":
            try:
                entries = list(self.root.iterdir())
            except OSError as error:
                raise EnforcementError(f"Cannot list USB root {self.root}: {error}") from error
            found = [p.name for p in entries
                     if ROOT_ID.fullmatch(p.name) and self._default_path(p.name).exists()]
            if not found:
                raise EnforcementError(f"No USB buses with authorized_default under {self.root}")
            return sorted(found, key=self._bus_sort_key)
        missing = [bus for bus in self.config.managed_buses if not self._default_path(bus).exists()]
        if missing:
            raise EnforcementError(f"Configured buses not found on this host: {', '.join(missing)}")
        return sorted(self.config.managed_buses, key=self._bus_sort_key)

    @staticmethod
    def _bus_sort_key(bus):
        return int(ROOT_ID.fullmatch(bus)[1])

    def read_default(self, bus):
        try:
            value = self._default_path(bus).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise EnforcementError(f"Cannot read authorized_default for {bus}: {error}") from error
        if value not in ("0", "1"):
            raise EnforcementError(f"Unexpected authorized_default for {bus}: {value!r}")
        return value

    def write_default(self, bus, value):
        if value not in ("0", "1"):
            raise EnforcementError(f"Refusing to write invalid authorized_default: {value!r}")
        try:
            with self._default_path(bus).open("w", encoding="utf-8") as handle:
                handle.write(value + "\n")
        except OSError as error:
            raise EnforcementError(f"Cannot write authorized_default for {bus}: {error}") from error


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
        for action in actions:
            bus = action["bus"]
            if bus not in saved:
                saved[bus] = {"original_default": action["original_default"]}
            manager.write_default(bus, "0")
        state["armed_at"] = time.time()
        _write_state_atomic(Path(state_path), state)
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
    for bus, record in sorted(state["buses"].items(), key=lambda kv: BusManager._bus_sort_key(kv[0])):
        original = record.get("original_default")
        if original not in ("0", "1"):
            raise EnforcementError(f"State file has invalid original_default for {bus}: {original!r}")
        present = manager._default_path(bus).exists()
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

    def read(self, usb_id, expected_address=None):
        return self.reader.read(usb_id, expected_address=expected_address)

    def set_authorized(self, usb_id, value):
        if value not in ("0", "1"):
            raise EnforcementError(f"Refusing to write invalid authorized value: {value!r}")
        try:
            with self._authorized_path(usb_id).open("w", encoding="utf-8") as handle:
                handle.write(value + "\n")
        except OSError as error:
            raise EnforcementError(f"Cannot write authorized for {usb_id}: {error}") from error

    def managed_device_ids(self, buses):
        """Non-root devices currently present on the given managed buses, sorted."""
        bus_numbers = {int(ROOT_ID.fullmatch(bus)[1]) for bus in buses}
        found = []
        try:
            entries = list(self.root.iterdir())
        except OSError as error:
            raise EnforcementError(f"Cannot list USB root {self.root}: {error}") from error
        for entry in entries:
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

    ``expected`` is the device identity from the decision, if any. The device is
    re-read from sysfs, its identity is confirmed against ``expected``, and the policy
    is reloaded and re-evaluated before any write. A device that no longer matches, or
    is no longer allowed, is left blocked.
    """
    expected_address = expected.get("device_address") if expected else None
    device = controller.read(usb_id, expected_address=expected_address)
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
        controller.set_authorized(usb_id, "1")
    return _result("allow", usb_id, device, applied=apply, reason="allowlist_match",
                   matched_rule=decision["matched_rule"], policy_revision=policy.revision)


def revoke_device(controller, usb_id, apply=True):
    """Block a device by writing authorized=0, whatever the policy says."""
    device = None
    try:
        device = controller.read(usb_id)
    except DeviceError:
        device = None
    if apply:
        controller.set_authorized(usb_id, "0")
    return _result("block", usb_id, device, applied=apply, reason="revoked")


class DeviceEnforcer:
    """Act on the policy component's decisions: authorise allowed devices, keep others blocked."""

    def __init__(self, controller, policy_path, clock=time.monotonic_ns,
                 max_age_ns=MAX_DECISION_AGE_NS, apply=True):
        self.controller = controller
        self.policy_path = policy_path
        self.clock = clock
        self.max_age_ns = max_age_ns
        self.apply = apply

    def _ensure_blocked(self, usb_id, expected):
        expected_address = (expected or {}).get("device_address")
        try:
            device = self.controller.read(usb_id, expected_address=expected_address)
        except DeviceError as error:
            return _result("block", usb_id, None, applied=False, reason=error.code)
        if device["is_root_hub"]:
            return _result("ignore", usb_id, device, applied=False, reason="root_hub")
        if device.get("kernel_authorized"):
            if self.apply:
                self.controller.set_authorized(usb_id, "0")
            return _result("block", usb_id, device, applied=self.apply, reason="revoked_unauthorised")
        return _result("block", usb_id, device, applied=False, reason="already_blocked")

    def handle(self, record):
        if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
            return {"type": "enforcement_input_error", "message": "Expected policy schema_version 1"}
        if record.get("type") != "policy_decision":
            return None  # monitor status, skips, stream-closed: not ours to act on
        usb_id = record.get("usb_id")
        context = {"connection_id": record.get("connection_id"), "session_id": record.get("session_id")}
        timestamp = record.get("decision_timestamp_ns")
        if type(timestamp) is int:
            age = self.clock() - timestamp
            if not 0 <= age <= self.max_age_ns:
                return {"type": "enforcement_skipped", "reason": "stale_decision",
                        "usb_id": usb_id, **context}
        action = record.get("action")
        expected = record.get("device")
        try:
            if action == "allow":
                result = authorize_device(self.controller, usb_id, self.policy_path,
                                          expected=expected, apply=self.apply)
            elif action == "block":
                result = self._ensure_blocked(usb_id, expected)
            else:
                return {"type": "enforcement_skipped", "reason": action or "unknown",
                        "usb_id": usb_id, **context}
        except DeviceError as error:
            result = _result("block", usb_id, None, applied=False, reason=error.code)
        except PolicyError as error:
            result = _result("block", usb_id, None, applied=False, reason="invalid_policy",
                             message=str(error))
        event_timestamp = record.get("event_timestamp_ns")
        if type(event_timestamp) is int:
            result["enforcement_latency_ns"] = self.clock() - event_timestamp
        result.update(context)
        return result


def reconcile(controller, bus_manager, policy_path, apply=True):
    """Evaluate devices already present on managed buses and authorise the allowed ones.

    Non-allowed devices are reported but left blocked (not revoked), so existing input
    devices and hubs are not cut off. This covers devices connected before the service.
    """
    buses = bus_manager.discover()
    results = []
    for usb_id in controller.managed_device_ids(buses):
        try:
            results.append(authorize_device(controller, usb_id, policy_path,
                                             expected=None, apply=apply))
        except DeviceError as error:
            results.append(_result("block", usb_id, None, applied=False, reason=error.code))
        except PolicyError as error:
            results.append(_result("block", usb_id, None, applied=False,
                                   reason="invalid_policy", message=str(error)))
    return {"type": "enforcement_reconcile", "applied": apply, "dry_run": not apply,
            "buses": buses, "devices": results}


def enforce(controller, policy_path, apply=True):
    """Read policy decisions as NDJSON on stdin and enforce each one."""
    require_linux()
    if sys.stdin.isatty():
        raise EnforcementError("Pipe the policy watcher's JSON into enforce; see docs/STEP5-TESTING.md")
    load_policy(policy_path)
    enforcer = DeviceEnforcer(controller, policy_path, apply=apply)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            record = enforcer.handle(_parse_json(line, "decision stream"))
        except EnforcementError as error:
            record = {"type": "enforcement_input_error", "message": str(error)}
        if record is not None:
            emit(record)
    return 0


def require_linux():
    if sys.platform != "linux":
        raise EnforcementError("Live USB authorisation runs inside the Ubuntu VM")


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
    authorize_parser = sub.add_parser("authorize", help="Re-validate one device and authorise it if allowed (dry run unless --apply)")
    authorize_parser.add_argument("usb_id")
    authorize_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    revoke_parser = sub.add_parser("revoke", help="Block one device (dry run unless --apply)")
    revoke_parser.add_argument("usb_id")
    revoke_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    reconcile_parser = sub.add_parser("reconcile", help="Evaluate devices already present on managed buses (dry run unless --apply)")
    reconcile_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    enforce_parser = sub.add_parser("enforce", help="Read policy decisions on stdin and enforce them")
    enforce_parser.add_argument("--dry-run", action="store_true", help="Decide and report without writing")
    return parser


def main(argv=None):
    """Dispatch one CLI command and emit its JSON result; return a process exit code."""
    args = make_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        manager = BusManager(config, root=args.usb_root)
        if args.command == "arm":
            emit(arm(manager, config.state_file, apply=args.apply))
        elif args.command == "restore":
            emit(restore(manager, config.state_file, apply=args.apply))
        elif args.command == "status":
            emit(status(manager, config.state_file))
        elif args.command in ("authorize", "revoke", "reconcile", "enforce"):
            require_linux()
            controller = DeviceController(root=args.usb_root)
            if args.command == "authorize":
                emit(authorize_device(controller, args.usb_id, args.policy, apply=args.apply))
            elif args.command == "revoke":
                emit(revoke_device(controller, args.usb_id, apply=args.apply))
            elif args.command == "reconcile":
                emit(reconcile(controller, manager, args.policy, apply=args.apply))
            else:
                return enforce(controller, args.policy, apply=not args.dry_run)
        return 0
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
        return 1
    except EnforcementError as error:
        emit({"type": "enforcement_error", "message": str(error)})
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
