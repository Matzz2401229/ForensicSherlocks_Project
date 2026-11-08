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
USB_ROOT = Path("/sys/bus/usb/devices")
ROOT_ID = re.compile(r"usb([1-9][0-9]*)\Z")
MAX_CONFIG_BYTES = 65536


class EnforcementError(RuntimeError):
    pass


def emit(record):
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


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Enforcement config JSON")
    parser.add_argument("--usb-root", type=Path, default=USB_ROOT,
                        help="sysfs USB device root (for testing)")
    sub = parser.add_subparsers(dest="command", required=True)
    arm_parser = sub.add_parser("arm", help="Set default-deny on managed buses (dry run unless --apply)")
    arm_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    restore_parser = sub.add_parser("restore", help="Restore saved original defaults (dry run unless --apply)")
    restore_parser.add_argument("--apply", action="store_true", help="Actually write; otherwise dry run")
    sub.add_parser("status", help="Show current and recorded default-authorisation per bus")
    return parser


def main(argv=None):
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
