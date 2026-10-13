#!/usr/bin/env python3
"""Identify USB devices and produce allowlist decisions without enforcing them."""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "config" / "allowlist.json"
USB_ID = re.compile(r"([1-9][0-9]*)-([1-9][0-9]*(?:\.[1-9][0-9]*)*)\Z")
ROOT_ID = re.compile(r"usb([1-9][0-9]*)\Z")
HEX4 = re.compile(r"[0-9a-fA-F]{4}\Z")
HEX2 = re.compile(r"[0-9a-fA-F]{2}\Z")


class PolicyError(ValueError):
    pass


class DeviceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def emit(record):
    print(json.dumps({"schema_version": 1, **record}, separators=(",", ":")), flush=True)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError) as error:
        raise PolicyError(f"Invalid JSON: {error}") from error


def identifier(value, *, roots=True):
    if not isinstance(value, str) or len(value) > 32:
        raise ValueError("USB ID must be a device name such as 2-1 or 2-1.2")
    match = USB_ID.fullmatch(value)
    if match:
        return int(match[1]), False
    match = ROOT_ID.fullmatch(value) if roots else None
    if match:
        return int(match[1]), True
    raise ValueError("Invalid USB ID (paths and interface names are not accepted)")


def plain_string(value, field, limit=255):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise PolicyError(f"{field} must be a nonempty string of at most {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PolicyError(f"{field} cannot contain control characters")
    return value


def validate_document(document):
    if not isinstance(document, dict) or set(document) != {"schema_version", "default_action", "allowlist"}:
        raise PolicyError("Policy must contain exactly schema_version, default_action, and allowlist")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise PolicyError("schema_version must be integer 1")
    if document["default_action"] != "block":
        raise PolicyError("default_action must be block")
    rules = document["allowlist"]
    if not isinstance(rules, list) or len(rules) > 256:
        raise PolicyError("allowlist must be a list containing at most 256 rules")
    normalised = []
    names = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"Rule {index} must be an object")
        required = {"name", "vendor_id", "product_id"}
        if not required <= set(rule) or set(rule) - required - {"serial", "usb_id"}:
            raise PolicyError(f"Rule {index} has missing or unsupported fields")
        name = plain_string(rule["name"], "rule name", 128)
        if name in names:
            raise PolicyError(f"Duplicate rule name: {name}")
        names.add(name)
        result = {"name": name}
        for field in ("vendor_id", "product_id"):
            value = rule[field]
            if not isinstance(value, str) or not HEX4.fullmatch(value):
                raise PolicyError(f"{field} must be a quoted four-digit hexadecimal string")
            result[field] = value.lower()
        if "serial" in rule:
            result["serial"] = plain_string(rule["serial"], "serial")
        if "usb_id" in rule:
            try:
                identifier(rule["usb_id"], roots=False)
            except ValueError as error:
                raise PolicyError(str(error)) from error
            result["usb_id"] = rule["usb_id"]
        normalised.append(result)
    return {"schema_version": 1, "default_action": "block", "allowlist": normalised}


@dataclass(frozen=True)
class Policy:
    document: dict
    revision: str


def load_policy(path):
    try:
        with Path(path).open("rb") as source:
            raw = source.read(65537)
    except OSError as error:
        raise PolicyError(f"Cannot read policy: {error}") from error
    if len(raw) > 65536:
        raise PolicyError("Policy exceeds the 64 KiB limit")
    document = validate_document(parse_json(raw))
    return Policy(document, hashlib.sha256(raw).hexdigest())


def write_policy(path, document):
    document = validate_document(document)
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".allowlist-",
                                         suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            json.dump(document, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


class DeviceReader:
    def __init__(self, root="/sys/bus/usb/devices"):
        self.root = Path(root)

    def _text(self, directory, name, optional=False):
        try:
            with (directory / name).open("r", encoding="utf-8") as source:
                value = source.read(4097)
        except FileNotFoundError:
            if optional:
                return None
            raise
        if len(value) > 4096 or "\x00" in value:
            raise DeviceError("invalid_device_attributes", f"Invalid attribute: {name}")
        return value.rstrip("\n")

    def _identity(self, directory):
        vendor = self._text(directory, "idVendor").strip()
        product = self._text(directory, "idProduct").strip()
        if not HEX4.fullmatch(vendor) or not HEX4.fullmatch(product):
            raise DeviceError("invalid_device_attributes", "Malformed USB vendor/product ID")
        bus = int(self._text(directory, "busnum").strip())
        address = int(self._text(directory, "devnum").strip())
        if not 1 <= bus <= 9999 or not 1 <= address <= 127:
            raise DeviceError("invalid_device_attributes", "Invalid USB bus/address")
        serial = self._text(directory, "serial", optional=True)
        if serial == "":
            serial = None
        return vendor.lower(), product.lower(), bus, address, serial

    def _once(self, usb_id, expected_address=None):
        bus_from_name, is_root = identifier(usb_id)
        directory = self.root / usb_id
        before = directory.stat()
        identity = self._identity(directory)
        vendor, product, bus, address, serial = identity
        if bus != bus_from_name:
            raise DeviceError("invalid_device_attributes", "USB ID and bus number disagree")
        if expected_address is not None and address != expected_address:
            raise DeviceError("stale_device", "Port now refers to a different USB device address")
        device_class = self._text(directory, "bDeviceClass", optional=True)
        if device_class is not None:
            device_class = device_class.strip().lower()
            if not HEX2.fullmatch(device_class):
                raise DeviceError("invalid_device_attributes", "Malformed device class")
        authorised = self._text(directory, "authorized", optional=True)
        if authorised is not None:
            authorised = authorised.strip()
            if authorised not in ("0", "1"):
                raise DeviceError("invalid_device_attributes", "Malformed authorisation state")
        record = {"usb_id": usb_id, "sysfs_path": str(directory), "bus": bus,
                  "device_address": address, "vendor_id": vendor, "product_id": product,
                  "serial": serial, "manufacturer": self._text(directory, "manufacturer", optional=True),
                  "product": self._text(directory, "product", optional=True),
                  "device_class": device_class,
                  "kernel_authorized": None if authorised is None else authorised == "1",
                  "is_root_hub": is_root}
        after = directory.stat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or self._identity(directory) != identity:
            raise DeviceError("device_changed", "Device changed while attributes were being read")
        return record

    def read(self, usb_id, expected_address=None, timeout=0.5):
        identifier(usb_id)
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self._once(usb_id, expected_address)
            except FileNotFoundError as error:
                if time.monotonic() >= deadline:
                    raise DeviceError("device_unavailable", "Device or required attributes unavailable") from error
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            except DeviceError:
                raise
            except (ValueError, UnicodeError) as error:
                raise DeviceError("invalid_device_attributes", str(error)) from error
            except OSError as error:
                raise DeviceError("device_read_error", str(error)) from error

    def list_ids(self):
        return sorted(path.name for path in self.root.iterdir()
                      if USB_ID.fullmatch(path.name) or ROOT_ID.fullmatch(path.name))


def evaluate(device, policy):
    base = {"type": "policy_decision", "usb_id": device["usb_id"], "device": device,
            "policy_revision": policy.revision, "enforcement_applied": False}
    if device["is_root_hub"]:
        return {**base, "action": "ignore", "reason": "root_hub", "matched_rule": None}
    mismatches = []
    for rule in policy.document["allowlist"]:
        fields = [field for field in ("vendor_id", "product_id", "serial", "usb_id")
                  if field in rule and device.get(field) != rule[field]]
        if not fields:
            return {**base, "action": "allow", "reason": "allowlist_match", "matched_rule": rule["name"]}
        mismatches.append({"rule": rule["name"], "fields": fields})
    return {**base, "action": "block", "reason": "no_matching_allowlist_rule",
            "matched_rule": None, "rule_mismatches": mismatches}


def blocked(usb_id, reason, message, **extra):
    return {"type": "policy_decision", "action": "block", "reason": reason,
            "message": message, "usb_id": usb_id, "device": None,
            "matched_rule": None, "enforcement_applied": False, **extra}


class PolicyProcessor:
    """Consume monitor v1 events; preserve monitor-health and generation checks."""
    def __init__(self, reader, policy_path, boot_id, clock=time.monotonic_ns, max_age_ns=2_000_000_000):
        self.reader = reader
        self.policy_path = policy_path
        self.boot_id = boot_id
        self.clock = clock
        self.max_age_ns = max_age_ns
        self.session = None
        self.healthy = False
        self.degraded = False
        self.stopped = False
        self.seen = OrderedDict()

    def handle(self, event):
        if not isinstance(event, dict) or type(event.get("schema_version")) is not int or event["schema_version"] != 1:
            self.healthy = False
            self.degraded = True
            return {"type": "policy_input_error", "message": "Expected monitor schema_version 1"}
        kind = event.get("type")
        session = event.get("session_id")
        if kind == "monitor_starting":
            if self.session is not None and session == self.session:
                if event.get("boot_id") != self.boot_id or event.get("clock") != "monotonic":
                    self.healthy = False
                    self.degraded = True
                return {"type": "policy_monitor_status", "monitor_type": kind,
                        "healthy": self.healthy, "degraded": self.degraded,
                        "session_id": session, "reason": "duplicate_start"}
            self.session = session if isinstance(session, str) and 0 < len(session) <= 128 else None
            self.degraded = event.get("boot_id") != self.boot_id or event.get("clock") != "monotonic" or self.session is None
            self.healthy = False
            self.stopped = False
            self.seen.clear()
            return {"type": "policy_monitor_status", "monitor_type": kind, "healthy": False,
                    "session_id": self.session, "reason": "starting" if not self.degraded else "invalid_monitor_context"}
        if self.session is None or session != self.session:
            self.healthy = False
            self.degraded = True
            return {"type": "policy_input_error", "message": "Missing or inconsistent monitor session"}
        if kind in ("monitor_alive", "monitor_heartbeat", "monitor_loss", "monitor_diagnostic",
                    "monitor_error", "monitor_stopped", "monitor_backend_stopped"):
            if kind == "monitor_heartbeat":
                loss = event.get("reported_lost_events")
                if type(event.get("degraded")) is not bool or type(loss) is not int or loss < 0:
                    self.degraded = True
                elif event["degraded"] or loss:
                    self.degraded = True
            if kind in ("monitor_loss", "monitor_diagnostic", "monitor_error"):
                self.degraded = True
            if kind in ("monitor_stopped", "monitor_backend_stopped"):
                self.stopped = True
                self.healthy = False
            elif kind in ("monitor_alive", "monitor_heartbeat"):
                self.healthy = not self.degraded and not self.stopped
            else:
                self.healthy = False
            return {"type": "policy_monitor_status", "monitor_type": kind,
                    "healthy": self.healthy, "degraded": self.degraded, "session_id": session}
        if kind in ("usb_setup_started", "usb_setup_failed", "usb_disconnect_started"):
            return {"type": "policy_skipped", "reason": kind, "usb_id": event.get("usb_id"),
                    "connection_id": event.get("connection_id"), "session_id": session}
        if kind != "usb_setup_completed":
            self.healthy = False
            self.degraded = True
            return {"type": "policy_input_error", "message": "Unsupported monitor record type"}

        usb_id = event.get("usb_id")
        context = {"connection_id": event.get("connection_id"), "session_id": session,
                   "event_timestamp_ns": event.get("timestamp_ns")}
        try:
            bus, is_root = identifier(usb_id)
            timestamp = event.get("timestamp_ns")
            start = event.get("setup_started_ns")
            address = event.get("device_address")
            if (event.get("source") != "ebpf" or event.get("clock") != "monotonic"
                    or type(timestamp) is not int or type(start) is not int
                    or not 0 < start <= timestamp or type(address) is not int or not 1 <= address <= 127
                    or type(event.get("bus")) is not int or event["bus"] != bus
                    or type(event.get("result")) is not int or event["result"] != 0
                    or type(event.get("duplicate")) is not bool):
                raise ValueError("Invalid completed-setup event")
            port = "0" if is_root else USB_ID.fullmatch(usb_id)[2]
            if event.get("port_path") != port or event.get("connection_id") != f"{self.boot_id}:{bus}-{port}:{start}":
                raise ValueError("Inconsistent USB generation/location")
            if event.get("sysfs_path") != f"/sys/bus/usb/devices/{usb_id}":
                raise ValueError("Unexpected sysfs path")
            age = self.clock() - timestamp
            if not 0 <= age <= self.max_age_ns:
                return blocked(usb_id, "stale_event", "Event is older than two seconds or has a future timestamp", **context)
            if is_root:
                return {"type": "policy_skipped", "reason": "root_hub", "usb_id": usb_id, **context}
            if not self.healthy:
                return blocked(usb_id, "monitor_unhealthy", "Monitor is not ready or has reported an error", **context)
            if event["duplicate"] or context["connection_id"] in self.seen:
                return {"type": "policy_skipped", "reason": "duplicate_event", "usb_id": usb_id, **context}
            policy = load_policy(self.policy_path)
            device = self.reader.read(usb_id, expected_address=address)
            if self.clock() - timestamp > self.max_age_ns:
                return blocked(usb_id, "stale_event", "Identification exceeded event freshness limit", **context)
            decision = evaluate(device, policy)
            self.seen[context["connection_id"]] = None
            if len(self.seen) > 1024:
                self.seen.popitem(last=False)
            return {**decision, **context, "decision_timestamp_ns": self.clock()}
        except PolicyError as error:
            return blocked(usb_id, "invalid_policy", str(error), **context)
        except DeviceError as error:
            return blocked(usb_id, error.code, str(error), **context)
        except ValueError as error:
            self.healthy = False
            self.degraded = True
            return blocked(usb_id, "invalid_event", str(error), **context)


def require_linux():
    if sys.platform != "linux":
        raise RuntimeError("Live sysfs identification runs inside the Ubuntu VM")


def watch(policy_path):
    require_linux()
    if sys.stdin.isatty():
        raise RuntimeError("Pipe the monitor's JSON output into watch; see docs/STEP4-TESTING.md")
    load_policy(policy_path)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    processor = PolicyProcessor(DeviceReader(), policy_path, boot_id)
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            if len(line) > 65536:
                processor.healthy = False
                processor.degraded = True
                emit({"type": "policy_input_error", "message": "Input line exceeds 64 KiB"})
                continue
            try:
                record = processor.handle(parse_json(line))
            except PolicyError as error:
                processor.healthy = False
                processor.degraded = True
                record = {"type": "policy_input_error", "message": str(error)}
            emit(record)
    except KeyboardInterrupt:
        emit({"type": "policy_stream_closed", "reason": "requested_stop", "healthy": False})
        return 0
    emit({"type": "policy_stream_closed", "reason": "end_of_input", "healthy": False})
    return 0 if processor.stopped and not processor.degraded else 1


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="Policy JSON file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Validate the policy file")
    sub.add_parser("list", help="Inspect currently visible USB devices")
    sub.add_parser("watch", help="Read live monitor JSON from stdin and produce decisions")
    inspect = sub.add_parser("inspect", help="Read one device's attributes")
    inspect.add_argument("usb_id")
    evaluate_parser = sub.add_parser("evaluate", help="Evaluate one device without changing access")
    evaluate_parser.add_argument("usb_id")
    add = sub.add_parser("add-rule", help="Add an allowlist rule to the selected local policy file")
    add.add_argument("--name", required=True)
    add.add_argument("--vendor-id", required=True)
    add.add_argument("--product-id", required=True)
    add.add_argument("--serial")
    add.add_argument("--usb-id")
    remove = sub.add_parser("remove-rule", help="Remove a named rule from the selected local policy file")
    remove.add_argument("--name", required=True)
    return parser


def main():
    args = make_parser().parse_args()
    try:
        if args.command == "validate":
            policy = load_policy(args.policy)
            emit({"type": "policy_validated", "status": "passed", "rule_count": len(policy.document["allowlist"]),
                  "policy_revision": policy.revision, "default_action": "block"})
        elif args.command in ("add-rule", "remove-rule"):
            policy = load_policy(args.policy)
            rules = policy.document["allowlist"]
            if args.command == "add-rule":
                rule = {"name": args.name, "vendor_id": args.vendor_id, "product_id": args.product_id}
                if args.serial is not None:
                    rule["serial"] = args.serial
                if args.usb_id is not None:
                    rule["usb_id"] = args.usb_id
                rules.append(rule)
            else:
                filtered = [rule for rule in rules if rule["name"] != args.name]
                if len(filtered) == len(rules):
                    raise PolicyError(f"Rule does not exist: {args.name}")
                policy.document["allowlist"] = filtered
            write_policy(args.policy, policy.document)
            emit({"type": "policy_updated", "operation": args.command, "name": args.name,
                  "policy_revision": load_policy(args.policy).revision})
        elif args.command == "watch":
            return watch(args.policy)
        else:
            require_linux()
            reader = DeviceReader()
            if args.command == "list":
                for usb_id in reader.list_ids():
                    try:
                        emit({"type": "device_identified", "device": reader.read(usb_id)})
                    except DeviceError as error:
                        emit({"type": "device_error", "usb_id": usb_id, "reason": error.code,
                              "message": str(error)})
            elif args.command == "inspect":
                emit({"type": "device_identified", "device": reader.read(args.usb_id)})
            elif args.command == "evaluate":
                try:
                    policy = load_policy(args.policy)
                    device = reader.read(args.usb_id)
                    emit(evaluate(device, policy))
                except PolicyError as error:
                    emit(blocked(args.usb_id, "invalid_policy", str(error)))
                    return 2
                except DeviceError as error:
                    emit(blocked(args.usb_id, error.code, str(error)))
                    return 2
        return 0
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
        return 1
    except (PolicyError, DeviceError, RuntimeError, ValueError, OSError) as error:
        emit({"type": "policy_error", "message": str(error)})
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
