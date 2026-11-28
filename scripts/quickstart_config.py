#!/usr/bin/env python3
"""Create the quick-start configuration in logs/ from the drive saved in step 4."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
DEVICE = "logs/quick-device.json"
DEMO_DIR = "build/test-tmp/quickstart"
STATE = "logs/quick-state.json"


class SetupError(Exception):
    pass


def describe(device):
    name = " ".join(part for part in (device.get("manufacturer"), device.get("product")) if part)
    return (f'{device["usb_id"]:<8} bus {device["bus"]:<3} {device["vendor_id"]}:{device["product_id"]}  '
            f'{name or "(no name)"}  serial {device.get("serial") or "-"}')


def protected_file(value):
    """Return an extra file to protect as an absolute path, refusing anything that is not a plain file."""
    path = Path(value).expanduser().absolute()
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise SetupError(f"File to protect does not exist (create it first): {path}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SetupError(f"Only regular files can be protected, not folders or symlinks: {path}")
    # The guard refuses symlinks anywhere in the path, so store the real location.
    return str(path.resolve())


def documents(device, demo, extra, single_bus=False):
    rule = {"name": "trusted-usb", "vendor_id": device["vendor_id"], "product_id": device["product_id"]}
    if device.get("serial"):
        rule["serial"] = device["serial"]

    def service(policy):
        return {"schema_version": 1, "policy": policy,
                "enforcement": "logs/quick-enforcement.json",
                "responses": "logs/quick-responses.json",
                "lsm": None, "local_lsm": "logs/quick-lsm.json",
                "apply_responses": False}

    paths = list(dict.fromkeys([str(demo / "restricted.txt"), *extra]))
    return {
        "quick-allow.json": {"schema_version": 1, "default_action": "block", "allowlist": [rule]},
        "quick-block.json": {"schema_version": 1, "default_action": "block", "allowlist": []},
        # "auto" arms every bus, so a device on another port or controller is still blocked.
        "quick-enforcement.json": {"schema_version": 1,
                                   "managed_buses": ["usb" + str(device["bus"])] if single_bus else "auto",
                                   "state_file": STATE},
        "quick-responses.json": {"schema_version": 1, "cooldown_seconds": 30,
                                 "actions": [{"type": "lock_session"}]},
        "quick-lsm.json": {"schema_version": 1, "socket_path": "/run/portwatchman/lsm_controller.sock",
                           "protected_paths": paths},
        "quick-service-allow.json": service("logs/quick-allow.json"),
        "quick-service-block.json": service("logs/quick-block.json"),
    }


def load_device(path):
    """Return the device record saved by 'device_policy.py inspect' in step 4."""
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        raise SetupError(f"{DEVICE} not found. Run step 4 first.") from None
    except (OSError, ValueError) as error:
        raise SetupError(f"Cannot read {DEVICE} ({error}). Run step 4 again.") from None
    device = record.get("device") if isinstance(record, dict) else None
    if not isinstance(device, dict) or record.get("type") != "device_identified" or not all(
            key in device for key in ("usb_id", "bus", "vendor_id", "product_id", "is_root_hub")):
        raise SetupError(f"{DEVICE} is not a device record. Check the USB ID and run step 4 again.")
    return device


def create(root, extra, single_bus=False):
    """Write the configuration and demo files under root; return the device and documents."""
    state = root / STATE
    if state.exists() or Path(str(state) + ".service-owner.json").exists():
        raise SetupError("A previous run was not restored (logs/quick-state.json exists). "
                         "See 'If something goes wrong' in the quick start.")
    device = load_device(root / DEVICE)
    if device["is_root_hub"] or device.get("device_class") == "09":
        raise SetupError(f"{device['usb_id']} is a hub, not a drive. Pick your flash drive in step 4.")
    extra = [protected_file(value) for value in extra]

    demo = (root / DEMO_DIR).resolve()
    demo.mkdir(parents=True, exist_ok=True)
    (demo / "restricted.txt").write_text("Protected VM file\n")
    (demo / "control.txt").write_text("Readable control file\n")
    (root / "logs").mkdir(exist_ok=True)
    docs = documents(device, demo, extra, single_bus)
    for name, document in docs.items():
        (root / "logs" / name).write_text(json.dumps(document, indent=2) + "\n")
    return device, docs


def main(argv=None, root=ROOT):
    parser = argparse.ArgumentParser(description="Create the PortWatchman quick-start configuration in logs/ from logs/quick-device.json.")
    parser.add_argument("--protect", action="append", default=[], metavar="FILE",
                        help="Extra VM file to protect while the service runs (repeatable)")
    parser.add_argument("--single-bus", action="store_true",
                        help="Manage only the drive's bus instead of every bus (devices on other ports are not blocked)")
    args = parser.parse_args(argv)
    try:
        device, docs = create(Path(root), args.protect, args.single_bus)
    except SetupError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Drive:            {describe(device)}")
    buses = docs["quick-enforcement.json"]["managed_buses"]
    print(f"Managed USB buses: {'all (auto)' if buses == 'auto' else ', '.join(buses)}")
    print("Protected files:")
    for path in docs["quick-lsm.json"]["protected_paths"]:
        print(f"  {path}")
    print("Configuration created in logs/. Next, check both profiles:")
    print("  sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json check")
    print("  sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
