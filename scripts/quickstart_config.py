#!/usr/bin/env python3
"""Create the quick-start configuration in logs/ from the drive saved in step A4.

The files to protect and the files to destroy are remembered in logs/quick-files.json,
so each run adds to (or removes from) the earlier selection instead of replacing it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
DEVICE = "logs/quick-device.json"
SELECTION = "logs/quick-files.json"
DEMO_DIR = "build/test-tmp/quickstart"
STATE = "logs/quick-state.json"
DESTROY_FILES = ("quick-responses-destroy.json", "quick-service-destroy.json")
ALLOW_FILES = ("quick-allow.json", "quick-service-allow.json")


class SetupError(Exception):
    pass


def describe(device):
    name = " ".join(part for part in (device.get("manufacturer"), device.get("product")) if part)
    return (f'{device["usb_id"]:<8} bus {device["bus"]:<3} {device["vendor_id"]}:{device["product_id"]}  '
            f'{name or "(no name)"}  serial {device.get("serial") or "-"}')


def protected_file(value):
    """Return a file to protect as an absolute path, refusing anything that is not a plain file."""
    path = Path(value).expanduser().absolute()
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise SetupError(f"File to protect does not exist (create it, or drop it with --unprotect): {path}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SetupError(f"Only regular files can be protected, not folders or symlinks: {path}")
    # The guard refuses symlinks anywhere in the path, so store the real location.
    return str(path.resolve())


def destroyed_entry(value):
    """Return a file or folder to destroy on trigger as an absolute path, refusing symlinks."""
    path = Path(value).expanduser().absolute()
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise SetupError(f"File to destroy does not exist (create it, or drop it with --undestroy): {path}") from None
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise SetupError(f"Only regular files or folders can be destroyed, not symlinks: {path}")
    return str(path.resolve())


def update_selection(root, args):
    """Merge this run's options into the saved selection and return it."""
    saved = {"protect": [], "destroy": []}
    path = root / SELECTION
    if path.exists() and not args.reset:
        try:
            document = json.loads(path.read_text())
            saved = {key: [str(item) for item in document[key]] for key in ("protect", "destroy")}
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise SetupError(f"Cannot read {SELECTION} ({error}). Fix it, or run again with --reset.") from None

    def resolved(value):
        return str(Path(value).expanduser().absolute().resolve())

    for key, add, remove, check in (("protect", args.protect, args.unprotect, protected_file),
                                    ("destroy", args.destroy, args.undestroy, destroyed_entry)):
        dropped = {resolved(value) for value in remove}
        unknown = dropped - set(saved[key])
        if unknown:
            raise SetupError(f"Not in the saved {key} list: {', '.join(sorted(unknown))}")
        items = [item for item in saved[key] if item not in dropped]
        items += [check(value) for value in add]
        # Saved entries are checked again, so a file that has since gone is reported.
        saved[key] = list(dict.fromkeys(check(item) for item in items))
    return saved


def documents(device, demo, selection, single_bus=False):
    """Build every configuration document. device is None when no approved USB is set up."""

    def service(policy, responses="logs/quick-responses.json"):
        return {"schema_version": 1, "policy": policy,
                "enforcement": "logs/quick-enforcement.json",
                "responses": responses,
                "lsm": None, "local_lsm": "logs/quick-lsm.json",
                "apply_responses": False}

    paths = list(dict.fromkeys([str(demo / "restricted.txt"), *selection["protect"]]))
    if single_bus and device is None:
        raise SetupError("--single-bus needs the drive from step A4; leave out --no-allowed-device")
    docs = {
        "quick-block.json": {"schema_version": 1, "default_action": "block", "allowlist": []},
        # "auto" arms every bus, so a device on another port or controller is still blocked.
        "quick-enforcement.json": {"schema_version": 1,
                                   "managed_buses": ["usb" + str(device["bus"])] if single_bus else "auto",
                                   "state_file": STATE},
        "quick-responses.json": {"schema_version": 1, "cooldown_seconds": 30,
                                 "actions": [{"type": "lock_session"}]},
        "quick-lsm.json": {"schema_version": 1, "socket_path": "/run/portwatchman/lsm_controller.sock",
                           "protected_paths": paths},
        "quick-service-block.json": service("logs/quick-block.json"),
    }
    if device is not None:
        rule = {"name": "trusted-usb", "vendor_id": device["vendor_id"], "product_id": device["product_id"]}
        if device.get("serial"):
            rule["serial"] = device["serial"]
        docs["quick-allow.json"] = {"schema_version": 1, "default_action": "block", "allowlist": [rule]}
        docs["quick-service-allow.json"] = service("logs/quick-allow.json")
    if selection["destroy"]:
        # Each destroyed entry's folder becomes an allowed root, so deletion stays inside it.
        roots = sorted({str(Path(item).parent) for item in selection["destroy"]})
        if len(roots) > 16 or len(selection["destroy"]) > 64:
            raise SetupError("At most 64 files to destroy, in at most 16 different folders")
        docs["quick-responses-destroy.json"] = {
            "schema_version": 1, "cooldown_seconds": 30, "allowed_roots": roots,
            "actions": [{"type": "lock_session"},
                        {"type": "delete", "paths": selection["destroy"], "passes": 1},
                        {"type": "power", "mode": "poweroff", "method": "graceful"}]}
        docs["quick-service-destroy.json"] = service("logs/quick-block.json",
                                                     "logs/quick-responses-destroy.json")
    return docs


def load_device(path):
    """Return the device record saved by 'device_policy.py inspect' in step A4."""
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        raise SetupError(f"{DEVICE} not found. Run step A4 first.") from None
    except (OSError, ValueError) as error:
        raise SetupError(f"Cannot read {DEVICE} ({error}). Run step A4 again.") from None
    device = record.get("device") if isinstance(record, dict) else None
    if not isinstance(device, dict) or record.get("type") != "device_identified" or not all(
            key in device for key in ("usb_id", "bus", "vendor_id", "product_id", "is_root_hub")):
        raise SetupError(f"{DEVICE} is not a device record. Check the USB ID and run step A4 again.")
    return device


def create(root, args):
    """Write the configuration and demo files under root; return the device, documents and selection."""
    state = root / STATE
    if state.exists() or Path(str(state) + ".service-owner.json").exists():
        raise SetupError("A previous run was not restored (logs/quick-state.json exists). "
                         "See 'If something goes wrong' in the quick start.")
    device = None
    if not args.no_allowed_device:
        device = load_device(root / DEVICE)
        if device["is_root_hub"] or device.get("device_class") == "09":
            raise SetupError(f"{device['usb_id']} is a hub, not a drive. Pick your flash drive in step A4.")
    selection = update_selection(root, args)

    demo = (root / DEMO_DIR).resolve()
    docs = documents(device, demo, selection, args.single_bus)
    demo.mkdir(parents=True, exist_ok=True)
    (demo / "restricted.txt").write_text("Protected VM file\n")
    (demo / "control.txt").write_text("Readable control file\n")
    logs = root / "logs"
    logs.mkdir(exist_ok=True)
    (logs / Path(SELECTION).name).write_text(
        json.dumps({"schema_version": 1, **selection}, indent=2) + "\n")
    for name in DESTROY_FILES + ALLOW_FILES:  # do not leave profiles that no longer apply
        if name not in docs:
            (logs / name).unlink(missing_ok=True)
    for name, document in docs.items():
        (logs / name).write_text(json.dumps(document, indent=2) + "\n")
    return device, docs, selection


def main(argv=None, root=ROOT):
    parser = argparse.ArgumentParser(
        description="Create the PortWatchman quick-start configuration in logs/ from logs/quick-device.json. "
                    f"The protect and destroy lists are kept in {SELECTION} between runs.")
    parser.add_argument("--protect", action="append", default=[], metavar="FILE",
                        help="Add a VM file to protect while the service runs (repeatable)")
    parser.add_argument("--unprotect", action="append", default=[], metavar="FILE",
                        help="Remove a file from the protect list (repeatable)")
    parser.add_argument("--destroy", action="append", default=[], metavar="PATH",
                        help="Add a file or folder that an unapproved USB destroys (repeatable); it may also be protected")
    parser.add_argument("--undestroy", action="append", default=[], metavar="PATH",
                        help="Remove an entry from the destroy list (repeatable)")
    parser.add_argument("--reset", action="store_true",
                        help="Forget the saved protect and destroy lists before applying this run's options")
    parser.add_argument("--no-allowed-device", action="store_true",
                        help="Skip step A4: no approved USB, so every USB is blocked and no allow profile is made")
    parser.add_argument("--single-bus", action="store_true",
                        help="Manage only the drive's bus instead of every bus (devices on other ports are not blocked)")
    args = parser.parse_args(argv)
    try:
        device, docs, selection = create(Path(root), args)
    except SetupError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    if device is None:
        print("Drive:            none (--no-allowed-device): every USB is unapproved and blocked")
        print("WARNING: no allow profile was created, so test B1 cannot run. To show an approved USB")
        print("         later, do step A4 and run this command again without --no-allowed-device.")
    else:
        print(f"Drive:            {describe(device)}")
    buses = docs["quick-enforcement.json"]["managed_buses"]
    print(f"Managed USB buses: {'all (auto)' if buses == 'auto' else ', '.join(buses)}")
    destroyed = set(selection["destroy"])
    print("Protected files (no one can open them while the service runs):")
    for path in docs["quick-lsm.json"]["protected_paths"]:
        print(f"  {path}" + ("   [also destroyed on trigger]" if path in destroyed else ""))
    if selection["destroy"]:
        print("Destroyed when an unapproved USB is connected (logs/quick-service-destroy.json):")
        for path in selection["destroy"]:
            print(f"  {path}")
    print(f"Selection saved in {SELECTION}; run again with --protect/--unprotect/--destroy/--undestroy to change it.")
    print("Configuration created in logs/. Next, check the profiles:")
    if device is not None:
        print("  sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json check")
    print("  sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json check")
    if selection["destroy"]:
        print("  sudo python3 src/daemon/portwatchman.py --config logs/quick-service-destroy.json check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
