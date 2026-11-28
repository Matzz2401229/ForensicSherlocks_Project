#!/usr/bin/env python3
"""Install a root-owned PortWatchman snapshot; never start or enable the service."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/daemon"))
from service_config import DEFAULT_CONFIG, ServiceError, components, load_config
from service_runtime import Lease, owner_path, require_linux_root

CODE = Path("/opt/portwatchman")
ETC = Path("/etc/portwatchman")
DATA = Path("/var/lib/portwatchman")
UNIT = Path("/etc/systemd/system/portwatchman.service")
MARKER = ".portwatchman-install.json"
FILES = (
    "src/daemon/portwatchman.py", "src/daemon/service_config.py", "src/daemon/service_runtime.py",
    "src/daemon/service_summary.py",
    "src/monitor/usb_monitor.py", "src/monitor/usb_events.bt", "src/policy/device_policy.py",
    "src/enforcement/usb_authorization.py", "src/enforcement/lsm_client.py", "src/enforcement/lsm_bridge.py",
    "src/enforcement/lsm_local.py",
    "src/responses/responses.py", "src/responses/response_delete.py",
)
CONTROLLER = "src/enforcement/bpf/build/lsm_controller"
OPTIONAL_CONFIGS = ("lsm.json", "lsm-local.json")


def service_active():
    """True while the installed service is running (or starting/stopping)."""
    return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "portwatchman"],
                          timeout=30).returncode == 0


def stale_configs(configs):
    """Optional installed config files the new profile no longer uses."""
    return [name for name in OPTIONAL_CONFIGS if name not in configs]


def directory(path, mode):
    if path.resolve() != path:
        raise ServiceError(f"Installation directory must not use symlink aliases: {path}")
    path.mkdir(parents=True, mode=mode, exist_ok=True)
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ServiceError(f"Installation directory ancestors must be root-owned and not user-writable: {ancestor}")


def safe_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ServiceError(f"Unsafe installed file: {path}")


def write_file(path, payload, mode):
    directory(path.parent, 0o755 if path.is_relative_to(CODE) else 0o700)
    if os.path.lexists(path):
        safe_file(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pw-install-", delete=False) as output:
            temporary = Path(output.name)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def encoded(document):
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def payloads(config):
    _policy, enforcement, _responses, _bridge = components(config)
    if enforcement.state_file.exists() or owner_path(enforcement.state_file).exists():
        raise ServiceError("Restore the source configuration's arm state before installation")
    enf = json.loads(config.enforcement.read_text())
    enf["state_file"] = str(DATA / "enforcement-state.json")
    installed = {"schema_version": 1, "policy": str(ETC / "allowlist.json"),
                 "enforcement": str(ETC / "enforcement.json"), "responses": str(ETC / "responses.json"),
                 "lsm": str(ETC / "lsm.json") if config.lsm else None,
                 "local_lsm": str(ETC / "lsm-local.json") if config.local_lsm else None,
                 "apply_responses": config.apply_responses, "startup_timeout": config.startup_timeout,
                 "shutdown_timeout": config.shutdown_timeout, "command_timeout": config.command_timeout}
    result = {"allowlist.json": config.policy.read_bytes(), "enforcement.json": encoded(enf),
              "responses.json": config.responses.read_bytes(), "service.json": encoded(installed)}
    if config.lsm:
        result["lsm.json"] = config.lsm.read_bytes()
    if config.local_lsm:
        result["lsm-local.json"] = config.local_lsm.read_bytes()
    return result


def install(config_path, update=False, replace=False):
    require_linux_root()
    lease = Lease()
    lease.acquire()
    try:
        if os.path.lexists(UNIT):
            safe_file(UNIT)
            if not UNIT.read_text().startswith("# Managed by the PortWatchman installer."):
                raise ServiceError("Existing unit is not managed by this installer")
        for path, mode in ((CODE, 0o755), (ETC, 0o700), (DATA, 0o700)):
            existed = path.exists() or path.is_symlink()
            directory(path, mode)
            if existed and path in (CODE, ETC) and not (path / MARKER).exists():
                raise ServiceError(f"Refusing an existing unmanaged directory: {path}")
            marker = path / MARKER
            if path in (CODE, ETC):
                if marker.exists():
                    safe_file(marker)
                    if json.loads(marker.read_text()).get("managed_by") != "portwatchman":
                        raise ServiceError(f"Invalid installation marker: {marker}")
                else:
                    write_file(marker, encoded({"schema_version": 1, "managed_by": "portwatchman"}), 0o600)
        if update:
            if not (ETC / "service.json").is_file():
                raise ServiceError("No installed configuration; use initial install first")
            config = load_config(ETC / "service.json")
            components(config)
            configs = {}
        else:
            if (ETC / "service.json").exists() and not replace:
                raise ServiceError("Already installed. Use --update-code to keep the installed configuration, "
                                   "or --replace-config to switch to another profile")
            if replace and service_active():
                raise ServiceError("Stop the service first: sudo systemctl stop portwatchman")
            if (DATA / "enforcement-state.json").exists():
                raise ServiceError("Saved service arm state exists; restore it before installation")
            config = load_config(config_path)
            configs = payloads(config)
            if not replace:
                for name, data in configs.items():
                    target = ETC / name
                    if target.exists() and target.read_bytes() != data:
                        raise ServiceError(f"Conflicting partial configuration; inspect before retrying: {target}")
        files = list(FILES)
        binary = ROOT / CONTROLLER
        if binary.exists():
            files.append(CONTROLLER)
        elif config.lsm_enabled:
            raise ServiceError("Build the native BPF-LSM controller before installing an LSM-enabled profile")
        hashes = {}
        for name in files:
            source = ROOT / name
            if source.is_symlink() or not source.resolve(strict=True).is_relative_to(ROOT):
                raise ServiceError(f"Source file escaped the reviewed snapshot: {name}")
            data = source.read_bytes()
            write_file(CODE / name, data, 0o755 if name == CONTROLLER else 0o644)
            hashes[name] = hashlib.sha256(data).hexdigest()
        # Commit the service config last; a partially copied profile is not launchable.
        for name in sorted(configs, key=lambda name: name == "service.json"):
            write_file(ETC / name, configs[name], 0o600)
        if replace:
            for name in stale_configs(configs):
                stale = ETC / name
                if os.path.lexists(stale):
                    safe_file(stale)
                    stale.unlink()
        write_file(CODE / MARKER, encoded({"schema_version": 1, "managed_by": "portwatchman", "files": hashes}), 0o600)
        write_file(UNIT, (ROOT / "systemd/portwatchman.service").read_bytes(), 0o644)
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)
        print(json.dumps({"schema_version": 1, "type": "service_installed", "update_code": update,
                          "replaced_config": replace, "profile": None if update else str(config_path),
                          "code_directory": str(CODE), "config_directory": str(ETC),
                          "start_requested": False, "enable_requested": False,
                          "message": "Installation does not change existing enablement; no start/enable command was issued"}))
        return 0
    finally:
        lease.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--update-code", action="store_true", help="Update managed code/unit only; preserve installed configs and arm state")
    mode.add_argument("--replace-config", action="store_true",
                      help="Switch an existing installation to the --config profile (the service must be stopped)")
    args = parser.parse_args(argv)
    try:
        return install(args.config, args.update_code, args.replace_config)
    except Exception as error:
        print(json.dumps({"schema_version": 1, "type": "service_install_error", "message": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
