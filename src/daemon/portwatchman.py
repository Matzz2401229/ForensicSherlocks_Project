#!/usr/bin/env python3
"""Validate, run and inspect the integrated PortWatchman component service."""
from __future__ import annotations
import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

from service_config import DEFAULT_CONFIG, ROOT, RUNTIME, ServiceError, commands, components, load_config, parse
from service_runtime import Host, Lease, Supervisor, boot_id, process_identity, require_linux_root, restore_owned, write_json


class Reporter:
    def __init__(self):
        self.lock = threading.Lock()
        self.on_error = None
        self.summary = None  # set for run --summary: short lines instead of JSON

    def text(self, record):
        if self.summary is not None:
            try:
                return self.summary.line(record)
            except Exception:  # A formatting bug must never hide the record itself.
                pass
        return json.dumps({"schema_version": 1, "service_timestamp_ns": time.monotonic_ns(),
                           **record}, separators=(",", ":"))

    def __call__(self, record):
        error = None
        with self.lock:
            try:
                text = self.text(record)
                if text is not None:
                    print(text, flush=True)
            except (OSError, ValueError) as failure:
                error = str(failure)
        if error and self.on_error:
            self.on_error(f"Service logging failed: {error}")


def status(directory=RUNTIME):
    require_linux_root()
    path = Path(directory) / "status.json"
    if not path.exists():
        return {"type": "service_status", "running": False, "healthy": False, "phase": "not_started"}
    info = path.lstat()
    import stat
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise ServiceError("Unsafe service status file")
    record = parse(path.read_bytes())
    running = False
    try:
        running = record["boot_id"] == boot_id() and process_identity(record["pid"]) == record["process_start_ticks"]
    except (FileNotFoundError, ProcessLookupError, KeyError):
        pass
    return {**record, "type": "service_status", "running": running,
            "healthy": running and record.get("phase") == "running" and record.get("healthy") is True}


def restore(config, emit):
    require_linux_root()
    lease = Lease()
    lease.acquire()
    try:
        # A broken policy/response config must not prevent bus-state recovery.
        directory = str(ROOT / "src/enforcement")
        if directory not in sys.path:
            sys.path.insert(0, directory)
        from usb_authorization import BusManager, load_config as enforcement_config
        enforcement = enforcement_config(config.enforcement)
        result = restore_owned(BusManager(enforcement), enforcement.state_file)
        emit({"type": "service_bus_restore", "event": result})
        return 0
    finally:
        lease.close()


def run(config, emit, log_all=False):
    require_linux_root()
    lease = Lease()
    lease.acquire()
    previous = {}
    try:
        host = Host(config, emit, clear_previous_boot=True)
        identity = {"pid": os.getpid(), "boot_id": boot_id(),
                    "process_start_ticks": process_identity(os.getpid()),
                    "apply_responses": config.apply_responses, "lsm_enabled": config.lsm_enabled,
                    "lsm_scope": config.lsm_scope,
                    "scope": "new USB connections", "policy": str(config.policy),
                    "enforcement": str(config.enforcement)}
        supervisor = None
        def save(phase, fields):
            data = {**identity, "phase": phase, "healthy": False,
                    "updated_timestamp_ns": time.monotonic_ns(), **fields}
            if supervisor is not None:
                data["children"] = {name: process.pid for name, process in supervisor.processes.items()}
            write_json(RUNTIME / "status.json", data)
        supervisor = Supervisor(config, host, emit, state=save, log_all=log_all)
        emit.on_error = supervisor.health.fail
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, lambda _sig, _frame: supervisor.stop.set())
        return supervisor.run()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        lease.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Validate component configs and display the planned commands; no processes or writes")
    sub.add_parser("check", help="Check Linux/root, buses and probe prerequisites; no bus changes")
    foreground = sub.add_parser("run", help="Run the foreground service; USB authorisation is live")
    foreground.add_argument("--apply-responses", action="store_true", help="Override response preview with applied configured actions")
    foreground.add_argument("--log-all", action="store_true", help="Also log unchanged heartbeat and status records")
    foreground.add_argument("--summary", action="store_true", help="Print short readable lines for important events instead of JSON")
    sub.add_parser("status", help="Inspect root-owned runtime status, checking PID and boot identity")
    sub.add_parser("restore", help="Restore saved bus defaults after a failure, only when the service is stopped")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    emit = Reporter()
    try:
        if args.command == "status":
            record = status()
            emit(record)
            return 0 if record["running"] and record["healthy"] else 1
        config = load_config(args.config)
        if args.command == "restore":
            return restore(config, emit)
        if args.command == "validate":
            _policy, _enforcement, response, bridge = components(config)
            emit({"type": "service_config", "valid": True, "commands": commands(config),
                  "apply_responses": config.apply_responses, "lsm_enabled": config.lsm_enabled,
                  "lsm_scope": config.lsm_scope,
                  "response_plan": response.actions, "scope": "new USB connections"})
            return 0
        if args.command == "check":
            require_linux_root()
            lease = Lease()
            lease.acquire()
            try:
                Host(config, emit).preflight()
                emit({"type": "service_preflight_passed"})
            finally:
                lease.close()
            return 0
        if args.apply_responses:
            config = replace(config, apply_responses=True)
        if args.summary:
            from service_summary import Summary
            emit.summary = Summary()
        return run(config, emit, log_all=args.log_all)
    except Exception as error:
        emit({"type": "service_error", "message": str(error)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
