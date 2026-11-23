#!/usr/bin/env python3
"""Run configurable anti-forensic responses when an unapproved USB device is blocked (step 7).

Reads the enforcement stage's NDJSON on stdin and, for each blocked device, runs the
ordered actions in ``config/responses.json``:
- ``lock_session``: lock every graphical session through systemd-logind.
- ``delete``: descriptor-relative best-effort overwrite/removal of selected files or trees.
- ``sanitise``: delete common user activity traces (recent files, thumbnails, shell
  history, trash) and drop the kernel page cache.
- ``power``: power off or reboot, gracefully, forced, or immediately via sysrq.

Design notes:
- Every command is a dry run unless ``--apply`` is given, because these actions are
  destructive. A dry run previews the plan and current filesystem snapshot.
- Actions run in the configured order. ``power`` must be last, because nothing runs
  after it; a failed action is reported and the remaining actions still run.
- Deletion is confined to ``allowed_roots`` (and, for ``sanitise``, the listed home
  directories). Roots and parent paths must not use symlink aliases; nested mounts
  and multiply linked files are refused. Private capture and directory descriptors
  prevent parent-path swaps from redirecting overwrites. Failures retain recoverable entries.
- Watch accepts fresh boot/producer/session-correlated records once per connection.
  A global cooldown suppresses rapid new connections, and once
  a power action has been issued every later trigger is suppressed.
- The proc root and command runner are injectable so the logic is unit-testable.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
import uuid

from response_delete import DeleteError, DeleteReport, secure_delete, validate_root

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "responses.json"
PROC_ROOT = Path("/proc")
MAX_CONFIG_BYTES = 65536
COMMAND_TIMEOUT_S = 15
MAX_EVENT_AGE_NS = 2_000_000_000
MAX_SEEN_CONNECTIONS = 4096

ACTION_TYPES = ("lock_session", "delete", "sanitise", "power")
POWER_MODES = {"poweroff": "o", "reboot": "b"}  # value: sysrq trigger character
POWER_METHODS = ("graceful", "force", "immediate")

# Per-user activity traces, relative to a home directory. drop_caches is system-wide.
SANITISE_ITEMS = {
    "recent_files": (".local/share/recently-used.xbel",),
    "thumbnails": (".cache/thumbnails",),
    "shell_history": (".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"),
    "trash": (".local/share/Trash",),
    "drop_caches": (),
}

class ResponseError(RuntimeError):
    pass


def emit(record):
    """Print one record as a single schema-tagged JSON line (the shared NDJSON format)."""
    print(json.dumps({"schema_version": SCHEMA_VERSION, **record}, separators=(",", ":")), flush=True)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ResponseError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ResponseError(f"Non-finite JSON number: {value}")


def _parse_json(raw, what):
    try:
        return json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_reject_constant)
    except (ValueError, UnicodeError) as error:
        raise ResponseError(f"Invalid JSON in {what}: {error}") from error


def _within(path, root):
    """True if ``path`` is ``root`` or inside it (both already absolute and normalised)."""
    return path == root or root in path.parents


def _check_root(value, what):
    try:
        return validate_root(value, what, allow_final_symlink=what == "delete path")
    except DeleteError as error:
        raise ResponseError(str(error)) from error


def _check_keys(document, allowed, what):
    extra = set(document) - set(allowed)
    if extra:
        raise ResponseError(f"Unknown {what} fields: {', '.join(sorted(extra))}")


@dataclass
class Config:
    actions: list
    cooldown_seconds: float = 30.0
    include_skipped: bool = False
    allowed_roots: tuple = ()
    path: Path | None = None
    summary: dict = field(default_factory=dict)


def _validate_action(index, action, allowed_roots):
    if not isinstance(action, dict):
        raise ResponseError(f"Action {index} must be an object")
    kind = action.get("type")
    if kind not in ACTION_TYPES:
        raise ResponseError(f"Action {index} has unknown type {kind!r}; expected one of {', '.join(ACTION_TYPES)}")
    if kind == "lock_session":
        _check_keys(action, ("type",), f"{kind} action")
        return {"type": kind}
    if kind == "delete":
        _check_keys(action, ("type", "paths", "passes"), f"{kind} action")
        paths = action.get("paths")
        if not isinstance(paths, list) or not paths or len(paths) > 64:
            raise ResponseError("delete.paths must be a list of 1 to 64 absolute paths")
        if not allowed_roots:
            raise ResponseError("delete needs allowed_roots so deletion stays inside chosen folders")
        normalised = []
        for value in paths:
            path = _check_root(value, "delete path")
            if not any(_within(path, root) and path != root for root in allowed_roots):
                raise ResponseError(f"delete path is not inside any allowed_roots entry: {value!r}")
            normalised.append(str(path))
        return {"type": kind, "paths": normalised, "passes": _passes(action)}
    if kind == "sanitise":
        _check_keys(action, ("type", "home_dirs", "items", "passes"), f"{kind} action")
        items = action.get("items")
        if not isinstance(items, list) or not items or any(not isinstance(i, str) for i in items) or len(set(items)) != len(items) \
                or any(item not in SANITISE_ITEMS for item in items):
            raise ResponseError(f"sanitise.items must be a non-empty list of distinct items from: "
                                f"{', '.join(SANITISE_ITEMS)}")
        homes = action.get("home_dirs", [])
        needs_homes = any(SANITISE_ITEMS[item] for item in items)
        if not isinstance(homes, list) or len(homes) > 16 or (needs_homes and not homes):
            raise ResponseError("sanitise.home_dirs must list the home directories to clean (at most 16)")
        homes = [str(_check_root(home, "sanitise home_dir")) for home in homes]
        return {"type": kind, "home_dirs": homes, "items": list(items), "passes": _passes(action)}
    _check_keys(action, ("type", "mode", "method"), f"{kind} action")
    mode = action.get("mode", "poweroff")
    method = action.get("method", "graceful")
    if not isinstance(mode, str) or mode not in POWER_MODES:
        raise ResponseError(f"power.mode must be one of {', '.join(POWER_MODES)}")
    if method not in POWER_METHODS:
        raise ResponseError(f"power.method must be one of {', '.join(POWER_METHODS)}")
    return {"type": kind, "mode": mode, "method": method}


def _passes(action):
    passes = action.get("passes", 1)
    if type(passes) is not int or not 1 <= passes <= 7:
        raise ResponseError("passes must be an integer from 1 to 7")
    return passes


def validate_document(document, path=None):
    """Validate a parsed responses config and return a normalised Config."""
    if not isinstance(document, dict):
        raise ResponseError("Config must be a JSON object")
    _check_keys(document, ("schema_version", "trigger", "cooldown_seconds", "allowed_roots", "actions"),
                "config")
    if type(document.get("schema_version")) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise ResponseError("Config schema_version must be integer 1")

    trigger = document.get("trigger", {})
    if not isinstance(trigger, dict):
        raise ResponseError("trigger must be an object")
    _check_keys(trigger, ("include_skipped",), "trigger")
    include_skipped = trigger.get("include_skipped", False)
    if type(include_skipped) is not bool:
        raise ResponseError("trigger.include_skipped must be true or false")

    cooldown = document.get("cooldown_seconds", 30)
    if type(cooldown) not in (int, float) or not 0 <= cooldown <= 86400:
        raise ResponseError("cooldown_seconds must be a number from 0 to 86400")

    roots = document.get("allowed_roots", [])
    if not isinstance(roots, list) or len(roots) > 16:
        raise ResponseError("allowed_roots must be a list of at most 16 absolute paths")
    roots = tuple(_check_root(root, "allowed_roots entry") for root in roots)

    actions = document.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ResponseError("actions must be a non-empty list")
    normalised = [_validate_action(index, action, roots) for index, action in enumerate(actions)]
    kinds = [action["type"] for action in normalised]
    duplicates = sorted({kind for kind in kinds if kinds.count(kind) > 1})
    if duplicates:
        raise ResponseError(f"Each action type may appear once; repeated: {', '.join(duplicates)}")
    if "power" in kinds and kinds[-1] != "power":
        raise ResponseError("power must be the last action, because nothing runs after it")

    summary = {"actions": kinds, "cooldown_seconds": cooldown, "include_skipped": include_skipped,
               "allowed_roots": [str(root) for root in roots]}
    return Config(normalised, float(cooldown), include_skipped, roots, path, summary)


def load_config(path):
    path = Path(path)
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise ResponseError(f"Cannot read config: {error}") from error
    if len(raw) > MAX_CONFIG_BYTES:
        raise ResponseError("Config exceeds the 64 KiB limit")
    return validate_document(_parse_json(raw, "config"), path)


class SystemExecutor:
    """Side effects behind one seam: commands, /proc writes, disk sync and random data."""

    def __init__(self, proc_root=PROC_ROOT, runner=subprocess.run, sync=None, randbytes=os.urandom):
        self.proc_root = Path(proc_root)
        self.runner = runner
        self.sync = sync if sync is not None else getattr(os, 'sync', self._unsupported_sync)
        self.randbytes = randbytes

    @staticmethod
    def _unsupported_sync():
        raise ResponseError("Disk sync requires a supported Linux runtime")

    def run(self, argv):
        """Run a command; return (ok, detail). Never raises for a failing command."""
        try:
            done = self.runner(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               timeout=COMMAND_TIMEOUT_S, check=False)
        except FileNotFoundError:
            return False, f"command not found: {argv[0]}"
        except (OSError, subprocess.SubprocessError) as error:
            return False, f"{argv[0]} failed: {error}"
        if done.returncode != 0:
            message = (done.stderr or done.stdout or "").strip()[:300]
            return False, f"{argv[0]} exited {done.returncode}: {message}"
        return True, None

    def write_proc(self, relative, value):
        try:
            with (self.proc_root / relative).open("w", encoding="ascii") as handle:
                handle.write(value)
        except OSError as error:
            raise ResponseError(f"Cannot write /proc/{relative}: {error}") from error


# --- Actions ---------------------------------------------------------------------------

def power_command(action):
    """The command (or sysrq write) a power action issues."""
    mode, method = action["mode"], action["method"]
    if method == "immediate":
        return {"sysrq": POWER_MODES[mode]}
    argv = ["systemctl", mode]
    if method == "force":
        # Skip stopping units one by one; systemd still kills processes and unmounts or
        # remounts file systems read-only, so it is much faster but not a hard power cut.
        argv.append("--force")
    return {"argv": argv}


class ActionRunner:
    """Run (or, in a dry run, describe) one configured action and report the outcome."""

    def __init__(self, config, executor, apply=False):
        self.config = config
        self.executor = executor
        self.apply = apply

    def run(self, action):
        handler = getattr(self, "_" + action["type"])
        try:
            ok, detail = handler(action)
        except (ResponseError, OSError) as error:
            ok, detail = False, {"error": str(error)}
        return ok, detail

    def _lock_session(self, action):
        argv = ["loginctl", "lock-sessions"]  # as root this locks every session
        if not self.apply:
            return True, {"would_run": argv}
        ok, error = self.executor.run(argv)
        return ok, {"ran": argv, **({"error": error} if error else {})}

    def _delete(self, action):
        report = DeleteReport()
        for path in action["paths"]:
            secure_delete(path, self.config.allowed_roots, action["passes"], self.apply,
                          self.executor.randbytes, report)
        return not report.errors, {"passes": action["passes"], **report.as_dict(self.apply)}

    def _sanitise(self, action):
        report = DeleteReport()
        cleaned = []
        for item in action["items"]:
            for home in action["home_dirs"]:
                for relative in SANITISE_ITEMS[item]:
                    secure_delete(Path(home) / relative, [Path(home)], action["passes"], self.apply,
                                  self.executor.randbytes, report)
            cleaned.append(item)
        detail = {"items": cleaned, "home_dirs": action["home_dirs"], **report.as_dict(self.apply)}
        ok = not report.errors
        if "drop_caches" in action["items"]:
            if self.apply:
                try:
                    self.executor.sync()
                    self.executor.write_proc("sys/vm/drop_caches", "3\n")  # page cache + dentries/inodes
                    detail["drop_caches"] = "done"
                except (ResponseError, OSError) as error:
                    ok = False
                    detail["drop_caches"] = f"failed: {error}"
            else:
                detail["drop_caches"] = "would sync and write 3 to /proc/sys/vm/drop_caches"
        return ok, detail

    def _power(self, action):
        command = power_command(action)
        if not self.apply:
            return True, {"mode": action["mode"], "method": action["method"], "would_issue": command}
        if "sysrq" in command:
            self.executor.sync()  # sysrq poweroff/reboot does not flush dirty pages itself
            self.executor.write_proc("sysrq-trigger", command["sysrq"])
            return True, {"mode": action["mode"], "method": action["method"], "issued": command}
        ok, error = self.executor.run(command["argv"])
        return ok, {"mode": action["mode"], "method": action["method"], "issued": command,
                    **({"error": error} if error else {})}


# --- Pipeline stage --------------------------------------------------------------------

TRIGGER_FIELDS = ("usb_id", "connection_id", "session_id", "reason", "policy_reason", "device")


class ResponseEngine:
    """Decide when a record triggers the response plan, run it, and track the stream.

    ``out`` receives each output record as soon as it exists, so the power action's
    record is written before the machine goes down.
    """

    def __init__(self, config, executor, out=emit, apply=False, clock=time.monotonic_ns, boot_id=None):
        self.config = config
        self.runner = ActionRunner(config, executor, apply=apply)
        self.out = out
        self.apply = apply
        self.clock = clock
        self.last_fired_ns = None
        self.power_issued = False
        self.responses = 0
        self.failures = 0
        self.input_errors = 0
        self.monitor_healthy = None
        self.upstream_close = None
        self.upstream_failed = False
        self.boot_id = boot_id
        self.producer = None
        self.producer_apply = None
        self.session_id = None
        self.seen_connections = set()
        self.seen_order = deque()

    def _input_error(self, message):
        self.input_errors += 1
        self.out({"type": "response_input_error", "message": message})

    def _envelope(self, record, starting=False):
        if self.boot_id is None:
            try:
                self.boot_id = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))
            except (OSError, ValueError) as error:
                raise ResponseError(f"Cannot verify the producer boot: {error}") from error
        if record.get("boot_id") != self.boot_id or record.get("clock") != "monotonic":
            raise ResponseError("Enforcement record is from an unknown boot or clock")
        timestamp = record.get("emitted_timestamp_ns")
        if type(timestamp) is not int or not 0 <= self.clock() - timestamp <= MAX_EVENT_AGE_NS:
            raise ResponseError("Stale, future or missing enforcement timestamp")
        producer = record.get("enforcement_instance_id")
        if not isinstance(producer, str) or not 1 <= len(producer) <= 128:
            raise ResponseError("Missing enforcement producer identity")
        apply = record.get("enforcement_apply")
        if type(apply) is not bool:
            raise ResponseError("Missing enforcement apply/dry-run context")
        if not starting and (producer != self.producer or apply is not self.producer_apply):
            raise ResponseError("Record is not from the current enforcement producer")

    def _connection(self, record):
        usb_id = record.get("usb_id")
        if not isinstance(usb_id, str) or not re.fullmatch(r"[1-9][0-9]*-[1-9][0-9]*(?:\.[1-9][0-9]*)*", usb_id):
            raise ResponseError("Invalid or missing USB identity")
        connection = record.get("connection_id")
        prefix = self.boot_id + ":" + usb_id + ":"
        if not isinstance(connection, str) or len(connection) >= 256 or not connection.startswith(prefix):
            raise ResponseError("Missing or mismatched connection identity")
        generation = connection[len(prefix):]
        if not generation.isascii() or not generation.isdecimal() or not 0 < int(generation) <= record["emitted_timestamp_ns"]:
            raise ResponseError("Invalid connection generation")
        if record.get("session_id") != self.session_id or self.monitor_healthy is not True:
            raise ResponseError("Trigger is not from a healthy current monitor session")
        if self.apply and self.producer_apply is not True:
            raise ResponseError("Live responses refuse dry-run enforcement input")
        if record["type"] == "enforcement_result":
            device = record.get("device")
            if (not isinstance(device, dict) or device.get("usb_id") != usb_id
                    or device.get("is_root_hub") is not False
                    or type(device.get("device_address")) is not int
                    or not 1 <= device["device_address"] <= 127):
                raise ResponseError("Blocked-device record has incomplete identity context")
        return connection

    def is_trigger(self, record):
        kind = record.get("type")
        if kind == "enforcement_result":
            return record.get("action") == "block"
        if kind == "enforcement_skipped":
            return (self.config.include_skipped and record.get("requested_action") == "block"
                    and record.get("policy_reason") == "no_matching_allowlist_rule"
                    and record.get("reason") in {"device_unavailable", "device_changed", "stale_device"})
        return False

    def handle(self, record):
        if (not isinstance(record, dict) or type(record.get("schema_version")) is not int
                or record["schema_version"] != SCHEMA_VERSION):
            self._input_error("Expected enforcement schema_version integer 1")
            return
        kind = record.get("type")
        if not isinstance(kind, str):
            self._input_error("Record type must be a string")
            return
        relevant = {"enforcement_started", "enforcement_result", "enforcement_skipped", "enforcement_monitor_status",
                    "enforcement_stream_closed", "enforcement_error", "enforcement_input_error"}
        if kind not in relevant and not (isinstance(kind, str) and kind.startswith("lsm_")):
            return
        try:
            self._envelope(record, starting=kind == "enforcement_started")
        except ResponseError as error:
            self._input_error(str(error))
            return
        if kind == "enforcement_started":
            if record.get("apply") is not record["enforcement_apply"]:
                self._input_error("Inconsistent enforcement mode")
                return
            if self.producer is not None:
                if record["enforcement_instance_id"] != self.producer or record["enforcement_apply"] is not self.producer_apply:
                    self._input_error("A new enforcement producer requires a fresh response watcher")
                return  # A repeated header must never reset deduplication or failure state.
            self.producer = record["enforcement_instance_id"]
            self.producer_apply = record["enforcement_apply"]
            self.monitor_healthy = None
            self.session_id = None
            self.upstream_close = None
            self.seen_connections.clear()
            self.seen_order.clear()
            return
        if isinstance(kind, str) and kind.startswith("lsm_"):
            if kind == "lsm_bridge_error":
                self.upstream_failed = True
            self.out(record)  # Preserve Step 6's observability in a four-stage pipeline.
            return
        if kind in {"enforcement_error", "enforcement_input_error"}:
            self.upstream_failed = True
            self.out({"type": "response_upstream_error", "record": record})
            return
        if kind == "enforcement_monitor_status":
            healthy = record.get("healthy")
            session = record.get("session_id")
            if not isinstance(session, str) or not 1 <= len(session) <= 128 or type(healthy) is not bool:
                self._input_error("Invalid monitor session/status")
                return
            if record.get("monitor_type") == "monitor_starting":
                self.session_id = session
            elif self.session_id is not None and session != self.session_id:
                self._input_error("Monitor status belongs to another session")
                return
            self.session_id = session
            if (record.get("degraded") is True or (healthy is False and
                    record.get("monitor_type") not in {"monitor_starting", "monitor_stopped"})):
                self.upstream_failed = True
            if type(healthy) is bool and healthy != self.monitor_healthy:
                self.monitor_healthy = healthy
                self.out({"type": "response_monitor_status", "healthy": healthy,
                          "monitor_type": record.get("monitor_type"), "apply": self.apply})
            return
        if kind == "enforcement_stream_closed":
            self.upstream_close = record
            self.upstream_failed |= record.get("ok") is not True
            self.monitor_healthy = False
            return
        if self.is_trigger(record):
            try:
                connection = self._connection(record)
            except ResponseError as error:
                self._input_error(str(error))
                return
            if self.upstream_close is not None:
                self._input_error("Record arrived after enforcement closed")
                return
            if connection in self.seen_connections:
                self.out({"type": "response_suppressed", "reason": "duplicate_connection",
                          "usb_id": record["usb_id"], "connection_id": connection})
                return
            self.seen_connections.add(connection)
            self.seen_order.append(connection)
            if len(self.seen_order) > MAX_SEEN_CONNECTIONS:
                self.seen_connections.remove(self.seen_order.popleft())
            self.fire(record)

    def fire(self, record):
        """Run the whole plan for one triggering record, unless suppressed."""
        # The upstream "reason" becomes trigger_reason so it never collides with our own.
        context = {("trigger_reason" if name == "reason" else name): record[name]
                   for name in TRIGGER_FIELDS if name in record}
        context["trigger_type"] = record.get("type")
        now = self.clock()
        if self.power_issued:
            self.out({"type": "response_suppressed", "reason": "power_action_issued", **context})
            return
        cooldown_ns = int(self.config.cooldown_seconds * 1e9)
        if self.last_fired_ns is not None and now - self.last_fired_ns < cooldown_ns:
            self.out({"type": "response_suppressed", "reason": "cooldown",
                      "cooldown_remaining_s": round((cooldown_ns - (now - self.last_fired_ns)) / 1e9, 3),
                      **context})
            return
        self.last_fired_ns = now
        self.responses += 1
        response_id = self.responses
        upstream_latency = record.get("enforcement_latency_ns")
        self.out({"type": "response_triggered", "response_id": response_id, "apply": self.apply,
                  "dry_run": not self.apply, "planned_actions": [a["type"] for a in self.config.actions],
                  **({"upstream_enforcement_latency_ns": upstream_latency}
                     if type(upstream_latency) is int else {}),
                  **context})
        failed = 0
        for action in self.config.actions:
            if action["type"] == "power" and self.apply:
                # Write the record first: after this call the process may not get another chance.
                self.power_issued = True
                self.out({"type": "response_action", "response_id": response_id, "action": "power",
                          "status": "issuing", "applied": True, "command": power_command(action),
                          "usb_id": context.get("usb_id"),
                          "since_trigger_ns": self.clock() - now})
            started = self.clock()
            try:
                ok, detail = self.runner.run(action)
            except KeyboardInterrupt:
                # A requested stop during a side effect is not proof that it completed.
                self.failures += 1
                if action["type"] == "power":
                    self.power_issued = False
                self.out({"type": "response_action", "response_id": response_id,
                          "action": action["type"], "status": "interrupted", "ok": False,
                          "applied": self.apply, "usb_id": context.get("usb_id"),
                          "detail": {"error": "Action interrupted; inspect partial effects and retained deletion directories"}})
                raise
            finished = self.clock()
            if not ok:
                failed += 1
                if action["type"] == "power":
                    self.power_issued = False  # it did not happen, so later triggers may retry
            self.out({"type": "response_action", "response_id": response_id, "action": action["type"],
                      "status": "ok" if ok else "failed", "applied": self.apply, "ok": ok,
                      "duration_ns": finished - started, "since_trigger_ns": finished - now,
                      "detail": detail, "usb_id": context.get("usb_id")})
        self.failures += failed
        self.out({"type": "response_completed", "response_id": response_id, "apply": self.apply,
                  "ok": failed == 0, "failed_actions": failed, "total_ns": self.clock() - now,
                  "usb_id": context.get("usb_id")})

    def outcome(self, interrupted):
        """Return (closing reason, ok). ok needs a clean stop, upstream ok, and no failures."""
        if interrupted:
            reason, upstream_ok = "requested_stop", True
        elif self.upstream_close is not None:
            reason = "upstream_" + str(self.upstream_close.get("reason") or "closed")
            upstream_ok = self.upstream_close.get("ok") is True
        else:
            reason, upstream_ok = "unexpected_end_of_input", False
        return reason, upstream_ok and not self.upstream_failed and not self.failures and not self.input_errors


def process_stream(engine, stream):
    """Handle each NDJSON line and end with a response_stream_closed record; return exit status."""
    interrupted = False
    try:
        for line in stream:
            if not line.strip():
                continue
            try:
                record = _parse_json(line, "enforcement stream")
            except ResponseError as error:
                engine.input_errors += 1
                engine.out({"type": "response_input_error", "message": str(error)})
                continue
            engine.handle(record)
    except KeyboardInterrupt:
        interrupted = True
    reason, ok = engine.outcome(interrupted)
    engine.out({"type": "response_stream_closed", "reason": reason, "ok": ok, "apply": engine.apply,
                "responses": engine.responses, "failures": engine.failures,
                "input_errors": engine.input_errors})
    return 0 if ok else 1


# --- CLI -------------------------------------------------------------------------------

def require_root():
    if sys.platform != "linux":
        raise ResponseError("Live responses run inside the Ubuntu VM")
    if os.geteuid() != 0:
        raise ResponseError("--apply needs root: run this stage with sudo")


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Responses config JSON")
    parser.add_argument("--proc-root", type=Path, default=PROC_ROOT, help="/proc root (for testing)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Check the config and print the response plan")
    watch = sub.add_parser("watch", help="Read enforcement results on stdin and respond (dry run unless --apply)")
    watch.add_argument("--apply", action="store_true", help="Actually run the actions; otherwise dry run")
    trigger = sub.add_parser("trigger", help="Run the whole plan once now, as if a device was blocked")
    trigger.add_argument("--apply", action="store_true", help="Actually run the actions; otherwise dry run")
    one = sub.add_parser("run-action", help="Run one configured action now (dry run unless --apply)")
    one.add_argument("action", choices=ACTION_TYPES)
    one.add_argument("--apply", action="store_true", help="Actually run the action; otherwise dry run")
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "validate":
            emit({"type": "response_config", "config": str(args.config), "valid": True,
                  **config.summary, "plan": config.actions})
            return 0
        if args.apply:
            require_root()
        executor = SystemExecutor(proc_root=args.proc_root)
        if args.command == "run-action":
            chosen = [a for a in config.actions if a["type"] == args.action]
            if not chosen:
                raise ResponseError(f"{args.action} is not configured in {args.config}")
            config.actions = chosen
        engine = ResponseEngine(config, executor, apply=args.apply)
        if args.command in ("trigger", "run-action"):
            engine.fire({"type": "manual_trigger", "reason": "manual"})
            return 0 if engine.failures == 0 else 1
        if sys.stdin.isatty():
            raise ResponseError("Pipe the enforcement stage's JSON into watch; see docs/STEP7-TESTING.md")
        emit({"type": "response_started", "apply": args.apply, "dry_run": not args.apply,
              "config": str(args.config), **config.summary})
        return process_stream(engine, sys.stdin)
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
        return 1
    except (ResponseError, OSError) as error:
        emit({"type": "response_error", "message": str(error)})
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
