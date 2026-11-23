#!/usr/bin/env python3
"""PortWatchman step 7: configurable responses for blocked USB devices.

Reads enforcement records on stdin and runs the configured actions
(lock_session, delete, sanitise, power). Dry run unless --apply is given.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "responses.json"
PROC_ROOT = Path("/proc")
MAX_CONFIG_BYTES = 65536
CHUNK_BYTES = 1024 * 1024
COMMAND_TIMEOUT_S = 15

ACTION_TYPES = ("lock_session", "delete", "sanitise", "power")
POWER_MODES = {"poweroff": "o", "reboot": "b"}  # sysrq key for each mode
POWER_METHODS = ("graceful", "force", "immediate")

# Trace files per home folder; drop_caches is system-wide.
SANITISE_ITEMS = {
    "recent_files": (".local/share/recently-used.xbel",),
    "thumbnails": (".cache/thumbnails",),
    "shell_history": (".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"),
    "trash": (".local/share/Trash",),
    "drop_caches": (),
}

# Deletion is never allowed inside these system folders.
FORBIDDEN_TREES = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
                   "/proc", "/run", "/sbin", "/snap", "/sys", "/usr", "/var")


class ResponseError(RuntimeError):
    pass


def emit(record):
    """Print one record as a JSON line."""
    print(json.dumps({"schema_version": SCHEMA_VERSION, **record}, separators=(",", ":")), flush=True)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ResponseError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(raw, what):
    try:
        return json.loads(raw, object_pairs_hook=_unique_keys)
    except (ValueError, UnicodeError) as error:
        raise ResponseError(f"Invalid JSON in {what}: {error}") from error


def _within(path, root):
    """True if path is root or inside it."""
    return path == root or root in path.parents


def _check_root(value, what):
    """Check a path is absolute, at least two levels deep and outside system folders."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ResponseError(f"{what} must be a non-empty path string")
    path = Path(os.path.normpath(value))
    if not path.is_absolute():
        raise ResponseError(f"{what} must be an absolute path: {value!r}")
    if len(path.parts) < 3:  # e.g. /home/nelson
        raise ResponseError(f"{what} is too broad (needs at least two levels, e.g. /home/user): {value!r}")
    for tree in FORBIDDEN_TREES:
        if _within(path, Path(tree)):
            raise ResponseError(f"{what} is inside protected system tree {tree}: {value!r}")
    return path


def _check_keys(document, allowed, what):
    extra = set(document) - set(allowed)
    if extra:
        raise ResponseError(f"Unknown {what} fields: {', '.join(sorted(extra))}")


@dataclass
class Config:
    actions: list
    cooldown_seconds: float = 30.0
    include_skipped: bool = False
    include_lsm_errors: bool = False
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
        if not isinstance(items, list) or not items or len(set(items)) != len(items) \
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
    if mode not in POWER_MODES:
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
    """Validate a parsed config and return a Config."""
    if not isinstance(document, dict):
        raise ResponseError("Config must be a JSON object")
    _check_keys(document, ("schema_version", "trigger", "cooldown_seconds", "allowed_roots", "actions"),
                "config")
    if type(document.get("schema_version")) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise ResponseError("Config schema_version must be integer 1")

    trigger = document.get("trigger", {})
    if not isinstance(trigger, dict):
        raise ResponseError("trigger must be an object")
    _check_keys(trigger, ("include_skipped", "include_lsm_errors"), "trigger")
    include_skipped = trigger.get("include_skipped", False)
    if type(include_skipped) is not bool:
        raise ResponseError("trigger.include_skipped must be true or false")
    include_lsm_errors = trigger.get("include_lsm_errors", False)
    if type(include_lsm_errors) is not bool:
        raise ResponseError("trigger.include_lsm_errors must be true or false")

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
               "include_lsm_errors": include_lsm_errors,
               "allowed_roots": [str(root) for root in roots]}
    return Config(normalised, float(cooldown), include_skipped, include_lsm_errors, roots, path, summary)


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
    """Runs commands and /proc writes; tests swap in fakes."""

    def __init__(self, proc_root=PROC_ROOT, runner=subprocess.run, sync=os.sync, randbytes=os.urandom):
        self.proc_root = Path(proc_root)
        self.runner = runner
        self.sync = sync
        self.randbytes = randbytes

    def run(self, argv):
        """Run a command and return (ok, error message)."""
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


# Secure deletion

@dataclass
class DeleteReport:
    files: int = 0
    others: int = 0  # symlinks, pipes, device files
    dirs: int = 0
    bytes: int = 0
    absent: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    planned: list = field(default_factory=list)

    def as_dict(self, apply):
        out = {"files": self.files, "other_entries": self.others, "dirs": self.dirs, "bytes": self.bytes,
               "absent": self.absent, "errors": self.errors}
        if not apply:
            out["would_delete"] = self.planned[:200]
            out["would_delete_truncated"] = len(self.planned) > 200
        return out


def _real_location(path):
    """Resolve symlinks in the parent folder, keeping the last name as it is."""
    return Path(os.path.realpath(path.parent)) / path.name


def _overwrite_file(path, passes, randbytes):
    """Overwrite a file with random data, empty it, rename it and delete it."""
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"not a regular file: {path}")
        size = info.st_size
        for _ in range(passes):
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = size
            while remaining:
                block = randbytes(min(CHUNK_BYTES, remaining))
                view = memoryview(block)
                while view:  # os.write may write less than asked
                    written = os.write(fd, view)
                    view = view[written:]
                remaining -= len(block)
            os.fsync(fd)
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    # Rename first so the original name is not left behind.
    scrambled = path.with_name("." + secrets.token_hex(8))
    os.rename(path, scrambled)
    os.unlink(scrambled)
    return size


def _remove_entry(path, passes, apply, report, randbytes):
    """Overwrite and delete a file; just unlink links and special files."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not apply:
        report.planned.append(str(path))
        if stat.S_ISREG(info.st_mode):
            report.files += 1
            report.bytes += info.st_size
        else:
            report.others += 1
        return
    try:
        if stat.S_ISREG(info.st_mode):
            report.bytes += _overwrite_file(path, passes, randbytes)
            report.files += 1
        else:
            os.unlink(path)
            report.others += 1
    except OSError as error:
        report.errors.append({"path": str(path), "error": str(error)})


def secure_delete(target, roots, passes, apply, randbytes=os.urandom, report=None):
    """Securely delete a file or folder tree that lies inside the allowed roots."""
    report = report or DeleteReport()
    target = Path(target)
    real = _real_location(target)
    # Re-check in case the path changed since the config was loaded.
    real_roots = [Path(os.path.realpath(root)) for root in roots]
    if not any(_within(real, root) and real != root for root in real_roots):
        report.errors.append({"path": str(target), "error": "outside allowed roots after resolving symlinks"})
        return report
    try:
        info = os.lstat(real)
    except FileNotFoundError:
        report.absent.append(str(target))
        return report
    except OSError as error:
        report.errors.append({"path": str(target), "error": str(error)})
        return report
    if not stat.S_ISDIR(info.st_mode):
        _remove_entry(real, passes, apply, report, randbytes)
        return report

    def walk_error(error):
        report.errors.append({"path": str(getattr(error, "filename", target)), "error": str(error)})

    # Walk bottom-up without following symlinks.
    dirs = []
    for directory, subdirs, files in os.walk(real, topdown=False, onerror=walk_error, followlinks=False):
        base = Path(directory)
        for name in files:
            _remove_entry(base / name, passes, apply, report, randbytes)
        for name in subdirs:
            child = base / name
            if child.is_symlink():  # symlinked folders are listed here
                _remove_entry(child, passes, apply, report, randbytes)
        dirs.append(base)
    for directory in dirs:
        if not apply:
            report.planned.append(str(directory) + "/")
            report.dirs += 1
            continue
        try:
            os.rmdir(directory)
            report.dirs += 1
        except OSError as error:
            report.errors.append({"path": str(directory), "error": str(error)})
    return report


# Actions

def power_command(action):
    """Build the command for a power action."""
    mode, method = action["mode"], action["method"]
    if method == "immediate":
        return {"sysrq": POWER_MODES[mode]}
    argv = ["systemctl", mode]
    if method == "force":
        argv.append("--force")  # skip stopping services one by one
    return {"argv": argv}


class ActionRunner:
    """Run one action, or describe it in a dry run."""

    def __init__(self, config, executor, apply=False):
        self.config = config
        self.executor = executor
        self.apply = apply

    def run(self, action):
        handler = getattr(self, "_" + action["type"])
        try:
            ok, detail = handler(action)
        except ResponseError as error:
            ok, detail = False, {"error": str(error)}
        return ok, detail

    def _lock_session(self, action):
        argv = ["loginctl", "lock-sessions"]  # locks every session when run as root
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
                    self.executor.write_proc("sys/vm/drop_caches", "3\n")
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
            self.executor.sync()  # sysrq does not save pending writes itself
            self.executor.write_proc("sysrq-trigger", command["sysrq"])
            return True, {"mode": action["mode"], "method": action["method"], "issued": command}
        ok, error = self.executor.run(command["argv"])
        return ok, {"mode": action["mode"], "method": action["method"], "issued": command,
                    **({"error": error} if error else {})}


# Pipeline stage

TRIGGER_FIELDS = ("usb_id", "connection_id", "session_id", "reason", "policy_reason", "device", "message")


class ResponseEngine:
    """Decide which records trigger a response, and run the plan."""

    def __init__(self, config, executor, out=emit, apply=False, clock=time.monotonic_ns):
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

    def is_trigger(self, record):
        kind = record.get("type")
        if kind == "enforcement_result":
            return record.get("action") == "block"
        if kind == "enforcement_skipped":
            return self.config.include_skipped and record.get("requested_action") == "block"
        if kind == "lsm_bridge_error":
            return self.config.include_lsm_errors  # opt-in: BPF-LSM protection failed
        return False

    def handle(self, record):
        if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
            self.input_errors += 1
            self.out({"type": "response_input_error", "message": "Expected enforcement schema_version 1"})
            return
        kind = record.get("type")
        if kind == "enforcement_monitor_status":
            healthy = record.get("healthy")
            if type(healthy) is bool and healthy != self.monitor_healthy:
                self.monitor_healthy = healthy
                self.out({"type": "response_monitor_status", "healthy": healthy,
                          "monitor_type": record.get("monitor_type"), "apply": self.apply})
            return
        if kind == "enforcement_stream_closed":
            self.upstream_close = record
            return
        if self.is_trigger(record):
            self.fire(record)

    def fire(self, record):
        """Run the plan for one trigger, unless cooldown or a power-off suppresses it."""
        # Keep upstream reason/message apart from our own fields.
        renamed = {"reason": "trigger_reason", "message": "trigger_message"}
        context = {renamed.get(name, name): record[name] for name in TRIGGER_FIELDS if name in record}
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
                # Log before powering off, in case nothing gets written after.
                self.power_issued = True
                self.out({"type": "response_action", "response_id": response_id, "action": "power",
                          "status": "issuing", "applied": True, "command": power_command(action),
                          "usb_id": context.get("usb_id"),
                          "since_trigger_ns": self.clock() - now})
            started = self.clock()
            ok, detail = self.runner.run(action)
            finished = self.clock()
            if not ok:
                failed += 1
                if action["type"] == "power":
                    self.power_issued = False  # allow a retry
            self.out({"type": "response_action", "response_id": response_id, "action": action["type"],
                      "status": "ok" if ok else "failed", "applied": self.apply, "ok": ok,
                      "duration_ns": finished - started, "since_trigger_ns": finished - now,
                      "detail": detail, "usb_id": context.get("usb_id")})
        self.failures += failed
        self.out({"type": "response_completed", "response_id": response_id, "apply": self.apply,
                  "ok": failed == 0, "failed_actions": failed, "total_ns": self.clock() - now,
                  "usb_id": context.get("usb_id")})

    def outcome(self, interrupted):
        """Return the closing reason and whether the run was ok."""
        if interrupted:
            reason, upstream_ok = "requested_stop", True
        elif self.upstream_close is not None:
            reason = "upstream_" + str(self.upstream_close.get("reason") or "closed")
            upstream_ok = self.upstream_close.get("ok") is True
        else:
            reason, upstream_ok = "unexpected_end_of_input", False
        return reason, upstream_ok and not self.failures and not self.input_errors


def process_stream(engine, stream):
    """Handle each input line, then report how the stream ended."""
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


# Command line

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
