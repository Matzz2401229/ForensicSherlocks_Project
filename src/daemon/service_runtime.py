"""Foreground supervision, ordered pipe relays and Linux service ownership."""
from __future__ import annotations
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import threading
import time

from service_config import ROOT, RUNTIME, ServiceError, commands, components, parse

PIPELINE = ("monitor", "policy", "enforcement", "responses")
MAX_LINE = 4 * 1024 * 1024 + 65536


class StopRequested(ServiceError):
    pass


def require_linux_root():
    import sys
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ServiceError("The running service requires root inside the Ubuntu system under test")


def secure_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ServiceError(f"Expected a privately owned directory with mode 0700: {path}")


def write_json(path, value):
    import tempfile
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".service-", delete=False) as output:
            temp = Path(output.name)
            json.dump(value, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


class Lease:
    def __init__(self, directory=RUNTIME):
        self.directory = Path(directory)
        self.fd = None

    def acquire(self):
        import fcntl
        secure_directory(self.directory)
        # Keep the lock inode outside systemd's RuntimeDirectory lifecycle.
        lock_path = self.directory.with_name(self.directory.name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise ServiceError("Unsafe service lock file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ServiceError("Another PortWatchman service operation already owns the lock") from error
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def process_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw.rsplit(")", 1)[1].split()[19]


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def owner_path(state_path):
    return Path(str(state_path) + ".service-owner.json")


def restore_owned(manager, state_path):
    from usb_authorization import restore
    marker = owner_path(state_path)
    if marker.exists():
        owner = parse(marker.read_bytes())
        if (not isinstance(owner, dict) or owner.get("boot_id") != boot_id()
                or owner.get("state_file") != str(state_path)):
            raise ServiceError("Saved service state has a different boot/path identity; inspect it before manual recovery")
    elif Path(state_path).exists():
        raise ServiceError("Saved arm state is not owned by the service; use its original enforcement configuration to restore")
    result = restore(manager, state_path, apply=True)
    marker.unlink(missing_ok=True)
    return result


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.sendto(message.encode("utf-8"), address)


def enable_subreaper():
    # Adopt an orphaned bpftrace if its monitor crashes, so cleanup can reap it.
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "Cannot become a child subreaper")


def orphan_children(known):
    text = Path(f"/proc/self/task/{os.getpid()}/children").read_text()
    return [int(value) for value in text.split() if int(value) not in known]


def clean_orphans(known, emit):
    """Signal only children currently adopted by this dedicated supervisor."""
    clean = True
    for sig in (signal.SIGINT, signal.SIGKILL):
        children = orphan_children(known)
        if not children:
            return clean
        for pid in children:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            remaining = []
            for pid in orphan_children(known):
                try:
                    reaped, status = os.waitpid(pid, os.WNOHANG)
                    if reaped:
                        emit({"type": "service_orphan_reaped", "pid": pid, "wait_status": status})
                    else:
                        remaining.append(pid)
                except ChildProcessError:
                    pass
            if not remaining:
                return clean
            time.sleep(0.05)
        clean = False  # Requiring SIGKILL is recorded as an unsuccessful cleanup.
    return False


class Health:
    def __init__(self, lsm=False):
        self.lock = threading.Lock()
        self.flags = set()
        self.error = None
        self.closing = {}
        self.lsm = lsm

    def fail(self, message):
        with self.lock:
            if self.error is None:
                self.error = str(message)

    def observe(self, stage, record):
        kind = record.get("type")
        if type(record.get("schema_version")) is not int or record["schema_version"] != 1 or not isinstance(kind, str):
            raise ServiceError(f"{stage} emitted an invalid event envelope")
        with self.lock:
            if stage == "lsm" and kind == "lsm_ready":
                if record.get("mode") != "usb":
                    self.error = "Controller did not start in USB mode"
                self.flags.add("lsm")
            if stage == "monitor" and kind == "monitor_alive":
                self.flags.add("monitor")
            if stage in ("policy", "enforcement", "responses") and kind == {
                    "policy": "policy_monitor_status", "enforcement": "enforcement_monitor_status",
                    "responses": "response_monitor_status"}[stage] and record.get("healthy") is True:
                self.flags.add(stage)
            if stage == "enforcement" and kind == "enforcement_started":
                self.flags.add("enforcement_started")
            if stage == "responses" and kind == "response_started":
                self.flags.add("response_started")
            if stage == "enforcement" and kind == "lsm_bridge_started":
                self.flags.add("bridge")
            if kind.endswith("_stream_closed") or kind in ("monitor_stopped", "lsm_stopped"):
                self.closing[stage] = record
            failure = (kind.endswith("_error") or kind in ("monitor_loss", "monitor_diagnostic")
                       or record.get("degraded") is True or record.get("ok") is False
                       or (kind == "lsm_status" and record.get("failures", 0) != 0))
            if failure and self.error is None:
                self.error = f"{stage}: {kind}: {record.get('message', record.get('reason', 'reported failure'))}"

    def ready(self):
        required = set(PIPELINE) | {"enforcement_started", "response_started"}
        if self.lsm:
            required |= {"lsm", "bridge"}
        with self.lock:
            return self.error is None and required <= self.flags

    def failure(self):
        with self.lock:
            return self.error


class Host:
    def __init__(self, config, emit):
        self.config = config
        self.emit = emit
        self.parts = components(config)
        self.policy, self.enforcement, self.responses, self.bridge = self.parts
        from usb_authorization import BusManager
        self.manager = BusManager(self.enforcement)

    def control(self, args):
        process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, errors = process.communicate(timeout=self.config.command_timeout)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise ServiceError(f"Preflight command timed out: {args}") from error
        if process.returncode:
            raise ServiceError(f"Command failed ({process.returncode}): {args}: {errors.decode(errors='replace')[-1000:]}")
        if len(output) > MAX_LINE:
            raise ServiceError("Preflight output exceeded the record limit")
        records = [parse(line) for line in output.splitlines() if line.strip()]
        for record in records:
            self.emit({"type": "service_preflight_record", "event": record})
        return records

    def preflight(self):
        from usb_authorization import load_state
        if load_state(self.enforcement.state_file) is not None or owner_path(self.enforcement.state_file).exists():
            raise ServiceError("Existing arm state found. Restore it with its owning configuration before starting the service")
        self.manager.discover()
        plan = commands(self.config)
        checked = self.control([*plan["monitor"], "--check"])
        if not any(isinstance(r, dict) and r.get("type") == "monitor_preflight" and r.get("status") == "passed" for r in checked):
            raise ServiceError("Monitor did not confirm a passed preflight")
        if self.bridge:
            binary = ROOT / "src/enforcement/bpf/build/lsm_controller"
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise ServiceError("Build the native controller before enabling the LSM bridge")
            if os.path.lexists(self.bridge.socket_path):
                raise ServiceError("An LSM socket already exists; stop its owner before starting this service")
            checked = self.control([str(binary), "--check"])
            if not any(isinstance(r, dict) and r.get("type") == "lsm_preflight_passed" for r in checked):
                raise ServiceError("Controller did not confirm a passed preflight")
        from device_policy import DeviceReader
        reader = DeviceReader()
        inventory = []
        buses = {int(bus[3:]) for bus in self.manager.discover()}
        for usb_id in reader.list_ids():
            try:
                device = reader.read(usb_id)
                if device["bus"] in buses and not device["is_root_hub"]:
                    inventory.append({"usb_id": usb_id, "kernel_authorized": device["kernel_authorized"]})
            except Exception as error:
                raise ServiceError(f"Cannot inspect startup device {usb_id}: {error}") from error
        self.emit({"type": "service_startup_inventory", "devices": inventory,
                   "scope": "new connections only; existing devices are not automatically reconciled or revoked"})

    def prepare(self):
        enable_subreaper()

    def arm(self):
        from usb_authorization import arm
        state_path = self.enforcement.state_file
        state_path.parent.mkdir(parents=True, exist_ok=True)
        marker = owner_path(state_path)
        if marker.exists() or state_path.exists():
            raise ServiceError("Arm state appeared after preflight; refusing to adopt it")
        write_json(marker, {"schema_version": 1, "boot_id": boot_id(), "state_file": str(state_path)})
        return arm(self.manager, self.enforcement.state_file, apply=True)

    def restore(self):
        return restore_owned(self.manager, self.enforcement.state_file)

    def controller_command(self):
        return [str(ROOT / "src/enforcement/bpf/build/lsm_controller"), "--usb", "--serve", "--socket", self.bridge.socket_path]

    def spawn(self, args, stdin):
        env = dict(os.environ)
        for key in ("PYTHONPATH", "PYTHONHOME", "NOTIFY_SOCKET"):
            env.pop(key, None)
        env.update(PYTHONUNBUFFERED="1", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
        env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
        return subprocess.Popen(args, cwd=ROOT, stdin=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, env=env)

    def signal(self, process, sig):
        if process.poll() is None:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass

    def orphans(self, processes):
        return clean_orphans({p.pid for p in processes}, self.emit)


class Supervisor:
    def __init__(self, config, host, emit, state=None, notifier=notify, clock=time.monotonic):
        self.config, self.host, self.emit = config, host, emit
        self.state = state or (lambda _phase, _fields: None)
        self.notifier, self.clock = notifier, clock
        self.health = Health(config.lsm is not None)
        self.stop = threading.Event()
        self.processes = {}
        self.threads = []
        self.arm_attempted = False

    def save_state(self, phase, fields):
        try:
            self.state(phase, fields)
            return True
        except (OSError, ValueError) as error:
            self.health.fail(f"Cannot save service status: {error}")
            self.emit({"type": "service_state_error", "message": str(error)})
            return False

    def send_notify(self, message):
        try:
            self.notifier(message)
        except OSError as error:
            self.health.fail(f"Cannot notify systemd: {error}")
            self.emit({"type": "service_notify_error", "message": str(error)})

    def relay(self, stage, stream, destination=None, diagnostic=False):
        try:
            while True:
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    raise ServiceError(f"{stage} emitted an oversized line")
                if diagnostic:
                    self.emit({"type": "service_diagnostic", "stage": stage,
                               "message": raw.decode("utf-8", errors="replace").rstrip()})
                    continue
                if not raw.strip():
                    continue
                record = parse(raw)
                if not isinstance(record, dict):
                    raise ServiceError(f"{stage} emitted a non-object record")
                self.health.observe(stage, record)
                self.emit({"type": "service_stage_event", "stage": stage, "event": record})
                if destination is not None:
                    destination.write(raw)
                    destination.flush()
        except Exception as error:
            self.health.fail(f"{stage} relay failed: {error}")
        finally:
            stream.close()
            if destination is not None:
                try:
                    destination.close()
                except OSError as error:
                    self.health.fail(f"Cannot close {stage} output: {error}")

    def spawn(self, stage, args, destination=None):
        process = self.host.spawn(args, subprocess.DEVNULL if stage in ("monitor", "lsm") else subprocess.PIPE)
        self.processes[stage] = process
        for stream, target, diagnostic in ((process.stdout, destination, False), (process.stderr, None, True)):
            thread = threading.Thread(target=self.relay, args=(stage, stream, target, diagnostic), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.emit({"type": "service_child_started", "stage": stage, "pid": process.pid})
        return process

    def wait_for(self, predicate, timeout):
        deadline = self.clock() + timeout
        while True:
            if self.stop.is_set():
                raise StopRequested("Stop requested during startup")
            if self.health.failure():
                raise ServiceError(self.health.failure())
            for stage, process in self.processes.items():
                code = process.poll()
                if code is not None:
                    raise ServiceError(f"{stage} exited during startup with status {code}")
            if predicate():
                return
            if self.clock() >= deadline:
                raise ServiceError("Component readiness deadline expired")
            self.stop.wait(0.1)

    def wait_exit(self, stages, timeout):
        deadline = self.clock() + timeout
        while any(self.processes[name].poll() is None for name in stages if name in self.processes):
            if self.clock() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def shutdown(self, requested):
        self.save_state("stopping", {"requested": requested})
        self.send_notify("STOPPING=1\nSTATUS=Releasing component pipeline")
        clean = True
        pipeline = [name for name in PIPELINE if name in self.processes]
        if "monitor" in self.processes:
            self.host.signal(self.processes["monitor"], signal.SIGINT)
        elif pipeline:
            # Startup may have failed before the upstream producer was launched.
            self.processes[pipeline[0]].stdin.close()
        if not self.wait_exit(pipeline, self.config.shutdown_timeout):
            clean = False
            self.emit({"type": "service_shutdown_timeout", "scope": "pipeline"})
            for stage in pipeline:
                self.host.signal(self.processes[stage], signal.SIGINT)
            if not self.wait_exit(pipeline, 5):
                for stage in pipeline:
                    self.host.signal(self.processes[stage], signal.SIGKILL)
                clean &= self.wait_exit(pipeline, 5)
        # The bridge must finish releasing targets before its controller exits.
        if "lsm" in self.processes:
            self.host.signal(self.processes["lsm"], signal.SIGINT)
            if not self.wait_exit(["lsm"], 5):
                clean = False
                self.host.signal(self.processes["lsm"], signal.SIGKILL)
                self.wait_exit(["lsm"], 5)
        exited = all(process.poll() is not None for process in self.processes.values())
        orphan_clean = False
        if exited:
            for process in self.processes.values():
                process.wait()
            try:
                orphan_clean = self.host.orphans(list(self.processes.values()))
            except OSError as error:
                self.emit({"type": "service_cleanup_error", "message": str(error)})
            clean &= orphan_clean
        else:
            clean = False
        for thread in self.threads:
            thread.join(timeout=1)
            if thread.is_alive():
                clean = False
        codes = {name: process.poll() for name, process in self.processes.items()}
        clean &= all(code == 0 for code in codes.values())
        restored = False
        if requested and self.arm_attempted and exited and orphan_clean and not any(thread.is_alive() for thread in self.threads):
            try:
                self.emit({"type": "service_bus_restore", "event": self.host.restore()})
                restored = True
            except Exception as error:
                clean = False
                self.emit({"type": "service_restore_error", "message": str(error)})
        elif self.arm_attempted:
            self.emit({"type": "service_bus_state_retained",
                       "message": "Default-deny and saved originals retained; inspect the failure and restore manually"})
        return clean, restored, codes

    def run(self):
        requested = False
        error = None
        try:
            if not self.save_state("starting", {}):
                raise ServiceError(self.health.failure())
            if self.stop.is_set():
                raise StopRequested("Stop requested before preflight")
            self.host.prepare()
            self.host.preflight()
            if self.stop.is_set():
                raise StopRequested("Stop requested before starting components")
            startup_deadline = self.clock() + self.config.startup_timeout
            if self.config.lsm:
                self.spawn("lsm", self.host.controller_command())
                self.wait_for(lambda: "lsm" in self.health.flags, max(0, startup_deadline - self.clock()))
            if self.stop.is_set():
                raise StopRequested("Stop requested before arming")
            self.arm_attempted = True  # Partial arm failures also own a recovery state.
            self.emit({"type": "service_bus_arm", "event": self.host.arm()})
            plan = commands(self.config)
            response = self.spawn("responses", plan["responses"])
            enforce = self.spawn("enforcement", plan["enforcement"], response.stdin)
            policy = self.spawn("policy", plan["policy"], enforce.stdin)
            self.spawn("monitor", plan["monitor"], policy.stdin)
            self.wait_for(self.health.ready, max(0, startup_deadline - self.clock()))
            if not self.save_state("running", {"healthy": True}):
                raise ServiceError(self.health.failure())
            self.emit({"type": "service_ready", "apply_responses": self.config.apply_responses,
                       "lsm_enabled": self.config.lsm is not None, "scope": "new USB connections"})
            self.send_notify("READY=1\nSTATUS=USB pipeline ready")
            while not self.stop.wait(0.2):
                if self.health.failure():
                    raise ServiceError(self.health.failure())
                for name, process in self.processes.items():
                    if process.poll() is not None:
                        raise ServiceError(f"{name} exited unexpectedly with status {process.returncode}")
            requested = True
        except StopRequested:
            requested = True
        except Exception as failure:
            error = str(failure)
            requested = self.stop.is_set()
            self.emit({"type": "service_error", "message": error})
        finally:
            clean, restored, codes = self.shutdown(requested)
        ok = requested and error is None and clean and self.health.failure() is None
        fields = {"ok": ok, "healthy": False, "buses_restored": restored, "exit_codes": codes,
                  "reason": error or self.health.failure() or ("requested_stop" if requested else "failure")}
        if not self.save_state("stopped" if ok else "failed", fields):
            ok = False
            fields.update(ok=False, reason=self.health.failure())
        self.emit({"type": "service_stopped", **fields})
        return 0 if ok else 1
