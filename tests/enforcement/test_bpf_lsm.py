#!/usr/bin/env python3
"""Real Linux BPF-LSM acceptance tests. Run with sudo; see docs/STEP6-TESTING.md."""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "src/enforcement/bpf/build/lsm_controller"
sys.path.insert(0, str(REPO / "src/enforcement"))
from lsm_client import LsmClient, LsmClientError


class Controller:
    def __init__(self, mode, paths=(), socket_path=None):
        self.error_log = tempfile.TemporaryFile(mode="w+b")
        self.audit_log = tempfile.TemporaryFile(mode="w+b") if socket_path else None
        self.audit_offset = 0
        self.process = subprocess.Popen(
            [str(BINARY), mode, *( ["--socket", str(socket_path)] if socket_path else ["--control-stdin"] ),
             *map(str, paths)],
            stdin=subprocess.PIPE, stdout=self.audit_log or subprocess.PIPE, stderr=self.error_log)
        self.selector = selectors.DefaultSelector()
        if self.audit_log is None:
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b""
        self.recent = []
        self.sequence = 0
        self.closed = False
        try:
            self.wait_for(lambda row: row["type"] == "lsm_ready")
        except BaseException:
            self.release()
            raise

    def next(self, timeout=15):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            if time.monotonic() >= deadline:
                raise AssertionError("Timed out waiting for controller output")
            if self.audit_log is not None:
                chunk = os.pread(self.audit_log.fileno(), 65536, self.audit_offset)
                self.audit_offset += len(chunk)
                if not chunk and self.process.poll() is None:
                    time.sleep(0.01)
                    continue
            else:
                if not self.selector.select(max(0, deadline - time.monotonic())):
                    continue
                chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise AssertionError("Controller ended unexpectedly: " +
                                     json.dumps(self.recent) + "\n" +
                                     os.pread(self.error_log.fileno(), 65536, 0).decode(errors="replace"))
            self.buffer += chunk
            assert len(self.buffer) <= 1_048_576, "Controller output exceeds test bound"
        line, self.buffer = self.buffer.split(b"\n", 1)
        row = json.loads(line)
        assert row["schema_version"] == 1 and isinstance(row.get("type"), str), row
        self.recent = (self.recent + [row])[-20:]
        return row

    def wait_for(self, predicate):
        deadline = time.monotonic() + 15
        while True:
            row = self.next(max(0.01, deadline - time.monotonic()))
            if predicate(row):
                return row
            assert time.monotonic() < deadline, "Expected controller record did not arrive"

    def request(self, command, **fields):
        self.sequence += 1
        command_id = f"test-{self.sequence}"
        data = json.dumps({"command": command, "command_id": command_id, **fields}) + "\n"
        self.process.stdin.write(data.encode())
        self.process.stdin.flush()
        return self.wait_for(lambda row: row.get("command_id") == command_id)

    def stop(self, expected=0, sig=None):
        if sig is None:
            self.request("stop")
        else:
            self.process.send_signal(sig)
        closing = self.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert self.process.wait(timeout=10) == expected, closing
        assert closing["ok"] is (expected == 0), closing
        self.release()
        return closing

    def release(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.selector.close()
        self.process.stdin.close()
        if self.process.stdout:
            self.process.stdout.close()
        if self.audit_log:
            self.audit_log.close()
        self.error_log.close()


def readable(path):
    with path.open("rb") as stream:
        assert stream.read() == b"PortWatchman fixture\n"


def denied(path, flags=os.O_RDONLY):
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        assert error.errno == errno.EACCES, f"Expected EACCES, got {error!r}"
    else:
        os.close(descriptor)
        raise AssertionError(f"Restricted file opened successfully: {path}")


def refused(change):
    try:
        change()
    except OSError as error:
        assert error.errno == errno.EACCES, f"Expected EACCES, got {error!r}"
    else:
        raise AssertionError("A protected file was changed")


def check_rejected(mode, path):
    result = subprocess.run([str(BINARY), mode, "--inspect", str(path)],
                            capture_output=True, timeout=10, text=True)
    assert result.returncode != 0, f"Accepted invalid target: {path}"
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert any(row["type"] == "lsm_error" and row["reason"] == "invalid_target" for row in rows), result


def run_checks(mode, directory, loop_device=None):
    files = [directory / name for name in ("restricted.txt", "second.txt", "control.txt")]
    for path in files:
        with path.open("xb") as stream:
            stream.write(b"PortWatchman fixture\n")
        readable(path)
    check_rejected(mode, directory)
    check_rejected(mode, directory / "missing")
    if mode in ("--test-loopback", "--local-files"):
        alias = directory / "symlink"
        alias.symlink_to(files[0].name)
        check_rejected(mode, alias)
    # Host-root target must never be accepted in physical-USB mode.
    check_rejected("--usb", Path("/etc/hostname"))
    if mode != "--local-files":
        check_rejected("--local-files", files[0])
    print("PASS: invalid targets rejected; all fixture files readable before enforcement", flush=True)

    client = Controller(mode, [files[0]])
    try:
        denied(files[0])
        denied(files[0], os.O_WRONLY)
        readable(files[1])
        readable(files[2])
        state = client.request("status")
        assert state["type"] == "lsm_status" and state["denied_opens"] >= 1, state
        first = state["targets"][0]
        assert first["denied_opens"] >= 1
        added = client.request("restrict", path=str(files[1]))
        assert added["type"] == "lsm_target_added", added
        second_id = added["target"]["target_id"]
        denied(files[0])
        denied(files[1])
        readable(files[2])
        removed = client.request("unrestrict", target_id=first["target_id"])
        assert removed["type"] == "lsm_target_removed", removed
        readable(files[0])
        denied(files[1])
        state = client.request("status")
        assert len(state["targets"]) == 1 and state["denied_opens"] >= 3, state
        assert state["targets"][0]["target_id"] == second_id
        client.stop()
    finally:
        client.release()
    for path in files:
        readable(path)
    print("PASS: multiple targets, exact EACCES, counters, runtime removal, clean stop/detach", flush=True)

    # Existing inode stays protected after a rename; a replacement inode is not enrolled.
    client = Controller(mode, [files[0]])
    renamed = directory / "renamed.txt"
    try:
        files[0].rename(renamed)
        with files[0].open("xb") as stream:
            stream.write(b"PortWatchman fixture\n")
        denied(renamed)
        readable(files[0])
        client.stop(sig=signal.SIGTERM)
    finally:
        client.release()
    readable(renamed)
    print("PASS: identity semantics survive rename; replacement not automatically enrolled; SIGTERM detaches", flush=True)

    client = Controller(mode, [files[1]])
    other = directory / "other.txt"
    other.write_bytes(b"replacement\n")
    try:
        for change in (files[1].unlink, lambda: other.replace(files[1]), lambda: os.truncate(files[1], 0)):
            refused(change)
        state = client.request("status")
        assert len(state["targets"]) == 1 and state["denied_changes"] >= 3 and state["failures"] == 0, state
        client.stop()
    finally:
        client.release()
        other.unlink()
    readable(files[1])
    print("PASS: delete, replace and truncate of a protected file refused; target kept; clean stop", flush=True)

    client = Controller(mode)
    try:
        response = client.request("restrict", path=str(directory / "missing"))
        assert response["type"] == "lsm_error", response
        readable(files[2])
        client.stop(expected=1)
    finally:
        client.release()
    client = Controller(mode, [files[0]])
    try:
        duplicate = client.request("restrict", path=str(files[0]))
        assert duplicate["type"] == "lsm_error" and duplicate["reason"] == "duplicate_target", duplicate
        denied(files[0])
        readable(files[2])
        client.stop(expected=1)
    finally:
        client.release()
    client = Controller(mode)
    try:
        client.process.stdin.close()
        closing = client.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert not closing["ok"] and client.process.wait(timeout=10) == 1, closing
    finally:
        client.release()
    client = Controller(mode)
    try:
        client.process.stdin.write(b"x" * 65536)
        client.process.stdin.flush()
        closing = client.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert not closing["ok"] and client.process.wait(timeout=10) == 1, closing
    finally:
        client.release()
    print("PASS: rejected/duplicate commands, oversized input and unexpected control EOF remain failures", flush=True)
    if mode == "--local-files":
        local_socket_checks(files)
    else:
        socket_checks(mode, files, loop_device=loop_device)


def local_socket_checks(files):
    from lsm_local import LocalFileGuard, LocalGuardConfig, LocalGuardError
    parent = Path(tempfile.mkdtemp(prefix="portwatchman-local-test-", dir="/run"))
    owner = parent.stat()
    path = parent / "controller.sock"
    controller = None
    try:
        controller = Controller("--local-files", socket_path=path)
        client = LsmClient(str(path))
        guard = LocalFileGuard(LocalGuardConfig(str(path), tuple(map(str, files[:2]))), client=client)
        # An existing data descriptor is explicitly outside the new-open guard.
        with files[0].open("rb") as existing:
            registered = guard.start()
            assert registered["protection_complete"] is True
            assert existing.read() == b"PortWatchman fixture\n"
            denied(files[0])
            denied(files[0], os.O_WRONLY)
            denied(files[1])
            readable(files[2])
        state = client.status()
        assert state["mode"] == "local-files" and state["failures"] == 0
        assert len(state["targets"]) == 2 and state["denied_opens"] >= 3
        assert all(target["usb_id"] is None for target in state["targets"])
        guard.verify()
        # Manual removal must be detected; the manager never silently re-adds it.
        target = state["targets"][0]
        client.request("REMOVE", target_id=target["target_id"], connection_id=guard.owner_id)
        try:
            guard.verify()
        except LocalGuardError:
            pass
        else:
            raise AssertionError("A missing VM-file registration was not detected")
        client.request("STOP")
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert closing["ok"] and controller.process.wait(timeout=10) == 0, closing
        controller.release()
        for file in files:
            readable(file)
        controller = Controller("--local-files", socket_path=path)
        client = LsmClient(str(path))
        guard = LocalFileGuard(LocalGuardConfig(str(path), (str(files[0]),)), client=client)
        guard.start()
        try:
            client.request("PREPARE_REMOVE", connection_id=guard.owner_id)
        except LsmClientError as error:
            assert "unsupported_command" in str(error)
        else:
            raise AssertionError("USB removal command released VM files")
        denied(files[0])
        client.request("STOP")
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert not closing["ok"] and controller.process.wait(timeout=10) == 1, closing
        readable(files[0])
        print("PASS: VM-file socket registration, exact read/write denial, pre-existing descriptor boundary, missing-entry detection and independent ownership", flush=True)
    finally:
        if controller:
            controller.release()
        current = parent.stat()
        if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
            raise RuntimeError("Local test socket directory ownership changed; refusing cleanup")
        shutil.rmtree(parent)


def socket_checks(mode, files, loop_device=None):
    parent = Path(tempfile.mkdtemp(prefix="portwatchman-lsm-test-", dir="/run"))
    owner = parent.stat()
    path = parent / "controller.sock"
    controller = None
    try:
        controller = Controller(mode, socket_path=path)
        client = LsmClient(str(path))
        assert parent.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600
        state = client.status()
        assert not state["targets"]
        assert state["mode"] == ("usb" if mode == "--usb" else "test-loopback")
        # An ordinary non-root process cannot reach the socket at all.
        child_code = ('import socket,sys,json; s=socket.socket(socket.AF_UNIX); '
                      's.settimeout(3); s.connect(sys.argv[1]); '
                      'print(s.recv(1024).decode())')
        def nobody():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        child = subprocess.run([sys.executable, "-c", child_code, str(path)],
                               preexec_fn=nobody, capture_output=True, text=True, timeout=5)
        assert child.returncode != 0 and "PermissionError" in child.stderr, child
        # Relax ONLY this owned disposable fixture to exercise SO_PEERCRED itself.
        try:
            parent.chmod(0o711)
            path.chmod(0o666)
            child = subprocess.run([sys.executable, "-c", child_code, str(path)],
                                   preexec_fn=nobody, capture_output=True, text=True, timeout=5)
            assert child.returncode == 0 and json.loads(child.stdout)["reason"] == "unauthorized_client", child
        finally:
            path.chmod(0o600)
            parent.chmod(0o700)
        assert client.status()["rejected_clients"] >= 1
        # One stalled authenticated client must not block other clients or expiry.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5)
            raw.connect(str(path))
            raw.sendall(b'{"command":')
            assert client.status()["enforcement_active"] is True
            assert raw.recv(1024) == b"", "Incomplete request did not expire"
        added = client.request("ADD", path=str(files[0]))
        first = added["target"]
        second = client.request("ADD", path=str(files[1]))["target"]
        denied(files[0])
        denied(files[1])
        readable(files[2])
        state = client.request("LIST")
        assert len(state["targets"]) == 2 and state["denied_opens"] >= 2
        removed = client.request("REMOVE", target_id=first["target_id"])
        assert removed["type"] == "lsm_target_removed"
        readable(files[0])
        denied(files[1])
        assert client.request("REMOVE", target_id=first["target_id"])["type"] == "lsm_target_absent"
        expected = {"expected_" + key: first[key] for key in ("major", "minor", "inode", "mount_id")}
        expected.update(expected_usb_id=first["usb_id"], expected_address=first["device_address"])
        bad_expected = {**expected, "expected_inode": first["inode"] + 1}
        try:
            client.request("ADD", path=str(files[0]), connection_id="test:connection", **bad_expected)
        except LsmClientError as error:
            assert "target_context_mismatch" in str(error)
        else:
            raise AssertionError("Changed file identity was accepted")
        owned = client.request("ADD", path=str(files[0]), connection_id="test:connection", **expected)["target"]
        try:
            client.request("REMOVE", target_id=owned["target_id"], connection_id="old:connection")
        except LsmClientError as error:
            assert "connection_mismatch" in str(error)
        else:
            raise AssertionError("Old connection removed a new registration")
        denied(files[0])
        client.request("REMOVE", target_id=owned["target_id"], connection_id="test:connection")
        # A second controller must refuse an existing socket, never unlink it.
        result = subprocess.run([str(BINARY), mode, "--socket", str(path)], capture_output=True, timeout=10)
        assert result.returncode != 0 and path.exists(), result
        assert client.status()["controller_id"] == state["controller_id"]
        try:
            client.request("ADD", path=str(files[1]))
        except LsmClientError as error:
            assert "duplicate_target" in str(error)
        else:
            raise AssertionError("Duplicate socket registration was accepted")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5)
            raw.connect(str(path))
            raw.sendall(b'{"command":42}\n')
            assert json.loads(raw.recv(65536))["type"] == "lsm_error"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(5)
            raw.connect(str(path))
            raw.sendall(b"x" * 65536)
            assert json.loads(raw.recv(65536))["reason"] == "invalid_frame"
        assert client.status()["rejected_requests"] >= 1
        client.request("REMOVE", target_id=second["target_id"])
        client.request("STOP")
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert not closing["ok"] and controller.process.wait(timeout=10) == 1, closing
        assert not path.exists(), "Controller did not remove its own socket"
        controller.release()
        # A clean STOP succeeds without poisoning the outcome from earlier tests.
        controller = Controller(mode, socket_path=path)
        LsmClient(str(path)).request("STOP")
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert closing["ok"] and controller.process.wait(timeout=10) == 0, closing
        controller.release()
        controller = Controller(mode, socket_path=path)
        client = LsmClient(str(path))
        old_connection = "fixture:removal:1"
        def owned_add(file, connection):
            inspection = subprocess.run([str(BINARY), mode, "--inspect", str(file)],
                                        capture_output=True, text=True, timeout=10, check=True)
            identity = next(json.loads(line)["target"] for line in inspection.stdout.splitlines()
                            if json.loads(line)["type"] == "lsm_target_inspected")
            expected = {"expected_" + key: identity[key] for key in ("major", "minor", "inode", "mount_id")}
            expected.update(expected_usb_id=identity["usb_id"], expected_address=identity["device_address"])
            return client.request("ADD", path=str(file), connection_id=connection, **expected)
        old_id = owned_add(files[0], old_connection)["target"]["target_id"]
        owned_add(files[1], old_connection)
        unrelated = client.request("ADD", path=str(files[2]))["target"]["target_id"]
        if loop_device:
            mountpoint = files[0].parent
            actual = subprocess.check_output(["findmnt", "-n", "-o", "SOURCE", "--target", str(mountpoint)], text=True).strip()
            assert actual == loop_device and re.fullmatch(r"/dev/loop[0-9]+", loop_device), actual
            busy = subprocess.run(["umount", str(mountpoint)], capture_output=True, text=True)
            assert busy.returncode != 0 and os.path.ismount(mountpoint), "Expected held references to keep the owned loop mount busy"
        prepared = client.request("PREPARE_REMOVE", connection_id=old_connection)
        assert prepared["type"] == "lsm_connection_prepared" and prepared["removed_targets"] == 2, prepared
        state = client.status()
        assert old_connection in state["prepared_connections"] and state["failures"] == 0, state
        assert [t["target_id"] for t in state["targets"]] == [unrelated], state
        readable(files[0])
        readable(files[1])
        denied(files[2])
        client.request("REMOVE", target_id=unrelated)
        assert client.request("PREPARE_REMOVE", connection_id=old_connection)["already_prepared"] is True
        blocked_add = owned_add(files[0], old_connection)
        assert blocked_add["type"] == "lsm_connection_prepared", blocked_add
        assert not client.status()["targets"]
        if loop_device:
            # Only our verified, disposable loop fixture is unmounted/remounted.
            subprocess.run(["umount", str(mountpoint)], check=True)
            assert client.status()["enforcement_active"] is True
            subprocess.run(["mount", loop_device, str(mountpoint)], check=True)
        fresh = owned_add(files[0], "fixture:removal:2")["target"]
        assert fresh["target_id"] > old_id
        client.request("PREPARE_REMOVE", connection_id=old_connection)
        denied(files[0])
        assert client.status()["targets"][0]["connection_id"] == "fixture:removal:2"
        client.request("REMOVE", target_id=fresh["target_id"], connection_id="fixture:removal:2")
        assert client.status()["failures"] == 0
        client.request("STOP")
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert closing["ok"] and controller.process.wait(timeout=10) == 0, closing
        controller.release()
        print("PASS: coordinated removal, connection isolation, pending ADD refusal and mount-reference release", flush=True)
        # Replacement path belongs to the test, not the controller's socket inode.
        controller = Controller(mode, socket_path=path)
        original = path.lstat()
        assert original.st_uid == 0
        path.unlink()
        path.write_text("replacement owned by the fixture\n")
        controller.process.send_signal(signal.SIGTERM)
        closing = controller.wait_for(lambda row: row["type"] == "lsm_stopped")
        assert closing["ok"] and controller.process.wait(timeout=10) == 0, closing
        assert path.read_text() == "replacement owned by the fixture\n", "Controller removed a replacement path"
        readable(files[0])
        readable(files[1])
        print("PASS: socket commands, multiple targets, permissions, peer authentication, invalid input and shutdown", flush=True)
    finally:
        if controller:
            controller.release()
        current = parent.stat()
        if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
            raise RuntimeError("Socket fixture ownership changed; refusing cleanup")
        shutil.rmtree(parent)


def usb_directory(path):
    directory = path.resolve(strict=True)
    if directory.stat().st_dev == Path("/").stat().st_dev:
        raise SystemExit("Refusing the guest root filesystem")
    node = Path(f"/sys/dev/block/{os.major(directory.stat().st_dev)}:{os.minor(directory.stat().st_dev)}").resolve(strict=True)
    for ancestor in (node, *node.parents):
        try:
            if (ancestor / "subsystem").resolve(strict=True) == Path("/sys/bus/usb") and (ancestor / "idVendor").is_file():
                return directory
        except FileNotFoundError:
            continue
    raise SystemExit("The selected directory is not on a verified USB filesystem")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--loopback", action="store_true")
    modes.add_argument("--local", action="store_true", help="Use disposable files on the VM's internal filesystem")
    modes.add_argument("--usb", type=Path, metavar="MOUNT_DIRECTORY")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run inside Ubuntu with sudo")
    if not BINARY.is_file():
        parser.error("Build the controller first")
    subprocess.run([str(BINARY), "--check"], check=True)
    if args.local:
        base = (REPO / "build/test-tmp").resolve()
        base.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix="lsm-local-", dir=base)).resolve()
        owner = temporary.stat()
        try:
            run_checks("--local-files", temporary)
        finally:
            current = temporary.stat()
            if temporary.parent != base or (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
                raise RuntimeError("Local fixture ownership changed; refusing cleanup")
            shutil.rmtree(temporary)
    elif args.usb:
        directory = usb_directory(args.usb)
        # Only this newly owned fixture directory is created/deleted on the drive.
        temporary = Path(tempfile.mkdtemp(prefix="portwatchman-lsm-", dir=directory))
        owner = temporary.stat()
        try:
            run_checks("--usb", temporary)
        finally:
            if temporary.exists():
                current = temporary.stat()
                if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
                    raise RuntimeError("USB fixture ownership changed; refusing cleanup")
                shutil.rmtree(temporary)
    else:
        for command in ("mkfs.ext4", "losetup", "mount", "umount", "findmnt"):
            if not shutil.which(command):
                parser.error(f"Missing command: {command}")
        base = REPO / "build/test-tmp"
        base.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="lsm-loop-", dir=base)).resolve()
        assert work.parent == base.resolve()
        image, mountpoint = work / "test.img", work / "mount"
        mountpoint.mkdir()
        with image.open("xb") as stream:
            stream.truncate(64 * 1024 * 1024)
        device = None
        try:
            subprocess.run(["mkfs.ext4", "-q", "-F", str(image)], check=True)
            device = subprocess.check_output(["losetup", "--find", "--show", str(image)], text=True).strip()
            assert re.fullmatch(r"/dev/loop[0-9]+", device), device
            subprocess.run(["mount", device, str(mountpoint)], check=True)
            run_checks("--test-loopback", mountpoint, loop_device=device)
        finally:
            if os.path.ismount(mountpoint):
                actual = subprocess.check_output(["findmnt", "-n", "-o", "SOURCE", "--target", str(mountpoint)], text=True).strip()
                if actual != device:
                    raise RuntimeError("Mount ownership changed; refusing cleanup")
                subprocess.run(["umount", str(mountpoint)], check=True)
            if device:
                backing = subprocess.check_output(["losetup", "--noheadings", "--output", "BACK-FILE", device], text=True).strip()
                if Path(backing).resolve() != image:
                    raise RuntimeError("Loop-device ownership changed; refusing detach")
                subprocess.run(["losetup", "--detach", device], check=True)
            shutil.rmtree(work)  # verified, owned workspace; no mount remains
    print("All BPF-LSM acceptance checks passed", flush=True)


if __name__ == "__main__":
    main()
