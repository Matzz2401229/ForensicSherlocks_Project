#!/usr/bin/env python3
"""Observe USB kernel hooks and emit newline-delimited JSON; never enforce policy."""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

PROBES = ("kprobe:usb_new_device", "kretprobe:usb_new_device", "kprobe:usb_disconnect")
SCRIPT = Path(__file__).with_name("usb_events.bt")
PORT = re.compile(r"(?:0|[1-9][0-9]*(?:\.[1-9][0-9]*)*)\Z")
LOSS = re.compile(r"\blost\s+(\d+)\s+events?\b", re.IGNORECASE)


def emit(record: dict) -> None:
    print(json.dumps({"schema_version": 1, **record}, separators=(",", ":")), flush=True)


class Decoder:
    """Validate backend frames; correlate generations without hiding duplicates."""

    def __init__(self, boot_id: str):
        self.boot_id = boot_id
        self.connections: OrderedDict[tuple, tuple[int, str | None]] = OrderedDict()
        self.seen: set[tuple] = set()
        self.order: deque[tuple] = deque()

    def decode(self, line: str, received_ns: int | None = None) -> dict:
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 3 or parts[0] != "PW1":
            raise ValueError("Unrecognised backend frame")
        kind = parts[1]
        timestamp = int(parts[2])
        if timestamp <= 0:
            raise ValueError("Invalid kernel timestamp")
        base = {"source": "ebpf", "timestamp_ns": timestamp, "clock": "monotonic"}
        if received_ns is not None:
            base["received_timestamp_ns"] = received_ns
            base["delivery_delay_ns"] = max(0, received_ns - timestamp)
        if kind in ("heartbeat", "backend_stopped"):
            if len(parts) != 3:
                raise ValueError("Invalid lifecycle frame")
            return {**base, "type": "monitor_heartbeat" if kind == "heartbeat"
                    else "monitor_backend_stopped"}
        if len(parts) != 8 or kind not in ("setup_started", "setup_result", "disconnect_started"):
            raise ValueError("Invalid USB frame")
        start, bus, address, result = map(int, (parts[3], parts[4], parts[5], parts[7]))
        port = parts[6]
        if not 1 <= bus <= 9999 or not 1 <= address <= 127 or not PORT.fullmatch(port):
            raise ValueError("Invalid USB location")
        if kind != "disconnect_started" and not 0 < start <= timestamp:
            raise ValueError("Invalid setup timestamp")
        if kind == "setup_started" and (start != timestamp or result != 0):
            raise ValueError("Inconsistent setup-start frame")
        if kind == "disconnect_started" and (start != 0 or result != 0):
            raise ValueError("Inconsistent disconnect frame")
        if kind == "setup_result" and result > 0:
            raise ValueError("Unexpected positive setup result")

        location = (bus, port, address)
        prior_time, prior_id = self.connections.get(location, (0, None))
        connection_id = (f"{self.boot_id}:{bus}-{port}:{start}"
                         if start else prior_id if timestamp >= prior_time else None)
        event_type = {"setup_started": "usb_setup_started",
                      "disconnect_started": "usb_disconnect_started"}.get(kind)
        if kind == "setup_result":
            event_type = "usb_setup_completed" if result == 0 else "usb_setup_failed"
        # Late frames cannot resurrect a connection after a newer disconnect.
        if timestamp >= prior_time:
            active_id = None if kind == "disconnect_started" or result < 0 else connection_id
            self.connections[location] = (timestamp, active_id)
            self.connections.move_to_end(location)
            if len(self.connections) > 1024:
                self.connections.popitem(last=False)
        event_key = (kind, timestamp, start, bus, address, port, result)
        duplicate = event_key in self.seen
        if not duplicate:
            self.seen.add(event_key)
            self.order.append(event_key)
            if len(self.order) > 2048:
                self.seen.remove(self.order.popleft())
        usb_id = f"usb{bus}" if port == "0" else f"{bus}-{port}"
        record = {**base, "type": event_type, "bus": bus, "device_address": address,
                  "port_path": port, "usb_id": usb_id,
                  "sysfs_path": f"/sys/bus/usb/devices/{usb_id}",
                  "connection_id": connection_id, "duplicate": duplicate,
                  "is_root_hub": port == "0"}
        if start:
            record["setup_started_ns"] = start
        if kind == "setup_result":
            record["result"] = result
            record["setup_duration_ns"] = timestamp - start
        return record


def preflight() -> dict:
    if sys.platform != "linux":
        raise RuntimeError("Run the live monitor inside the Ubuntu VM")
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo to load the eBPF probes")
    if not SCRIPT.is_file():
        raise RuntimeError(f"Missing script: {SCRIPT}")
    if not Path("/sys/kernel/btf/vmlinux").is_file():
        raise RuntimeError("Kernel BTF is unavailable")
    executable = shutil.which("bpftrace")
    if not executable:
        raise RuntimeError("bpftrace is not installed")
    version = subprocess.run([executable, "--version"], capture_output=True,
                             text=True, timeout=15, check=True).stdout.strip()
    for probe in PROBES:
        check = subprocess.run([executable, "-l", probe], capture_output=True,
                               text=True, timeout=15)
        if check.returncode or probe not in check.stdout.splitlines():
            raise RuntimeError(f"Probe unavailable: {probe}\n{check.stderr.strip()}")
    return {"type": "monitor_preflight", "status": "passed", "kernel_release": os.uname().release,
            "bpftrace_version": version, "probes": list(PROBES)}


def read_stream(name, stream, inbox, overflow):
    try:
        for line in iter(stream.readline, ""):
            if len(line) > 16384:
                overflow.set()
                break
            try:
                inbox.put_nowait((name, line))
            except queue.Full:
                overflow.set()
                break
    finally:
        stream.close()
        try:
            inbox.put_nowait((name, None))
        except queue.Full:
            overflow.set()


def stop_backend(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def run_monitor(duration: float | None) -> int:
    decoder = Decoder(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    stop = threading.Event()
    overflow = threading.Event()
    inbox: queue.Queue = queue.Queue(maxsize=4096)
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, lambda _sig, _frame: stop.set())
    process = None
    threads = []
    counts: dict[str, int] = {}
    lost = 0
    degraded = False
    alive = False
    reason = "requested_stop"
    exit_status = 0
    started = time.monotonic()
    last_heartbeat = started
    session_id = str(uuid.uuid4())

    def output(record):
        emit({"session_id": session_id, **record})

    try:
        output({"type": "monitor_starting", "clock": "monotonic",
                "boot_id": decoder.boot_id, "backend": "bpftrace"})
        process = subprocess.Popen(["bpftrace", "-q", "-k", "-B", "line", str(SCRIPT)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   encoding="utf-8", errors="replace", start_new_session=True)
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            thread = threading.Thread(target=read_stream,
                                      args=(name, stream, inbox, overflow), daemon=True)
            thread.start()
            threads.append(thread)
        ended = set()
        while not stop.is_set():
            now = time.monotonic()
            if overflow.is_set():
                raise RuntimeError("Reader queue overflow or oversized backend line: events may be lost")
            if duration is not None and now - started >= duration:
                reason = "duration_elapsed"
                break
            if not alive and now - started > 45:
                raise RuntimeError("No kernel heartbeat within the 45-second startup deadline")
            if alive and now - last_heartbeat > 20:
                raise RuntimeError("Kernel heartbeat timeout: monitoring health is uncertain")
            try:
                stream, line = inbox.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and len(ended) == 2:
                    raise RuntimeError(f"Backend exited unexpectedly with status {process.returncode}")
                continue
            if line is None:
                ended.add(stream)
                continue
            if stream == "stdout" and line.startswith("PW1\t"):
                record = decoder.decode(line, time.monotonic_ns())
                if record["type"] == "monitor_heartbeat":
                    last_heartbeat = now
                    if not alive:
                        alive = True
                        output({"type": "monitor_alive", "timestamp_ns": record["timestamp_ns"],
                                "clock": "monotonic"})
                    record.update(event_counts=dict(counts), reported_lost_events=lost,
                                  degraded=degraded)
                elif record["type"].startswith("usb_"):
                    counts[record["type"]] = counts.get(record["type"], 0) + 1
                output(record)
            elif line.strip():
                message = line.rstrip()
                print(message, file=sys.stderr, flush=True)
                match = LOSS.search(message)
                if match:
                    lost += int(match.group(1))
                    degraded = True
                    output({"type": "monitor_loss", "reported_lost_events": int(match.group(1)),
                            "degraded": True})
                else:
                    degraded = True
                    output({"type": "monitor_diagnostic", "message": message, "degraded": True})
    except (OSError, RuntimeError, ValueError) as error:
        reason = "error"
        exit_status = 1
        print(str(error), file=sys.stderr, flush=True)
        output({"type": "monitor_error", "message": str(error)})
    finally:
        if process is not None:
            stop_backend(process)
            for thread in threads:
                thread.join(timeout=2)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    output({"type": "monitor_stopped", "reason": reason, "event_counts": counts,
            "reported_lost_events": lost, "degraded": degraded,
            "duration_seconds": round(time.monotonic() - started, 3)})
    return exit_status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check prerequisites and hook names only")
    parser.add_argument("--duration", type=float, help="Stop automatically after this many seconds")
    args = parser.parse_args()
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")
    try:
        status = preflight()
        if args.check:
            emit(status)
            return 0
        return run_monitor(args.duration)
    except BrokenPipeError:
        # The downstream consumer closed its input. Avoid a shutdown flush error.
        sys.stdout = open(os.devnull, "w")
        return 1
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        emit({"type": "monitor_error", "message": str(error)})
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
