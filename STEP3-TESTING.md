# Step 3: USB monitoring component v1

Copy the src/ and tests/ directories into the repository on Windows, commit on
feature/usb-monitor, and push. Also copy this guide if useful. Keep the existing
.gitattributes and .gitignore. The Ubuntu clone is at:
/home/ryelle/df/project/portwatchman.

This component uses real eBPF programs loaded by bpftrace 0.20.2, supervised by
a Python 3 standard-library launcher. No Python packages or compilation are
required. A native libbpf loader can replace this backend later if required by
your assessment; this implementation is deliberately based on the hooks you
have already tested. It never changes USB authorisation, locks sessions, deletes
files, or shuts down the VM.

## Files

- src/monitor/usb_events.bt: kernel probes and correlation maps.
- src/monitor/usb_monitor.py: validated NDJSON interface, bounded input queue,
  lifecycle messages, heartbeat timeout, diagnostics, and child-process cleanup.
- tests/test_usb_monitor.py: parser and correlation unit tests (no root needed).

## Pull and check

```bash
cd ~/df/project/portwatchman
git pull --ff-only
python3 --version
python3 -m unittest discover -s tests -p test_usb_monitor.py -v
sudo python3 src/monitor/usb_monitor.py --check
```

The preflight checks root privileges, BTF, bpftrace and all three hook names. It
does not load the script, so the live run is still necessary to validate it.

## Live test

```bash
sudo python3 src/monitor/usb_monitor.py
```

Wait for monitor_alive and a monitor_heartbeat, typically about five seconds
after attachment. Eject/unmount before unplugging a mounted drive, then reconnect
it through VMware. Three reconnect/unplug cycles should show:

- usb_setup_started
- usb_setup_completed (result 0)
- usb_disconnect_started

The start and completion share a connection_id. A disconnect is correlated when
the monitor saw the relevant generation. A device present before startup can
have a null connection_id on disconnect. Root hubs and other guest USB devices
are included rather than silently filtered. A hub removal can generate several
disconnect events for its children.

Press Ctrl+C, expect monitor_stopped, then verify no monitor backend remains:

```bash
pgrep -af 'bpftrace.*usb_events[.]bt'
```

No matches is expected (pgrep exits 1 when none are found). Repeat the launch to
verify restart works. For a timed run, add --duration 30. Attach/startup time is
included in this duration. Prefer Ctrl+C for the manual device test.

## Capture machine-readable output

```bash
mkdir -p logs
sudo python3 src/monitor/usb_monitor.py > logs/usb-events.jsonl
```

After stopping, validate and summarise the JSON stream:

```bash
python3 -c 'import collections,json; from pathlib import Path; rows=[json.loads(s) for s in Path("logs/usb-events.jsonl").read_text().splitlines() if s.strip()]; print(collections.Counter(r["type"] for r in rows))'
```

Diagnostics are also written to stderr. Known bpftrace lost-event messages are
represented by monitor_loss; helper errors/other messages appear as
monitor_diagnostic. Queue overflow, malformed event frames, a stopped backend,
or absent heartbeats fail with monitor_error and a nonzero exit code. A reported
loss or warning leaves degraded=true for the remainder of that session.

## Default-deny regression

After confirming ordinary monitoring, repeat the earlier default-deny experiment
on the confirmed test bus (previously bus 2): unmount, set authorized_default=0,
reconnect, and confirm monitoring events still appear while authorized=0 and no
USB block device appears. Restore the original authorized_default=1, confirm the
device identity (058f:6387 at the expected path), and approve it again. Do not
write blanket settings across every USB bus.

## Event semantics and limits

- schema_version is 1; each stdout line is JSON, including lifecycle/error records.
- timestamp_ns is CLOCK_MONOTONIC inside the guest; receipt time uses the same
  clock. delivery_delay_ns is transport/processing delay, not physical insertion
  latency. setup_duration_ns measures the usb_new_device call only.
- setup_started is early and sysfs may not yet exist. setup_completed means
  successful device registration, not authorisation, identity authentication,
  or permission to mount. Device identification/policy are step 4.
- disconnect_started is entry into kernel disconnect handling. It does not prove
  completed teardown or distinguish physical removal from logical disconnection.
- Events can arrive out of timestamp order across CPUs. All are preserved;
  bounded recent duplicates are labelled duplicate=true, not dropped.
- This is a monitor, not an initial inventory. The daemon will need startup and
  recovery reconciliation against sysfs. Connection IDs represent setup attempts
  during one kernel boot, not trusted physical identities.
- Kernel kprobe names/structures are not a stable cross-kernel API. Keep the
  tested guest kernel consistent across team members. A function-name check
  cannot prove field-read or attachment compatibility until the live test passes.
- Lost-event counters only cover loss reported by bpftrace, not every possible
  missed kprobe/kretprobe or map update. A heartbeat proves backend liveness,
  not complete event delivery. Burst coverage and adversarial failure handling
  remain later evaluation work. The bounded reader queue fails visibly on
  overflow; stdout consumers must drain the output to avoid backpressure.
- No objects are pinned. Normal termination stops the separate backend process
  group and releases its probes. SIGKILL of the Python supervisor cannot run its
  cleanup handler; service-level supervision for that case belongs to step 9.

## Completion evidence

Keep step 3 in progress until the live script compiles/attaches, the three-cycle
test produces correlated setup/disconnect records, default-deny still works,
the saved stream parses as JSON, and stop/restart releases the backend normally.
The Python tests have been run locally on Windows; kernel attachment and event
behaviour still require your Ubuntu VM results.
