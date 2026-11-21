# Step 6: selected-file BPF-LSM enforcement

Status: complete for the selected-file prototype scope in the recorded Ubuntu VM
environment. Verification includes the 181-test suite, native build/preflight,
loopback and physical USB enforcement, socket authentication, automatic bridge
registration, rejection, normal cleanup, coordinated removal/reconnect and deliberate
controller-loss reporting. Live failure handling was tested with `on_error: report`;
automatic deauthorisation on failure has unit coverage but has not been live-tested.
Rerun the procedures for another environment; Windows checks do not prove attachment.

## Roadmap and current scope

| Development stage | Implementation supplied | Verified behaviour |
| --- | --- | --- |
| 1. Target management | Inspection, held file/device references, bounded registry, map synchronisation | Linux build and multiple-file tests |
| 2. Commands | ADD, REMOVE, LIST, STATUS, PREPARE_REMOVE, STOP; correlated replies | Socket acceptance tests |
| 3. Unix socket | `/run/portwatchman/lsm_controller.sock`, root `SO_PEERCRED`, 0700 directory/0600 socket, bounded input, deadlines and shutdown | Permission and peer-credential tests |
| 4. Tests | Existing stdin/loopback regressions retained; socket and Python bridge tests added | Run suite and root acceptance runner |
| 5. Python integration | Optional bridge, configured paths, connection ownership, disconnect cleanup and explicit error behaviour | VM end-to-end allow/block/registration/removal tests |

The guard denies **new data opens of selected regular file identities on an
authorised, mounted USB filesystem**. It does not protect every file on a drive
automatically. Step 5 keeps unapproved USB devices blocked. Step 6 supplements an
approved device with configured file restrictions. Response actions and service
installation are separate later work.

Up to 128 targets use `(filesystem major, minor, inode)`. Held `O_PATH` references
keep the inode/mount alive while registered. Mount IDs and held physical USB sysfs
nodes are checked every 250 ms. Rules follow renames/hardlinks of that identity,
not replacement files at the original path. Native removal deletes the map entry
before releasing references. Device/mount departure triggers lifecycle cleanup;
unexpected unlink/identity or map failures keep the run unsuccessful. The Python
bridge detects missing entries while a connection is still registered.

Existing data descriptors, mmap, raw devices, mount operations and HID traffic are
outside this hook's scope. Direct USB-backed filesystems only: stacked/device-mapper
storage is unsupported. A controller and bridge must share the mount namespace.
Device-reported IDs can be spoofed. Periodic checks are best effort, not a guarantee
against every forced-unmount/device-number-reuse race. Counters are in-memory
snapshots, not durable audit storage. No links/maps are pinned.

## Preparation

Complete [shared testing setup](TESTING-SETUP.md). It defines how to select your
current `USB_ID`, `USB_PARTITION` and `USB_MOUNT`, and creates ignored local policies
and a selected-bus enforcement config. This guide uses those generated files;
neither a particular username nor a development branch is required.

Start each terminal in your actual repository root. Shell variables are local to a
terminal; repeat the relevant assignments when opening another terminal. Recheck
device IDs and mounts after reconnecting. If the device moves to a different bus,
restore the old test configuration before regenerating it for the current topology.

## Round 1 — build and ordinary tests (no USB needed)

```bash
sudo apt update
sudo apt install -y clang llvm linux-tools-common build-essential pkg-config \
  libbpf-dev libelf-dev libjson-c-dev python3
bash src/enforcement/bpf/build.sh
sudo src/enforcement/bpf/build/lsm_controller --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The build generates this kernel's BTF header, BPF object, skeleton and controller
under ignored `src/enforcement/bpf/build/`. Building does not load BPF. A failed
build does not install a partial controller. If Ubuntu's `bpftool` wrapper reports
missing kernel tools, provide the matching kernel tools package or a working
bpftool binary; do not copy another kernel's generated headers to hide the problem.

`--check` confirms active BPF-LSM and readable BTF. It does not prove attachment.
Eight native CLI safety tests run once the controller is built in Linux; otherwise
they skip. Five resolver tests require Linux O_PATH. Four pre-existing file-behaviour
tests also skip on Windows.

**Stop here and resolve any build/test errors before continuing.**

## Round 2 — loopback and socket acceptance (no physical USB needed)

```bash
sudo python3 tests/enforcement/test_bpf_lsm.py --loopback
```

The retained shell entry point also runs this test:

```bash
sudo bash tests/enforcement/test_bpf_lsm.sh
```

The runner creates its own 64 MiB image under `build/test-tmp`, formats that new
image, attaches a loop device and mounts it privately. It verifies ownership before
cleanup; it never formats a physical drive. Requires `mkfs.ext4`, `losetup`, `mount`,
`umount` and `findmnt`.

Checks: exact `EACCES` on read/write opens, permitted controls, multiple targets,
counters, runtime removal, rename/replacement behaviour, unlink expiry, duplicate
registration, bad commands, oversize input, unexpected stdin EOF, SIGTERM and STOP.
Socket checks exercise the controller commands, expected file/connection identity,
existing-socket refusal, permissions and non-root rejection. To reach SO_PEERCRED
itself, the test briefly relaxes permissions on **its own disposable test socket
under `/run/portwatchman-lsm-test-*`**, then restores them. It never relaxes the
production socket. The loopback test also confirms that held file references
prevent unmounting until PREPARE_REMOVE releases them, then unmounts/remounts only
its own verified loop fixture while the controller remains running. Expected result:
`All BPF-LSM acceptance checks passed`.

## Round 3 — standalone physical USB acceptance

With the selected test drive connected, authorise it using your matching policy:

```bash
sudo python3 src/enforcement/usb_authorization.py \
  --policy logs/test-allow.json authorize "$USB_ID" --apply
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

If needed, mount the verified USB partition with `udisksctl mount -b "$USB_PARTITION"`.
Set `USB_MOUNT` to its actual mount directory as described in shared setup, then:

```bash
findmnt -T "$USB_MOUNT" -o SOURCE,TARGET,FSTYPE
sudo python3 tests/enforcement/test_bpf_lsm.py --usb "$USB_MOUNT"
```

The runner independently verifies USB ancestry and creates/removes an owned
`portwatchman-lsm-*` test directory. It does not select existing user files or format
the drive. Keep the drive mounted/connected for this run. Expected final line:
`All BPF-LSM acceptance checks passed`.

## Round 4 — manual socket demonstration and bridge fixture

With the drive still authorised and mounted, create a fresh, owned demonstration
directory. This script verifies the selected mount against your current USB ID,
creates two new test files and records their relative directory in `logs/`. It also
creates the bridge config needed for Round 5. It does not overwrite existing USB files.

```bash
python3 - "$USB_ID" "$USB_MOUNT" <<'PY'
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, "src/enforcement")
from lsm_bridge import UsbTargetResolver

usb_id, mount = sys.argv[1], Path(sys.argv[2]).resolve(strict=True)
mounts = {Path(p).resolve(strict=True) for p in UsbTargetResolver().mounts(usb_id)}
if mount not in mounts:
    raise SystemExit("The selected directory is not a mount of the selected USB device")
directory = Path(tempfile.mkdtemp(prefix="portwatchman-demo-", dir=mount))
for name, content in [("restricted.txt", "Restricted test\n"),
                      ("control.txt", "Unrestricted control\n")]:
    with (directory / name).open("x", encoding="utf-8") as output:
        output.write(content)
relative = directory.relative_to(mount).as_posix()
Path("logs/test-lsm-fixture.json").write_text(json.dumps({"relative_directory": relative}) + "\n")
config = {"schema_version": 1, "socket_path": "/run/portwatchman/lsm_controller.sock",
          "registration_timeout_seconds": 30, "on_error": "report",
          "rules": [{"allowlist_rule": "test-usb", "protected_paths": [relative + "/restricted.txt"]}]}
Path("logs/test-lsm.json").write_text(json.dumps(config, indent=2) + "\n")
print("Created demonstration files at:", directory)
PY
```

In each terminal that will read the files, set its current `USB_MOUNT` and run:

```bash
USB_RELATIVE_DIR=$(python3 -c 'import json; from pathlib import Path; print(json.loads(Path("logs/test-lsm-fixture.json").read_text())["relative_directory"])')
USB_DEMO="$USB_MOUNT/$USB_RELATIVE_DIR"
cat "$USB_DEMO/restricted.txt"
cat "$USB_DEMO/control.txt"
```

Both files should initially be readable. Terminal A:

```bash
sudo src/enforcement/bpf/build/lsm_controller --usb --serve
```

Wait for `lsm_ready`. Terminal B, with its `USB_DEMO` set as above:

```bash
sudo python3 src/enforcement/lsm_client.py STATUS
sudo python3 src/enforcement/lsm_client.py ADD "$USB_DEMO/restricted.txt"
sudo python3 src/enforcement/lsm_client.py LIST
cat "$USB_DEMO/restricted.txt"
cat "$USB_DEMO/control.txt"
cat /etc/hostname
sudo python3 src/enforcement/lsm_client.py STATUS
```

Expect selected-file denial, readable controls and an increasing denial count.
Replace `TARGET_ID` with the ID returned by this controller's ADD/LIST response:

```bash
sudo python3 src/enforcement/lsm_client.py REMOVE TARGET_ID
cat "$USB_DEMO/restricted.txt"
sudo python3 src/enforcement/lsm_client.py STOP
```

The selected file should become readable after REMOVE. Wait for Terminal A to exit
with `lsm_stopped`, `ok: true`. STOP detaches and removes its owned socket; the empty
0700 socket directory may remain. Keep the demonstration files for Round 5.

## Round 5 — opt-in Python bridge and live pipeline

Only `enforce --lsm-config FILE` enables the bridge. Direct `authorize` and
`reconcile` do not register targets. The bridge handles new correlated connections,
so reconnect the drive after the pipeline is healthy.

The sequence is: allowlist match → authorise USB → mount filesystem → register
selected files → `lsm_bridge_registered`. There is an access window between USB
authorisation and file registration. Missing mounts/files retry on upstream events,
normally five-second heartbeats, until the configured deadline. Protection is
confirmed only by `lsm_bridge_registered` with `protection_complete: true`.

### Failure-policy choice

Review `logs/test-lsm.json` before enabling it:

- `on_error: report` reports protection failure and leaves the USB authorised. This
  is the generated demonstration setting and the live-validated failure policy.
- `on_error: deauthorize` additionally attempts to block the same still-current USB
  connection and can interrupt I/O. It is implemented and unit-tested; live acceptance
  for this option is not part of the recorded results.

Existing map entries can remain after a bridge error while the controller is alive.
No protection survives controller exit. The bridge reports failure instead of
claiming that a lost or incomplete restriction is active.

### Run the matching policy

Stop any controller from Round 4. Unmount the verified partition and disconnect:

```bash
udisksctl unmount -b "$USB_PARTITION"
```

After successful unmounting, disconnect the drive, then arm the selected bus:

```bash
sudo python3 src/enforcement/usb_authorization.py \
  --config logs/test-enforcement.json arm --apply
```

Terminal A:

```bash
sudo src/enforcement/bpf/build/lsm_controller --usb --serve
```

Terminal B:

```bash
set -o pipefail
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy logs/test-allow.json watch |
  sudo python3 src/enforcement/usb_authorization.py \
    --config logs/test-enforcement.json --policy logs/test-allow.json \
    enforce --lsm-config logs/test-lsm.json
```

Wait for `lsm_bridge_started` and healthy monitoring, then reconnect. Expect allow,
`lsm_bridge_pending`, then `lsm_bridge_registered`. If the partition is not
automounted, identify it with `lsblk` and mount it before the 30-second deadline.

In Terminal C, recheck/set `USB_ID`, `USB_PARTITION` and `USB_MOUNT`. Reconstruct
`USB_DEMO` using the saved relative-directory block in Round 4, then:

```bash
sudo python3 src/enforcement/lsm_client.py STATUS
cat "$USB_DEMO/restricted.txt"
cat "$USB_DEMO/control.txt"
cat /etc/hostname
sudo python3 src/enforcement/lsm_client.py STATUS
```

Expect selected-file denial, readable controls, increasing counters and a nonempty
connection ID. An allow result alone proves USB authorisation, not file protection.

### Coordinated removal and reconnect

The controller holds O_PATH references to preserve file identity. Those references
also keep the mount busy. Release them intentionally before normal unmounting;
leave both the controller and pipeline running.

The following reads live STATUS and chooses the one current connection for your
selected `USB_ID`. It sends no mutation if the controller is degraded or the choice
is missing/ambiguous. It also binds the request to the same controller instance.

```bash
sudo python3 - "$USB_ID" <<'PY'
import json
import sys

sys.path.insert(0, "src/enforcement")
from lsm_client import LsmClient

client = LsmClient()
state = client.status()
connections = {t["connection_id"] for t in state["targets"] if t["usb_id"] == sys.argv[1]}
if state["failures"] != 0 or len(connections) != 1 or not all(connections):
    raise SystemExit("Expected a healthy controller and one current USB connection; nothing changed")
print(json.dumps(client.request("PREPARE_REMOVE", connection_id=connections.pop())))
PY
```

Expect `lsm_connection_prepared`, then `lsm_bridge_prepared_for_removal` in Terminal B
by the next heartbeat. Wait for the bridge event, then:

```bash
sudo python3 src/enforcement/lsm_client.py STATUS
udisksctl unmount -b "$USB_PARTITION"
```

Expect no active targets for that connection and `failures: 0`. After successful
unmounting, disconnect. The bridge should emit `lsm_bridge_disconnected`.
Reconnect without restarting either process: expect a new connection ID/target ID
and renewed file denial after mounting. Recheck the mount and reconstruct `USB_DEMO`
before reading its files again. The old ID may remain in `prepared_connections`;
it must not affect the new registration.

PREPARE_REMOVE explicitly ends selected-file protection; it does not unmount,
deauthorise or eject the drive. If removal is cancelled, disconnect/reconnect to
obtain a newly protected connection. If normal unmount still reports busy, another
application may hold references; inspect with `sudo fuser -vm "$USB_MOUNT"` if
`fuser` is available. Stopping the owning pipeline/controller normally also releases
its references. Normal REMOVE without preparation is an unexpected loss to the bridge.

### Deliberate controller-loss test

After successful reconnect and renewed file denial, keep Terminal B running and
stop the controller from Terminal C:

```bash
sudo python3 src/enforcement/lsm_client.py STOP
```

Expect Terminal A to exit and Terminal B to report `lsm_bridge_error`,
`protection_complete: false`, normally within 5–10 seconds. With `on_error: report`,
the USB remains authorised and both files become readable:

```bash
cat "/sys/bus/usb/devices/$USB_ID/authorized"
cat "$USB_DEMO/restricted.txt"
cat "$USB_DEMO/control.txt"
```

Expect `1` and both contents. Ctrl+C in Terminal B should then produce `ok: false`
and a nonzero failure count. This is the expected deliberate-failure result.
Any `lsm_bridge_retained` record refers to registration records and does not prove
that kernel protection remains. A controller restart changes its instance ID;
old IDs must not be reused against it. The bridge does not adopt old registrations.

### Rejection with the bridge enabled

For a separate run, stop/clean up the previous processes, unmount/disconnect the
drive, arm the selected bus and start a fresh controller as above. Use the generated
serial-mismatch policy on both policy stages:

```bash
set -o pipefail
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy logs/test-mismatch.json watch |
  sudo python3 src/enforcement/usb_authorization.py \
    --config logs/test-enforcement.json --policy logs/test-mismatch.json \
    enforce --lsm-config logs/test-lsm.json
```

The rule name remains `test-usb`, so the bridge config is valid, but its serial does
not match. Reconnect after healthy monitoring. Expect block/already_blocked,
`authorized: 0`, no USB block device/filesystem and no LSM registration. Confirm with
the sysfs attribute, `lsblk` and controller STATUS. Do not use an empty policy with
this bridge config: startup correctly refuses a reference to a missing allowlist rule.

### Normal stop and final restoration

For a normal-stop test, repeat a healthy matching run and press Ctrl+C in Terminal B.
Expect `lsm_bridge_released`, a successful closing record and an empty owned target
inventory. The selected file becomes readable. The controller remains running until
STOP or its own signal; targets belonging to other clients are not removed.

Stop the controller, wait for its exit and restore defaults:

```bash
sudo python3 src/enforcement/lsm_client.py STOP
sudo python3 src/enforcement/usb_authorization.py \
  --config logs/test-enforcement.json restore --apply
python3 src/enforcement/usb_authorization.py \
  --config logs/test-enforcement.json status
pgrep -af 'bpftrace.*usb_events[.]bt'
```

If the controller already exited during the failure test, skip STOP. Expect
`armed: false`, recorded original defaults restored and no monitor backend. If a
rejected device remains connected/blocked, confirm its current USB ID and use:

```bash
sudo python3 src/enforcement/usb_authorization.py \
  --policy logs/test-allow.json authorize "$USB_ID" --apply
```

An incorrect root command, such as preparation with an obsolete connection ID,
records a controller failure; the bridge treats that run as degraded even if a
later command succeeds. Inspect `lsm_error` records and STATUS, then stop both
processes and restart a clean test. Do not suppress the failure counter.

## Protocol and lifecycle notes

Socket mode: `--serve` selects the default path; `--socket /run/PRIVATE/name.sock`
selects an alternative. Its parent must be a canonical root-owned 0700 directory
under root-owned ancestors not writable by other users. The controller refuses any
existing socket path, including stale sockets; investigate its owner before cleanup.
It unlinks only the socket inode it created. Up to eight root clients are accepted;
each connection carries one newline-terminated JSON request and one response, with
a 64 KiB request bound and three-second receive/send deadlines. Replies are bounded.
New connections are required for further commands. stdout is NDJSON audit output;
libbpf diagnostics go to stderr.

Requests use `command` and optional `command_id`; replies echo the ID and include a
boot/process/start-specific `controller_id`. `expected_controller_id` prevents old
clients mutating a replacement controller. ADD accepts `path`; REMOVE uses returned
`target_id`. LIST/STATUS return inventory and counters; STOP acknowledges then drains
queued replies, detaches and exits. Duplicate file identities are rejected. REMOVE
of an absent ID is idempotent. Invalid root commands/map failures latch a nonzero
run outcome; rejected unprivileged clients do not poison it.

PREPARE_REMOVE takes `connection_id` and releases all and only that connection's
targets before closing their held file references. Its single summary response is
`lsm_connection_prepared`; detailed target removals remain in stdout audit output.
Repeated preparation is idempotent. STATUS retains up to 128 recent intentional
release markers. A bridge already waiting for removal stays in that state even if
an old marker is later evicted. ADD for a recently prepared connection returns the
prepared acknowledgement without re-registering it, including when an in-flight
ADD races preparation. New connection IDs remain eligible for registration.

Bridge ADD includes `connection_id`, expected filesystem major/minor/inode/mount ID,
USB ID and device address. Python holds O_PATH references through the reply; C
independently opens and validates the same identity before inserting the map entry.
REMOVE includes connection ownership. Both sides require root peers; the Python
client also checks socket ownership/permissions and response correlation. The bridge
retains IDs only within that controller instance and checks inventory on upstream
events. It rejects multiple mounts, symlink path components and duplicate identities
as ambiguous/unsupported instead of guessing. It does not create missing files.

Legacy `--control-stdin` still accepts restrict/unrestrict/status/stop aliases and
uppercase commands. It is mutually exclusive with socket mode. Unexpected stdin EOF
is a failure; ordinary foreground mode ignores stdin and uses signals. SIGUSR1 emits
status; SIGINT/SIGTERM detach and stop. `--inspect --usb FILE` validates a file without
loading BPF. `--test-loopback` accepts only loop-backed filesystems.

## Completion evidence

The Step 6 milestone was validated in the recorded Ubuntu/VMware environment on
2026-11-21. These are results for that environment, not guarantees for other kernels
or hosts. A new deployment should repeat the procedures above.

- [x] Ubuntu build and preflight.
- [x] All 181 tests, with native CLI checks enabled.
- [x] Loopback enforcement, socket/authentication and mount-reference release.
- [x] Standalone physical USB enforcement on an exFAT test filesystem.
- [x] Manual ADD/REMOVE/LIST/STATUS/STOP and selected-file counters.
- [x] Automatic bridge registration, permitted controls and normal cleanup.
- [x] Coordinated preparation, normal unmount, disconnect and reconnect.
- [x] Serial-mismatch rejection while the bridge is enabled.
- [x] Controller-loss detection and failed pipeline outcome under `on_error: report`.
- [x] Original bus defaults restored and monitor backend released.

Service orchestration, durable logs, response actions and system-wide hardening remain
outside this implementation milestone.
