# Step 6: selected-file BPF-LSM enforcement

Status: implementation prepared on `feature/bpf-lsm-sq`; Ubuntu compilation,
kernel loading and live acceptance remain to be verified by the VM operator.
Windows test results do not establish successful BPF attachment.

## Roadmap and current scope

| Groupmate's stage | Implementation supplied | Required verification |
| --- | --- | --- |
| 1. Target management | Inspection, held file/device references, bounded registry, map synchronisation | Linux build and multiple-file tests |
| 2. Commands | ADD, REMOVE, LIST, STATUS, STOP; correlated JSON replies | Socket acceptance tests |
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

## Round 0 — publish your Windows changes, then pull in Ubuntu

In Windows GitHub Desktop, confirm `feature/bpf-lsm-sq`, review the changes, commit
and push that branch. Do not merge into `main` yet. Then in Ubuntu:

```bash
cd ~/df/project/portwatchman
git status
git fetch origin
git switch feature/bpf-lsm-sq
git pull --ff-only origin feature/bpf-lsm-sq
git branch --show-current
git status
```

If the local branch does not exist, use
`git switch --track origin/feature/bpf-lsm-sq` instead of the plain switch.
Resolve any local changes before switching; do not reset or discard them.

## Round 1 — build and ordinary tests (no USB needed)

```bash
sudo apt update
sudo apt install -y clang llvm bpftool build-essential pkg-config \
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
Socket checks exercise all five commands, expected file/connection identity,
existing-socket refusal, permissions and non-root rejection. To reach SO_PEERCRED
itself, the test briefly relaxes permissions on **its own disposable test socket
under `/run/portwatchman-lsm-test-*`**, then restores them. It never relaxes the
production socket. Expected result: `All BPF-LSM acceptance checks passed`.

## Round 3 — standalone physical USB acceptance

```bash
lsusb
python3 src/policy/device_policy.py list
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

Rediscover the current USB ID, bus and mount. Your newer drive was `4-1` / `usb4`,
VID `058f`, PID `6387`, serial `CDCC363B`; these paths can change. Do not reuse the
mouse's ID or assume `/dev/sdb1` without checking.

For this round the test drive must be authorised and mounted. Restore any previous
default-deny test using the exact configuration that owns its saved state, then
authorise the drive using its matching policy. A blocked device has no accessible
filesystem to test.

Replace `ACTUAL_VOLUME` with the verified mount:

```bash
findmnt -T '/media/ryelle/ACTUAL_VOLUME' -o SOURCE,TARGET,FSTYPE
sudo python3 tests/enforcement/test_bpf_lsm.py --usb '/media/ryelle/ACTUAL_VOLUME'
```

The runner verifies USB ancestry and creates/removes only an owned
`portwatchman-lsm-*` test directory. Keep the drive mounted/connected for the entire
run. Expected result: `All BPF-LSM acceptance checks passed`.

## Round 4 — manually demonstrate the socket commands

Create two fresh disposable files on the verified USB mount:

```bash
(set -C; printf 'restricted test\n' > '/media/ryelle/ACTUAL_VOLUME/portwatchman-lsm-test.txt')
(set -C; printf 'control test\n' > '/media/ryelle/ACTUAL_VOLUME/portwatchman-control.txt')
```

Terminal A:

```bash
sudo src/enforcement/bpf/build/lsm_controller --usb --serve
```

Wait for `lsm_ready`. Terminal B:

```bash
sudo python3 src/enforcement/lsm_client.py STATUS
sudo python3 src/enforcement/lsm_client.py ADD '/media/ryelle/ACTUAL_VOLUME/portwatchman-lsm-test.txt'
sudo python3 src/enforcement/lsm_client.py LIST
cat '/media/ryelle/ACTUAL_VOLUME/portwatchman-lsm-test.txt'
cat '/media/ryelle/ACTUAL_VOLUME/portwatchman-control.txt'
cat /etc/hostname
sudo python3 src/enforcement/lsm_client.py STATUS
```

Expect permission denied only for the selected file, and an increasing denial
count. Use the actual returned `target_id` in place of `TARGET_ID`:

```bash
sudo python3 src/enforcement/lsm_client.py REMOVE TARGET_ID
cat '/media/ryelle/ACTUAL_VOLUME/portwatchman-lsm-test.txt'
sudo python3 src/enforcement/lsm_client.py STOP
```

The file becomes readable after REMOVE. STOP detaches and removes the owned socket;
Terminal A exits. A clean run reports `lsm_stopped` with `ok: true`. Socket directory
permissions remain 0700; the empty directory may remain for the next start.

## Round 5 — opt-in Python bridge / live pipeline

This round is **Stage 5 of the BPF-LSM roadmap**, within overall project Step 6.
Only `enforce --lsm-config FILE` enables it. Ordinary Step 5 commands remain usable.
Direct `authorize` and `reconcile` do not register LSM targets; this prototype bridge
handles new correlated pipeline connections only. Disconnect/reconnect the test
drive after the pipeline is ready.

The order is: allowlist match → authorise USB → mount filesystem → register selected
files → confirm `lsm_bridge_registered`. A desktop may automount the drive; otherwise
mount it manually after authorisation. There is a registration window in which the
USB is accessible before the selected files are restricted. Missing mounts/files
retry on upstream events (normally every five-second heartbeat), up to the configured
deadline. Do not claim protection before the registration confirmation.

### Choose registration-failure behaviour explicitly

- `on_error: report`: report failure, return an unsuccessful pipeline outcome and
  leave the USB authorised. Existing installed restrictions are retained.
- `on_error: deauthorize`: additionally attempt to block the **same still-current
  USB connection**. This can interrupt I/O. Replacement devices are not revoked.

The example uses `report` for demonstration; it is not enabled automatically. Review
this choice before copying/enabling it. No automatic deauthorisation was selected
by the project owner. Invalid/unavailable controller configuration prevents startup
before the bridge-enabled pipeline authorises any device.

### Prepare test-only configuration

While the intended test drive is still authorised/mounted, keep the two disposable
files from Round 4. Stop the Round 4 controller. Set the current device ID (replace
this example if different), inspect it and review its identity:

```bash
mkdir -p logs
PW_USB_ID=4-1
python3 src/policy/device_policy.py inspect "$PW_USB_ID" > logs/step6-usb-device.json
cat logs/step6-usb-device.json
```

The following creates isolated test policies/configs; it does not arm a bus or write
to the USB. It refuses an existing Step 6 state file to avoid overwriting saved
original defaults. Restore the old test first if that state exists.

```bash
python3 - <<'PY'
import json
from pathlib import Path

device = json.loads(Path('logs/step6-usb-device.json').read_text())['device']
assert not device['is_root_hub']
assert device['vendor_id'] == '058f' and device['product_id'] == '6387'
assert device.get('serial'), 'This test requires a drive serial number'
assert not Path('logs/step6-enforcement-state.json').exists(), 'Restore the previous Step 6 arm state first'
rule = {'name': 'step6-test-drive', 'vendor_id': device['vendor_id'],
        'product_id': device['product_id'], 'serial': device['serial']}
allow = {'schema_version': 1, 'default_action': 'block', 'allowlist': [rule]}
deny = {'schema_version': 1, 'default_action': 'block', 'allowlist': []}
enforcement = {'schema_version': 1, 'managed_buses': ['usb' + str(device['bus'])],
               'state_file': 'logs/step6-enforcement-state.json'}
bridge = {'schema_version': 1, 'socket_path': '/run/portwatchman/lsm_controller.sock',
          'registration_timeout_seconds': 30, 'on_error': 'report',
          'rules': [{'allowlist_rule': 'step6-test-drive',
                     'protected_paths': ['portwatchman-lsm-test.txt']}]}
for name, document in [('step6-allow.json', allow), ('step6-deny.json', deny),
                       ('step6-enforcement.json', enforcement), ('step6-lsm.json', bridge)]:
    Path('logs', name).write_text(json.dumps(document, indent=2) + '\n')
print('Prepared test configs using report-only registration failure handling.')
PY
python3 src/policy/device_policy.py --policy logs/step6-allow.json validate
```

This example targets your reported `058f:6387` flash drives. Adapt the explicit
assertions if using another test device, after reviewing its identity. Keep these
test configs under ignored `logs/`.

Safely unmount the actual USB partition shown by `lsblk`, then unplug/disconnect the
drive from the guest. Do not select the Ubuntu system disk. Arm the selected bus:

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/step6-enforcement.json arm --apply
```

Terminal A — leave the native controller running:

```bash
sudo src/enforcement/bpf/build/lsm_controller --usb --serve
```

Terminal B — start the pipeline:

```bash
cd ~/df/project/portwatchman
set -o pipefail
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy logs/step6-allow.json watch |
  sudo python3 src/enforcement/usb_authorization.py \
    --config logs/step6-enforcement.json --policy logs/step6-allow.json \
    enforce --lsm-config logs/step6-lsm.json
```

Wait for `lsm_bridge_started` and healthy monitoring, then connect the USB to Ubuntu.
Expect `enforcement_result` allow, `lsm_bridge_pending`, then
`lsm_bridge_registered` with `protection_complete: true`. If it is not automounted,
use a third terminal to identify/mount the actual USB partition before the deadline.

In Terminal C, rediscover the mount and verify:

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
sudo python3 src/enforcement/lsm_client.py STATUS
cat '/media/ryelle/ACTUAL_VOLUME/portwatchman-lsm-test.txt'
cat '/media/ryelle/ACTUAL_VOLUME/portwatchman-control.txt'
cat /etc/hostname
sudo python3 src/enforcement/lsm_client.py STATUS
```

Expect exact selected-file denial, successful controls, a nonempty connection ID on
the guard target and an increasing counter. These checks establish filesystem
enforcement; `enforcement_result` allow alone establishes only USB authorisation.

### Stop, disconnect and repeat

Ctrl+C in Terminal B is a deliberate normal stop. A healthy bridge removes only
registrations it owns; it does not stop the C controller or remove somebody else's
targets. STATUS should show its targets removed and the test file readable again.
Default-deny remains armed until explicit restore.

For lifecycle testing, restart the pipeline, reconnect and wait for registration.
Safely unmount the drive, then unplug it. Expect cleanup for that connection. A
new connection gets a new connection ID; an old disconnect cannot remove its
registrations. Safe unmount before physical removal can already expire a rule;
if the bridge observes that while the device is still connected, it reports missing
protection and fails the run. This is a valid degraded result, not a successful file
denial. Restart after inspecting/cleaning the retained entries.

If the controller dies/restarts, the bridge reports failure and never reuses old
target IDs against the new controller instance. Unexpected pipeline termination or
registration errors retain installed entries for inspection. Use STATUS and explicit
REMOVE, or stop the owned controller, before retrying. The bridge does not adopt
registrations from a previous process. No protection survives controller exit.

### Confirm unapproved USB behaviour remains Step 5's default-deny

Stop the allow pipeline, unmount/unplug the drive and use `logs/step6-deny.json` for
both policy arguments, omitting `--lsm-config`. Reconnect after healthy monitoring.
Expect block/already_blocked, `authorized=0`, no USB block device/filesystem, and no
new LSM target. An empty deny policy has no approved rule to map to a protected file.

### Restore the test environment

Stop the pipeline with Ctrl+C, then stop the owned controller and restore bus defaults:

```bash
sudo python3 src/enforcement/lsm_client.py STOP
sudo python3 src/enforcement/usb_authorization.py \
  --config logs/step6-enforcement.json restore --apply
sudo python3 src/enforcement/usb_authorization.py \
  --policy logs/step6-allow.json authorize "$PW_USB_ID" --apply
python3 src/enforcement/usb_authorization.py --config logs/step6-enforcement.json status
pgrep -af 'bpftrace.*usb_events[.]bt'
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

Run authorise only if that ID still identifies the intended connected drive. If the
controller was already stopped, STOP reports unavailable; Ctrl+C in its terminal is
also valid. Expect restored original defaults, `armed: false`, no monitor backend,
and normal access to the reauthorised drive.

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

- [ ] Clean-checkout Ubuntu build and preflight.
- [ ] Python suite with native CLI tests enabled.
- [ ] Loopback acceptance, including socket/authentication regressions.
- [ ] Standalone physical USB acceptance.
- [ ] Manual ADD/REMOVE/LIST/STATUS/STOP and selected-file counters.
- [ ] Bridge registration, controls, ownership cleanup, reconnect and failure handling.
- [ ] Existing Step 5 allow/block and environment restore still pass.

Mark overall Step 6 complete only after the corresponding Ubuntu results pass.
Service orchestration, durable logs, response actions and system-wide hardening remain
outside this implementation milestone.
