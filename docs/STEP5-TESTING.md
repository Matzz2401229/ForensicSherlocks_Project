# Step 5: USB access control (default-deny, authorise, enforce, reconcile)

This component writes USB authorisation state in sysfs: the per-bus
`authorized_default` flag and the per-device `authorized` flag. It is the first
component that changes device access; steps 3 and 4 only observed and decided.

All write commands **default to a dry run** and change nothing until you add
`--apply`. Writes to sysfs require root, so the live `--apply` commands use `sudo`.

> **Safety.** These commands affect USB devices **inside the Ubuntu VM only**. The
> sysfs paths they touch do not exist on, and have no write path to, the Windows
> host, so they cannot block host devices, shut down the host, or affect host data.
> `arm --apply` sets default-deny on every managed bus. Devices already connected
> keep working (the flag only gates *newly* connected devices), but after arming, a
> newly plugged or replugged device - including a USB mouse or keyboard passed
> through to the VM - starts blocked until it is authorised. `restore --apply` undoes
> default-deny. Keep a non-USB way to control the VM (VMware console) during testing.

Config: `config/enforcement.json` sets `managed_buses` (`"auto"` arms every bus) and
the state file. The allowlist policy is the step 4 file; the example
`config/allowlist.example.json` matches the lab drive `058f:6387`.

## Pull and run the unit tests

```bash
cd ~/df/project/portwatchman
git pull --ff-only
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expect `OK`. The enforcement tests use a fake sysfs tree and need no root or USB drive.

## Slice 1: default-deny a bus (arm / restore / status)

Look first, write nothing:

```bash
python3 src/enforcement/usb_authorization.py status
python3 src/enforcement/usb_authorization.py arm          # dry run: prints the plan
```

`status` lists each bus and its `authorized_default`; `arm` reports the buses it
would set to `0`. Now apply default-deny, with the test flash drive unplugged:

```bash
sudo python3 src/enforcement/usb_authorization.py arm --apply
```

Plug in the test drive, then confirm it does **not** appear:

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

The drive should be absent (blocked by default-deny). Restore when done:

```bash
sudo python3 src/enforcement/usb_authorization.py restore --apply
```

`restore` only changes the default for devices connected from now on. A drive that was
blocked while armed stays blocked: replug it, or authorise it (slice 2), and it appears in
`lsblk` again.

## Slice 2: authorise or revoke one device

With the drive connected, find its USB ID (step 4's `list`/`inspect`), e.g. `2-1`.
Dry run first, then apply using the example policy that lists the lab drive:

```bash
python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json authorize 2-1
sudo python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json authorize 2-1 --apply
cat /sys/bus/usb/devices/2-1/authorized        # 1
```

The command binds to the device instance first, then re-reads the device and re-checks the
policy, and writes only to that same instance. A device whose attributes no longer match,
or that the policy no longer allows, stays blocked (`action: block`). If the device is
unplugged or replaced at the same port during the command, nothing is written and the
command reports `device_unavailable` or `device_changed`. Revoke to block it again:

```bash
sudo python3 src/enforcement/usb_authorization.py revoke 2-1 --apply
cat /sys/bus/usb/devices/2-1/authorized        # 0
```

## Slice 3: the live enforcement pipeline

Arm default-deny first (slice 1), with the drive unplugged. Then run the full
pipeline - monitor detects, policy decides, enforce acts:

```bash
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy config/allowlist.example.json watch |
  sudo python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json enforce
```

`enforce` reads `config/enforcement.json` and acts only on devices on the managed buses.
It prints `enforcement_started` immediately, listing `managed_buses` and any
`unarmed_buses` (managed buses not set to default-deny; this should be empty after `arm`).
Then it prints an `enforcement_monitor_status` record when the monitor's health changes.
Wait for one with `healthy: true` (about five seconds), then connect the drive. Heartbeats
are not repeated, so the screen stays quiet until a device appears. A device inserted
before the monitor is healthy gets a `block` decision (the step 4 safety rule), not an
authorisation.

Expect an `enforcement_result` with `action: allow`, `enforcement_applied: true`,
`policy_reason: allowlist_match` and an `enforcement_latency_ns` (insertion to
authorisation). Confirm the drive now appears in `lsblk`. To test the unlisted case, run
the same pipeline without `--policy` (the default policy has no rules): the result is
`action: block`, `reason: already_blocked`, `policy_reason: no_matching_allowlist_rule`,
and the drive stays absent from `lsblk`.

Decisions that do not change anything are reported as `enforcement_skipped` with a reason:

| Reason | Meaning |
| --- | --- |
| `unmanaged_bus` | The device is on a bus outside `managed_buses`; it is left untouched. |
| `uncorrelated_decision` | The decision has no decision time or device address (for example a policy error such as `stale_event`), so it cannot be tied to the device now on the port. Nothing is written; default-deny keeps a new device blocked. |
| `stale_decision` | The decision is older than two seconds. |
| `stale_device`, `device_changed`, `device_unavailable` | A different device now occupies the port, or the device was removed. Nothing is written. |

If a sysfs write itself fails, `enforce` prints an `enforcement_error` with
`reason: sysfs_write_failed`, the `usb_id`, connection, `requested_action` and
`enforcement_applied: false`, and keeps processing other devices.

Press Ctrl+C to stop. `enforce` ends with an `enforcement_stream_closed` record
(`reason: requested_stop`, `ok: true`) and no traceback. Its exit status is 0 only after a
deliberate stop (Ctrl+C here or in `watch`) or a clean monitor stop with no failed writes
or bad input. An unexpected end of input, an unhealthy upstream, or any failed write gives
exit status 1, with `reason` (`unexpected_end_of_input`, `upstream_failed`) and the
`failures` count in the closing record. Confirm the backend is gone:

```bash
pgrep -af 'bpftrace.*usb_events[.]bt'          # no matches expected
```

Add `--dry-run` to the enforce command to see decisions acted on without writing.

### Check: a removed device cannot receive a write (Linux)

Instance binding relies on Linux refusing writes through a sysfs file that was opened
before its device was removed. To confirm this on the VM, with the drive connected and
its USB ID known (for example `4-1`):

```bash
sudo python3 -c '
import errno, sys
path = "/sys/bus/usb/devices/" + sys.argv[1] + "/authorized"
held = open(path, "r+b")
input("Holding " + path + ". Disconnect the drive in VMware, then press Enter...")
try:
    held.write(b"1\n"); held.flush(); print("UNEXPECTED: write accepted")
except OSError as error:
    print("Refused as expected:", errno.errorcode.get(error.errno, error.errno))
' 4-1
```

Expected: `Refused as expected: ENODEV` (or another refusal), never `write accepted`.

## Slice 4: reconcile devices already connected

Arm default-deny, then connect the drive **before** starting any monitor, so it was
present while nothing was watching. Reconcile sweeps the managed buses:

```bash
python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json reconcile
sudo python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json reconcile --apply
```

Expect the allowed drive to be authorised (`action: allow`, `enforcement_applied: true`)
and appear in `lsblk`. Devices that are not allowlisted are never revoked. One that is
still blocked is reported as `action: block`. One that was already authorised, such as the
VMware hubs and virtual mouse, is reported as `action: unchanged` with
`reason: not_allowlisted_left_unchanged` and `enforcement_applied: false`, so it cannot be
mistaken for a device that was blocked. The policy's own reason is in `policy_reason`.

## Clean up

```bash
sudo python3 src/enforcement/usb_authorization.py restore --apply
cat /sys/bus/usb/devices/usb2/authorized_default   # back to the original (usually 1)
```

## Limits

- Writing `authorized`/`authorized_default` enforces whole-device access. Per-interface
  authorisation (composite or BadUSB-style devices that re-register as another type) is
  out of scope for step 5 and belongs with the BPF-LSM layer (step 6).
- Vendor/product IDs and serials are device-reported and can be spoofed. Writes are bound to
  the device instance that was validated, so a replacement at the same port cannot inherit
  an approval, but a device that copies an allowlisted identity is still accepted.
- `authorize` and `revoke` act on the USB ID given, whatever the managed buses; only
  `enforce` and `reconcile` are limited to the managed buses.
- The anti-forensic *response* to a blocked device (lock, shutdown) is step 7; this
  component only emits `enforcement_result` records for it to consume.
