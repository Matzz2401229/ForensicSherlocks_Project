# Step 5: USB access control (default-deny, authorise, enforce, reconcile)

This component writes USB authorisation state in sysfs: the per-bus
`authorized_default` flag and the per-device `authorized` flag. It is the first
component that changes device access; steps 3 and 4 only observed and decided.

`arm`, `restore`, `authorize`, `revoke` and `reconcile` are dry runs unless
`--apply` is supplied. **`enforce` writes by default; use `enforce --dry-run` to
prevent its writes.** Live sysfs writes require root.

Commands affect the Linux system running them. Inside a VM, they control devices
connected to that guest; they do not change the Windows host's USB authorisation
settings. `arm --apply` gates newly connected devices on the managed buses; already
connected devices retain their access. Keep a working way to control the system
while testing. Unmount a test filesystem before revoking or disconnecting its drive.

Complete [shared testing setup](TESTING-SETUP.md) first. It selects your actual
`USB_ID`, creates a matching policy in `logs/test-allow.json` and scopes
`logs/test-enforcement.json` to that drive's inspected bus. Every bus-level command
below uses that same config and its saved original state. Stop any Step 6 controller
before these independent tests, or follow its coordinated-removal procedure first.

## Pull and run the unit tests

```bash
cd '/path/to/portwatchman'
# Check git status and the intended branch before updating your clone.
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expect `OK`. The enforcement tests use a fake sysfs tree and need no root or USB drive.

## Slice 1: default-deny a bus

Look first, write nothing:

```bash
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json status
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json arm          # dry run: prints the plan
```

`status` lists each bus and its `authorized_default`; `arm` reports the buses it
would set to `0`. Now apply default-deny, with the test flash drive unplugged:

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json arm --apply
```

Plug in the test drive, then confirm it does **not** appear:

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

The drive should be absent (blocked by default-deny). Restore when done:

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json restore --apply
```

`restore` only changes the default for devices connected from now on. A drive that was
blocked while armed stays blocked: replug it, or authorise it (slice 2), and it appears in
`lsblk` again.

## Slice 2: authorise or revoke one device

With the drive connected, confirm its current `USB_ID` using `list`/`inspect`.
Dry run first, then apply using your generated matching policy:

```bash
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json --policy logs/test-allow.json authorize "$USB_ID"
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json --policy logs/test-allow.json authorize "$USB_ID" --apply
cat "/sys/bus/usb/devices/$USB_ID/authorized"        # 1
```

The command binds to the device instance first, then re-reads the device and re-checks the
policy, and writes only to that same instance. A device whose attributes no longer match,
or that the policy no longer allows, stays blocked (`action: block`). If the device is
unplugged or replaced at the same port during the command, nothing is written and the
command reports `device_unavailable` or `device_changed`. If the filesystem mounted
after authorisation, identify its current partition and unmount it before revoking:

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
udisksctl unmount -b "$USB_PARTITION"
```

Then revoke to block it again:

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json revoke "$USB_ID" --apply
cat "/sys/bus/usb/devices/$USB_ID/authorized"        # 0
```

## Slice 3: the live enforcement pipeline

Arm default-deny first (slice 1), with the drive unplugged. Then run the USB-authorisation
pipeline - monitor detects, policy decides, enforce acts:

```bash
set -o pipefail
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy logs/test-allow.json watch |
  sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json --policy logs/test-allow.json enforce
```

`enforce` reads the selected `logs/test-enforcement.json` and acts only on devices on the managed buses.
It prints `enforcement_started` immediately, listing `managed_buses` and any
`unarmed_buses` (managed buses not set to default-deny; this should be empty after `arm`).
Then it prints an `enforcement_monitor_status` record when the monitor's health changes.
Wait for one with `healthy: true` (about five seconds), then connect the drive. Heartbeats
are not repeated, so the screen stays quiet until a device appears. A device inserted
before the monitor is healthy gets a `block` decision (the step 4 safety rule), not an
authorisation.

Expect an `enforcement_result` with `action: allow`, `enforcement_applied: true`,
`policy_reason: allowlist_match` and an `enforcement_latency_ns` (from the
referenced guest USB event to the enforcement result, not physical insertion time). Confirm the drive now appears in `lsblk`. To test the unlisted case, run
the same pipeline with `--policy logs/test-deny.json` on both stages: the result is
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
before its device was removed. With the test filesystem unmounted and the drive
still connected, confirm its current `USB_ID`:

```bash
sudo python3 -c '
import errno, sys
path = "/sys/bus/usb/devices/" + sys.argv[1] + "/authorized"
held = open(path, "r+b", buffering=0)
input("Holding " + path + ". Disconnect the selected test drive, then press Enter...")
try:
    held.write(b"1\n"); held.flush(); print("UNEXPECTED: write accepted")
except OSError as error:
    print("Refused as expected:", errno.errorcode.get(error.errno, error.errno))
' "$USB_ID"
```

Expected: `Refused as expected: ENODEV` (or another refusal), never `write accepted`.

## Slice 4: reconcile devices already connected

Arm default-deny, then connect the drive **before** starting any monitor, so it was
present while nothing was watching. Reconcile sweeps the managed buses:

```bash
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json --policy logs/test-allow.json reconcile
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json --policy logs/test-allow.json reconcile --apply
```

Expect the allowed drive to be authorised (`action: allow`, `enforcement_applied: true`)
and appear in `lsblk`. Devices that are not allowlisted are never revoked. One that is
still blocked is reported as `action: block`. One that was already authorised, such as the
VMware hubs and virtual mouse, is reported as `action: unchanged` with
`reason: not_allowlisted_left_unchanged` and `enforcement_applied: false`, so it cannot be
mistaken for a device that was blocked. The policy's own reason is in `policy_reason`.

## Clean up

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json restore --apply
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json status
```

## Limits

- Writing `authorized`/`authorized_default` enforces whole-device access. Per-interface
  authorisation (composite or BadUSB-style devices that re-register as another type) is
  not implemented in either Step 5 or the selected-file BPF-LSM guard in Step 6.
- Vendor/product IDs and serials are device-reported and can be spoofed. Writes are bound to
  the device instance that was validated, so a replacement at the same port cannot inherit
  an approval, but a device that copies an allowlisted identity is still accepted.
- `authorize` and `revoke` act on the USB ID given, whatever the managed buses; only
  `enforce` and `reconcile` are limited to the managed buses.
- The anti-forensic *response* to a blocked device (lock, shutdown) is step 7; this
  component only emits `enforcement_result` records for it to consume.

## Validation record

Step 5 is validated for the recorded Ubuntu VM environment: unit tests, live
authorise/revoke, allow/block pipeline behaviour, reconciliation, removed-device
write refusal and restoration passed. A new environment should rerun this guide.
The selected-file bridge is covered separately by [Step 6](STEP6-TESTING.md).
