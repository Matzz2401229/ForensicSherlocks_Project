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
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS      # drive returns
```

## Slice 2: authorise or revoke one device

With the drive connected, find its USB ID (step 4's `list`/`inspect`), e.g. `2-1`.
Dry run first, then apply using the example policy that lists the lab drive:

```bash
python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json authorize 2-1
sudo python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json authorize 2-1 --apply
cat /sys/bus/usb/devices/2-1/authorized        # 1
```

The command re-reads the device and re-checks the policy before writing; a device
whose attributes no longer match, or that the policy no longer allows, stays blocked
(`action: block`). Revoke to block it again:

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

`enforce` prints `enforcement_started` immediately, then an `enforcement_monitor_status`
record when the monitor's health changes. Wait for one with `healthy: true` (about five
seconds), then connect the drive. Heartbeats are not repeated, so the screen stays quiet
until a device appears. A device inserted before the monitor is healthy gets a `block`
decision (the step 4 safety rule), not an authorisation.

Expect an `enforcement_result` with `action: allow`, `enforcement_applied: true`,
`policy_reason: allowlist_match` and an `enforcement_latency_ns` (insertion to
authorisation). Confirm the drive now appears in `lsblk`. To test the unlisted case, run
the same pipeline without `--policy` (the default policy has no rules): the result is
`action: block`, `reason: already_blocked`, `policy_reason: no_matching_allowlist_rule`,
and the drive stays absent from `lsblk`.

Press Ctrl+C to stop. `enforce` ends with an `enforcement_stream_closed` record
(`reason: requested_stop`) and no traceback. Confirm the backend is gone:

```bash
pgrep -af 'bpftrace.*usb_events[.]bt'          # no matches expected
```

Add `--dry-run` to the enforce command to see decisions acted on without writing.

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
- Vendor/product IDs and serials are device-reported and can be spoofed; re-validation
  narrows the swap window between decision and write but does not authenticate hardware.
- The anti-forensic *response* to a blocked device (lock, shutdown) is step 7; this
  component only emits `enforcement_result` records for it to consume.
