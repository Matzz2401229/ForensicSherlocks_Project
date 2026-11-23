# Step 4: device identification and allowlist decisions

This component reads sysfs and produces decisions. It does not change USB
authorisation: `enforcement_applied` is false. Step 5 implements those writes.
Config and CLI outputs use schema version 1. Python 3.10+ and its standard library
are sufficient; no third-party Python packages are required.

Complete [shared testing setup](TESTING-SETUP.md), including selection of `USB_ID`
and generation of local test policies from your inspected device. Start in the
repository root, and use the same current `USB_ID` throughout each test:

```bash
cd '/path/to/portwatchman'
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 src/policy/device_policy.py --policy logs/test-allow.json validate
```

## Inspect a connected device

Connect the selected test flash drive to the Linux system under test:

```bash
python3 src/policy/device_policy.py list
python3 src/policy/device_policy.py inspect "$USB_ID"
```

Expect the vendor/product IDs of your inspected drive, its current device address,
optional serial and device-level class. Manufacturer/product/serial are self-reported.
No serial file means `serial: null`. `kernel_authorized` describes current kernel
state independently of the policy decision. Inventory includes root hubs but excludes
interface directories.

## Negative and positive policy tests

Use the generated empty policy to test rejection:

```bash
python3 src/policy/device_policy.py --policy logs/test-deny.json evaluate "$USB_ID"
```

Expect `action: block`, `reason: no_matching_allowlist_rule`.

Use your generated matching policy:

```bash
python3 src/policy/device_policy.py --policy logs/test-allow.json evaluate "$USB_ID"
```

Expect `action: allow`, `matched_rule: test-usb`, `enforcement_applied: false`.
This does not change the drive's actual authorisation.

Use the generated deliberately different serial:

```bash
python3 src/policy/device_policy.py --policy logs/test-mismatch.json evaluate "$USB_ID"
```

Expect `action: block`, with `serial` in `rule_mismatches`. A missing serial also
cannot satisfy a serial-specific rule. None of these tests requires the shipped
example policy or its illustrative device identity to match your hardware.

## Live monitor-to-policy test

Start with the drive unplugged, run:

```bash
set -o pipefail
sudo python3 src/monitor/usb_monitor.py | python3 src/policy/device_policy.py --policy logs/test-allow.json watch
```

Wait for a policy_monitor_status record with healthy=true (after monitor_alive),
then connect the drive to Ubuntu. Expected:

- setup_started is skipped because sysfs identification may not be ready yet;
- setup_completed produces a policy_decision with action=allow;
- the decision retains the monitor connection_id and matches the live address;
- disconnect_started is skipped as an approval decision, but remains visible;
- heartbeats report monitoring health.

Unmount before unplugging. Ctrl+C stops the pipeline. Confirm backend cleanup:

```bash
pgrep -af 'bpftrace.*usb_events[.]bt'
```

No matches expected. To capture decisions, redirect the policy output:

```bash
set -o pipefail
sudo python3 src/monitor/usb_monitor.py | python3 src/policy/device_policy.py --policy logs/test-allow.json watch > logs/device-decisions.jsonl
```

Read it from another terminal with tail. json.loads can validate each saved line,
as in step 3. Unexpected EOF produces a nonzero policy exit status; deliberate
Ctrl+C is a requested stop. Because a pipeline normally reports the last
command's exit status, use `set -o pipefail` when automating test runs.

## Authorisation-independent identification

Use the selected-bus arm/restore procedure in [Step 5](STEP5-TESTING.md), with
`logs/test-enforcement.json`. Connect the drive while default-deny is armed, then
inspect and evaluate its current USB ID with `logs/test-allow.json`.
Expect `kernel_authorized: false` but `action: allow`. The USB block device remains
absent because this component does not enforce its decision. Restore the original
defaults and use Step 5's policy-checked authorisation command for cleanup.

## Rules and CLI

Policies require exactly schema_version=1, default_action=block, allowlist=[...].
Every rule requires a unique name and quoted four-hex-digit vendor_id/product_id.
Optional serial is an exact, case-sensitive constraint; optional usb_id pins
the rule to a guest USB location, such as 2-1. All supplied constraints must match.
First matching rule wins. Unknown fields, duplicate JSON keys/rule names, malformed
IDs, unsupported versions, and default-allow policies are rejected as a whole.
Limits: 256 rules, 64 KiB config. A policy revision hash appears in valid decisions.

Commands: validate, list, inspect USB_ID, evaluate USB_ID, watch, add-rule,
remove-rule. The global --policy option goes BEFORE the command. add-rule and
remove-rule only change the selected local JSON file, using a validated atomic
replacement. They do not commit, push, alter sysfs, or modify GitHub. Defaults
resolve relative to this module's repository, not the shell's working directory.

The shared setup creates a strict rule from your actual vendor/product IDs and
includes the exact serial when available. To constrain a rule to a USB location,
add its current `usb_id`; that constraint may need updating after topology changes.
Do not substitute a sample serial or another user's device ID.

## Failure behaviour and limits

- Missing required attributes are retried for up to 0.5 seconds; optional absent
  serial/manufacturer/product values are null. Permission/format errors produce
  explicit failures. Identification errors yield block decisions in evaluate/watch.
- The reader compares directory inode/device and identity before/after reading;
  the watcher also checks the event's device address and current boot/session.
  These reduce stale-device races. Sysfs snapshots are not atomic and cannot
  guarantee physical identity; the Step 5 enforcer revalidates immediately
  before writing. Device address reuse is possible.
- Live events must be at most two seconds old, using the guest monotonic clock.
  Saved old logs are not a replay mechanism; they produce stale_event decisions.
- Every completed event reloads and validates the policy, so subsequent new
  events see config changes. A change does not revoke a previously approved
  device or re-evaluate already processed generations.
- Monitor startup, loss, diagnostics, invalid stream data, and stop conditions
  prevent allow decisions until a healthy new context is established. Loss is
  latched until a new monitor session starts. Devices inserted before the first
  healthy signal receive a conservative block decision; future daemon startup
  reconciliation will need to revisit them.
- Only setup_completed is evaluated. Root hubs are skipped; duplicates are
  suppressed within a bounded 1024-generation cache. Metadata validation limits
  accidental misuse, not forgery by an attacker controlling the input process.
- The device-level class is informative only. For composite devices, class 00
  does not describe all interfaces. Interface/capability allowlisting is not
  implemented; no class-based security guarantee is made.
- Vendor/product IDs and serials come from the device and can be spoofed.
  Allowlisting means attributes satisfy policy, not cryptographic authentication.
- Inventory via list is manual; watch processes new events only. Service-wide
  startup/recovery reconciliation and more extensive concurrency/burst testing
  remain later integration and failure-handling work.

## Completion evidence

Step 4 is validated for the recorded Ubuntu VM environment: unit tests,
identification, empty-policy rejection, matching-policy approval, serial mismatch,
live correlation and identification while unauthorised passed. Rerun the guide for
another environment. Policy decisions alone do not establish access control;
Step 5 separately implements and validates enforcement.
