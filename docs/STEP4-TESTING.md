# Step 4: device identification and allowlist decisions

This component only reads sysfs and produces decisions. A block decision does
not revoke current authorisation; an allow decision does not approve a blocked
device. `enforcement_applied` is always false. Step 5 will implement those writes.
All config and CLI outputs use schema_version 1. No third-party Python packages
are needed; Python 3.10+ is sufficient (Ubuntu 24.04 supplies a suitable Python).

Copy src/, config/, tests/, and this docs/ file into the Windows repository on
feature/device-policy. Preserve the existing monitor source, tests, Git settings,
and docs/STEP3-TESTING.md. Commit and push, then pull in Ubuntu:

```bash
cd ~/df/project/portwatchman
git pull --ff-only
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 src/policy/device_policy.py validate
```

## Inspect a connected device

Connect the known flash drive to Ubuntu through VMware:

```bash
python3 src/policy/device_policy.py list
python3 src/policy/device_policy.py inspect 2-1
```

Expected: vendor_id 058f, product_id 6387, current device_address, optional serial
and device-level class. Manufacturer/product/serial are self-reported strings.
No serial file means serial=null. kernel_authorized describes current kernel
state and is independent of the upcoming policy decision. Root hubs are included
in inventory; interface directories are excluded.

## Negative and positive policy tests

The shipped config/allowlist.json is default-block with no rules:

```bash
python3 src/policy/device_policy.py evaluate 2-1
```

Expected: action=block, reason=no_matching_allowlist_rule.

The example explicitly includes the known lab drive's vendor/product pair:

```bash
python3 src/policy/device_policy.py --policy config/allowlist.example.json validate
python3 src/policy/device_policy.py --policy config/allowlist.example.json evaluate 2-1
```

Expected: action=allow, matched_rule=lab-flash-drive, enforcement_applied=false.
Changing the JSON policy never changes the drive's actual authorisation here.

For a serial mismatch test, use an ignored local test policy (keep normal config
edits on Windows to preserve your chosen development workflow):

```bash
mkdir -p logs
cp config/allowlist.json logs/serial-mismatch-policy.json
python3 src/policy/device_policy.py --policy logs/serial-mismatch-policy.json add-rule --name wrong-serial --vendor-id 058f --product-id 6387 --serial PORTWATCHMAN-NEGATIVE-TEST-ONLY
python3 src/policy/device_policy.py --policy logs/serial-mismatch-policy.json evaluate 2-1
```

Ensure that the intentionally wrong serial differs from the serial shown by
inspect. Expected action=block, with serial in rule_mismatches. A missing serial
also cannot satisfy a serial-specific rule.

## Live monitor-to-policy test

Start with the drive unplugged, run:

```bash
sudo python3 src/monitor/usb_monitor.py | python3 src/policy/device_policy.py --policy config/allowlist.example.json watch
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
sudo python3 src/monitor/usb_monitor.py | python3 src/policy/device_policy.py --policy config/allowlist.example.json watch > logs/device-decisions.jsonl
```

Read it from another terminal with tail. json.loads can validate each saved line,
as in step 3. Unexpected EOF produces a nonzero policy exit status; deliberate
Ctrl+C is a requested stop. Because a pipeline normally reports the last
command's exit status, use `set -o pipefail` when automating test runs.

## Authorisation-independent identification

Repeat the earlier default-deny test on the confirmed lab bus (usb2), recording
and restoring its original default. Connect the unauthorised drive and inspect
and evaluate it with the example policy. Expected kernel_authorized=false but
action=allow. The USB block device remains absent: this stage does not enforce
the decision. Confirm IDs before manually approving the drive afterwards.

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

Example strict rule, after inspecting the real serial (do not copy a placeholder):

```json
{
  "name": "lab-flash-drive",
  "vendor_id": "058f",
  "product_id": "6387",
  "serial": "REPLACE_WITH_INSPECTED_SERIAL",
  "usb_id": "2-1"
}
```

## Failure behaviour and limits

- Missing required attributes are retried for up to 0.5 seconds; optional absent
  serial/manufacturer/product values are null. Permission/format errors produce
  explicit failures. Identification errors yield block decisions in evaluate/watch.
- The reader compares directory inode/device and identity before/after reading;
  the watcher also checks the event's device address and current boot/session.
  These reduce stale-device races. Sysfs snapshots are not atomic and cannot
  guarantee physical identity; future enforcement must revalidate immediately
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

Complete step 4 after tests pass in Ubuntu, actual attributes are identified,
empty-policy block / matching-policy allow / serial-mismatch block are confirmed,
the live monitor stream produces correctly correlated decisions, and a device
still unauthorised can be identified and evaluated. No actual access-control
claim follows until step 5 implements and validates enforcement.
