# Shared setup for USB testing

Use this setup for the identification, USB authorisation and BPF-LSM guides.
Commands use Bash inside the Linux system under test. The validated environment
is the Ubuntu/VMware configuration recorded in the [README](../README.md).
For a VM, connect the intended USB device to the guest using USB passthrough.
On a physical Linux host, commands affect that host's devices; that deployment
has not been validated by this project.

## Repository and dependencies

Replace the quoted path with your clone's repository root. Start every terminal
used in a test from that directory:

```bash
cd '/path/to/portwatchman'
mkdir -p logs
```

If updating an existing clone, inspect `git status` first. Use `git pull --ff-only`
only when the current branch tracks the revision you intend to test and local
changes have been handled. No particular development branch or host editor is required.

For Ubuntu, install the dependencies:

```bash
sudo apt update
sudo apt install -y git python3 bpftrace clang llvm linux-tools-common \
  build-essential pkg-config libbpf-dev libelf-dev libjson-c-dev
```

`linux-tools-common` provides Ubuntu's bpftool entry point. Check `bpftool version`.
If it reports missing tools for the running kernel, install the matching kernel-tools
package if available, or provide a working bpftool executable. Kernel BTF must exist
at `/sys/kernel/btf/vmlinux`; Step 6 additionally requires `bpf` in the active LSM
list (`sudo cat /sys/kernel/security/lsm`). Building/loading is covered by the Step 6
guide. Do not change the kernel or LSM configuration merely to copy the recorded
version numbers from the development environment table.

## Identify your own test device

Connect an intended test flash drive and inspect the current topology:

```bash
lsusb
python3 src/policy/device_policy.py list
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

Select the **device-level `usb_id` from the JSON inventory**, not the device address
from `lsusb`. Set the variable below to that value. The placeholder deliberately
does not identify a real device:

```bash
export USB_ID='REPLACE_WITH_USB_ID'
python3 src/policy/device_policy.py inspect "$USB_ID" > logs/test-usb-device.json
cat logs/test-usb-device.json
```

Continue only if inspection succeeds and the record describes the intended drive,
not an input device or hub. Stop a procedure when a prerequisite command fails.
USB IDs, bus numbers, addresses, block-device names and mount directories may change
after reconnecting or reconfiguring the VM. Re-list devices when needed. A USB ID
has a format such as `1-2` or `1-2.3`; these are illustrations, not values to reuse.

## Generate local test policies and bus configuration

The following reads the inspected identity and writes only ignored files under
`logs/`. It does not change the repository policies, USB authorisation or USB files.
It refuses an existing test arm-state file: restore with its owning configuration
before regenerating configuration for a different device or bus.

```bash
python3 - <<'PY'
import json
from pathlib import Path

device = json.loads(Path("logs/test-usb-device.json").read_text())["device"]
if device["is_root_hub"]:
    raise SystemExit("Select a test flash drive, not a root hub")
if Path("logs/test-enforcement-state.json").exists():
    raise SystemExit("Restore the previous test using logs/test-enforcement.json first")

rule = {"name": "test-usb", "vendor_id": device["vendor_id"],
        "product_id": device["product_id"]}
if device.get("serial"):
    rule["serial"] = device["serial"]
allow = {"schema_version": 1, "default_action": "block", "allowlist": [rule]}
deny = {"schema_version": 1, "default_action": "block", "allowlist": []}
wrong_serial = "PORTWATCHMAN-NONMATCHING-SERIAL"
if wrong_serial == device.get("serial"):
    wrong_serial += "-2"
mismatch = {"schema_version": 1, "default_action": "block",
            "allowlist": [{**rule, "serial": wrong_serial}]}
enforcement = {"schema_version": 1, "managed_buses": ["usb" + str(device["bus"])],
               "state_file": "logs/test-enforcement-state.json"}
for name, document in [("test-allow.json", allow), ("test-deny.json", deny),
                       ("test-mismatch.json", mismatch), ("test-enforcement.json", enforcement)]:
    Path("logs", name).write_text(json.dumps(document, indent=2) + "\n")
print("Prepared test policies for the inspected identity and selected bus.")
PY

python3 src/policy/device_policy.py --policy logs/test-allow.json validate
python3 src/policy/device_policy.py --policy logs/test-deny.json validate
python3 src/policy/device_policy.py --policy logs/test-mismatch.json validate
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json status
```

The allow rule matches vendor/product IDs and, when present, the exact serial.
Without a serial it matches all devices reporting that vendor/product pair. The
serial-mismatch rule cannot match the inspected serial, including when no serial
is reported. These are attribute checks, not authentication of physical hardware.
The shipped `config/allowlist.example.json` is illustrative and may not match your
drive; the guides use the generated policies to avoid that assumption.

## Select the current partition and mount

When the drive is authorised, use `lsblk` to select its partition and mount directory:

```bash
export USB_PARTITION='/dev/REPLACE_WITH_USB_PARTITION'
export USB_MOUNT='/path/to/mounted/usb'
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
findmnt -T "$USB_MOUNT" -o SOURCE,TARGET,FSTYPE
```

Replace both placeholders. `USB_PARTITION` is a block-device path; `USB_MOUNT` is
an existing mounted directory. Confirm that `findmnt` identifies the USB filesystem,
not the Linux system filesystem. If the drive is authorised but not automounted,
use `udisksctl mount -b "$USB_PARTITION"`, then read its actual mount directory.
These shell variables belong to one terminal; set them again in another terminal.
Do not reuse a saved partition or mount path after reconnecting without checking it.

## Release and restore

Unmount before disconnecting a mounted drive:

```bash
udisksctl unmount -b "$USB_PARTITION"
```

An active Step 6 controller holds file references that can keep the mount busy.
Follow [coordinated removal](STEP6-TESTING.md#coordinated-removal-and-reconnect), or
stop the owning pipeline/controller normally, before unmounting. Disconnect only
after successful unmounting.

For tests using the generated enforcement config, restore the saved bus defaults:

```bash
sudo python3 src/enforcement/usb_authorization.py \
  --config logs/test-enforcement.json restore --apply
python3 src/enforcement/usb_authorization.py \
  --config logs/test-enforcement.json status
```

Restore returns the recorded original value, which need not be `1`. A drive already
blocked stays blocked after restoring defaults; after confirming its current USB ID,
authorise it with `logs/test-allow.json` or reconnect it under the restored defaults.
Use the exact configuration/state file that originally armed a bus. Do not delete
the state file as a substitute for restoring it.
