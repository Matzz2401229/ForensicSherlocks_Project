# PortWatchman quick start (fresh Ubuntu VM)

This sets up PortWatchman and tests USB allow/block, the screen-lock response and
VM-file protection. For everything else, see the [user manual](docs/USER-MANUAL.md).

The guide has two parts:

| Part | What you do | When |
|---|---|---|
| [A. Setup and configuration](#part-a-setup-and-configuration) | Install, build, identify your USB, generate the configuration, install the background service | Once per VM, or again after changing the USB or the files to protect |
| [B. Functionality tests](#part-b-functionality-tests) | Arm the background service with each test profile and check each behaviour | Each dry run, and before recording |

**You need**

- An Ubuntu 24.04 desktop VM under VMware, with internet access
- A USB flash drive that can be passed through to the VM
- A VM snapshot taken before you start (recommended)

Run every command in a terminal **inside the Ubuntu VM**, from the repository
folder. Stop at the first step that does not show the expected result.

---

## Part A. Setup and configuration

Nothing in Part A blocks USB devices or protects files yet.

### A1. Install

```bash
sudo apt update
sudo apt install -y git python3 bpftrace usbutils udisks2 clang llvm \
  linux-tools-common build-essential pkg-config libbpf-dev libelf-dev libjson-c-dev
sudo apt install -y "linux-tools-$(uname -r)"

git clone -b fix/BPF-rules-modification https://github.com/Matzz2401229/ForensicSherlocks_Project.git portwatchman
cd portwatchman
mkdir -p logs
```

Use `main` instead of `fix/BPF-rules-modification` once it has been merged. If you
were given the code another way, open a terminal in its top folder instead.
**All later commands run from that folder.**

### A2. Turn on BPF-LSM

```bash
sudo cat /sys/kernel/security/lsm
```

If the list already contains `bpf`, go to A3. Otherwise add it and reboot:

```bash
LSMS="$(sudo cat /sys/kernel/security/lsm),bpf"
echo "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX lsm=$LSMS\"" |
  sudo tee /etc/default/grub.d/99-portwatchman-lsm.cfg
sudo update-grub
sudo reboot
```

After the reboot, run `cd portwatchman`, then the `cat` command again. The list
must now contain `bpf`.

### A3. Build and check

```bash
bash src/enforcement/bpf/build.sh
sudo src/enforcement/bpf/build/lsm_controller --check
sudo python3 src/monitor/usb_monitor.py --check
```

**Expect:** `Built: ...lsm_controller`, then `lsm_preflight_passed`, then a
`monitor_preflight` record with `"status": "passed"`. The build may print a few
warnings from the generated `vmlinux.h` kernel header; they are harmless.

Then run the automated tests. The second command loads the file guard into the
kernel and tests it on disposable files only:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
sudo python3 tests/enforcement/test_bpf_lsm.py --local
```

**Expect:** the unit tests end with `OK`, and the guard tests print a series of
`PASS:` lines ending with `All BPF-LSM acceptance checks passed`. Do not continue
if either fails.

### A4. Identify your USB drive

This step sets up the approved USB, the device PortWatchman will allow.

> **Skipping A4 (not recommended).** You can leave it out and add
> `--no-allowed-device` to the A5 command. Every USB is then unapproved and blocked,
> no allow profile is created, and test B1 cannot run, so you cannot show that an
> approved device still works. To add an approved USB later, do A4 and run A5 again
> without `--no-allowed-device`.

Plug in the drive and connect it to the VM (**VM > Removable Devices**). Then:

```bash
python3 src/policy/device_policy.py list
```

Find your flash drive in the output and note its `usb_id` (it looks like `3-2`).
Do not pick a mouse, keyboard or hub.

```bash
USB_ID='REPLACE_WITH_YOUR_USB_ID'
python3 src/policy/device_policy.py inspect "$USB_ID" > logs/quick-device.json
cat logs/quick-device.json
```

Check that the record describes your drive.

### A5. Generate the configuration

```bash
python3 scripts/quickstart_config.py
```

This reads the drive saved in A4, creates the demo files and everything under
`logs/`, then prints the drive, the managed USB buses and the files it will protect.

**Choose your files.** Two lists can be set, and a file can be on both:

| Option | List | Effect |
|---|---|---|
| `--protect FILE` | Protected files | Nobody can open, change or delete them while PortWatchman runs, not even root |
| `--destroy PATH` | Destroyed on trigger | When an unapproved USB is connected, the response locks the screen, overwrites and deletes them, then powers off (test B5) |

For example, to protect two evidence files and destroy them if an unapproved USB
appears:

```bash
python3 scripts/quickstart_config.py \
  --protect ~/Desktop/evidence/notes.txt --protect ~/Desktop/evidence/archive.zip \
  --destroy ~/Desktop/evidence/notes.txt --destroy ~/Desktop/evidence/archive.zip
```

Each file must already exist. The lists are saved in `logs/quick-files.json`, and
each run adds to them, so you can also add files one run at a time. To change the
lists later:

| To | Run with |
|---|---|
| Remove a protected file | `--unprotect FILE` |
| Remove a file to destroy | `--undestroy PATH` |
| Start both lists again | `--reset` |
| See the current lists | no options (they are printed) |

The response stage is the only process that may pass the file guard, so it can
destroy protected files while everything else is still denied.

**Managed buses.** By default every USB bus is managed (`"managed_buses": "auto"`),
so a device plugged into any port is blocked. Add `--single-bus` to manage only the
bus your drive is on now. Bus numbers can change after a reboot, and devices on
other buses are then not blocked at all, so use it only for a narrow test.

Devices that are already connected when PortWatchman starts keep their access. A
device that connects later is treated as new, including a VMware virtual mouse or
hub that reconnects after the VM is suspended. Avoid suspending the VM while
PortWatchman is running.

The generated files:

| File | Contains |
|---|---|
| `logs/quick-allow.json` | Allowlist with your drive |
| `logs/quick-block.json` | Empty allowlist |
| `logs/quick-enforcement.json` | Managed buses and the saved-state file |
| `logs/quick-responses.json` | Response plan: lock the screen |
| `logs/quick-lsm.json` | VM files to protect |
| `logs/quick-files.json` | Your protect and destroy lists, kept between runs |
| `logs/quick-service-allow.json` | Service profile using the allowlist with your drive |
| `logs/quick-service-block.json` | Service profile using the empty allowlist |
| `logs/quick-responses-destroy.json` | Response plan for B5: lock, destroy, power off (only with `--destroy`) |
| `logs/quick-service-lock.json` | Service profile for B3: empty allowlist, screen lock applied |
| `logs/quick-service-destroy.json` | Service profile for B5: empty allowlist, lock, destroy and power off applied (only with `--destroy`) |
| `logs/quick-service-deploy.json` | Profile for the background service (A7): your USB allowed, responses applied |

These files stay as they are until you edit them or run A5 again.

### A6. Check the profiles

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json check
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json check
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-destroy.json check
```

Skip the third command if you did not use `--destroy`.

**Expect:** `service_preflight_passed` for each profile.

| Profile | Your USB is | Used to show |
|---|---|---|
| `quick-service-allow.json` | On the allowlist | An approved device |
| `quick-service-block.json` | Not on the allowlist | An unapproved device |
| `quick-service-destroy.json` | Not on the allowlist | The full lock, destroy and power-off response |

One drive is enough for all of these tests. If you used `--no-allowed-device`,
skip the first `check` command; there is no allow profile.

### A7. Install the background service (not armed yet)

For real use, PortWatchman runs as a background (systemd) service. It has no
terminal or window, keeps running when a terminal is closed or the user logs out,
and can start again at every boot. Install it with the profile made for that:

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-deploy.json
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py --config /etc/portwatchman/service.json check
```

**Expect:** a `service_installed` record, then `service_preflight_passed`.

Installing copies the code to `/opt/portwatchman` and the configuration to
`/etc/portwatchman`; it does **not** start the service. The installed profile allows
your USB from A4, protects the files from A5 and **applies** the response plan:
once armed, an unapproved USB locks the screen and, if you used
`--destroy`, destroys those files and powers off. Later changes to `logs/` do not
change the installed copy until it is installed again; Part B switches between
the test profiles with `--replace-config`.

Now unmount the drive (use the eject icon in Files), then disconnect it from the
VM. **Keep it disconnected until a test says to connect it.** This is a good point
for a VM snapshot to return to before Part B.

---

## Part B. Functionality tests

Every test uses the background service installed in A7, the way PortWatchman is
meant to run. It has no window; watch what it does with `follow`, which prints one
short line per important event.

**Two terminals.** Terminal A shows the events; Terminal B runs the test commands.
Open both inside `portwatchman`. Start `follow` in Terminal A first: it shows only
events from that moment on.

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py follow
```

| To | Run in Terminal B |
|---|---|
| Arm now | `sudo systemctl start portwatchman` |
| Arm now and at every boot | `sudo systemctl enable --now portwatchman` |
| Disarm | `sudo systemctl disable --now portwatchman` |
| Check the state | `sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status` |
| Switch the installed profile (disarmed only) | `sudo python3 scripts/install_service.py --config logs/PROFILE --replace-config` |

| Test | Shows | Installed profile |
|---|---|---|
| [B1](#b1-approved-usb-and-file-protection) | An approved USB is allowed; protected VM files are denied | `quick-service-deploy.json` (from A7) |
| [B2](#b2-unapproved-usb-preview) | An unapproved USB is blocked; the response is previewed only | `quick-service-block.json` |
| [B3](#b3-real-screen-lock-response) | The screen-lock response runs for real | `quick-service-lock.json` |
| [B4](#b4-the-service-persists) | The armed service keeps running after closing the terminal, logging out and restarting | `quick-service-deploy.json` |
| [B5](#b5-full-response-lock-destroy-and-power-off) | An unapproved USB locks the screen, destroys the chosen files (even protected ones) and powers off | `quick-service-destroy.json` |
| [B6](#b6-usb-connected-during-boot-known-limitation) | A USB connected while the VM starts is not re-checked (known limitation) | `quick-service-deploy.json` |

Before each test, check that the USB is disconnected and the service is disarmed.

The file guard (step 6) and the responses (step 7) work in sequence. While
PortWatchman runs, the guard keeps the protected files closed to everyone. When an
unapproved USB is connected, the response stage, the one process the guard lets
through, can destroy them.

A terminal run (`sudo python3 src/daemon/portwatchman.py --config logs/PROFILE run --summary`)
is also available for troubleshooting. It stops when its terminal is closed, so do
not use it for real protection.

### B1. Approved USB and file protection

The profile from A7 is already installed. **Its responses are applied:** connect
only your approved USB while it is armed.

**Terminal A:** start `follow`. **Terminal B:** arm the service.

```bash
sudo systemctl start portwatchman
```

**Expect** in Terminal A: `Protecting 3 VM file(s): ...`, `Armed usb1, ...`,
`Response stage may destroy protected files (exempt from the file guard)`, then
`Ready. Response plan: ... (APPLIED)`.

**Terminal B:** read the demo files with no USB connected.

```bash
cat build/test-tmp/quickstart/restricted.txt
cat build/test-tmp/quickstart/control.txt
sudo cat build/test-tmp/quickstart/restricted.txt
cat ~/Desktop/evidence/notes.txt
sudo python3 src/enforcement/lsm_client.py STATUS
```

Use one of your own protected files in the fourth command. **Expect:** every
protected file shows `Permission denied` and `control.txt` opens. About a second
later, Terminal A shows `Blocked ... attempts to open ...`, and the STATUS output
lists your protected files with `denied_opens` above 0.

Try to delete one too:

```bash
sudo rm build/test-tmp/quickstart/restricted.txt
```

**Expect:** `Permission denied`, and Terminal A shows `Blocked 1 attempt to delete or
change .../restricted.txt`.

Now connect the USB to the VM.

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** Terminal A shows your drive as `ALLOWED by rule "trusted-usb"`, the drive
appears in `lsblk`, and the protected file is still denied.

Unmount and disconnect the drive, then disarm:

```bash
sudo systemctl stop portwatchman
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** Terminal A shows `VM file protection released`, `Restored USB defaults:
usb1=1, usb2=1, ...` and `Stopped cleanly`, and the file now opens. This is the
"without protection" comparison.

### B2. Unapproved USB (preview)

**Terminal B:** install the preview profile and arm.

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-block.json --replace-config
sudo systemctl start portwatchman
```

Wait for `Ready.` in Terminal A (it says `preview only`), then connect the USB.

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

**Expect:**

- Terminal A shows your drive as `BLOCKED (not on the allowlist)`
- Terminal A shows `Response lock_session: preview only, not applied` (the screen does **not** lock)
- The drive's storage does not appear in `lsblk`

Disconnect the drive and disarm (`sudo systemctl stop portwatchman`).

### B3. Real screen-lock response

**Terminal B:**

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-lock.json --replace-config
sudo systemctl start portwatchman
```

Wait for `Ready.` (it now says `APPLIED`), then connect the USB.

**Expect:** the Ubuntu screen locks. Unlock it, and Terminal A shows
`Response lock_session: done`.

Disconnect the drive and disarm (`sudo systemctl stop portwatchman`).

### B4. The service persists

This shows that once armed, PortWatchman keeps running without a terminal, across
logouts and restarts, until the owner disarms it. **Its responses are applied:**
connect only your approved USB while it is armed.

**Terminal B:** switch back to the real-use profile from A7 (B2 and B3 replaced it
with test profiles), then arm it now and at every boot.

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-deploy.json --replace-config
sudo systemctl enable --now portwatchman
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** `"running": true` and `"healthy": true`, and the protected file shows
`Permission denied`.

**Close the terminals.** Close both terminals, open a new one in `portwatchman`, and
run the `status` and `cat` commands again. **Expect:** still running and healthy,
and the file is still denied.

**Log out.** Log out of the Ubuntu desktop, log back in, open a terminal in
`portwatchman` and repeat the two commands. **Expect:** the same.

**Restart.** With the USB disconnected, restart the VM (`sudo reboot`, or
**VM > Power > Reset** to test a forced restart). After logging in, open a terminal
in `portwatchman`:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
cat build/test-tmp/quickstart/restricted.txt
sudo journalctl -b -u portwatchman --no-pager -o cat | grep -E 'previous_boot|service_ready'
```

**Expect:** still healthy, the protected file is denied, and `service_ready` for this
boot. After a forced restart you also see `service_previous_boot_state_cleared`.
Connect your approved USB: it is allowed. Unmount and disconnect it again.

Keep any USB disconnected while the VM starts. A device that is already connected
when the service becomes ready keeps its access (see B6).

**Disarm:**

```bash
sudo systemctl disable --now portwatchman
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** the file opens again. To open protected files as the owner, disarm,
use them, then arm again with `enable --now`. `sudo systemctl stop portwatchman`
disarms only until the next boot.

### B5. Full response: lock, destroy and power off

This test destroys files and powers off the VM. **Take a VM snapshot first.**

It uses the files you added with `--destroy` in A5 (in the example, the two evidence
files, which are also protected). If you did not add any, run A5 again with
`--destroy`.

**Preview first.** List what would be destroyed (nothing is deleted):

```bash
python3 src/responses/responses.py --config logs/quick-responses-destroy.json validate
python3 src/responses/responses.py --config logs/quick-responses-destroy.json run-action delete
```

**Expect:** `validate` lists `lock_session`, `delete` and `power`, and `would_delete`
lists only your chosen files.

**Terminal B:** install the destroy profile and arm (now only, not at boot).

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-destroy.json --replace-config
sudo systemctl start portwatchman
```

Wait for `Ready.` in Terminal A (it says `APPLIED`). Check that a protected file you
chose is still denied, for example `sudo cat ~/Desktop/evidence/notes.txt`, then
connect the USB.

**Expect:** Terminal A shows the block and the responses, the screen locks, then the
VM shuts down by itself. A graceful shutdown can take a while if Ubuntu is
installing updates.

Start the VM, log in, and open a terminal in `portwatchman`:

```bash
ls -la ~/Desktop/evidence
cat build/test-tmp/quickstart/restricted.txt
sudo journalctl -b -1 -u portwatchman --no-pager -o cat | grep -E '"enforcement_result"|"response_action"|protected_file_destroyed'
```

**Expect:** the destroyed files are gone. `restricted.txt`, which is protected but not
on the destroy list, still exists and opens (the service was not set to start at
boot). The journal from the previous boot shows the `block` result, a `delete`
response with `"ok":true` and the `power` response; it may also show
`service_protected_file_destroyed` records if they were written before the shutdown.

Before arming again, clear the state left by the power-off:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py --config /etc/portwatchman/service.json restore
```

The next start reports each destroyed file as `Protected file not found, skipped`.
Revert to your snapshot to restore the files before testing again.

Deletion overwrites and removes the files. It does not guarantee that no copy is
left in snapshots, the VM's disk file on the host, or the filesystem journal.

### B6. USB connected during boot (known limitation)

This checks what happens when a device is connected before PortWatchman starts. It
needs a USB device that is **not** on the allowlist (for example a second flash
drive); with only your approved USB the result looks the same either way, so skip
B6 and record it as a limitation.

**Test:** switch back to the real-use profile from A7 (B5 replaced it), then arm it
at boot:

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-deploy.json --replace-config
sudo systemctl enable --now portwatchman
```

Shut down the VM. Power it on and, while the boot screen is still showing (press
**Esc** to stay at the GRUB menu if it appears), connect the unapproved USB to the
VM. Let it finish booting, log in, and open a terminal in `portwatchman`:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
sudo journalctl -b -u portwatchman --no-pager -o cat | grep service_startup_inventory
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

**Expect (limitation):** the service is healthy, the inventory line lists the device
as already connected, and its storage appears in `lsblk`. A device that is present
before the service becomes ready keeps its access and does not trigger a response.

**Disarm before disconnecting it** (`sudo systemctl disable --now portwatchman`).
Reconnecting it while armed would trigger the applied response.

---

## If something goes wrong

| Problem | What to do |
|---|---|
| `bpftool` reports missing tools | Install `linux-tools-$(uname -r)`; see the [user manual](docs/USER-MANUAL.md#requirements-and-installation) |
| `Existing arm state found` or the service failed | Run the restore command below (state from before a restart is set aside automatically) |
| `install_service.py` says already installed, or you changed A5 and want the service to use it | Disarm (`sudo systemctl disable --now portwatchman`), then install the profile again with `--replace-config`. For code updates only, see the [update procedure](docs/USER-MANUAL.md#update-the-installed-tool) |
| `install_service.py` says saved service arm state exists | Run the background-service restore command below, then try again |
| `follow` shows nothing | It shows only new events: start it before arming, or add `--recent 50` |
| `check` reports a missing VM file | Run the A5 command again |
| No block or allow record when connecting | If you used `--single-bus`, the drive may be on another bus: stop, restore, and repeat A4 and A5 |
| The VM mouse or keyboard stops working | A virtual device reconnected and was blocked: use the VMware console to stop PortWatchman and restore |
| Screen does not lock | Wait 30 seconds (cooldown) and reconnect; check that the `Ready.` line says `APPLIED` (B3 profile installed) |

Restore after a failure or a power-off response (disarm the service first):

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py --config /etc/portwatchman/service.json restore
```

After a failed terminal run, use the checkout instead:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json restore
```

A drive that was blocked stays blocked until you disconnect and reconnect it.

## What this does not cover

Changing the installed settings, the sanitise response, and the other power modes
(force, immediate and reboot) are in the [user manual](docs/USER-MANUAL.md). Run
destructive responses only
on disposable data in a VM with a snapshot. Fuller checks of file protection are in
[VM-file verification](docs/VM-FILE-PROTECTION-TESTING.md).
