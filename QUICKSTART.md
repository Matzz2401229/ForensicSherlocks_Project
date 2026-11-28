# PortWatchman quick start (fresh Ubuntu VM)

This sets up PortWatchman and tests USB allow/block, the screen-lock response and
VM-file protection. For everything else, see the [user manual](docs/USER-MANUAL.md).

The guide has two parts:

| Part | What you do | When |
|---|---|---|
| [A. Setup and configuration](#part-a-setup-and-configuration) | Install, build, identify your USB, generate the configuration | Once per VM, or again after changing the USB or the files to protect |
| [B. Functionality tests](#part-b-functionality-tests) | Run PortWatchman and check each behaviour | Each dry run, and before recording |

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
`monitor_preflight` record with `"status": "passed"`.

### A4. Identify your USB drive

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
| `logs/quick-service-destroy.json` | Service profile for B5 (only with `--destroy`) |

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

One drive is enough for both tests.

Now unmount the drive (use the eject icon in Files), then disconnect it from the
VM. **Keep it disconnected until a test says to connect it.**

---

## Part B. Functionality tests

Each test starts and stops PortWatchman itself. Before each one, check that the USB
is disconnected and no earlier run is still active (`Ctrl+C` in Terminal A).

| Test | Shows | Profile |
|---|---|---|
| [B1](#b1-approved-usb-and-file-protection) | An approved USB is allowed; protected VM files are denied | allow |
| [B2](#b2-unapproved-usb-preview) | An unapproved USB is blocked; the response is previewed only | block |
| [B3](#b3-real-screen-lock-response) | The screen-lock response runs for real | block |
| [B4](#b4-keep-protection-on-across-reboots) | The background service survives closing the terminal and restarting | block |
| [B5](#b5-full-response-lock-destroy-and-power-off) | An unapproved USB locks the screen, destroys the chosen files (even protected ones) and powers off | destroy |
| [B6](#b6-usb-connected-during-boot-known-limitation) | A USB connected while the VM starts is not re-checked (known limitation) | installed block |

The file guard (step 6) and the responses (step 7) work in sequence. While
PortWatchman runs, the guard keeps the protected files closed to everyone. When an
unapproved USB is connected, the response stage, the one process the guard lets
through, can destroy them.

### B1. Approved USB and file protection

**Terminal A:** start PortWatchman and wait for the `Ready.` line.

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json run --summary
```

`--summary` prints one short line per important event. Leave it off to see the full
JSON records instead.

**Terminal B** (also inside `portwatchman`): read the demo files with no USB connected.

```bash
cat build/test-tmp/quickstart/restricted.txt
cat build/test-tmp/quickstart/control.txt
sudo cat build/test-tmp/quickstart/restricted.txt
sudo python3 src/enforcement/lsm_client.py STATUS
```

**Expect:** both `restricted.txt` reads show `Permission denied` and `control.txt`
opens. About a second later, Terminal A shows `Blocked ... attempts to open
.../restricted.txt`, and `denied_opens` in the STATUS output is above 0.

Try to delete it too:

```bash
sudo rm build/test-tmp/quickstart/restricted.txt
```

**Expect:** `Permission denied`, and Terminal A shows `Blocked 1 attempt to delete or
change .../restricted.txt`. The service keeps running.

Now connect the USB to the VM.

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** Terminal A shows your drive as `ALLOWED by rule "trusted-usb"`, the drive
appears in `lsblk`, and the restricted file is still denied.

Unmount and disconnect the drive, then press **Ctrl+C** in Terminal A.
**Expect:** `Restored USB defaults: usb1=1, usb2=1, ...` (one entry per bus; your
buses may differ) and `Stopped cleanly`.

Read the restricted file once more:

```bash
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** it now opens. This is the "without protection" comparison.

### B2. Unapproved USB (preview)

**Terminal A:**

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json run --summary
```

Wait for `Ready.`, then connect the USB. In Terminal B:

```bash
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

**Expect:**

- Terminal A shows your drive as `BLOCKED (not on the allowlist)`
- Terminal A shows `Response lock_session: preview only, not applied` (the screen does **not** lock)
- The drive's storage does not appear in `lsblk`

Disconnect the drive and press **Ctrl+C** in Terminal A.

### B3. Real screen-lock response

Same test, with the response applied:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json run --apply-responses --summary
```

Wait for `Ready.` (it now says `APPLIED`), then connect the USB.

**Expect:** the Ubuntu screen locks. Unlock it, and Terminal A shows
`Response lock_session: done`.

Disconnect the drive and press **Ctrl+C**.

### B4. Keep protection on across reboots

A `run` in a terminal ends when the terminal closes or the VM restarts. To keep
PortWatchman armed until you turn it off, install it as a background service.

**Set up** (configuration step, done once per profile):

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-block.json
sudo systemctl enable --now portwatchman
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
```

**Expect:** `"running": true` and `"healthy": true`. The installed copy uses its own
settings in `/etc/portwatchman`, with responses in preview. Those settings stay
until you edit them there or reinstall; editing files in `logs/` does not change
the installed service.

**Test:** close the terminal, open a new one in `portwatchman`, and check the status
again. It is still running. Then disconnect the USB and restart the VM
(`sudo reboot`, or **VM > Power > Reset** to test a forced restart). After logging
in, open a terminal in `portwatchman`:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
cat build/test-tmp/quickstart/restricted.txt
sudo journalctl -b -u portwatchman --no-pager -o cat | grep -E 'previous_boot|service_ready'
```

**Expect:** still healthy, the restricted file is denied, and `service_ready` for
this boot. After a forced restart you also see `service_previous_boot_state_cleared`.
Connect the USB: it is blocked.

Keep the USB disconnected while the VM starts. A device that is already connected
when the service becomes ready keeps its access.

Protection stays on through every restart until you turn it off:

```bash
sudo systemctl disable --now portwatchman
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** the file opens again. `systemctl stop` without `disable` turns it off
only until the next boot.

### B5. Full response: lock, destroy and power off

This test destroys files and powers off the VM. **Take a VM snapshot first**, and run
B4's `disable --now` command if the background service is still running.

It uses the files you added with `--destroy` in A5 (in the example, the two evidence
files, which are also protected). If you did not add any, run A5 again with
`--destroy`, then the third A6 command.

**Preview first.** List what would be destroyed (nothing is deleted):

```bash
python3 src/responses/responses.py --config logs/quick-responses-destroy.json validate
python3 src/responses/responses.py --config logs/quick-responses-destroy.json run-action delete
```

**Expect:** `validate` lists `lock_session`, `delete` and `power`, and `would_delete`
lists only your chosen files.

Terminal A:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-destroy.json run --summary
```

Wait for `Ready.`. Terminal A also shows `Response stage may destroy protected files
(exempt from the file guard)`. In Terminal B, try to read a protected file you chose,
for example:

```bash
sudo cat ~/Desktop/evidence/notes.txt
```

**Expect:** `Permission denied`. Connect the USB and check that Terminal A shows all
three responses as `preview only, not applied`, and that your files still exist.
Disconnect the drive and press **Ctrl+C**.

**Applied.** Terminal A, saving the output so it survives the power-off:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-destroy.json run --apply-responses --summary | tee logs/b5-run.log
```

Wait for `Ready.` (it says `APPLIED`). Check once more that the protected file is
denied in Terminal B, then connect the USB.

**Expect:** the screen locks, then the VM shuts down by itself. A graceful shutdown
can take a while if Ubuntu is installing updates.

Start the VM, log in, and open a terminal in `portwatchman`:

```bash
ls -la ~/Desktop/evidence
cat build/test-tmp/quickstart/restricted.txt
grep -E 'BLOCKED|Response|destroyed' logs/b5-run.log
```

**Expect:** the destroyed files are gone. `restricted.txt`, which is protected but not
on the destroy list, still exists and opens (PortWatchman is not running now). The
log shows the block, `Response delete: done` and `Response power: issuing now`; it may
also show `Protected file destroyed` lines if they were written before the shutdown.

The next `run` sets aside the arm state left by the power-off automatically, and
reports each destroyed file as `Protected file not found, skipped`. Run A5 with
`--undestroy` and `--unprotect` for them, or revert to your snapshot, before testing
again.

Deletion overwrites and removes the files. It does not guarantee that no copy is
left in snapshots, the VM's disk file on the host, or the filesystem journal.

### B6. USB connected during boot (known limitation)

This checks what happens when a device is connected before PortWatchman starts. It
uses the background service from B4, so install and enable it again first if you
turned it off.

**Test:** shut down the VM. Power it on and, while the boot screen is still showing
(press **Esc** to stay at the GRUB menu if it appears), connect the USB to the VM.
Let it finish booting, log in, and open a terminal in `portwatchman`:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
sudo journalctl -b -u portwatchman --no-pager -o cat | grep service_startup_inventory
lsblk -o NAME,TRAN,SIZE,FSTYPE,MOUNTPOINTS
```

**Expect (limitation):** the service is healthy, the inventory line lists your drive
as already connected, and the drive's storage appears in `lsblk`. A device that is
present before the service becomes ready keeps its access and does not trigger a
response. Disconnect and reconnect it: it is now blocked.

Turn the service off afterwards with B4's `disable --now` command.

---

## If something goes wrong

| Problem | What to do |
|---|---|
| `bpftool` reports missing tools | Install `linux-tools-$(uname -r)`; see the [user manual](docs/USER-MANUAL.md#requirements-and-installation) |
| `Existing arm state found` or the service failed | Run the restore command below (state from before a restart is set aside automatically) |
| `install_service.py` says already installed | Stop it with `sudo systemctl disable --now portwatchman`; see the [update procedure](docs/USER-MANUAL.md#update-the-installed-tool) |
| `check` reports a missing VM file | Run the A5 command again |
| No block or allow record when connecting | If you used `--single-bus`, the drive may be on another bus: stop, restore, and repeat A4 and A5 |
| The VM mouse or keyboard stops working | A virtual device reconnected and was blocked: use the VMware console to stop PortWatchman and restore |
| Screen does not lock | Wait 30 seconds (cooldown) and reconnect; confirm you used `--apply-responses` |

Restore after a failure (stop the service first):

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json restore
```

A drive that was blocked stays blocked until you disconnect and reconnect it.

## What this does not cover

Changing the installed settings, the sanitise response, and the other power modes
(force, immediate and reboot) are in the [user manual](docs/USER-MANUAL.md). Run
destructive responses only
on disposable data in a VM with a snapshot. Fuller checks of file protection are in
[VM-file verification](docs/VM-FILE-PROTECTION-TESTING.md).
