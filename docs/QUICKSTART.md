# PortWatchman quick start (fresh Ubuntu VM)

This sets up PortWatchman and tests USB allow/block, the screen-lock response and
VM-file protection. For everything else, see the [user manual](USER-MANUAL.md).

**You need**

- An Ubuntu 24.04 desktop VM under VMware, with internet access
- A USB flash drive that can be passed through to the VM
- A VM snapshot taken before you start (recommended)

Run every command in a terminal **inside the Ubuntu desktop**. Stop at the first
step that does not show the expected result.

## 1. Install

```bash
sudo apt update
sudo apt install -y git python3 bpftrace usbutils udisks2 clang llvm \
  linux-tools-common build-essential pkg-config libbpf-dev libelf-dev libjson-c-dev
sudo apt install -y "linux-tools-$(uname -r)"

git clone -b fix/bpf-lsm https://github.com/Matzz2401229/ForensicSherlocks_Project.git portwatchman
cd portwatchman
mkdir -p logs
```

If you were given the code another way, open a terminal in its top folder instead.
**All later commands run from that folder.**

## 2. Turn on BPF-LSM

```bash
sudo cat /sys/kernel/security/lsm
```

If the list already contains `bpf`, go to step 3. Otherwise add it and reboot:

```bash
LSMS="$(sudo cat /sys/kernel/security/lsm),bpf"
echo "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX lsm=$LSMS\"" |
  sudo tee /etc/default/grub.d/99-portwatchman-lsm.cfg
sudo update-grub
sudo reboot
```

After the reboot, run `cd portwatchman`, then the `cat` command again. The list
must now contain `bpf`.

## 3. Build and check

```bash
bash src/enforcement/bpf/build.sh
sudo src/enforcement/bpf/build/lsm_controller --check
sudo python3 src/monitor/usb_monitor.py --check
```

**Expect:** `Built: ...lsm_controller`, then `lsm_preflight_passed`, then a
`monitor_preflight` record with `"status": "passed"`.

## 4. Identify your USB drive

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

## 5. Generate the configuration

```bash
python3 scripts/quickstart_config.py
```

This reads the drive saved in step 4, creates the demo files and everything under
`logs/`, then prints the drive and the files it will protect.

To protect extra files of your own as well, add `--protect` once per file. Each
file must already exist:

```bash
python3 scripts/quickstart_config.py --protect ~/Desktop/secret.txt
```

Then check both profiles:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json check
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json check
```

**Expect:** `service_preflight_passed` twice.

| Profile | Your USB is | Used to show |
|---|---|---|
| `quick-service-allow.json` | On the allowlist | An approved device |
| `quick-service-block.json` | Not on the allowlist | An unapproved device |

One drive is enough for both tests.

Now unmount the drive (use the eject icon in Files), then disconnect it from the
VM. **Keep it disconnected until each test says to connect it.**

## 6. Test an approved USB and file protection

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
**Expect:** `Restored USB defaults: usb4=1` (your bus may differ) and `Stopped cleanly`.

Read the restricted file once more:

```bash
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** it now opens. This is the "without protection" comparison.

## 7. Test an unapproved USB (preview)

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

## 8. Test the real screen-lock response

Same test, with the response applied:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-block.json run --apply-responses --summary
```

Wait for `Ready.` (it now says `APPLIED`), then connect the USB.

**Expect:** the Ubuntu screen locks. Unlock it, and Terminal A shows
`Response lock_session: done`.

Disconnect the drive and press **Ctrl+C**.

## 9. Keep protection on across reboots

A `run` in a terminal ends when the VM restarts. To keep PortWatchman armed until
you turn it off, install it as a background service and enable it:

```bash
sudo python3 scripts/install_service.py --config logs/quick-service-block.json
sudo systemctl enable --now portwatchman
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
```

**Expect:** `"running": true` and `"healthy": true`. The installed copy uses its own
settings in `/etc/portwatchman`, with responses in preview.

Disconnect the USB, then restart the VM (`sudo reboot`, or **VM > Power > Reset**
to test a forced restart). After logging in, open a terminal in `portwatchman`:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
cat build/test-tmp/quickstart/restricted.txt
sudo journalctl -b -u portwatchman --no-pager -o cat | grep -E 'previous_boot|service_ready'
```

**Expect:** still healthy, the restricted file is denied, and `service_ready` for
this boot. After a forced restart you also see `service_previous_boot_state_cleared`.
Connect the USB: it is blocked.

Protection stays on through every restart until you turn it off:

```bash
sudo systemctl disable --now portwatchman
cat build/test-tmp/quickstart/restricted.txt
```

**Expect:** the file opens again. `systemctl stop` without `disable` turns it off
only until the next boot.

## If something goes wrong

| Problem | What to do |
|---|---|
| `bpftool` reports missing tools | Install `linux-tools-$(uname -r)`; see the [user manual](USER-MANUAL.md#requirements-and-installation) |
| `Existing arm state found` or the service failed | Run the restore command below (state from before a restart is set aside automatically) |
| `install_service.py` says already installed | Stop it with `sudo systemctl disable --now portwatchman`; see the [update procedure](USER-MANUAL.md#update-the-installed-tool) |
| `check` reports a missing VM file | Run the step 5 command again |
| No block or allow record when connecting | The drive may be on another bus: stop, restore, and repeat steps 4 and 5 |
| Screen does not lock | Wait 30 seconds (cooldown) and reconnect; confirm you used `--apply-responses` |

Restore after a failure (stop the service first):

```bash
sudo python3 src/daemon/portwatchman.py --config logs/quick-service-allow.json restore
```

A drive that was blocked stays blocked until you disconnect and reconnect it.

## What this does not cover

Changing the installed settings, and the delete, sanitise and power responses, are
in the [user manual](USER-MANUAL.md). Run destructive responses only
on disposable data in a VM with a snapshot. Fuller checks of file protection are in
[VM-file verification](VM-FILE-PROTECTION-TESTING.md).
