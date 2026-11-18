# Development environment setup (Ubuntu VM on Windows)

This guide rebuilds the environment the project was validated on: an Ubuntu 24.04.5
LTS guest in VMware Workstation Pro on a Windows laptop, with USB passthrough. Use the
same versions as the rest of the team so test results and timings are comparable.

| Component | Use |
| --- | --- |
| Hypervisor | VMware Workstation Pro (free; current release 26H1) |
| Guest OS | Ubuntu 24.04.5 LTS Desktop, image `ubuntu-24.04.5.1-desktop-amd64.iso` |
| Kernel | 7.0 HWE kernel shipped with 24.04.5 (`7.0.0-xx-generic`) |
| Python | 3.10 or later (24.04 ships 3.12); standard library only |

Why 24.04.5 and not 26.04: the monitor, policy and enforcement components were
validated on 24.04.5 with the 7.0 kernel and bpftrace 0.20.2. Changing the release now
would change the kernel and tool versions mid-project.

Why the `.5.1` image: Canonical pulled the original 24.04.5 desktop ISO a few days after
release because of an installer crash, and reissued it as 24.04.5.1. The system you end
up with is the same 24.04.5 release.

## 1. Prepare the Windows host

- At least 16 GB RAM and 80 GB free disk is comfortable (the VM uses 8 GB and 60 GB).
- Enable hardware virtualisation (Intel VT-x or AMD-V) in the BIOS/UEFI if VMware
  reports that it is disabled.

## 2. Download and install VMware Workstation Pro

VMware Workstation Pro is free, but downloads come from the Broadcom Support Portal:

1. Create a free account at <https://support.broadcom.com> and sign in.
2. Go to **My Downloads**, search for **VMware Workstation Pro**, pick the latest
   release for Windows (26H1 at the time of writing), accept the terms and download.
3. Run the installer with defaults. If it shows a licence key field, leave it blank:
   the free edition needs no key.

## 3. Download the Ubuntu ISO

1. Open <https://releases.ubuntu.com/24.04.5.1/> (also linked from
   <https://releases.ubuntu.com/noble/>).
2. Download `ubuntu-24.04.5.1-desktop-amd64.iso` (about 6 GB) and the `SHA256SUMS` file.
3. Verify the download in PowerShell, from the download folder:

   ```powershell
   Get-FileHash .\ubuntu-24.04.5.1-desktop-amd64.iso -Algorithm SHA256
   ```

   The hash must match the line for that file in `SHA256SUMS`.

## 4. Create the VM

In VMware: **File > New Virtual Machine > Typical**, choose the ISO, then:

| Setting | Value |
| --- | --- |
| Guest OS | Linux, Ubuntu 64-bit |
| Name | `portwatchman-dev` |
| Disk | 60 GB, store as a single file |
| Memory | 8 GB (4 GB minimum) |
| Processors | 4 cores |
| USB controller | USB compatibility **USB 3.1** |

Before the first boot, open **VM > Settings > USB Controller** and make sure
"Show all USB input devices" is **off**, so your host mouse and keyboard are never
passed to the guest (default-deny would block them).

## 5. Install Ubuntu

Boot the VM and choose **Install Ubuntu**. Pick an interactive, default installation,
erase the (virtual) disk, and create your user. Third-party drivers are not needed.
`open-vm-tools-desktop` is installed automatically and gives clipboard sharing and
window resizing.

After the first login, update everything and reboot:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
```

## 6. Check the kernel

```bash
uname -r                       # expect 7.0.0-xx-generic
ls -l /sys/kernel/btf/vmlinux  # must exist (BTF for eBPF)
```

If `uname -r` shows `6.8.x`, the GA kernel is installed instead of HWE. Install the HWE
kernel and reboot:

```bash
sudo apt install -y --install-recommends linux-generic-hwe-24.04
sudo reboot
```

## 7. Install the project tools

```bash
sudo apt update
sudo apt install -y git python3 bpftrace clang llvm build-essential libbpf-dev libelf-dev pkg-config
bpftrace --version     # expect v0.20.x
python3 --version      # 3.10 or later
```

Quick eBPF smoke test (needs root):

```bash
sudo bpftrace -e 'BEGIN { printf("eBPF OK\n"); exit(); }'
```

## 8. Enable BPF-LSM (needed by the BPF-LSM layer)

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not in the list, append it to the kernel command line, keeping the
existing modules in the same order:

```bash
LSMS=$(cat /sys/kernel/security/lsm)
echo "$LSMS"
sudoedit /etc/default/grub
# Change:  GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
# To:      GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=<the list above>,bpf"
sudo update-grub
sudo reboot
cat /sys/kernel/security/lsm   # bpf should now be listed
```

## 9. Check what the response actions rely on

```bash
loginctl list-sessions          # your graphical session should be listed
cat /proc/sys/kernel/sysrq      # any value is fine: root writes to /proc/sysrq-trigger always work
systemctl --version | head -1
```

## 10. Take a snapshot

Shut the VM down and take a snapshot (**VM > Snapshot > Take Snapshot**), for example
`clean-tools-installed`. Take another before every destructive test (deletion,
sanitisation, power actions) so you can roll back in seconds.

## 11. Pass a USB drive through to the VM

- With the VM window focused, plug in the test drive. VMware asks whether to connect it
  to the host or the VM; choose the VM. If it does not ask, use
  **VM > Removable Devices > (your drive) > Connect (Disconnect from Host)**.
- To make VMware always ask, set **Edit > Preferences > USB > "Ask me what to do"**.
- Confirm in the guest: `lsusb` and `lsblk -o NAME,TRAN,SIZE,MOUNTPOINTS`.

Default-deny and the response actions only affect the guest. They cannot block host
devices, lock the Windows session, delete host files, or shut down the laptop.

## 12. Get the code and run the tests

```bash
mkdir -p ~/df/project
cd ~/df/project
git clone <team repository URL> portwatchman
cd portwatchman
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo python3 src/monitor/usb_monitor.py --check
```

All tests should pass (176 at step 7). Work on a feature branch, for example
`git checkout -b feature/configurable-responses`, and merge into `main` through the
team's usual review.
