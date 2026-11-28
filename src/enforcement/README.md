# USB access control (step 5)

`usb_authorization.py` keeps new USB devices blocked until approved, then authorises
permitted devices: default-deny on managed buses (`arm`/`restore`/`status`), per-device
`authorize`/`revoke` with re-validation, the `enforce` pipeline stage, and `reconcile` for
devices connected before startup.

See the "USB access control" section of the top-level README and
[docs/STEP5-TESTING.md](../../docs/STEP5-TESTING.md) for usage and live testing.

## Supplementary BPF-LSM guard (step 6)

`bpf/lsm_guard.bpf.c` restricts new opens of selected file identities.
`bpf/lsm_controller.c` loads/attaches it and exposes ADD/REMOVE/LIST/STATUS/STOP over
a root-only Unix socket (`bpf/lsm_socket.c`); target resolution and lifetime checks
are in `bpf/lsm_targets.c`. `--local-files` supports selected regular files on
non-USB block-backed VM filesystems, including the guest root filesystem. USB mode
still verifies physical USB ancestry; `--test-loopback` remains an explicit isolated
test mode. Nothing is pinned.

The integrated service uses `local_lsm` with `lsm_local.py` to register absolute VM
file paths before USB arming and readiness, then verifies them independently of USB
events. Missing entries or a changed/degraded controller fail the service, except a
file destroyed by the response stage, which is reported and released. A normal
service stop detaches the controller and releases the restrictions. No USB event
releases VM files, and PREPARE_REMOVE is refused by the local-files controller.
Configuration is in `config/lsm-local.example.json`; see
[VM-file verification](../../docs/VM-FILE-PROTECTION-TESTING.md).

VM-file protection denies new data opens by all processes, including root. It
does not revoke existing data descriptors, protect replacement inodes automatically,
or prevent memory dumping. The service exempts its own response stage (controller
`EXEMPT` command, by PID and process start time, removed when the process exits), so
a delete response can destroy protected files. Select either `local_lsm`
or legacy `lsm`, not both. Neither mode is enabled by the default profile.

Build with `bash src/enforcement/bpf/build.sh` from the repository root. See
[docs/STEP6-TESTING.md](../../docs/STEP6-TESTING.md) for requirements, exact protection
scope, acceptance tests and the socket protocol. Legacy stdin controls remain
available with `--control-stdin` for regression testing.

`lsm_client.py` authenticates the controller, correlates replies and binds requests
to one controller instance. `lsm_bridge.py` optionally connects successful USB
authorisation results to configured files on that USB, using connection IDs for
registration/removal. Enable only with `enforce --lsm-config FILE`; the ordinary
step 5 commands do not enable it. The example config uses `on_error: report`, which
reports registration failure and leaves the USB authorised. `deauthorize` is an
explicit alternative that can interrupt USB I/O. No default runtime config enables
either policy. This is post-authorisation protection with a registration window,
not an atomic gate. Live acceptance remains pending the Ubuntu VM tests.

Before unmounting a drive protected by the running bridge, use the root socket
client's `PREPARE_REMOVE CONNECTION_ID` command and wait for the pipeline's
`lsm_bridge_prepared_for_removal` event. This intentionally releases that connection's
map entries and O_PATH references, which otherwise keep the mount busy. Other
connections remain protected. The bridge waits for disconnect and registers a fresh
connection on reconnect. Protection is released during preparation; cancelled
removal requires disconnect/reconnect to enrol again. See the testing guide for
the complete procedure and evidence recorded so far.
