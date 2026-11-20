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
are in `bpf/lsm_targets.c`. USB mode verifies physical
USB ancestry; `--test-loopback` is an explicit isolated test mode. Nothing is pinned.

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
