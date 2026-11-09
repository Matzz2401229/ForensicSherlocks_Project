# USB access control (step 5)

`usb_authorization.py` keeps new USB devices blocked until approved, then authorises
permitted devices: default-deny on managed buses (`arm`/`restore`/`status`), per-device
`authorize`/`revoke` with re-validation, the `enforce` pipeline stage, and `reconcile` for
devices connected before startup.

See the "USB access control" section of the top-level README and
[docs/STEP5-TESTING.md](../../docs/STEP5-TESTING.md) for usage and live testing.
