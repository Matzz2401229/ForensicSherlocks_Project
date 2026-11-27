# Verify protection of selected VM files

This guide verifies the `local_lsm` service mode on Ubuntu. Previous USB-file test
results do not establish correctness of this mode. These checks are supplied for
the operator to run; no new Ubuntu results are claimed here.

## Build and regression checks

Stop any running installed or foreground PortWatchman service. Use its owning
profile to restore saved bus state if it failed. Confirm no controller/monitor is
still running. This guide starts the checkout, not the installed `/opt` snapshot.

```bash
sudo systemctl stop portwatchman
git branch --show-current
pgrep -af 'lsm_controller|bpftrace.*usb_events[.]bt|src/daemon/portwatchman[.]py.*run'
bash src/enforcement/bpf/build.sh
sudo src/enforcement/bpf/build/lsm_controller --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo python3 tests/enforcement/test_bpf_lsm.py --local
sudo python3 tests/enforcement/test_bpf_lsm.py --loopback
```

Expect branch `fix/bpf-lsm`, successful build/preflight, passing unit tests and both
acceptance runs. The `--local` run creates only owned disposable files under
`build/test-tmp` on the VM disk. It checks read/write EACCES, readable controls,
multiple targets, removal, rename/replacement identity semantics, unlink expiry,
clean detachment, the existing-descriptor boundary and socket-owned registration.
The local-files controller must reject USB removal commands without releasing its
targets. Loopback tests preserve coverage of the old controller mode. A physical
USB acceptance run using `--usb '/actual/mount'` can additionally confirm USB mode
still works and local mode rejects files on that drive.

## Prepare a foreground service profile

Keep your test USB disconnected until the service reports ready. Select an
existing validated service profile with the intended managed bus and matching
allowlist. The example below uses a previously prepared test profile; change
`SOURCE_PROFILE` if your profile has another name. Its existing response actions
are replaced with lock-session preview for this verification profile only.

```bash
export SOURCE_PROFILE='logs/step8-service.json'
python3 - <<'PY'
import json
import os
from pathlib import Path
import tempfile

profile = json.loads(Path(os.environ['SOURCE_PROFILE']).read_text())
base = Path('build/test-tmp').resolve()
base.mkdir(parents=True, exist_ok=True)
fixture = Path(tempfile.mkdtemp(prefix='vm-guard-check-', dir=base))
(fixture / 'restricted.txt').write_text('Protected VM fixture\n')
(fixture / 'second.txt').write_text('Second protected VM fixture\n')
(fixture / 'control.txt').write_text('VM CONTROL MUST REMAIN READABLE\n')

outputs = {
    'logs/vm-guard.json': {
        'schema_version': 1,
        'socket_path': '/run/portwatchman/lsm_controller.sock',
        'protected_paths': [str(fixture / 'restricted.txt'), str(fixture / 'second.txt')],
    },
    'logs/vm-guard-responses.json': {
        'schema_version': 1, 'actions': [{'type': 'lock_session'}],
    },
    'logs/vm-guard-fixture.json': {'fixture': str(fixture)},
}
profile.update(lsm=None, local_lsm='logs/vm-guard.json', apply_responses=False,
               responses='logs/vm-guard-responses.json')
outputs['logs/vm-guard-service.json'] = profile
if any(Path(name).exists() for name in outputs):
    raise SystemExit('A verification profile already exists; inspect it rather than overwriting it.')
for name, document in outputs.items():
    with Path(name).open('x') as output:
        output.write(json.dumps(document, indent=2) + '\n')
print('VM fixture:', fixture)
PY

python3 src/daemon/portwatchman.py --config logs/vm-guard-service.json validate
sudo python3 src/daemon/portwatchman.py --config logs/vm-guard-service.json check
```

Validation should report `lsm_scope: "vm-files"`. Preflight must inspect both VM
files without attaching the guard or arming USB buses. Before starting, all three
fixture files must be readable. The existing profile's managed USB bus and state
file are retained, so do not run it alongside that profile or an installed unit.

## Test service readiness and independent protection

Terminal A:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/vm-guard-service.json run
```

Wait for `lsm_local_registered` with `protection_complete: true` and then
`service_ready`. In Terminal B, load the generated fixture path:

```bash
PW_VM_FIXTURE=$(python3 -c 'import json; print(json.load(open("logs/vm-guard-fixture.json"))["fixture"])')
sudo python3 src/daemon/portwatchman.py status
sudo python3 src/enforcement/lsm_client.py STATUS
cat "$PW_VM_FIXTURE/restricted.txt"
cat "$PW_VM_FIXTURE/second.txt"
cat "$PW_VM_FIXTURE/control.txt"
cat /etc/hostname
sudo cat "$PW_VM_FIXTURE/restricted.txt"
sudo python3 src/enforcement/lsm_client.py STATUS
```

Expected: healthy service, `lsm_scope: "vm-files"`, controller mode `local-files`,
two targets with `usb_id: null`, and increasing denied-open counters. Both selected
files must be denied, including the sudo read; the control and hostname must remain
readable. This must work with **no USB connected**. Do not change target contents
or use real sensitive files for these checks.

Reconnect the approved test USB. Check its current sysfs ID with the policy's
`list` command, then read that device's `authorized` value: it should be `1`.
Repeat all VM file reads; protection must remain in place. Unmount the currently
verified USB partition normally, disconnect it and repeat the reads again. VM
targets must retain the same ownership and remain protected. Do not send
PREPARE_REMOVE: local protection has no USB removal lifecycle.

For rejection, stop normally and prepare a copy of the test profile using a
serial-mismatch policy for **both** policy/enforcement stages (the service uses
its single `policy` field for both). Start that profile, wait for ready, then
reconnect the test drive. Expect `authorized: 0`, no USB block device, lock-session
preview, and both VM files still denied. Applied lock responses were already
verified separately; this round can remain in preview.

## Normal stop and cleanup

Press Ctrl+C in Terminal A. Expect `service_stopped`, `ok: true`, zero component
exit codes and `buses_restored: true`. Both protected files must be readable again.
Check enforcement status with the exact `enforcement` profile named in
`logs/vm-guard-service.json`; it must report unarmed with the original bus defaults.
The process check should return no service/controller/monitor processes.

```bash
cat "$PW_VM_FIXTURE/restricted.txt"
cat "$PW_VM_FIXTURE/second.txt"
cat "$PW_VM_FIXTURE/control.txt"
pgrep -af 'lsm_controller|bpftrace.*usb_events[.]bt|src/daemon/portwatchman[.]py.*run'
```

## Failure and configuration checks

- A missing VM file, directory, symlink, USB file or pseudo-filesystem file must
  fail preflight, without service readiness or USB arming. Run these against copies
  of the verification configuration, never by unlinking a real protected file.
- Configure a delete response for one protected file or its parent, or sanitise
  for a protected history/trace file: service `validate` must refuse the overlap.
  Keep legitimate cleanup targets separate. Arbitrary future hard-link aliases or
  filesystem changes are not fully predicted by this configuration check; attempted
  data opens of the enrolled inode are still denied rather than exempted.
- Unit tests cover failed local registration before arming and missing-entry
  failure after readiness. The `--local` acceptance run removes a dummy entry and
  confirms its loss is detected. An optional live test may REMOVE one current
  dummy target through the socket: the owning service must fail, stop its children
  and retain USB default-deny for explicit recovery. Do not do this in a normal
  demonstration. After any such failure, inspect the logs and use:

  ```bash
  sudo python3 src/daemon/portwatchman.py --config logs/vm-guard-service.json restore
  ```

  A failed/stopped controller no longer protects VM files. This mode does not
  promise restrictions that survive controller exit.

## Installed-service verification

After foreground tests pass, follow the updated user manual to stop the installed
unit, rebuild and run `scripts/install_service.py --update-code`. The installer
preserves installed settings, so explicitly set `local_lsm` to a root-owned copy
of `logs/vm-guard.json` and set legacy `lsm` to `null` in
`/etc/portwatchman/service.json`. The fixture's absolute VM paths stay unchanged.
Run installed `validate` and `check` before `systemctl start`.

Repeat the no-USB denial, approved USB reconnect/disconnect and normal stop checks
against `/opt/portwatchman`, checking journal records for `lsm_local_registered`.
Leave boot enablement unchanged until this installed profile has passed. Old
USB-file boot tests are historical evidence for that mode, not proof of this new
local-file configuration.
