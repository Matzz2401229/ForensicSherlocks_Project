# Step 8: running service

Status: implementation prepared on the service branch. Only static checks have
been performed while editing on Windows; the new unit tests and all runtime checks
below must be run manually in Ubuntu before marking Step 8 complete.

## Behaviour and scope

`src/daemon/portwatchman.py` supervises the existing monitor → policy → USB
authorisation → responses pipeline. An optional controller is started and attached
before enabling the Step 6 bridge. Component records are forwarded unchanged and
logged as `service_stage_event` records with `stage` and `event` fields. Source
timestamps and correlation checks are preserved.

The service checks component configs/prerequisites, refuses existing arm state or
an already-owned LSM socket, records startup inventory, and arms the selected USB
buses. It launches downstream stages first, then the monitor. `service_ready` and
systemd `READY=1` require healthy monitoring through the full pipeline, not merely
that Python processes exist. With LSM enabled, controller and bridge readiness are
also required. A single runtime lock excludes another service/check/install/restore
operation. Stop standalone pipelines/controllers before using it; manual component
commands do not acquire that lock.

The supported scope is **new USB connections after readiness**. Existing devices
are inventoried and retain their current access. Startup does not automatically
reconcile/revoke them or enrol their files in LSM. Start the prototype with the test
USB disconnected, then reconnect after readiness. Boot enablement cannot establish
that access before service startup was prevented. Automatic startup reconciliation
and broader recovery remain later work.

`run` applies USB authorisation and default-deny. **Response actions stay a preview**
unless `apply_responses: true` is configured or foreground `run --apply-responses`
is selected. The default response plan is lock-only. LSM is disabled when `lsm` is
null. Relative configuration paths resolve from the code root, matching component
path conventions, not the current shell directory.

On a normal stop, the supervisor stops the monitor, lets EOF drain downstream, keeps
the controller alive while the bridge releases targets, then stops the controller
and restores saved bus defaults. Timeouts/failed actions are reported as failures;
cleanup is not silently called successful. It adopts orphaned descendants so a
crashed monitor's bpftrace child can be terminated/reaped. The systemd unit also
retains all descendants in its control group.

Unexpected component exit, malformed output or reported degradation fails the
service, stops its remaining processes and **retains default-deny and saved state**
for operator recovery. Already-authorised devices retain access; selected-file
restrictions end when their controller exits. This is not a guarantee of fail-closed
access for every device or previously opened file.

After startup, supervision detects process exits and reported errors. An independent
end-to-end progress watchdog for a frozen policy/enforcement/response process is not
implemented; broader hang detection belongs to Step 9. Runtime `healthy` reflects
the established pipeline state and failures the supervisor has observed.

The service saves a companion ownership record for its arm state. Recovery refuses
foreign/manual state and state from a different boot. If a forced reboot leaves
old state, inspect the bus mapping and saved state before recovery; do not delete
state files to bypass the refusal. Saved originals may differ from `1`.

## Known response limitation

The Step 7 slow-action fix was deliberately excluded. That component still runs
actions synchronously and checks input age when it later reads records. A slow
deletion can make legitimate queued closing/events exceed its two-second limit,
leading to rejected events, a failed closing result, or a missed subsequent response
(subject also to cooldown). The service does not bypass that check or conceal the
failure, and automatic restart is disabled. Use small owned fixtures for the
demonstration and retain this limitation in the report. USB default-deny is a
separate mechanism. Larger-workload results have not been established.

## 1. Pull and unit checks

Review/commit/push host changes first. On Ubuntu, inspect `git status`, handle any
local edits, then fetch/switch/pull the intended branch with `--ff-only`.

```bash
cd '/path/to/portwatchman'
python3 -m unittest discover -s tests -p 'test_service.py' -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The tree declares 300 tests, including 49 new service cases; these are counts,
not passing results. The new service cases use fake children/commands and owned temporary files. Native
Step 6 tests require the existing Linux controller build. No real service, USB write,
screen lock or power command is started by the service unit cases.

## 2. Prepare a local profile

Use [shared setup](TESTING-SETUP.md) to identify the actual test flash drive and
generate `logs/test-allow.json` and `logs/test-enforcement.json`. Restore any earlier
test arm state first. Start each terminal from the repository root. Keep the VMware
console available; newly attached peripherals on a managed bus also start denied.

```bash
mkdir -p logs
cat > logs/test-service.json <<'JSON'
{
  "schema_version": 1,
  "policy": "logs/test-allow.json",
  "enforcement": "logs/test-enforcement.json",
  "responses": "config/responses.json",
  "lsm": null,
  "apply_responses": false,
  "startup_timeout": 90,
  "shutdown_timeout": 30,
  "command_timeout": 60
}
JSON

python3 src/daemon/portwatchman.py --config logs/test-service.json validate
sudo python3 src/daemon/portwatchman.py --config logs/test-service.json check
```

Validation only displays the plan. Check starts one-shot prerequisite commands;
it does not arm buses or start persistent enforcement. Confirm policy paths match
between both stages and responses are a preview. Unmount the actual USB partition
successfully, then disconnect it before the next round.

## 3. Foreground smoke test

Terminal A:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/test-service.json run
```

Wait for `service_ready`. In Terminal B:

```bash
sudo python3 src/daemon/portwatchman.py status
```

Expect `running: true`, `healthy: true`, phase `running`, and all four child PIDs.
Reconnect the test USB. The matching policy should authorise it with zero response
triggers. Verify actual `authorized` and `lsblk` as in [Step 5](STEP5-TESTING.md).

Press Ctrl+C in Terminal A. Expect `service_stopped` with `ok: true` and
`buses_restored: true`. Status then returns nonzero with running/healthy false.
Check the owning enforcement config's status and that no project controller,
monitor or bpftrace process remains. Before disconnecting a mounted drive, unmount.

For rejection, change **only** the local profile's policy to
`logs/test-mismatch.json`, validate again, and repeat with the USB initially
disconnected. It should remain blocked and preview a single lock. After that passes,
foreground `run --apply-responses` enables the lock-only plan; confirm a visible
lock, then normal cleanup. No repository policy is changed by these local profiles.

## 4. LSM integration

Prepare the native build and a disposable selected file using [Step 6](STEP6-TESTING.md).
Create `logs/test-lsm.json` using the actual allowlist rule name and relative test
path. Set the local service profile's `lsm` to `logs/test-lsm.json` and use the
matching policy. **Do not start another controller manually.** The service owns it.

Repeat the approval/rejection checks. Expect bridge registration and denied opens
only for the configured selected file on an approved drive, readable controls,
and no response for approval. On rejection, expect no target registration and the
configured response. Stop the foreground service normally before unmounting; its
bridge release should remove held references. For removal/reconnect while running,
use Step 6's `PREPARE_REMOVE` sequence with the current connection ID.

LSM registration still waits for a mount. The service does not mount filesystems.
Desktop automount or an explicit operator mount must occur within the configured
registration deadline. Unattended boot without a mounted volume is not a verified
LSM deployment scenario.

## 5. Install and test systemd

After foreground tests pass, stop it and restore any state. Installation copies a
reviewed runtime snapshot into `/opt/portwatchman`, configs into `/etc/portwatchman`,
and uses `/var/lib/portwatchman/enforcement-state.json`. It excludes tests, logs,
temporary USB fixtures and the discarded slow-action patch. Existing unmanaged
installation paths/unit files are refused. Installation is not a running checkout:
later Git pulls do not change installed code.

```bash
sudo python3 scripts/install_service.py --config logs/test-service.json
sudo systemd-analyze verify /etc/systemd/system/portwatchman.service
sudo systemctl start portwatchman
sudo systemctl status portwatchman --no-pager
sudo journalctl -u portwatchman -n 60 --no-pager -o cat
```

The installer reloads unit definitions but does not start/enable the unit. Start
waits for actual pipeline readiness. Repeat the same USB checks. Applied responses
require `apply_responses: true` in **installed** `/etc/portwatchman/service.json`;
stop the unit before editing it with `sudoedit`, then start it again. Validate
installed configuration with:

```bash
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py --config /etc/portwatchman/service.json validate
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py status
sudo systemctl stop portwatchman
sudo journalctl -u portwatchman -n 60 --no-pager -o cat
```

Expect all stages to exit, targets released and saved bus defaults restored. A
failure must be visible in both logs and the unit exit result. `KillMode=mixed`
lets the supervisor order shutdown before systemd's final process-group cleanup;
automatic restart is deliberately disabled. Long active actions can delay draining
or hit the shutdown deadline; that is reported, not considered clean success.

Only after manual checks pass, optional boot enablement is:

```bash
sudo systemctl enable portwatchman
# To remove automatic startup later:
sudo systemctl disable portwatchman
```

Do not enable an applied destructive profile for the first boot test. Confirm the
current USB topology/configuration first; bus numbers and mounted paths can change.

## Failure recovery and code updates

For a failed stopped foreground instance, use its original local profile:

```bash
sudo python3 src/daemon/portwatchman.py --config logs/test-service.json restore
```

For the installed unit, first stop it, inspect logs, then restore using its installed
profile (not the checkout's different state file):

```bash
sudo systemctl stop portwatchman
sudo python3 /opt/portwatchman/src/daemon/portwatchman.py --config /etc/portwatchman/service.json restore
```

A different-boot/foreign-state refusal requires inspection, not deletion of the
ownership/state files or blind re-arming. After a normal stop, updating code from a
reviewed clone preserves installed configs:

```bash
sudo python3 scripts/install_service.py --update-code
sudo systemctl start portwatchman
```

Rebuild the native controller in the Ubuntu clone before updating if its source or
kernel changed. Config changes are explicit; the installer does not replace an
existing installed profile during a code update. Policy edits do not automatically
revoke existing devices or re-enrol already processed connections.

## Acceptance checklist

- [ ] New service unit cases and combined suite pass in Ubuntu.
- [ ] Foreground readiness, allow/reject, preview/applied lock and cleanup pass.
- [ ] Optional controller/bridge is managed and released correctly.
- [ ] Concurrent service ownership is refused; no leftover descendants remain.
- [ ] Installed snapshot starts, reports readiness/status and logs through systemd.
- [ ] Normal `systemctl stop` releases targets and restores original defaults.
- [ ] Unexpected child failure is reported and saved deny state can be recovered.
- [ ] Optional boot enablement is separately verified for the chosen profile.

Step 9 covers broader recovery/edge cases; whole-system evaluation remains later
work. Service supervision does not establish forensic erasure or eliminate the
documented component limitations.

## Implementation references

The unit/readiness and cleanup design follows the primary documentation for
[systemd service readiness](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html),
[mixed kill mode](https://www.freedesktop.org/software/systemd/man/255/systemd.kill.html),
[Python subprocess sessions](https://docs.python.org/3.12/library/subprocess.html),
and [Linux child subreapers](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html).
