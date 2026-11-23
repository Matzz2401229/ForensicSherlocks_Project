# Step 7: configurable responses

Status: Step 7 component verification completed in the recorded Ubuntu 24.04
VMware environment with kernel `7.0.0-38-generic`. The operator ran all **251 unit
tests** successfully and performed the manual checks summarised below. These are
recorded results for that environment; another environment must repeat verification.

## Recorded verification

| Check | Recorded result |
| --- | --- |
| Combined unit suite | 251 tests, `OK`; includes containment, freshness/context, duplicate and failure/interrupt regressions. |
| Manual lock | Dry-run preview passed; applied action visibly locked the desktop. |
| USB rejection | Serial mismatch kept the device unauthorised and absent from block-device inventory; preview did not lock, applied response visibly locked once. |
| USB approval | Device authorised while the bus default remained deny; applied response stage closed with zero responses and no errors. |
| Step 6/7 approval integration | Selected-file registration completed; opening the target was denied, controls stayed readable and the denial counter increased. No response was triggered. Stopping the pipeline released the target. |
| Step 6/7 rejection integration | USB stayed blocked, one lock occurred, and the controller retained no targets and zero failures. |
| Cleanup | Pipelines stopped, controller/backend processes exited and original bus defaults were restored. |
| Isolated deletion | Two files/two directories removed with one overwrite pass; control unchanged; no errors or retained directory. |
| Isolated sanitisation | Nine selected trace files removed; three controls unchanged; no retained directory. Separate cache-only action reported `drop_caches: done`. |
| Graceful poweroff | Poweroff-only manual action succeeded; guest fully powered off and was started manually in VMware. Boot ID changed and the running kernel stayed unchanged. |

USB-triggered locking was tested end to end. Deletion, sanitisation/cache dropping
and graceful poweroff were exercised separately through `run-action`; an applied
USB-triggered sequence combining every action was not manually tested. Reboot,
force and immediate/SysRq power modes retain unit coverage only. Filesystem checks
establish logical removal and selection boundaries, not forensic unrecoverability
or RAM erasure. Overall service integration and evaluation remain later milestones.

## Scope and prerequisites

The response stage consumes **live enforcement output**, not saved JSON logs.
It supports configured session-lock requests, best-effort file overwrite/removal,
selected trace cleanup and poweroff/reboot requests. Responses are dry runs unless
their own command includes `--apply`; real responses also require Linux/root.
USB enforcement still writes by default unless `enforce --dry-run` is selected.

Use [shared testing setup](TESTING-SETUP.md) to select your own USB and generate
`logs/test-allow.json`, `logs/test-mismatch.json` and `logs/test-enforcement.json`.
No particular username, device ID, serial number or feature-branch name is assumed.
Start every terminal in your actual repository root. Do not run power/deletion tests
on a production system or against real evidence. Use disposable data and a VM snapshot
before explicitly applying a destructive response. A VM shutdown controls the guest;
USB/shared storage contents are real data, and snapshots may preserve earlier copies.

The completed Step 6 implementation is retained. Its bridge is optional and can
run upstream of responses; its events are forwarded so guard state remains visible.
See [Step 6](STEP6-TESTING.md) for its selected-file scope and safe removal procedure.

## Actions and configuration

The default `config/responses.json` contains only `lock_session`. The all-actions
example is illustrative; create/review a local configuration before using it.
Machine-specific `config/*.local.json` and files under `logs/` are ignored by Git.

| Action | Behaviour |
| --- | --- |
| `lock_session` | Requests locking through `loginctl lock-sessions`; verify the visible lock screen in the desktop session. |
| `delete` | Captures selected entries privately, overwrites/truncates eligible regular files and unlinks them; removes links without following them. |
| `sanitise` | Applies the same rules to selected history/recent-file/thumbnail/trash paths and optionally drops clean kernel caches. |
| `power` | Requests poweroff/reboot through systemctl, force mode or SysRq; must be the final action. |

Configuration uses `schema_version: 1`, ordered `actions`, `cooldown_seconds` and
optional `allowed_roots`. Each action type may appear once. `passes` is 1–7.
`delete.paths` must be strictly below an approved root. Roots/parent components
must not use symlink aliases. Nested/bind mounts and multiply linked regular files
are refused; final symlinks are removed without following their destinations.

Live deletion holds directory/file references and performs operations relative to
them. Targets are captured in a private `.portwatchman-delete-*` directory under
the approved root before mutation. If deletion is incomplete, `retained_paths`
identifies the recovery directory; original names may already have moved there.
Inspect failures and retained entries before retrying. Remaining configured actions,
including a final power request, still run after a reported filesystem failure.

This is best-effort removal, not guaranteed forensic erasure. Copies in journals,
snapshots, backups, SSD layers, swap or applications can remain. Do not use the tool
as a guarantee against concurrent changes by processes retaining access to the data.
Existing hard links are refused and link counts are rechecked during overwriting;
this does not create an atomic filesystem-wide barrier against new link creation.
Applied deletion requires a root-owned private directory with mode 0700 under the
approved root. Filesystems/mounts that cannot provide those permissions (including
many exFAT/FAT USB mounts) are refused; use a disposable Linux filesystem fixture.
`drop_caches` releases clean cached objects and does not sanitise RAM.

## Live stream contract

The updated enforcer stamps output with `boot_id`, `enforcement_instance_id`,
`enforcement_apply`, `clock: monotonic` and `emitted_timestamp_ns`. Its start record
binds the response watcher to that producer. Monitor records establish the current
session. Block triggers need matching USB/connection/session identity and must be
no more than two seconds old. Stale logs, incomplete records, wrong sessions/boots,
post-close records and producer changes are rejected visibly. Restart the watcher
with a new producer; repeating a header does not reset failure/deduplication state.
This is a freshness/correlation check, not authentication or a durable replay ledger.
A newly started watcher can accept a recent copied stream within the freshness
window. Use the direct local pipeline and do not feed untrusted JSON to live responses.

Each accepted connection is handled at most once within a bounded recent cache.
The global cooldown also suppresses rapid *new* connections. Duplicate connection
records do not retry a failed action after cooldown; use a new connection or the
explicit manual trigger command. Live responses refuse upstream dry-run enforcement.
Dry-run responses can preview a live stream without executing actions.

`trigger.include_skipped` defaults to false. When enabled, it permits only fresh,
correlated removal/change skips whose policy already identified an unapproved
device. Stale, uncorrelated, unmanaged-bus and invalid-policy skips do not trigger
destructive responses. Degraded monitoring, enforcement failures and bridge errors
remain latched in the final outcome, including after Ctrl+C.

## 1. Unit tests — run manually in Ubuntu first

```bash
cd '/path/to/portwatchman'
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expect `OK`; keep the complete failure output if it is not. Native Step 6 checks
require its built controller. Response tests use owned temporary directories and
fake command/proc interfaces. They include link/path-swap containment, mount
rejection, retained failures, action continuation, producer/consumer agreement,
replay/freshness/context rejection and upstream failure followed by Ctrl+C.
Linux-specific response tests skip on Windows; importing the module no longer
requires the Unix-only `os.sync` attribute to exist.

Do not proceed to applied response tests until the unit results have been reviewed.

## 2. Validate and preview

```bash
python3 src/responses/responses.py validate
python3 src/responses/responses.py trigger
```

The default previews a lock request. `trigger` is an intentional manual test and
does not require a fabricated enforcement record. `run-action ACTION` previews one
configured action. Neither executes responses without `--apply`.

## 3. Isolated deletion demonstration

Create a unique disposable local directory and configuration. This writes only new
test data and ignored local config; it performs no response action:

```bash
mkdir -p logs
python3 - <<'PY'
import json
from pathlib import Path
import tempfile

base = Path("build/test-tmp").resolve()
base.mkdir(parents=True, exist_ok=True)
owned = Path(tempfile.mkdtemp(prefix="response-demo-", dir=base))
target = owned / "sensitive"
target.mkdir()
(target / "marker.txt").write_text("DISPOSABLE-PORTWATCHMAN-MARKER\n")
document = {"schema_version": 1, "allowed_roots": [str(owned)],
            "actions": [{"type": "delete", "paths": [str(target)], "passes": 1}]}
Path("logs/delete-demo.json").write_text(json.dumps(document, indent=2) + "\n")
print("Owned fixture:", owned)
PY
python3 src/responses/responses.py --config logs/delete-demo.json validate
python3 src/responses/responses.py --config logs/delete-demo.json run-action delete
```

Review `would_delete` and confirm every path belongs to this newly created fixture.
Only after review, apply the *delete-only* demonstration:

```bash
sudo python3 src/responses/responses.py --config logs/delete-demo.json run-action delete --apply
```

Expect successful deletion counters and no errors/retained paths. This demonstrates
logical overwrite/removal, not unrecoverability. Any raw-block comparison requires
a separately owned disposable filesystem/image, verified mount ownership and an
explicit config for that fixture. Do not reuse fixed image paths or assume that an
absent plaintext marker proves erasure across host storage or snapshots.

For sanitisation, create fake home/history/thumbnail/trash paths inside an owned
fixture and select only those paths. Do not use a real home directory for the first
applied test. Prefer unit-test evidence until that separate fixture is reviewed.

## 4. Live pipeline — responses remain a dry run initially

Start with the test drive safely unmounted/disconnected and arm only the selected
bus using the shared test config. Stop unrelated response/bridge processes first.

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json arm --apply
set -o pipefail
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy logs/test-mismatch.json watch |
  sudo python3 src/enforcement/usb_authorization.py \
    --config logs/test-enforcement.json --policy logs/test-mismatch.json enforce |
  python3 src/responses/responses.py watch
```

Reconnect after healthy monitoring. The mismatch policy should keep the device
blocked and the response stage should report a dry-run lock plan. Use the matching
policy on both upstream stages for a separate approval run: it should produce no
response plan. Keep both policy arguments identical in each run.

After the dry-run results pass, `sudo python3 src/responses/responses.py watch --apply`
as the final stage enables the default lock-only action. A zero loginctl exit means
the request was accepted; verify the desktop lock screen itself. Unlock through
the VM console and check action/closing records.

For Step 6 integration, start its native controller first and use its local test
LSM config with `enforce --lsm-config logs/test-lsm.json`. That config must reference
an existing policy rule. Approved USB connections should register protected files
without triggering responses; rejected connections should remain blocked and
trigger only the configured response. Step 6 events should remain visible at the
end of the pipeline. Prepare removal through its socket before unmounting protected
filesystems. A response delete aimed at an LSM-protected file may be denied; report
and retain that failure instead of claiming erasure or bypassing the guard.

Ctrl+C ends the pipeline. Normal startup/stopping statuses are not failures, but
known upstream degradation or action failures must produce `ok: false` even after
the deliberate stop. Interrupting an action also reports failure; inspect partial
effects and any `.portwatchman-delete-*` directories before retrying. Restore with
the same config that saved the original defaults:

```bash
sudo python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json restore --apply
python3 src/enforcement/usb_authorization.py --config logs/test-enforcement.json status
pgrep -af 'bpftrace.*usb_events[.]bt'
```

## 5. Power responses — separate, explicit VM test

Review a dedicated power-only local config and preview `run-action power` first.
Applying it requires `--apply` and root and can shut down/reboot the guest immediately.
Use a snapshot and a console recovery path. Do not combine power with unreviewed
deletion/sanitisation paths for an initial live test. Command acceptance is not
proof of completed shutdown; record the observed VM behaviour and latency.

The recorded graceful-poweroff run waited for an unattended upgrade during
shutdown. Allow such updates to finish. The approximately 59 ms action duration
measured the command call, not the time until the guest powered off. After the
guest fully powered off, manual startup and a different boot ID confirmed a new
boot session. Use observed power state as evidence; a successful command alone
does not establish completed or immediate shutdown.

## Completion evidence

The recorded VM run satisfies the following component checks; rerun them for a
different environment or relevant source change.

- [x] Combined Step 6/7 unit suite passes on the target VM (251 tests).
- [x] Dry-run/live lock, allow and rejection paths produce the expected records.
- [x] Freshness/context rejection, duplicate suppression and failure/interrupt regressions pass in the unit suite.
- [x] Deletion and sanitisation pass their isolated-fixture tests; cache dropping succeeds separately.
- [x] Configured `poweroff` / `graceful` mode is manually observed in an isolated VM.
- [x] Step 6 integration and original bus defaults remain correct after cleanup.

Do not mark Step 7 complete based on source review or a declared test count alone.
Service installation, durable logs, worker supervision and full-system evaluation
remain later milestones.
