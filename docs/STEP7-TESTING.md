# Step 7: Configurable responses (lock, delete, sanitise, power)

`src/responses/responses.py` is the fourth pipeline stage. It reads the enforcement
stage's NDJSON and, when a device is blocked, runs the ordered actions in a responses
config:

| Action | What it does |
| --- | --- |
| `lock_session` | `loginctl lock-sessions`: locks every graphical session (GNOME, X11 or Wayland) |
| `delete` | Overwrites each regular file with random data (`passes` times, fsync after each), truncates it, renames it to a random name, unlinks it, then removes the directories |
| `sanitise` | The same secure delete for common activity traces in listed home directories, plus `drop_caches` |
| `power` | `poweroff` or `reboot`, by `graceful` (`systemctl`), `force` (`systemctl --force`) or `immediate` (`sync`, then `/proc/sysrq-trigger`) |

Sanitise items:

| Item | Removes (relative to each home directory) |
| --- | --- |
| `recent_files` | `.local/share/recently-used.xbel` (GNOME "Recent" list) |
| `thumbnails` | `.cache/thumbnails/` (previews of opened images and documents) |
| `shell_history` | `.bash_history`, `.zsh_history`, `.python_history`, `.lesshst`, `.viminfo` |
| `trash` | `.local/share/Trash/` |
| `drop_caches` | Runs `sync`, then writes `3` to `/proc/sys/vm/drop_caches` (system-wide) |

> **Safety.** Every command is a **dry run** unless you add `--apply`, and `--apply`
> needs `sudo`. A dry run reports what would be locked, every file that would be
> deleted, and the exact power command. Everything happens inside the Ubuntu VM only.
> **Take a VM snapshot before any `--apply` test of `delete`, `sanitise` or `power`.**

## Configuration

`config/responses.json` (the default) only locks the session:

```json
{
  "schema_version": 1,
  "trigger": { "include_skipped": false },
  "cooldown_seconds": 30,
  "allowed_roots": [],
  "actions": [ { "type": "lock_session" } ]
}
```

`config/responses.example.json` shows every action. Copy it to a local file and change
`/home/student` to your own home directory:

```bash
cp config/responses.example.json config/responses.local.json
sed -i "s#/home/student#$HOME#g" config/responses.local.json
python3 src/responses/responses.py --config config/responses.local.json validate
```

`config/*.local.json` is ignored by Git, so personal paths are never committed.

Rules enforced when the config loads:

- `actions` run in the order listed. Each type may appear once, and `power` must be last.
- `delete.paths` must lie strictly inside an `allowed_roots` entry. Roots must be
  absolute, at least two levels deep (`/home/you`, not `/home`), and outside system trees
  (`/etc`, `/usr`, `/var`, `/boot`, `/proc`, `/sys`, `/dev`, `/run` and similar).
- Paths are checked again, with symlinks resolved, just before deletion. A symlink is
  removed as a link and never followed, so a link cannot redirect deletion elsewhere.
- `passes` is 1 to 7 (default 1).
- `cooldown_seconds` (default 30): after the plan runs, further blocked devices within
  this window are reported as `response_suppressed` instead of re-running it. Once a
  power action has been issued, every later trigger is suppressed.
- `trigger.include_skipped`: also respond to `enforcement_skipped` records whose policy
  decision was `block` (for example a stale decision, or a device removed while it was
  being processed). Off by default.

## Unit tests

```bash
cd ~/df/project/portwatchman
git pull --ff-only
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expect `OK` (176 tests; 46 are in `tests/test_responses.py`). They use temporary
directories, a fake `/proc` and a fake command runner, so they need no root, run no
commands, and never lock, delete outside the fixture, or power off. On Windows the
response tests are skipped, because the actions only exist on Linux.

## Dry runs (safe)

```bash
python3 src/responses/responses.py validate
python3 src/responses/responses.py --config config/responses.local.json trigger
python3 src/responses/responses.py --config config/responses.local.json run-action delete
```

`trigger` runs the whole plan once as if a device had been blocked. `run-action`
runs just one configured action. Without `--apply` the output lists `would_run`,
`would_delete` and `would_issue`.

## Live test 1: session lock

```bash
sudo python3 src/responses/responses.py run-action lock_session --apply
```

Expected: the GNOME lock screen appears immediately. Log back in and check the output:
`"action":"lock_session","status":"ok"`.

## Live test 2: secure delete versus `rm` (quantitative)

This uses a small throwaway ext4 image so you can scan the raw blocks for leftover data.

```bash
truncate -s 64M ~/pw-demo.img
mkfs.ext4 -q ~/pw-demo.img
mkdir -p ~/portwatchman-demo
sudo mount -o loop ~/pw-demo.img ~/portwatchman-demo
sudo chown "$USER": ~/portwatchman-demo
mkdir -p ~/portwatchman-demo/sensitive
for i in $(seq 1 200); do echo "PW-SECURE-MARKER-$i"; done > ~/portwatchman-demo/sensitive/secure.txt
for i in $(seq 1 200); do echo "PW-RM-MARKER-$i"; done > ~/portwatchman-demo/plain.txt
sync
```

Delete one file with `rm` and the other with the response action, then scan the image:

```bash
rm ~/portwatchman-demo/plain.txt
sudo python3 src/responses/responses.py --config config/responses.local.json run-action delete --apply
sync && sudo umount ~/portwatchman-demo
grep -a -c PW-RM-MARKER ~/pw-demo.img       # expect > 0: rm leaves the data in free blocks
grep -a -c PW-SECURE-MARKER ~/pw-demo.img   # expect 0: the blocks were overwritten
```

Record both counts for the evaluation. Clean up with `rm ~/pw-demo.img`.

`--apply` output includes `files`, `dirs`, `bytes`, `duration_ns` and any `errors`, so
the same run gives deletion time versus data size. Repeat with larger files (for example
`head -c 100M /dev/urandom > ~/portwatchman-demo/sensitive/big.bin`, after enlarging the
image) and with `passes` 1 and 3 to plot time against size.

## Live test 3: sanitisation

```bash
echo "secret-command" >> ~/.bash_history
ls ~/.local/share/recently-used.xbel ~/.cache/thumbnails 2>/dev/null
sudo python3 src/responses/responses.py --config config/responses.local.json run-action sanitise
sudo python3 src/responses/responses.py --config config/responses.local.json run-action sanitise --apply
ls -la ~/.bash_history ~/.local/share/recently-used.xbel ~/.cache/thumbnails
```

Expected: the files are gone and `"drop_caches":"done"`. Note that an open bash shell
keeps its history in memory and writes it back when it exits, so close other terminals
first (or run `history -c` in them) when demonstrating this.

## Live test 4: full pipeline

Use the default lock-only config first, with default-deny armed (see step 5):

```bash
sudo python3 src/enforcement/usb_authorization.py arm --apply
sudo -v
sudo python3 src/monitor/usb_monitor.py |
  python3 src/policy/device_policy.py --policy config/allowlist.example.json watch |
  sudo python3 src/enforcement/usb_authorization.py --policy config/allowlist.example.json enforce |
  sudo python3 src/responses/responses.py watch --apply
```

Wait for `response_monitor_status` with `healthy: true`, then:

1. Connect an **allowlisted** drive: no response records; it is authorised upstream.
2. Connect an **unlisted** drive: `response_triggered`, then `response_action` for
   `lock_session`, then `response_completed`. The screen locks.
3. Reconnect the unlisted drive within 30 s: `response_suppressed` with `cooldown`.

Press Ctrl+C. The last record is `response_stream_closed`; `ok` is true after a
deliberate stop with no failed actions. Restore default-deny when finished:

```bash
sudo python3 src/enforcement/usb_authorization.py restore --apply
```

To save the records for the report, add `| tee logs/responses.jsonl` at the end.

## Live test 5: power actions (snapshot first)

```bash
sudo python3 src/responses/responses.py --config config/responses.local.json run-action power
sudo python3 src/responses/responses.py --config config/responses.local.json run-action power --apply
```

Try each `method` in turn by editing the local config:

| Method | Expected in the VM | Trade-off |
| --- | --- | --- |
| `graceful` | Normal shutdown, services stopped in order | Slowest; a login session or service can delay it |
| `force` | Shutdown within a few seconds, file systems unmounted | Services are killed, not stopped cleanly |
| `immediate` | Instant power-off after `sync` | Like pulling the plug; unsaved data is lost |

For the full end-to-end demonstration, run live test 4 with
`config/responses.local.json` and connect an unlisted drive: lock, delete, sanitise and
power-off run in order. The `power` record with `"status":"issuing"` is written before
the command runs, so it is in the log even if nothing after it is.

## Output records

| Record | Meaning |
| --- | --- |
| `response_started` | Stage started; shows `apply`, the actions and roots |
| `response_monitor_status` | Upstream monitor health changed |
| `response_triggered` | A blocked device started the plan; includes `usb_id`, `connection_id`, `trigger_reason`, `upstream_enforcement_latency_ns` |
| `response_action` | One action finished: `status`, `ok`, `duration_ns`, `since_trigger_ns`, `detail` |
| `response_completed` | The plan finished: `ok`, `failed_actions`, `total_ns` |
| `response_suppressed` | A trigger was ignored: `cooldown` or `power_action_issued` |
| `response_input_error` | A line was not valid enforcement JSON |
| `response_stream_closed` | Stage ended: `reason`, `ok`, `responses`, `failures` |

Exit status is 0 only for a deliberate or clean upstream stop with no failed actions and
no bad input, 1 otherwise, and 2 for a config or usage error.

## Limitations (for the report)

- Overwriting in place removes data from the blocks the file occupies **now**. It does
  not reach older copies: ext4 with `data=journal`, copy-on-write file systems (btrfs,
  ZFS), SSD wear levelling and TRIM, swap, backups, cloud sync, VMware snapshots, or the
  `.vmdk` on the Windows host. Ubuntu's default ext4 (`data=ordered`) on a virtual disk
  overwrites in place, which is what live test 2 measures.
- `drop_caches` only drops clean cached pages; it does not wipe RAM. Powering off is what
  clears volatile memory, and even then data can briefly survive (cold-boot remanence).
- Locking the session protects the screen, not memory: a locked machine can still be
  imaged by someone with physical or hypervisor access.
- `sanitise` covers the listed traces only. Application-specific traces (browser history,
  editor caches, systemd journal entries) are not removed.
- A response is only as fast as the pipeline before it; `upstream_enforcement_latency_ns`
  and `since_trigger_ns` let you measure each part.
