# Step 9: focused final verification

Status: the agreed reduced verification round is complete for the recorded Ubuntu
VM setup. This records targeted checks and reuses Step 8 recovery evidence; it is
not exhaustive reliability, performance or security evaluation.

## Scope and environment

Results were supplied by the operator on 24 November 2026 from Ubuntu 24.04 under
VMware. Step 9 live checks ran on kernel `7.0.0-43-generic`, using the installed
runtime under `/opt/portwatchman` and private configuration under
`/etc/portwatchman`. Responses were in preview mode and the selected-file LSM bridge
was enabled. The test drive was disconnected during startup-failure checks and
connected only after readiness for registration/removal checks.

The existing 300-test Ubuntu pass, including 49 service cases, was reused; no new
unit tests or runtime code were added for this round and no new full-suite result
was reported on the updated kernel. See [Step 8](STEP8-TESTING.md#recorded-verification)
for installation, boot startup, monitor-crash handling and manual recovery.

## Recorded results

| Check | Evidence | Result |
|---|---|---|
| Duplicate instance | Second installed `run` exited 1 with `Another PortWatchman service operation already owns the lock`; original main and child PIDs unchanged, healthy, bus default still 0 | Passed |
| Duplicate-test cleanup | Normal stop: systemd success, main exit 0, armed false, original default restored to 1, no matching component processes | Passed |
| Invalid configuration | Separate copied profile set `apply_responses` to a string; `run` exited 1 with `apply_responses must be true or false` | Passed |
| Invalid-startup side effects | Unit remained inactive, bus unarmed at original default 1, no matching processes; original installed profile still validated with responses preview and LSM enabled | Passed |
| First USB connection | One target, file denial observed, control readable, denied-open count 1 and controller failures 0 | Passed |
| Three registration/removal cycles | Three distinct connection IDs; each PREPARE_REMOVE removed exactly one target; successful unmounts; subsequent snapshots had no active targets and failures 0 | Passed for registration/removal |
| Service continuity | Same main and child PIDs remained healthy through the three recorded cycles | Passed |
| Final cleanup | Further reconnect followed by successful service stop, main exit 0, restricted file readable, original default restored to 1, armed false and no matching processes | Passed |

The connection IDs shared the same boot/device prefix and had distinct final
timestamp components: `1838567183263`, `2040489354552`, and `2114467240190`.
These are evidence identifiers, not values to reuse for another test. In that
round the denied-open counter remained at 1: later registrations were removed
without repeating the restricted/control file reads. A final reconnect occurred
before shutdown, but no pre-stop registration snapshot was supplied for it.
Accordingly, this record does not claim that file denial was retested on every
connection. Only the first cycle's status was shown being saved to a local file;
the remaining cycle evidence was supplied as terminal output.

`prepared_connections` retained the three intentional-removal markers while
`targets` was empty. These markers are separate from active targets; the native
controller keeps a bounded recent-marker array. This short run does not establish
long-duration memory usage or behaviour after that capacity is exceeded.

## Repeating the focused checks

Use [shared setup](TESTING-SETUP.md) to discover the current device, USB bus,
partition and mount point. Use an owned disposable restricted file and readable
control as described in [Step 6](STEP6-TESTING.md). Do not reuse another person's
USB IDs, serials, mount paths, target IDs or connection IDs.

1. With the USB disconnected, start the installed service and capture healthy
   status. Attempt a second installed `run` with the same profile under a short
   timeout. Expect exit 1 and the ownership-lock error, not a timeout. Verify the
   original PID set and health, then stop normally and inspect restored state.
2. With the unit stopped, copy its service profile to an ignored local test file.
   Set only `apply_responses` to an invalid string and run using that copy. Expect
   exit 1 with the configuration error, no component start and no bus changes.
   Validate the original installed profile again. Do not edit installed settings
   for this negative test.
3. Start the valid service with the USB disconnected. Connect after readiness and
   wait for registration. Capture status, check that the selected file is denied
   and the control readable, and capture the increased counter. For each removal,
   read the current connection ID from healthy controller status, issue
   PREPARE_REMOVE for that ID, successfully unmount the verified partition, then
   disconnect. Verify no active targets and healthy service before reconnecting.
   Repeat for three connections; record separately whether file reads were
   repeated on every connection. Stop normally and verify release/restoration.

Keep local transcripts and snapshots under ignored `logs/`; report the actual
exit status, topology, fixture and kernel for each run. A failed check is not a
reason to delete saved arm/ownership state. Use the owning service's documented
restore command after components have stopped.

## Reused failure and recovery evidence

Step 8 already verified intentional termination of the current monitor, visible
service failure, cleanup of the remaining components and orphaned bpftrace,
retention of default-deny, and explicit restoration of saved original defaults.
It also verified normal installed shutdown and automatic startup after a normal
reboot with the drive disconnected until readiness. Those checks were not repeated
solely to assign them a second milestone number.

## Limits and deferred work

- No independent end-to-end watchdog detects a frozen pipeline stage. Runtime
  health can remain based on the last established state until an error is observed.
- The synchronous response/record-age limitation remains: a slow action can make
  later legitimate input stale, including closes or subsequent response triggers.
- Existing devices are not automatically reconciled or revoked at service startup;
  there is no verified guarantee of prevention before service readiness.
- LSM registration follows authorisation and mounting. It protects new opens of
  selected file identities, not whole devices, existing descriptors, mmap or raw
  device access. Controller exit ends those file restrictions.
- Missing-controller startup, process hangs, forced power loss, different-boot
  saved-state recovery, simultaneous devices, capacity limits and long-duration
  workload/resource measurements were not live-tested in this reduced round.
- Device-reported allowlist identity can be spoofed. File/trace cleanup is best
  effort and is not proof of forensic erasure, RAM sanitisation or removal of
  host/snapshot copies. Journal output is not a tamper-resistant audit store.

Steps 10 (whole-solution evaluation) and 11 (demonstration preparation) remain
separate. Completion here means the agreed focused checks passed within the
stated evidence, not that every possible failure or deployment has been tested.
