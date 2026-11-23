import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "responses"))
import responses
from responses import (ActionRunner, ResponseEngine, ResponseError, SystemExecutor,
                       load_config, main, power_command, process_stream, secure_delete,
                       validate_document)

REPO = Path(__file__).resolve().parents[1]
POSIX = os.name == "posix"


def setUpModule():
    # Responses act on Linux paths (/home, /proc); the whole module runs in the Ubuntu VM.
    if not POSIX:
        raise unittest.SkipTest("response tests need POSIX paths; run them in the Ubuntu VM")


class FakeRunner:
    """Stands in for subprocess.run and records each command."""

    def __init__(self, returncode=0, stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr
        self.before_call = None

    def __call__(self, argv, **kwargs):
        if self.before_call:
            self.before_call(argv)
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=self.returncode, stdout="", stderr=self.stderr)


class FakeClock:
    def __init__(self):
        self.now = 1_000_000_000

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += int(seconds * 1e9)


class Fixture(unittest.TestCase):
    def setUp(self):
        # Keep owned fixtures in the ignored build directory, mirroring the other tests.
        fixture_base = REPO / "build" / "test-tmp"
        fixture_base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=fixture_base)
        if Path(self.temporary.name).resolve().parent != fixture_base.resolve():
            raise RuntimeError("Temporary fixture escaped its intended directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.allowed = self.root / "allowed"
        self.allowed.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.proc = self.root / "proc"
        (self.proc / "sys" / "vm").mkdir(parents=True)
        self.runner = FakeRunner()
        self.synced = 0
        self.random_bytes = 0
        self.executor = SystemExecutor(proc_root=self.proc, runner=self.runner,
                                       sync=self._sync, randbytes=self._randbytes)
        self.records = []

    def _sync(self):
        self.synced += 1

    def _randbytes(self, count):
        self.random_bytes += count
        return b"\xa5" * count

    def document(self, actions, **extra):
        return {"schema_version": 1, "allowed_roots": [str(self.allowed)], "actions": actions, **extra}

    def config(self, actions, **extra):
        return validate_document(self.document(actions, **extra))

    def write(self, path, data=b"secret data"):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def engine(self, actions, apply=True, clock=None, **extra):
        return ResponseEngine(self.config(actions, **extra), self.executor, out=self.records.append,
                              apply=apply, clock=clock or FakeClock())

    def of_type(self, kind):
        return [record for record in self.records if record["type"] == kind]


def blocked(usb_id="2-1", **extra):
    return {"schema_version": 1, "type": "enforcement_result", "action": "block", "usb_id": usb_id,
            "enforcement_applied": False, "reason": "already_blocked", "connection_id": "c1",
            "session_id": "s1", "policy_reason": "no_matching_rule", "enforcement_latency_ns": 1234,
            **extra}


class ConfigTests(Fixture):
    def test_shipped_configs_are_valid(self):
        default = load_config(REPO / "config" / "responses.json")
        self.assertEqual([a["type"] for a in default.actions], ["lock_session"])
        example = load_config(REPO / "config" / "responses.example.json")
        self.assertEqual([a["type"] for a in example.actions],
                         ["lock_session", "delete", "sanitise", "power"])

    def test_defaults_are_filled_in(self):
        config = self.config([{"type": "power"}])
        self.assertEqual(config.actions, [{"type": "power", "mode": "poweroff", "method": "graceful"}])
        self.assertEqual(config.cooldown_seconds, 30.0)
        self.assertFalse(config.include_skipped)

    def assert_rejected(self, document, message):
        with self.assertRaisesRegex(ResponseError, message):
            validate_document(document)

    def test_rejects_bad_top_level(self):
        self.assert_rejected([], "JSON object")
        self.assert_rejected({"schema_version": 2, "actions": [{"type": "lock_session"}]}, "schema_version")
        self.assert_rejected({"schema_version": True, "actions": [{"type": "lock_session"}]}, "schema_version")
        self.assert_rejected(self.document([{"type": "lock_session"}], extra=1), "Unknown config fields")
        self.assert_rejected(self.document([]), "non-empty list")
        self.assert_rejected(self.document([{"type": "lock_session"}], cooldown_seconds=-1), "cooldown")
        self.assert_rejected(self.document([{"type": "lock_session"}], trigger={"include_skipped": "yes"}),
                             "include_skipped")
        self.assert_rejected(self.document([{"type": "lock_session"}], trigger={"other": 1}), "Unknown trigger")
        self.assert_rejected(self.document([{"type": "lock_session"}], trigger={"include_lsm_errors": 1}),
                             "include_lsm_errors")

    def test_rejects_bad_actions(self):
        self.assert_rejected(self.document([{"type": "format_disk"}]), "unknown type")
        self.assert_rejected(self.document([{"type": "lock_session", "x": 1}]), "Unknown lock_session")
        self.assert_rejected(self.document([{"type": "power"}, {"type": "lock_session"}]), "last action")
        self.assert_rejected(self.document([{"type": "lock_session"}, {"type": "lock_session"}]), "once")
        self.assert_rejected(self.document([{"type": "power", "mode": "hibernate"}]), "power.mode")
        self.assert_rejected(self.document([{"type": "power", "method": "pull_plug"}]), "power.method")

    def test_rejects_unsafe_delete_paths(self):
        inside = str(self.allowed / "x")
        self.assert_rejected(self.document([{"type": "delete", "paths": [str(self.outside / "x")]}]),
                             "not inside any allowed_roots")
        self.assert_rejected(self.document([{"type": "delete", "paths": [str(self.allowed)]}]),
                             "not inside any allowed_roots")
        self.assert_rejected(self.document([{"type": "delete", "paths": ["relative/x"]}]), "absolute")
        self.assert_rejected(self.document([{"type": "delete", "paths": [inside]}], allowed_roots=[]),
                             "needs allowed_roots")
        self.assert_rejected(self.document([{"type": "delete", "paths": [inside], "passes": 0}]), "passes")
        self.assert_rejected(self.document([{"type": "delete", "paths": [inside], "passes": True}]), "passes")
        # A sneaky ../ is normalised before the containment check.
        self.assert_rejected(self.document([{"type": "delete",
                                             "paths": [str(self.allowed) + "/../outside/x"]}]),
                             "not inside any allowed_roots")

    def test_rejects_broad_or_system_roots(self):
        for root in ("/", "/home", "/etc/portwatchman", "/usr/local/data", "/var/lib/x", "/boot/efi"):
            with self.subTest(root=root):
                self.assert_rejected(self.document([{"type": "lock_session"}], allowed_roots=[root]),
                                     "too broad|protected system tree")

    def test_rejects_bad_sanitise(self):
        home = str(self.home)
        self.assert_rejected(self.document([{"type": "sanitise", "home_dirs": [home], "items": ["browser"]}]),
                             "sanitise.items")
        self.assert_rejected(self.document([{"type": "sanitise", "home_dirs": [home],
                                             "items": ["trash", "trash"]}]), "sanitise.items")
        self.assert_rejected(self.document([{"type": "sanitise", "items": ["trash"]}]), "home_dirs")
        self.assert_rejected(self.document([{"type": "sanitise", "home_dirs": ["/root"], "items": ["trash"]}]),
                             "too broad")
        # drop_caches alone needs no home directory.
        validate_document(self.document([{"type": "sanitise", "items": ["drop_caches"]}]))

    def test_load_rejects_duplicate_keys_and_oversize(self):
        path = self.root / "responses.json"
        path.write_text('{"schema_version": 1, "schema_version": 1, "actions": []}', encoding="utf-8")
        with self.assertRaisesRegex(ResponseError, "Duplicate JSON key"):
            load_config(path)
        path.write_bytes(b" " * (responses.MAX_CONFIG_BYTES + 1))
        with self.assertRaisesRegex(ResponseError, "64 KiB"):
            load_config(path)
        with self.assertRaisesRegex(ResponseError, "Cannot read config"):
            load_config(self.root / "missing.json")


class SecureDeleteTests(Fixture):
    def test_dry_run_changes_nothing_and_lists_targets(self):
        self.write(self.allowed / "docs" / "a.txt", b"12345")
        self.write(self.allowed / "docs" / "sub" / "b.txt", b"123")
        report = secure_delete(self.allowed / "docs", [self.allowed], 1, apply=False,
                               randbytes=self._randbytes)
        self.assertTrue((self.allowed / "docs" / "sub" / "b.txt").exists())
        self.assertEqual((report.files, report.dirs, report.bytes), (2, 2, 8))
        self.assertEqual(self.random_bytes, 0)
        detail = report.as_dict(apply=False)
        self.assertIn(str(self.allowed / "docs" / "a.txt"), detail["would_delete"])

    def test_apply_overwrites_each_pass_then_removes_tree(self):
        self.write(self.allowed / "docs" / "a.txt", b"x" * 3000)
        self.write(self.allowed / "docs" / "sub" / "deeper" / "b.txt", b"y" * 1000)
        report = secure_delete(self.allowed / "docs", [self.allowed], 3, apply=True,
                               randbytes=self._randbytes)
        self.assertFalse((self.allowed / "docs").exists())
        self.assertEqual(report.errors, [])
        self.assertEqual((report.files, report.dirs, report.bytes), (2, 3, 4000))
        self.assertEqual(self.random_bytes, 4000 * 3)  # every byte, every pass
        self.assertEqual(list(self.allowed.iterdir()), [])  # no renamed leftovers

    def test_overwrite_reaches_the_file_contents(self):
        # A hard link outside the tree shares the inode, so it shows what was written.
        target = self.write(self.allowed / "a.bin", b"plaintext!" * 10)
        witness = self.outside / "witness"
        os.link(target, witness)
        seen = []
        original = os.ftruncate

        def capture(fd, length):
            seen.append(witness.read_bytes())
            return original(fd, length)

        with mock.patch("os.ftruncate", capture):
            secure_delete(target, [self.allowed], 1, apply=True, randbytes=self._randbytes)
        self.assertEqual(seen, [b"\xa5" * 100])
        self.assertEqual(witness.read_bytes(), b"")  # truncated after overwriting
        self.assertFalse(target.exists())

    def test_absent_target_is_reported_not_an_error(self):
        report = secure_delete(self.allowed / "nothing", [self.allowed], 1, apply=True)
        self.assertEqual(report.absent, [str(self.allowed / "nothing")])
        self.assertEqual(report.errors, [])

    @unittest.skipUnless(POSIX, "symlinks need POSIX file behaviour")
    def test_symlink_inside_tree_is_removed_not_followed(self):
        precious = self.write(self.outside / "precious.txt", b"keep me")
        (self.allowed / "docs").mkdir()
        os.symlink(precious, self.allowed / "docs" / "link.txt")
        os.symlink(self.outside, self.allowed / "docs" / "linkdir")
        report = secure_delete(self.allowed / "docs", [self.allowed], 1, apply=True,
                               randbytes=self._randbytes)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.others, 2)
        self.assertEqual(precious.read_bytes(), b"keep me")
        self.assertFalse((self.allowed / "docs").exists())

    @unittest.skipUnless(POSIX, "symlinks need POSIX file behaviour")
    def test_symlinked_parent_escaping_root_is_refused(self):
        precious = self.write(self.outside / "precious.txt", b"keep me")
        os.symlink(self.outside, self.allowed / "escape")
        report = secure_delete(self.allowed / "escape" / "precious.txt", [self.allowed], 1, apply=True)
        self.assertEqual(len(report.errors), 1)
        self.assertIn("outside allowed roots", report.errors[0]["error"])
        self.assertEqual(precious.read_bytes(), b"keep me")

    @unittest.skipUnless(POSIX and hasattr(os, "mkfifo"), "FIFOs need POSIX")
    def test_fifo_is_unlinked_without_opening(self):
        (self.allowed / "docs").mkdir()
        os.mkfifo(self.allowed / "docs" / "pipe")  # opening this for writing would hang
        report = secure_delete(self.allowed / "docs", [self.allowed], 1, apply=True)
        self.assertEqual(report.errors, [])
        self.assertFalse((self.allowed / "docs").exists())

    def test_write_failure_is_reported_and_others_still_deleted(self):
        self.write(self.allowed / "docs" / "a.txt")
        self.write(self.allowed / "docs" / "b.txt")
        real_open = os.open

        def failing_open(path, *args, **kwargs):
            if str(path).endswith("a.txt"):
                raise PermissionError(13, "Permission denied", str(path))
            return real_open(path, *args, **kwargs)

        with mock.patch("os.open", failing_open):
            report = secure_delete(self.allowed / "docs", [self.allowed], 1, apply=True,
                                   randbytes=self._randbytes)
        self.assertFalse((self.allowed / "docs" / "b.txt").exists())
        self.assertTrue((self.allowed / "docs" / "a.txt").exists())
        self.assertEqual(report.files, 1)
        paths = [error["path"] for error in report.errors]
        self.assertIn(str(self.allowed / "docs" / "a.txt"), paths)


class ActionTests(Fixture):
    def runner_for(self, actions, apply=True):
        config = self.config(actions)
        return ActionRunner(config, self.executor, apply=apply), config.actions

    def test_lock_session(self):
        runner, (action,) = self.runner_for([{"type": "lock_session"}], apply=False)
        self.assertEqual(runner.run(action), (True, {"would_run": ["loginctl", "lock-sessions"]}))
        self.assertEqual(self.runner.calls, [])
        runner.apply = True
        ok, _ = runner.run(action)
        self.assertTrue(ok)
        self.assertEqual(self.runner.calls, [["loginctl", "lock-sessions"]])

    def test_lock_failure_is_reported(self):
        self.runner.returncode, self.runner.stderr = 1, "Access denied"
        runner, (action,) = self.runner_for([{"type": "lock_session"}])
        ok, detail = runner.run(action)
        self.assertFalse(ok)
        self.assertIn("Access denied", detail["error"])

    def test_missing_command_is_reported(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        self.executor.runner = missing
        runner, (action,) = self.runner_for([{"type": "lock_session"}])
        ok, detail = runner.run(action)
        self.assertFalse(ok)
        self.assertIn("command not found", detail["error"])

    def test_power_commands(self):
        cases = {("poweroff", "graceful"): {"argv": ["systemctl", "poweroff"]},
                 ("reboot", "force"): {"argv": ["systemctl", "reboot", "--force"]},
                 ("poweroff", "immediate"): {"sysrq": "o"},
                 ("reboot", "immediate"): {"sysrq": "b"}}
        for (mode, method), expected in cases.items():
            with self.subTest(mode=mode, method=method):
                self.assertEqual(power_command({"mode": mode, "method": method}), expected)

    def test_power_dry_run_issues_nothing(self):
        (self.proc / "sysrq-trigger").write_text("", encoding="ascii")
        runner, (action,) = self.runner_for([{"type": "power", "method": "immediate"}], apply=False)
        ok, detail = runner.run(action)
        self.assertTrue(ok)
        self.assertEqual(detail["would_issue"], {"sysrq": "o"})
        self.assertEqual((self.proc / "sysrq-trigger").read_text(encoding="ascii"), "")
        self.assertEqual(self.synced, 0)

    def test_power_immediate_syncs_then_writes_sysrq(self):
        runner, (action,) = self.runner_for([{"type": "power", "mode": "reboot", "method": "immediate"}])
        ok, _ = runner.run(action)
        self.assertTrue(ok)
        self.assertEqual(self.synced, 1)
        self.assertEqual((self.proc / "sysrq-trigger").read_text(encoding="ascii"), "b")

    def test_power_graceful_runs_systemctl(self):
        runner, (action,) = self.runner_for([{"type": "power"}])
        runner.run(action)
        self.assertEqual(self.runner.calls, [["systemctl", "poweroff"]])

    def test_sanitise_removes_traces_only(self):
        self.write(self.home / ".bash_history", b"ls\nsecret-command\n")
        self.write(self.home / ".local" / "share" / "recently-used.xbel", b"<xbel/>")
        self.write(self.home / ".cache" / "thumbnails" / "large" / "abc.png", b"png")
        self.write(self.home / ".local" / "share" / "Trash" / "files" / "old.txt", b"old")
        keep = self.write(self.home / "Documents" / "report.docx", b"keep")
        keep_cache = self.write(self.home / ".cache" / "other" / "x", b"keep")
        runner, (action,) = self.runner_for([{"type": "sanitise", "home_dirs": [str(self.home)],
                                              "items": ["shell_history", "recent_files", "thumbnails",
                                                        "trash", "drop_caches"]}])
        ok, detail = runner.run(action)
        self.assertTrue(ok, detail)
        self.assertFalse((self.home / ".bash_history").exists())
        self.assertFalse((self.home / ".local" / "share" / "recently-used.xbel").exists())
        self.assertFalse((self.home / ".cache" / "thumbnails").exists())
        self.assertFalse((self.home / ".local" / "share" / "Trash").exists())
        self.assertTrue(keep.exists() and keep_cache.exists())
        self.assertEqual((self.proc / "sys" / "vm" / "drop_caches").read_text(encoding="ascii"), "3\n")
        self.assertEqual(self.synced, 1)
        self.assertEqual(detail["drop_caches"], "done")

    def test_sanitise_drop_caches_failure_is_reported(self):
        self.executor.proc_root = self.root / "no-proc"
        runner, (action,) = self.runner_for([{"type": "sanitise", "items": ["drop_caches"]}])
        ok, detail = runner.run(action)
        self.assertFalse(ok)
        self.assertTrue(detail["drop_caches"].startswith("failed"))

    def test_delete_action_dry_run_and_apply(self):
        target = self.write(self.allowed / "sensitive" / "plan.txt")
        runner, (action,) = self.runner_for([{"type": "delete", "paths": [str(self.allowed / "sensitive")]}],
                                            apply=False)
        ok, detail = runner.run(action)
        self.assertTrue(ok)
        self.assertTrue(target.exists())
        self.assertEqual(detail["files"], 1)
        runner.apply = True
        ok, detail = runner.run(action)
        self.assertTrue(ok)
        self.assertFalse((self.allowed / "sensitive").exists())
        self.assertNotIn("would_delete", detail)


class EngineTests(Fixture):
    def test_only_blocked_devices_trigger(self):
        engine = self.engine([{"type": "lock_session"}], cooldown_seconds=0)
        for record in (blocked(action="allow"), blocked(action="ignore"), blocked(action="unchanged"),
                       {"schema_version": 1, "type": "enforcement_started"},
                       {"schema_version": 1, "type": "enforcement_skipped", "requested_action": "block"}):
            engine.handle(record)
        self.assertEqual(self.runner.calls, [])
        engine.handle(blocked())
        self.assertEqual(self.runner.calls, [["loginctl", "lock-sessions"]])
        triggered, = self.of_type("response_triggered")
        self.assertEqual(triggered["usb_id"], "2-1")
        self.assertEqual(triggered["connection_id"], "c1")
        self.assertEqual(triggered["upstream_enforcement_latency_ns"], 1234)

    def test_skipped_blocks_trigger_when_configured(self):
        engine = self.engine([{"type": "lock_session"}], trigger={"include_skipped": True})
        engine.handle({"schema_version": 1, "type": "enforcement_skipped", "requested_action": "allow"})
        self.assertEqual(self.runner.calls, [])
        engine.handle({"schema_version": 1, "type": "enforcement_skipped", "requested_action": "block",
                       "reason": "stale_decision", "usb_id": "2-1"})
        self.assertEqual(len(self.runner.calls), 1)

    def test_lsm_bridge_errors_trigger_only_when_configured(self):
        error = {"schema_version": 1, "type": "lsm_bridge_error", "usb_id": "4-1", "connection_id": "c9",
                 "message": "controller lost", "protection_complete": False}
        engine = self.engine([{"type": "lock_session"}])
        engine.handle(error)
        self.assertEqual(self.runner.calls, [])
        self.records.clear()
        engine = self.engine([{"type": "lock_session"}], trigger={"include_lsm_errors": True})
        engine.handle(error)
        self.assertEqual(self.runner.calls, [["loginctl", "lock-sessions"]])
        triggered, = self.of_type("response_triggered")
        self.assertEqual(triggered["trigger_type"], "lsm_bridge_error")
        self.assertEqual(triggered["trigger_message"], "controller lost")
        self.assertEqual(triggered["connection_id"], "c9")

    def test_other_lsm_bridge_records_never_trigger(self):
        engine = self.engine([{"type": "lock_session"}], cooldown_seconds=0,
                             trigger={"include_lsm_errors": True, "include_skipped": True})
        for kind in ("lsm_bridge_started", "lsm_bridge_pending", "lsm_bridge_registered",
                     "lsm_bridge_plan", "lsm_bridge_released", "lsm_bridge_disconnected",
                     "lsm_bridge_prepared_for_removal", "lsm_bridge_retained", "lsm_bridge_revoke_result"):
            engine.handle({"schema_version": 1, "type": kind, "usb_id": "4-1"})
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(engine.input_errors, 0)

    def test_cooldown_suppresses_repeat_triggers(self):
        clock = FakeClock()
        engine = self.engine([{"type": "lock_session"}], clock=clock, cooldown_seconds=10)
        engine.handle(blocked())
        clock.advance(4)
        engine.handle(blocked())
        suppressed, = self.of_type("response_suppressed")
        self.assertEqual(suppressed["reason"], "cooldown")
        self.assertAlmostEqual(suppressed["cooldown_remaining_s"], 6.0)
        clock.advance(6)
        engine.handle(blocked())
        self.assertEqual(len(self.runner.calls), 2)
        self.assertEqual([r["response_id"] for r in self.of_type("response_triggered")], [1, 2])

    def test_actions_run_in_order_and_failure_does_not_stop_the_rest(self):
        target = self.write(self.allowed / "sensitive" / "a.txt")
        self.runner.returncode = 1  # loginctl and systemctl both "fail"
        engine = self.engine([{"type": "lock_session"},
                              {"type": "delete", "paths": [str(self.allowed / "sensitive")]},
                              {"type": "power"}])
        engine.handle(blocked())
        results = [r for r in self.of_type("response_action") if r["status"] != "issuing"]
        self.assertEqual([r["action"] for r in results], ["lock_session", "delete", "power"])
        self.assertEqual([r["ok"] for r in results], [False, True, False])
        self.assertFalse(target.exists())
        completed, = self.of_type("response_completed")
        self.assertEqual((completed["ok"], completed["failed_actions"]), (False, 2))
        self.assertEqual(engine.failures, 2)

    def test_power_record_is_written_before_the_command_runs(self):
        engine = self.engine([{"type": "lock_session"}, {"type": "power", "method": "force"}])
        seen_at_power = []
        self.runner.before_call = lambda argv: seen_at_power.append(
            [r.get("status") for r in self.records if r.get("action") == "power"]) \
            if argv[0] == "systemctl" else None
        engine.handle(blocked())
        self.assertEqual(seen_at_power, [["issuing"]])

    def test_later_triggers_suppressed_after_power_issued(self):
        engine = self.engine([{"type": "power"}], cooldown_seconds=0)
        engine.handle(blocked())
        engine.handle(blocked(usb_id="2-2"))
        suppressed, = self.of_type("response_suppressed")
        self.assertEqual(suppressed["reason"], "power_action_issued")
        self.assertEqual(len(self.runner.calls), 1)

    def test_failed_power_allows_a_later_retry(self):
        self.runner.returncode = 1
        engine = self.engine([{"type": "power"}], cooldown_seconds=0)
        engine.handle(blocked())
        engine.handle(blocked())
        self.assertEqual(len(self.runner.calls), 2)
        self.assertEqual(self.of_type("response_suppressed"), [])

    def test_dry_run_engine_runs_nothing(self):
        target = self.write(self.allowed / "sensitive" / "a.txt")
        engine = self.engine([{"type": "lock_session"},
                              {"type": "delete", "paths": [str(self.allowed / "sensitive")]},
                              {"type": "power", "method": "immediate"}], apply=False)
        engine.handle(blocked())
        self.assertEqual(self.runner.calls, [])
        self.assertTrue(target.exists())
        self.assertFalse((self.proc / "sysrq-trigger").exists())
        self.assertFalse(engine.power_issued)
        self.assertTrue(all(r["applied"] is False for r in self.of_type("response_action")))

    def test_monitor_status_is_reported_on_change_only(self):
        engine = self.engine([{"type": "lock_session"}])
        status = {"schema_version": 1, "type": "enforcement_monitor_status", "healthy": True}
        engine.handle(status)
        engine.handle(status)
        engine.handle({**status, "healthy": False})
        self.assertEqual([r["healthy"] for r in self.of_type("response_monitor_status")], [True, False])

    def test_wrong_schema_is_an_input_error(self):
        engine = self.engine([{"type": "lock_session"}])
        engine.handle({"type": "enforcement_result", "action": "block"})
        self.assertEqual(engine.input_errors, 1)
        self.assertEqual(self.runner.calls, [])


class StreamTests(Fixture):
    def stream(self, *records):
        return io.StringIO("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in records))

    def closed(self):
        record, = self.of_type("response_stream_closed")
        return record

    def test_clean_upstream_stop_exits_zero(self):
        engine = self.engine([{"type": "lock_session"}])
        status = process_stream(engine, self.stream(
            blocked(), "", {"schema_version": 1, "type": "enforcement_stream_closed",
                            "reason": "requested_stop", "ok": True}))
        self.assertEqual(status, 0)
        self.assertEqual(self.closed()["reason"], "upstream_requested_stop")
        self.assertEqual(self.closed()["responses"], 1)

    def test_upstream_failure_or_missing_close_exits_nonzero(self):
        engine = self.engine([{"type": "lock_session"}])
        self.assertEqual(process_stream(engine, self.stream(
            {"schema_version": 1, "type": "enforcement_stream_closed", "reason": "upstream_failed",
             "ok": False})), 1)
        self.records.clear()
        engine = self.engine([{"type": "lock_session"}])
        self.assertEqual(process_stream(engine, self.stream(blocked())), 1)
        self.assertEqual(self.closed()["reason"], "unexpected_end_of_input")

    def test_bad_json_is_reported_and_fails_the_stream(self):
        engine = self.engine([{"type": "lock_session"}])
        status = process_stream(engine, self.stream(
            "{not json", blocked(), {"schema_version": 1, "type": "enforcement_stream_closed",
                                     "reason": "requested_stop", "ok": True}))
        self.assertEqual(status, 1)
        self.assertEqual(len(self.of_type("response_input_error")), 1)
        self.assertEqual(len(self.runner.calls), 1)  # the good record after it still triggered

    def test_failed_action_fails_the_stream(self):
        self.runner.returncode = 1
        engine = self.engine([{"type": "lock_session"}])
        status = process_stream(engine, self.stream(
            blocked(), {"schema_version": 1, "type": "enforcement_stream_closed",
                        "reason": "requested_stop", "ok": True}))
        self.assertEqual(status, 1)

    def test_ctrl_c_is_a_requested_stop(self):
        class Interrupting:
            def __iter__(self):
                yield json.dumps(blocked()) + "\n"
                raise KeyboardInterrupt

        engine = self.engine([{"type": "lock_session"}])
        self.assertEqual(process_stream(engine, Interrupting()), 0)
        self.assertEqual(self.closed()["reason"], "requested_stop")


class CliTests(Fixture):
    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            status = main(list(argv))
        return status, [json.loads(line) for line in out.getvalue().splitlines()]

    def config_file(self, actions):
        path = self.root / "responses.json"
        path.write_text(json.dumps(self.document(actions)), encoding="utf-8")
        return str(path)

    def test_validate(self):
        status, (record,) = self.run_main("--config", self.config_file([{"type": "lock_session"}]), "validate")
        self.assertEqual(status, 0)
        self.assertEqual(record["actions"], ["lock_session"])

    def test_trigger_dry_run_touches_nothing(self):
        target = self.write(self.allowed / "sensitive" / "a.txt")
        path = self.config_file([{"type": "delete", "paths": [str(self.allowed / "sensitive")]},
                                 {"type": "power"}])
        with mock.patch("subprocess.run", FakeRunner()) as fake:
            status, records = self.run_main("--config", path, "trigger")
        self.assertEqual(status, 0)
        self.assertTrue(target.exists())
        self.assertEqual(fake.calls, [])
        self.assertEqual(records[-1]["type"], "response_completed")

    def test_run_action_selects_one_action(self):
        path = self.config_file([{"type": "lock_session"}, {"type": "power"}])
        status, records = self.run_main("--config", path, "run-action", "power")
        self.assertEqual(status, 0)
        self.assertEqual([r["action"] for r in records if r["type"] == "response_action"], ["power"])
        status, records = self.run_main("--config", path, "run-action", "delete")
        self.assertEqual(status, 2)
        self.assertIn("not configured", records[-1]["message"])

    def test_apply_requires_root(self):
        path = self.config_file([{"type": "lock_session"}])
        with mock.patch.object(responses.sys, "platform", "linux"), \
                mock.patch.object(responses.os, "geteuid", lambda: 1000, create=True):
            status, records = self.run_main("--config", path, "trigger", "--apply")
        self.assertEqual(status, 2)
        self.assertIn("needs root", records[-1]["message"])

    def test_invalid_config_exits_two(self):
        path = self.root / "bad.json"
        path.write_text('{"schema_version": 1, "actions": [{"type": "nope"}]}', encoding="utf-8")
        status, records = self.run_main("--config", str(path), "validate")
        self.assertEqual(status, 2)
        self.assertEqual(records[-1]["type"], "response_error")


if __name__ == "__main__":
    unittest.main()
