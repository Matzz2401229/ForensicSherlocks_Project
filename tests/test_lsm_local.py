"""VM-file registration tests; no BPF program or live service is started."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/enforcement"))
sys.path.insert(0, str(ROOT / "src/responses"))
from lsm_local import LocalFileGuard, LocalGuardConfig, LocalGuardError, check_response_overlap, load_local_config


class LocalConfigTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / "build/test-tmp"
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "lsm.json"

    def load(self, **fields):
        document = {"schema_version": 1, "socket_path": "/run/portwatchman/lsm_controller.sock",
                    "protected_paths": ["/var/tmp/demo/restricted.txt"], **fields}
        self.path.write_text(json.dumps(document))
        return load_local_config(self.path)

    def test_config_is_independent_of_allowlist_and_usb_port(self):
        config = self.load()
        self.assertEqual(config.protected_paths, ("/var/tmp/demo/restricted.txt",))

    def test_rejects_unsafe_paths_and_invalid_types(self):
        for paths in ([], "file", [None], ["relative.txt"], ["/"], ["//home/a"],
                      ["/home/../etc/file"], ["/home/./file"], ["/home//file"],
                      ["/home/file/"], ["/home/a\n"], ["/a", "/a"], ["/a\\b"], ["/a" * 3000]):
            with self.subTest(paths=paths), self.assertRaises(LocalGuardError):
                self.load(protected_paths=paths)

    def test_rejects_unknown_fields_and_noninteger_schema(self):
        for fields in ({"schema_version": True}, {"rules": []}, {"socket_path": "relative.sock"},
                       {"protected_paths": [f"/home/file-{index}" for index in range(129)]}):
            with self.subTest(fields=fields), self.assertRaises(LocalGuardError):
                self.load(**fields)

    def test_duplicate_json_keys_and_nonfinite_values_rejected(self):
        for raw in ('{"schema_version":1,"schema_version":1}', '{"schema_version":NaN}'):
            self.path.write_text(raw)
            with self.assertRaises(LocalGuardError):
                load_local_config(self.path)

    def test_config_bound_is_enforced(self):
        self.path.write_bytes(b" " * 65537)
        with self.assertRaises(LocalGuardError):
            load_local_config(self.path)

    def test_cleanup_same_file_or_parent_refused(self):
        config = self.load()
        for action in ({"type": "delete", "paths": ["/var/tmp/demo"]},
                       {"type": "delete", "paths": ["/var/tmp/demo/restricted.txt"]}):
            with self.subTest(action=action), self.assertRaises(LocalGuardError):
                check_response_overlap(config, SimpleNamespace(actions=[action]))

    def test_sanitise_overlap_refused_but_other_actions_allowed(self):
        config = LocalGuardConfig("/run/portwatchman/lsm_controller.sock", ("/home/demo/.bash_history",))
        with self.assertRaises(LocalGuardError):
            check_response_overlap(config, SimpleNamespace(actions=[{
                "type": "sanitise", "home_dirs": ["/home/demo"], "items": ["shell_history"]}]))
        check_response_overlap(config, SimpleNamespace(actions=[{"type": "lock_session"},
            {"type": "power", "mode": "poweroff"},
            {"type": "delete", "paths": ["/var/tmp/other-demo"]},
            {"type": "sanitise", "home_dirs": [], "items": ["drop_caches"]}]))

    @unittest.skipUnless(sys.platform == "linux", "Linux hard-link semantics")
    def test_direct_cleanup_hardlink_alias_refused(self):
        original = Path(self.temp.name) / "original"
        original.write_text("fixture")
        alias = original.with_name("alias")
        os.link(original, alias)
        with self.assertRaises(LocalGuardError):
            check_response_overlap(LocalGuardConfig("/run/pw/guard.sock", (str(original.resolve()),)),
                                   SimpleNamespace(actions=[{"type": "delete", "paths": [str(alias)]}]))


class FakeClient:
    def __init__(self):
        self.controller_id = "fixture-controller"
        self.mode = "local-files"
        self.failures = 0
        self.targets = []
        self.calls = []
        self.state_calls = 0
        self.reject_add = None

    def status(self):
        self.state_calls += 1
        return {"mode": self.mode, "failures": self.failures, "targets": self.targets,
                "enforcement_active": True}

    def request(self, command, **fields):
        self.calls.append((command, fields))
        if self.reject_add == len(self.calls):
            raise LocalGuardError("Injected ADD failure")
        target = {name.removeprefix("expected_"): value for name, value in fields.items()
                  if name.startswith("expected_")}
        target.update(path=fields["path"], connection_id=fields["connection_id"],
                      target_id=len(self.targets) + 1, usb_id=None)
        self.targets.append(target)
        return {"type": "lsm_target_added", "target": target}


class LocalRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.time = 10
        self.config = LocalGuardConfig("/run/portwatchman/lsm_controller.sock", ("/vm/first", "/vm/second"))
        self.closed = mock.patch("lsm_local.os.close")
        self.close = self.closed.start()
        self.addCleanup(self.closed.stop)
        self.inspect_calls = []
        self.guard = LocalFileGuard(self.config, client=self.client, inspect=self.inspect, clock=lambda: self.time)

    def inspect(self, path):
        self.inspect_calls.append(path)
        inode = self.config.protected_paths.index(path) + 40
        return inode, {"expected_major": 8, "expected_minor": 2,
                       "expected_inode": inode, "expected_mount_id": 20}

    def test_registers_all_files_without_usb_event_and_verifies_identity(self):
        event = self.guard.start()
        self.assertTrue(event["protection_complete"])
        self.assertEqual(event["target_ids"], [1, 2])
        self.assertEqual(len(self.inspect_calls), 2)
        self.assertEqual(self.close.call_count, 2)
        self.assertTrue(all(command == "ADD" for command, _fields in self.client.calls))
        self.assertTrue(all("expected_usb_id" not in fields for _command, fields in self.client.calls))

    def test_checks_do_not_depend_on_usb_or_clear_entries(self):
        self.guard.start()
        for _index in range(3):
            self.time += 2
            self.guard.tick()
        self.assertEqual(len(self.client.targets), 2)
        self.assertEqual(len(self.client.calls), 2)

    def test_poll_is_paced(self):
        self.guard.start()
        calls = self.client.state_calls
        self.guard.tick()
        self.assertEqual(self.client.state_calls, calls)
        self.time += 1
        self.guard.tick()
        self.assertEqual(self.client.state_calls, calls + 1)

    def test_removed_target_is_failure(self):
        self.guard.start()
        self.client.targets.pop()
        with self.assertRaisesRegex(LocalGuardError, "disappeared"):
            self.guard.verify()

    def test_replaced_or_foreign_identity_is_failure(self):
        for key, value in (("inode", 1234), ("mount_id", 99), ("connection_id", "another-owner"), ("usb_id", "3-2")):
            self.client = FakeClient()
            self.guard = LocalFileGuard(self.config, client=self.client, inspect=self.inspect)
            self.guard.start()
            self.client.targets[0][key] = value
            with self.subTest(key=key), self.assertRaises(LocalGuardError):
                self.guard.verify()

    def test_wrong_mode_or_degraded_controller_refused(self):
        for mode, failures in (("usb", 0), ("test-loopback", 0), ("local-files", 1)):
            self.client.mode, self.client.failures = mode, failures
            with self.subTest(mode=mode, failures=failures), self.assertRaises(LocalGuardError):
                self.guard.start()
        self.assertFalse(self.client.calls)

    def test_foreign_registry_not_adopted(self):
        self.client.targets.append({"target_id": 9})
        with self.assertRaises(LocalGuardError):
            self.guard.start()
        self.assertFalse(self.client.calls)

    def test_duplicate_inode_is_rejected_before_any_add(self):
        self.guard.inspect = lambda path: (40, {"expected_major": 8, "expected_minor": 2,
                                               "expected_inode": 40, "expected_mount_id": 20})
        with self.assertRaisesRegex(LocalGuardError, "same file identity"):
            self.guard.start()
        self.assertFalse(self.client.calls)
        self.assertEqual(self.close.call_count, 2)

    def test_partial_failure_does_not_claim_complete_or_remove_existing_entries(self):
        self.client.reject_add = 2
        with self.assertRaisesRegex(LocalGuardError, "Injected"):
            self.guard.start()
        self.assertEqual(len(self.guard.targets), 1)
        self.assertEqual(len(self.client.targets), 1)
        self.assertEqual(self.close.call_count, 2)
        self.assertTrue(all(op == "ADD" for op, _fields in self.client.calls))

    def test_changed_controller_propagates_as_failure(self):
        self.guard.start()
        from lsm_client import ControllerChanged
        self.client.status = mock.Mock(side_effect=ControllerChanged("restarted"))
        with self.assertRaises(ControllerChanged):
            self.guard.verify()

    def test_startup_deadline_cannot_claim_readiness(self):
        with self.assertRaisesRegex(LocalGuardError, "deadline"):
            self.guard.start(deadline=self.time)
        self.assertFalse(self.client.calls)


if __name__ == "__main__":
    unittest.main()
