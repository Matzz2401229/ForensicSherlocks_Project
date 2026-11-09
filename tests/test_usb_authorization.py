import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "enforcement"))
import usb_authorization
from usb_authorization import (BusManager, Config, DeviceController, DeviceEnforcer,
                               EnforcementError, arm, authorize_device, load_config,
                               load_state, main, process_stream, reconcile, restore,
                               revoke_device, status)


class Fixture(unittest.TestCase):
    def setUp(self):
        # Keep owned fixtures in the ignored build directory, mirroring the policy tests.
        fixture_base = Path(__file__).resolve().parents[1] / "build" / "test-tmp"
        fixture_base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=fixture_base)
        if Path(self.temporary.name).resolve().parent != fixture_base.resolve():
            raise RuntimeError("Temporary fixture escaped its intended directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sysfs = self.root / "devices"
        self.state_file = self.root / "state" / "enforcement-state.json"

    def make_bus(self, name, default="1"):
        bus = self.sysfs / name
        bus.mkdir(parents=True, exist_ok=True)
        (bus / "authorized_default").write_text(default + "\n", encoding="utf-8")

    def make_device(self, name):
        # A device directory such as 2-1 has no authorized_default; it must be ignored.
        (self.sysfs / name).mkdir(parents=True, exist_ok=True)

    def manager(self, managed_buses="auto"):
        return BusManager(Config(managed_buses, self.state_file), root=self.sysfs)

    def read_bus(self, name):
        return (self.sysfs / name / "authorized_default").read_text(encoding="utf-8").strip()

    def make_usb_device(self, usb_id, bus, address=5, vendor="058f", product="6387",
                        serial="LAB-1", authorized="0"):
        device = self.sysfs / usb_id
        device.mkdir(parents=True, exist_ok=True)
        values = {"idVendor": vendor, "idProduct": product, "busnum": str(bus),
                  "devnum": str(address), "serial": serial, "bDeviceClass": "00",
                  "authorized": authorized}
        for name, value in values.items():
            (device / name).write_text(value + "\n", encoding="utf-8")
        return usb_id

    def controller(self):
        return DeviceController(root=self.sysfs)

    def read_authorized(self, usb_id):
        return (self.sysfs / usb_id / "authorized").read_text(encoding="utf-8").strip()

    def write_policy(self, rules):
        path = self.root / "allowlist.json"
        document = {"schema_version": 1, "default_action": "block", "allowlist": rules}
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def allow_policy(self):
        return self.write_policy([{"name": "lab", "vendor_id": "058f", "product_id": "6387"}])

    def block_policy(self):
        return self.write_policy([])


class ConfigTests(Fixture):
    def _write_config(self, document):
        path = self.root / "enforcement.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_auto_is_default(self):
        config = load_config(self._write_config({"schema_version": 1}))
        self.assertEqual(config.managed_buses, "auto")
        self.assertTrue(str(config.state_file).endswith("enforcement-state.json"))

    def test_explicit_bus_list_normalised_to_tuple(self):
        config = load_config(self._write_config(
            {"schema_version": 1, "managed_buses": ["usb2", "usb3"]}))
        self.assertEqual(config.managed_buses, ("usb2", "usb3"))

    def test_rejects_wrong_schema_version(self):
        with self.assertRaises(EnforcementError):
            load_config(self._write_config({"schema_version": 2}))

    def test_rejects_bad_bus_name(self):
        with self.assertRaises(EnforcementError):
            load_config(self._write_config({"schema_version": 1, "managed_buses": ["2-1"]}))

    def test_rejects_duplicate_bus(self):
        with self.assertRaises(EnforcementError):
            load_config(self._write_config(
                {"schema_version": 1, "managed_buses": ["usb2", "usb2"]}))

    def test_rejects_empty_bus_list(self):
        with self.assertRaises(EnforcementError):
            load_config(self._write_config({"schema_version": 1, "managed_buses": []}))

    def test_rejects_unknown_field(self):
        with self.assertRaises(EnforcementError):
            load_config(self._write_config({"schema_version": 1, "surprise": True}))


class DiscoveryTests(Fixture):
    def test_auto_finds_buses_sorted_and_ignores_non_buses(self):
        self.make_bus("usb3")
        self.make_bus("usb2")
        self.make_device("2-1")
        (self.sysfs / "usb_notabus").mkdir()  # name without a numeric suffix
        self.assertEqual(self.manager().discover(), ["usb2", "usb3"])

    def test_auto_errors_when_no_buses(self):
        self.sysfs.mkdir(parents=True)
        with self.assertRaises(EnforcementError):
            self.manager().discover()

    def test_explicit_missing_bus_errors(self):
        self.make_bus("usb2")
        with self.assertRaises(EnforcementError):
            self.manager(("usb2", "usb3")).discover()

    def test_read_default_rejects_garbage(self):
        self.make_bus("usb2", default="banana")
        with self.assertRaises(EnforcementError):
            self.manager().read_default("usb2")


class ArmRestoreTests(Fixture):
    def test_dry_run_writes_nothing(self):
        self.make_bus("usb2", "1")
        self.make_bus("usb3", "1")
        result = arm(self.manager(), self.state_file, apply=False)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["applied"])
        self.assertEqual(self.read_bus("usb2"), "1")
        self.assertEqual(self.read_bus("usb3"), "1")
        self.assertIsNone(load_state(self.state_file))
        self.assertEqual({b["bus"]: b["will_set"] for b in result["buses"]},
                         {"usb2": "0", "usb3": "0"})

    def test_apply_blocks_and_records_originals(self):
        self.make_bus("usb2", "1")
        self.make_bus("usb3", "1")
        arm(self.manager(), self.state_file, apply=True)
        self.assertEqual(self.read_bus("usb2"), "0")
        self.assertEqual(self.read_bus("usb3"), "0")
        state = load_state(self.state_file)
        self.assertEqual(state["buses"]["usb2"]["original_default"], "1")
        self.assertEqual(state["buses"]["usb3"]["original_default"], "1")

    def test_rearm_does_not_overwrite_true_original(self):
        self.make_bus("usb2", "1")
        arm(self.manager(), self.state_file, apply=True)
        self.assertEqual(self.read_bus("usb2"), "0")
        # Re-arming must keep the first-seen original (1), not the now-blocked value (0).
        arm(self.manager(), self.state_file, apply=True)
        self.assertEqual(load_state(self.state_file)["buses"]["usb2"]["original_default"], "1")

    def test_failed_write_part_way_still_leaves_originals_restorable(self):
        self.make_bus("usb2", "1")
        self.make_bus("usb3", "1")
        manager = self.manager()
        real_write = manager.write_default

        def fail_on_usb3(bus, value):
            if bus == "usb3":
                raise EnforcementError("simulated sysfs write failure")
            real_write(bus, value)

        manager.write_default = fail_on_usb3
        with self.assertRaises(EnforcementError):
            arm(manager, self.state_file, apply=True)
        self.assertEqual(self.read_bus("usb2"), "0")  # changed before the failure
        saved = load_state(self.state_file)["buses"]
        self.assertEqual(saved["usb2"]["original_default"], "1")  # still recoverable
        restore(self.manager(), self.state_file, apply=True)
        self.assertEqual(self.read_bus("usb2"), "1")

    def test_restore_puts_back_original_and_clears_state(self):
        self.make_bus("usb2", "1")
        self.make_bus("usb3", "0")  # a bus that was already default-deny before us
        arm(self.manager(), self.state_file, apply=True)
        restore(self.manager(), self.state_file, apply=True)
        self.assertEqual(self.read_bus("usb2"), "1")
        self.assertEqual(self.read_bus("usb3"), "0")
        self.assertFalse(self.state_file.exists())

    def test_restore_dry_run_keeps_state_and_values(self):
        self.make_bus("usb2", "1")
        arm(self.manager(), self.state_file, apply=True)
        result = restore(self.manager(), self.state_file, apply=False)
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.read_bus("usb2"), "0")
        self.assertTrue(self.state_file.exists())

    def test_restore_without_state_reports_nothing(self):
        self.make_bus("usb2", "1")
        result = restore(self.manager(), self.state_file, apply=True)
        self.assertEqual(result["buses"], [])
        self.assertIn("message", result)


class StatusTests(Fixture):
    def test_status_before_and_after_arm(self):
        self.make_bus("usb2", "1")
        before = status(self.manager(), self.state_file)
        self.assertFalse(before["armed"])
        self.assertFalse(before["buses"][0]["blocking_new_devices"])
        arm(self.manager(), self.state_file, apply=True)
        after = status(self.manager(), self.state_file)
        self.assertTrue(after["armed"])
        self.assertTrue(after["buses"][0]["blocking_new_devices"])
        self.assertEqual(after["buses"][0]["original_default"], "1")


class AuthorizeTests(Fixture):
    def test_allowed_device_is_authorized(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        result = authorize_device(self.controller(), "2-1", self.allow_policy(), apply=True)
        self.assertEqual(result["action"], "allow")
        self.assertTrue(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "1")

    def test_dry_run_does_not_write(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        result = authorize_device(self.controller(), "2-1", self.allow_policy(), apply=False)
        self.assertEqual(result["action"], "allow")
        self.assertFalse(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_unlisted_device_stays_blocked(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        result = authorize_device(self.controller(), "2-1", self.block_policy(), apply=True)
        self.assertEqual(result["action"], "block")
        self.assertFalse(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_identity_mismatch_refuses_authorisation(self):
        # The device on the port reports a different serial than the decision expected.
        self.make_usb_device("2-1", bus=2, serial="SWAPPED", authorized="0")
        expected = {"vendor_id": "058f", "product_id": "6387", "serial": "LAB-1", "device_address": 5}
        result = authorize_device(self.controller(), "2-1", self.allow_policy(),
                                  expected=expected, apply=True)
        self.assertEqual(result["action"], "block")
        self.assertEqual(result["reason"], "identity_mismatch")
        self.assertEqual(result["mismatch_field"], "serial")
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_revoke_blocks_device(self):
        self.make_usb_device("2-1", bus=2, authorized="1")
        result = revoke_device(self.controller(), "2-1", apply=True)
        self.assertEqual(result["action"], "block")
        self.assertEqual(self.read_authorized("2-1"), "0")


class EnforcerTests(Fixture):
    NOW = 10_000_000_000

    def enforcer(self, policy_path, apply=True):
        return DeviceEnforcer(self.controller(), policy_path, clock=lambda: self.NOW, apply=apply)

    def decision(self, usb_id, action, device=None, age_ns=0, **extra):
        ts = self.NOW - age_ns
        return {"schema_version": 1, "type": "policy_decision", "action": action,
                "usb_id": usb_id, "device": device, "decision_timestamp_ns": ts,
                "event_timestamp_ns": ts, "connection_id": "c1", "session_id": "s1", **extra}

    def test_allow_decision_authorizes_and_reports_latency(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        device = {"vendor_id": "058f", "product_id": "6387", "serial": "LAB-1", "device_address": 5}
        record = self.decision("2-1", "allow", device=device, age_ns=100)
        result = self.enforcer(self.allow_policy()).handle(record)
        self.assertEqual(result["action"], "allow")
        self.assertTrue(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "1")
        self.assertEqual(result["enforcement_latency_ns"], 100)
        self.assertEqual(result["connection_id"], "c1")

    def test_block_decision_revokes_an_authorized_device(self):
        self.make_usb_device("2-1", bus=2, authorized="1")
        result = self.enforcer(self.block_policy()).handle(self.decision("2-1", "block"))
        self.assertEqual(result["reason"], "revoked_unauthorised")
        self.assertTrue(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_block_decision_leaves_already_blocked_device(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        result = self.enforcer(self.block_policy()).handle(self.decision("2-1", "block"))
        self.assertEqual(result["reason"], "already_blocked")
        self.assertFalse(result["enforcement_applied"])

    def test_stale_decision_is_skipped(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        record = self.decision("2-1", "allow", age_ns=3_000_000_000)
        result = self.enforcer(self.allow_policy()).handle(record)
        self.assertEqual(result["type"], "enforcement_skipped")
        self.assertEqual(result["reason"], "stale_decision")
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_allow_without_timestamp_is_refused(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        record = self.decision("2-1", "allow")
        del record["decision_timestamp_ns"]
        result = self.enforcer(self.allow_policy()).handle(record)
        self.assertEqual(result["reason"], "stale_decision")
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_block_without_timestamp_is_still_enforced(self):
        self.make_usb_device("2-1", bus=2, authorized="1")
        record = self.decision("2-1", "block")
        del record["decision_timestamp_ns"]
        result = self.enforcer(self.block_policy()).handle(record)
        self.assertEqual(result["reason"], "revoked_unauthorised")
        self.assertEqual(self.read_authorized("2-1"), "0")

    def test_skip_and_close_records_are_ignored(self):
        enforcer = self.enforcer(self.allow_policy())
        for kind in ("policy_skipped", "policy_stream_closed"):
            self.assertIsNone(enforcer.handle({"schema_version": 1, "type": kind}))

    def test_monitor_health_is_reported_only_when_it_changes(self):
        enforcer = self.enforcer(self.allow_policy())
        status_record = lambda healthy: {"schema_version": 1, "type": "policy_monitor_status",
                                         "healthy": healthy, "degraded": False,
                                         "monitor_type": "monitor_heartbeat", "session_id": "s1"}
        first = enforcer.handle(status_record(False))
        self.assertEqual((first["type"], first["healthy"]), ("enforcement_monitor_status", False))
        self.assertIsNone(enforcer.handle(status_record(False)))  # unchanged: no heartbeat noise
        self.assertTrue(enforcer.handle(status_record(True))["healthy"])
        self.assertIsNone(enforcer.handle(status_record(True)))
        self.assertFalse(enforcer.handle(status_record(False))["healthy"])  # a drop is reported

    def test_policy_reason_is_carried_into_block_result(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        record = self.decision("2-1", "block", reason="no_matching_allowlist_rule")
        result = self.enforcer(self.block_policy()).handle(record)
        self.assertEqual(result["reason"], "already_blocked")
        self.assertEqual(result["policy_reason"], "no_matching_allowlist_rule")

    def test_policy_reason_is_carried_into_allow_result(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        device = {"vendor_id": "058f", "product_id": "6387", "serial": "LAB-1", "device_address": 5}
        record = self.decision("2-1", "allow", device=device, reason="allowlist_match")
        result = self.enforcer(self.allow_policy()).handle(record)
        self.assertEqual(result["policy_reason"], "allowlist_match")

    def test_dry_run_enforcer_does_not_write(self):
        self.make_usb_device("2-1", bus=2, authorized="0")
        device = {"vendor_id": "058f", "product_id": "6387", "serial": "LAB-1", "device_address": 5}
        result = self.enforcer(self.allow_policy(), apply=False).handle(
            self.decision("2-1", "allow", device=device))
        self.assertFalse(result["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-1"), "0")


class StreamTests(Fixture):
    def run_stream(self, stream):
        enforcer = DeviceEnforcer(self.controller(), self.allow_policy(), clock=lambda: 10_000_000_000)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = process_stream(enforcer, stream)
        return code, [json.loads(line) for line in out.getvalue().splitlines()]

    def test_end_of_input_closes_the_stream(self):
        code, records = self.run_stream(io.StringIO("\n"))
        self.assertEqual(code, 0)
        self.assertEqual(records[-1]["type"], "enforcement_stream_closed")
        self.assertEqual(records[-1]["reason"], "end_of_input")

    def test_ctrl_c_is_a_clean_requested_stop(self):
        class Interrupted:
            def __iter__(self):
                return self

            def __next__(self):
                raise KeyboardInterrupt

        code, records = self.run_stream(Interrupted())  # no traceback escapes
        self.assertEqual(code, 0)
        self.assertEqual(records, [{"schema_version": 1, "type": "enforcement_stream_closed",
                                    "reason": "requested_stop"}])

    def test_malformed_line_is_reported_not_fatal(self):
        code, records = self.run_stream(io.StringIO("not json\n"))
        self.assertEqual(code, 0)
        self.assertEqual(records[0]["type"], "enforcement_input_error")
        self.assertEqual(records[-1]["type"], "enforcement_stream_closed")


class CliErrorTests(Fixture):
    def run_cli(self, *args):
        config = self.root / "enforcement.json"
        config.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        argv = ["--config", str(config), "--usb-root", str(self.sysfs), *args]
        # Skip the Linux-only guard so the real error paths run on any platform.
        with mock.patch.object(usb_authorization, "require_linux"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, json.loads(out.getvalue())

    def test_unreadable_policy_is_a_json_error(self):
        self.make_usb_device("2-1", bus=2)
        code, record = self.run_cli("--policy", str(self.root / "missing.json"), "authorize", "2-1")
        self.assertEqual(code, 2)
        self.assertEqual(record["type"], "enforcement_error")

    def test_malformed_usb_id_is_a_json_error(self):
        code, record = self.run_cli("--policy", str(self.allow_policy()), "authorize", "bogus")
        self.assertEqual(code, 2)
        self.assertEqual(record["type"], "enforcement_error")


class ReconcileTests(Fixture):
    def test_authorizes_allowed_leaves_others_blocked(self):
        self.make_bus("usb2", "0")  # armed bus
        self.make_usb_device("2-1", bus=2, vendor="058f", product="6387", authorized="0")
        self.make_usb_device("2-2", bus=2, vendor="dead", product="beef", authorized="0")
        result = reconcile(self.controller(), self.manager(("usb2",)), self.allow_policy(), apply=True)
        actions = {row["usb_id"]: (row["action"], row["enforcement_applied"]) for row in result["devices"]}
        self.assertEqual(actions["2-1"], ("allow", True))
        self.assertEqual(actions["2-2"], ("block", False))
        self.assertEqual(self.read_authorized("2-1"), "1")  # allowed device authorised
        self.assertEqual(self.read_authorized("2-2"), "0")  # unlisted device left blocked

    def test_authorised_unlisted_device_is_unchanged_not_block(self):
        self.make_bus("usb2", "0")
        # An input device that was already authorised before arming and is not allowlisted.
        self.make_usb_device("2-2", bus=2, vendor="dead", product="beef", authorized="1")
        result = reconcile(self.controller(), self.manager(("usb2",)), self.allow_policy(), apply=True)
        row = result["devices"][0]
        self.assertEqual(row["action"], "unchanged")
        self.assertEqual(row["reason"], "not_allowlisted_left_unchanged")
        self.assertEqual(row["policy_reason"], "no_matching_allowlist_rule")
        self.assertFalse(row["enforcement_applied"])
        self.assertEqual(self.read_authorized("2-2"), "1")  # never revoked

    def test_blocked_unlisted_device_is_still_reported_as_block(self):
        self.make_bus("usb2", "0")
        self.make_usb_device("2-2", bus=2, vendor="dead", product="beef", authorized="0")
        result = reconcile(self.controller(), self.manager(("usb2",)), self.allow_policy(), apply=True)
        self.assertEqual(result["devices"][0]["action"], "block")

    def test_skips_devices_on_unmanaged_buses(self):
        self.make_bus("usb2", "0")
        self.make_usb_device("2-1", bus=2, authorized="0")
        self.make_usb_device("3-1", bus=3, authorized="0")  # bus 3 not managed here
        result = reconcile(self.controller(), self.manager(("usb2",)), self.allow_policy(), apply=True)
        self.assertEqual([row["usb_id"] for row in result["devices"]], ["2-1"])


if __name__ == "__main__":
    unittest.main()
