import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "policy"))
from device_policy import (DeviceError, DeviceReader, PolicyError, PolicyProcessor,
                           evaluate, identifier, load_policy, main, parse_json,
                           validate_document, write_policy)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "monitor"))
from usb_monitor import Decoder


def document(rules=None):
    return {"schema_version": 1, "default_action": "block", "allowlist": rules or []}


def rule(**constraints):
    return {"name": "lab-drive", "vendor_id": "058f", "product_id": "6387", **constraints}


class Fixture(unittest.TestCase):
    def setUp(self):
        # Keep owned fixtures in the ignored build directory. Verify the exact
        # resolved target before registering TemporaryDirectory's recursive cleanup.
        fixture_base = Path(__file__).resolve().parents[1] / "build" / "test-tmp"
        fixture_base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=fixture_base)
        if Path(self.temporary.name).resolve().parent != fixture_base.resolve():
            raise RuntimeError("Temporary fixture escaped its intended directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.usb = self.root / "devices" / "2-1"
        self.usb.mkdir(parents=True)
        values = {"idVendor": "058f", "idProduct": "6387", "busnum": "2", "devnum": "8",
                  "serial": "LAB-123", "bDeviceClass": "00", "authorized": "1",
                  "manufacturer": "Test manufacturer", "product": "Mass Storage"}
        for name, value in values.items():
            (self.usb / name).write_text(value + "\n", encoding="utf-8")
        self.reader = DeviceReader(self.root / "devices")
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps(document()), encoding="utf-8")

    def policy(self, rules=None):
        write_policy(self.policy_path, document(rules))
        return load_policy(self.policy_path)


class IdentificationTests(Fixture):
    def test_reads_identity_and_current_authorisation(self):
        record = self.reader.read("2-1")
        self.assertEqual(record["vendor_id"], "058f")
        self.assertEqual(record["product_id"], "6387")
        self.assertEqual(record["serial"], "LAB-123")
        self.assertEqual(record["device_address"], 8)
        self.assertTrue(record["kernel_authorized"])

    def test_optional_serial_and_strings_may_be_absent(self):
        for name in ("serial", "manufacturer", "product"):
            (self.usb / name).unlink()
        record = self.reader.read("2-1")
        self.assertIsNone(record["serial"])
        self.assertIsNone(record["product"])

    def test_unauthorised_device_is_still_identifiable(self):
        (self.usb / "authorized").write_text("0\n")
        record = self.reader.read("2-1")
        self.assertFalse(record["kernel_authorized"])
        self.assertEqual(record["vendor_id"], "058f")

    def test_old_event_does_not_select_new_device_address(self):
        with self.assertRaises(DeviceError) as raised:
            self.reader.read("2-1", expected_address=7)
        self.assertEqual(raised.exception.code, "stale_device")

    def test_changed_identity_during_read_is_rejected(self):
        original = self.reader._identity(self.usb)
        changed = (*original[:3], 9, original[4])
        with mock.patch.object(self.reader, "_identity", side_effect=[original, changed]):
            with self.assertRaises(DeviceError) as raised:
                self.reader.read("2-1")
        self.assertEqual(raised.exception.code, "device_changed")

    def test_missing_required_attribute_blocks_identification(self):
        (self.usb / "idVendor").unlink()
        with self.assertRaises(DeviceError) as raised:
            self.reader.read("2-1", timeout=0)
        self.assertEqual(raised.exception.code, "device_unavailable")

    def test_malformed_required_attribute_is_rejected(self):
        (self.usb / "idVendor").write_text("not-hex\n")
        with self.assertRaises(DeviceError) as raised:
            self.reader.read("2-1")
        self.assertEqual(raised.exception.code, "invalid_device_attributes")

    def test_retry_handles_delayed_sysfs_visibility(self):
        expected = self.reader.read("2-1")
        with mock.patch.object(self.reader, "_once", side_effect=[FileNotFoundError(), expected]), \
             mock.patch("device_policy.time.sleep"):
            self.assertEqual(self.reader.read("2-1"), expected)

    def test_paths_interfaces_and_invalid_port_ids_are_rejected(self):
        for usb_id in ("../etc", "/sys/bus/usb/devices/2-1", "2-1:1.0", "2-0", "02-1", "2-1.0"):
            with self.subTest(usb_id=usb_id), self.assertRaises(ValueError):
                self.reader.read(usb_id)

    def test_listing_excludes_interface_directories(self):
        # Linux interface names contain ':' and cannot be created on Windows.
        entries = [self.reader.root / name for name in ("2-1", "2-1:1.0", "usb2")]
        with mock.patch("device_policy.Path.iterdir", return_value=iter(entries)):
            self.assertEqual(self.reader.list_ids(), ["2-1", "usb2"])


class MatchingTests(Fixture):
    def test_empty_allowlist_blocks_without_enforcing(self):
        decision = evaluate(self.reader.read("2-1"), self.policy())
        self.assertEqual(decision["action"], "block")
        self.assertFalse(decision["enforcement_applied"])
        self.assertTrue(decision["device"]["kernel_authorized"])

    def test_matching_vendor_and_product_allow(self):
        decision = evaluate(self.reader.read("2-1"), self.policy([rule()]))
        self.assertEqual(decision["action"], "allow")
        self.assertEqual(decision["matched_rule"], "lab-drive")

    def test_serial_constraint_must_match_exactly(self):
        decision = evaluate(self.reader.read("2-1"), self.policy([rule(serial="lab-123")]))
        self.assertEqual(decision["action"], "block")
        self.assertEqual(decision["rule_mismatches"][0]["fields"], ["serial"])

    def test_matching_serial_and_location_allow(self):
        decision = evaluate(self.reader.read("2-1"), self.policy([rule(serial="LAB-123", usb_id="2-1")]))
        self.assertEqual(decision["action"], "allow")

    def test_missing_serial_cannot_match_serial_rule(self):
        (self.usb / "serial").unlink()
        self.assertEqual(evaluate(self.reader.read("2-1"), self.policy([rule(serial="LAB-123")]))["action"], "block")

    def test_other_port_is_not_approved(self):
        self.assertEqual(evaluate(self.reader.read("2-1"), self.policy([rule(usb_id="2-2")]))["action"], "block")

    def test_all_constraints_are_required(self):
        self.assertEqual(evaluate(self.reader.read("2-1"), self.policy([rule(product_id="1111", serial="LAB-123")]))["action"], "block")

    def test_hexadecimal_case_is_normalised(self):
        self.assertEqual(evaluate(self.reader.read("2-1"), self.policy([rule(vendor_id="058F")]))["action"], "allow")

    def test_root_hub_is_ignored(self):
        device = self.reader.read("2-1")
        device.update(usb_id="usb2", is_root_hub=True)
        self.assertEqual(evaluate(device, self.policy())["action"], "ignore")


class ValidationTests(Fixture):
    def test_invalid_policies_are_rejected_entirely(self):
        candidates = [[], document([None]), document([rule(unknown=True)]),
                      document([rule(vendor_id=1423)]), document([rule(vendor_id="0x058f")]),
                      document([rule(serial="")]), document([rule(serial=None)]),
                      document([rule(usb_id="../../etc")]), document([rule(), rule()]),
                      {**document(), "schema_version": True},
                      {**document(), "schema_version": 2},
                      {**document(), "default_action": "allow"},
                      {**document(), "unexpected": 1}, document([rule(name="bad\nname")])]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(PolicyError):
                validate_document(candidate)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(PolicyError):
            parse_json('{"default_action":"block","default_action":"allow"}')

    def test_invalid_json_and_missing_file_are_errors(self):
        self.policy_path.write_text("{not-json")
        with self.assertRaises(PolicyError):
            load_policy(self.policy_path)
        self.policy_path.unlink()
        with self.assertRaises(PolicyError):
            load_policy(self.policy_path)

    def test_policy_size_limit(self):
        self.policy_path.write_text(" " * 65537)
        with self.assertRaises(PolicyError):
            load_policy(self.policy_path)

    def test_revision_changes_after_valid_update(self):
        first = load_policy(self.policy_path).revision
        second = self.policy([rule()]).revision
        self.assertNotEqual(first, second)

    def test_invalid_write_does_not_replace_valid_policy(self):
        before = self.policy_path.read_bytes()
        with self.assertRaises(PolicyError):
            write_policy(self.policy_path, document([rule(), rule()]))
        self.assertEqual(self.policy_path.read_bytes(), before)

    def test_cli_add_and_remove_rule(self):
        command = ["device_policy.py", "--policy", str(self.policy_path)]
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(sys, "argv", command + ["add-rule", "--name", "lab", "--vendor-id", "058f", "--product-id", "6387"]):
                self.assertEqual(main(), 0)
            self.assertEqual(load_policy(self.policy_path).document["allowlist"][0]["name"], "lab")
            with mock.patch.object(sys, "argv", command + ["remove-rule", "--name", "lab"]):
                self.assertEqual(main(), 0)
        self.assertEqual(load_policy(self.policy_path).document["allowlist"], [])


class StreamTests(Fixture):
    def setUp(self):
        super().setUp()
        self.policy([rule()])
        self.processor = PolicyProcessor(self.reader, self.policy_path, "testboot", clock=lambda: 1000)
        self.start_monitor()

    def start_monitor(self, boot="testboot", session="session-one"):
        self.processor.handle({"schema_version": 1, "type": "monitor_starting", "session_id": session,
                               "boot_id": boot, "clock": "monotonic"})
        self.processor.handle({"schema_version": 1, "type": "monitor_alive", "session_id": session})

    def event(self, **changes):
        return {"schema_version": 1, "type": "usb_setup_completed", "session_id": "session-one",
                "source": "ebpf", "clock": "monotonic", "timestamp_ns": 100, "setup_started_ns": 50,
                "result": 0, "bus": 2, "device_address": 8, "port_path": "1", "usb_id": "2-1",
                "sysfs_path": "/sys/bus/usb/devices/2-1", "connection_id": "testboot:2-1:50",
                "duplicate": False, **changes}

    def test_live_completed_setup_produces_correlated_allow(self):
        result = self.processor.handle(self.event())
        self.assertEqual(result["action"], "allow")
        self.assertEqual(result["connection_id"], "testboot:2-1:50")
        self.assertFalse(result["enforcement_applied"])

    def test_actual_monitor_decoder_output_is_accepted(self):
        decoder = Decoder("testboot")
        start = decoder.decode("PW1\tsetup_started\t100\t100\t2\t8\t1\t0\n")
        completed = decoder.decode("PW1\tsetup_result\t120\t100\t2\t8\t1\t0\n")
        skipped = self.processor.handle({"schema_version": 1, "session_id": "session-one", **start})
        decision = self.processor.handle({"schema_version": 1, "session_id": "session-one", **completed})
        self.assertEqual(skipped["type"], "policy_skipped")
        self.assertEqual(decision["action"], "allow")
        self.assertEqual(decision["connection_id"], completed["connection_id"])

    def test_setup_started_is_not_evaluated(self):
        result = self.processor.handle(self.event(type="usb_setup_started"))
        self.assertEqual(result["type"], "policy_skipped")

    def test_duplicate_completion_is_skipped(self):
        self.processor.handle(self.event())
        self.assertEqual(self.processor.handle(self.event())["reason"], "duplicate_event")

    def test_old_event_is_blocked(self):
        self.processor.clock = lambda: 3_000_000_000
        self.assertEqual(self.processor.handle(self.event())["reason"], "stale_event")

    def test_future_timestamp_is_blocked(self):
        self.assertEqual(self.processor.handle(self.event(timestamp_ns=2000))["reason"], "stale_event")

    def test_reused_device_path_with_new_address_is_blocked(self):
        self.assertEqual(self.processor.handle(self.event(device_address=7))["reason"], "stale_device")

    def test_monitor_loss_blocks_decisions_until_new_session(self):
        self.processor.handle({"schema_version": 1, "type": "monitor_loss", "session_id": "session-one"})
        self.processor.handle({"schema_version": 1, "type": "monitor_heartbeat", "session_id": "session-one",
                               "degraded": False, "reported_lost_events": 0})
        self.assertEqual(self.processor.handle(self.event())["reason"], "monitor_unhealthy")
        self.start_monitor(session="session-two")
        self.assertEqual(self.processor.handle(self.event(session_id="session-two"))["action"], "allow")

    def test_duplicate_start_cannot_clear_reported_loss(self):
        self.processor.handle({"schema_version": 1, "type": "monitor_loss", "session_id": "session-one"})
        self.start_monitor()
        self.assertEqual(self.processor.handle(self.event())["reason"], "monitor_unhealthy")

    def test_old_boot_is_not_trusted(self):
        self.start_monitor(boot="differentboot")
        self.assertEqual(self.processor.handle(self.event())["reason"], "monitor_unhealthy")

    def test_new_event_uses_reloaded_policy(self):
        write_policy(self.policy_path, document())
        self.assertEqual(self.processor.handle(self.event())["action"], "block")

    def test_invalid_policy_cannot_allow(self):
        self.policy_path.write_text("{bad-json")
        self.assertEqual(self.processor.handle(self.event())["reason"], "invalid_policy")

    def test_invalid_fields_and_untrusted_paths_cannot_allow(self):
        for changes in ({"sysfs_path": "/etc"}, {"device_address": True}, {"bus": 3},
                        {"clock": "boot"}, {"result": True}, {"connection_id": "forged"},
                        {"source": "fake"}, {"duplicate": 1}):
            with self.subTest(changes=changes):
                self.assertEqual(self.processor.handle(self.event(**changes))["reason"], "invalid_event")

    def test_missing_device_yields_block_decision(self):
        with mock.patch.object(self.reader, "read", side_effect=DeviceError("device_unavailable", "gone")):
            self.assertEqual(self.processor.handle(self.event())["reason"], "device_unavailable")

    def test_unknown_schema_marks_stream_unhealthy(self):
        result = self.processor.handle({"schema_version": True})
        self.assertEqual(result["type"], "policy_input_error")
        self.assertFalse(self.processor.healthy)


if __name__ == "__main__":
    unittest.main()
