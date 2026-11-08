import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "enforcement"))
from usb_authorization import (BusManager, Config, EnforcementError, arm, load_config,
                               load_state, restore, status)


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


if __name__ == "__main__":
    unittest.main()
