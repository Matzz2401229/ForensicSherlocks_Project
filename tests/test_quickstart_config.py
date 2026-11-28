import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import quickstart_config  # noqa: E402
sys.path.insert(0, str(ROOT / "src" / "enforcement"))
from lsm_local import load_local_config  # noqa: E402
sys.path.insert(0, str(ROOT / "src" / "policy"))
from device_policy import load_policy  # noqa: E402
from usb_authorization import load_config as load_enforcement  # noqa: E402

DRIVE = {"usb_id": "4-1", "sysfs_path": "/sys/bus/usb/devices/4-1", "bus": 4, "device_address": 3,
         "vendor_id": "125f", "product_id": "db8a", "serial": "20A1210010230055",
         "manufacturer": "ADATA", "product": "USB Flash Drive", "device_class": "00",
         "kernel_authorized": True, "is_root_hub": False}


class QuickstartConfigTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / "build" / "test-tmp"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "logs").mkdir()
        self.save_device(DRIVE)

    def save_device(self, device, kind="device_identified"):
        (self.root / "logs" / "quick-device.json").write_text(
            json.dumps({"schema_version": 1, "type": kind, "device": device}))

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = quickstart_config.main(list(argv), root=self.root)
        return code, out.getvalue(), err.getvalue()

    def load(self, name):
        return json.loads((self.root / "logs" / name).read_text())

    def test_writes_every_quickstart_file(self):
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("quick-service-block.json check", out)
        self.assertEqual(self.load("quick-device.json")["device"]["serial"], "20A1210010230055")
        self.assertEqual(self.load("quick-allow.json")["allowlist"],
                         [{"name": "trusted-usb", "vendor_id": "125f", "product_id": "db8a",
                           "serial": "20A1210010230055"}])
        self.assertEqual(self.load("quick-block.json")["allowlist"], [])
        self.assertEqual(self.load("quick-enforcement.json")["managed_buses"], "auto")
        self.assertEqual(self.load("quick-responses.json")["actions"], [{"type": "lock_session"}])
        service = self.load("quick-service-block.json")
        self.assertEqual(service["policy"], "logs/quick-block.json")
        self.assertEqual(service["local_lsm"], "logs/quick-lsm.json")
        self.assertIsNone(service["lsm"])
        demo = (self.root / quickstart_config.DEMO_DIR).resolve()
        self.assertEqual((demo / "restricted.txt").read_text(), "Protected VM file\n")
        self.assertEqual((demo / "control.txt").read_text(), "Readable control file\n")

    def test_single_bus_option_manages_only_the_drive_bus(self):
        code, out, _ = self.run_main("--single-bus")
        self.assertEqual(code, 0)
        self.assertEqual(self.load("quick-enforcement.json")["managed_buses"], ["usb4"])
        self.assertIn("Managed USB buses: usb4", out)

    def test_generated_files_pass_the_project_validators(self):
        self.run_main()
        load_policy(self.root / "logs" / "quick-allow.json")
        load_policy(self.root / "logs" / "quick-block.json")
        load_local_config(self.root / "logs" / "quick-lsm.json")
        self.assertEqual(load_enforcement(self.root / "logs" / "quick-enforcement.json").managed_buses, "auto")

    def test_extra_protected_files_are_added_once(self):
        secret = self.root / "secret.txt"
        secret.write_text("secret\n")
        code, out, _ = self.run_main("--protect", str(secret), "--protect", str(secret))
        self.assertEqual(code, 0)
        paths = self.load("quick-lsm.json")["protected_paths"]
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[1], str(secret.resolve()))
        self.assertIn(str(secret.resolve()), out)

    def make(self, name, text="evidence\n"):
        path = self.root / name
        path.write_text(text)
        return path

    def test_protect_adds_to_the_saved_list_across_runs(self):
        first, second = self.make("first.txt"), self.make("second.zip")
        self.assertEqual(self.run_main("--protect", str(first))[0], 0)
        code, out, _ = self.run_main("--protect", str(second))
        self.assertEqual(code, 0)
        paths = self.load("quick-lsm.json")["protected_paths"]
        self.assertEqual(paths[1:], [str(first.resolve()), str(second.resolve())])
        self.assertEqual(self.load("quick-files.json")["protect"], paths[1:])
        self.assertIn(str(first.resolve()), out)

    def test_unprotect_and_reset_change_the_saved_list(self):
        first, second = self.make("first.txt"), self.make("second.zip")
        self.run_main("--protect", str(first), "--protect", str(second))
        self.run_main("--unprotect", str(first))
        self.assertEqual(self.load("quick-lsm.json")["protected_paths"][1:], [str(second.resolve())])
        code, _, err = self.run_main("--unprotect", str(first))
        self.assertEqual(code, 1)
        self.assertIn("Not in the saved protect list", err)
        self.run_main("--reset")
        self.assertEqual(len(self.load("quick-lsm.json")["protected_paths"]), 1)
        self.assertEqual(self.load("quick-files.json"), {"schema_version": 1, "protect": [], "destroy": []})

    def test_a_saved_file_that_has_gone_is_reported(self):
        first = self.make("first.txt")
        self.run_main("--protect", str(first))
        first.unlink()
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("--unprotect", err)

    def test_destroy_creates_a_profile_and_may_include_protected_files(self):
        evidence = self.make("evidence.txt")
        folder = self.root / "case"
        folder.mkdir()
        code, out, _ = self.run_main("--protect", str(evidence), "--destroy", str(evidence),
                                     "--destroy", str(folder))
        self.assertEqual(code, 0)
        responses = self.load("quick-responses-destroy.json")
        self.assertEqual([action["type"] for action in responses["actions"]], ["lock_session", "delete", "power"])
        self.assertEqual(responses["actions"][1]["paths"], [str(evidence.resolve()), str(folder.resolve())])
        self.assertEqual(responses["actions"][2], {"type": "power", "mode": "poweroff", "method": "graceful"})
        self.assertEqual(responses["allowed_roots"], [str(self.root.resolve())])
        service = self.load("quick-service-destroy.json")
        self.assertEqual(service["responses"], "logs/quick-responses-destroy.json")
        self.assertEqual(service["policy"], "logs/quick-block.json")
        self.assertEqual(service["local_lsm"], "logs/quick-lsm.json")
        self.assertIn("[also destroyed on trigger]", out)
        self.assertIn("quick-service-destroy.json check", out)

    def test_emptied_destroy_list_removes_the_old_profile(self):
        evidence = self.make("evidence.txt")
        self.run_main("--destroy", str(evidence))
        self.assertTrue((self.root / "logs" / "quick-service-destroy.json").exists())
        self.run_main("--undestroy", str(evidence))
        for name in quickstart_config.DESTROY_FILES:
            self.assertFalse((self.root / "logs" / name).exists())

    def test_refuses_a_symlink_to_destroy(self):
        target = self.make("evidence.txt")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks need extra privileges on this platform")
        code, _, err = self.run_main("--destroy", str(link))
        self.assertEqual(code, 1)
        self.assertIn("not symlinks", err)

    @unittest.skipUnless(sys.platform == "linux", "response roots are Linux paths")
    def test_destroy_profile_passes_the_response_validator(self):
        sys.path.insert(0, str(ROOT / "src" / "responses"))
        from responses import load_config as load_responses
        evidence = self.make("evidence.txt")
        self.run_main("--destroy", str(evidence))
        config = load_responses(self.root / "logs" / "quick-responses-destroy.json")
        self.assertEqual(config.actions[-1]["type"], "power")

    def test_no_allowed_device_skips_step_a4_and_the_allow_profile(self):
        (self.root / "logs" / "quick-device.json").unlink()
        evidence = self.make("evidence.txt")
        code, out, _ = self.run_main("--no-allowed-device", "--protect", str(evidence), "--destroy", str(evidence))
        self.assertEqual(code, 0)
        self.assertIn("WARNING: no allow profile", out)
        self.assertNotIn("quick-service-allow.json check", out)
        for name in quickstart_config.ALLOW_FILES:
            self.assertFalse((self.root / "logs" / name).exists())
        self.assertEqual(self.load("quick-block.json")["allowlist"], [])
        self.assertEqual(self.load("quick-enforcement.json")["managed_buses"], "auto")
        self.assertTrue((self.root / "logs" / "quick-service-destroy.json").exists())

    def test_no_allowed_device_removes_an_earlier_allow_profile(self):
        self.run_main()
        self.assertTrue((self.root / "logs" / "quick-service-allow.json").exists())
        self.run_main("--no-allowed-device")
        for name in quickstart_config.ALLOW_FILES:
            self.assertFalse((self.root / "logs" / name).exists())

    def test_single_bus_needs_the_drive(self):
        code, _, err = self.run_main("--no-allowed-device", "--single-bus")
        self.assertEqual(code, 1)
        self.assertIn("--single-bus needs the drive", err)

    def test_symlinked_folder_is_stored_as_real_path(self):
        real = self.root / "real"
        real.mkdir()
        (real / "secret.txt").write_text("secret\n")
        (self.root / "alias").symlink_to(real)
        self.run_main("--protect", str(self.root / "alias" / "secret.txt"))
        self.assertEqual(self.load("quick-lsm.json")["protected_paths"][1],
                         str((real / "secret.txt").resolve()))

    def test_refuses_bad_protected_targets(self):
        folder = self.root / "folder"
        folder.mkdir()
        link = self.root / "link.txt"
        link.symlink_to(folder)
        for target, message in ((self.root / "missing.txt", "does not exist"),
                                (folder, "regular files"), (link, "regular files")):
            code, _, err = self.run_main("--protect", str(target))
            self.assertEqual(code, 1)
            self.assertIn(message, err)
        self.assertFalse((self.root / "logs" / "quick-allow.json").exists())

    def test_refuses_hubs(self):
        for change in ({"is_root_hub": True, "usb_id": "usb4"}, {"device_class": "09", "usb_id": "4-2"}):
            self.save_device({**DRIVE, **change})
            code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn(f"{change['usb_id']} is a hub", err)
        self.assertFalse((self.root / "logs" / "quick-allow.json").exists())

    def test_refuses_missing_or_failed_step_4(self):
        device_file = self.root / "logs" / "quick-device.json"
        device_file.write_text('{"schema_version":1,"type":"policy_error","message":"unavailable"}')
        code, _, err = self.run_main()
        self.assertIn("not a device record", err)
        for content in ("", "[]"):
            device_file.write_text(content)
            code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn("step A4", err)
        device_file.unlink()
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("not found. Run step A4 first", err)
        self.assertFalse((self.root / "logs" / "quick-allow.json").exists())

    def test_refuses_when_previous_run_was_not_restored(self):
        for leftover in ("quick-state.json", "quick-state.json.service-owner.json"):
            marker = self.root / "logs" / leftover
            marker.write_text("{}")
            code, _, err = self.run_main()
            self.assertEqual(code, 1)
            self.assertIn("not restored", err)
            marker.unlink()
        self.assertFalse((self.root / "logs" / "quick-allow.json").exists())

    def test_no_serial_means_vendor_and_product_rule(self):
        self.save_device({**DRIVE, "serial": None})
        self.run_main()
        self.assertNotIn("serial", self.load("quick-allow.json")["allowlist"][0])

    def test_summary_shows_drive_and_files(self):
        _, out, _ = self.run_main()
        self.assertIn("ADATA USB Flash Drive", out)
        self.assertIn("bus 4", out)
        self.assertIn("Managed USB buses: all (auto)", out)
        self.assertIn("restricted.txt", out)

if __name__ == "__main__":
    unittest.main()
