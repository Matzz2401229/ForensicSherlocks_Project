"""Kernel-independent native CLI tests; build the controller in Linux first."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
BINARY = REPO / "src/enforcement/bpf/build/lsm_controller"


@unittest.skipUnless(sys.platform == "linux" and os.access(BINARY, os.X_OK),
                     "Build the native BPF-LSM controller in Ubuntu first")
class NativeControllerTests(unittest.TestCase):
    def setUp(self):
        base = REPO / "build/test-tmp"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temporary.name)
        if self.root.resolve().parent != base.resolve():
            raise RuntimeError("Fixture escaped workspace")
        self.addCleanup(self.temporary.cleanup)
        self.file = self.root / "host-file.txt"
        self.file.write_text("Local fixture\n", encoding="utf-8")

    def run_controller(self, *args):
        return subprocess.run([str(BINARY), *map(str, args)], capture_output=True,
                              text=True, timeout=10)

    def rejected(self, *args, reason="invalid_target"):
        result = self.run_controller(*args)
        self.assertNotEqual(result.returncode, 0)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(any(row.get("type") == "lsm_error" and row.get("reason") == reason
                            for row in rows), result)
        self.assertFalse(any(row.get("type") == "lsm_ready" for row in rows))

    def test_missing_target_is_rejected(self):
        self.rejected("--inspect", self.root / "missing")

    def test_directory_is_rejected(self):
        self.rejected("--inspect", self.root)

    def test_final_symlink_is_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.file.name)
        self.rejected("--inspect", link)

    def test_host_filesystem_is_not_accepted_as_usb(self):
        self.rejected("--usb", "--inspect", self.file)

    def test_host_filesystem_is_not_accepted_as_loop(self):
        self.rejected("--test-loopback", "--inspect", self.file)

    def test_target_limit_is_checked_before_loading(self):
        self.rejected(*([self.file] * 129), reason="invalid_arguments")

    def test_unknown_option_fails(self):
        self.assertNotEqual(self.run_controller("--unknown").returncode, 0)

    def test_help_does_not_require_kernel_access(self):
        result = self.run_controller("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--control-stdin", result.stdout)


if __name__ == "__main__":
    unittest.main()
