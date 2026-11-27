import contextlib
import io
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/daemon"))
import portwatchman  # noqa: E402
from service_summary import Summary  # noqa: E402

DEVICE = {"usb_id": "4-1", "vendor_id": "125f", "product_id": "db8a",
          "manufacturer": "ADATA", "product": "USB Flash Drive"}


def stage(name, kind, **fields):
    return {"type": "service_stage_event", "stage": name, "event": {"schema_version": 1, "type": kind, **fields}}


def status(*counts, failures=0):
    return stage("lsm", "lsm_status", failures=failures, targets=[
        {"target_id": index + 1, "path": f"/vm/file{index + 1}.txt", "denied_opens": count}
        for index, count in enumerate(counts)])


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.summary = Summary(clock=lambda: time.struct_time((2026, 11, 27, 18, 5, 9, 4, 331, 0)))

    def lines(self, *records):
        return [line for line in map(self.summary.line, records) if line is not None]

    def test_startup_sequence_is_a_few_lines(self):
        lines = self.lines(
            {"type": "service_preflight_record", "event": {}},
            {"type": "service_child_started", "stage": "lsm", "pid": 1},
            stage("local", "lsm_local_registered", protected_paths=["/vm/a.txt", "/vm/b.txt"]),
            {"type": "service_bus_arm", "event": {"buses": [{"bus": "usb4"}]}},
            stage("responses", "response_started", actions=["lock_session"]),
            stage("monitor", "monitor_heartbeat"),
            {"type": "service_ready", "apply_responses": False})
        self.assertEqual(lines, [
            "18:05:09  Protecting 2 VM file(s): /vm/a.txt, /vm/b.txt",
            "18:05:09  Armed usb4: new USB devices are blocked until checked",
            "18:05:09  Ready. Response plan: lock_session (preview only)"])

    def test_denials_report_only_the_increase_per_file(self):
        lines = self.lines(status(0, 0), status(0, 0), status(1, 0), status(1, 3), status(1, 3))
        self.assertEqual([line[10:] for line in lines], [
            "Blocked 1 attempt to open /vm/file1.txt (1 so far)",
            "Blocked 3 attempts to open /vm/file2.txt (3 so far)"])

    def test_refused_deletes_are_reported_separately(self):
        record = stage("lsm", "lsm_status", targets=[{"target_id": 1, "path": "/vm/a.txt",
                                                      "denied_opens": 1, "denied_changes": 2}])
        self.assertEqual(self.lines(record)[0].split("\n"), [
            "18:05:09  Blocked 1 attempt to open /vm/a.txt (1 so far)",
            "          Blocked 2 attempts to delete or change /vm/a.txt (2 so far)"])

    def test_protection_failure_is_flagged(self):
        self.assertIn("PROBLEM", self.lines(status(0, failures=1))[0])

    def test_usb_decisions_and_responses(self):
        lines = self.lines(
            stage("enforcement", "enforcement_result", action="allow", usb_id="4-1", enforcement_applied=True,
                  matched_rule="trusted-usb", device=DEVICE),
            stage("monitor", "usb_disconnect_started", usb_id="4-1"),
            stage("enforcement", "enforcement_result", action="block", usb_id="4-1",
                  reason="no_matching_allowlist_rule", device=DEVICE),
            stage("responses", "response_action", action="lock_session", status="ok", applied=False, ok=True),
            stage("responses", "response_action", action="lock_session", status="ok", applied=True, ok=True),
            stage("responses", "response_action", action="lock_session", status="failed", applied=True, ok=False),
            stage("responses", "response_suppressed", reason="cooldown", cooldown_remaining_s=21.4))
        self.assertEqual([line[10:] for line in lines], [
            'USB 4-1 ADATA USB Flash Drive (125f:db8a): ALLOWED by rule "trusted-usb"',
            "USB 4-1 disconnected",
            "USB 4-1 ADATA USB Flash Drive (125f:db8a): BLOCKED (not on the allowlist)",
            "Response lock_session: preview only, not applied",
            "Response lock_session: done",
            "Response lock_session: FAILED (failed)",
            "Response skipped (cooldown, 21s left)"])

    def test_problems_and_stops_are_always_shown(self):
        lines = self.lines(stage("monitor", "monitor_loss", degraded=True, reported_lost_events=2),
                           {"type": "service_error", "message": "policy exited"},
                           {"type": "service_bus_state_retained"},
                           {"type": "service_stopped", "ok": False, "reason": "policy exited"},
                           {"type": "service_stopped", "ok": True})
        self.assertIn("PROBLEM in monitor: monitor_loss", lines[0])
        self.assertIn("ERROR: policy exited", lines[1])
        self.assertIn("WARNING", lines[2])
        self.assertIn("Stopped with a failure: policy exited", lines[3])
        self.assertTrue(lines[4].endswith("Stopped cleanly"))

    def test_previous_boot_and_restore_lines(self):
        lines = self.lines({"type": "service_previous_boot_state_cleared"},
                           {"type": "service_bus_restore", "event": {"buses": [{"bus": "usb4", "restore_to": "1"}]}})
        self.assertIn("set aside", lines[0])
        self.assertTrue(lines[1].endswith("Restored USB defaults: usb4=1"))


class ReporterTests(unittest.TestCase):
    def capture(self, reporter, record):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reporter(record)
        return out.getvalue()

    def test_json_is_still_the_default(self):
        output = self.capture(portwatchman.Reporter(), {"type": "service_ready"})
        self.assertEqual(json.loads(output)["type"], "service_ready")

    def test_summary_hides_routine_records(self):
        reporter = portwatchman.Reporter()
        reporter.summary = Summary()
        self.assertEqual(self.capture(reporter, {"type": "service_child_started"}), "")

    def test_formatting_bug_falls_back_to_json(self):
        reporter = portwatchman.Reporter()
        reporter.summary = Summary()
        output = self.capture(reporter, {"type": "service_bus_arm", "event": {"buses": [{}]}})
        self.assertEqual(json.loads(output)["type"], "service_bus_arm")

    def test_run_accepts_summary(self):
        self.assertTrue(portwatchman.parser().parse_args(["run", "--summary"]).summary)

    def test_installer_copies_the_summary_module(self):
        source = (ROOT / "scripts/install_service.py").read_text()
        self.assertIn('"src/daemon/service_summary.py"', source)


if __name__ == "__main__":
    unittest.main()
