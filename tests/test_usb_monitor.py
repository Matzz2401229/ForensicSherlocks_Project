import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "monitor"))
from usb_monitor import Decoder, LOSS, emit, run_monitor


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder("test-boot")

    def frame(self, kind, timestamp=100, start=100, bus=2, address=7, port="1", result=0):
        return f"PW1\t{kind}\t{timestamp}\t{start}\t{bus}\t{address}\t{port}\t{result}\n"

    def test_complete_cycle_keeps_generation(self):
        start = self.decoder.decode(self.frame("setup_started"), 105)
        done = self.decoder.decode(self.frame("setup_result", timestamp=120), 130)
        disconnect = self.decoder.decode(self.frame("disconnect_started", timestamp=200, start=0))
        self.assertEqual(start["connection_id"], done["connection_id"])
        self.assertEqual(done["connection_id"], disconnect["connection_id"])
        self.assertEqual(done["setup_duration_ns"], 20)
        self.assertEqual(done["delivery_delay_ns"], 10)
        self.assertEqual(done["sysfs_path"], "/sys/bus/usb/devices/2-1")

    def test_failure_is_not_success_and_clears_generation(self):
        self.decoder.decode(self.frame("setup_started"))
        failed = self.decoder.decode(self.frame("setup_result", timestamp=120, result=-19))
        disconnected = self.decoder.decode(self.frame("disconnect_started", timestamp=200, start=0))
        self.assertEqual(failed["type"], "usb_setup_failed")
        self.assertEqual(failed["result"], -19)
        self.assertIsNone(disconnected["connection_id"])

    def test_missing_start_can_be_correlated_from_result(self):
        done = self.decoder.decode(self.frame("setup_result", timestamp=120))
        self.assertEqual(done["connection_id"], "test-boot:2-1:100")

    def test_preexisting_device_disconnect_is_unknown(self):
        record = self.decoder.decode(self.frame("disconnect_started", timestamp=200, start=0))
        self.assertIsNone(record["connection_id"])

    def test_reconnect_changes_generation(self):
        first = self.decoder.decode(self.frame("setup_started"))
        second = self.decoder.decode(self.frame("setup_started", timestamp=300, start=300, address=8))
        self.assertNotEqual(first["connection_id"], second["connection_id"])

    def test_duplicates_are_flagged_not_hidden(self):
        first = self.decoder.decode(self.frame("setup_started"))
        second = self.decoder.decode(self.frame("setup_started"))
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])

    def test_late_start_cannot_resurrect_disconnected_generation(self):
        self.decoder.decode(self.frame("setup_started"))
        self.decoder.decode(self.frame("disconnect_started", timestamp=200, start=0))
        self.decoder.decode(self.frame("setup_started"))
        later = self.decoder.decode(self.frame("disconnect_started", timestamp=250, start=0))
        self.assertIsNone(later["connection_id"])

    def test_hub_paths_and_root_hub(self):
        child = self.decoder.decode(self.frame("setup_started", port="1.2"))
        root = self.decoder.decode(self.frame("setup_started", address=1, port="0"))
        self.assertEqual(child["usb_id"], "2-1.2")
        self.assertEqual(root["usb_id"], "usb2")
        self.assertTrue(root["is_root_hub"])

    def test_malformed_frames_rejected(self):
        for frame in ("garbage", "PW1\theartbeat\t0", self.frame("setup_started", port="../bad"),
                      self.frame("setup_started", bus=0), self.frame("setup_started", address=128),
                      self.frame("setup_started", start=101), self.frame("setup_result", result=1),
                      self.frame("disconnect_started", start=100), "PW1\tunknown\t100"):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                self.decoder.decode(frame)

    def test_success_does_not_invent_authorisation(self):
        done = self.decoder.decode(self.frame("setup_result", timestamp=120))
        self.assertEqual(done["type"], "usb_setup_completed")
        self.assertNotIn("authorized", done)

    def test_metadata_memory_is_bounded(self):
        for index in range(2200):
            self.decoder.decode(self.frame("setup_started", timestamp=index+1, start=index+1,
                                           bus=index+1))
        self.assertLessEqual(len(self.decoder.connections), 1024)
        self.assertLessEqual(len(self.decoder.seen), 2048)

    def test_lifecycle_frames(self):
        self.assertEqual(self.decoder.decode("PW1\theartbeat\t100\n")["type"], "monitor_heartbeat")
        self.assertEqual(self.decoder.decode("PW1\tbackend_stopped\t100\n")["type"],
                         "monitor_backend_stopped")

    def test_loss_message_count(self):
        self.assertEqual(int(LOSS.search("Lost 12 events").group(1)), 12)

    def test_output_is_one_json_record_per_line(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            emit({"type": "monitor_diagnostic", "message": 'quote " and newline\n'})
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        record = json.loads(output.getvalue())
        self.assertEqual(record["schema_version"], 1)


class SupervisorTests(unittest.TestCase):
    def exercise(self, stdout, stderr="", duration=None):
        process = mock.Mock()
        process.stdout = io.StringIO(stdout)
        process.stderr = io.StringIO(stderr)
        process.poll.return_value = None if duration is not None else 3
        process.returncode = 3
        captured = io.StringIO()
        with mock.patch("usb_monitor.Path.read_text", return_value="test-boot"), \
             mock.patch("usb_monitor.subprocess.Popen", return_value=process), \
             mock.patch("usb_monitor.stop_backend") as cleanup, \
             contextlib.redirect_stdout(captured), contextlib.redirect_stderr(io.StringIO()):
            result = run_monitor(duration)
        cleanup.assert_called_once_with(process)
        return result, [json.loads(line) for line in captured.getvalue().splitlines()]

    def test_unexpected_backend_exit_fails_and_preserves_received_events(self):
        status, records = self.exercise("PW1\tsetup_started\t100\t100\t2\t7\t1\t0\n")
        self.assertEqual(status, 1)
        self.assertTrue(any(r["type"] == "monitor_error" for r in records))
        self.assertEqual(records[-1]["event_counts"]["usb_setup_started"], 1)
        self.assertEqual(records[-1]["reason"], "error")

    def test_loss_is_exposed_as_degraded_monitoring(self):
        status, records = self.exercise("PW1\theartbeat\t100\n", "Lost 12 events\n")
        self.assertEqual(status, 1)  # mock backend then exits unexpectedly
        self.assertTrue(any(r["type"] == "monitor_loss" for r in records))
        self.assertEqual(records[-1]["reported_lost_events"], 12)
        self.assertTrue(records[-1]["degraded"])

    def test_duration_stop_cleans_up_without_reporting_backend_failure(self):
        status, records = self.exercise("PW1\theartbeat\t100\n", duration=0.01)
        self.assertEqual(status, 0)
        self.assertEqual(records[-1]["reason"], "duration_elapsed")
        self.assertFalse(any(r["type"] == "monitor_error" for r in records))


if __name__ == "__main__":
    unittest.main()
