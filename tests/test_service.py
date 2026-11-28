"""Service config/supervision tests: fake children; Linux locks use owned fixtures."""
import contextlib
from dataclasses import replace
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/daemon"))
import portwatchman
import service_runtime
from service_config import Config, ServiceError, commands, load_config
from service_runtime import Health, Host, Lease, Supervisor


OLD_BOOT = "0f3c2a11-5d6e-4f70-8a91-b2c3d4e5f607"
CURRENT_BOOT = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d"


def event(kind, **fields):
    return {"schema_version": 1, "type": kind, **fields}


class Fixture(unittest.TestCase):
    def setUp(self):
        base = ROOT / "build/test-tmp"
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.config = Config(self.directory / "allow.json", self.directory / "enforcement.json",
                             self.directory / "responses.json", startup_timeout=1, shutdown_timeout=1)

    def document(self, **fields):
        path = self.directory / "service.json"
        path.write_text(json.dumps({"schema_version": 1, **fields}))
        return path


class ConfigTests(Fixture):
    def test_default_profile_has_preview_responses_and_no_lsm(self):
        config = load_config(ROOT / "config/service.json")
        self.assertFalse(config.apply_responses)
        self.assertIsNone(config.lsm)

    def test_relative_paths_resolve_against_repository(self):
        config = load_config(self.document(policy="config/allowlist.json"))
        self.assertEqual(config.policy, ROOT / "config/allowlist.json")

    def test_policy_path_is_identical_for_both_stages(self):
        plan = commands(self.config)
        for stage in ("policy", "enforcement"):
            self.assertEqual(plan[stage][plan[stage].index("--policy") + 1], str(self.config.policy))

    def test_preview_has_no_apply_but_enforcement_is_live(self):
        plan = commands(self.config)
        self.assertNotIn("--apply", plan["responses"])
        self.assertNotIn("--dry-run", plan["enforcement"])

    def test_applied_responses_are_explicit(self):
        config = load_config(self.document(apply_responses=True))
        self.assertIn("--apply", commands(config)["responses"])

    def test_bridge_is_opt_in(self):
        config = load_config(self.document(lsm="logs/owned-lsm.json"))
        self.assertIn("--lsm-config", commands(config)["enforcement"])
        self.assertNotIn("--lsm-config", commands(self.config)["enforcement"])

    def test_vm_guard_is_opt_in_and_not_a_usb_bridge(self):
        config = load_config(self.document(local_lsm="logs/vm-files.json"))
        self.assertTrue(config.lsm_enabled)
        self.assertEqual(config.lsm_scope, "vm-files")
        self.assertNotIn("--lsm-config", commands(config)["enforcement"])
        self.assertEqual(config.local_lsm, ROOT / "logs/vm-files.json")

    def test_vm_and_usb_modes_cannot_be_combined(self):
        with self.assertRaises(ServiceError):
            load_config(self.document(local_lsm="logs/vm-files.json", lsm="logs/usb-files.json"))

    def test_empty_vm_config_path_is_rejected(self):
        with self.assertRaises(ServiceError):
            load_config(self.document(local_lsm=""))

    def test_local_controller_command_does_not_use_usb_mode(self):
        host = object.__new__(Host)
        host.local_guard = SimpleNamespace(config=SimpleNamespace(socket_path="/run/portwatchman/lsm_controller.sock"))
        command = host.controller_command()
        self.assertIn("--local-files", command)
        self.assertNotIn("--usb", command)

    def test_rejects_bad_types_and_unknown_fields(self):
        for fields in ({"schema_version": True}, {"apply_responses": "yes"}, {"policy": []},
                       {"unknown": 1}, {"startup_timeout": False}, {"shutdown_timeout": 0},
                       {"command_timeout": 61}, {"lsm": ""}):
            with self.subTest(fields=fields), self.assertRaises(ServiceError):
                load_config(self.document(**fields))

    def test_duplicate_and_nonfinite_json_rejected(self):
        path = self.directory / "bad.json"
        for raw in ('{"schema_version":1,"schema_version":1}',
                    '{"schema_version":1,"startup_timeout":NaN}'):
            path.write_text(raw)
            with self.assertRaises(ServiceError):
                load_config(path)

    def test_oversized_config_rejected(self):
        path = self.directory / "bad.json"
        path.write_bytes(b" " * 65537)
        with self.assertRaises(ServiceError):
            load_config(path)

    def test_controller_uses_socket_option_without_enrolling_socket_as_a_file(self):
        host = object.__new__(Host)
        host.bridge = SimpleNamespace(socket_path="/run/portwatchman/lsm_controller.sock")
        command = host.controller_command()
        self.assertEqual(command[-2:], ["--socket", host.bridge.socket_path])
        self.assertIn("--usb", command)
        self.assertIn("--serve", command)


class HealthTests(unittest.TestCase):
    def populate(self, health):
        health.observe("monitor", event("monitor_alive"))
        for stage in ("policy", "enforcement", "responses"):
            health.observe(stage, event({"policy": "policy_monitor_status", "enforcement": "enforcement_monitor_status",
                                         "responses": "response_monitor_status"}[stage], healthy=True))
        health.observe("enforcement", event("enforcement_started"))
        health.observe("responses", event("response_started"))

    def test_readiness_needs_all_stages(self):
        health = Health()
        health.observe("responses", event("response_started"))
        self.assertFalse(health.ready())
        self.populate(health)
        self.assertTrue(health.ready())

    def test_lsm_requires_controller_and_bridge_readiness(self):
        health = Health(lsm=True)
        self.populate(health)
        self.assertFalse(health.ready())
        health.observe("lsm", event("lsm_ready", mode="usb"))
        self.assertFalse(health.ready())
        health.observe("enforcement", event("lsm_bridge_started"))
        self.assertTrue(health.ready())

    def test_vm_guard_requires_local_registration_not_usb_bridge(self):
        health = Health(lsm=True, local_files=True)
        self.populate(health)
        health.observe("lsm", event("lsm_ready", mode="local-files"))
        health.observe("enforcement", event("lsm_bridge_started"))
        self.assertFalse(health.ready())
        health.observe("local", event("lsm_local_registered", protection_complete=False))
        self.assertFalse(health.ready())
        health.observe("local", event("lsm_local_registered", protection_complete=True))
        self.assertTrue(health.ready())

    def test_vm_guard_rejects_usb_controller_mode(self):
        health = Health(lsm=True, local_files=True)
        health.observe("lsm", event("lsm_ready", mode="usb"))
        self.assertIsNotNone(health.failure())

    def test_starting_status_and_already_blocked_are_not_failures(self):
        health = Health()
        health.observe("responses", event("response_monitor_status", healthy=False, monitor_type="monitor_starting"))
        health.observe("enforcement", event("enforcement_result", action="block", enforcement_applied=False,
                                             reason="already_blocked"))
        self.assertIsNone(health.failure())

    def test_errors_degradation_and_failed_actions_latch_failure(self):
        for record in (event("monitor_loss", degraded=True), event("response_action", ok=False),
                       event("lsm_bridge_error", message="lost controller")):
            with self.subTest(record=record):
                health = Health()
                health.observe("responses", record)
                self.populate(health)
                self.assertFalse(health.ready())
                self.assertIsNotNone(health.failure())

    def test_controller_loopback_mode_rejected(self):
        health = Health(lsm=True)
        health.observe("lsm", event("lsm_ready", mode="test-loopback"))
        self.assertIsNotNone(health.failure())

    def test_invalid_schema_and_nonstring_type_rejected(self):
        for record in ({"schema_version": True, "type": "monitor_alive"}, event([])):
            with self.subTest(record=record), self.assertRaises(ServiceError):
                Health().observe("monitor", record)

    def test_clean_close_is_recorded_without_failure(self):
        health = Health()
        health.observe("responses", event("response_stream_closed", ok=True))
        self.assertIsNone(health.failure())
        self.assertIn("responses", health.closing)


class FakeProcess:
    next_pid = 100
    def __init__(self, stage):
        FakeProcess.next_pid += 1
        self.pid = FakeProcess.next_pid
        self.stage = stage
        self.returncode = None
        self.stdin = io.BytesIO()
    def poll(self):
        return self.returncode
    def wait(self):
        return self.returncode


class FakeHost:
    def __init__(self, processes, fail_at=None):
        self.processes = processes
        self.calls = []
        self.fail_at = fail_at
    def prepare(self):
        self.calls.append("prepare")
    def preflight(self):
        self.calls.append("preflight")
        if self.fail_at == "preflight":
            raise ServiceError("injected preflight error")
    def arm(self):
        self.calls.append("arm")
        if self.fail_at == "arm":
            raise ServiceError("injected partial arm error")
        return {"applied": True}
    def restore(self):
        self.calls.append("restore")
        if self.fail_at == "restore":
            raise OSError("injected restore error")
        return {"applied": True}
    def controller_command(self):
        return ["fake-controller"]
    def register_local(self, deadline):
        self.calls.append("register_local")
        if self.fail_at == "register_local":
            raise ServiceError("injected local registration failure")
        return event("lsm_local_registered", protection_complete=True)
    def exempt_responder(self, pid):
        self.calls.append(("exempt", pid))
        if self.fail_at == "exempt":
            raise ServiceError("injected exemption failure")
        return event("lsm_local_exempted", pid=pid)
    def check_local(self, *, force=False):
        self.calls.append("check_local")
        if self.fail_at == "check_local":
            raise ServiceError("injected local guard loss")
    def signal(self, process, sig):
        self.calls.append((process.stage, sig))
        if process.stage == "monitor":
            for name, child in self.processes.items():
                if name != "lsm" and child.returncode is None:
                    child.returncode = 0
        else:
            process.returncode = 0
    def orphans(self, processes):
        self.calls.append("orphans")
        return self.fail_at != "orphans"


class Harness(Supervisor):
    def spawn(self, stage, args, destination=None):
        process = FakeProcess(stage)
        self.processes[stage] = process
        self.host.calls.append(("spawn", stage))
        self.health.flags.add(stage)
        if stage == "enforcement":
            self.health.flags.add("enforcement_started")
            self.health.flags.add("bridge")
        if stage == "responses":
            self.health.flags.add("response_started")
        return process


class SupervisionTests(Fixture):
    def harness(self, fail_at=None, lsm=False, unexpected=False, local_files=False):
        if local_files:
            self.config = replace(self.config, local_lsm=self.directory / "local.json")
        if lsm:
            self.config = Config(self.config.policy, self.config.enforcement, self.config.responses,
                                 self.directory / "lsm.json", shutdown_timeout=1)
        output = []
        states = []
        host = FakeHost({}, fail_at)
        supervisor = None
        def notified(message):
            if message.startswith("READY=1"):
                if unexpected:
                    supervisor.processes["responses"].returncode = 1
                else:
                    supervisor.stop.set()
        supervisor = Harness(self.config, host, output.append,
                             state=lambda phase, data: states.append((phase, data)), notifier=notified)
        host.processes = supervisor.processes
        return supervisor, host, output, states

    def test_normal_stop_restores_after_controller_stops(self):
        supervisor, host, output, states = self.harness(lsm=True)
        self.assertEqual(supervisor.run(), 0)
        self.assertLess(host.calls.index(("monitor", signal.SIGINT)), host.calls.index(("lsm", signal.SIGINT)))
        self.assertLess(host.calls.index(("lsm", signal.SIGINT)), host.calls.index("restore"))
        self.assertEqual(states[-1][0], "stopped")
        self.assertTrue(output[-1]["buses_restored"])

    def test_pipeline_starts_downstream_first(self):
        supervisor, host, _, _ = self.harness()
        self.assertEqual(supervisor.run(), 0)
        self.assertEqual([call[1] for call in host.calls if isinstance(call, tuple) and call[0] == "spawn"],
                         ["responses", "enforcement", "policy", "monitor"])

    def test_unexpected_exit_keeps_bus_state_for_recovery(self):
        supervisor, host, output, _ = self.harness(unexpected=True)
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn("restore", host.calls)
        self.assertTrue(any(r["type"] == "service_bus_state_retained" for r in output))

    def test_preflight_failure_never_arms(self):
        supervisor, host, _, _ = self.harness(fail_at="preflight")
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn("arm", host.calls)

    def test_local_files_are_registered_before_usb_arming_and_readiness(self):
        supervisor, host, output, _ = self.harness(local_files=True)
        self.assertEqual(supervisor.run(), 0)
        self.assertLess(host.calls.index("register_local"), host.calls.index("arm"))
        self.assertLess(host.calls.index("register_local"), host.calls.index(("spawn", "monitor")))
        ready = next(row for row in output if row["type"] == "service_ready")
        self.assertEqual(ready["lsm_scope"], "vm-files")
        self.assertTrue(ready["lsm_enabled"])
        self.assertIn("restore", host.calls)

    def test_response_stage_is_exempted_before_usb_events_can_reach_it(self):
        supervisor, host, output, _ = self.harness(local_files=True)
        self.assertEqual(supervisor.run(), 0)
        exempt = next(call for call in host.calls if isinstance(call, tuple) and call[0] == "exempt")
        self.assertEqual(exempt[1], supervisor.processes["responses"].pid)
        self.assertLess(host.calls.index(("spawn", "responses")), host.calls.index(exempt))
        self.assertLess(host.calls.index(exempt), host.calls.index(("spawn", "enforcement")))
        self.assertTrue(any(row.get("event", {}).get("type") == "lsm_local_exempted" for row in output))

    def test_failed_exemption_stops_before_readiness(self):
        supervisor, host, output, _ = self.harness(local_files=True, fail_at="exempt")
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn(("spawn", "monitor"), host.calls)
        self.assertFalse(any(row["type"] == "service_ready" for row in output))

    def test_no_exemption_without_vm_file_protection(self):
        supervisor, host, _, _ = self.harness()
        self.assertEqual(supervisor.run(), 0)
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "exempt" for call in host.calls))

    def test_failed_vm_registration_stops_controller_without_arming_or_ready(self):
        supervisor, host, output, _ = self.harness(local_files=True, fail_at="register_local")
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn("arm", host.calls)
        self.assertIn(("lsm", signal.SIGINT), host.calls)
        self.assertFalse(any(row["type"] == "service_ready" for row in output))

    def test_lost_vm_registration_fails_service_and_retains_usb_deny(self):
        supervisor, host, output, _ = self.harness(local_files=True, fail_at="check_local")
        supervisor.notifier = lambda message: None
        self.assertEqual(supervisor.run(), 1)
        self.assertIn("check_local", host.calls)
        self.assertNotIn("restore", host.calls)
        self.assertFalse(output[-1]["ok"])
        self.assertIn("local guard loss", output[-1]["reason"])

    def test_partial_arm_failure_preserves_recovery_state(self):
        supervisor, host, output, _ = self.harness(fail_at="arm")
        self.assertEqual(supervisor.run(), 1)
        self.assertTrue(supervisor.arm_attempted)
        self.assertNotIn("restore", host.calls)
        self.assertTrue(any(r["type"] == "service_bus_state_retained" for r in output))

    def test_restore_error_is_a_failed_stop(self):
        supervisor, _, output, _ = self.harness(fail_at="restore")
        self.assertEqual(supervisor.run(), 1)
        self.assertFalse(output[-1]["buses_restored"])

    def test_unverified_orphan_cleanup_does_not_restore_buses(self):
        supervisor, host, output, _ = self.harness(fail_at="orphans")
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn("restore", host.calls)
        self.assertFalse(output[-1]["buses_restored"])

    def test_stop_requested_before_starting_components_is_clean(self):
        supervisor, host, _, _ = self.harness()
        supervisor.stop.set()
        self.assertEqual(supervisor.run(), 0)
        self.assertNotIn("arm", host.calls)

    def test_notify_failure_is_reported_without_skipping_cleanup(self):
        supervisor, host, _, _ = self.harness()
        supervisor.notifier = mock.Mock(side_effect=OSError("notify unavailable"))
        # Startup notification fails; next loop iteration observes the failure.
        self.assertEqual(supervisor.run(), 1)
        self.assertIn("orphans", host.calls)

    def test_relay_preserves_wire_data_and_records_event(self):
        supervisor, _, output, _ = self.harness()
        class Sink(io.BytesIO):
            def close(self):
                self.saved = self.getvalue()
                super().close()
        source = (json.dumps(event("enforcement_result", action="block", enforcement_applied=False)) + "\n").encode()
        sink = Sink()
        supervisor.relay("enforcement", io.BytesIO(source), sink)
        self.assertEqual(sink.saved, source)
        self.assertEqual(output[0]["event"]["type"], "enforcement_result")

    def test_malformed_child_output_fails_supervision(self):
        supervisor, _, _, _ = self.harness()
        supervisor.relay("policy", io.BytesIO(b"not json\n"))
        self.assertIsNotNone(supervisor.health.failure())

    def test_stderr_is_logged_as_diagnostic_not_forwarded(self):
        supervisor, _, output, _ = self.harness()
        supervisor.relay("monitor", io.BytesIO(b"diagnostic\n"), diagnostic=True)
        self.assertEqual(output[0]["type"], "service_diagnostic")
        self.assertIsNone(supervisor.health.failure())

    def test_readiness_does_not_override_known_failure(self):
        supervisor, _, _, _ = self.harness()
        supervisor.health.fail("injected component failure")
        with self.assertRaises(ServiceError):
            supervisor.wait_for(lambda: True, 1)

    def test_readiness_does_not_override_requested_cancellation(self):
        supervisor, _, _, _ = self.harness()
        supervisor.stop.set()
        with self.assertRaises(ServiceError):
            supervisor.wait_for(lambda: True, 1)

    def test_status_write_failure_prevents_arming(self):
        supervisor, host, _, _ = self.harness()
        supervisor.state = mock.Mock(side_effect=OSError("status storage failed"))
        self.assertEqual(supervisor.run(), 1)
        self.assertNotIn("arm", host.calls)


@unittest.skipUnless(sys.platform == "linux", "Linux file locking and Unix file semantics")
class OwnershipTests(Fixture):
    def test_second_instance_is_refused_then_allowed_after_release(self):
        directory = self.directory / "runtime"
        first, second = Lease(directory), Lease(directory)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.acquire()
        with self.assertRaises(ServiceError):
            second.acquire()
        first.close()
        second.acquire()

    def test_lock_symlink_is_refused(self):
        directory = self.directory / "runtime"
        directory.mkdir(mode=0o700)
        witness = self.directory / "witness"
        witness.write_text("keep")
        directory.with_name(directory.name + ".lock").symlink_to(witness)
        with self.assertRaises(OSError):
            Lease(directory).acquire()
        self.assertEqual(witness.read_text(), "keep")

    def test_removing_status_directory_cannot_bypass_live_lock(self):
        directory = self.directory / "runtime"
        first, second = Lease(directory), Lease(directory)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.acquire()
        directory.rmdir()  # Simulate runtime-directory cleanup; the lock stays outside it.
        with self.assertRaises(ServiceError):
            second.acquire()


class InterfaceTests(Fixture):
    def test_validate_does_not_spawn_or_arm(self):
        response = SimpleNamespace(actions=[{"type": "lock_session"}])
        output = io.StringIO()
        with mock.patch.object(portwatchman, "load_config", return_value=self.config), \
                mock.patch.object(portwatchman, "components", return_value=(None, None, response, None)), \
                mock.patch.object(portwatchman, "Host") as host, contextlib.redirect_stdout(output):
            self.assertEqual(portwatchman.main(["validate"]), 0)
        host.assert_not_called()
        self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_run_requires_linux_root_before_starting_children(self):
        with mock.patch.object(portwatchman, "load_config", return_value=self.config), \
                mock.patch.object(portwatchman, "require_linux_root", side_effect=ServiceError("root required")), \
                mock.patch.object(portwatchman, "Host") as host, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(portwatchman.main(["run"]), 1)
        host.assert_not_called()

    def test_broken_logging_reports_failure_without_raising(self):
        reporter = portwatchman.Reporter()
        failures = []
        reporter.on_error = failures.append
        with mock.patch("builtins.print", side_effect=BrokenPipeError("closed")):
            reporter(event("test"))
        self.assertEqual(len(failures), 1)

    def test_stale_pid_identity_is_not_reported_healthy(self):
        (self.directory / "status.json").write_text(json.dumps({"pid": 123, "boot_id": "old",
            "process_start_ticks": "10", "phase": "running", "healthy": True}))
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        with mock.patch.object(portwatchman, "require_linux_root"), \
                mock.patch.object(Path, "lstat", return_value=metadata), \
                mock.patch.object(portwatchman, "boot_id", return_value="new"):
            result = portwatchman.status(self.directory)
        self.assertFalse(result["running"])
        self.assertFalse(result["healthy"])

    def test_unit_notifies_readiness_and_preserves_ordered_shutdown(self):
        text = (ROOT / "systemd/portwatchman.service").read_text()
        self.assertIn("Type=notify", text)
        self.assertIn("KillMode=mixed", text)
        self.assertIn("Restart=no", text)
        self.assertIn("RuntimeDirectoryPreserve=yes", text)
        self.assertNotIn("ExecStart=/bin/sh", text)


class InstallationTests(Fixture):
    def module(self):
        spec = importlib.util.spec_from_file_location("pw_install_service", ROOT / "scripts/install_service.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_installed_config_uses_private_state_and_preserves_policy(self):
        module = self.module()
        self.config.policy.write_text('{"schema_version":1,"default_action":"block","allowlist":[]}')
        self.config.enforcement.write_text('{"schema_version":1,"managed_buses":["usb3"],"state_file":"logs/source-state.json"}')
        self.config.responses.write_text('{"schema_version":1,"actions":[{"type":"lock_session"}]}')
        enforcement = SimpleNamespace(state_file=self.directory / "source-state.json")
        with mock.patch.object(module, "components", return_value=(None, enforcement, None, None)):
            result = module.payloads(self.config)
        self.assertEqual(result["allowlist.json"], self.config.policy.read_bytes())
        self.assertEqual(json.loads(result["enforcement.json"])["state_file"], str(module.DATA / "enforcement-state.json"))
        self.assertFalse(json.loads(result["service.json"])["apply_responses"])

    def test_source_arm_state_blocks_installation(self):
        module = self.module()
        state = self.directory / "state.json"
        state.write_text("{}")
        with mock.patch.object(module, "components", return_value=(None, SimpleNamespace(state_file=state), None, None)), \
                self.assertRaises(ServiceError):
            module.payloads(self.config)

    def test_installer_preserves_vm_file_config_and_separate_installed_path(self):
        module = self.module()
        self.config.policy.write_text('{}')
        self.config.enforcement.write_text('{}')
        self.config.responses.write_text('{}')
        local = self.directory / "local.json"
        local.write_text('{"schema_version":1,"socket_path":"/run/portwatchman/lsm_controller.sock",'
                         '"protected_paths":["/var/tmp/demo/restricted.txt"]}')
        config = replace(self.config, local_lsm=local)
        with mock.patch.object(module, "components", return_value=(None, SimpleNamespace(state_file=self.directory / "state"), None, None)):
            result = module.payloads(config)
        installed = json.loads(result["service.json"])
        self.assertEqual(installed["local_lsm"], str(module.ETC / "lsm-local.json"))
        self.assertIsNone(installed["lsm"])
        self.assertEqual(result["lsm-local.json"], local.read_bytes())
        self.assertIn("src/enforcement/lsm_local.py", module.FILES)

    def test_install_manifest_excludes_runtime_data_and_discarded_fix(self):
        files = self.module().FILES
        self.assertTrue(all(name.startswith("src/") for name in files))
        self.assertNotIn("src/responses/response_stream.py", files)
        self.assertIn("src/responses/response_delete.py", files)

    def test_installer_refuses_a_user_writable_ancestor(self):
        module = self.module()
        unsafe = self.directory.parent
        def metadata(path, *args, **kwargs):
            return SimpleNamespace(st_mode=stat.S_IFDIR | (0o777 if path == unsafe else 0o755), st_uid=0)
        with mock.patch.object(Path, "lstat", autospec=True, side_effect=metadata), self.assertRaises(ServiceError):
            module.directory(self.directory / "owned-install", 0o755)


class RecoveryTests(Fixture):
    def prepare(self, boot="current"):
        directory = str(ROOT / "src/enforcement")
        sys.path.insert(0, directory)
        import usb_authorization
        state = self.directory / "state.json"
        state.write_text("{}")
        marker = service_runtime.owner_path(state)
        marker.write_text(json.dumps({"boot_id": boot, "state_file": str(state)}))
        return state, marker, usb_authorization

    def test_owned_state_restores_and_clears_owner_only_after_success(self):
        state, marker, module = self.prepare()
        with mock.patch.object(service_runtime, "boot_id", return_value="current"), \
                mock.patch.object(module, "restore", return_value={"applied": True}) as restore:
            self.assertTrue(service_runtime.restore_owned(object(), state)["applied"])
        restore.assert_called_once()
        self.assertFalse(marker.exists())

    def test_old_boot_state_is_set_aside_without_writing_defaults(self):
        state, marker, module = self.prepare(boot=OLD_BOOT)
        state.write_text(json.dumps({"schema_version": 1, "buses": {"usb4": {"original_default": "1"}}}))
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                mock.patch.object(module, "restore") as restore:
            result = service_runtime.restore_owned(object(), state)
        restore.assert_not_called()
        self.assertEqual(result["type"], "service_previous_boot_state_cleared")
        self.assertFalse(result["buses_written"])
        self.assertEqual(result["saved_buses"], {"usb4": {"original_default": "1"}})
        self.assertFalse(state.exists() or marker.exists())
        archived = [Path(path) for path in result["archived"]]
        self.assertEqual([path.name for path in archived],
                         ["state.json.previous-boot-0f3c2a11", "state.json.service-owner.json.previous-boot-0f3c2a11"])
        self.assertTrue(all(path.exists() for path in archived))

    def test_old_boot_marker_without_state_is_set_aside(self):
        state, marker, module = self.prepare(boot=OLD_BOOT)
        state.unlink()
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT):
            result = service_runtime.restore_owned(object(), state)
        self.assertEqual(result["saved_buses"], {})
        self.assertFalse(marker.exists())

    def test_unverifiable_old_owner_is_still_refused(self):
        for boot in ("old", "", None):
            state, marker, module = self.prepare(boot=boot)
            with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                    mock.patch.object(module, "restore") as restore, self.assertRaises(ServiceError):
                service_runtime.restore_owned(object(), state)
            restore.assert_not_called()
            self.assertTrue(marker.exists() and state.exists())

    def test_owner_for_another_state_path_is_refused(self):
        state, marker, module = self.prepare(boot=OLD_BOOT)
        marker.write_text(json.dumps({"boot_id": OLD_BOOT, "state_file": "/elsewhere/state.json"}))
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                self.assertRaises(ServiceError):
            service_runtime.restore_owned(object(), state)
        self.assertTrue(marker.exists())

    def preflight_host(self, state, clear):
        host = object.__new__(Host)
        records = []
        host.emit = records.append
        host.clear_previous_boot = clear
        host.enforcement = SimpleNamespace(state_file=state)
        # Stop at the first step after the saved-state check.
        host.manager = SimpleNamespace(discover=mock.Mock(side_effect=RuntimeError("past state check")))
        return host, records

    def test_run_preflight_sets_aside_previous_boot_state(self):
        state, marker, _ = self.prepare(boot=OLD_BOOT)
        host, records = self.preflight_host(state, clear=True)
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                self.assertRaisesRegex(RuntimeError, "past state check"):
            host.preflight()
        self.assertEqual(records[0]["type"], "service_previous_boot_state_cleared")
        self.assertFalse(state.exists() or marker.exists())

    def test_check_preflight_reports_previous_boot_state_without_changes(self):
        state, marker, _ = self.prepare(boot=OLD_BOOT)
        host, records = self.preflight_host(state, clear=False)
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                self.assertRaisesRegex(RuntimeError, "past state check"):
            host.preflight()
        self.assertEqual(records[0]["type"], "service_previous_boot_state_found")
        self.assertTrue(state.exists() and marker.exists())

    def test_current_boot_state_still_blocks_startup(self):
        state, marker, _ = self.prepare(boot=CURRENT_BOOT)
        state.write_text(json.dumps({"schema_version": 1, "buses": {}}))
        host, records = self.preflight_host(state, clear=True)
        with mock.patch.object(service_runtime, "boot_id", return_value=CURRENT_BOOT), \
                self.assertRaisesRegex(ServiceError, "Existing arm state"):
            host.preflight()
        self.assertTrue(state.exists() and marker.exists())

    def test_restore_failure_retains_owner_for_retry(self):
        state, marker, module = self.prepare()
        with mock.patch.object(service_runtime, "boot_id", return_value="current"), \
                mock.patch.object(module, "restore", side_effect=OSError("write failed")), \
                self.assertRaises(OSError):
            service_runtime.restore_owned(object(), state)
        self.assertTrue(marker.exists())

    def test_foreign_manual_state_is_not_adopted(self):
        state, marker, module = self.prepare()
        marker.unlink()
        with mock.patch.object(module, "restore") as restore, self.assertRaises(ServiceError):
            service_runtime.restore_owned(object(), state)
        restore.assert_not_called()

    def test_preflight_timeout_kills_its_process_group(self):
        host = object.__new__(Host)
        host.config = SimpleNamespace(command_timeout=1)
        host.emit = lambda _record: None
        process = mock.Mock(pid=12345)
        process.communicate.side_effect = [service_runtime.subprocess.TimeoutExpired(["fake"], 1), (b"", b"")]
        with mock.patch.object(service_runtime.subprocess, "Popen", return_value=process), \
                mock.patch.object(service_runtime.os, "killpg") as kill, self.assertRaises(ServiceError):
            host.control(["fake"])
        kill.assert_called_once_with(12345, signal.SIGKILL)


class RoutineLogTests(Fixture):
    def relay(self, records, log_all=False):
        output = []
        supervisor = Supervisor(self.config, object(), output.append, log_all=log_all)
        stream = io.BytesIO(b"".join(json.dumps(record).encode() + b"\n" for record in records))
        destination = io.BytesIO()
        destination.close = lambda: None
        supervisor.relay("monitor" if records[0]["type"].startswith("monitor") else "lsm", stream, destination)
        logged = [row["event"] for row in output if row["type"] == "service_stage_event"]
        return logged, destination.getvalue().count(b"\n"), supervisor

    def heartbeat(self, timestamp, **fields):
        return event("monitor_heartbeat", timestamp_ns=timestamp, received_timestamp_ns=timestamp + 5,
                     delivery_delay_ns=5, event_counts={"usb_setup_completed": timestamp}, session_id="s",
                     degraded=False, reported_lost_events=0, **fields)

    def test_unchanged_heartbeats_are_logged_once_but_all_forwarded(self):
        records = [self.heartbeat(1), self.heartbeat(2), event("usb_setup_completed", usb_id="4-1"),
                   self.heartbeat(3), self.heartbeat(4, )]
        logged, forwarded, _ = self.relay(records)
        self.assertEqual([row["type"] for row in logged], ["monitor_heartbeat", "usb_setup_completed"])
        self.assertEqual(forwarded, 5)

    def test_changed_heartbeat_is_logged(self):
        records = [self.heartbeat(1), self.heartbeat(2)]
        records[1]["reported_lost_events"] = 3
        logged, _, supervisor = self.relay(records)
        self.assertEqual(len(logged), 2)

    def test_status_logged_on_denial_and_failure_seen_by_health(self):
        def status(command, denied, failures=0):
            return event("lsm_status", command_id=command, timestamp_ns=command, mode="local-files",
                         denied_opens=denied, failures=failures, targets=[{"target_id": 1, "denied_opens": denied}])
        records = [status(1, 0), status(2, 0), status(3, 0), status(4, 2), status(5, 2), status(6, 2, failures=1)]
        logged, forwarded, supervisor = self.relay(records)
        self.assertEqual([row["denied_opens"] for row in logged], [0, 2, 2])
        self.assertEqual(logged[-1]["failures"], 1)
        self.assertEqual(forwarded, 6)
        self.assertIn("lsm_status", supervisor.health.failure())

    def test_log_all_keeps_every_record(self):
        logged, _, _ = self.relay([self.heartbeat(1), self.heartbeat(2), self.heartbeat(3)], log_all=True)
        self.assertEqual(len(logged), 3)

    def test_same_type_from_other_stage_is_not_filtered(self):
        output = []
        supervisor = Supervisor(self.config, object(), output.append)
        for _ in range(3):
            supervisor.relay("enforcement", io.BytesIO(json.dumps(event("lsm_status", failures=0)).encode() + b"\n"))
        self.assertEqual(len(output), 3)

    def test_run_accepts_log_all(self):
        args = portwatchman.parser().parse_args(["run", "--log-all"])
        self.assertTrue(args.log_all)


if __name__ == "__main__":
    unittest.main()
