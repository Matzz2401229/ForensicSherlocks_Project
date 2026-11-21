import contextlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/enforcement"))
import lsm_bridge
import lsm_client
import usb_authorization
from lsm_bridge import BridgeConfig, BridgeError, LsmBridge, TargetPending, load_bridge_config
from lsm_client import ControllerChanged, LsmClient, LsmClientError


class Wire:
    def __init__(self, transform=None, uid=0, chunk=7):
        self.transform, self.uid, self.chunk = transform, uid, chunk
        self.output = b""
        self.payload = None

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, timeout): pass
    def connect(self, path): pass
    def getsockopt(self, *args): return struct.pack("3i", 123, self.uid, self.uid)

    def sendall(self, data):
        self.payload = json.loads(data)
        reply = {"schema_version": 1, "command_id": self.payload["command_id"],
                 "controller_id": "controller-A", "type": "lsm_status", "mode": "usb",
                 "enforcement_active": True, "failures": 0, "targets": []}
        if self.transform:
            reply = self.transform(reply)
        self.output = reply if isinstance(reply, bytes) else (json.dumps(reply) + "\n").encode()

    def recv(self, size):
        output, self.output = self.output[:min(size, self.chunk)], self.output[min(size, self.chunk):]
        return output


class ClientTests(unittest.TestCase):
    def wire(self, wire):
        self.enterContext(mock.patch.object(lsm_client.sys, "platform", "linux"))
        self.enterContext(mock.patch.object(lsm_client, "verify_socket_files"))
        self.enterContext(mock.patch.object(lsm_client.socket, "AF_UNIX", 1, create=True))
        self.enterContext(mock.patch.object(lsm_client.socket, "socket", return_value=wire))
        return LsmClient()

    def test_fragmented_response_and_instance_binding(self):
        wire = Wire()
        client = self.wire(wire)
        self.assertEqual(client.status()["controller_id"], "controller-A")
        client.request("LIST")
        self.assertEqual(wire.payload["expected_controller_id"], "controller-A")

    def test_server_peer_must_be_root(self):
        with self.assertRaisesRegex(LsmClientError, "peer must be root"):
            self.wire(Wire(uid=1000)).status()

    def test_command_correlation_is_required(self):
        def wrong(reply):
            reply["command_id"] = "wrong"
            return reply
        with self.assertRaisesRegex(LsmClientError, "correlation"):
            self.wire(Wire(wrong)).status()

    def test_restart_rejected_before_old_target_ids_can_be_reused(self):
        wire = Wire()
        client = self.wire(wire)
        client.status()
        def restarted(reply):
            reply["controller_id"] = "controller-B"
            return reply
        wire.transform = restarted
        with self.assertRaises(ControllerChanged):
            client.request("REMOVE", target_id=1)
        self.assertEqual(wire.payload["expected_controller_id"], "controller-A")
        self.assertEqual(client.controller_id, "controller-A")

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(LsmClientError, "Duplicate response"):
            self.wire(Wire(lambda reply: b'{"schema_version":1,"schema_version":1}\n')).status()

    def test_truncated_reply_is_rejected(self):
        with self.assertRaisesRegex(LsmClientError, "complete response"):
            self.wire(Wire(lambda reply: b'{"incomplete":')).status()

    def test_inactive_controller_is_rejected(self):
        def inactive(reply):
            reply["enforcement_active"] = False
            return reply
        with self.assertRaisesRegex(LsmClientError, "not actively enforcing"):
            self.wire(Wire(inactive)).status()

    def test_oversized_reply_is_bounded(self):
        with mock.patch.object(lsm_client, "MAX_REPLY", 100):
            with self.assertRaisesRegex(LsmClientError, "exceeds"):
                self.wire(Wire(lambda reply: b"x" * 101, chunk=1000)).status()

    def test_invalid_socket_paths(self):
        for path in (None, "relative.sock", "/run/../tmp/a", "/run//a", "/run/" + "x" * 110):
            with self.subTest(path=path), self.assertRaises(LsmClientError):
                LsmClient(path)


class FakeClient:
    def __init__(self):
        self.controller_id = "controller-A"
        self.targets = {}
        self.calls = []
        self.next_id = 1
        self.fail = None
        self.prepared = []

    def status(self):
        if self.fail:
            raise self.fail
        return {"mode": "usb", "enforcement_active": True, "failures": 0,
                "targets": list(self.targets.values()), "prepared_connections": self.prepared[:]}

    def request(self, command, **fields):
        self.calls.append((command, fields))
        if self.fail:
            raise self.fail
        if command == "PREPARE_REMOVE":
            connection = fields["connection_id"]
            self.prepared.append(connection)
            self.targets = {i: t for i, t in self.targets.items() if t["connection_id"] != connection}
            return {"type": "lsm_connection_prepared", "connection_id": connection}
        if command == "ADD":
            if fields["connection_id"] in self.prepared:
                return {"type": "lsm_connection_prepared", "connection_id": fields["connection_id"]}
            target = {"target_id": self.next_id, "connection_id": fields["connection_id"]}
            self.targets[self.next_id] = target
            self.next_id += 1
            return {"type": "lsm_target_added", "target": target}
        target = self.targets.get(fields["target_id"])
        if target:
            if target["connection_id"] != fields["connection_id"]:
                raise LsmClientError("connection_mismatch")
            del self.targets[fields["target_id"]]
        return {"type": "lsm_target_removed" if target else "lsm_target_absent"}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.device = {"usb_id": "4-1", "device_address": 2, "vendor_id": "058f", "product_id": "6387",
                       "serial": "TEST", "kernel_authorized": True}
        self.client = FakeClient()
        self.reader = SimpleNamespace(read=mock.Mock(side_effect=lambda *a, **kw: self.device.copy()))
        self.revoke = mock.Mock(return_value={"action": "block"})
        self.resolver = mock.Mock()
        self.target = SimpleNamespace(path="/media/test/secret.txt", close=mock.Mock(),
                                      fields={"expected_major": 8, "expected_minor": 17,
                                              "expected_inode": 741, "expected_mount_id": 32})
        self.resolver.resolve.return_value = [self.target]
        self.now = 10
        self.config = BridgeConfig("/run/portwatchman/lsm_controller.sock", 30, "report", {"lab": ("secret.txt",)})
        self.bridge = self.make()
        self.result = {"type": "enforcement_result", "action": "allow", "usb_id": "4-1",
                       "connection_id": "boot:4-1:100", "device": self.device.copy(), "matched_rule": "lab"}

    def make(self, **options):
        return LsmBridge(self.config, self.reader, self.revoke, client=self.client,
                         resolver=self.resolver, clock=lambda: self.now, **options)

    def register(self):
        self.bridge.start()
        self.bridge.handle({}, self.result)
        return self.bridge.tick()

    def test_registration_carries_file_and_connection_identity(self):
        self.assertTrue(self.register()[0]["protection_complete"])
        command, fields = self.client.calls[0]
        self.assertEqual(command, "ADD")
        for key, value in self.target.fields.items():
            self.assertEqual(fields[key], value)
        self.assertEqual(fields["connection_id"], self.result["connection_id"])
        self.assertEqual(fields["expected_usb_id"], "4-1")
        self.assertEqual(fields["expected_address"], 2)
        self.target.close.assert_called_once()

    def test_dry_run_never_uses_socket_or_revokes(self):
        self.bridge = self.make(apply=False)
        self.client.fail = AssertionError("socket must not be used")
        self.bridge.start()
        events = self.bridge.handle({}, self.result)
        self.assertEqual(events[0]["type"], "lsm_bridge_plan")
        self.assertFalse(self.bridge.tick())
        self.assertFalse(self.client.calls)
        self.revoke.assert_not_called()

    def test_pending_mount_retries_then_registers(self):
        self.resolver.resolve.side_effect = [TargetPending("not mounted"), [self.target]]
        self.bridge.handle({}, self.result)
        self.assertFalse(self.bridge.tick())
        self.assertFalse(self.client.calls)
        self.now += 5
        self.assertEqual(self.bridge.tick()[0]["type"], "lsm_bridge_registered")

    def test_missing_mount_deadline_reports_without_deauthorizing(self):
        self.resolver.resolve.side_effect = TargetPending("not mounted")
        self.bridge.handle({}, self.result)
        self.now = 41
        self.assertEqual(self.bridge.tick()[0]["type"], "lsm_bridge_error")
        self.assertEqual(self.bridge.failures, 1)
        self.revoke.assert_not_called()

    def test_explicit_error_policy_can_revoke_same_device(self):
        self.config = BridgeConfig(self.config.socket_path, 30, "deauthorize", self.config.rules)
        self.bridge = self.make()
        self.resolver.resolve.side_effect = BridgeError("bad target")
        self.bridge.handle({}, self.result)
        events = self.bridge.tick()
        self.revoke.assert_called_once_with("4-1", self.result["device"])
        self.assertEqual(events[-1]["type"], "lsm_bridge_revoke_result")

    def test_changed_device_is_never_registered_or_revoked(self):
        self.config = BridgeConfig(self.config.socket_path, 30, "deauthorize", self.config.rules)
        self.bridge = self.make()
        self.bridge.handle({}, self.result)
        self.device["device_address"] = 3
        self.bridge.tick()
        self.assertFalse(self.client.calls)
        self.revoke.assert_not_called()

    def test_old_disconnect_cannot_remove_new_connection(self):
        self.register()
        old = self.result["connection_id"]
        self.result["connection_id"] = "boot:4-1:200"
        self.result["device"]["device_address"] = self.device["device_address"] = 3
        self.bridge.handle({}, self.result)
        self.bridge.tick()
        self.assertEqual(len(self.client.targets), 1)
        before = list(self.client.calls)
        self.bridge.handle({"type": "policy_skipped", "reason": "usb_disconnect_started",
                            "connection_id": old, "usb_id": "4-1"}, None)
        self.assertEqual(self.client.calls, before)
        self.assertEqual(next(iter(self.client.targets.values()))["connection_id"], self.result["connection_id"])

    def test_disconnect_removes_only_owned_target(self):
        self.register()
        self.client.targets[99] = {"target_id": 99, "connection_id": "somebody-else"}
        self.bridge.handle({"type": "policy_skipped", "reason": "usb_disconnect_started",
                            "connection_id": self.result["connection_id"], "usb_id": "4-1"}, None)
        self.assertEqual(set(self.client.targets), {99})

    def test_missing_registered_entry_is_detected(self):
        self.register()
        self.client.targets.clear()
        self.assertEqual(self.bridge.tick()[0]["type"], "lsm_bridge_error")
        self.assertEqual(self.bridge.failures, 1)

    def test_prepare_removal_is_intentional_and_does_not_fault_bridge(self):
        self.register()
        self.client.request("PREPARE_REMOVE", connection_id=self.result["connection_id"])
        events = self.bridge.tick()
        self.assertEqual(events[0]["type"], "lsm_bridge_prepared_for_removal")
        self.assertFalse(events[0]["protection_complete"])
        self.assertFalse(self.bridge.faulted)
        self.assertEqual(self.bridge.failures, 0)
        self.assertFalse(self.client.targets)
        for _ in range(3):
            self.assertFalse(self.bridge.tick())
        self.assertEqual(len([c for c in self.client.calls if c[0] == "ADD"]), 1)

    def test_prepared_removal_then_reconnect_registers_new_generation(self):
        self.register()
        old_connection = self.result["connection_id"]
        self.client.request("PREPARE_REMOVE", connection_id=old_connection)
        self.bridge.tick()
        self.bridge.handle({"type": "policy_skipped", "reason": "usb_disconnect_started",
                            "usb_id": "4-1", "connection_id": old_connection}, None)
        self.assertFalse(self.bridge.registrations)
        self.result["connection_id"] = "boot:4-1:200"
        self.result["device"]["device_address"] = self.device["device_address"] = 3
        self.bridge.handle({}, self.result)
        events = self.bridge.tick()
        self.assertEqual(events[0]["type"], "lsm_bridge_registered")
        new_id = next(iter(self.client.targets))
        self.assertGreater(new_id, 1)
        before = list(self.client.calls)
        self.bridge.handle({"type": "policy_skipped", "reason": "usb_disconnect_started",
                            "usb_id": "4-1", "connection_id": old_connection}, None)
        self.assertEqual(self.client.calls, before)
        self.assertIn(new_id, self.client.targets)

    def test_prepare_remove_racing_add_closes_held_reference(self):
        original = self.client.request
        def race(command, **fields):
            if command == "ADD":
                self.client.prepared.append(fields["connection_id"])
            return original(command, **fields)
        self.client.request = race
        self.bridge.handle({}, self.result)
        events = self.bridge.tick()
        self.assertEqual(events[0]["type"], "lsm_bridge_prepared_for_removal")
        self.assertFalse(any(e["type"] == "lsm_bridge_registered" for e in events))
        self.assertFalse(self.bridge.faulted)
        self.target.close.assert_called_once()

    def test_prepared_connection_needs_no_device_access_until_disconnect(self):
        self.register()
        self.client.request("PREPARE_REMOVE", connection_id=self.result["connection_id"])
        self.bridge.tick()
        self.reader.read.side_effect = BridgeError("USB is being removed")
        self.assertFalse(self.bridge.tick())
        self.assertFalse(self.bridge.faulted)
        self.assertFalse(self.bridge.failures)

    def test_prepare_removal_does_not_release_other_connections(self):
        self.register()
        self.client.targets[99] = {"target_id": 99, "connection_id": "other-connection"}
        self.client.request("PREPARE_REMOVE", connection_id=self.result["connection_id"])
        self.bridge.tick()
        self.assertEqual(set(self.client.targets), {99})

    def test_prepared_state_survives_bounded_marker_eviction(self):
        self.register()
        self.client.request("PREPARE_REMOVE", connection_id=self.result["connection_id"])
        self.bridge.tick()
        self.client.prepared.clear()
        self.assertFalse(self.bridge.tick())
        self.assertFalse(self.bridge.faulted)
        self.assertFalse(self.client.targets)

    def test_invalid_prepared_inventory_is_reported(self):
        self.register()
        self.client.prepared = [123]
        self.assertEqual(self.bridge.tick()[0]["type"], "lsm_bridge_error")

    def test_abnormal_stop_does_not_claim_guard_survives_controller_exit(self):
        self.register()
        event = self.bridge.close(clean=False)[0]
        self.assertFalse(event["protection_complete"])
        self.assertIn("unverified", event["message"])

    def test_restart_never_deletes_ids_on_replacement_controller(self):
        self.register()
        self.client.fail = ControllerChanged("restart")
        self.bridge.tick()
        before = len(self.client.calls)
        self.bridge.close(clean=False)
        self.assertEqual(len(self.client.calls), before)
        self.assertEqual(self.bridge.failures, 1)

    def test_normal_stop_releases_only_owned_entries(self):
        self.register()
        self.client.targets[99] = {"target_id": 99, "connection_id": "elsewhere"}
        self.bridge.close(clean=True)
        self.assertEqual(set(self.client.targets), {99})

    def test_abnormal_stop_preserves_guard_entries(self):
        self.register()
        events = self.bridge.close(clean=False)
        self.assertEqual(events[0]["type"], "lsm_bridge_retained")
        self.assertEqual(len(self.client.targets), 1)

    def test_unrelated_allowlist_rule_and_block_do_not_register(self):
        self.result["matched_rule"] = "other"
        self.assertFalse(self.bridge.handle({}, self.result))
        self.result.update(matched_rule="lab", action="block")
        self.assertFalse(self.bridge.handle({}, self.result))
        self.assertFalse(self.client.calls)

    def test_no_connection_context_does_not_claim_protection(self):
        del self.result["connection_id"]
        events = self.bridge.handle({}, self.result)
        self.assertFalse(events[0]["protection_complete"])
        self.assertFalse(self.client.calls)

    def test_partial_registration_is_retained_on_failure(self):
        second = SimpleNamespace(path="/media/test/second.txt", fields=self.target.fields, close=mock.Mock())
        self.resolver.resolve.return_value = [self.target, second]
        original = self.client.request
        def fail_second(command, **fields):
            if fields.get("path") == second.path:
                raise LsmClientError("map full")
            return original(command, **fields)
        self.client.request = fail_second
        self.bridge.handle({}, self.result)
        self.bridge.tick()
        self.assertEqual(len(self.client.targets), 1)
        self.assertEqual(self.bridge.failures, 1)
        second.close.assert_called_once()

    def test_process_stream_includes_bridge_failures_in_exit_status(self):
        enforcer = usb_authorization.DeviceEnforcer(mock.Mock(), "unused")
        bridge = mock.Mock(failures=1)
        bridge.handle.return_value = bridge.tick.return_value = bridge.close.return_value = []
        stream = ['{"schema_version":1,"type":"policy_stream_closed","reason":"requested_stop"}\n']
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(usb_authorization.process_stream(enforcer, stream, bridge), 1)
        closing = json.loads(output.getvalue().splitlines()[-1])
        self.assertFalse(closing["ok"])
        self.assertEqual(closing["failures"], 1)

    def test_bad_input_does_not_reuse_previous_decision(self):
        enforcer = usb_authorization.DeviceEnforcer(mock.Mock(), "unused")
        bridge = mock.Mock(failures=0)
        bridge.handle.return_value = bridge.tick.return_value = bridge.close.return_value = []
        with contextlib.redirect_stdout(io.StringIO()):
            usb_authorization.process_stream(enforcer, ["{bad json}\n"], bridge)
        bridge.handle.assert_not_called()


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "lsm.json"
        self.document = {"schema_version": 1, "socket_path": "/run/portwatchman/lsm_controller.sock",
                         "registration_timeout_seconds": 30, "on_error": "report",
                         "rules": [{"allowlist_rule": "lab", "protected_paths": ["secret.txt"]}]}

    def load(self):
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        return load_bridge_config(self.path)

    def test_valid_config(self):
        self.assertEqual(self.load().rules, {"lab": ("secret.txt",)})

    def test_error_policy_must_be_explicit(self):
        del self.document["on_error"]
        with self.assertRaises(BridgeError): self.load()

    def test_unsafe_relative_paths_rejected(self):
        for value in ("../secret", "/etc/hostname", "a/../b", "a//b", ".", "a\\b", "a\n"):
            self.document["rules"][0]["protected_paths"] = [value]
            with self.subTest(value=value), self.assertRaises(BridgeError): self.load()

    def test_duplicate_rules_rejected(self):
        self.document["rules"] *= 2
        with self.assertRaises(BridgeError): self.load()


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "O_PATH"), "Linux O_PATH resolver tests")
class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "file.txt"
        self.path.write_text("test")
        self.resolver = lsm_bridge.UsbTargetResolver()
        self.resolver.mounts = lambda usb_id: [str(self.root)]

    def test_holds_identity_through_registration(self):
        targets = self.resolver.resolve("4-1", ("file.txt",))
        try:
            self.assertEqual(targets[0].fields["expected_inode"], self.path.stat().st_ino)
            self.assertGreater(targets[0].fields["expected_mount_id"], 0)
            self.assertEqual(os.fstat(targets[0].fd).st_ino, self.path.stat().st_ino)
        finally:
            for target in targets: target.close()

    def test_final_symlink_cannot_escape_selected_mount(self):
        (self.root / "alias").symlink_to(self.path)
        with self.assertRaises(BridgeError): self.resolver.resolve("4-1", ("alias",))

    def test_missing_file_is_pending(self):
        with self.assertRaises(TargetPending): self.resolver.resolve("4-1", ("missing",))

    def test_multiple_mounts_are_ambiguous(self):
        self.resolver.mounts = lambda usb_id: [str(self.root), "/other"]
        with self.assertRaises(BridgeError): self.resolver.resolve("4-1", ("file.txt",))

    def test_duplicate_hardlinks_are_rejected(self):
        os.link(self.path, self.root / "alias")
        with self.assertRaises(BridgeError): self.resolver.resolve("4-1", ("file.txt", "alias"))


if __name__ == "__main__":
    unittest.main()
