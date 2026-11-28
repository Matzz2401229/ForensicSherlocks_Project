"""Short human-readable lines for the important service events (run --summary)."""
from __future__ import annotations
import time

BLOCK_REASONS = {"no_matching_allowlist_rule": "not on the allowlist",
                 "identity_mismatch": "device changed after the decision",
                 "revoked": "revoked"}
SUPPRESSED = {"cooldown": "cooldown", "duplicate_connection": "same connection",
              "power_action_issued": "power action already issued"}


def device_name(record):
    device = record.get("device") or {}
    name = " ".join(part for part in (device.get("manufacturer"), device.get("product")) if part)
    ids = f'{device["vendor_id"]}:{device["product_id"]}' if device.get("vendor_id") else ""
    label = " ".join(part for part in (name, f"({ids})" if ids else "") if part)
    return f'USB {record.get("usb_id", "?")}' + (f" {label}" if label else "")


def is_problem(event):
    kind = event.get("type", "")
    return (kind.endswith("_error") or kind in ("monitor_loss", "monitor_diagnostic")
            or event.get("ok") is False or event.get("degraded") is True)


class Summary:
    def __init__(self, clock=time.localtime):
        self.clock = clock
        self.denials = {}
        self.actions = []

    def line(self, record):
        """Return the text to print for a service record, or None to stay quiet."""
        text = self.describe(record)
        return None if text is None else time.strftime("%H:%M:%S", self.clock()) + "  " + text

    def describe(self, record):
        kind = record.get("type")
        if kind == "service_stage_event":
            return self.stage(record.get("stage"), record.get("event") or {})
        if kind == "service_startup_inventory" and record.get("devices"):
            ids = ", ".join(device["usb_id"] for device in record["devices"])
            return f"Already connected before start (not re-checked): {ids}"
        if kind == "service_protected_file_missing":
            return f'Protected file not found, skipped: {record.get("path")}'
        if kind == "service_protected_file_destroyed":
            return f'Protected file destroyed: {record.get("path")}'
        if kind == "service_previous_boot_state_cleared":
            return "The last boot ended without a clean stop; its saved state was set aside"
        if kind == "service_bus_arm":
            buses = ", ".join(row["bus"] for row in record["event"].get("buses", []))
            return f"Armed {buses}: new USB devices are blocked until checked"
        if kind == "service_ready":
            plan = ", ".join(self.actions) or "none"
            mode = "APPLIED" if record.get("apply_responses") else "preview only"
            return f"Ready. Response plan: {plan} ({mode})"
        if kind == "service_bus_restore":
            event = record.get("event", {})
            if event.get("type") == "service_previous_boot_state_cleared":
                return "Saved state from an earlier boot was set aside; nothing to restore"
            restored = ", ".join(f'{row["bus"]}={row["restore_to"]}' for row in event.get("buses", []))
            return f"Restored USB defaults: {restored or 'nothing saved'}"
        if kind == "service_bus_state_retained":
            return "WARNING: USB buses left blocking new devices; inspect, then run restore"
        if kind == "service_shutdown_timeout":
            return "WARNING: components were slow to stop"
        if kind == "service_stopped":
            if record.get("ok"):
                return "Stopped cleanly"
            return f'Stopped with a failure: {record.get("reason")}'
        if kind and kind.endswith("_error"):
            return f'ERROR: {record.get("message", kind)}'
        return None

    def stage(self, stage, event):
        kind = event.get("type")
        if stage == "local" and kind == "lsm_local_registered":
            paths = event.get("protected_paths", [])
            return f"Protecting {len(paths)} VM file(s): " + ", ".join(paths)
        if stage == "local" and kind == "lsm_local_exempted":
            return "Response stage may destroy protected files (exempt from the file guard)"
        if stage == "lsm" and kind == "lsm_status":
            lines = []
            for target in event.get("targets", []):
                for field, verb in (("denied_opens", "open"), ("denied_changes", "delete or change")):
                    count = target.get(field, 0)
                    before = self.denials.get((target.get("target_id"), field), 0)
                    self.denials[(target.get("target_id"), field)] = count
                    if count > before:
                        times = "attempt" if count - before == 1 else "attempts"
                        lines.append(f'Blocked {count - before} {times} to {verb} {target.get("path")} ({count} so far)')
            if event.get("failures"):
                lines.append(f'PROBLEM: file protection reports {event["failures"]} failure(s)')
            return "\n          ".join(lines) or None
        if stage == "lsm" and kind == "lsm_stopped" and event.get("ok"):
            return "VM file protection released"
        if stage == "responses" and kind == "response_started":
            self.actions = list(event.get("actions", []))
            return None
        if stage == "enforcement" and kind == "enforcement_result":
            if event.get("action") == "allow":
                note = "" if event.get("enforcement_applied") else " (not applied)"
                return f'{device_name(event)}: ALLOWED by rule "{event.get("matched_rule")}"{note}'
            if event.get("action") == "block":
                reason = BLOCK_REASONS.get(event.get("reason"), event.get("reason"))
                return f"{device_name(event)}: BLOCKED ({reason})"
            return None
        if stage == "enforcement" and kind == "enforcement_skipped":
            return f'USB {event.get("usb_id", "?")}: no action ({event.get("reason")})'
        if stage == "monitor" and kind == "usb_disconnect_started":
            return f'USB {event.get("usb_id", "?")} disconnected'
        if stage == "responses" and kind == "response_suppressed":
            reason = SUPPRESSED.get(event.get("reason"), event.get("reason"))
            left = f', {event["cooldown_remaining_s"]:.0f}s left' if "cooldown_remaining_s" in event else ""
            return f"Response skipped ({reason}{left})"
        if stage == "responses" and kind == "response_action":
            action = event.get("action")
            if event.get("status") == "issuing":
                return f"Response {action}: issuing now"
            if not event.get("applied"):
                return f"Response {action}: preview only, not applied"
            if event.get("ok"):
                return f"Response {action}: done"
            return f'Response {action}: FAILED ({event.get("status")})'
        if is_problem(event):
            message = event.get("message") or event.get("reason") or kind
            return f"PROBLEM in {stage}: {kind}: {message}"
        return None
