from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from wincur.hardening import HardeningEngine, ManagementState, WindowsHardeningBackend
from wincur.models import ActionAvailability, ActionOutcome


class FakeBackend:
    def __init__(self, management=ManagementState.UNMANAGED, initially_compliant=False,
                 verifies_after_apply=True, apply_error=None) -> None:
        self.management = management; self.initially_compliant = initially_compliant
        self.verifies_after_apply = verifies_after_apply; self.apply_error = apply_error
        self.applied = 0; self.rolled_back = 0; self.changed = False; self.external_version = 0

    def management_state(self, action_id): return self.management, "mock management evidence"
    def capture(self, action_id): return {"values": [{"exists": False, "name": "mock"}], "changed": self.changed, "external_version": self.external_version}
    def describe(self, action_id, state): return "Human-readable configuration", "advanced mock details"
    def apply(self, action_id, expected_state):
        self.applied += 1
        if self.apply_error: raise self.apply_error
        self.changed = True
    def verify(self, action_id):
        verified = self.initially_compliant if not self.changed else self.verifies_after_apply
        return verified, "mock verification"
    def rollback(self, action_id, original, owned_state): self.rolled_back += 1; return True, True, "restored"


def execute_current(engine: HardeningEngine, action_id="disable_autorun"):
    preview = engine.preview(action_id)
    return engine.execute(action_id, True, preview.preview_token, preview.created_utc)


class HardeningEngineTests(unittest.TestCase):
    def test_managed_setting_is_distinct(self) -> None:
        preview = HardeningEngine(FakeBackend(management=ManagementState.MANAGED)).preview("disable_autorun")
        self.assertEqual(preview.availability, ActionAvailability.MANAGED)

    def test_permission_requirement_is_distinct(self) -> None:
        preview = HardeningEngine(FakeBackend(management=ManagementState.REQUIRES_ELEVATION)).preview("disable_autorun")
        self.assertEqual(preview.availability, ActionAvailability.REQUIRES_ELEVATION)

    def test_preview_only_never_calls_apply(self) -> None:
        backend = FakeBackend(); preview = HardeningEngine(backend).preview("disable_autorun")
        self.assertEqual(preview.availability, ActionAvailability.AVAILABLE); self.assertEqual(backend.applied, 0)
        self.assertEqual(preview.current_configuration, "Human-readable configuration")

    def test_registry_state_has_human_summary_and_advanced_details(self) -> None:
        state = {"values": [{"path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "name": "NoDriveTypeAutoRun", "exists": False, "value": None, "type": None}, {"path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "name": "NoAutorun", "exists": False, "value": None, "type": None}]}
        summary, technical = WindowsHardeningBackend().describe("disable_autorun", state)
        self.assertIn("not configured", summary); self.assertNotIn("SOFTWARE\\", summary); self.assertIn("SOFTWARE", technical)

    def test_already_compliant_is_not_available(self) -> None:
        preview = HardeningEngine(FakeBackend(initially_compliant=True)).preview("enable_firewall_profiles")
        self.assertEqual(preview.availability, ActionAvailability.ALREADY_COMPLIANT)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_noop_compliant_action_never_calls_apply(self, mocked_admin) -> None:
        backend = FakeBackend(initially_compliant=True); record = HardeningEngine(backend).execute("enable_firewall_profiles", True)
        self.assertEqual(record.outcome, ActionOutcome.CANCELLED); self.assertEqual(backend.applied, 0)

    def test_unconfirmed_action_never_calls_backend_apply(self) -> None:
        backend = FakeBackend(); record = HardeningEngine(backend).execute("disable_autorun", False)
        self.assertEqual(record.outcome, ActionOutcome.CANCELLED); self.assertEqual(backend.applied, 0)

    @patch("wincur.hardening.is_administrator", return_value=False)
    def test_denied_permissions_before_apply(self, mocked_admin) -> None:
        backend = FakeBackend(); engine = HardeningEngine(backend); preview = engine.preview("disable_autorun")
        record = engine.execute("disable_autorun", True, preview.preview_token, preview.created_utc)
        self.assertEqual(record.outcome, ActionOutcome.FAILURE); self.assertEqual(backend.applied, 0)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_stale_preview_is_rejected(self, mocked_admin) -> None:
        backend = FakeBackend(); engine = HardeningEngine(backend); preview = engine.preview("disable_autorun")
        stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        record = engine.execute("disable_autorun", True, preview.preview_token, stale)
        self.assertEqual(record.outcome, ActionOutcome.FAILURE); self.assertIn("stale", record.message.lower()); self.assertEqual(backend.applied, 0)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_changed_state_invalidates_preview(self, mocked_admin) -> None:
        backend = FakeBackend(); engine = HardeningEngine(backend); preview = engine.preview("disable_autorun"); backend.external_version = 1
        record = engine.execute("disable_autorun", True, preview.preview_token, preview.created_utc)
        self.assertEqual(record.outcome, ActionOutcome.FAILURE); self.assertEqual(backend.applied, 0)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_verified_action_succeeds(self, mocked_admin) -> None:
        record = execute_current(HardeningEngine(FakeBackend()), "enable_powershell_logging")
        self.assertEqual(record.outcome, ActionOutcome.SUCCESS)
        self.assertEqual(record.requested_configuration.get("changed"), True)
        self.assertFalse(record.rollback_available)  # malformed fake state must not become actionable audit data

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_verification_failure_is_partial_not_success(self, mocked_admin) -> None:
        self.assertEqual(execute_current(HardeningEngine(FakeBackend(verifies_after_apply=False))).outcome, ActionOutcome.PARTIAL)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_apply_failure_is_not_success(self, mocked_admin) -> None:
        record = execute_current(HardeningEngine(FakeBackend(apply_error=OSError("denied"))))
        self.assertEqual(record.outcome, ActionOutcome.FAILURE); self.assertIn("denied", record.message)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_failed_noop_has_no_rollback(self, mocked_admin) -> None:
        record = execute_current(HardeningEngine(FakeBackend(apply_error=OSError("denied"))))
        self.assertFalse(record.rollback_available)
        self.assertEqual(record.requested_configuration, {})

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_rollback_uses_captured_original(self, mocked_admin) -> None:
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        original = {"values": [{"path": path, "name": "NoDriveTypeAutoRun", "exists": False, "value": None, "type": None}, {"path": path, "name": "NoAutorun", "exists": False, "value": None, "type": None}]}
        owned = {"values": [{"path": path, "name": "NoDriveTypeAutoRun", "exists": True, "value": 255, "type": 4}, {"path": path, "name": "NoAutorun", "exists": True, "value": 1, "type": 4}]}
        backend = FakeBackend(); record = {"action_id": "disable_autorun", "original_configuration": original, "requested_configuration": owned, "rollback_available": True}
        result = HardeningEngine(backend).rollback(record, True)
        self.assertEqual(result.outcome, ActionOutcome.SUCCESS); self.assertEqual(backend.rolled_back, 1)

    @patch("wincur.hardening.is_administrator", return_value=True)
    def test_legacy_or_noop_record_cannot_rollback(self, mocked_admin) -> None:
        backend = FakeBackend(); record = {"action_id": "disable_autorun", "original_configuration": {"values": [1]}, "requested_configuration": {"recommended": "legacy"}, "rollback_available": False}
        result = HardeningEngine(backend).rollback(record, True)
        self.assertEqual(result.outcome, ActionOutcome.FAILURE); self.assertEqual(backend.rolled_back, 0)


if __name__ == "__main__": unittest.main()
