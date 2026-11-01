from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from wincur.hardening import WindowsHardeningBackend, rollback_record_eligibility
from wincur.models import ActionOutcome, ActionRecord
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def action_record(outcome: ActionOutcome = ActionOutcome.SUCCESS) -> ActionRecord:
    action_id = "disable_autorun"; path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    keys = [{"path": key, "exists": True} for key in WindowsHardeningBackend._registry_key_paths(action_id)]
    original = {"schema_version": 2, "keys": keys, "values": [
        {"path": path, "name": "NoDriveTypeAutoRun", "exists": True, "value": 145, "type": 4},
        {"path": path, "name": "NoAutorun", "exists": True, "value": 0, "type": 4},
    ]}
    owned = {"schema_version": 2, "keys": keys, "values": [
        {"path": path, "name": "NoDriveTypeAutoRun", "exists": True, "value": 255, "type": 4},
        {"path": path, "name": "NoAutorun", "exists": True, "value": 1, "type": 4},
    ]}
    return ActionRecord.create(action_id, original, owned, outcome, "The action was verified.", "Both values verified.", True, rollback_snapshot_schema=2)


def rollback_record(source: ActionRecord, outcome: ActionOutcome, status: str) -> ActionRecord:
    return ActionRecord.create(source.action_id, source.requested_configuration, source.original_configuration, outcome,
                               f"Rollback {outcome.value}.", "Rollback verification evidence.", False, status, 2, source.timestamp_utc)


class RemediationLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.theme = ThemeManager(Path(self.temp.name) / "appearance.json"); self.records = []

    def tearDown(self): self.temp.cleanup()

    def make_window(self, administrator=False):
        with patch("wincur.ui.load_history", return_value=[]), patch("wincur.ui.load_action_history", side_effect=lambda limit=100: list(self.records)[-limit:]), patch("wincur.ui.is_administrator", return_value=administrator):
            return WinCurWindow(self.theme, baseline_path=Path(self.temp.name) / "baselines.json")

    def handle(self, window, record, kind):
        def save(item): self.records.append(item.to_dict()); return Path(self.temp.name) / "action_history.jsonl"
        with patch("wincur.ui.save_action_record", side_effect=save), patch("wincur.ui.load_action_history", side_effect=lambda limit=100: list(self.records)[-limit:]), patch.object(window, "_show_action_result") as result_dialog, patch.object(window, "_refresh_action_after_operation") as refresh, patch.object(window, "start_scan") as scan:
            window._handle_action_record(record, kind)
        return result_dialog, refresh, scan

    def test_successful_remediation_refreshes_selects_and_enables_rollback_without_scan(self):
        window = self.make_window(); record = action_record(); result_dialog, refresh, scan = self.handle(window, record, "action")
        self.assertEqual(len(self.records), 1); self.assertEqual(window.action_history_table.currentRow(), 0); self.assertTrue(window.rollback_button.isEnabled())
        self.assertTrue(rollback_record_eligibility(self.records[0], window.action_history_records)[0]); self.assertIn("score has not been refreshed", window.scan_message.text())
        result_dialog.assert_called_once_with(record, "action"); refresh.assert_called_once_with(record.action_id); scan.assert_not_called(); window.close()

    def test_successful_rollback_refreshes_history_and_consumes_original_action(self):
        source = action_record(); self.records = [source.to_dict()]; window = self.make_window(); completed = rollback_record(source, ActionOutcome.SUCCESS, "Completed")
        _, refresh, scan = self.handle(window, completed, "rollback")
        self.assertEqual(window.action_history_table.currentRow(), 0); self.assertFalse(window.rollback_button.isEnabled()); self.assertIn("Rollback Success", window.scan_message.text())
        window.action_history_table.selectRow(1); self.assertFalse(window.rollback_button.isEnabled()); self.assertIn("already been rolled back", window.rollback_button.toolTip())
        self.assertFalse(rollback_record_eligibility(self.records[0], self.records)[0]); refresh.assert_called_once_with(source.action_id); scan.assert_not_called(); window.close()

    def test_partial_rollback_consumes_original_and_uses_warning_presentation(self):
        source = action_record(); partial = rollback_record(source, ActionOutcome.PARTIAL, "Partial"); self.records = [source.to_dict()]; window = self.make_window()
        self.handle(window, partial, "rollback"); self.assertIn("Partial Success", window.scan_message.text()); self.assertFalse(rollback_record_eligibility(self.records[0], self.records)[0])
        with patch.object(QMessageBox, "setIcon") as set_icon, patch.object(QMessageBox, "exec", return_value=0): window._show_action_result(partial, "rollback")
        set_icon.assert_called_with(QMessageBox.Icon.Warning); window.close()

    def test_failed_rollback_uses_error_presentation_and_remains_retry_eligible(self):
        source = action_record(); failed = rollback_record(source, ActionOutcome.FAILURE, "Failed"); self.records = [source.to_dict()]; window = self.make_window()
        self.handle(window, failed, "rollback"); self.assertIn("Rollback Failure", window.scan_message.text()); self.assertTrue(rollback_record_eligibility(self.records[0], self.records)[0])
        with patch.object(QMessageBox, "setIcon") as set_icon, patch.object(QMessageBox, "exec", return_value=0): window._show_action_result(failed, "rollback")
        set_icon.assert_called_with(QMessageBox.Icon.Critical); window.close()

    def test_administrator_mode_is_explicit_and_redundant_scan_is_disabled(self):
        window = self.make_window(administrator=True)
        self.assertEqual(window.elevated_button.text(), "Already Running as Administrator"); self.assertFalse(window.elevated_button.isEnabled()); self.assertTrue(window.administrator_mode_label.isVisibleTo(window)); self.assertIn("already running", window.elevated_button.toolTip().lower()); window.close()

    def test_standard_mode_preserves_elevated_scan_workflow_label(self):
        window = self.make_window(administrator=False)
        self.assertEqual(window.elevated_button.text(), "Scan as Administrator"); self.assertTrue(window.elevated_button.isEnabled()); self.assertTrue(window.administrator_mode_label.isHidden()); window.close()


if __name__ == "__main__": unittest.main()
