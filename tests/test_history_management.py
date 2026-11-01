from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from wincur.models import AssessmentScore, ScanRecord
from wincur.reporting import clear_history, delete_history_indices, load_history, save_history
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def record(timestamp: str, profile: str = "Standard") -> ScanRecord:
    assessment = AssessmentScore(80.0, 90.0, profile=profile, policy_version="2.0")
    return ScanRecord.create("0.8.0", "Windows 11", "TEST", [], assessment, "Standard", timestamp_utc=timestamp)


class HistoryPersistenceTests(unittest.TestCase):
    def test_selected_and_clear_all_rewrite_history_persistently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.jsonl"; audit_path = Path(directory) / "action_history.jsonl"; audit_path.write_text("audit sentinel\n", encoding="utf-8")
            records = [record(f"2026-10-{day:02d}T12:00:00+00:00") for day in (27, 28, 29)]
            for item in records: save_history(item, path)
            _, removed = delete_history_indices({1}, path)
            self.assertEqual([item["timestamp_utc"] for item in removed], [records[1].timestamp_utc])
            self.assertEqual([item["timestamp_utc"] for item in load_history(path, 100)], [records[0].timestamp_utc, records[2].timestamp_utc])
            _, removed = clear_history(path)
            self.assertEqual(len(removed), 2); self.assertEqual(load_history(path, 100), [])
            self.assertEqual(audit_path.read_text(encoding="utf-8"), "audit sentinel\n")


class HistoryUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); self.history_path = self.root / "history.jsonl"
        self.records = [record("2026-10-28T12:00:00+00:00"), record("2026-10-29T12:00:00+00:00")]
        for item in self.records: save_history(item, self.history_path)
        self.theme = ThemeManager(self.root / "appearance.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_window(self) -> WinCurWindow:
        with patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=False):
            return WinCurWindow(self.theme, baseline_path=self.root / "snapshots.json", history_path=self.history_path)

    def test_delete_selected_clears_displayed_history_and_preserves_snapshot(self) -> None:
        window = self.make_window(); snapshot = window.baseline_store.create(window.baseline_collection, "Keep", self.records[1].to_dict()); window.baseline_store.set_active(window.baseline_collection, snapshot.baseline_id); window._refresh_baseline_ui()
        window._view_history_record(self.records[1].to_dict()); window.history_table.selectRow(0); window.history_table.item(0, 0).setCheckState(Qt.CheckState.Checked)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes): window._delete_selected_history()
        self.assertIsNone(window.current_record); self.assertEqual(len(load_history(self.history_path, 100)), 1)
        self.assertEqual(window.baseline_collection.active.name, "Keep"); self.assertTrue((self.root / "snapshots.json").exists())
        self.assertEqual(window.history_table.rowCount(), 1); self.assertFalse(hasattr(window, "trend_table")); window.close()

    def test_checkbox_selection_select_all_and_deselect_all_are_independent_from_open_row(self) -> None:
        window = self.make_window(); window.history_table.selectRow(0)
        self.assertEqual(window._selected_history_indices(), set()); self.assertFalse(window.delete_history_button.isEnabled())
        window.history_table.item(0, 0).setCheckState(Qt.CheckState.Checked); self.assertEqual(window.history_selection_label.text(), "1 selected"); self.assertTrue(window.delete_history_button.isEnabled())
        window.history_select_all_button.click(); self.assertEqual(len(window._selected_history_indices()), 2); self.assertEqual(window.history_selection_label.text(), "2 selected")
        window.history_deselect_all_button.click(); self.assertEqual(window._selected_history_indices(), set()); self.assertFalse(window.delete_history_button.isEnabled()); window.close()

    def test_select_all_uses_visible_filtered_records_and_cancel_preserves_history(self) -> None:
        advanced = record("2026-10-30T12:00:00+00:00", "Advanced"); save_history(advanced, self.history_path)
        window = self.make_window(); window.history_profile_filter.setCurrentText("Advanced"); window.history_select_all_button.click()
        self.assertEqual(len(window._selected_history_indices()), 1); self.assertEqual(sum(not window.history_table.isRowHidden(row) for row in range(window.history_table.rowCount())), 1)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No) as confirmation: window._delete_selected_history()
        self.assertIn("1 selected saved assessment", confirmation.call_args.args[2]); self.assertEqual(len(load_history(self.history_path, 100)), 3)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes): window._delete_selected_history()
        remaining = load_history(self.history_path, 100); self.assertEqual(len(remaining), 2); self.assertTrue(all(item["assessment"]["profile"] == "Standard" for item in remaining)); window.close()

    def test_clear_all_requires_confirmation_and_handles_empty_history(self) -> None:
        window = self.make_window()
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No): window._clear_scan_history()
        self.assertEqual(len(load_history(self.history_path, 100)), 2)
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes) as confirmation: window._clear_scan_history()
        self.assertIn("all 2 saved assessments", confirmation.call_args.args[2]); self.assertEqual(load_history(self.history_path, 100), [])
        self.assertEqual(window.history_table.rowCount(), 0); self.assertFalse(window.clear_history_button.isEnabled()); self.assertFalse(hasattr(window, "trend_chart"))
        window.close()


if __name__ == "__main__": unittest.main()
