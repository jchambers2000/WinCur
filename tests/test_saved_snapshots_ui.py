from __future__ import annotations

import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from wincur.baselines import BaselineStore
from wincur.models import AssessmentScore, ScanRecord
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def saved_record(timestamp: str = "2026-10-29T12:30:00+00:00", privilege: str = "Standard") -> dict:
    assessment = AssessmentScore(82.0, 91.0, profile="Standard", policy_version="2.1")
    return ScanRecord.create("1.0.0", "Windows 11", "TEST-PC", [], assessment, privilege, timestamp_utc=timestamp).to_dict()


class SavedSnapshotsUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.baseline_path = self.root / "baselines.json"; self.history = [saved_record()]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_window(self, history=None) -> WinCurWindow:
        theme = ThemeManager(self.root / "appearance.json")
        with patch("wincur.ui.load_history", return_value=list(self.history if history is None else history)), patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=False):
            return WinCurWindow(theme, baseline_path=self.baseline_path, history_path=self.root / "history.jsonl")

    def open_dialog(self, window: WinCurWindow) -> None:
        with patch("wincur.ui.QDialog.exec", return_value=0): window._open_saved_snapshots()

    def test_lazy_dialog_refreshes_assessments_and_keeps_four_pages(self) -> None:
        window = self.make_window(); self.assertIsNone(window.baseline_dialog); self.assertFalse(hasattr(window, "active_baseline_combo"))
        self.open_dialog(window)
        self.assertEqual(window.pages.count(), 4); self.assertIsNotNone(window.baseline_dialog); self.assertEqual(window.baseline_assessment_combo.count(), 1); self.assertTrue(window.create_baseline_button.isEnabled()); self.assertFalse(window.baseline_advanced_widget.isVisible())
        window.close()

    def test_dialog_is_keyboard_dismissible(self) -> None:
        window = self.make_window(); self.open_dialog(window); window.baseline_dialog.show(); self.app.processEvents(); self.assertTrue(window.baseline_dialog.isVisible())
        QTest.keyClick(window.baseline_dialog, Qt.Key.Key_Escape); self.app.processEvents(); self.assertFalse(window.baseline_dialog.isVisible()); window.close()

    def test_expanded_layout_is_accessible_at_supported_scale_factors(self) -> None:
        root = Path(__file__).resolve().parent.parent
        for scale in ("1", "1.25", "1.5"):
            with self.subTest(scale=scale):
                environment = dict(os.environ, QT_QPA_PLATFORM="offscreen", QT_SCALE_FACTOR=scale)
                completed = subprocess.run([sys.executable, "-m", "tests.snapshot_layout_probe"], cwd=root, env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads([line for line in completed.stdout.splitlines() if line.strip()][-1])
                self.assertAlmostEqual(payload["scale"], float(scale)); self.assertTrue(payload["dialog_within_screen"]); self.assertTrue(payload["details_visible"])
                self.assertGreaterEqual(payload["splitter_height"], 300); self.assertTrue(payload["header_visible"]); self.assertGreaterEqual(payload["table_viewport_height"], payload["row_height"] * 3)
                self.assertGreater(payload["table_vertical_maximum"], 0); self.assertTrue(payload["last_row_visible"]); self.assertGreater(payload["table_horizontal_maximum"], 0); self.assertTrue(payload["table_horizontal_visible"]); self.assertFalse(payload["outer_horizontal_visible"])
                self.assertGreater(payload["outer_vertical_maximum"], 0); self.assertTrue(payload["close_visible"]); self.assertTrue(payload["reopened_collapsed"]); self.assertTrue(payload["reopened_at_top"])
                self.assertGreaterEqual(payload["splitter_sizes"][0], 180); self.assertGreaterEqual(payload["splitter_sizes"][1], 80)
                self.assertTrue(payload["collapsed_after_toggle"]); self.assertTrue(payload["collapsed_height_not_larger"]); self.assertTrue(payload["collapsed_close_visible"])

    def test_empty_state_disables_creation_until_an_assessment_exists(self) -> None:
        window = self.make_window([]); self.open_dialog(window)
        self.assertEqual(window.baseline_assessment_combo.count(), 0); self.assertFalse(window.create_baseline_button.isEnabled()); self.assertIn("No current or saved assessment", window.baseline_compatibility.text()); window.close()

    def test_create_is_single_save_and_preserves_historical_metadata(self) -> None:
        historical = saved_record("2024-05-06T07:08:09+00:00", "Administrator"); window = self.make_window([historical]); self.open_dialog(window)
        with patch.object(window.baseline_store, "save", wraps=window.baseline_store.save) as save, patch("wincur.ui.QInputDialog.getText", return_value=("Known good", True)):
            window._create_baseline()
        self.assertEqual(save.call_count, 1); active = window.baseline_collection.active; self.assertIsNotNone(active); self.assertEqual(active.name, "Known good")
        self.assertEqual(active.assessment_snapshot["timestamp_utc"], historical["timestamp_utc"]); self.assertEqual(active.assessment_snapshot["assessment_privilege"], "Administrator"); self.assertEqual(active.assessment_snapshot["assessment"]["policy_version"], "2.1")
        self.assertEqual(BaselineStore(self.baseline_path).load().active_baseline_id, active.baseline_id); window.close()

    def test_failed_create_restores_collection_active_selection_and_ui(self) -> None:
        window = self.make_window(); self.open_dialog(window)
        with patch.object(window.baseline_store, "save", side_effect=OSError("disk full")), patch("wincur.ui.QInputDialog.getText", return_value=("Must not remain", True)), patch("wincur.ui.QMessageBox.warning") as warning:
            window._create_baseline()
        self.assertEqual(window.baseline_collection.baselines, []); self.assertIsNone(window.baseline_collection.active_baseline_id); self.assertEqual(window.active_baseline_combo.currentData(), None); warning.assert_called_once(); window.close()

    def test_activate_rename_delete_and_restart_persistence(self) -> None:
        window = self.make_window(); self.open_dialog(window)
        with patch("wincur.ui.QInputDialog.getText", side_effect=[("First", True), ("Renamed", True)]):
            window._create_baseline(); first_id = window.baseline_collection.active_baseline_id; window._rename_baseline()
        self.assertEqual(window.baseline_collection.active.name, "Renamed")
        second = window.baseline_store.create(window.baseline_collection, "Second", self.history[0]); window._refresh_baseline_ui(); window.active_baseline_combo.setCurrentIndex(window.active_baseline_combo.findData(second.baseline_id)); self.app.processEvents()
        self.assertEqual(window.baseline_collection.active_baseline_id, second.baseline_id)
        with patch("wincur.ui.QMessageBox.exec", return_value=QMessageBox.StandardButton.Yes): window._delete_baseline()
        self.assertNotIn(second.baseline_id, [item.baseline_id for item in window.baseline_collection.baselines]); self.assertEqual(window.baseline_collection.active_baseline_id, first_id); window.close()
        restarted = self.make_window(); self.open_dialog(restarted); self.assertEqual(restarted.baseline_collection.active.name, "Renamed"); restarted.close()

    def test_storage_warning_and_external_snapshot_refresh_are_visible(self) -> None:
        self.baseline_path.write_text("not-json", encoding="utf-8"); window = self.make_window(); self.open_dialog(window)
        self.assertIn("Storage warning", window.baseline_compatibility.text()); self.assertIn("could not be read", window.baseline_compatibility.text())
        external = BaselineStore(self.baseline_path); collection = external.load(); external.create(collection, "Recovered", self.history[0], activate=True)
        self.open_dialog(window); self.assertEqual(window.baseline_collection.active.name, "Recovered"); self.assertEqual(window.active_baseline_combo.currentData(), window.baseline_collection.active_baseline_id); window.close()

    def test_compare_updates_dialog_without_running_a_scan(self) -> None:
        window = self.make_window(); self.open_dialog(window)
        with patch("wincur.ui.QInputDialog.getText", return_value=("Reference", True)): window._create_baseline()
        with patch.object(window, "start_scan") as scan: window._compare_selected_baseline()
        scan.assert_not_called(); self.assertIn("Compared with saved snapshot 'Reference'", window.baseline_compatibility.text()); window.close()


if __name__ == "__main__":
    unittest.main()
