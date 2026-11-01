from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from wincur.models import AssessmentEnvelope, CheckResult, CheckStatus
from wincur.scoring import load_scoring_config, score_results
from wincur.theme import ThemeManager
from wincur.ui import ScanWorker, WinCurWindow


def finding(check_id: str, title: str, category: str, status: CheckStatus, weight: float) -> CheckResult:
    return CheckResult(check_id, title, category, status, "mock evidence", "mock explanation", weight, "Medium")


class NoHistoryWindow(WinCurWindow):
    def _save_history_async(self, record) -> None:
        pass


class ScanUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.theme = ThemeManager(Path(self.temp.name) / "appearance.json")
        self.config = load_scoring_config()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_window(self, results: list[CheckResult]) -> NoHistoryWindow:
        factory = lambda config, profile, privilege: ScanWorker(config, profile, privilege, check_runner=lambda _: results)
        with patch("wincur.ui.is_administrator", return_value=False), patch("wincur.ui.load_selected_profile", return_value="Standard"):
            return NoHistoryWindow(self.theme, scan_worker_factory=factory)

    def finish_thread(self, window: WinCurWindow) -> None:
        thread = window.scan_thread
        if thread:
            thread.quit(); thread.wait(1000); self.app.processEvents()
        window.close()

    def run_scan_and_wait(self, window: WinCurWindow) -> list[AssessmentEnvelope]:
        received: list[AssessmentEnvelope] = []; loop = QEventLoop()
        window.assessment_displayed.connect(lambda envelope: (received.append(envelope), loop.quit()))
        window.start_scan()
        if not received:
            QTimer.singleShot(2000, loop.quit); loop.exec()
        return received

    def test_scan_completion_updates_every_view_without_navigation(self) -> None:
        results = [finding("uac", "User Account Control", "OS Security", CheckStatus.PASS, 15), finding("bitlocker_system", "BitLocker", "OS Security", CheckStatus.FAIL, 30)]
        window = self.make_window(results); self.assertTrue(self.run_scan_and_wait(window))
        self.assertEqual(window.score_panel.value.text(), "100.0%")
        self.assertEqual(window.coverage_panel.value.text(), "100.0%")
        self.assertEqual(window.category_table.rowCount(), 5)
        self.assertEqual(window.tree.topLevelItemCount(), 0)
        window.current_status_filter.setCurrentText("All Checks")
        self.assertEqual(window.tree.topLevelItemCount(), 2)
        self.assertGreater(window.dashboard_findings.topLevelItemCount(), 0)
        self.assertIn("all assessment views updated", window.scan_message.text())
        self.assertEqual(window.assessment_privilege_label.text(), "Assessment privilege: Standard")
        self.assertEqual(window.assessment_source_label.text(), "Scoring policy: 2.1")
        self.finish_thread(window)

    def test_standard_scan_replaces_elevated_assessment_metadata_and_results(self) -> None:
        standard_results = [finding("uac", "Standard UAC result", "OS Security", CheckStatus.PASS, 15)]
        window = self.make_window(standard_results)
        elevated_results = [finding("uac", "Elevated old result", "OS Security", CheckStatus.FAIL, 15)]
        elevated_score = score_results(elevated_results, self.config, "Standard")
        window._commit_assessment(AssessmentEnvelope(elevated_results, elevated_score, "2025-01-01T00:00:00+00:00", "Administrator", "Live elevated scan"), False)
        self.assertIn("Administrator", window.assessment_privilege_label.text())
        self.assertTrue(self.run_scan_and_wait(window))
        self.assertEqual(window.app_privilege_label.text(), "Application privilege: Standard")
        self.assertEqual(window.assessment_privilege_label.text(), "Assessment privilege: Standard")
        self.assertEqual(window.assessment_source_label.text(), "Scoring policy: 2.1")
        self.assertNotIn("2025-01-01", window.assessment_timestamp_label.text())
        window.current_status_filter.setCurrentText("All Checks")
        self.assertEqual(window.tree.topLevelItem(0).text(0), "Standard UAC result")
        self.finish_thread(window)


if __name__ == "__main__": unittest.main()
