from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

from wincur import APP_VERSION
from wincur.build_info import DEVELOPMENT_BUILD_ID
from wincur.models import AssessmentScore, ScanRecord
from wincur.reporting import export_html
from wincur.scoring import load_scoring_config
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


class VersioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_title_about_and_report_use_implemented_version(self) -> None:
        self.assertEqual(APP_VERSION, "1.0.0")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manager = ThemeManager(root / "appearance.json"); window = WinCurWindow(manager)
            self.assertIn(f"WinCur {APP_VERSION}", window.windowTitle())
            self.assertTrue(any(f"Build: {DEVELOPMENT_BUILD_ID}" in label.text() for label in window.pages.widget(3).findChildren(QLabel)))
            with patch.object(QMessageBox, "about") as about:
                window._show_about(); self.assertIn(f"WinCur {APP_VERSION}", about.call_args.args[2]); self.assertIn(f"Build: {DEVELOPMENT_BUILD_ID}", about.call_args.args[2])
            assessment = AssessmentScore(100.0, 100.0, profile="Standard", policy_version="2.1")
            record = ScanRecord.create(APP_VERSION, "Windows 11", "TEST", [], assessment, "Standard")
            report = export_html(record, load_scoring_config(), root / "report.html").read_text(encoding="utf-8")
            self.assertIn(f"WinCur {APP_VERSION}", report); self.assertNotIn("WinCur 0.4", report)
            window.close()


if __name__ == "__main__": unittest.main()
