from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


class AssessmentOnlyPrivilegeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app = QApplication.instance() or QApplication([])

    def make_window(self, administrator=False):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        with patch("wincur.ui.load_history", return_value=[]), patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=administrator):
            window = WinCurWindow(ThemeManager(root / "appearance.json"), baseline_path=root / "baselines.json", history_path=root / "history.jsonl", layout_path=root / "layout.json")
        window._test_temporary_directory = temporary
        return window

    def test_manually_elevated_process_is_passively_labeled_without_elevation_control(self):
        window = self.make_window(administrator=True)
        self.assertIn("Administrator Mode", window.administrator_mode_label.text())
        self.assertFalse(any(button.text() == "Scan as Administrator" for button in window.findChildren(QPushButton)))
        self.assertFalse(hasattr(window, "elevated_button"))
        window.close()

    def test_standard_mode_has_only_standard_scan_control(self):
        window = self.make_window(administrator=False)
        texts = [button.text() for button in window.findChildren(QPushButton)]
        self.assertIn("Scan PC", texts)
        self.assertNotIn("Scan as Administrator", texts)
        self.assertFalse(hasattr(window, "administrator_mode_label"))
        window.close()


if __name__ == "__main__": unittest.main()
