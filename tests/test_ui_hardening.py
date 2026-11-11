from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


class AssessmentOnlyUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_mutation_controls_are_absent_and_recommendations_remain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            window = WinCurWindow(ThemeManager(root / "appearance.json"), baseline_path=root / "baselines.json", history_path=root / "history.jsonl", layout_path=root / "layout.json")
            button_texts = {button.text() for button in window.findChildren(QPushButton)}
            for removed in (
                "Fix workspace", "Preview Selected Action", "Apply Selected Action",
                "View Available Fix", "Rollback Selected Action", "Scan as Administrator",
            ):
                self.assertNotIn(removed, button_texts)
            self.assertIn("Scan PC", button_texts)
            self.assertIn("Open Windows Settings", button_texts)
            self.assertFalse(hasattr(window, "apply_button"))
            self.assertFalse(hasattr(window, "rollback_button"))
            self.assertFalse(hasattr(window, "elevated_button"))
            window.close()


if __name__ == "__main__": unittest.main()
