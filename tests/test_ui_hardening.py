from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from wincur.ui import WinCurWindow


class HardeningUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_preview_and_apply_are_distinct_and_apply_starts_disabled(self) -> None:
        window = WinCurWindow()
        self.assertEqual(window.preview_selected_button.text(), "Preview Selected Action")
        self.assertEqual(window.apply_button.text(), "Apply Selected Action")
        self.assertFalse(window.apply_button.isEnabled())
        window.close()


if __name__ == "__main__": unittest.main()
