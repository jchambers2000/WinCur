from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPixmap
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

from wincur.branding import EASTER_EGG_TEXT, HeaderLogo, PortraitView, load_application_icon
from wincur.theme import ThemeManager
from wincur.ui import ModernHeader


def artwork() -> QPixmap:
    pixmap = QPixmap(1024, 1024); pixmap.fill(QColor("white")); painter = QPainter(pixmap); painter.setPen(QColor("black")); painter.drawEllipse(180, 80, 660, 820); painter.end(); return pixmap


class BrandingInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_five_clicks_trigger_once_and_fewer_clicks_do_nothing(self) -> None:
        logo = HeaderLogo(artwork(), 1000); triggered = []; logo.triggered.connect(lambda: triggered.append(True)); logo.show(); self.app.processEvents()
        for _ in range(4): QTest.mouseClick(logo, Qt.MouseButton.LeftButton)
        self.assertEqual(triggered, []); self.assertEqual(logo.click_count, 4)
        QTest.mouseClick(logo, Qt.MouseButton.LeftButton)
        self.assertEqual(triggered, [True]); self.assertEqual(logo.click_count, 0); logo.close()

    def test_timeout_resets_continuous_click_sequence(self) -> None:
        logo = HeaderLogo(artwork(), 40); triggered = []; logo.triggered.connect(lambda: triggered.append(True)); logo.show()
        QTest.mouseClick(logo, Qt.MouseButton.LeftButton); QTest.mouseClick(logo, Qt.MouseButton.LeftButton); QTest.qWait(80)
        self.assertEqual(logo.click_count, 0)
        for _ in range(5): QTest.mouseClick(logo, Qt.MouseButton.LeftButton)
        self.assertEqual(triggered, [True]); logo.close()

    def test_repeated_triggering_uses_one_modal_at_a_time_and_close_resets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            header = ModernHeader(ThemeManager(Path(directory) / "theme.json"), portrait=artwork(), click_window_ms=1000); header.show(); self.app.processEvents()
            for _ in range(5): QTest.mouseClick(header.logo, Qt.MouseButton.LeftButton)
            first = header.easter_dialog; self.assertIsNotNone(first); self.assertTrue(first.isModal()); self.assertTrue(first.isVisible())
            header._show_easter_egg(); self.assertIs(header.easter_dialog, first)
            phrases = [label.text() for label in first.findChildren(QLabel)]; self.assertIn(EASTER_EGG_TEXT, phrases)
            first.reject(); self.app.processEvents(); self.assertIsNone(header.easter_dialog); self.assertEqual(header.logo.click_count, 0)
            for _ in range(5): QTest.mouseClick(header.logo, Qt.MouseButton.LeftButton)
            second = header.easter_dialog; self.assertIsNotNone(second); self.assertIsNot(second, first)
            QTest.keyClick(second, Qt.Key.Key_Escape); self.app.processEvents(); self.assertIsNone(header.easter_dialog); header.close()

    def test_four_header_clicks_do_not_open_dialog_or_change_other_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            header = ModernHeader(ThemeManager(Path(directory) / "theme.json"), portrait=artwork(), click_window_ms=1000); marker = "unchanged"; header.setProperty("securityState", marker); header.show()
            for _ in range(4): QTest.mouseClick(header.logo, Qt.MouseButton.LeftButton)
            self.assertIsNone(header.easter_dialog); self.assertEqual(header.logo.click_count, 4); self.assertEqual(header.property("securityState"), marker); header.close()

    def test_missing_artwork_never_activates_or_substitutes_an_icon(self) -> None:
        logo = HeaderLogo(QPixmap(), 20); triggered = []; logo.triggered.connect(lambda: triggered.append(True))
        for _ in range(5): logo.register_click()
        self.assertEqual(triggered, []); self.assertFalse(logo.has_artwork); self.assertIn("missing", logo.toolTip().casefold())
        with tempfile.TemporaryDirectory() as directory: self.assertTrue(load_application_icon(Path(directory) / "missing.ico").isNull())
        self.assertFalse(load_application_icon().isNull())

    def test_portrait_rendering_retains_high_resolution_source_at_high_dpi(self) -> None:
        view = PortraitView(artwork(), 48); self.assertEqual(view.source_size.width(), 1024)
        target = QImage(96, 96, QImage.Format.Format_ARGB32_Premultiplied); target.setDevicePixelRatio(2.0); target.fill(Qt.GlobalColor.transparent); view.render(target)
        self.assertEqual(view.size().width(), 48); self.assertFalse(target.isNull()); self.assertTrue(any(target.pixelColor(x, 48).alpha() for x in range(target.width())))


if __name__ == "__main__": unittest.main()
