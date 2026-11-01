from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QCheckBox, QMessageBox, QPushButton, QStyle, QStyleOptionButton, QStyleOptionComboBox

from wincur.models import AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.theme import AppearanceMode, DARK, LIGHT, ThemeManager
from wincur.ui import WinCurWindow


class ThemeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.path = Path(self.temp.name) / "appearance.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_existing_users_default_to_light_without_preference(self) -> None:
        manager = ThemeManager(self.path, system_detector=lambda: True)
        self.assertEqual(manager.mode, AppearanceMode.LIGHT)
        self.assertEqual(manager.tokens, LIGHT)

    def test_preference_persists_separately(self) -> None:
        manager = ThemeManager(self.path); manager.set_mode(AppearanceMode.DARK)
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), {"appearance": "Dark"})
        self.assertEqual(ThemeManager(self.path).mode, AppearanceMode.DARK)

    def test_switching_updates_application_without_restart(self) -> None:
        manager = ThemeManager(self.path); manager.apply(self.app)
        manager.set_mode(AppearanceMode.DARK, persist=False)
        self.assertEqual(manager.tokens, DARK)
        self.assertEqual(self.app.palette().window().color(), QColor(DARK.window))
        manager.set_mode(AppearanceMode.LIGHT, persist=False)
        self.assertEqual(self.app.palette().window().color(), QColor(LIGHT.window))

    def test_system_mode_tracks_detector_change(self) -> None:
        state = {"dark": False}; manager = ThemeManager(self.path, system_detector=lambda: state["dark"])
        manager.set_mode(AppearanceMode.SYSTEM, persist=False); self.assertEqual(manager.effective_mode, AppearanceMode.LIGHT)
        state["dark"] = True; manager.check_system_preference()
        self.assertEqual(manager.effective_mode, AppearanceMode.DARK)

    def test_both_themes_start_window_offscreen(self) -> None:
        for mode in (AppearanceMode.LIGHT, AppearanceMode.DARK):
            manager = ThemeManager(self.path); manager.set_mode(mode, persist=False); window = WinCurWindow(manager)
            self.assertEqual(window.header.tokens.name, mode.value)
            self.assertEqual(window.appearance_combo.currentText(), mode.value)
            window.close()

    def test_dynamic_dialog_and_widget_inherit_dark_palette(self) -> None:
        manager = ThemeManager(self.path); manager.set_mode(AppearanceMode.DARK, persist=False)
        window = WinCurWindow(manager); dialog = QMessageBox(window); button = QPushButton("Dynamic", window)
        self.assertEqual(dialog.palette().window().color(), QColor(DARK.window))
        self.assertEqual(button.palette().buttonText().color(), QColor(DARK.button_text))
        dialog.close(); window.close()

    def test_existing_severity_items_recolor_when_theme_changes(self) -> None:
        manager = ThemeManager(self.path); manager.set_mode(AppearanceMode.DARK, persist=False)
        finding = CheckResult("autorun", "AutoRun", "Attack Surface", CheckStatus.FAIL, "evidence", "explanation", 10, "High")
        assessment = AssessmentScore(0.0, 100.0, profile="Standard", policy_version="2.0", dispositions={"autorun": "Scored"})
        record = ScanRecord.create("0.8.0", "Windows 11", "TEST", [finding], assessment, "Standard").to_dict()
        with patch("wincur.ui.load_history", return_value=[record]), patch("wincur.ui.load_action_history", return_value=[]):
            window = WinCurWindow(manager); window._view_history_record(record)
        dark_issue = window.tree.topLevelItem(0).foreground(1).color(); dark_overview = window.dashboard_findings.topLevelItem(0).foreground(2).color()
        manager.set_mode(AppearanceMode.LIGHT, persist=False); self.app.processEvents()
        self.assertEqual(window.tree.topLevelItem(0).foreground(1).color(), QColor(LIGHT.high))
        self.assertEqual(window.dashboard_findings.topLevelItem(0).foreground(2).color(), QColor(LIGHT.high))
        self.assertEqual(window.tree.topLevelItem(0).background(1).style().value, 0)
        self.assertNotEqual(dark_issue, window.tree.topLevelItem(0).foreground(1).color()); self.assertNotEqual(dark_overview, window.dashboard_findings.topLevelItem(0).foreground(2).color())
        window.close()

    def test_activity_controls_combo_arrows_and_checkboxes_render_after_theme_switch(self) -> None:
        manager = ThemeManager(self.path); window = WinCurWindow(manager); window.resize(1180, 800); window.show(); self.app.processEvents()
        for mode in (AppearanceMode.DARK, AppearanceMode.LIGHT, AppearanceMode.SYSTEM):
            manager.set_mode(mode, persist=False); self.app.processEvents()
            option = QStyleOptionComboBox(); option.initFrom(window.profile_combo)
            arrow = window.profile_combo.style().subControlRect(QStyle.ComplexControl.CC_ComboBox, option, QStyle.SubControl.SC_ComboBoxArrow, window.profile_combo)
            self.assertGreater(arrow.width(), 0); self.assertGreaterEqual(arrow.left(), window.profile_combo.width() // 2)
            self.assertEqual([button.text() for button in window.activity_view_buttons], ["Scan History", "Hardening Audit"])
            self.assertTrue(all(button.height() >= 30 for button in window.activity_view_buttons))
            checkbox = QCheckBox("Visible selection", window); checkbox.setChecked(True); checkbox.show(); checkbox_option = QStyleOptionButton(); checkbox_option.initFrom(checkbox)
            indicator = checkbox.style().subElementRect(QStyle.SubElement.SE_CheckBoxIndicator, checkbox_option, checkbox)
            self.assertGreaterEqual(indicator.width(), 16); self.assertGreaterEqual(indicator.height(), 16); checkbox.close()
            self.assertIn("QTableView::indicator:checked", self.app.styleSheet()); self.assertIn("QCheckBox::indicator:disabled", self.app.styleSheet())
        window.close()

    def test_repeated_navigation_and_theme_switches_keep_page_text_readable(self) -> None:
        manager = ThemeManager(self.path); window = WinCurWindow(manager); window.show(); self.app.processEvents()
        for mode in (AppearanceMode.LIGHT, AppearanceMode.DARK, AppearanceMode.LIGHT, AppearanceMode.SYSTEM, AppearanceMode.LIGHT):
            manager.set_mode(mode, persist=False); self.app.processEvents(); expected = manager.tokens
            for page in range(4):
                window._set_page(page); self.app.processEvents(); self.assertEqual(window.page_heading.palette().color(QPalette.ColorRole.WindowText), QColor(expected.heading)); self.assertEqual(window.page_subtitle.palette().color(QPalette.ColorRole.WindowText), QColor(expected.muted_text))
            self.assertNotIn("QTableWidget:!active::item:selected", self.app.styleSheet())
        window.close()


if __name__ == "__main__": unittest.main()
