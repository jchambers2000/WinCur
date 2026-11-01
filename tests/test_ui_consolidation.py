from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QImage, QPainter, QTextOption
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QWidget

from wincur.history_analysis import history_point
from wincur.hardening import ACTIONS, HardeningEngine
from wincur.models import ActionAvailability, AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.theme import AppearanceMode, ThemeManager
from wincur.ui import LayoutStateStore, ResponsiveSplitter, TrendChart, WinCurWindow, evidence_preview, friendly_timestamp


def saved_record(timestamp="2026-10-29T12:30:00+00:00", privilege="Standard") -> dict:
    assessment = AssessmentScore(82.0, 91.0, profile="Standard", policy_version="2.0")
    return ScanRecord.create("0.8.5", "Windows 11", "TEST", [], assessment, privilege, timestamp_utc=timestamp).to_dict()


def issue_record(status: CheckStatus = CheckStatus.FAIL) -> dict:
    finding = CheckResult("autorun", "AutoRun Policy", "Attack Surface", status, "raw technical evidence", "Automatic media execution is enabled.", 25, "Medium")
    assessment = AssessmentScore(0.0 if status == CheckStatus.FAIL else 100.0, 100.0, profile="Standard", policy_version="2.0", dispositions={"autorun": "Scored"})
    return ScanRecord.create("0.8.5", "Windows 11", "TEST", [finding], assessment, "Standard", timestamp_utc="2026-10-29T12:30:00+00:00").to_dict()


class ConsolidatedUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.theme = ThemeManager(Path(self.temp.name) / "appearance.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_window(self, history=None, actions=None) -> WinCurWindow:
        with patch("wincur.ui.load_history", return_value=list(history or [])), patch("wincur.ui.load_action_history", return_value=list(actions or [])), patch("wincur.ui.is_administrator", return_value=False):
            return WinCurWindow(self.theme, baseline_path=Path(self.temp.name) / "baselines.json")

    def test_sidebar_and_activity_are_the_only_primary_navigation(self) -> None:
        window = self.make_window(); self.assertIsInstance(window.pages, QStackedWidget); self.assertEqual(window.pages.count(), 4); self.assertEqual(len(window.nav_buttons), 4)
        self.assertEqual(len(window.findChildren(QTabWidget)), 0)
        self.assertEqual([button.text() for button in window.activity_view_buttons], ["Scan History", "Hardening Audit"]); self.assertEqual(window.activity_pages.count(), 2); self.assertEqual(window.activity_pages.currentIndex(), 0)
        window.activity_view_buttons[1].click(); self.assertEqual(window.activity_pages.currentIndex(), 1)
        window.nav_buttons[2].click(); self.assertEqual(window.page_subtitle.text(), "Review previous security assessments and hardening activity."); window.close()

    def test_snapshot_management_is_modal_without_new_primary_navigation(self) -> None:
        window = self.make_window(); button_texts = {button.text() for button in window.findChildren(type(window.scan_button))}
        self.assertNotIn("Security Trends", button_texts); self.assertIn("Manage Saved Snapshots…", button_texts); self.assertNotIn("Saved Changes", button_texts); self.assertIsNone(window.baseline_dialog)
        with patch("wincur.ui.QDialog.exec", return_value=0): window._open_saved_snapshots()
        self.assertEqual(window.pages.count(), 4); self.assertEqual(window.pages.currentIndex(), 0); self.assertIsNotNone(window.baseline_dialog); self.assertTrue(hasattr(window, "active_baseline_combo"))
        window._set_activity_view(99); self.assertEqual(window.activity_pages.currentIndex(), 0); window.close()

    def test_scan_history_uses_compact_columns_summary_and_details(self) -> None:
        record = saved_record(); window = self.make_window([record], [{"timestamp_utc": record["timestamp_utc"]}])
        self.assertEqual([window.history_table.horizontalHeaderItem(i).text() for i in range(window.history_table.columnCount())], ["Select", "Scan date/time", "Privilege", "Profile", "Score", "Coverage"])
        self.assertIn("1 saved assessment", window.history_label.text()); self.assertIn("1 hardening audit record", window.history_label.text())
        window.history_table.selectRow(0); self.app.processEvents(); details = window.history_record_details.toPlainText()
        for text in ("Assessment date", "Standard", "2.0", "82.0%", "91.0%", "TEST"): self.assertIn(text, details)
        self.assertEqual(window.last_assessment_button.text(), "Open Assessment"); window.close()

    def test_scan_history_empty_state_is_concise(self) -> None:
        window = self.make_window(); self.assertEqual(window.history_record_details.toPlainText(), "Select an assessment to view its details."); window.close()

    def test_hardening_audit_columns_do_not_invent_success(self) -> None:
        action = {"timestamp_utc": "2026-10-29T12:30:00+00:00", "action_id": "disable_autorun", "outcome": "Denied", "verification_evidence": "Permission denied", "rollback_status": "Not requested", "message": "No change was made"}
        window = self.make_window(actions=[action]); headers = [window.action_history_table.horizontalHeaderItem(i).text() for i in range(window.action_history_table.columnCount())]
        self.assertEqual(headers, ["Date and time", "Action", "Operation type", "Result", "Verification / rollback"]); self.assertEqual(window.action_history_table.item(0, 2).text(), "Hardening action"); self.assertEqual(window.action_history_table.item(0, 3).text(), "Denied"); self.assertNotIn("Success", " ".join(window.action_history_table.item(0, i).text() for i in range(5))); window.close()

    def test_malformed_legacy_audit_record_cannot_appear_rollback_actionable(self) -> None:
        record = {"timestamp_utc": "2026-10-29T12:30:00+00:00", "action_id": "disable_autorun", "outcome": "Success", "rollback_available": True, "original_configuration": {"values": []}, "requested_configuration": {"recommended": "legacy"}}
        window = self.make_window(actions=[record])
        with patch("wincur.ui.load_action_history", return_value=[record]): window.action_history_table.selectRow(0); window._update_rollback_button()
        self.assertFalse(window.rollback_button.isEnabled()); self.assertIn("schema", window.rollback_button.toolTip().lower()); window.close()

    def test_page_changes_clear_highlight_but_preserve_delete_checkbox(self) -> None:
        window = self.make_window([saved_record()]); window.show(); window._set_page(2); window.history_table.selectRow(0); window.history_table.item(0, 0).setCheckState(Qt.CheckState.Checked)
        window._set_page(0); self.assertFalse(window.history_table.selectionModel().hasSelection()); self.assertEqual(window.history_table.item(0, 0).checkState(), Qt.CheckState.Checked); window.close()

    def test_historical_selection_is_explicit_and_returns_to_overview(self) -> None:
        record = saved_record(); window = self.make_window([record]); window._set_page(2); window.history_table.selectRow(0); window._view_selected_history()
        self.assertEqual(window.pages.currentIndex(), 0); self.assertIn("Historical", window.current_record.assessment_source); self.assertIn("not a current scan", window.assessment_source_label.text()); window.close()

    def test_problem_first_findings_and_fix_workspace_remain_intact(self) -> None:
        record = issue_record(); window = self.make_window([record]); window._view_history_record(record)
        self.assertEqual(window.findings_panel.value.text(), "1"); self.assertEqual(window.tree.topLevelItemCount(), 1); self.assertTrue(window.technical_finding_details.isHidden()); window._toggle_finding_technical(); self.assertIn("raw technical evidence", window.technical_finding_details.toPlainText())
        window._open_finding_fix(); self.assertEqual(window.pages.currentIndex(), 1); self.assertEqual(window.issues_pages.currentIndex(), 1); self.assertTrue(window.issues_view_buttons[1].isChecked()); self.assertFalse(window.apply_button.isEnabled()); window.close()

    def test_hardening_refresh_clears_stale_preview_and_marks_transitions(self) -> None:
        window = self.make_window(); action_ids = list(ACTIONS); selected = window.action_tree.topLevelItem(0); window.action_tree.setCurrentItem(selected)
        window.previews = [SimpleNamespace(action_id=action_ids[0])]; window.validated_preview = window.previews[0]; window.apply_button.setEnabled(True)
        window._mark_previews_pending(action_ids)
        self.assertEqual(window.previews, []); self.assertFalse(window.apply_button.isEnabled())
        self.assertTrue(all(window.action_tree.topLevelItem(row).text(2) == "Reading configuration" for row in range(window.action_tree.topLevelItemCount())))
        preview = HardeningEngine._preview(ACTIONS[action_ids[0]], ActionAvailability.MANAGED, "Current state", "Confirmed management evidence")
        window._previews_ready([preview])
        self.assertEqual(selected.text(2), ActionAvailability.MANAGED.value)
        self.assertEqual(window.action_tree.topLevelItem(1).text(2), "Refresh failed")
        self.assertIs(window.action_tree.currentItem(), selected); self.assertFalse(window.apply_button.isEnabled()); window.close()

    def test_hardening_refresh_failure_never_retains_actionable_state(self) -> None:
        window = self.make_window(); action_id = next(iter(ACTIONS)); item = window.action_tree.topLevelItem(0); window.action_tree.setCurrentItem(item)
        window.previews = [SimpleNamespace(action_id=action_id)]; window.validated_preview = window.previews[0]; window.apply_button.setEnabled(True); window._mark_previews_pending([action_id])
        with patch("wincur.ui.QMessageBox.warning"): window._previews_failed("provider failed")
        self.assertEqual(item.text(2), "Refresh failed"); self.assertEqual(item.text(3), "Configuration unavailable")
        self.assertIsNone(window.validated_preview); self.assertFalse(window.apply_button.isEnabled()); self.assertEqual(window.preview_status_title.text(), "Preview failed"); window.close()

    def test_apply_explains_explicit_preview_requirement_and_completion(self) -> None:
        window = self.make_window(); item = window.action_tree.topLevelItem(0); window.action_tree.setCurrentItem(item); window._show_action(item, None)
        self.assertEqual(window.preview_status_title.text(), "Preview required before applying")
        self.assertEqual(window.preview_status_text.text(), "Review the proposed changes before applying this remediation. No changes will be made during the preview.")
        self.assertFalse(window.apply_button.isEnabled()); self.assertEqual(window.apply_button.toolTip(), "Preview this remediation before applying it.")
        action_id = str(item.data(0, Qt.ItemDataRole.UserRole)); preview = HardeningEngine._preview(ACTIONS[action_id], ActionAvailability.AVAILABLE, "Current state", "Not managed", token="preview-token", created_utc=datetime.now(timezone.utc).isoformat())
        window.preview_mode = "selected"; window.preview_request_ids = [action_id]; window._previews_ready([preview])
        self.assertEqual(window.preview_status_title.text(), "Preview complete"); self.assertEqual(window.preview_status_text.text(), "This action is ready for confirmation.")
        self.assertTrue(window.apply_button.isEnabled()); self.assertIn("explicit confirmation", window.apply_button.toolTip()); window.close()

    def test_preview_status_updates_when_switching_to_blocked_action(self) -> None:
        window = self.make_window(); first = window.action_tree.topLevelItem(0); second = window.action_tree.topLevelItem(1)
        first_id = str(first.data(0, Qt.ItemDataRole.UserRole)); second_id = str(second.data(0, Qt.ItemDataRole.UserRole))
        available = HardeningEngine._preview(ACTIONS[first_id], ActionAvailability.AVAILABLE, "Current", "Not managed", token="ready", created_utc=datetime.now(timezone.utc).isoformat())
        managed = HardeningEngine._preview(ACTIONS[second_id], ActionAvailability.MANAGED, "Current", "Matching Group Policy settings=1", token="blocked", created_utc=datetime.now(timezone.utc).isoformat())
        window.previews = [available, managed]; window._accept_validated_preview(available)
        window.action_tree.setCurrentItem(first); window._show_action(first, None); self.assertEqual(window.preview_status_title.text(), "Preview complete"); self.assertTrue(window.apply_button.isEnabled())
        window.action_tree.setCurrentItem(second); window._show_action(second, first); self.assertEqual(window.preview_status_title.text(), "Action blocked — managed setting"); self.assertIn("Matching Group Policy", window.preview_status_text.text()); self.assertFalse(window.apply_button.isEnabled()); self.assertEqual(window.apply_button.toolTip(), "Preview this remediation before applying it.")
        window.close()

    def test_expired_preview_requires_a_new_preview(self) -> None:
        window = self.make_window(); item = window.action_tree.topLevelItem(0); action_id = str(item.data(0, Qt.ItemDataRole.UserRole))
        preview = HardeningEngine._preview(ACTIONS[action_id], ActionAvailability.AVAILABLE, "Current", "Not managed", token="ready", created_utc=datetime.now(timezone.utc).isoformat())
        window.previews = [preview]; window._accept_validated_preview(preview); window.action_tree.setCurrentItem(item); window._show_action(item, None); self.assertTrue(window.apply_button.isEnabled())
        window._expire_validated_preview(); self.assertFalse(window.apply_button.isEnabled()); self.assertEqual(window.preview_status_title.text(), "Preview required again"); self.assertIn("expired", window.preview_status_text.text()); window.close()

    def test_already_stale_preview_is_never_authorized(self) -> None:
        window = self.make_window(); item = window.action_tree.topLevelItem(0); action_id = str(item.data(0, Qt.ItemDataRole.UserRole))
        stale_time = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(); preview = HardeningEngine._preview(ACTIONS[action_id], ActionAvailability.AVAILABLE, "Current", "Not managed", token="stale", created_utc=stale_time)
        window.previews = [preview]; window._accept_validated_preview(preview); window.action_tree.setCurrentItem(item); window._show_action(item, None)
        self.assertIsNone(window.validated_preview); self.assertFalse(window.apply_button.isEnabled()); self.assertEqual(window.preview_status_title.text(), "Preview required again"); window.close()

    def test_unknown_is_not_counted_as_a_confirmed_finding(self) -> None:
        record = issue_record(CheckStatus.UNKNOWN); window = self.make_window([record]); window._view_history_record(record)
        self.assertEqual(window.findings_panel.value.text(), "0"); self.assertIn("1 could not be assessed", window.findings_panel.description.text()); self.assertEqual(window.tree.topLevelItemCount(), 0)
        window.current_status_filter.setCurrentText("Could Not Assess"); self.assertEqual(window.tree.topLevelItemCount(), 1); window.close()

    def test_confirmed_failure_count_excludes_unknown_in_mixed_assessment(self) -> None:
        failed = CheckResult("autorun", "AutoRun", "Attack Surface", CheckStatus.FAIL, "disabled=false", "AutoRun is enabled.", 25, "Medium")
        unknown = CheckResult("smartscreen", "SmartScreen", "Attack Surface", CheckStatus.UNKNOWN, "Diagnostic reason: Not configured / insufficient evidence.", "Protection state is inconclusive.", 25, "High")
        assessment = AssessmentScore(0.0, 50.0, profile="Advanced", policy_version="2.1", dispositions={"autorun": "Scored", "smartscreen": "Scored"})
        record = ScanRecord.create("0.9.5", "Windows 11", "TEST", [failed, unknown], assessment, "Administrator", timestamp_utc="2026-10-31T12:30:00+00:00").to_dict()
        window = self.make_window([record]); window._view_history_record(record)
        self.assertEqual(window.findings_panel.value.text(), "1"); self.assertIn("1 could not be assessed", window.findings_panel.description.text()); window.close()

    def test_unknown_scoring_terms_and_admin_context_recommendation_are_clear(self) -> None:
        finding = CheckResult("local_admins", "Local Administrators membership", "Account Security", CheckStatus.UNKNOWN, "Diagnostic reason: Ambiguous configuration. Enumeration succeeded; direct members=2.", "Membership was enumerated, but the approved_local_administrators policy is empty, so WinCur will not guess whether these administrators are authorized.", 60, "High")
        assessment = AssessmentScore(100.0, 40.0, profile="Advanced", policy_version="2.1", dispositions={"local_admins": "Scored"}, disposition_explanations={"local_admins": "This check is scored by the Advanced profile."})
        record = ScanRecord.create("0.9.5", "Windows 11", "TEST", [finding], assessment, "Administrator", timestamp_utc="2026-10-31T12:30:00+00:00").to_dict()
        window = self.make_window([record]); window._view_history_record(record); window.current_status_filter.setCurrentText("Could Not Assess"); self.app.processEvents()
        details = window.details.toPlainText(); self.assertIn("Configure an approved-administrator policy", details); self.assertNotIn("try an Administrator assessment", details)
        window._toggle_finding_technical(); technical = window.technical_finding_details.toPlainText(); self.assertIn("Scoring eligibility", technical); self.assertIn("Included in the Advanced profile", technical); self.assertIn("Inconclusive", technical); self.assertIn("reduces assessment coverage", technical); window.close()

    def test_missing_smartscreen_recommendation_points_to_reputation_settings(self) -> None:
        finding = CheckResult("smartscreen", "Microsoft Defender SmartScreen", "Attack Surface", CheckStatus.UNKNOWN, "Diagnostic reason: Not configured / insufficient evidence. SmartScreenEnabled exists=False, value=not present", "The inspected configuration values are not present.", 25, "High")
        assessment = AssessmentScore(None, 0.0, profile="Advanced", policy_version="2.1", dispositions={"smartscreen": "Scored"})
        record = ScanRecord.create("0.9.5", "Windows 11", "TEST", [finding], assessment, "Administrator", timestamp_utc="2026-10-31T12:30:00+00:00").to_dict()
        window = self.make_window([record]); window._view_history_record(record); window.current_status_filter.setCurrentText("Could Not Assess"); self.app.processEvents()
        self.assertIn("Windows Security > App & browser control", window.details.toPlainText()); window.close()

    def test_security_issue_detail_panel_starts_at_top_of_left_workspace(self) -> None:
        window = self.make_window([issue_record()]); window.resize(1600, 900); window.show(); window._view_history_record(issue_record()); window._set_page(1); self.app.processEvents(); window.findings_splitter.update_for_width(1200); self.app.processEvents()
        self.assertEqual(window.findings_splitter.orientation(), Qt.Orientation.Horizontal)
        self.assertEqual(window.findings_list_panel.geometry().top(), window.finding_detail_panel.geometry().top())
        self.assertLessEqual(window.detail_title.geometry().top(), window.current_status_filter.geometry().bottom())
        self.assertTrue(window.finding_technical_button.isVisible()); self.assertTrue(window.finding_fix_button.isVisible()); window.close()

    def test_advanced_finding_filters_remain_optional_and_resettable(self) -> None:
        record = issue_record(); window = self.make_window([record]); window._view_history_record(record)
        self.assertTrue(window.findings_advanced_filters.isHidden()); window.findings_advanced_button.click(); self.assertFalse(window.findings_advanced_filters.isHidden()); self.assertNotEqual(window.finding_category_combo.findText("Attack Surface"), -1)
        window.finding_severity_combo.setCurrentText("High"); self.assertEqual(window.tree.topLevelItemCount(), 0); window.reset_findings_filters_button.click(); self.assertEqual(window.finding_category_combo.currentText(), "All categories"); self.assertEqual(window.tree.topLevelItemCount(), 1); window.close()

    def test_dashboard_snapshot_summary_still_uses_preserved_comparison_engine(self) -> None:
        baseline_record = issue_record(CheckStatus.PASS); baseline_record["timestamp_utc"] = "2026-10-28T12:30:00+00:00"; current_record = issue_record(CheckStatus.FAIL)
        window = self.make_window([baseline_record, current_record]); baseline = window.baseline_store.create(window.baseline_collection, "Trusted", baseline_record); window.baseline_store.set_active(window.baseline_collection, baseline.baseline_id); window._refresh_baseline_ui(); window._view_history_record(current_record)
        self.assertIn("1 security setting", window.dashboard_baseline_label.text()); window.baseline_change_filter.setCurrentText("Security setting worsened"); self.assertEqual(window.tree.topLevelItemCount(), 1); window.close()

    def test_responsive_findings_splitter_preserves_both_panes(self) -> None:
        splitter = ResponsiveSplitter(820); splitter.addWidget(QStackedWidget()); splitter.addWidget(QStackedWidget()); splitter.update_for_width(700); self.assertEqual(splitter.orientation(), Qt.Orientation.Vertical); splitter.update_for_width(1000); self.assertEqual(splitter.orientation(), Qt.Orientation.Horizontal); self.assertFalse(splitter.childrenCollapsible()); splitter.close()

    def test_responsive_splitter_hysteresis_avoids_resize_thrashing(self) -> None:
        splitter = ResponsiveSplitter(860); splitter.addWidget(QWidget()); splitter.addWidget(QWidget())
        splitter.update_for_width(850); self.assertEqual(splitter.orientation(), Qt.Orientation.Vertical)
        splitter.update_for_width(900); self.assertEqual(splitter.orientation(), Qt.Orientation.Vertical)
        splitter.update_for_width(950); self.assertEqual(splitter.orientation(), Qt.Orientation.Horizontal)
        splitter.update_for_width(900); self.assertEqual(splitter.orientation(), Qt.Orientation.Horizontal)
        splitter.update_for_width(850); self.assertEqual(splitter.orientation(), Qt.Orientation.Vertical); splitter.close()

    def test_window_resize_preserves_finding_selection_and_reachable_actions(self) -> None:
        record = issue_record(); window = self.make_window([record]); window.show(); window._view_history_record(record); window._set_page(1); window.current_status_filter.setCurrentText("All Checks"); window.finding_category_combo.setCurrentText("Attack Surface"); window._toggle_finding_technical()
        for width, height, orientation in ((900, 640, Qt.Orientation.Vertical), (1024, 768, Qt.Orientation.Vertical), (1280, 800, Qt.Orientation.Vertical), (1600, 900, Qt.Orientation.Horizontal), (1024, 768, Qt.Orientation.Vertical)):
            window.resize(width, height); self.app.processEvents(); self.assertEqual(window.findings_splitter.orientation(), orientation); self.assertIsNotNone(window.tree.currentItem()); self.assertEqual(window.tree.currentItem().data(0, Qt.ItemDataRole.UserRole), 0); self.assertEqual(window.current_status_filter.currentText(), "All Checks"); self.assertEqual(window.finding_category_combo.currentText(), "Attack Surface"); self.assertFalse(window.technical_finding_details.isHidden()); self.assertTrue(window.finding_technical_button.isVisible()); self.assertTrue(window.finding_fix_button.isVisible()); self.assertTrue(window.settings_button.isVisible())
            if width == 900:
                self.assertGreaterEqual(window.tree.height(), 150); scroll = window.current_issues_scroll.verticalScrollBar(); self.assertGreater(scroll.maximum(), 0); scroll.setValue(scroll.maximum()); self.app.processEvents(); center = window.settings_button.mapTo(window.current_issues_scroll.viewport(), window.settings_button.rect().center()); self.assertTrue(window.current_issues_scroll.viewport().rect().contains(center))
        self.assertGreaterEqual(window.technical_finding_details.height(), 70); window._toggle_finding_technical(); self.assertTrue(window.technical_finding_details.isHidden()); window.close()

    def test_compact_empty_assessment_keeps_details_and_controls_reachable(self) -> None:
        window = self.make_window(); window.resize(1024, 768); window.show(); window._set_page(1); self.app.processEvents()
        self.assertEqual(window.findings_splitter.orientation(), Qt.Orientation.Vertical); self.assertEqual(window.tree.topLevelItemCount(), 0); self.assertTrue(window.detail_title.isVisible()); self.assertTrue(window.finding_technical_button.isVisible()); self.assertTrue(window.finding_fix_button.isVisible()); window.close()

    def test_medium_table_and_maximized_wide_geometry_remain_readable(self) -> None:
        record = issue_record(CheckStatus.UNKNOWN); window = self.make_window([record]); window.show(); window._view_history_record(record); window._set_page(1); window.current_status_filter.setCurrentText("Could Not Assess")
        window.resize(1280, 800); self.app.processEvents(); self.assertEqual(window.findings_splitter.orientation(), Qt.Orientation.Vertical); self.assertGreaterEqual(window.tree.columnWidth(3), 300); self.assertGreaterEqual(window.tree.columnWidth(2), window.tree.fontMetrics().horizontalAdvance("Could not assess"))
        window.resize(1920, 1080); self.app.processEvents(); self.assertEqual(window.findings_splitter.orientation(), Qt.Orientation.Horizontal); sizes = window.findings_splitter.sizes(); ratio = sizes[0] / sum(sizes); self.assertGreaterEqual(ratio, 0.60); self.assertLessEqual(ratio, 0.70); self.assertGreaterEqual(window.finding_detail_panel.width(), 350); window.close()

    def test_responsive_splitter_persists_both_modes_and_accepts_legacy_sizes(self) -> None:
        path = Path(self.temp.name) / "responsive-layout.json"; splitter = ResponsiveSplitter(860); splitter.addWidget(QWidget()); splitter.addWidget(QWidget()); splitter.resize(1100, 700); splitter.show(); splitter.update_for_width(1100); splitter.setSizes([700, 400]); self.app.processEvents(); splitter.update_for_width(700); splitter.setSizes([260, 435]); self.app.processEvents(); LayoutStateStore(path).save({"security_issues": splitter}); saved = LayoutStateStore(path).data["security_issues"]
        self.assertEqual(set(saved), {"horizontal", "vertical"}); self.assertTrue(all(sum(saved[key]) > 0 for key in saved))
        restored = ResponsiveSplitter(860); restored.addWidget(QWidget()); restored.addWidget(QWidget()); restored.restore_persistent_sizes(saved, [650, 350]); self.assertEqual(restored._saved_sizes[Qt.Orientation.Horizontal], saved["horizontal"])
        legacy = ResponsiveSplitter(860); legacy.addWidget(QWidget()); legacy.addWidget(QWidget()); legacy.restore_persistent_sizes([900, 100], [650, 350]); legacy.resize(1000, 600); legacy.show(); legacy.update_for_width(1000); self.app.processEvents(); self.assertGreaterEqual(legacy.sizes()[1], 300)
        corrupt = ResponsiveSplitter(860); corrupt.addWidget(QWidget()); corrupt.addWidget(QWidget()); corrupt.restore_persistent_sizes({"horizontal": [-1, 0], "vertical": "obsolete"}, [650, 350]); self.assertEqual(corrupt._saved_sizes[Qt.Orientation.Horizontal], [650, 350]); self.assertEqual(corrupt._saved_sizes[Qt.Orientation.Vertical], [220, 330])
        splitter.close(); restored.close(); legacy.close(); corrupt.close()

    def test_long_evidence_wraps_in_compact_mode_for_both_themes(self) -> None:
        record = issue_record(); record["results"][0]["evidence"] = "SmartScreen diagnostic; administrator SID=S-1-5-21-1234567890-1234567890-1234567890-1001; HKLM\\SOFTWARE\\AReallyLongUnbrokenRegistryPath\\" + ("abcdef0123456789" * 220)
        for mode in (AppearanceMode.LIGHT, AppearanceMode.DARK):
            self.theme.set_mode(mode, persist=False); self.theme.apply(self.app); window = self.make_window([record]); window.resize(1024, 768); window.show(); window._view_history_record(record); window._set_page(1); window._toggle_finding_technical(); self.app.processEvents()
            self.assertEqual(window.findings_splitter.orientation(), Qt.Orientation.Vertical); self.assertEqual(window.technical_finding_details.wordWrapMode(), QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere); self.assertEqual(window.technical_finding_details.horizontalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff); technical = window.technical_finding_details.toPlainText(); self.assertIn("SmartScreen diagnostic", technical); self.assertIn("S-1-5-21-1234567890", technical); self.assertIn("AReallyLongUnbrokenRegistryPath", technical); window.close()

    def test_main_layout_responds_at_supported_desktop_sizes(self) -> None:
        window = self.make_window(); window.show(); window._set_page(1)
        for width, height in ((900, 640), (1280, 720), (1366, 768), (1600, 900), (1920, 1080)):
            window.resize(width, height); self.app.processEvents(); self.assertTrue(window.page_heading.isVisible()); self.assertTrue(all(button.isVisible() for button in window.nav_buttons)); self.assertGreater(window.tree.width(), 0); self.assertGreater(window.details.width(), 0)
            expected = Qt.Orientation.Vertical if window.findings_splitter.width() < window.findings_splitter.breakpoint else Qt.Orientation.Horizontal; self.assertEqual(window.findings_splitter.orientation(), expected)
        window.close()

    def test_row_selection_is_immediate_and_keyboard_accessible(self) -> None:
        for mode in (AppearanceMode.LIGHT, AppearanceMode.DARK, AppearanceMode.SYSTEM):
            self.theme.set_mode(mode, persist=False); self.theme.apply(self.app); table = QTableWidget(2, 1); table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); table.setItem(0, 0, QTableWidgetItem("First")); table.setItem(1, 0, QTableWidgetItem("Second")); table.resize(260, 120); table.show(); self.app.processEvents()
            center = table.visualItemRect(table.item(0, 0)).center(); QTest.mouseMove(table.viewport(), center); QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=center); self.assertTrue(table.item(0, 0).isSelected()); table.setFocus(); QTest.keyClick(table, Qt.Key.Key_Down); self.assertTrue(table.item(1, 0).isSelected()); table.close()

    def test_details_and_evidence_reflow_and_are_resizable(self) -> None:
        record = issue_record(); record["results"][0]["evidence"] = "LongRegistryValue=" + ("abcdef0123456789" * 180); window = self.make_window([record]); window.resize(1280, 720); window.show(); window._view_history_record(record); window._set_page(1); self.app.processEvents(); window.findings_splitter.update_for_width(1000); window.findings_splitter.setSizes([700, 280]); window._toggle_finding_technical(); window.finding_detail_splitter.setSizes([170, 250]); self.app.processEvents()
        self.assertTrue(window.detail_title.wordWrap()); self.assertEqual(window.details.lineWrapMode(), QTextEdit.LineWrapMode.WidgetWidth); self.assertEqual(window.technical_finding_details.horizontalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff); before = window.finding_detail_splitter.sizes(); window.finding_detail_splitter.setSizes([280, 140]); self.app.processEvents(); self.assertNotEqual(before, window.finding_detail_splitter.sizes()); window.close()

    def test_splitter_layout_store_persists_and_rejects_invalid_sizes(self) -> None:
        path = Path(self.temp.name) / "layout.json"; splitter = QSplitter(Qt.Orientation.Horizontal); splitter.addWidget(QWidget()); splitter.addWidget(QWidget()); splitter.resize(600, 200); splitter.show(); splitter.setSizes([360, 240]); self.app.processEvents(); LayoutStateStore(path).save({"workspace": splitter}); self.assertEqual(len(LayoutStateStore(path).sizes("workspace", [1, 1])), 2)
        path.write_text('{"workspace": [-1, 0]}', encoding="utf-8"); self.assertEqual(LayoutStateStore(path).sizes("workspace", [3, 2]), [3, 2]); splitter.close()

    def test_open_data_folder_uses_existing_application_directory(self) -> None:
        window = self.make_window(); data = Path(self.temp.name) / "local-data"; data.mkdir()
        with patch("wincur.ui.default_history_path", return_value=data / "history.jsonl"), patch("wincur.ui.QDesktopServices.openUrl", return_value=True) as opener: window._open_data_folder()
        self.assertEqual(Path(opener.call_args.args[0].toLocalFile()), data)
        with patch("wincur.ui.default_history_path", return_value=Path(self.temp.name) / "missing" / "history.jsonl"), patch("wincur.ui.QMessageBox.information") as information, patch("wincur.ui.QDesktopServices.openUrl") as opener: window._open_data_folder()
        information.assert_called_once(); opener.assert_not_called(); window.close()

    def test_existing_snapshot_data_is_available_in_lazy_snapshot_dialog(self) -> None:
        record = saved_record(); window = self.make_window([record]); baseline = window.baseline_store.create(window.baseline_collection, "Existing", record); window.baseline_store.set_active(window.baseline_collection, baseline.baseline_id); window._refresh_baseline_ui()
        self.assertEqual(window.baseline_collection.active.name, "Existing"); self.assertIn("Existing", window.dashboard_baseline_label.text()); self.assertFalse(hasattr(window, "active_baseline_combo"))
        with patch("wincur.ui.QDialog.exec", return_value=0): window._open_saved_snapshots()
        self.assertEqual(window.active_baseline_combo.currentData(), baseline.baseline_id); window.close()

    def test_local_timestamp_and_evidence_preview_are_presentation_only(self) -> None:
        raw = "2026-10-29T12:30:00+00:00"; record = saved_record(raw); self.assertRegex(friendly_timestamp(raw), r"^[A-Z][a-z]{2} \d{2}, \d{2}:\d{2} [AP]M$"); self.assertEqual(record["timestamp_utc"], raw)
        full = "Registry evidence " + ("value " * 40); preview = evidence_preview(full, 50); self.assertLessEqual(len(preview), 50); self.assertTrue(preview.endswith("…")); self.assertEqual(full, "Registry evidence " + ("value " * 40))

    def test_chart_component_click_and_empty_drag_remain_safe_for_preserved_engine(self) -> None:
        for mode in (AppearanceMode.LIGHT, AppearanceMode.DARK, AppearanceMode.SYSTEM):
            with self.subTest(mode=mode.value):
                self.theme.set_mode(mode, persist=False); chart = TrendChart(self.theme); point = history_point(saved_record()); selected = []; chart.point_selected.connect(selected.append); chart.set_points([point]); chart.resize(640, 300); chart.show(); self.app.processEvents()
                image = QImage(chart.size(), QImage.Format.Format_ARGB32); painter = QPainter(image); chart.render(painter, QPoint(0, 0)); painter.end(); before = image.pixelColor(QPoint(310, 145))
                QTest.mousePress(chart, Qt.MouseButton.LeftButton, pos=QPoint(20, 250)); QTest.mouseMove(chart, QPoint(430, 250)); QTest.mouseRelease(chart, Qt.MouseButton.LeftButton, pos=QPoint(430, 250)); self.app.processEvents(); self.assertIsNone(chart.selected_point)
                image2 = QImage(chart.size(), QImage.Format.Format_ARGB32); painter = QPainter(image2); chart.render(painter, QPoint(0, 0)); painter.end(); self.assertEqual(image2.pixelColor(QPoint(310, 145)), before)
                QTest.mouseClick(chart, Qt.MouseButton.LeftButton, pos=chart.hit_points[0][0]); self.assertEqual(selected[-1], point); chart.close()


if __name__ == "__main__": unittest.main()
