from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from wincur import APP_VERSION
from wincur.models import AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.reporting import assessment_report_filename, export_html, unique_report_path
from wincur.scoring import load_scoring_config
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


def report_record(timestamp: str = "2026-10-30T18:00:00+00:00", computer: str = "TEST-PC", score: float = 80.0) -> ScanRecord:
    finding = CheckResult("uac", "User Account Control", "OS Security", CheckStatus.PASS, f"evidence for {computer}", "Enabled", 10, "High")
    assessment = AssessmentScore(score, 90.0, profile="Standard", policy_version="2.1", dispositions={"uac": "Scored"})
    return ScanRecord.create(APP_VERSION, "Windows 11", computer, [finding], assessment, "Standard", timestamp_utc=timestamp)


class ReportFilenameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_unique_name_advances_across_multiple_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("WinCur-Report.html", "WinCur-Report (1).html", "WinCur-Report (2).html"): (root / name).write_text("existing", encoding="utf-8")
            self.assertEqual(unique_report_path(root, "WinCur-Report.html").name, "WinCur-Report (3).html")

    def test_existing_numeric_suffix_advances_without_nesting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "WinCur-Report (2).html").write_text("existing", encoding="utf-8")
            self.assertEqual(unique_report_path(root, "WinCur-Report (2).html").name, "WinCur-Report (3).html")

    def test_extension_is_added_once_and_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(unique_report_path(root, "WinCur-Report").name, "WinCur-Report.html")
            self.assertEqual(unique_report_path(root, "WinCur-Report.HTML").name, "WinCur-Report.HTML")

    def test_same_assessment_date_uses_next_available_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); base = assessment_report_filename("DESKTOP-D9H0LHV", "2026-10-30T23:59:59+00:00")
            (root / base).write_text("first", encoding="utf-8"); (root / "WinCur-DESKTOP-D9H0LHV-2026-10-30 (1).html").write_text("second", encoding="utf-8")
            self.assertEqual(unique_report_path(root, base).name, "WinCur-DESKTOP-D9H0LHV-2026-10-30 (2).html")

    def test_filename_uses_stored_assessment_utc_date_not_local_or_export_date(self) -> None:
        # At 00:30 UTC on November 1 it is still October 31 in America/Chicago.
        self.assertEqual(assessment_report_filename("TEST", "2026-11-01T00:30:00+00:00"), "WinCur-TEST-2026-11-01.html")
        # Exporting an old historical assessment retains its assessment date.
        self.assertEqual(assessment_report_filename("TEST", "2020-02-03T04:05:06Z"), "WinCur-TEST-2020-02-03.html")

    def test_html_content_matches_selected_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "selected.html"; selected = report_record("2026-10-31T01:02:03Z", "SELECTED-PC", 73.5)
            export_html(selected, load_scoring_config(), destination, exclusive=True); document = destination.read_text(encoding="utf-8")
            self.assertTrue(document.startswith("<!doctype html>")); self.assertIn('<meta charset="utf-8">', document); self.assertIn("SELECTED-PC", document); self.assertIn("2026-10-31T01:02:03Z", document); self.assertIn("73.5%", document); self.assertIn("evidence for SELECTED-PC", document)

    def test_exclusive_export_prevents_race_overwrite_and_invalid_destination_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); record = report_record(); destination = root / "report.html"; destination.write_text("sentinel", encoding="utf-8")
            with self.assertRaises(FileExistsError): export_html(record, load_scoring_config(), destination, exclusive=True)
            self.assertEqual(destination.read_text(encoding="utf-8"), "sentinel")
            with self.assertRaises(OSError): export_html(record, load_scoring_config(), root / "missing" / "report.html", exclusive=True)
            with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError): export_html(record, load_scoring_config(), root / "denied.html", exclusive=True)

    def test_explicit_existing_selection_overwrites_only_after_dialog_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); destination = root / "existing.html"; destination.write_text("sentinel", encoding="utf-8"); record = report_record(computer="CONFIRMED-PC")
            manager = ThemeManager(root / "appearance.json")
            with patch("wincur.ui.load_history", return_value=[]), patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=False):
                window = WinCurWindow(manager, history_path=root / "history.jsonl", baseline_path=root / "baselines.json")
            window.current_record = record
            with patch("wincur.ui.QStandardPaths.writableLocation", return_value=str(root)), patch("wincur.ui.QFileDialog.getSaveFileName", return_value=(str(destination), "HTML reports (*.html)")), patch.object(QMessageBox, "information"):
                window.export_report()
            document = destination.read_text(encoding="utf-8"); self.assertNotEqual(document, "sentinel"); self.assertIn("CONFIRMED-PC", document); window.close()

    def test_ui_suggestion_and_permission_error_handling_follow_existing_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manager = ThemeManager(root / "appearance.json")
            with patch("wincur.ui.load_history", return_value=[]), patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=False):
                window = WinCurWindow(manager, history_path=root / "history.jsonl", baseline_path=root / "baselines.json")
            window.computer_name = "BOUNDARY-PC"; window.current_record = report_record("2026-11-01T00:30:00+00:00")
            with patch("wincur.ui.QStandardPaths.writableLocation", return_value=str(root)), patch("wincur.ui.QFileDialog.getSaveFileName", return_value=("", "")) as chooser:
                window.export_report()
            self.assertEqual(Path(chooser.call_args.args[2]).name, "WinCur-BOUNDARY-PC-2026-11-01.html")
            destination = root / "denied.html"
            with patch("wincur.ui.QStandardPaths.writableLocation", return_value=str(root)), patch("wincur.ui.QFileDialog.getSaveFileName", return_value=(str(destination), "HTML reports (*.html)")), patch("wincur.ui.export_html", side_effect=PermissionError("denied")), patch.object(QMessageBox, "warning") as warning:
                window.export_report()
            self.assertIn("denied", warning.call_args.args[2]); window.close()


if __name__ == "__main__": unittest.main()
