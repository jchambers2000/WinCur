from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from wincur import checks
from wincur.action_history import load_action_history
from wincur.checks import PowerShellRunner, check_autorun, check_powershell_logging
from wincur.logging_setup import configure_logging
from wincur.models import AssessmentScore, CheckStatus, ScanRecord
from wincur.reporting import load_history, save_history
from wincur.scoring import load_scoring_config
from wincur.storage import atomic_write_json
from wincur.theme import ThemeManager
from wincur.ui import WinCurWindow


class Runner:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response; self.error = error

    def json(self, script: str, timeout: int = 30):
        if self.error: raise self.error
        return self.response


class ReliabilityBoundaryTests(unittest.TestCase):
    def test_unexpected_individual_check_failure_becomes_unknown(self) -> None:
        config = load_scoring_config()
        finding = checks._run_check_group(checks.check_uac, Runner(error=RuntimeError("provider exploded")), config)[0]
        self.assertEqual(finding.status, CheckStatus.UNKNOWN)
        self.assertIn("provider exploded", finding.explanation)

    def test_registry_access_failure_is_not_treated_as_absent_policy(self) -> None:
        config = load_scoring_config()
        autorun = check_autorun(Runner({"MachineDrive": None, "MachineNoAutorun": None, "UserDrive": None, "UserNoAutorun": None, "Errors": ["Access denied"]}), config)[0]
        logging_result = check_powershell_logging(Runner({"ScriptBlock": None, "Module": None, "ModuleWildcard": None, "Errors": "Access denied"}), config)[0]
        self.assertEqual(autorun.status, CheckStatus.UNKNOWN)
        self.assertEqual(logging_result.status, CheckStatus.UNKNOWN)
        self.assertIn("Access denied", autorun.explanation)

    def test_absent_registry_policy_remains_a_supported_fail_result(self) -> None:
        config = load_scoring_config()
        autorun = check_autorun(Runner({"MachineDrive": None, "MachineNoAutorun": None, "UserDrive": None, "UserNoAutorun": None, "Errors": []}), config)[0]
        self.assertEqual(autorun.status, CheckStatus.FAIL)

    def test_powershell_timeout_has_bounded_sanitized_diagnostic(self) -> None:
        with patch("wincur.checks.subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 7)):
            with self.assertRaisesRegex(checks.ProbeError, "timed out after 7 seconds"):
                PowerShellRunner().json("Get-Date", timeout=7)

    def test_jsonl_loaders_ignore_corrupt_and_non_object_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.jsonl"
            valid = ScanRecord.create("0.9.7", "Windows 11", "TEST", [], AssessmentScore(100, 100, policy_version="2.1"))
            history.write_text("null\n[]\n{broken}\n" + json.dumps(valid.to_dict()) + "\n", encoding="utf-8")
            self.assertEqual(load_history(history, 10), [valid.to_dict()])
            self.assertEqual(load_action_history(history, 10), [valid.to_dict()])

    def test_history_append_recovers_after_partial_trailing_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.jsonl"; history.write_text('{"partial":', encoding="utf-8")
            record = ScanRecord.create("0.9.7", "Windows 11", "TEST", [], AssessmentScore(80, 90, policy_version="2.1"))
            save_history(record, history)
            self.assertEqual(load_history(history, 10), [record.to_dict()])
            self.assertTrue(history.read_text(encoding="utf-8").startswith('{"partial":\n'))

    def test_interrupted_atomic_setting_write_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "setting.json"; path.write_text('{"appearance":"Light"}', encoding="utf-8")
            with patch("wincur.storage.os.replace", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError): atomic_write_json(path, {"appearance": "Dark"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"appearance": "Light"})
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_logging_failure_falls_back_without_preventing_startup(self) -> None:
        logger = logging.getLogger("wincur"); original = list(logger.handlers); logger.handlers = []
        try:
            with patch("wincur.logging_setup.RotatingFileHandler", side_effect=OSError("denied")):
                self.assertIsNone(configure_logging())
            self.assertTrue(logger.handlers)
        finally:
            for handler in logger.handlers: handler.close()
            logger.handlers = original

    def test_production_entry_and_ui_do_not_import_elevation_module(self) -> None:
        root = Path(__file__).resolve().parent.parent
        for path in (root / "main.py", root / "wincur" / "ui.py"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("wincur.privileges", source)
            self.assertNotIn("launch_elevated_helper", source)


class ReliabilityUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.theme = ThemeManager(self.root / "appearance.json")
        with patch("wincur.ui.load_action_history", return_value=[]), patch("wincur.ui.is_administrator", return_value=False):
            self.window = WinCurWindow(self.theme, baseline_path=self.root / "baselines.json", history_path=self.root / "history.jsonl", layout_path=self.root / "layout.json")

    def tearDown(self) -> None:
        self.window.close(); self.temp.cleanup()

    def test_failed_history_save_is_visible_and_does_not_claim_persistence(self) -> None:
        with patch.object(QMessageBox, "warning") as warning:
            self.window._history_saved("Access denied")
        self.assertIn("could not be saved", self.window.scan_message.text())
        self.assertIn("Access denied", warning.call_args.args[2])

    def test_failed_rescan_retains_previous_export_availability(self) -> None:
        self.window.current_record = ScanRecord.create("0.9.7", "Windows 11", "TEST", [], AssessmentScore(75, 80, policy_version="2.1"))
        self.window.export_button.setEnabled(False)
        with patch.object(QMessageBox, "warning"):
            self.window._scan_failed("provider failed")
        self.assertTrue(self.window.export_button.isEnabled())
        self.assertIn("no new assessment", self.window.scan_message.text())

    def test_window_has_no_helper_polling_or_elevation_state(self) -> None:
        for removed in ("_poll_helper", "pending_path", "pending_kind", "action_busy", "elevated_button"):
            self.assertFalse(hasattr(self.window, removed))


if __name__ == "__main__": unittest.main()
