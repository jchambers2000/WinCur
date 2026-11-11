from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from wincur.baselines import BaselineCollection, BaselineStore, SecurityBaseline
from wincur.models import AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.reporting import export_html
from wincur.scoring import load_scoring_config
from wincur.ui import HistoryWorker


def assessment() -> dict:
    return {"timestamp_utc": "2026-11-01T00:00:00Z", "assessment": {"profile": "Standard"}, "results": []}


def report_record() -> ScanRecord:
    finding = CheckResult("uac", "UAC", "OS Security", CheckStatus.PASS, "Enabled", "Enabled", 10, "High")
    score = AssessmentScore(100.0, 100.0, profile="Standard", policy_version="2.1", dispositions={"uac": "Scored"})
    return ScanRecord.create("1.0.0", "Windows 11", "TEST-PC", [finding], score, "Standard")


class BaselineTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = BaselineStore(Path(self.temp.name) / "baselines.json")
        self.existing = SecurityBaseline.create("Existing", assessment())
        self.collection = BaselineCollection([self.existing], self.existing.baseline_id)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_unchanged(self) -> None:
        self.assertEqual(self.collection.baselines, [self.existing])
        self.assertEqual(self.collection.active_baseline_id, self.existing.baseline_id)

    def test_create_rename_delete_and_activation_roll_back_live_state_when_save_fails(self) -> None:
        with patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError): self.store.create(self.collection, "New", assessment())
            self._assert_unchanged()
            with self.assertRaises(OSError): self.store.rename(self.collection, self.existing.baseline_id, "Changed")
            self._assert_unchanged()
            with self.assertRaises(OSError): self.store.delete(self.collection, self.existing.baseline_id)
            self._assert_unchanged()
            with self.assertRaises(OSError): self.store.set_active(self.collection, None)
            self._assert_unchanged()


class ReportDurabilityTests(unittest.TestCase):
    def test_failed_confirmed_overwrite_preserves_previous_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.html"
            destination.write_text("known-good report", encoding="utf-8")
            with patch("wincur.storage.os.replace", side_effect=OSError("replace denied")):
                with self.assertRaises(OSError):
                    export_html(report_record(), load_scoring_config(), destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "known-good report")
            self.assertEqual(list(destination.parent.glob(".report.html.*.tmp")), [])

    def test_failed_exclusive_export_removes_only_its_partial_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "new-report.html"
            with patch("wincur.storage.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    export_html(report_record(), load_scoring_config(), destination, exclusive=True)
            self.assertFalse(destination.exists())


class AssessmentOnlyEntryPointTests(unittest.TestCase):
    def test_removed_mutation_modes_cannot_reach_gui_or_helpers(self) -> None:
        root = Path(__file__).resolve().parent.parent
        for mode in ("--helper-action", "--helper-rollback", "--helper-preview", "--helper-scan"):
            completed = subprocess.run(
                [sys.executable, str(root / "main.py"), mode], cwd=root,
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("unrecognized arguments", completed.stderr)


class HistoryWorkerBoundaryTests(unittest.TestCase):
    def test_unexpected_save_failure_always_emits_completion_error(self) -> None:
        errors: list[str] = []
        worker = HistoryWorker(report_record())
        worker.finished.connect(errors.append)
        with patch("wincur.ui.save_history", side_effect=RuntimeError("serialization failed")):
            worker.run()
        self.assertEqual(errors, ["serialization failed"])


if __name__ == "__main__":
    unittest.main()
