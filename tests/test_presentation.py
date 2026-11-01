from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wincur.models import AssessmentScore, CheckResult, CheckStatus, ScanRecord
from wincur.presentation import sanitize_display_text
from wincur.reporting import export_html
from wincur.scoring import load_scoring_config


class PresentationSanitizationTests(unittest.TestCase):
    def test_control_characters_and_trailing_nuls_are_removed_for_display(self) -> None:
        raw = "ManufacturerVersion=7.2; vendor\x07value\nsecond line\x00\x00"; original = raw
        self.assertEqual(sanitize_display_text(raw), "ManufacturerVersion=7.2; vendorvalue\nsecond line")
        self.assertEqual(raw, original)

    def test_html_export_sanitizes_without_mutating_finding_evidence(self) -> None:
        evidence = "TPM ManufacturerVersion=5.63\x00\x00"
        finding = CheckResult("tpm", "TPM", "OS Security", CheckStatus.PASS, evidence, "Ready\x01", 10, "Low")
        assessment = AssessmentScore(100.0, 100.0, profile="Standard", policy_version="2.0", dispositions={"tpm": "Scored"})
        record = ScanRecord.create("0.8.1", "Windows 11", "TEST", [finding], assessment, "Standard")
        with tempfile.TemporaryDirectory() as directory:
            report = export_html(record, load_scoring_config(), Path(directory) / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("\x00", report); self.assertNotIn("\x01", report); self.assertIn("ManufacturerVersion=5.63", report); self.assertEqual(finding.evidence, evidence)


if __name__ == "__main__": unittest.main()
