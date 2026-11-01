from __future__ import annotations

import unittest

from wincur.models import CheckResult, CheckStatus, Remediation, ScanRecord


class CheckResultTests(unittest.TestCase):
    def test_serialization_uses_public_status_value(self) -> None:
        remediation = Remediation("Do this", "Admin", "Impact", "Verify", "Rollback")
        finding = CheckResult("id", "Title", "Category", CheckStatus.FAIL, "e", "x", 10, "High", remediation)
        serialized = finding.to_dict()
        self.assertEqual(serialized["status"], "Fail")
        self.assertEqual(serialized["remediation"]["summary"], "Do this")

    def test_legacy_scan_record_loads_without_new_metadata(self) -> None:
        legacy = {"timestamp_utc": "2024-01-01T00:00:00Z", "application_version": "0.1", "windows_version": "Windows 11", "computer_name": "PC", "results": [], "assessment": {"score": 50, "coverage": 75, "categories": []}}
        record = ScanRecord.from_dict(legacy)
        self.assertEqual(record.assessment.profile, "Legacy")
        self.assertEqual(record.assessment.policy_version, "Unversioned")
        self.assertEqual(record.assessment_privilege, "Unknown")
        self.assertEqual(record.assessment_source, "Historical assessment")


if __name__ == "__main__":
    unittest.main()
