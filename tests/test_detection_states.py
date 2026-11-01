from __future__ import annotations

import unittest

from wincur.checks import check_secure_boot_and_tpm, check_windows_update
from wincur.models import CheckStatus


CONFIG = {"checks": {
    "secure_boot": {"category": "OS", "weight": 1, "severity": "High"},
    "tpm": {"category": "OS", "weight": 1, "severity": "High"},
    "windows_update": {"category": "OS", "weight": 1, "severity": "High"},
}}


class SequenceRunner:
    def __init__(self, responses): self.responses = iter(responses)
    def json(self, script, timeout=30): return next(self.responses)


class DetectionStateTests(unittest.TestCase):
    def test_tpm_not_ready_is_not_reported_as_pass(self) -> None:
        runner = SequenceRunner([
            {"Value": True, "Error": None, "ErrorId": None},
            {"TpmPresent": True, "TpmReady": False, "TpmEnabled": True, "ManufacturerVersion": "mock"},
        ])
        findings = check_secure_boot_and_tpm(runner, CONFIG)
        self.assertEqual(findings[1].status, CheckStatus.FAIL)
        self.assertIn("not ready", findings[1].explanation)

    def test_optional_updates_alone_do_not_fail(self) -> None:
        optional = {"UpdateID": "mock", "UpdateType": 1, "BrowseOnly": True, "Categories": [{"Id": "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83"}], "KBArticleIDs": []}
        finding = check_windows_update(SequenceRunner([{"Updates": [optional, optional, optional], "Total": 3, "Truncated": False, "RebootRequired": False}]), CONFIG)[0]
        self.assertEqual(finding.status, CheckStatus.PASS)


if __name__ == "__main__": unittest.main()
