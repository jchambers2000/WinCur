from __future__ import annotations

import unittest

from wincur.checks import ProbeError, check_firewall
from wincur.models import CheckStatus


CONFIG = {
    "checks": {
        "firewall_domain": {"category": "Network Security", "weight": 25, "severity": "High"},
        "firewall_private": {"category": "Network Security", "weight": 25, "severity": "High"},
        "firewall_public": {"category": "Network Security", "weight": 25, "severity": "Critical"},
    }
}


class FakeRunner:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error

    def json(self, script: str, timeout: int = 30):
        if self.error:
            raise self.error
        return self.response


class CheckHandlingTests(unittest.TestCase):
    def test_firewall_profiles_are_independent(self) -> None:
        runner = FakeRunner([
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": False},
            {"Name": "Public", "Enabled": True},
        ])
        findings = check_firewall(runner, CONFIG)
        self.assertEqual([f.status for f in findings], [CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.PASS])

    def test_probe_failure_becomes_unknown_not_pass(self) -> None:
        findings = check_firewall(FakeRunner(error=ProbeError("access denied")), CONFIG)
        self.assertTrue(all(f.status == CheckStatus.UNKNOWN for f in findings))
        self.assertTrue(all("access denied" in f.explanation for f in findings))


if __name__ == "__main__":
    unittest.main()
