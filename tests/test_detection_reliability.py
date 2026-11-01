from __future__ import annotations

import unittest

from wincur.checks import check_accounts, check_autorun, check_defender, check_firewall, check_remote_desktop, check_secure_boot_and_tpm, check_smartscreen, check_uac
from wincur.models import CheckStatus


CHECK_IDS = ("defender_realtime", "defender_cloud", "defender_tamper", "defender_signatures", "firewall_domain", "firewall_private", "firewall_public", "secure_boot", "tpm", "uac", "guest_account", "local_admins", "remote_desktop", "smartscreen", "autorun")
CONFIG = {"checks": {check_id: {"category": "Test", "weight": 1, "severity": "High"} for check_id in CHECK_IDS}, "assessment_policy": {"approved_local_administrators": ["TEST\\Approved"]}}


class Runner:
    def __init__(self, *responses): self.responses = iter(responses)
    def json(self, script, timeout=30): return next(self.responses)


class DetectionReliabilityTests(unittest.TestCase):
    def test_active_defender_missing_individual_states_returns_unknown_not_fail(self) -> None:
        data = {"AMServiceEnabled": True, "AntivirusEnabled": True, "AntivirusSignatureLastUpdated": None}
        results = check_defender(Runner(data), CONFIG); by_id = {result.check_id: result for result in results}
        self.assertEqual(by_id["defender_realtime"].status, CheckStatus.UNKNOWN); self.assertEqual(by_id["defender_cloud"].status, CheckStatus.UNKNOWN); self.assertEqual(by_id["defender_tamper"].status, CheckStatus.UNKNOWN)

    def test_defender_missing_activation_metadata_does_not_claim_inactive(self) -> None:
        results = check_defender(Runner({"AMServiceEnabled": True}), CONFIG); self.assertTrue(all(result.status == CheckStatus.UNKNOWN for result in results))

    def test_firewall_profile_without_enabled_state_is_unknown(self) -> None:
        results = check_firewall(Runner([{"Name": "Domain"}, {"Name": "Private", "Enabled": True}, {"Name": "Public", "Enabled": False}]), CONFIG)
        self.assertEqual([result.status for result in results], [CheckStatus.UNKNOWN, CheckStatus.PASS, CheckStatus.FAIL])

    def test_secure_boot_and_tpm_incomplete_provider_data_is_unknown(self) -> None:
        results = check_secure_boot_and_tpm(Runner({"Value": None, "Error": None, "ErrorId": None}, {"TpmPresent": True}), CONFIG)
        self.assertEqual([result.status for result in results], [CheckStatus.UNKNOWN, CheckStatus.UNKNOWN])

    def test_uac_and_remote_desktop_missing_values_are_unknown_not_defaulted(self) -> None:
        self.assertEqual(check_uac(Runner({"EnableLUA": 1}), CONFIG)[0].status, CheckStatus.UNKNOWN)
        self.assertEqual(check_remote_desktop(Runner({"NLA": 1}), CONFIG)[0].status, CheckStatus.UNKNOWN)

    def test_missing_administrator_membership_never_passes_approved_baseline(self) -> None:
        results = check_accounts(Runner({"Guest": None}), CONFIG); by_id = {result.check_id: result for result in results}
        self.assertEqual(by_id["guest_account"].status, CheckStatus.NOT_APPLICABLE); self.assertEqual(by_id["local_admins"].status, CheckStatus.UNKNOWN)

    def test_machine_smartscreen_disable_policy_overrides_user_value(self) -> None:
        finding = check_smartscreen(Runner({"PolicyEnabled": 0, "PolicyLevel": "", "UserSetting": "Warn"}), CONFIG)[0]
        self.assertEqual(finding.status, CheckStatus.FAIL); self.assertIn("cannot override", finding.explanation)

    def test_autorun_requires_both_policy_values_at_one_scope(self) -> None:
        partial = check_autorun(Runner({"MachineDrive": 255, "MachineNoAutorun": None, "UserDrive": None, "UserNoAutorun": None}), CONFIG)[0]
        complete = check_autorun(Runner({"MachineDrive": 255, "MachineNoAutorun": 1, "UserDrive": None, "UserNoAutorun": None}), CONFIG)[0]
        self.assertEqual(partial.status, CheckStatus.FAIL); self.assertEqual(complete.status, CheckStatus.PASS); self.assertEqual(complete.title, "AutoRun policy")


if __name__ == "__main__": unittest.main()
