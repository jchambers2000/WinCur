from __future__ import annotations

import copy
import unittest

from wincur.checks import ProbeError, check_accounts, check_smartscreen
from wincur.models import CheckResult, CheckStatus
from wincur.scoring import load_scoring_config, score_results


BASE_CONFIG = {
    "checks": {
        "guest_account": {"category": "Account Security", "weight": 40, "severity": "High"},
        "local_admins": {"category": "Account Security", "weight": 60, "severity": "High"},
        "smartscreen": {"category": "Attack Surface", "weight": 25, "severity": "High"},
    },
    "assessment_policy": {"approved_local_administrators": []},
}


class Runner:
    def __init__(self, response):
        self.response = response
        self.scripts: list[str] = []

    def json(self, script, timeout=30):
        self.scripts.append(script)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def accounts(members, **overrides):
    data = {
        "Guest": None,
        "GuestStatus": "Success",
        "Administrators": members,
        "AdministratorStatus": "Success",
        "AdministratorProvider": "LocalAccounts",
        "AdministratorGroup": "Administrators",
        "AdministratorGroupSID": "S-1-5-32-544",
    }
    data.update(overrides)
    return data


def member(name, sid, source="Local", object_class="User"):
    return {"Name": name, "SID": sid, "PrincipalSource": source, "ObjectClass": object_class, "Direct": True}


def smartscreen(**overrides):
    data = {
        "PolicyKeyExists": True,
        "PolicyValueExists": False,
        "PolicyEnabled": None,
        "PolicyLevelValueExists": False,
        "PolicyLevel": None,
        "PolicyError": None,
        "PolicyLevelError": None,
        "MachineKeyExists": True,
        "MachineValueExists": False,
        "MachineSetting": None,
        "MachineError": None,
    }
    data.update(overrides)
    return data


class LocalAdministratorsAccuracyTests(unittest.TestCase):
    def finding(self, data, config=None):
        return {item.check_id: item for item in check_accounts(Runner(data), config or BASE_CONFIG)}["local_admins"]

    def test_successful_multiple_local_members_remain_unknown_without_authorization_policy(self):
        data = accounts([
            member(r"WINCURTESTVM\Administrator", "S-1-5-21-1-500"),
            member(r"WINCURTESTVM\user", "S-1-5-21-1-1001"),
        ])
        finding = self.finding(data)
        self.assertEqual(finding.status, CheckStatus.UNKNOWN)
        self.assertIn("Enumeration succeeded", finding.evidence)
        self.assertIn("direct members=2", finding.evidence)
        self.assertIn("built-in Administrator", finding.evidence)
        self.assertIn("will not guess", finding.explanation)

    def test_configured_allowlist_can_produce_objective_pass(self):
        config = copy.deepcopy(BASE_CONFIG)
        config["assessment_policy"]["approved_local_administrators"] = [r"vm\administrator", r"vm\user"]
        finding = self.finding(accounts([
            member(r"VM\Administrator", "S-1-5-21-1-500"),
            member(r"VM\user", "S-1-5-21-1-1001"),
        ]), config)
        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertIn("all members are approved", finding.evidence)

    def test_unapproved_member_fails_only_against_explicit_allowlist(self):
        config = copy.deepcopy(BASE_CONFIG)
        config["assessment_policy"]["approved_local_administrators"] = [r"vm\administrator"]
        finding = self.finding(accounts([
            member(r"VM\Administrator", "S-1-5-21-1-500"),
            member(r"VM\user", "S-1-5-21-1-1001"),
        ]), config)
        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertIn(r"unexpected: VM\user", finding.evidence)
        self.assertNotIn("malicious", finding.explanation.casefold())

    def test_localized_group_name_and_well_known_sid_are_preserved(self):
        finding = self.finding(accounts(
            [member(r"RECHNER\Administrator", "S-1-5-21-2-500")],
            AdministratorGroup="Administratoren",
        ))
        self.assertEqual(finding.status, CheckStatus.UNKNOWN)
        self.assertIn("Administratoren (S-1-5-32-544)", finding.evidence)

    def test_domain_and_microsoft_members_are_enumerated_without_assumed_failure(self):
        data = accounts([
            member(r"CONTOSO\Admin", "S-1-5-21-3-1100", "ActiveDirectory"),
            member(r"MicrosoftAccount\person@example.test", "S-1-12-1-1", "MicrosoftAccount"),
        ])
        finding = self.finding(data)
        self.assertEqual(finding.status, CheckStatus.UNKNOWN)
        self.assertIn("ActiveDirectory", finding.evidence)
        self.assertIn("MicrosoftAccount", finding.evidence)

    def test_unresolved_sid_is_ambiguous_not_confirmed_unauthorized(self):
        finding = self.finding(accounts([member("", "S-1-5-21-4-1200", "Unknown")]))
        self.assertEqual(finding.status, CheckStatus.UNKNOWN)
        self.assertIn("Unresolved SID", finding.evidence)
        self.assertIn("not treated as confirmed unauthorized", finding.explanation)

    def test_malformed_or_partial_member_output_is_unknown(self):
        for members in ([{"Name": None, "SID": None}], ["not a mapping"]):
            with self.subTest(members=members):
                finding = self.finding(accounts(members))
                self.assertEqual(finding.status, CheckStatus.UNKNOWN)
                self.assertIn("Ambiguous configuration", finding.evidence)

    def test_empty_successful_enumeration_is_distinct_from_failed_collection(self):
        empty = self.finding(accounts([]))
        failed = self.finding(accounts([], AdministratorStatus="CollectionFailure", AdministratorError="provider failed"))
        self.assertEqual(empty.status, CheckStatus.UNKNOWN)
        self.assertIn("Enumeration succeeded", empty.evidence)
        self.assertIn("Collection failure", failed.evidence)

    def test_access_denied_and_unsupported_provider_have_specific_reasons(self):
        denied = self.finding(accounts([], AdministratorStatus="CollectionFailure", AdministratorError="Access denied"))
        unsupported = self.finding(accounts([], AdministratorStatus="CollectionFailure", AdministratorError="Get-LocalGroup is not recognized"))
        self.assertIn("Insufficient permissions", denied.evidence)
        self.assertIn("Unsupported detection", unsupported.evidence)

    def test_collection_script_resolves_group_by_sid_and_has_cim_fallback(self):
        runner = Runner(accounts([]))
        check_accounts(runner, BASE_CONFIG)
        script = runner.scripts[0]
        self.assertIn("S-1-5-32-544", script)
        self.assertIn("Get-LocalGroupMember -Group $group.Name", script)
        self.assertIn("Get-CimAssociatedInstance", script)


class SmartScreenAccuracyTests(unittest.TestCase):
    def finding(self, data):
        return check_smartscreen(Runner(data), BASE_CONFIG)[0]

    def test_explicit_policy_enable_with_level_passes(self):
        finding = self.finding(smartscreen(PolicyValueExists=True, PolicyEnabled=1, PolicyLevelValueExists=True, PolicyLevel="Warn"))
        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertIn("machine policy", finding.explanation)

    def test_explicit_machine_explorer_enable_passes(self):
        finding = self.finding(smartscreen(MachineValueExists=True, MachineSetting="RequireAdmin"))
        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertIn("machine Explorer", finding.explanation)

    def test_policy_disable_overrides_conflicting_machine_enable(self):
        finding = self.finding(smartscreen(
            PolicyValueExists=True, PolicyEnabled=0,
            MachineValueExists=True, MachineSetting="Warn",
        ))
        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertIn("cannot override", finding.explanation)

    def test_explicit_machine_disable_fails(self):
        finding = self.finding(smartscreen(MachineValueExists=True, MachineSetting="Off"))
        self.assertEqual(finding.status, CheckStatus.FAIL)

    def test_missing_key_and_existing_key_with_missing_value_are_unknown(self):
        missing_key = self.finding(smartscreen(PolicyKeyExists=False, MachineKeyExists=False))
        missing_values = self.finding(smartscreen(PolicyKeyExists=True, MachineKeyExists=True))
        for finding in (missing_key, missing_values):
            self.assertEqual(finding.status, CheckStatus.UNKNOWN)
            self.assertIn("Not configured / insufficient evidence", finding.evidence)
            self.assertIn("cannot determine the effective protection state", finding.explanation)
        self.assertIn("key exists=False", missing_key.evidence)
        self.assertIn("key exists=True", missing_values.evidence)

    def test_invalid_policy_machine_and_incomplete_enabled_policy_are_unknown(self):
        cases = (
            smartscreen(PolicyValueExists=True, PolicyEnabled=7),
            smartscreen(MachineValueExists=True, MachineSetting="Unexpected"),
            smartscreen(PolicyValueExists=True, PolicyEnabled=1, PolicyLevel=None),
        )
        for data in cases:
            with self.subTest(data=data):
                finding = self.finding(data)
                self.assertEqual(finding.status, CheckStatus.UNKNOWN)
                self.assertIn("Ambiguous configuration", finding.evidence)

    def test_access_denied_and_unsupported_collection_are_classified(self):
        denied = self.finding(smartscreen(PolicyError="Access denied"))
        unsupported = self.finding(ProbeError("Registry provider is not available"))
        self.assertEqual(denied.status, CheckStatus.UNKNOWN)
        self.assertIn("Insufficient permissions", denied.evidence)
        self.assertIn("Unsupported detection", unsupported.evidence)

    def test_collection_scope_is_explorer_and_uses_hklm_not_hkcu(self):
        runner = Runner(smartscreen())
        finding = check_smartscreen(runner, BASE_CONFIG)[0]
        self.assertEqual(finding.check_id, "smartscreen")
        self.assertIn("Windows Explorer SmartScreen", finding.evidence)
        self.assertIn("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", runner.scripts[0])
        self.assertNotIn("HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", runner.scripts[0])


class CompatibilityTests(unittest.TestCase):
    def test_unknown_round_trip_and_scoring_semantics_remain_compatible(self):
        config = load_scoring_config()
        finding = check_smartscreen(Runner(smartscreen()), config)[0]
        restored = CheckResult.from_dict(finding.to_dict())
        assessment = score_results([restored], config)
        self.assertEqual(restored.check_id, "smartscreen")
        self.assertEqual(restored.status, CheckStatus.UNKNOWN)
        self.assertEqual(assessment.policy_version, "2.1")
        self.assertIsNone(assessment.score)
        self.assertEqual(assessment.coverage, 0.0)


if __name__ == "__main__":
    unittest.main()
