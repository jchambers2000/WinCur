from __future__ import annotations

import unittest

from wincur.checks import ProbeError, UPDATE_CLASSIFICATIONS, check_windows_update, classify_windows_update_payload
from wincur.models import CheckStatus


CONFIG = {"checks": {"windows_update": {"category": "OS Security", "weight": 20, "severity": "High"}}}


def update(classification: str | None, *, browse=False, kb="5000000", update_type=1, extra_classification: str | None = None) -> dict:
    categories = []
    if classification: categories.append({"Id": UPDATE_CLASSIFICATIONS[classification], "Name": "Localized classification", "Type": "UpdateClassification"})
    if extra_classification: categories.append({"Id": UPDATE_CLASSIFICATIONS[extra_classification], "Name": "Other classification", "Type": "UpdateClassification"})
    return {"UpdateID": "12345678-1111-2222-3333-444444444444", "UpdateType": update_type, "BrowseOnly": browse, "AutoSelectOnWebSites": True, "UpdateRebootRequired": False, "KBArticleIDs": [kb], "Categories": categories}


def payload(*updates: dict, reboot=False, **extra) -> dict:
    return {"Updates": list(updates), "Total": len(updates), "Truncated": False, "RebootRequired": reboot, **extra}


class Runner:
    def __init__(self, response=None, error=None): self.response = response; self.error = error; self.script = ""
    def json(self, script, timeout=30):
        self.script = script
        if self.error: raise self.error
        return self.response


class WindowsUpdateClassificationTests(unittest.TestCase):
    def finding(self, data): return check_windows_update(Runner(data), CONFIG)[0]

    def test_defender_definition_update_only_passes_os_update_check(self) -> None:
        finding = self.finding(payload(update("definition", kb="2267602")))
        self.assertEqual(finding.status, CheckStatus.PASS); self.assertIn("Defender definitions=1", finding.evidence); self.assertIn("KB2267602", finding.evidence); self.assertIn("separately", finding.explanation)

    def test_required_security_and_quality_updates_fail(self) -> None:
        security = self.finding(payload(update("security", kb="5010001"))); quality = self.finding(payload(update("updates", kb="5010002")))
        self.assertEqual(security.status, CheckStatus.FAIL); self.assertIn("required security=1", security.evidence)
        self.assertEqual(quality.status, CheckStatus.FAIL); self.assertIn("required quality=1", quality.evidence)

    def test_msrc_severity_is_a_security_signal_when_classification_is_absent(self) -> None:
        item = update(None, kb="5010005"); item["MsrcSeverity"] = "Important"
        finding = self.finding(payload(item)); self.assertEqual(finding.status, CheckStatus.FAIL); self.assertIn("required security=1", finding.evidence)

    def test_optional_preview_update_only_passes(self) -> None:
        finding = self.finding(payload(update("updates", browse=True, kb="5010003")))
        self.assertEqual(finding.status, CheckStatus.PASS); self.assertIn("optional/preview=1", finding.evidence)

    def test_driver_and_feature_offers_are_reported_without_becoming_quality_failures(self) -> None:
        driver = update("driver", update_type=2, kb="driver"); feature = update("feature", kb="feature")
        finding = self.finding(payload(driver, feature)); self.assertEqual(finding.status, CheckStatus.PASS); self.assertIn("drivers=1", finding.evidence); self.assertIn("feature/other=1", finding.evidence)

    def test_mixed_required_and_definition_updates_fail_for_confirmed_required_item(self) -> None:
        finding = self.finding(payload(update("definition", kb="2267602"), update("security", kb="5010004")))
        self.assertEqual(finding.status, CheckStatus.FAIL); self.assertIn("required security=1", finding.evidence); self.assertIn("Defender definitions=1", finding.evidence)

    def test_pending_restart_fails_even_with_empty_update_set(self) -> None:
        finding = self.finding(payload(reboot=True)); self.assertEqual(finding.status, CheckStatus.FAIL); self.assertIn("restart required=True", finding.evidence)

    def test_empty_applicable_update_set_passes(self) -> None:
        finding = self.finding(payload()); self.assertEqual(finding.status, CheckStatus.PASS); self.assertIn("total=0", finding.evidence)

    def test_missing_ambiguous_and_contradictory_metadata_is_unknown(self) -> None:
        missing = self.finding(payload(update(None))); contradictory = self.finding(payload(update("definition", extra_classification="security")))
        self.assertEqual(missing.status, CheckStatus.UNKNOWN); self.assertIn("unclassified=1", missing.evidence)
        self.assertEqual(contradictory.status, CheckStatus.UNKNOWN); self.assertIn("contradictory", contradictory.explanation)

    def test_truncated_result_is_unknown_when_no_confirmed_failure_exists(self) -> None:
        data = payload(update("definition")); data.update({"Total": 3, "Truncated": True})
        finding = self.finding(data); self.assertEqual(finding.status, CheckStatus.UNKNOWN); self.assertIn("unclassified=2", finding.evidence)

    def test_agent_error_access_denied_and_unavailable_api_are_unknown(self) -> None:
        for message in ("Access is denied", "ActiveX component cannot create object Microsoft.Update.Session"):
            finding = check_windows_update(Runner(error=ProbeError(message)), CONFIG)[0]; self.assertEqual(finding.status, CheckStatus.UNKNOWN); self.assertIn(message, finding.explanation)

    def test_category_ids_work_with_localized_or_managed_metadata_and_probe_is_read_only(self) -> None:
        item = update("security"); item["Categories"][0]["Name"] = "Actualización de seguridad"; runner = Runner(payload(item)); finding = check_windows_update(runner, CONFIG)[0]
        self.assertEqual(finding.status, CheckStatus.FAIL); self.assertIn('IsInstalled=0 and IsHidden=0', runner.script); self.assertIn("Microsoft.Update.SystemInfo", runner.script); self.assertNotIn(".Download", runner.script); self.assertNotIn(".Install", runner.script)

    def test_non_mapping_agent_payload_is_rejected(self) -> None:
        with self.assertRaises(ValueError): classify_windows_update_payload(None)


if __name__ == "__main__": unittest.main()
