from __future__ import annotations

import unittest

from wincur.models import CheckResult, CheckStatus
from wincur.scoring import load_scoring_config, load_selected_profile, save_selected_profile, score_results


CONFIG = {"categories": {"A": {"weight": 60}, "B": {"weight": 40}}, "checks": {}}


def finding(check_id: str, category: str, status: CheckStatus, weight: float, severity: str = "High") -> CheckResult:
    return CheckResult(check_id, check_id, category, status, "evidence", "explanation", weight, severity)


class ScoringTests(unittest.TestCase):
    def test_all_scored_checks_pass(self) -> None:
        score = score_results([finding("a", "A", CheckStatus.PASS, 100), finding("b", "B", CheckStatus.PASS, 100)], CONFIG)
        self.assertEqual((score.score, score.coverage), (100.0, 100.0))

    def test_pass_and_fail_use_check_and_category_weights(self) -> None:
        score = score_results([finding("a", "A", CheckStatus.PASS, 100), finding("b", "B", CheckStatus.FAIL, 100)], CONFIG)
        self.assertEqual((score.score, score.coverage), (60.0, 100.0))

    def test_pass_and_unknown_keep_known_score_but_reduce_coverage(self) -> None:
        score = score_results([finding("a1", "A", CheckStatus.PASS, 40), finding("a2", "A", CheckStatus.UNKNOWN, 60)], CONFIG)
        category = score.categories[0]
        self.assertEqual((category.score, category.coverage), (100.0, 40.0))
        self.assertEqual(score.score, 100.0)

    def test_pass_fail_and_unknown_are_calculated_independently(self) -> None:
        score = score_results([finding("a1", "A", CheckStatus.PASS, 25), finding("a2", "A", CheckStatus.FAIL, 25), finding("a3", "A", CheckStatus.UNKNOWN, 50)], CONFIG)
        self.assertEqual((score.categories[0].score, score.categories[0].coverage), (50.0, 50.0))

    def test_all_applicable_scored_checks_unknown_are_not_scored(self) -> None:
        score = score_results([finding("a", "A", CheckStatus.UNKNOWN, 100), finding("b", "B", CheckStatus.UNKNOWN, 100)], CONFIG)
        self.assertIsNone(score.score); self.assertEqual(score.coverage, 0.0)

    def test_unknown_severity_does_not_change_weighted_results(self) -> None:
        high = score_results([finding("pass", "A", CheckStatus.PASS, 50), finding("unknown", "A", CheckStatus.UNKNOWN, 50, "Critical")], CONFIG)
        low = score_results([finding("pass", "A", CheckStatus.PASS, 50), finding("unknown", "A", CheckStatus.UNKNOWN, 50, "Low")], CONFIG)
        self.assertEqual((high.score, high.coverage), (low.score, low.coverage))

    def test_informational_and_not_applicable_are_excluded(self) -> None:
        config = {"categories": {"A": {"weight": 100}}, "checks": {}, "profiles": {"Standard": {"checks": {"info": {"disposition": "Informational"}}}}}
        score = score_results([finding("pass", "A", CheckStatus.PASS, 20), finding("info", "A", CheckStatus.FAIL, 70), finding("na", "A", CheckStatus.NOT_APPLICABLE, 10)], config, "Standard")
        self.assertEqual((score.score, score.coverage), (100.0, 100.0)); self.assertEqual(score.categories[0].informational, 1); self.assertEqual(score.categories[0].not_applicable, 1)

    def test_category_counts_and_vm_account_security_fixture(self) -> None:
        config = {"categories": {"Account Security": {"weight": 100}}, "checks": {}}
        score = score_results([finding("guest_account", "Account Security", CheckStatus.PASS, 40), finding("local_admins", "Account Security", CheckStatus.UNKNOWN, 60)], config)
        category = score.categories[0]
        self.assertEqual((category.score, category.coverage, category.passed, category.failed, category.unknown), (100.0, 40.0, 1, 0, 1))

    def test_overall_aggregation_renormalizes_known_category_weights(self) -> None:
        results = [finding("a1", "A", CheckStatus.PASS, 75), finding("a2", "A", CheckStatus.UNKNOWN, 25), finding("b1", "B", CheckStatus.FAIL, 100)]
        score = score_results(results, CONFIG)
        self.assertEqual((score.score, score.coverage), (60.0, 85.0))

    def test_weighted_score_and_coverage_are_separate(self) -> None:
        results = [finding("a1", "A", CheckStatus.PASS, 75), finding("a2", "A", CheckStatus.UNKNOWN, 25), finding("b1", "B", CheckStatus.FAIL, 100)]
        score = score_results(results, CONFIG)
        self.assertEqual(score.score, 60.0)
        self.assertEqual(score.coverage, 85.0)

    def test_unknown_never_counts_as_pass(self) -> None:
        score = score_results([finding("a", "A", CheckStatus.UNKNOWN, 100)], CONFIG)
        self.assertIsNone(score.score)
        self.assertEqual(score.coverage, 0.0)

    def test_not_applicable_is_excluded(self) -> None:
        results = [finding("a", "A", CheckStatus.NOT_APPLICABLE, 100), finding("b", "B", CheckStatus.PASS, 100)]
        score = score_results(results, CONFIG)
        self.assertEqual(score.score, 100.0)
        self.assertEqual(score.coverage, 100.0)

    def test_mixed_weights_within_category(self) -> None:
        results = [finding("a1", "A", CheckStatus.PASS, 25), finding("a2", "A", CheckStatus.FAIL, 75)]
        score = score_results(results, CONFIG)
        self.assertEqual(score.score, 25.0)

    def test_standard_profile_excludes_bitlocker_as_informational(self) -> None:
        config = load_scoring_config()
        results = [
            finding("bitlocker_system", "OS Security", CheckStatus.FAIL, 30),
            finding("uac", "OS Security", CheckStatus.PASS, 15),
        ]
        score = score_results(results, config, "Standard")
        self.assertEqual(score.score, 100.0)
        self.assertEqual(score.dispositions["bitlocker_system"], "Informational")
        self.assertEqual(score.categories[2].informational, 1)
        self.assertEqual(score.categories[2].failed, 0)

    def test_advanced_and_enterprise_profiles_score_bitlocker(self) -> None:
        config = load_scoring_config(); results = [finding("bitlocker_system", "OS Security", CheckStatus.FAIL, 30), finding("uac", "OS Security", CheckStatus.PASS, 15)]
        advanced = score_results(results, config, "Advanced"); enterprise = score_results(results, config, "Enterprise")
        self.assertEqual(advanced.score, 33.3); self.assertEqual(enterprise.score, 33.3)
        self.assertEqual(advanced.policy_version, "2.1")

    def test_profile_preference_round_trip(self) -> None:
        import tempfile
        from pathlib import Path
        config = load_scoring_config()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"; save_selected_profile("Advanced", config, path)
            self.assertEqual(load_selected_profile(config, path), "Advanced")


if __name__ == "__main__":
    unittest.main()

