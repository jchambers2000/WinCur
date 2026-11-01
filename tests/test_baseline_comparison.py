from __future__ import annotations

import unittest

from wincur.baseline_comparison import (EVIDENCE_ONLY, IMPROVEMENT, NEWLY_ASSESSABLE, NO_LONGER_ASSESSABLE,
    NOT_COMPARABLE, REGRESSION, UNCHANGED, compare_to_baseline)


def finding(check_id, status, evidence="same", severity="High"):
    return {"check_id": check_id, "title": check_id, "category": "OS Security", "status": status, "evidence": evidence, "severity": severity}


def record(results, privilege="Standard", profile="Standard", policy="2.0", score=50, coverage=100, dispositions=None):
    return {"timestamp_utc": "2026-01-01T00:00:00Z", "assessment_privilege": privilege, "assessment": {"profile": profile, "policy_version": policy, "score": score, "coverage": coverage, "dispositions": dispositions or {}}, "results": results}


class BaselineComparisonTests(unittest.TestCase):
    def classification(self, old_status, new_status, **kwargs):
        result = compare_to_baseline(record([finding("a", old_status)], privilege=kwargs.get("old_privilege", "Standard")), record([finding("a", new_status)], privilege=kwargs.get("new_privilege", "Standard")))
        return result.results[0]

    def test_regression_and_improvement(self) -> None:
        self.assertEqual(self.classification("Pass", "Fail").classification, REGRESSION)
        self.assertEqual(self.classification("Fail", "Pass").classification, IMPROVEMENT)

    def test_unknown_transitions_and_privilege_change_are_not_drift(self) -> None:
        newly = self.classification("Unknown", "Pass", old_privilege="Standard", new_privilege="Administrator")
        lost = self.classification("Pass", "Unknown", old_privilege="Administrator", new_privilege="Standard")
        self.assertEqual(newly.classification, NEWLY_ASSESSABLE); self.assertIn("privilege", newly.explanation)
        self.assertEqual(lost.classification, NO_LONGER_ASSESSABLE); self.assertIn("privilege", lost.explanation)
        comparison = compare_to_baseline(record([finding("a", "Pass")], privilege="Standard"), record([finding("a", "Pass")], privilege="Administrator"))
        self.assertTrue(comparison.privilege_difference); self.assertIn("visibility", comparison.compatibility_explanation)

    def test_evidence_normalization_and_evidence_only_change(self) -> None:
        equivalent = compare_to_baseline(record([finding("a", "Pass", "{'Enabled': True, 'Mode': 1}")]), record([finding("a", "Pass", '{"Mode":1,"Enabled":true}')]))
        changed = compare_to_baseline(record([finding("a", "Pass", "Enabled")]), record([finding("a", "Pass", "Enabled by policy")]))
        self.assertEqual(equivalent.results[0].classification, UNCHANGED); self.assertEqual(changed.results[0].classification, EVIDENCE_ONLY)

    def test_profile_policy_and_missing_check_are_not_comparable(self) -> None:
        mismatch = compare_to_baseline(record([finding("a", "Pass")]), record([finding("a", "Fail")], profile="Advanced"))
        missing = compare_to_baseline(record([finding("a", "Pass")]), record([]))
        self.assertFalse(mismatch.aggregate_comparable); self.assertIsNone(mismatch.score_change); self.assertEqual(mismatch.results[0].classification, NOT_COMPARABLE)
        self.assertEqual(missing.results[0].classification, NOT_COMPARABLE)
        legacy = compare_to_baseline(record([finding("a", "Pass")], profile="Legacy", policy="Unversioned"), record([finding("a", "Pass")]))
        self.assertFalse(legacy.aggregate_comparable); self.assertIsNone(legacy.score_change); self.assertIn("not comparable", legacy.compatibility_explanation)

    def test_informational_treatment_is_retained(self) -> None:
        result = compare_to_baseline(record([finding("bitlocker_system", "Pass")], dispositions={"bitlocker_system": "Informational"}), record([finding("bitlocker_system", "Fail")], dispositions={"bitlocker_system": "Informational"}))
        self.assertEqual(result.results[0].classification, REGRESSION); self.assertEqual(result.results[0].treatment, "Informational"); self.assertIn("excluded", result.results[0].explanation)


if __name__ == "__main__": unittest.main()
