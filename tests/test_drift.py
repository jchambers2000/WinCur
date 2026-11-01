from __future__ import annotations

import unittest

from wincur.drift import compare_assessments, normalize_evidence


def finding(check_id, status, evidence, severity="High"):
    return {"check_id": check_id, "title": check_id, "category": "OS Security", "status": status, "evidence": evidence, "explanation": "x", "weight": 10, "severity": severity}


def assessment(results, timestamp, profile="Standard", policy="2.0", score=50, coverage=100):
    return {"timestamp_utc": timestamp, "assessment": {"profile": profile, "policy_version": policy, "score": score, "coverage": coverage}, "results": results}


class DriftTests(unittest.TestCase):
    def test_pass_fail_and_unknown_transitions_are_distinguished(self) -> None:
        older = assessment([finding("a", "Pass", "on"), finding("b", "Fail", "off"), finding("c", "Pass", "visible")], "2026-01-01T00:00:00Z")
        newer = assessment([finding("a", "Fail", "off"), finding("b", "Pass", "on"), finding("c", "Unknown", "access denied")], "2026-02-01T00:00:00Z", score=70, coverage=80)
        result = compare_assessments(older, newer); by_id = {change.check_id: change for change in result.changes}
        self.assertEqual(by_id["a"].classification, "Pass to Fail"); self.assertEqual(by_id["a"].confidence, "Confirmed status drift")
        self.assertEqual(by_id["b"].classification, "Fail to Pass")
        self.assertEqual(by_id["c"].confidence, "Insufficient evidence")
        self.assertEqual(result.score_change, 20); self.assertEqual(result.coverage_change, -20)

    def test_evidence_normalization_ignores_mapping_format_and_order(self) -> None:
        left, reliable_left = normalize_evidence("{'Enabled': True, 'Mode': 1}")
        right, reliable_right = normalize_evidence('{"Mode":1,"Enabled":true}')
        self.assertEqual(left, right); self.assertTrue(reliable_left and reliable_right)
        result = compare_assessments(assessment([finding("a", "Pass", "{'Enabled': True, 'Mode': 1}")], "2026-01-01T00:00:00Z"), assessment([finding("a", "Pass", '{"Mode":1,"Enabled":true}')], "2026-02-01T00:00:00Z"))
        self.assertEqual(result.changes, [])

    def test_text_only_evidence_change_is_not_confirmed_drift(self) -> None:
        result = compare_assessments(assessment([finding("a", "Pass", "Enabled True")], "2026-01-01T00:00:00Z"), assessment([finding("a", "Pass", "Enabled: True")], "2026-02-01T00:00:00Z"))
        self.assertEqual(result.changes[0].classification, "Evidence text changed"); self.assertEqual(result.changes[0].confidence, "Insufficient evidence")

    def test_policy_mismatch_suppresses_score_delta(self) -> None:
        result = compare_assessments(assessment([], "2026-01-01T00:00:00Z"), assessment([], "2026-02-01T00:00:00Z", policy="3.0"))
        self.assertFalse(result.directly_comparable); self.assertIsNone(result.score_change); self.assertIn("not directly comparable", result.comparison_note)


if __name__ == "__main__": unittest.main()
