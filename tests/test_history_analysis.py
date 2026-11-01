from __future__ import annotations

import unittest
from datetime import date

from wincur.history_analysis import aggregate_trend_points, build_trend_presentation, comparison_explanation, filter_history, history_point


def record(timestamp="2026-01-01T12:00:00+00:00", profile="Standard", policy="2.0", score=80, coverage=90, privilege="Standard"):
    assessment = {"score": score, "coverage": coverage}
    if profile is not None: assessment["profile"] = profile
    if policy is not None: assessment["policy_version"] = policy
    return {"timestamp_utc": timestamp, "assessment_privilege": privilege, "assessment": assessment, "results": []}


class HistoryAnalysisTests(unittest.TestCase):
    def test_filters_by_profile_and_inclusive_date_range(self) -> None:
        records = [record("2026-01-01T00:00:00Z"), record("2026-02-01T00:00:00Z", "Advanced"), record("2026-03-01T00:00:00Z")]
        points = filter_history(records, "Standard", date(2026, 1, 15), date(2026, 3, 1))
        self.assertEqual([point.record["timestamp_utc"] for point in points], ["2026-03-01T00:00:00Z"])

    def test_missing_metadata_is_labeled_and_undated_record_is_safe(self) -> None:
        point = history_point({"timestamp_utc": "not-a-date", "assessment": {"score": None}, "results": []})
        self.assertIsNone(point.timestamp); self.assertEqual(point.profile, "Legacy"); self.assertEqual(point.policy_version, "Unversioned"); self.assertEqual(point.privilege, "Unknown")
        self.assertEqual(filter_history([point.record], start_date=date(2020, 1, 1)), [])
        other = history_point({"timestamp_utc": "2025-01-01T00:00:00Z", "assessment": {"score": 20, "coverage": 50}})
        self.assertIn("not directly comparable", comparison_explanation(point, other))

    def test_different_profile_or_policy_is_not_directly_comparable(self) -> None:
        text = comparison_explanation(history_point(record(profile="Standard")), history_point(record(profile="Advanced", policy="3.0")))
        self.assertIn("not directly comparable", text)

    def test_trend_series_separates_privilege_profile_and_policy(self) -> None:
        standard = history_point(record(privilege="Standard")); admin = history_point(record(privilege="Administrator"))
        advanced = history_point(record(profile="Advanced")); different_policy = history_point(record(policy="2.1"))
        self.assertNotEqual(standard.trend_series_key, admin.trend_series_key)
        self.assertNotEqual(standard.trend_series_key, advanced.trend_series_key)
        self.assertNotEqual(standard.trend_series_key, different_policy.trend_series_key)

    def test_daily_trend_aggregation_keeps_latest_comparable_assessment(self) -> None:
        points = [history_point(record("2026-01-01T08:00:00Z", score=70)), history_point(record("2026-01-01T20:00:00Z", score=85)), history_point(record("2026-01-02T09:00:00Z", score=90))]
        aggregated = aggregate_trend_points(points, "score")
        self.assertEqual([point.score for point in aggregated], [85.0, 90.0])

    def test_trend_aggregation_handles_duplicates_legacy_and_missing_metric(self) -> None:
        duplicate_old = history_point(record("2026-01-01T12:00:00Z", score=40)); duplicate_new = history_point(record("2026-01-01T12:00:00Z", score=60))
        legacy = history_point(record("2026-01-02T12:00:00Z", profile=None, policy=None, score=50)); missing = history_point(record("2026-01-03T12:00:00Z", score=None, coverage=75))
        score_points = aggregate_trend_points([duplicate_old, duplicate_new, legacy, missing], "score")
        self.assertEqual([point.score for point in score_points], [60.0, 50.0]); self.assertEqual(aggregate_trend_points([missing], "coverage")[0].coverage, 75.0)

    def test_adaptive_trend_modes_and_score_change(self) -> None:
        self.assertEqual(build_trend_presentation([]).mode, "empty")
        points = [history_point(record(f"2026-01-{day:02d}T12:00:00Z", score=70 + day)) for day in range(1, 8)]
        self.assertEqual(build_trend_presentation(points[:1]).mode, "single")
        two = build_trend_presentation(points[:2]); self.assertEqual(two.mode, "comparison"); self.assertEqual(two.change, 1.0)
        self.assertEqual(build_trend_presentation(points[:5]).mode, "timeline"); self.assertEqual(build_trend_presentation(points).mode, "chart")

    def test_adaptive_trend_collapses_same_day_and_limits_recent_assessments(self) -> None:
        points = [history_point(record("2026-01-01T08:00:00Z", score=70)), history_point(record("2026-01-01T20:00:00Z", score=80))]
        presentation = build_trend_presentation(points); self.assertEqual(presentation.mode, "single"); self.assertEqual(len(presentation.assessments), 2); self.assertEqual([point.score for point in presentation.daily_points], [80.0])
        many = [history_point(record(f"2026-01-{day:02d}T12:00:00Z", score=day)) for day in range(1, 13)]
        limited = build_trend_presentation(many); self.assertEqual(len(limited.assessments), 10); self.assertEqual(limited.assessments[0].score, 3.0)

    def test_adaptive_trend_rejects_mixed_privilege_profile_and_policy(self) -> None:
        base = history_point(record("2026-01-01T12:00:00Z"))
        for incompatible in (history_point(record("2026-01-02T12:00:00Z", privilege="Administrator")), history_point(record("2026-01-02T12:00:00Z", profile="Advanced")), history_point(record("2026-01-02T12:00:00Z", policy="3.0"))):
            presentation = build_trend_presentation([base, incompatible]); self.assertEqual(presentation.mode, "incomparable"); self.assertIsNone(presentation.change)


if __name__ == "__main__": unittest.main()
