"""Read-only filtering and comparison guidance for locally saved assessments."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable


@dataclass(frozen=True)
class HistoryPoint:
    record: dict[str, Any]
    timestamp: datetime | None
    profile: str
    policy_version: str
    privilege: str
    score: float | None
    coverage: float | None

    @property
    def comparison_key(self) -> tuple[str, ...]:
        if self.profile == "Legacy" or self.policy_version == "Unversioned":
            return self.profile, self.policy_version, str(self.record.get("timestamp_utc", id(self.record)))
        return self.profile, self.policy_version

    @property
    def trend_series_key(self) -> tuple[str, ...]:
        """A line-safe grouping key that never crosses privilege visibility."""
        privilege = "Administrator" if self.privilege.casefold().startswith("admin") else "Standard" if self.privilege.casefold().startswith("standard") else self.privilege
        return (*self.comparison_key, privilege)


@dataclass(frozen=True)
class TrendPresentation:
    """Adaptive presentation data for one strictly comparable series."""
    mode: str
    assessments: tuple[HistoryPoint, ...]
    daily_points: tuple[HistoryPoint, ...]
    latest: HistoryPoint | None
    previous: HistoryPoint | None
    change: float | None


def build_trend_presentation(points: Iterable[HistoryPoint], metric: str = "score", limit: int | None = 10) -> TrendPresentation:
    if metric not in ("score", "coverage"): raise ValueError(f"Unsupported trend metric: {metric}")
    usable = sorted((point for point in points if point.timestamp is not None and getattr(point, metric) is not None), key=lambda point: point.timestamp)
    if limit is not None and limit > 0: usable = usable[-limit:]
    if not usable: return TrendPresentation("empty", (), (), None, None, None)
    keys = {point.trend_series_key for point in usable}
    latest = usable[-1]
    if len(keys) != 1: return TrendPresentation("incomparable", tuple(usable), (), latest, None, None)
    daily = aggregate_trend_points(usable, metric)
    distinct_dates = len(daily)
    mode = "single" if distinct_dates <= 1 else "comparison" if distinct_dates == 2 else "timeline" if distinct_dates <= 5 else "chart"
    previous = usable[-2] if len(usable) > 1 else None
    change = None if previous is None else getattr(latest, metric) - getattr(previous, metric)
    return TrendPresentation(mode, tuple(usable), tuple(daily), latest, previous, change)


def parse_timestamp(value: object) -> datetime | None:
    try:
        text = str(value).strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def history_point(record: dict[str, Any]) -> HistoryPoint:
    assessment = record.get("assessment") if isinstance(record.get("assessment"), dict) else {}

    def number(value: object) -> float | None:
        try:
            return None if value is None else float(value)
        except (TypeError, ValueError):
            return None

    return HistoryPoint(
        record=record,
        timestamp=parse_timestamp(record.get("timestamp_utc")),
        profile=str(assessment.get("profile") or "Legacy"),
        policy_version=str(assessment.get("policy_version") or "Unversioned"),
        privilege=str(record.get("assessment_privilege") or "Unknown"),
        score=number(assessment.get("score")),
        coverage=number(assessment.get("coverage")),
    )


def filter_history(records: Iterable[dict[str, Any]], profile: str = "All",
                   start_date: date | None = None, end_date: date | None = None) -> list[HistoryPoint]:
    points = []
    for record in records:
        point = history_point(record)
        if profile != "All" and point.profile != profile:
            continue
        if point.timestamp is None:
            # Undated legacy records cannot safely satisfy a date-range query.
            if start_date is not None or end_date is not None:
                continue
        elif (start_date and point.timestamp.date() < start_date) or (end_date and point.timestamp.date() > end_date):
            continue
        points.append(point)
    return sorted(points, key=lambda point: point.timestamp or datetime.min.replace(tzinfo=timezone.utc))


def aggregate_trend_points(points: Iterable[HistoryPoint], metric: str = "score") -> list[HistoryPoint]:
    """Keep the latest local-day point in each directly connectable series."""
    if metric not in ("score", "coverage"):
        raise ValueError(f"Unsupported trend metric: {metric}")
    representatives: dict[tuple[tuple[str, ...], date], tuple[datetime, int, HistoryPoint]] = {}
    for order, point in enumerate(points):
        value = getattr(point, metric)
        if point.timestamp is None or value is None:
            continue
        local_day = point.timestamp.astimezone().date()
        key = point.trend_series_key, local_day
        candidate = point.timestamp, order, point
        if key not in representatives or candidate[:2] >= representatives[key][:2]:
            representatives[key] = candidate
    return sorted((candidate[2] for candidate in representatives.values()), key=lambda point: (point.timestamp, point.trend_series_key))


def comparison_explanation(older: HistoryPoint, newer: HistoryPoint) -> str:
    if "Legacy" in (older.profile, newer.profile) or "Unversioned" in (older.policy_version, newer.policy_version):
        return "Scores are not directly comparable because one or both records lack profile or scoring-policy metadata."
    differences = []
    if older.profile != newer.profile:
        differences.append(f"profile changed from {older.profile} to {newer.profile}")
    if older.policy_version != newer.policy_version:
        differences.append(f"policy changed from {older.policy_version} to {newer.policy_version}")
    if differences:
        return "Scores are not directly comparable because " + " and ".join(differences) + ". Status transitions remain visible."
    return f"Scores use the same {older.profile} profile and scoring policy {older.policy_version}."


def latest_saved_timestamp(records: Iterable[dict[str, Any]]) -> str | None:
    points = [point for point in (history_point(record) for record in records) if point.timestamp]
    if not points:
        return None
    return max(points, key=lambda point: point.timestamp).record.get("timestamp_utc")
