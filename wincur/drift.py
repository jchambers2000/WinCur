"""Configuration-drift classification between two saved assessments."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Any

from .models import CheckStatus


@dataclass(frozen=True)
class DriftChange:
    check_id: str
    title: str
    category: str
    older_status: str
    newer_status: str
    classification: str
    confidence: str
    first_observed_utc: str
    older_evidence: str
    newer_evidence: str
    evidence_changed: bool
    severity_change: str
    score_treatment: str


@dataclass(frozen=True)
class DriftComparison:
    changes: list[DriftChange]
    score_change: float | None
    coverage_change: float | None
    directly_comparable: bool
    comparison_note: str


def normalize_evidence(value: object) -> tuple[str, bool]:
    """Return a formatting-insensitive form and whether structure is reliable.

    JSON/Python mappings and sequences are stable enough to compare after key
    sorting. Free-form command output is normalized for display/deduplication,
    but a text-only change is never called confirmed configuration drift.
    """
    text = str(value or "").strip()
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
        except (ValueError, SyntaxError, TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, (dict, list, tuple, bool, int, float, type(None))):
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str).casefold(), True
    return re.sub(r"\s+", " ", text).casefold(), False


def _status(value: object) -> str:
    text = str(value or CheckStatus.UNKNOWN.value)
    return text if text in {status.value for status in CheckStatus} else CheckStatus.UNKNOWN.value


def _number(value: object) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _classification(old: str, new: str, evidence_changed: bool, evidence_reliable: bool) -> tuple[str, str]:
    if old == CheckStatus.PASS.value and new == CheckStatus.FAIL.value:
        return "Pass to Fail", "Confirmed status drift"
    if old == CheckStatus.FAIL.value and new == CheckStatus.PASS.value:
        return "Fail to Pass", "Confirmed status drift"
    if new == CheckStatus.UNKNOWN.value and old != new:
        return "Changed to Unknown", "Insufficient evidence"
    if old == CheckStatus.UNKNOWN.value and new != old:
        return "Unknown to " + new, "Newly assessable"
    if old != new:
        return f"{old} to {new}", "Status transition"
    if evidence_changed and evidence_reliable:
        return "Evidence changed", "Confirmed normalized evidence change"
    if evidence_changed:
        return "Evidence text changed", "Insufficient evidence"
    return "Unchanged", "No drift observed"


def compare_assessments(older: dict[str, Any], newer: dict[str, Any]) -> DriftComparison:
    old_results = {str(item.get("check_id")): item for item in older.get("results", []) if isinstance(item, dict) and item.get("check_id")}
    new_results = {str(item.get("check_id")): item for item in newer.get("results", []) if isinstance(item, dict) and item.get("check_id")}
    old_assessment = older.get("assessment") if isinstance(older.get("assessment"), dict) else {}
    new_assessment = newer.get("assessment") if isinstance(newer.get("assessment"), dict) else {}
    old_dispositions = old_assessment.get("dispositions") if isinstance(old_assessment.get("dispositions"), dict) else {}
    new_dispositions = new_assessment.get("dispositions") if isinstance(new_assessment.get("dispositions"), dict) else {}
    changes = []
    for check_id in sorted(old_results.keys() | new_results.keys()):
        old = old_results.get(check_id, {})
        new = new_results.get(check_id, {})
        old_status = _status(old.get("status")) if old else "Missing"
        new_status = _status(new.get("status")) if new else "Missing"
        old_normal, old_reliable = normalize_evidence(old.get("evidence", ""))
        new_normal, new_reliable = normalize_evidence(new.get("evidence", ""))
        evidence_changed = old_normal != new_normal
        classification, confidence = _classification(old_status, new_status, evidence_changed, old_reliable and new_reliable)
        old_severity = str(old.get("severity", "Unknown")); new_severity = str(new.get("severity", "Unknown"))
        severity_change = "Unchanged" if old_severity == new_severity else f"{old_severity} to {new_severity}"
        old_treatment = str(old_dispositions.get(check_id, "Scored")); new_treatment = str(new_dispositions.get(check_id, "Scored"))
        old_weight = old.get("weight", "Unknown"); new_weight = new.get("weight", "Unknown")
        score_treatment = (f"{new_treatment}; check weight {new_weight}" if old_treatment == new_treatment and old_weight == new_weight
                           else f"{old_treatment} ({old_weight}) to {new_treatment} ({new_weight})")
        if classification != "Unchanged":
            changes.append(DriftChange(
                check_id, str(new.get("title") or old.get("title") or check_id),
                str(new.get("category") or old.get("category") or "Unknown"), old_status, new_status,
                classification, confidence, str(newer.get("timestamp_utc", "Unknown")),
                str(old.get("evidence", "Missing")), str(new.get("evidence", "Missing")), evidence_changed, severity_change, score_treatment,
            ))
    old_profile = str(old_assessment.get("profile") or "Legacy"); new_profile = str(new_assessment.get("profile") or "Legacy")
    old_policy = str(old_assessment.get("policy_version") or "Unversioned"); new_policy = str(new_assessment.get("policy_version") or "Unversioned")
    comparable = (old_profile == new_profile and old_policy == new_policy and
                  old_profile != "Legacy" and old_policy != "Unversioned")
    note = (f"Comparable: both assessments use {old_profile} / policy {old_policy}." if comparable else
            f"Scores are not directly comparable ({old_profile}/{old_policy} versus {new_profile}/{new_policy}); status transitions are still reported.")
    old_score = _number(old_assessment.get("score")); new_score = _number(new_assessment.get("score"))
    old_coverage = _number(old_assessment.get("coverage")); new_coverage = _number(new_assessment.get("coverage"))
    return DriftComparison(
        changes,
        (new_score - old_score) if comparable and old_score is not None and new_score is not None else None,
        (new_coverage - old_coverage) if comparable and old_coverage is not None and new_coverage is not None else None,
        comparable, note,
    )
