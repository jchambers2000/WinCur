"""Security-state-aware comparison of an assessment against a baseline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .drift import normalize_evidence
from .models import CheckStatus


REGRESSION = "Regression"
IMPROVEMENT = "Improvement"
UNCHANGED = "Unchanged"
NEWLY_ASSESSABLE = "Newly assessable"
NO_LONGER_ASSESSABLE = "No longer assessable"
EVIDENCE_ONLY = "Evidence-only change"
NOT_COMPARABLE = "Not comparable"


@dataclass(frozen=True)
class BaselineCheckComparison:
    check_id: str
    title: str
    category: str
    baseline_status: str
    current_status: str
    classification: str
    severity: str
    baseline_evidence: str
    current_evidence: str
    explanation: str
    treatment: str


@dataclass(frozen=True)
class BaselineComparison:
    results: list[BaselineCheckComparison]
    aggregate_comparable: bool
    compatibility_explanation: str
    score_change: float | None
    coverage_change: float | None
    privilege_difference: bool = False

    def count(self, classification: str) -> int:
        return sum(item.classification == classification for item in self.results)

    @property
    def review_count(self) -> int:
        return sum(item.classification in (NEWLY_ASSESSABLE, NO_LONGER_ASSESSABLE, EVIDENCE_ONLY, NOT_COMPARABLE) for item in self.results)


def _assessment(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("assessment") if isinstance(record.get("assessment"), dict) else {}


def _number(value: object) -> float | None:
    try: return None if value is None else float(value)
    except (TypeError, ValueError): return None


def _results(record: dict[str, Any]) -> list[dict[str, Any]]:
    values = record.get("results", [])
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def compare_to_baseline(baseline: dict[str, Any], current: dict[str, Any]) -> BaselineComparison:
    base_assessment, current_assessment = _assessment(baseline), _assessment(current)
    base_profile = str(base_assessment.get("profile") or "Legacy"); current_profile = str(current_assessment.get("profile") or "Legacy")
    base_policy = str(base_assessment.get("policy_version") or "Unversioned"); current_policy = str(current_assessment.get("policy_version") or "Unversioned")
    compatible = (base_profile == current_profile and base_policy == current_policy and base_profile != "Legacy" and base_policy != "Unversioned")
    base_privilege = str(baseline.get("assessment_privilege", "Unknown")); current_privilege = str(current.get("assessment_privilege", "Unknown")); privilege_changed = base_privilege != current_privilege
    if compatible:
        compatibility = f"Comparable profile {base_profile} and scoring policy {base_policy}."
        if privilege_changed: compatibility += f" Assessment privilege differs ({base_privilege} versus {current_privilege}); score and coverage movement may reflect visibility, so confirmed per-check changes are more reliable."
    else: compatibility = f"Aggregate scores are not comparable ({base_profile}/{base_policy} versus {current_profile}/{current_policy}). Per-check results are marked Not comparable."
    base_results = {str(item.get("check_id")): item for item in _results(baseline) if item.get("check_id")}
    current_results = {str(item.get("check_id")): item for item in _results(current) if item.get("check_id")}
    base_dispositions = base_assessment.get("dispositions") if isinstance(base_assessment.get("dispositions"), dict) else {}
    current_dispositions = current_assessment.get("dispositions") if isinstance(current_assessment.get("dispositions"), dict) else {}
    comparisons = []
    for check_id in sorted(base_results.keys() | current_results.keys()):
        old, new = base_results.get(check_id), current_results.get(check_id)
        reference = new or old or {}; title = str(reference.get("title") or check_id); category = str(reference.get("category") or "Unknown"); severity = str(reference.get("severity") or "Unknown")
        old_status = str(old.get("status", "Missing")) if old else "Missing"; new_status = str(new.get("status", "Missing")) if new else "Missing"
        old_evidence = str(old.get("evidence", "Check was not present.")) if old else "Check was not present."
        new_evidence = str(new.get("evidence", "Check was not present.")) if new else "Check was not present."
        treatment_old = str(base_dispositions.get(check_id, "Scored")); treatment_new = str(current_dispositions.get(check_id, "Scored")); treatment = treatment_new if treatment_old == treatment_new else f"{treatment_old} to {treatment_new}"
        if not compatible:
            classification, explanation = NOT_COMPARABLE, compatibility
        elif not old or not new:
            classification, explanation = NOT_COMPARABLE, "This check was added or removed between assessment versions; no configuration change is inferred."
        elif old_status not in {status.value for status in CheckStatus} or new_status not in {status.value for status in CheckStatus}:
            classification, explanation = NOT_COMPARABLE, "One assessment contains an unsupported or missing status; no security change is inferred."
        elif CheckStatus.NOT_APPLICABLE.value in (old_status, new_status) and old_status != new_status:
            classification, explanation = NOT_COMPARABLE, "Check applicability changed; this is not treated as security drift."
        elif old_status == CheckStatus.PASS.value and new_status == CheckStatus.FAIL.value:
            classification, explanation = REGRESSION, "The check changed from Pass to Fail. This is a confirmed security-state regression."
        elif old_status == CheckStatus.FAIL.value and new_status == CheckStatus.PASS.value:
            classification, explanation = IMPROVEMENT, "The check changed from Fail to Pass. This is a confirmed security-state improvement."
        elif old_status == CheckStatus.UNKNOWN.value and new_status in (CheckStatus.PASS.value, CheckStatus.FAIL.value):
            suffix = " The assessment privilege also changed, so increased visibility may explain the result." if privilege_changed else ""
            classification, explanation = NEWLY_ASSESSABLE, "The check now has a known result; no prior security state is inferred." + suffix
        elif new_status == CheckStatus.UNKNOWN.value and old_status in (CheckStatus.PASS.value, CheckStatus.FAIL.value):
            suffix = " The assessment privilege changed and may explain the lost visibility." if privilege_changed else ""
            classification, explanation = NO_LONGER_ASSESSABLE, "The current assessment cannot confirm the prior known state." + suffix
        else:
            old_normal, _ = normalize_evidence(old_evidence); new_normal, _ = normalize_evidence(new_evidence)
            if old_status != new_status:
                classification, explanation = NOT_COMPARABLE, f"The transition from {old_status} to {new_status} is not a confirmed Pass/Fail security-state change."
            elif old_normal != new_normal:
                classification, explanation = EVIDENCE_ONLY, "Normalized evidence changed, but the security status did not; review without inferring a regression."
            else:
                classification, explanation = UNCHANGED, "Status and normalized evidence are unchanged."
        if treatment_new == "Informational": explanation += " This check is informational under the current profile and is excluded from its score."
        comparisons.append(BaselineCheckComparison(check_id, title, category, old_status, new_status, classification, severity, old_evidence, new_evidence, explanation, treatment))
    base_score, current_score = _number(base_assessment.get("score")), _number(current_assessment.get("score")); base_coverage, current_coverage = _number(base_assessment.get("coverage")), _number(current_assessment.get("coverage"))
    return BaselineComparison(comparisons, compatible, compatibility,
                              current_score - base_score if compatible and base_score is not None and current_score is not None else None,
                              current_coverage - base_coverage if compatible and base_coverage is not None and current_coverage is not None else None,
                              privilege_changed)
