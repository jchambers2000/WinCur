"""Explainable weighted assessment scoring."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import AssessmentScore, CategoryScore, CheckResult, CheckStatus
from .resources import require_resource
from .storage import atomic_write_json


DEFAULT_CONFIG_PATH = Path(__file__).with_name("scoring_config.json")


def load_scoring_config(path: Path | None = None) -> dict[str, Any]:
    path = path or require_resource("scoring_config.json")
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    categories = config.get("categories", {})
    if not categories or abs(sum(float(v["weight"]) for v in categories.values()) - 100.0) > 0.001:
        raise ValueError("Category weights in scoring_config.json must total 100.")
    for check_id, definition in config.get("checks", {}).items():
        if definition.get("category") not in categories:
            raise ValueError(f"Check {check_id} refers to an undefined category.")
        if float(definition.get("weight", 0)) <= 0:
            raise ValueError(f"Check {check_id} must have a positive weight.")
    return config


def default_profile_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "WinCur" / "assessment_profile.json"


def load_selected_profile(config: dict[str, Any], path: Path | None = None) -> str:
    profiles = config.get("profiles", {}); default = str(config.get("default_profile", "Standard"))
    try:
        selected = str(json.loads((path or default_profile_path()).read_text(encoding="utf-8")).get("profile", default))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        selected = default
    return selected if selected in profiles else default


def save_selected_profile(profile: str, config: dict[str, Any], path: Path | None = None) -> None:
    if profile not in config.get("profiles", {}): raise ValueError("Unknown assessment profile.")
    destination = path or default_profile_path()
    atomic_write_json(destination, {"profile": profile}, indent=2)


def score_results(results: list[CheckResult], config: dict[str, Any], profile: str | None = None) -> AssessmentScore:
    """Score known results and report separately how much was assessable.

    Unknown checks are excluded from the score numerator and denominator but
    remain in the coverage denominator. Not Applicable checks are excluded from
    both. Category weights are re-normalized only when a whole category is N/A.
    """
    category_definitions = config["categories"]
    profiles = config.get("profiles", {})
    selected_profile = profile or str(config.get("default_profile", "Standard"))
    if profiles and selected_profile not in profiles: raise ValueError(f"Unknown assessment profile: {selected_profile}")
    profile_checks = profiles.get(selected_profile, {}).get("checks", {})
    policy_version = str(config.get("policy_version", config.get("methodology_version", "Unversioned")))
    dispositions: dict[str, str] = {}
    explanations: dict[str, str] = {}
    for finding in results:
        override = profile_checks.get(finding.check_id, {})
        if finding.status == CheckStatus.NOT_APPLICABLE:
            dispositions[finding.check_id] = "Not Applicable"
            explanations[finding.check_id] = "The check reported Not Applicable for this Windows configuration."
        else:
            dispositions[finding.check_id] = str(override.get("disposition", "Scored"))
            explanations[finding.check_id] = str(override.get("explanation", f"This check is scored by the {selected_profile} profile."))
    category_scores: list[CategoryScore] = []
    overall_known_points = 0.0
    overall_known_weight = 0.0
    overall_coverage_points = 0.0
    overall_applicable_weight = 0.0

    for category, category_config in category_definitions.items():
        members = [result for result in results if result.category == category]
        scored_members = [r for r in members if dispositions.get(r.check_id) == "Scored"]
        applicable = [r for r in scored_members if r.status != CheckStatus.NOT_APPLICABLE]
        known = [r for r in applicable if r.status in (CheckStatus.PASS, CheckStatus.FAIL)]
        applicable_weight = sum(max(r.weight, 0.0) for r in applicable)
        known_weight = sum(max(r.weight, 0.0) for r in known)
        pass_weight = sum(max(r.weight, 0.0) for r in known if r.status == CheckStatus.PASS)
        category_weight = float(category_config["weight"])

        category_score = (100.0 * pass_weight / known_weight) if known_weight else None
        coverage = (100.0 * known_weight / applicable_weight) if applicable_weight else 100.0
        category_scores.append(
            CategoryScore(
                category=category,
                score=round(category_score, 1) if category_score is not None else None,
                coverage=round(coverage, 1),
                passed=sum(r.status == CheckStatus.PASS for r in scored_members),
                failed=sum(r.status == CheckStatus.FAIL for r in scored_members),
                unknown=sum(r.status == CheckStatus.UNKNOWN for r in scored_members),
                not_applicable=sum(r.status == CheckStatus.NOT_APPLICABLE for r in members),
                informational=sum(dispositions.get(r.check_id) == "Informational" for r in members),
            )
        )
        if applicable_weight:
            overall_applicable_weight += category_weight
            overall_coverage_points += category_weight * known_weight / applicable_weight
        if known_weight:
            overall_known_weight += category_weight
            overall_known_points += category_weight * pass_weight / known_weight

    score = 100.0 * overall_known_points / overall_known_weight if overall_known_weight else None
    coverage = (
        100.0 * overall_coverage_points / overall_applicable_weight
        if overall_applicable_weight
        else 100.0
    )
    return AssessmentScore(
        score=round(score, 1) if score is not None else None,
        coverage=round(coverage, 1),
        categories=category_scores,
        profile=selected_profile,
        policy_version=policy_version,
        dispositions=dispositions,
        disposition_explanations=explanations,
    )

