"""Shared, UI-independent data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    PASS = "Pass"
    FAIL = "Fail"
    UNKNOWN = "Unknown"
    NOT_APPLICABLE = "Not Applicable"


@dataclass(frozen=True)
class Remediation:
    summary: str
    required_permissions: str
    impact: str
    verification: str
    rollback: str
    settings_uri: str | None = None


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    title: str
    category: str
    status: CheckStatus
    evidence: str
    explanation: str
    weight: float
    severity: str
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CheckResult":
        remediation_data = data.get("remediation")
        remediation = Remediation(**remediation_data) if remediation_data else None
        return cls(
            check_id=str(data["check_id"]), title=str(data["title"]), category=str(data["category"]),
            status=CheckStatus(data["status"]), evidence=str(data["evidence"]),
            explanation=str(data["explanation"]), weight=float(data["weight"]),
            severity=str(data["severity"]), remediation=remediation,
        )


@dataclass(frozen=True)
class CategoryScore:
    category: str
    score: float | None
    coverage: float
    passed: int
    failed: int
    unknown: int
    not_applicable: int
    informational: int = 0


@dataclass(frozen=True)
class AssessmentScore:
    score: float | None
    coverage: float
    categories: list[CategoryScore] = field(default_factory=list)
    profile: str = "Legacy"
    policy_version: str = "Unversioned"
    dispositions: dict[str, str] = field(default_factory=dict)
    disposition_explanations: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "coverage": self.coverage, "categories": [asdict(item) for item in self.categories],
                "profile": self.profile, "policy_version": self.policy_version, "dispositions": self.dispositions,
                "disposition_explanations": self.disposition_explanations}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssessmentScore":
        categories = []
        for item in data.get("categories", []):
            values = dict(item); values.setdefault("informational", 0); categories.append(CategoryScore(**values))
        return cls(score=data.get("score"), coverage=float(data["coverage"]), categories=categories,
                   profile=str(data.get("profile", "Legacy")), policy_version=str(data.get("policy_version", "Unversioned")),
                   dispositions=dict(data.get("dispositions") or {}), disposition_explanations=dict(data.get("disposition_explanations") or {}))


@dataclass(frozen=True)
class AssessmentEnvelope:
    findings: list[CheckResult]
    assessment: AssessmentScore
    timestamp_utc: str
    privilege: str
    source: str = "Live scan"

    @classmethod
    def create(cls, findings: list[CheckResult], assessment: AssessmentScore, privilege: str,
               source: str = "Live scan") -> "AssessmentEnvelope":
        return cls(findings, assessment, datetime.now(timezone.utc).isoformat(), privilege, source)


class ActionAvailability(str, Enum):
    AVAILABLE = "Available"
    ALREADY_COMPLIANT = "Already Compliant"
    REQUIRES_ELEVATION = "Requires Elevation"
    MANAGED = "Managed by Organization"
    MANUAL = "Requires Manual Action"
    UNSUPPORTED = "Unsupported"


class ActionOutcome(str, Enum):
    SUCCESS = "Success"
    FAILURE = "Failure"
    PARTIAL = "Partial Success"
    CANCELLED = "Cancelled"


@dataclass(frozen=True)
class ActionPreview:
    action_id: str
    title: str
    finding: str
    severity: str
    availability: ActionAvailability
    current_configuration: str
    recommended_configuration: str
    rationale: str
    compatibility: str
    required_permissions: str
    exact_change: str
    verification: str
    rollback: str
    management_evidence: str
    technical_details: str = ""
    preview_token: str = ""
    created_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self); data["availability"] = self.availability.value; return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionPreview":
        values = dict(data); values["availability"] = ActionAvailability(values["availability"]); return cls(**values)


@dataclass(frozen=True)
class ActionRecord:
    timestamp_utc: str
    action_id: str
    original_configuration: dict[str, Any]
    requested_configuration: dict[str, Any]
    outcome: ActionOutcome
    message: str
    verification_evidence: str
    rollback_available: bool
    rollback_status: str
    rollback_snapshot_schema: int = 1
    rollback_source_timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self); data["outcome"] = self.outcome.value; return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRecord":
        return cls(
            timestamp_utc=str(data["timestamp_utc"]), action_id=str(data["action_id"]),
            original_configuration=dict(data.get("original_configuration") or {}),
            requested_configuration=dict(data.get("requested_configuration") or {}),
            outcome=ActionOutcome(data["outcome"]), message=str(data.get("message", "")),
            verification_evidence=str(data.get("verification_evidence", "")),
            rollback_available=bool(data.get("rollback_available")), rollback_status=str(data.get("rollback_status", "Not requested")),
            rollback_snapshot_schema=int(data.get("rollback_snapshot_schema", 1)),
            rollback_source_timestamp_utc=str(data.get("rollback_source_timestamp_utc", "")),
        )

    @classmethod
    def create(cls, action_id: str, original: dict[str, Any], requested: dict[str, Any], outcome: ActionOutcome,
               message: str, evidence: str, rollback_available: bool, rollback_status: str = "Not requested",
               rollback_snapshot_schema: int = 1, rollback_source_timestamp_utc: str = "") -> "ActionRecord":
        return cls(datetime.now(timezone.utc).isoformat(), action_id, original, requested, outcome, message, evidence, rollback_available, rollback_status, rollback_snapshot_schema, rollback_source_timestamp_utc)


@dataclass(frozen=True)
class ScanRecord:
    timestamp_utc: str
    application_version: str
    windows_version: str
    computer_name: str
    results: list[CheckResult]
    assessment: AssessmentScore
    assessment_privilege: str = "Unknown"
    assessment_source: str = "Live scan"

    @classmethod
    def create(
        cls,
        application_version: str,
        windows_version: str,
        computer_name: str,
        results: list[CheckResult],
        assessment: AssessmentScore,
        assessment_privilege: str = "Unknown",
        assessment_source: str = "Live scan",
        timestamp_utc: str | None = None,
    ) -> "ScanRecord":
        return cls(
            timestamp_utc=timestamp_utc or datetime.now(timezone.utc).isoformat(),
            application_version=application_version,
            windows_version=windows_version,
            computer_name=computer_name,
            results=results,
            assessment=assessment,
            assessment_privilege=assessment_privilege,
            assessment_source=assessment_source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "application_version": self.application_version,
            "windows_version": self.windows_version,
            "computer_name": self.computer_name,
            "results": [result.to_dict() for result in self.results],
            "assessment": {
                **self.assessment.to_dict(),
            },
            "assessment_privilege": self.assessment_privilege,
            "assessment_source": self.assessment_source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanRecord":
        """Load both current records and history written by older WinCur builds."""
        assessment_data = dict(data.get("assessment") or {})
        assessment_data.setdefault("coverage", 0.0)
        return cls(
            timestamp_utc=str(data.get("timestamp_utc", "Unknown")),
            application_version=str(data.get("application_version", "Unknown")),
            windows_version=str(data.get("windows_version", "Unknown")),
            computer_name=str(data.get("computer_name", "Unknown")),
            results=[CheckResult.from_dict(item) for item in data.get("results", []) if isinstance(item, dict)],
            assessment=AssessmentScore.from_dict(assessment_data),
            assessment_privilege=str(data.get("assessment_privilege", "Unknown")),
            assessment_source=str(data.get("assessment_source", "Historical assessment")),
        )

