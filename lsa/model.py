"""Assessment document model.

The field names, ordering, status vocabulary and summary arithmetic mirror the
m365-assessor ``AssessmentDocument`` so Linux reports read and score exactly
like Microsoft 365 reports. The two tenant-specific blocks are replaced by
host-specific ones: ``tenant`` becomes ``host`` and ``authentication`` becomes
``execution``. Tokens, password hashes and file contents that may hold secrets
are never placed in this model.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
WARNING = "WARNING"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_ASSESSED = "NOT_ASSESSED"
ERROR = "ERROR"
STATUSES = (PASS, FAIL, WARNING, NOT_APPLICABLE, NOT_ASSESSED, ERROR)
UNEVALUATED = (NOT_ASSESSED, ERROR)

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

COLLECTOR_STATUSES = ("SUCCESS", "PARTIAL", "NOT_ASSESSED", "ERROR")
COVERAGE_STATUSES = ("ASSESSED", "PARTIAL", "NOT_ASSESSED", "ERROR")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class FrameworkSelection:
    id: str
    name: str
    version: str


@dataclass
class BenchmarkMapping:
    framework: str
    benchmark: str
    version: str
    control: str


@dataclass
class CoverageArea:
    area: str
    name: str
    status: str
    coverage_percent: float
    reasons: list[str] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)
    detected_permissions: list[str] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)
    affected_collectors: list[str] = field(default_factory=list)
    affected_checks: list[str] = field(default_factory=list)


@dataclass
class CollectorExecution:
    collector_id: str
    name: str
    area: str
    status: str
    started_at: datetime = field(default_factory=utc_now)
    completed_at: datetime = field(default_factory=utc_now)
    objects_collected: int = 0
    pages_collected: int = 0
    api_errors: list[str] = field(default_factory=list)
    limitation_reason: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    check_id: str
    title: str
    severity: str
    status: str
    service: str
    category: str
    description: str = ""
    rationale: str = ""
    business_impact: str = ""
    benchmark: list[BenchmarkMapping] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_resources: list[str] = field(default_factory=list)
    observation: str = ""
    recommendation: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=utc_now)
    # Linux extension: the CIS profiles the recommendation belongs to.
    profiles: list[str] = field(default_factory=list)

    def cis_mapping(self) -> BenchmarkMapping | None:
        return next((item for item in self.benchmark if item.framework == "CIS"), None)


@dataclass
class AssessmentMetadata:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool: str = "linux-security-audit"
    tool_version: str = "1.0.0"
    client_name: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    completed_at: datetime | None = None
    scope: list[str] = field(default_factory=list)
    frameworks: list[FrameworkSelection] = field(default_factory=list)
    dry_run: bool = False


@dataclass
class HostInfo:
    hostname: str
    fqdn: str | None = None
    machine_id: str | None = None
    os_id: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_pretty_name: str | None = None
    kernel: str | None = None
    architecture: str | None = None
    virtualization: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    platform_type: str = "Server"
    profile: str = ""
    platform: str | None = None


@dataclass
class ExecutionContext:
    method: str = "local"
    identity: str | None = None
    uid: int | None = None
    effective_uid: int | None = None
    is_root: bool = False
    sudo_user: str | None = None
    python_version: str | None = None
    # Credentials are never used or recorded; the audit runs locally.


@dataclass
class AssessmentSummary:
    total_checks: int = 0
    pass_count: int = 0
    fail_count: int = 0
    warning_count: int = 0
    not_applicable_count: int = 0
    not_assessed_count: int = 0
    error_count: int = 0
    pass_percentage: float = 0
    failure_percentage: float = 0
    coverage_percentage: float = 0
    severity_distribution: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_results(cls, results: list[CheckResult]) -> AssessmentSummary:
        counts = {status: 0 for status in STATUSES}
        severity = {item: 0 for item in SEVERITIES}
        for result in results:
            counts[result.status] += 1
            if result.status in (FAIL, WARNING):
                severity[result.severity] += 1
        assessed = counts[PASS] + counts[FAIL] + counts[WARNING]
        applicable = assessed + counts[NOT_ASSESSED] + counts[ERROR]
        return cls(
            total_checks=len(results),
            pass_count=counts[PASS],
            fail_count=counts[FAIL],
            warning_count=counts[WARNING],
            not_applicable_count=counts[NOT_APPLICABLE],
            not_assessed_count=counts[NOT_ASSESSED],
            error_count=counts[ERROR],
            pass_percentage=round(100 * counts[PASS] / assessed, 2) if assessed else 0,
            failure_percentage=(
                round(100 * (counts[FAIL] + counts[WARNING]) / assessed, 2) if assessed else 0
            ),
            coverage_percentage=round(100 * assessed / applicable, 2) if applicable else 0,
            severity_distribution=severity,
        )


@dataclass
class AssessmentDocument:
    assessment: AssessmentMetadata
    host: HostInfo
    execution: ExecutionContext
    coverage: list[CoverageArea]
    collectors: dict[str, CollectorExecution]
    checks: list[CheckResult]
    findings: list[CheckResult]
    summary: AssessmentSummary
    benchmark_results: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _dump(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssessmentDocument:
        unknown = set(data) - {item.name for item in fields(cls)}
        if unknown:
            raise ValueError(f"Unknown assessment document field(s): {', '.join(sorted(unknown))}")
        assessment = dict(data["assessment"])
        assessment["frameworks"] = [FrameworkSelection(**item) for item in assessment.get("frameworks", [])]
        for key in ("started_at", "completed_at"):
            assessment[key] = from_iso(assessment.get(key))
        collectors = {}
        for key, value in data.get("collectors", {}).items():
            value = dict(value)
            value["started_at"] = from_iso(value.get("started_at"))
            value["completed_at"] = from_iso(value.get("completed_at"))
            collectors[key] = CollectorExecution(**value)
        checks = [_check_from_dict(item) for item in data.get("checks", [])]
        findings = [_check_from_dict(item) for item in data.get("findings", [])]
        return cls(
            assessment=AssessmentMetadata(**assessment),
            host=HostInfo(**data["host"]),
            execution=ExecutionContext(**data["execution"]),
            coverage=[CoverageArea(**item) for item in data.get("coverage", [])],
            collectors=collectors,
            checks=checks,
            findings=findings,
            summary=AssessmentSummary(**data["summary"]),
            benchmark_results=dict(data.get("benchmark_results", {})),
        )


def _check_from_dict(data: dict[str, Any]) -> CheckResult:
    values = dict(data)
    values["benchmark"] = [BenchmarkMapping(**item) for item in values.get("benchmark", [])]
    values["timestamp"] = from_iso(values.get("timestamp")) or utc_now()
    return CheckResult(**values)


def _dump(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {item.name: _dump(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, datetime):
        return to_iso(value)
    if isinstance(value, dict):
        return {str(key): _dump(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        items = sorted(value) if isinstance(value, set) else value
        return [_dump(item) for item in items]
    return value
