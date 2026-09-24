"""Benchmark definition validation and control execution.

Definitions are validated before any evidence is collected: missing fields,
duplicate identifiers, unknown providers, conditions or path sources, and a
declared control count that does not match the controls present all stop the
run. Each control then yields exactly one result. Unreadable evidence becomes
NOT_ASSESSED and provider defects become ERROR, so neither can masquerade as a
configuration failure, and no control disappears from the report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

from lsa import TOOL_NAME, __version__
from lsa.checks import CONDITIONS, PROVIDERS, SOURCES
from lsa.model import (
    ERROR,
    FAIL,
    NOT_APPLICABLE,
    NOT_ASSESSED,
    PASS,
    SEVERITIES,
    STATUSES,
    WARNING,
    AssessmentDocument,
    AssessmentMetadata,
    AssessmentSummary,
    BenchmarkMapping,
    CheckResult,
    CoverageArea,
    ExecutionContext,
    FrameworkSelection,
    HostInfo,
    utc_now,
)
from lsa.system import EvidenceUnavailable, System

REQUIRED_BENCHMARK_FIELDS = ("id", "framework", "name", "short_name", "version", "platform", "profiles", "automated_control_count")
REQUIRED_CONTROL_FIELDS = (
    "id", "cis_id", "title", "section", "category", "profiles", "automated", "severity",
    "description", "rationale", "business_impact", "recommendation", "remediation", "references", "check",
)
PROFILE_CHOICES = {
    "level1-server": "Level 1 - Server",
    "level2-server": "Level 2 - Server",
    "level1-workstation": "Level 1 - Workstation",
    "level2-workstation": "Level 2 - Workstation",
}
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
PLATFORM_LABELS = {"proxmox": "Proxmox VE"}
FRAMEWORK_SELECTIONS = {
    "CIS Controls": ("cis-controls-v8", "CIS Critical Security Controls", "8"),
    "NIST": ("nist-sp-800-53-r5", "NIST SP 800-53", "Rev. 5"),
}


class DefinitionError(Exception):
    """A benchmark definition is malformed and must not be executed."""


def _walk_sources(value: Any) -> list[str]:
    found = []
    if isinstance(value, dict):
        if isinstance(value.get("source"), str):
            found.append(value["source"])
        for item in value.values():
            found.extend(_walk_sources(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_sources(item))
    return found


def load_definition(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise DefinitionError(f"Benchmark definition does not exist: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DefinitionError(f"Unable to parse benchmark definition '{path}': {exc}") from exc
    for key in ("schema_version", "benchmark", "controls"):
        if key not in document:
            raise DefinitionError(f"Benchmark definition '{path.name}' is missing '{key}'.")
    benchmark = document["benchmark"]
    for key in REQUIRED_BENCHMARK_FIELDS:
        if key not in benchmark:
            raise DefinitionError(f"Benchmark metadata in '{path.name}' is missing '{key}'.")
    controls = document["controls"]
    if len(controls) != int(benchmark["automated_control_count"]):
        raise DefinitionError(
            f"'{path.name}' declares {benchmark['automated_control_count']} automated controls but contains {len(controls)}."
        )
    seen_ids: set[str] = set()
    seen_cis: set[str] = set()
    profiles = set(benchmark["profiles"])
    for control in controls:
        identifier = control.get("id", "<missing id>")
        for key in REQUIRED_CONTROL_FIELDS:
            if key not in control:
                raise DefinitionError(f"Control '{identifier}' is missing '{key}'.")
        if identifier in seen_ids:
            raise DefinitionError(f"Duplicate control ID '{identifier}'.")
        if control["cis_id"] in seen_cis:
            raise DefinitionError(f"Duplicate CIS recommendation '{control['cis_id']}'.")
        seen_ids.add(identifier)
        seen_cis.add(control["cis_id"])
        if control["automated"] is not True:
            raise DefinitionError(f"Control '{identifier}' is not marked automated.")
        if control["severity"] not in SEVERITIES:
            raise DefinitionError(f"Control '{identifier}' has invalid severity '{control['severity']}'.")
        if not control["profiles"] or not set(control["profiles"]) <= profiles:
            raise DefinitionError(f"Control '{identifier}' lists profiles outside the benchmark profile set.")
        check_type = control["check"].get("type")
        if check_type not in PROVIDERS:
            raise DefinitionError(f"Control '{identifier}' uses unsupported check type '{check_type}'.")
        for condition in control.get("applies_if", []):
            if condition.get("type") not in CONDITIONS:
                raise DefinitionError(f"Control '{identifier}' uses unsupported condition '{condition.get('type')}'.")
        for name in _walk_sources(control["check"]):
            if name not in SOURCES:
                raise DefinitionError(f"Control '{identifier}' references unknown path source '{name}'.")
    for manual in document.get("manual_recommendations", []):
        for key in ("id", "cis_id", "title", "section", "category", "profiles", "guidance"):
            if key not in manual:
                raise DefinitionError(f"Manual recommendation '{manual.get('cis_id', '?')}' is missing '{key}'.")
    return document


def resolve_profile(requested: str, platform_type: str, benchmark_profiles: list[str]) -> tuple[str, set[str]]:
    """Map a CLI profile choice to (selected CIS profile, profiles it includes).

    Linux benchmarks have Server and Workstation variants; ESXi benchmarks only
    have levels. Level 2 always includes Level 1 of the same variant.
    """
    requested = (requested or "auto").lower()
    choices = {"auto", "level1", "level2", *PROFILE_CHOICES}
    if requested not in choices:
        raise ValueError(f"Unknown profile '{requested}'. Choose auto, level1, level2 or one of {', '.join(PROFILE_CHOICES)}.")
    level = "1" if requested.startswith("level1") else "2"
    if any(item.endswith(("Server", "Workstation")) for item in benchmark_profiles):
        kind = "Workstation" if platform_type == "Workstation" else "Server"
        if requested in PROFILE_CHOICES:
            name = PROFILE_CHOICES[requested]
        else:
            name = f"Level {level} - {kind}"
        allowed = {name, name.replace("Level 2", "Level 1")} if name.startswith("Level 2") else {name}
        return name, allowed
    by_level = {item.split()[1]: item for item in benchmark_profiles if item.startswith("Level ")}
    allowed = {item for key, item in by_level.items() if key <= level}
    return by_level.get(level, sorted(benchmark_profiles)[-1]), allowed or set(benchmark_profiles)


def _mappings(control: dict, benchmark: dict) -> list[BenchmarkMapping]:
    mappings = [BenchmarkMapping("CIS", benchmark["short_name"], benchmark["version"], control["cis_id"])]
    for safeguard in control.get("cis_controls_v8", []):
        mappings.append(BenchmarkMapping("CIS Controls", "Critical Security Controls", "8", safeguard))
    for item in control.get("nist_800_53", []):
        mappings.append(BenchmarkMapping("NIST", "SP 800-53", "Rev. 5", item))
    return mappings


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


class Engine:
    """Evaluates every control of a validated definition exactly once."""

    def __init__(
        self,
        system: System,
        definition: dict[str, Any],
        *,
        profile: str,
        allowed_profiles: set[str],
        sections: list[str] | None = None,
        include_manual: bool = False,
        platform_tags: set[str] | None = None,
        progress: Callable[[int, int, str], None] | None = None,
    ) -> None:
        self.system = system
        self.definition = definition
        self.benchmark = definition["benchmark"]
        self.profile = profile
        self.allowed_profiles = allowed_profiles
        self.sections = [item.lower() for item in sections or []]
        self.include_manual = include_manual
        self.platform_tags = platform_tags or set()
        self.progress = progress
        self.permissions: dict[str, str | None] = {}
        self.collectors_used: dict[str, set[str]] = {}

    # ------------------------------------------------------------------ run
    def run(self) -> list[CheckResult]:
        self._prefetch_units()
        controls = self.definition["controls"]
        results = []
        for index, control in enumerate(controls, 1):
            if self.progress:
                self.progress(index, len(controls), control["id"])
            results.append(self.evaluate(control))
        if self.include_manual:
            results.extend(self._manual_result(item) for item in self.definition.get("manual_recommendations", []))
        return results

    def _in_scope(self, section: str, cis_id: str) -> bool:
        if not self.sections:
            return True
        top = cis_id.split(".")[0]
        return section.lower() in self.sections or top in self.sections

    def _prefetch_units(self) -> None:
        units: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "units" and isinstance(item, list):
                        units.update(u if isinstance(u, str) else u["name"] for u in item)
                    else:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect([control["check"] for control in self.definition["controls"]])
        if units:
            try:
                self.system.units(sorted(units))
            except Exception:  # noqa: BLE001 - prefetch is an optimisation; each control reports its own outcome
                pass

    def evaluate(self, control: dict[str, Any]) -> CheckResult:
        timestamp = utc_now()
        if not self._in_scope(control["section"], control["cis_id"]):
            return self._result(control, NOT_APPLICABLE, "Out of scope for this assessment (section filter).", {}, [], timestamp)
        if not set(control["profiles"]) & self.allowed_profiles:
            return self._result(
                control,
                NOT_APPLICABLE,
                f"Not part of the selected profile ({self.profile}); this recommendation belongs to {', '.join(control['profiles'])}.",
                {},
                [],
                timestamp,
            )
        self.system.begin_tracking()
        try:
            for condition in control.get("applies_if", []):
                applicable, reason = CONDITIONS[condition["type"]](self.system, condition)
                if not applicable:
                    return self._result(control, NOT_APPLICABLE, reason + ".", {}, [], timestamp)
            outcome = PROVIDERS[control["check"]["type"]](self.system, control["check"])
            observation = outcome.observation + self._platform_note(control)
            return self._result(control, outcome.status, observation, outcome.evidence, outcome.affected, timestamp)
        except EvidenceUnavailable as exc:
            self.permissions[control["id"]] = exc.permission
            observation = f"Evidence unavailable: {exc.reason}." + self._platform_note(control)
            return self._result(control, NOT_ASSESSED, observation, {}, [], timestamp)
        except Exception as exc:  # noqa: BLE001 - a provider defect must not abort the assessment
            return self._result(control, ERROR, f"Evaluation error: {type(exc).__name__}: {exc}", {}, [], timestamp)
        finally:
            self.collectors_used[control["id"]] = self.system.end_tracking()

    def _platform_note(self, control: dict[str, Any]) -> str:
        notes = control.get("notes", {})
        text = " ".join(f"Note ({PLATFORM_LABELS.get(tag, tag)}): {notes[tag]}" for tag in sorted(self.platform_tags) if tag in notes)
        return f" {text}" if text else ""

    def _manual_result(self, manual: dict[str, Any]) -> CheckResult:
        control = {
            **manual,
            "severity": manual.get("severity", "Informational"),
            "description": manual["guidance"],
            "rationale": manual.get("rationale", ""),
            "business_impact": manual.get("business_impact", ""),
            "recommendation": manual["guidance"],
            "remediation": manual.get("remediation", manual["guidance"]),
            "references": manual.get("references", []),
        }
        if not set(manual["profiles"]) & self.allowed_profiles:
            return self._result(control, NOT_APPLICABLE, f"Not part of the selected profile ({self.profile}).", {}, [], utc_now())
        return self._result(
            control,
            NOT_ASSESSED,
            "Manual recommendation: CIS requires assessor review; no automated verdict is produced.",
            {},
            [],
            utc_now(),
        )

    def _result(
        self,
        control: dict[str, Any],
        status: str,
        observation: str,
        evidence: dict[str, Any],
        affected: list[str],
        timestamp: Any,
    ) -> CheckResult:
        if status not in STATUSES:
            status = ERROR
            observation = f"Evaluation error: provider returned an invalid status. {observation}"
        return CheckResult(
            check_id=control["id"],
            title=control["title"],
            severity=control["severity"],
            status=status,
            service=control["section"],
            category=control["category"],
            description=control["description"],
            rationale=control["rationale"],
            business_impact=control["business_impact"],
            benchmark=_mappings(control, self.benchmark),
            evidence=_json_safe(evidence),
            affected_resources=[str(item) for item in affected],
            observation=observation,
            recommendation=control["recommendation"],
            remediation=control["remediation"],
            references=list(control["references"]),
            timestamp=timestamp,
            profiles=list(control["profiles"]),
        )


# ---------------------------------------------------------------- document
def build_coverage(engine: Engine, results: list[CheckResult]) -> list[CoverageArea]:
    items = list(engine.definition["controls"])
    if engine.include_manual:
        items += engine.definition.get("manual_recommendations", [])
    sections: list[str] = []
    for control in items:
        if control["section"] not in sections:
            sections.append(control["section"])
    collectors = engine.system.collectors()
    is_root = engine.system.is_root
    areas = []
    for section in sections:
        checks = [item for item in results if item.service == section]
        assessed = sum(1 for item in checks if item.status in (PASS, FAIL, WARNING))
        unevaluated = [item for item in checks if item.status in (NOT_ASSESSED, ERROR)]
        applicable = assessed + len(unevaluated)
        if applicable == 0:
            status = "NOT_ASSESSED"
        elif not unevaluated:
            status = "ASSESSED"
        elif assessed == 0:
            status = "ERROR" if all(item.status == ERROR for item in unevaluated) else "NOT_ASSESSED"
        else:
            status = "PARTIAL"
        reasons: dict[str, int] = {}
        for item in unevaluated:
            text = item.observation.replace("Evidence unavailable: ", "").rstrip(".")
            reasons[text] = reasons.get(text, 0) + 1
        reason_text = [f"{text} ({count} check{'s' if count != 1 else ''})" for text, count in reasons.items()]
        if applicable == 0 and checks:
            reason_text.append("Every control in this section is not applicable to this host, profile or scope")
        missing = sorted({engine.permissions.get(item.check_id) or "" for item in unevaluated} - {""})
        affected_collectors = sorted(
            {
                collector
                for item in unevaluated
                for collector in engine.collectors_used.get(item.check_id, set())
                if collector in collectors and collectors[collector].status != "SUCCESS"
            }
        )
        areas.append(
            CoverageArea(
                area=section.lower().replace(" ", "-"),
                name=section,
                status=status,
                coverage_percent=round(100 * assessed / applicable, 1) if applicable else 0.0,
                reasons=reason_text,
                required_permissions=["root"],
                detected_permissions=["root"] if is_root else [],
                missing_permissions=missing if not is_root else [],
                affected_collectors=affected_collectors,
                affected_checks=[item.check_id for item in unevaluated],
            )
        )
    return areas


def build_document(
    engine: Engine,
    results: list[CheckResult],
    *,
    host: HostInfo,
    execution: ExecutionContext,
    client_name: str | None,
    started_at: Any,
    definition_file: str,
    definition_sha256: str,
) -> AssessmentDocument:
    benchmark = engine.benchmark
    frameworks = [FrameworkSelection(f"cis-{benchmark['id']}-{benchmark['version']}", benchmark["name"], benchmark["version"])]
    present = {mapping.framework for result in results for mapping in result.benchmark}
    for framework, (identifier, name, version) in FRAMEWORK_SELECTIONS.items():
        if framework in present:
            frameworks.append(FrameworkSelection(identifier, name, version))
    order = {result.check_id: index for index, result in enumerate(results)}
    findings = sorted(
        (item for item in results if item.status in (FAIL, WARNING)),
        key=lambda item: (SEVERITY_RANK.get(item.severity, 99), order[item.check_id]),
    )
    scope = []
    for result in results:
        if result.status != NOT_APPLICABLE and result.service not in scope:
            scope.append(result.service)
    manual = engine.definition.get("manual_recommendations", [])
    return AssessmentDocument(
        assessment=AssessmentMetadata(
            tool=TOOL_NAME,
            tool_version=__version__,
            client_name=client_name,
            started_at=started_at,
            completed_at=utc_now(),
            scope=scope,
            frameworks=frameworks,
            dry_run=False,
        ),
        host=host,
        execution=execution,
        coverage=build_coverage(engine, results),
        collectors=engine.system.collectors(),
        checks=results,
        findings=findings,
        summary=AssessmentSummary.from_results(results),
        benchmark_results={
            frameworks[0].id: {
                "version": benchmark["version"],
                "mapping_status": f"implemented_{benchmark['automated_control_count']}_automated_control_pack",
                "profile": engine.profile,
                "definition_file": definition_file,
                "definition_sha256": definition_sha256,
                "automated_controls": benchmark["automated_control_count"],
                "manual_recommendations_not_automated": [f"{item['cis_id']} {item['title']}" for item in manual],
                "manual_recommendations_included": engine.include_manual,
            }
        },
    )


def console_progress(index: int, total: int, control_id: str) -> None:
    if sys.stderr.isatty():
        sys.stderr.write(f"\r[+] Evaluating {index}/{total} {control_id:<16}")
        if index == total:
            sys.stderr.write("\n")
        sys.stderr.flush()
