"""Consolidated four-sheet workbook in the m365-assessor (Monkey365) layout.

Executive Summary, Finding Register, Good Controls and Raw Data use the same
fills, fonts, row heights, column widths, priority bands and Raw Data columns
as the m365-assessor consolidated workbook, so Linux host reports can sit
beside Microsoft 365 reports and their Raw Data sheets can be stacked.

Raw Data keeps its Monkey365 column names: ``tenantId`` carries the host's
machine ID, ``tenantName`` the host name and ``provider`` is ``Linux``;
``resourceLocation`` holds the host name so multi-host consolidation stays
unambiguous.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from lsa.model import PASS, AssessmentDocument, CheckResult
from lsa.reporting.common import atomic_report_path, host_label, mapping_text, platform_label, report_title, validate_report_filename
from lsa.reporting.xlsx_writer import Style, Workbook, Worksheet

MAGENTA = "FFEC008C"
PALE = "FFFCE4F1"
WHITE = "FFFFFFFF"
BLACK = "FF000000"
BLUE = "FF0070C0"
GREY = "FF7F7F7F"

SEVERITY_FILL = {"Critical": "FFC00000", "High": "FFFF0000", "Medium": "FFFFC000", "Low": "FF00B050", "Informational": GREY}
SEVERITY_ID = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
PRIORITY = {"Critical": "P1 - High", "High": "P1 - High", "Medium": "P2 - Medium", "Low": "P3 - Low", "Informational": "P3 - Low"}
NOT_ASSESSED_PRIORITY = "P4 - Not Assessed"
NOT_ASSESSED_LABEL = "Not Assessed"
UNEVALUATED = {"NOT_ASSESSED", "ERROR"}

HEADER_HEIGHT = 29.1
DATA_HEIGHT = 54.9

FINDING_HEADERS = [
    "Priority", "Severity", "Service / Domain", "Finding ID", "Finding Title", "CIS Mapping", "Observation Count",
    "Resource Type", "Resource / Location", "Observed Status", "Recommended Management Action", "Remediation Guidance", "Reference",
]
FINDING_WIDTHS = [13, 14.5546875, 28.44140625, 34, 45, 32, 13, 26, 28.44140625, 45, 62.88671875, 62.88671875, 45]
GOOD_HEADERS = ["Severity", "Service / Domain", "Finding ID", "Finding Title", "CIS Mapping", "Resource / Location", "Status"]
GOOD_WIDTHS = [14.5546875, 28.44140625, 38, 50, 32, 28.44140625, 50]
RAW_HEADERS = [
    "timestamp", "tenantId", "tenantName", "uniqueId", "provider", "findingId", "findingTitle", "findingType", "findingTags",
    "serviceName", "severityId", "severity", "findingDescription", "findingRationale", "findingRemediation", "findingReferenceUrl",
    "resourceLocation", "status", "resourceType", "resourceId", "resourceName", "resourceGroup", "resourceTags", "compliance", "notes",
]
RAW_WIDTHS = {"A": 20, "D": 34, "E": 20, "F": 34, "H": 20, "M": 62.88671875, "Q": 20, "R": 34, "S": 20, "T": 34, "U": 20, "X": 34, "Y": 20}

WRAP_CENTER = Style(wrap=True, vertical="center")


def _banner(sheet: Worksheet, row: int, columns: int, text: str, size: float, height: float) -> None:
    sheet.merge(row, 1, row, columns)
    style = Style(bold=True, color=WHITE, size=size, fill=MAGENTA, wrap=True, vertical="center")
    for column in range(1, columns + 1):
        sheet.set(row, column, text if column == 1 else None, style)
    sheet.height(row, height)


def _label(sheet: Worksheet, row: int, column: int, text: str) -> None:
    sheet.set(row, column, text, Style(bold=True, color=BLACK, size=11, fill=PALE, wrap=True, vertical="center"))


def _value(sheet: Worksheet, row: int, column: int, value: Any) -> None:
    sheet.set(row, column, value, WRAP_CENTER)


def _metric(sheet: Worksheet, row: int, name: str, value: Any, fill: str | None = None) -> None:
    sheet.set(row, 1, name, Style(bold=True, size=11, wrap=True, vertical="center"))
    if fill:
        sheet.set(row, 2, value, Style(bold=True, color=WHITE, size=11, fill=fill, vertical="center"))
    else:
        sheet.set(row, 2, value, Style(vertical="center"))
    sheet.height(row, 25.95)


def _header_row(sheet: Worksheet, headers: list[str]) -> None:
    style = Style(bold=True, color=WHITE, size=11, fill=MAGENTA, wrap=True, vertical="center")
    for column, text in enumerate(headers, 1):
        sheet.set(1, column, text, style)
    sheet.height(1, HEADER_HEIGHT)
    sheet.freeze = "A2"


def _severity_fill(label: str) -> str | None:
    if label == "Good":
        return BLUE
    if label == NOT_ASSESSED_LABEL:
        return GREY
    return SEVERITY_FILL.get(label)


def _write_rows(sheet: Worksheet, rows: list[list[Any]], severity_column: int | None = None) -> None:
    for index, values in enumerate(rows, 2):
        for column, value in enumerate(values, 1):
            style = WRAP_CENTER
            if column == severity_column:
                fill = _severity_fill(str(value))
                if fill:
                    style = Style(bold=True, color=WHITE, size=11, fill=fill, vertical="center")
            sheet.set(index, column, value, style)
        sheet.height(index, DATA_HEIGHT)


def _widths(sheet: Worksheet, widths: list[float] | dict[str, float]) -> None:
    if isinstance(widths, dict):
        for letter, width in widths.items():
            sheet.width(ord(letter) - 64, width)
    else:
        for index, width in enumerate(widths, 1):
            sheet.width(index, width)


def _domain(check: CheckResult) -> str:
    return f"{check.service} / {check.category}" if check.category else check.service


def _severity_label(check: CheckResult) -> str:
    return NOT_ASSESSED_LABEL if check.status in UNEVALUATED else check.severity


def _priority(check: CheckResult) -> str:
    return NOT_ASSESSED_PRIORITY if check.status in UNEVALUATED else PRIORITY[check.severity]


def _resources(check: CheckResult) -> list[str]:
    return [str(item) for item in check.affected_resources] or [""]


def _access(document: AssessmentDocument) -> str:
    execution = document.execution
    identity = execution.identity or "unknown user"
    via = f" via sudo from {execution.sudo_user}" if execution.sudo_user else ""
    privilege = "root privileges" if execution.is_root else "without root privileges (limited evidence)"
    return f"{identity}{via} ({execution.method} execution, {privilege})"


def _posture(failure_percentage: float) -> str:
    if failure_percentage >= 50:
        return "Needs Improvement"
    if failure_percentage >= 25:
        return "Moderate"
    return "Strong"


def _priorities(document: AssessmentDocument) -> str:
    weighted = Counter()
    for item in document.findings:
        weighted[item.category] += SEVERITY_ID.get(item.severity, 1)
    top = [name for name, _ in weighted.most_common(3)]
    if not top:
        return "No failing controls were identified; maintain the current configuration baseline."
    if len(top) == 1:
        return f"Prioritize {top[0]}."
    return f"Prioritize {', '.join(top[:-1])}, and {top[-1]}."


def _executive_summary(sheet: Worksheet, document: AssessmentDocument) -> None:
    summary = document.summary
    completed = document.assessment.completed_at or document.assessment.started_at
    frameworks = ", ".join(f"{item.name} {item.version}" for item in document.assessment.frameworks)
    host = document.host

    _banner(sheet, 1, 8, report_title(document), 20, 26.1)
    _banner(sheet, 2, 8, host_label(document), 13, 22.05)

    _label(sheet, 4, 1, "Assessment date")
    _value(sheet, 4, 2, completed.strftime("%d %B %Y"))
    _label(sheet, 4, 7, "Benchmark")
    _value(sheet, 4, 8, f"{frameworks or 'Not specified'} ({host.profile})")
    sheet.height(4, 34.05)

    _label(sheet, 5, 1, "Assessment type")
    kind = "VMware ESXi host" if (host.os_id or "") == "esxi" else "Linux server"
    _value(sheet, 5, 2, f"{kind} configuration security assessment ({platform_label(document)})")
    sheet.height(5, 48.0)

    _label(sheet, 6, 1, "Access")
    _value(sheet, 6, 2, _access(document))
    sheet.height(6, 25.95)

    _label(sheet, 7, 1, "Scope")
    _value(sheet, 7, 2, ", ".join(sorted({item.name for item in document.coverage})))
    sheet.height(7, 48.0)

    _banner(sheet, 9, 2, "Key Metrics", 14, 29.1)
    sheet.merge(9, 4, 9, 8)
    posture_style = Style(bold=True, color=WHITE, size=14, fill=MAGENTA, wrap=True, vertical="center")
    for column in range(4, 9):
        sheet.set(9, column, "Assessment posture" if column == 4 else None, posture_style)

    evaluated = summary.pass_count + summary.fail_count + summary.warning_count
    non_good = summary.fail_count + summary.warning_count
    unevaluated = summary.not_assessed_count + summary.error_count
    severity = summary.severity_distribution
    good_rate = (summary.pass_count / evaluated) if evaluated else 0.0

    _metric(sheet, 10, "Raw observations", summary.total_checks)
    _metric(sheet, 11, "Unique controls/checks", summary.total_checks)
    _metric(sheet, 12, "Reported Good", summary.pass_count, BLUE)
    _metric(sheet, 13, "Non-Good unique checks", non_good)
    _metric(sheet, 14, "Not assessed", unevaluated, GREY)
    _metric(sheet, 15, "High unique checks", severity.get("High", 0) + severity.get("Critical", 0), SEVERITY_FILL["High"])
    _metric(sheet, 16, "Medium unique checks", severity.get("Medium", 0), SEVERITY_FILL["Medium"])
    _metric(sheet, 17, "Low unique checks", severity.get("Low", 0), SEVERITY_FILL["Low"])
    _metric(sheet, 18, "Reported Good rate", round(good_rate, 4))

    narrative = [
        (10, _posture(summary.failure_percentage), True, 16, MAGENTA),
        (11, f"{summary.failure_percentage:.1f}% of evaluated checks were reported as non-Good.", False, 11, BLACK),
        (12, _priorities(document), False, 11, BLACK),
        (
            13,
            f"The report contains {summary.pass_count} Good checks, {non_good} non-Good checks, and {unevaluated} that could not be evaluated.",
            False,
            11,
            BLACK,
        ),
    ]
    for row, text, bold, size, color in narrative:
        sheet.merge(row, 4, row, 8)
        sheet.set(row, 4, text, Style(bold=bold, size=size, color=color, wrap=True, vertical="center"))
        sheet.height(row, max(sheet.heights.get(row, 0), 30.0))

    _widths(sheet, [26, 34, 3, 20, 24, 3, 16, 40])


def _finding_rows(checks: list[CheckResult]) -> list[list[Any]]:
    rows = []
    for check in checks:
        resources = _resources(check)
        rows.append(
            [
                _priority(check),
                _severity_label(check),
                _domain(check),
                check.check_id,
                check.title,
                mapping_text(check),
                len(check.affected_resources) or 1,
                check.category,
                "; ".join(item for item in resources if item) or check.service,
                check.observation,
                check.recommendation,
                check.remediation,
                check.references[0] if check.references else "",
            ]
        )
    return rows


def _raw_rows(document: AssessmentDocument) -> list[list[Any]]:
    host = document.host
    timestamp = (document.assessment.completed_at or document.assessment.started_at).isoformat()
    host_id = host.machine_id or host.hostname
    rows = []
    for check in document.checks:
        for resource in _resources(check):
            rows.append(
                [
                    timestamp,
                    host_id,
                    host_label(document),
                    f"{document.assessment.id}-{check.check_id}",
                    "Linux",
                    check.check_id,
                    check.title,
                    check.status,
                    check.category,
                    check.service,
                    0 if check.status == PASS else SEVERITY_ID.get(check.severity, 0),
                    "Good" if check.status == PASS else _severity_label(check).casefold(),
                    check.description,
                    check.rationale,
                    check.remediation,
                    check.references[0] if check.references else "",
                    host_label(document),
                    check.observation,
                    check.category,
                    resource or check.check_id,
                    resource or check.title,
                    "",
                    "",
                    mapping_text(check),
                    "",
                ]
            )
    return rows


def write_consolidated_xlsx_report(document: AssessmentDocument, output_directory: Path, filename: str = "assessment-consolidated.xlsx") -> Path:
    validate_report_filename(filename, ".xlsx")
    destination = output_directory.resolve() / filename
    workbook = Workbook()
    _executive_summary(workbook.add_sheet("Executive Summary"), document)

    # Failures first, then everything the run could not evaluate, so the
    # actionable rows lead without the unevaluated ones disappearing.
    ordered = sorted(
        (item for item in document.checks if item.status not in (PASS, "NOT_APPLICABLE")),
        key=lambda item: (item.status in UNEVALUATED, -SEVERITY_ID.get(item.severity, 0), item.check_id),
    )
    finding_sheet = workbook.add_sheet("Finding Register")
    _header_row(finding_sheet, FINDING_HEADERS)
    _write_rows(finding_sheet, _finding_rows(ordered), severity_column=2)
    _widths(finding_sheet, FINDING_WIDTHS)

    good = [item for item in document.checks if item.status == PASS]
    good_sheet = workbook.add_sheet("Good Controls")
    _header_row(good_sheet, GOOD_HEADERS)
    _write_rows(
        good_sheet,
        [["Good", _domain(item), item.check_id, item.title, mapping_text(item), item.service, item.observation] for item in good],
        severity_column=1,
    )
    _widths(good_sheet, GOOD_WIDTHS)

    raw_sheet = workbook.add_sheet("Raw Data")
    _header_row(raw_sheet, RAW_HEADERS)
    _write_rows(raw_sheet, _raw_rows(document))
    _widths(raw_sheet, RAW_WIDTHS)

    with atomic_report_path(destination) as temporary:
        workbook.save(str(temporary))
    return destination
