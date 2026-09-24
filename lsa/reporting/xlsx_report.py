"""Eight-sheet assessment workbook in the m365-assessor layout.

Sheets: Executive Summary, Finding Register, Good Controls, Not Assessed,
Permission Coverage, Framework Mapping, Raw Evidence and Methodology.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lsa.model import SEVERITIES, AssessmentDocument, CheckResult
from lsa.reporting.common import all_mappings_text, atomic_report_path, collection_method, frameworks_text, platform_label, report_title, validate_report_filename
from lsa.reporting.xlsx_writer import Style, Workbook, Worksheet

NAVY = "17324D"
BLUE = "0B6E99"
WHITE = "FFFFFF"
SEVERITY_COLORS = {
    "Critical": "8B0000",
    "High": "C00000",
    "Medium": "F4B183",
    "Low": "FFD966",
    "Informational": "9DC3E6",
}
TITLE = Style(bold=True, color=WHITE, size=16, fill=NAVY, vertical="center")
HEADER = Style(bold=True, color=WHITE, fill=BLUE, wrap=True, vertical="top")
BODY = Style(wrap=True, vertical="top")
LINK = Style(wrap=True, vertical="top", underline=True, color="0563C1")
TIMESTAMP = Style(wrap=True, vertical="top", number_format="yyyy-mm-dd hh:mm")
PERCENT_BODY = Style(wrap=True, vertical="top", number_format="0.0%")
LABEL = Style(bold=True, color=NAVY)
PERCENT = Style(number_format="0.0%")
DATE = Style(number_format="yyyy-mm-dd hh:mm")

CHECK_HEADERS = [
    "Finding ID",
    "Title",
    "Severity",
    "Status",
    "Service",
    "Category",
    "Framework mapping",
    "Observation",
    "Business impact",
    "Recommendation",
    "Remediation",
    "Affected resources",
    "Reference",
    "Timestamp",
]


def _title(sheet: Worksheet, text: str, end_column: int) -> None:
    sheet.merge(1, 1, 1, end_column)
    sheet.set(1, 1, text, TITLE)
    for column in range(2, end_column + 1):
        sheet.set(1, column, None, TITLE)
    sheet.height(1, 28)


def _table(sheet: Worksheet, headers: list[str], rows: list[list[Any]], name: str, start_row: int = 3, styles: dict[int, Style] | None = None) -> None:
    for column, header in enumerate(headers, 1):
        sheet.set(start_row, column, header, HEADER)
    safe_rows = rows or [["" for _ in headers]]
    for row_index, data_row in enumerate(safe_rows, start_row + 1):
        for column, value in enumerate(data_row, 1):
            style = (styles or {}).get(column, BODY)
            sheet.set(row_index, column, value, style)
    end_row = start_row + len(safe_rows)
    sheet.add_table(name, start_row, 1, end_row, len(headers))
    sheet.freeze = f"A{start_row + 1}"
    for column, header in enumerate(headers, 1):
        width = min(max(len(header) + 2, 13), 45)
        for row_index in range(start_row + 1, end_row + 1):
            value = sheet.value(row_index, column)
            if value is not None:
                width = min(max(width, len(str(value)) + 2), 45)
        sheet.width(column, width)


def _check_rows(checks: list[CheckResult]) -> list[list[Any]]:
    return [
        [
            item.check_id,
            item.title,
            item.severity,
            item.status,
            item.service,
            item.category,
            all_mappings_text(item),
            item.observation,
            item.business_impact,
            item.recommendation,
            item.remediation,
            ", ".join(item.affected_resources),
            item.references[0] if item.references else "",
            item.timestamp,
        ]
        for item in checks
    ]


def _check_sheet(workbook: Workbook, title: str, heading: str, table_name: str, checks: list[CheckResult]) -> None:
    sheet = workbook.add_sheet(title)
    _title(sheet, heading, len(CHECK_HEADERS))
    _table(sheet, CHECK_HEADERS, _check_rows(checks), table_name, styles={14: TIMESTAMP})
    if checks:
        end = len(checks) + 3
        for severity, color in SEVERITY_COLORS.items():
            sheet.add_conditional_fill(f"C4:C{end}", f'$C4="{severity}"', color)
        for row in range(4, end + 1):
            reference = sheet.value(row, 13)
            if reference:
                sheet.restyle(row, 13, LINK)
                sheet.add_hyperlink(row, 13, str(reference))


def write_xlsx_report(document: AssessmentDocument, output_directory: Path, filename: str = "assessment.xlsx") -> Path:
    validate_report_filename(filename, ".xlsx")
    destination = output_directory.resolve() / filename
    workbook = Workbook()

    summary = workbook.add_sheet("Executive Summary")
    _title(summary, report_title(document), 8)
    completed = document.assessment.completed_at or document.assessment.started_at
    host = document.host
    rows: list[tuple[str, Any, Style | None]] = [
        ("Client", document.assessment.client_name or "Not specified", None),
        ("Host", host.fqdn or host.hostname, None),
        ("Operating system", platform_label(document), None),
        ("Assessment date", completed, DATE),
        ("Frameworks", f"{frameworks_text(document)} ({host.profile})", None),
        ("Scope", ", ".join(document.assessment.scope), None),
        ("Total checks", document.summary.total_checks, None),
        ("Passed", document.summary.pass_count, None),
        ("Failed", document.summary.fail_count, None),
        ("Warnings", document.summary.warning_count, None),
        ("Not assessed", document.summary.not_assessed_count, None),
        ("Errors", document.summary.error_count, None),
        ("Pass percentage", document.summary.pass_percentage / 100, PERCENT),
        ("Coverage percentage", document.summary.coverage_percentage / 100, PERCENT),
    ]
    for row, (label, value, style) in enumerate(rows, 3):
        summary.set(row, 1, label, LABEL)
        summary.set(row, 2, value, style)
    summary.width(1, 24)
    summary.width(2, 65)
    summary.freeze = "A3"
    summary.append(["Severity", "Findings"])
    for severity in SEVERITIES:
        summary.append([severity, document.summary.severity_distribution.get(severity, 0)])
    summary.add_bar_chart((3, 4), "Finding severity", "Findings", series_title=(17, 2), categories=(1, 18, 22), values=(2, 18, 22))

    _check_sheet(workbook, "Finding Register", "Finding Register", "FindingRegister", document.findings)
    _check_sheet(workbook, "Good Controls", "Good Controls", "GoodControls", [item for item in document.checks if item.status == "PASS"])
    _check_sheet(
        workbook,
        "Not Assessed",
        "Not Assessed and Errors",
        "NotAssessed",
        [item for item in document.checks if item.status in ("NOT_ASSESSED", "ERROR")],
    )

    coverage = workbook.add_sheet("Permission Coverage")
    coverage_headers = ["Area", "Status", "Coverage", "Missing permissions", "Affected collectors", "Affected checks", "Explanation"]
    _title(coverage, "Coverage and Permission Report", len(coverage_headers))
    _table(
        coverage,
        coverage_headers,
        [
            [
                area.name,
                area.status,
                area.coverage_percent / 100,
                ", ".join(area.missing_permissions),
                ", ".join(area.affected_collectors),
                ", ".join(area.affected_checks),
                "; ".join(area.reasons),
            ]
            for area in document.coverage
        ],
        "PermissionCoverage",
        styles={3: PERCENT_BODY},
    )

    mapping = workbook.add_sheet("Framework Mapping")
    mapping_headers = ["Framework", "Benchmark", "Version", "Control", "Check ID", "Title", "Status", "Severity"]
    _title(mapping, "Framework Mapping", len(mapping_headers))
    _table(
        mapping,
        mapping_headers,
        [
            [m.framework, m.benchmark, m.version, m.control, check.check_id, check.title, check.status, check.severity]
            for check in document.checks
            for m in check.benchmark
        ],
        "FrameworkMapping",
    )

    evidence = workbook.add_sheet("Raw Evidence")
    evidence_headers = ["Collector ID", "Name", "Area", "Status", "Objects", "Evidence JSON"]
    _title(evidence, "Raw Evidence", len(evidence_headers))
    _table(
        evidence,
        evidence_headers,
        [
            [
                item.collector_id,
                item.name,
                item.area,
                item.status,
                item.objects_collected,
                json.dumps(item.data, ensure_ascii=False, default=str)[:32700],
            ]
            for item in document.collectors.values()
        ],
        "RawEvidence",
    )

    methodology = workbook.add_sheet("Methodology")
    _title(methodology, "Methodology and Limitations", 4)
    _table(
        methodology,
        ["Topic", "Method"],
        [
            ["Principle", "Read-only collection; the assessment never changes system configuration."],
            ["Collection", collection_method(document)],
            ["Evaluation", "Deterministic, versioned JSON benchmark definition evaluated against normalized evidence."],
            ["Permission gaps", "Unavailable evidence is NOT_ASSESSED and is never treated as FAIL."],
            ["Applicability", "Controls outside the selected CIS profile or not relevant to the host are NOT_APPLICABLE."],
            ["Scoring", "Pass percentage excludes NOT_ASSESSED, NOT_APPLICABLE, and ERROR controls."],
            ["Sensitive data", "Password hashes, private keys, and secret file contents are never read into reports."],
        ],
        "Methodology",
    )

    with atomic_report_path(destination) as temporary:
        workbook.save(str(temporary))
    return destination
