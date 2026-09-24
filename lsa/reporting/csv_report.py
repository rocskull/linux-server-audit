from __future__ import annotations

import csv
from pathlib import Path

from lsa.model import AssessmentDocument
from lsa.reporting.common import atomic_report_path, neutralise_formula, validate_report_filename

HEADERS = [
    "Finding ID",
    "Title",
    "Severity",
    "Status",
    "Service",
    "Category",
    "CIS Framework",
    "CIS Version",
    "CIS Control",
    "Observation",
    "Recommendation",
    "Resource",
    "Timestamp",
]


def write_csv_report(document: AssessmentDocument, output_directory: Path, filename: str = "findings.csv") -> Path:
    validate_report_filename(filename, ".csv")
    destination = output_directory.resolve() / filename
    with atomic_report_path(destination) as temporary:
        with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=HEADERS, extrasaction="ignore")
            writer.writeheader()
            for finding in document.findings:
                cis = finding.cis_mapping()
                for resource in finding.affected_resources or [""]:
                    row = {
                        "Finding ID": finding.check_id,
                        "Title": finding.title,
                        "Severity": finding.severity,
                        "Status": finding.status,
                        "Service": finding.service,
                        "Category": finding.category,
                        "CIS Framework": cis.benchmark if cis else "",
                        "CIS Version": cis.version if cis else "",
                        "CIS Control": cis.control if cis else "",
                        "Observation": finding.observation,
                        "Recommendation": finding.recommendation,
                        "Resource": resource,
                        "Timestamp": finding.timestamp.isoformat(),
                    }
                    writer.writerow({key: neutralise_formula(str(value)) for key, value in row.items()})
    return destination
