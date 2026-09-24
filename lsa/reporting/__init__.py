"""Report generation in the m365-assessor file layout.

``<stem>.json``, ``<stem>.html``, ``<stem>-findings.csv``, ``<stem>.xlsx``
(eight-sheet internal workbook) and ``<stem>-consolidated.xlsx``
(four-sheet client-facing workbook).
"""

from __future__ import annotations

from pathlib import Path

from lsa.model import AssessmentDocument
from lsa.reporting.csv_report import write_csv_report
from lsa.reporting.html_report import write_html_report
from lsa.reporting.json_report import write_json_report
from lsa.reporting.xlsx_consolidated import write_consolidated_xlsx_report
from lsa.reporting.xlsx_report import write_xlsx_report

SUPPORTED_FORMATS = {"json", "html", "csv", "xlsx", "consolidated"}


def generate_reports(
    document: AssessmentDocument,
    output_directory: Path,
    formats: set[str] | None = None,
    filename_stem: str | None = None,
) -> dict[str, Path]:
    selected = formats or SUPPORTED_FORMATS
    unsupported = selected - SUPPORTED_FORMATS
    if unsupported:
        raise ValueError(f"Unsupported report format(s): {', '.join(sorted(unsupported))}")
    if filename_stem is not None and (Path(filename_stem).name != filename_stem or not filename_stem.strip()):
        raise ValueError("Report filename stem must be a non-empty simple filename")
    output_directory.mkdir(parents=True, exist_ok=True)
    filenames = {
        "json": f"{filename_stem}.json" if filename_stem else "assessment.json",
        "html": f"{filename_stem}.html" if filename_stem else "assessment.html",
        "csv": f"{filename_stem}-findings.csv" if filename_stem else "findings.csv",
        "xlsx": f"{filename_stem}.xlsx" if filename_stem else "assessment.xlsx",
        "consolidated": f"{filename_stem}-consolidated.xlsx" if filename_stem else "assessment-consolidated.xlsx",
    }
    writers = (
        ("json", write_json_report),
        ("html", write_html_report),
        ("csv", write_csv_report),
        ("xlsx", write_xlsx_report),
        ("consolidated", write_consolidated_xlsx_report),
    )
    return {name: writer(document, output_directory, filenames[name]) for name, writer in writers if name in selected}
