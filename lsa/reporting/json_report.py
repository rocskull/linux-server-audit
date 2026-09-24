from __future__ import annotations

import json
from pathlib import Path

from lsa.model import AssessmentDocument
from lsa.reporting.common import atomic_report_path, validate_report_filename


def write_json_report(document: AssessmentDocument, output_directory: Path, filename: str = "assessment.json") -> Path:
    validate_report_filename(filename, ".json")
    destination = output_directory.resolve() / filename
    with atomic_report_path(destination) as temporary:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(document.to_dict(), stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    return destination
