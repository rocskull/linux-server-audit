"""Report files in the m365-assessor layout, produced directly and through the CLI."""

from __future__ import annotations

import csv
import io
import json
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree

from lsa import cli
from lsa.model import AssessmentDocument
from lsa.reporting import generate_reports
from lsa.reporting.csv_report import HEADERS
from tests.support import TempRoot, assess, esxi_system
from tests.test_debian import build_debian

MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def workbook_sheets(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith(".xml") or name.endswith(".rels"):
                ElementTree.fromstring(archive.read(name))  # every part must be well-formed XML
        workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
    return [sheet.get("name") for sheet in workbook.iter(f"{MAIN}sheet")]


class ReportTests(unittest.TestCase):
    def check_reports(self, document: AssessmentDocument, directory: Path, title: str) -> None:
        paths = generate_reports(document, directory, None, "client-host-assessment-20260924-101500")
        self.assertEqual(set(paths), {"json", "html", "csv", "xlsx", "consolidated"})

        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        for key in ("assessment", "host", "execution", "coverage", "collectors", "checks", "findings", "summary", "benchmark_results"):
            self.assertIn(key, data)
        restored = AssessmentDocument.from_dict(data)
        self.assertEqual(restored.summary, document.summary)
        self.assertEqual(len(restored.checks), len(document.checks))

        html = paths["html"].read_text(encoding="utf-8")
        self.assertIn(f"<title>{title}", html)
        for item in document.findings:
            self.assertIn(item.check_id, html)

        rows = list(csv.reader(io.StringIO(paths["csv"].read_text(encoding="utf-8-sig"))))
        self.assertEqual(rows[0], HEADERS)
        expected_rows = sum(max(1, len(item.affected_resources)) for item in document.findings)
        self.assertEqual(len(rows) - 1, expected_rows)

        self.assertEqual(
            workbook_sheets(paths["xlsx"]),
            ["Executive Summary", "Finding Register", "Good Controls", "Not Assessed", "Permission Coverage", "Framework Mapping", "Raw Evidence", "Methodology"],
        )
        self.assertEqual(len(workbook_sheets(paths["consolidated"])), 4)

    def test_esxi_reports(self):
        with TempRoot() as root:
            document, _, _ = assess(esxi_system(root / "host"))
            self.check_reports(document, root / "out", "VMware ESXi Security Assessment")

    def test_debian_reports(self):
        with TempRoot() as root:
            document, _, _ = assess(build_debian(root / "host"))
            self.check_reports(document, root / "out", "Linux Server Security Assessment")

    def test_cli_end_to_end_on_esxi(self):
        with TempRoot() as root:
            system = esxi_system(root / "host")
            with mock.patch.object(cli, "System", return_value=system), mock.patch.object(cli, "_interactive", return_value=False):
                code = cli.main(["--client-name", "Test Client", "--output", str(root / "out"), "--yes"])
            self.assertEqual(code, 0)
            folders = list((root / "out").iterdir())
            self.assertEqual(len(folders), 1)
            folder = folders[0]
            self.assertRegex(folder.name, r"^Test-Client-localhost-esxi-assessment-\d{8}-\d{6}$")
            names = sorted(path.name for path in folder.iterdir())
            stem = folder.name
            self.assertEqual(
                names,
                sorted([f"{stem}.json", f"{stem}.html", f"{stem}-findings.csv", f"{stem}.xlsx", f"{stem}-consolidated.xlsx", "linux-security-audit.log"]),
            )
            cli._configure_logging(None)  # release the log file before the folder is removed
            log = (folder / "linux-security-audit.log").read_text(encoding="utf-8")
            self.assertIn("Selected CIS VMware ESXi 8.0 Benchmark", log)

    def test_report_from_regenerates_all_formats(self):
        with TempRoot() as root:
            document, _, _ = assess(esxi_system(root / "host"))
            paths = generate_reports(document, root / "first", {"json"}, "esx01-assessment")
            code = cli.main(["--report-from", str(paths["json"]), "--output", str(root / "second")])
            self.assertEqual(code, 0)
            self.assertEqual(len(list((root / "second").iterdir())), 5)
