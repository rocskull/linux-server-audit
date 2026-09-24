"""Build a versioned benchmark definition from a CIS PDF and a check specification.

Maintainer utility, not part of the runtime assessment path. The CIS document
supplies control identity: recommendation numbers, titles, profile
applicability, Automated/Manual status and the CIS Controls v8 and NIST SP
800-53 mappings. The specification modules under ``specs/`` supply the
provider and parameters for every automated recommendation, a severity and
independently written guidance. The build fails when an Automated
recommendation has no specification, when a specification has no matching
Automated recommendation, or when a Manual recommendation has no guidance
(specifications may set ``AUTO_MANUAL_GUIDANCE`` to generate a generic
review note for Manual recommendations instead).

The source document remains authoritative. Review the CIS terms of use before
redistributing derived benchmark content.

Usage:
    python tools/build_benchmark_definition.py --spec debian13 --pdf CIS_Debian_Linux_13_Benchmark_v1.1.0.pdf
    python tools/build_benchmark_definition.py --spec esxi8 --pdf CIS_VMware_ESXi_8.0_Benchmark_v1.4.0_PDF.pdf
    python tools/build_benchmark_definition.py --spec esxi7 --pdf "CIS VMWare ESXi 7 Benchmark V1.6.0 PDF.pdf"
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(PROJECT_DIR))

SPEC_MODULES = {
    "debian13": ["specs.debian13", "specs.debian13_network_access", "specs.debian13_logging_maintenance", "specs.debian13_proxmox"],
    "esxi8": ["specs.esxi8"],
    "esxi7": ["specs.esxi7"],
}
FIELDS = (
    "Profile Applicability",
    "Description",
    "Rationale",
    "Impact",
    "Audit",
    "Remediation",
    "Default Value",
    "References",
    "CIS Controls",
    "Additional Information",
    "MITRE ATT&CK Mappings",
)
# A recommendation header is its number, a title of up to four lines and the
# assessment status, directly followed by the profile block. Continuation lines
# never start with another number, so section headings are not merged in.
HEADER = re.compile(
    r"(?m)^(?P<id>\d+(?:\.\d+)+) (?P<title>[^\n]+?(?:\n(?!Profile Applicability:|\d+(?:\.\d+)+ )[^\n]*?){0,3})\s*"
    r"\((?P<mode>Automated|Manual)\)\s*\nProfile Applicability:"
)
FIELD_RE = re.compile(r"(?m)^(%s):\s*" % "|".join(re.escape(item) for item in FIELDS))


def extract_text(pdf: Path) -> str:
    """Page text of the CIS PDF using PyMuPDF, falling back to pypdf."""
    try:
        import fitz  # type: ignore[import-not-found]

        with fitz.open(pdf) as document:
            return "\n".join(f"=== PDF PAGE {number} ===\n{page.get_text('text')}" for number, page in enumerate(document, 1))
    except ImportError:
        pass
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit("Install PyMuPDF or pypdf, or pass --text with pre-extracted text.") from exc
    reader = PdfReader(str(pdf))
    return "\n".join(f"=== PDF PAGE {number} ===\n{page.extract_text() or ''}" for number, page in enumerate(reader.pages, 1))


def clean(value: str) -> str:
    value = value.replace(" ", " ").replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", value).strip()


def clean_title(value: str) -> str:
    """Title without the '(L1) ' level prefix, stray brackets or a final full stop."""
    title = re.sub(r"^\(L\d\)\s*", "", clean(value))
    if title.startswith("(") and ")" not in title.split(" ")[0]:
        title = title[1:]
    return title.strip().rstrip(".").strip()


def profiles_for(block: str, benchmark_profiles: list[str]) -> list[str]:
    """Profiles named in a Profile Applicability block, in benchmark order.

    Linux benchmarks name 'Level 1 - Server'; ESXi benchmarks name
    'Level 1 (L1) - Corporate/Enterprise Environment (general use)', which may
    wrap across lines, so ESXi levels are matched by number.
    """
    found = set(re.findall(r"Level \d - (?:Server|Workstation)", block))
    for level in re.findall(r"Level (\d) \(L\d\)", block):
        found.update(name for name in benchmark_profiles if name.startswith(f"Level {level} (L{level})"))
    order = {name: index for index, name in enumerate(benchmark_profiles)}
    return sorted(found, key=lambda item: (order.get(item, len(order)), item))


def parse_recommendations(text: str, benchmark_profiles: list[str]) -> list[dict[str, Any]]:
    text = re.sub(r"\n=== PDF PAGE \d+ ===\n(?:Page \d+ ?\n)?(?:Internal Only - General ?\n)?", "\n", text)
    start = text.index("\nRecommendations \n1 ")
    end = text.find("\nAppendix: Summary Table", start + 10)
    body = text[start : end if end != -1 else len(text)]
    matches = list(HEADER.finditer(body))
    records = []
    for index, match in enumerate(matches):
        block = body[match.start() : matches[index + 1].start() if index + 1 < len(matches) else len(body)]
        record: dict[str, Any] = {"id": match.group("id"), "title": clean_title(match.group("title")), "automated": match.group("mode") == "Automated"}
        parts = list(FIELD_RE.finditer(block))
        for position, part in enumerate(parts):
            finish = parts[position + 1].start() if position + 1 < len(parts) else len(block)
            record[part.group(1)] = block[part.end() : finish]
        record["profiles"] = profiles_for(record.get("Profile Applicability", ""), benchmark_profiles)
        if not record["profiles"]:
            raise SystemExit(f"Recommendation {record['id']} names no profile known to the specification")
        record["cis_controls_v8"] = _controls_v8(record.get("CIS Controls", ""))
        record["nist_800_53"] = _nist(record.get("References", ""))
        records.append(record)
    return records


def _controls_v8(block: str) -> list[str]:
    match = re.search(r"(?s)\bv8\b(.*?)(?:\bv7\b|$)", block)
    if not match:
        return []
    found = [item for item in re.findall(r"(?m)^(\d{1,2}\.\d{1,2}) [A-Z]", match.group(1)) if item != "0.0"]
    return list(dict.fromkeys(found))


def _nist(block: str) -> list[str]:
    found = []
    for line in block.splitlines():
        if "NIST SP 800-53" not in line or "800-53A" in line:
            continue
        tail = re.split(r":+", line, maxsplit=1)[-1]
        found.extend(re.findall(r"\b([A-Z]{2}-\d+)", tail))
    return list(dict.fromkeys(found))


def load_spec(name: str) -> Any:
    if name not in SPEC_MODULES:
        raise SystemExit(f"Unknown specification '{name}'. Available: {', '.join(SPEC_MODULES)}")
    modules = [importlib.import_module(module) for module in SPEC_MODULES[name]]
    return modules[0]


def section_for(spec: Any, cis_id: str) -> tuple[str, str, str]:
    for prefix, section, category, code in sorted(spec.SECTIONS, key=lambda item: -len(item[0])):
        if cis_id == prefix or cis_id.startswith(prefix + "."):
            return section, category, code
    raise SystemExit(f"No section mapping covers recommendation {cis_id}")


def generic_manual(spec: Any, record: dict[str, Any]) -> dict[str, Any]:
    """Review note for a Manual recommendation the specification does not describe."""
    title = record["title"]
    return {
        "guidance": (
            f"Manual review required: {title[0].lower() + title[1:]}. This recommendation depends on evidence the tool "
            "cannot verify reliably from the host itself (management server, hardware, guest or organisational records); "
            "confirm it with the responsible administrator and record the result."
        ),
        "remediation": (
            f"Where the review finds a gap, apply the remediation for recommendation {record['id']} of the "
            f"{spec.BENCHMARK['name']} v{spec.BENCHMARK['version']} after assessing operational impact."
        ),
        "references": list(getattr(spec, "MANUAL_REFERENCES", [])),
    }


def build(spec: Any, records: list[dict[str, Any]]) -> dict[str, Any]:
    automated = {record["id"]: record for record in records if record["automated"]}
    manual = {record["id"]: record for record in records if not record["automated"]}
    missing = sorted(set(automated) - set(spec.CONTROLS), key=_key)
    extra = sorted(set(spec.CONTROLS) - set(automated), key=_key)
    auto_guidance = bool(getattr(spec, "AUTO_MANUAL_GUIDANCE", False))
    unguided = [] if auto_guidance else sorted(set(manual) - set(spec.MANUAL), key=_key)
    stale = sorted(set(spec.MANUAL) - set(manual), key=_key)
    notes = getattr(spec, "NOTES", {})
    stray_notes = sorted(set(notes) - set(automated), key=_key)
    prefix = getattr(spec, "ID_PREFIX", "LNX")
    problems = []
    if stale:
        problems.append(f"Manual guidance without a matching Manual recommendation: {', '.join(stale)}")
    if stray_notes:
        problems.append(f"Platform notes without a matching Automated recommendation: {', '.join(stray_notes)}")
    if missing:
        problems.append(f"Automated recommendations without a specification: {', '.join(missing)}")
    if extra:
        problems.append(f"Specifications without a matching Automated recommendation: {', '.join(extra)}")
    if unguided:
        problems.append(f"Manual recommendations without guidance: {', '.join(unguided)}")
    if problems:
        raise SystemExit("\n".join(problems))
    counters: dict[str, int] = {}
    controls, manual_items = [], []
    for record in records:
        section, category, code = section_for(spec, record["id"])
        counters[code] = counters.get(code, 0) + 1
        identifier = f"{prefix}-{code}-{counters[code]:03d}"
        common = {
            "id": identifier,
            "cis_id": record["id"],
            "title": record["title"],
            "section": section,
            "category": category,
            "profiles": record["profiles"],
        }
        if record["automated"]:
            item = spec.CONTROLS[record["id"]]
            control = {
                **common,
                "automated": True,
                "severity": item["severity"],
                "description": item["description"],
                "rationale": item["rationale"],
                "business_impact": item["business_impact"],
                "recommendation": item["recommendation"],
                "remediation": item["remediation"],
                "references": item["references"],
                "cis_controls_v8": record["cis_controls_v8"],
                "nist_800_53": record["nist_800_53"],
            }
            if item["applies_if"]:
                control["applies_if"] = item["applies_if"]
            if record["id"] in notes:
                control["notes"] = notes[record["id"]]
            control["check"] = item["check"]
            controls.append(control)
        else:
            item = spec.MANUAL.get(record["id"]) or generic_manual(spec, record)
            manual_items.append(
                {
                    **common,
                    "severity": "Informational",
                    "guidance": item["guidance"],
                    "remediation": item["remediation"],
                    "references": item["references"],
                    "cis_controls_v8": record["cis_controls_v8"],
                    "nist_800_53": record["nist_800_53"],
                }
            )
    benchmark = {key: value for key, value in spec.BENCHMARK.items() if key != "output_file"}
    benchmark["automated_control_count"] = len(controls)
    benchmark["manual_control_count"] = len(manual_items)
    return {
        "schema_version": "1.0",
        "generated_by": Path(__file__).name,
        "benchmark": benchmark,
        "controls": controls,
        "manual_recommendations": manual_items,
    }


def _key(value: str) -> list[int]:
    return [int(part) for part in value.split(".")]


def write_catalog(directory: Path) -> Path:
    entries = []
    for path in sorted(directory.glob("CIS_*.json")):
        benchmark = json.loads(path.read_text(encoding="utf-8"))["benchmark"]
        entries.append({"file_name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **benchmark})
    catalog = directory / "catalog.json"
    catalog.write_text(json.dumps({"schema_version": "1.0", "generated_by": Path(__file__).name, "benchmarks": entries}, indent=2) + "\n", encoding="utf-8")
    return catalog


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", required=True, choices=sorted(SPEC_MODULES))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pdf", type=Path, help="CIS benchmark PDF")
    source.add_argument("--text", type=Path, help="Text previously extracted from the PDF with page markers")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_DIR / "benchmarks")
    args = parser.parse_args()
    spec = load_spec(args.spec)
    text = extract_text(args.pdf) if args.pdf else args.text.read_text(encoding="utf-8")
    records = parse_recommendations(text, spec.BENCHMARK["profiles"])
    definition = build(spec, records)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / spec.BENCHMARK["output_file"]
    output.write_text(json.dumps(definition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    from lsa.engine import load_definition

    load_definition(output)
    catalog = write_catalog(args.output_dir)
    benchmark = definition["benchmark"]
    print(f"{output.name}: {benchmark['automated_control_count']} automated controls, {benchmark['manual_control_count']} manual recommendations")
    print(f"Catalog updated: {catalog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
