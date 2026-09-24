"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from lsa import TOOL_NAME, __version__
from lsa.engine import DefinitionError, Engine, build_document, console_progress, load_definition, resolve_profile
from lsa.model import STATUSES, AssessmentDocument, utc_now
from lsa.platform import describe_execution, describe_host, detect_platform, load_catalog, select_benchmark
from lsa.reporting import SUPPORTED_FORMATS, generate_reports
from lsa.system import System

PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG = logging.getLogger(TOOL_NAME)
COMMANDS_USED = [
    "systemctl show", "sshd -T -C", "auditctl -l", "apt-config dump", "apt-cache policy", "aa-status", "ufw status verbose",
    "modprobe --showconfig", "modprobe -n -v", "systemd-sysctl --cat-config", "systemd-analyze cat-config", "gsettings get/writable",
    "journalctl -t sudo", "postconf -n", "useradd -D", "aide -p", "ip -o addr", "hostname --fqdn", "systemd-detect-virt",
    "pveversion", "pve-firewall status", "root login shell (PATH evaluation)",
]
ESXI_COMMANDS = [
    "vmware -v", "esxcli --formatter=csv (system, software, network, iscsi and storage namespaces; get/list only)",
    "vim-cmd hostsvc/hostconfig", "vim-cmd hostsvc/advopt/view", "vim-cmd vmsvc/getallvms", "reading registered VMs' .vmx files",
]
PRIVILEGE_NOTE = {
    False: "root (run with sudo) is required for /etc/shadow, sudoers, sshd -T, auditctl, ufw and AppArmor evidence",
    True: "root on the ESXi Shell (SSH) is required for esxcli, vim-cmd and VM configuration files",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux_security_audit.py",
        description=(
            "Read-only CIS configuration assessment for Linux servers (including Proxmox VE) and VMware ESXi hosts. "
            "Detects the platform, selects the matching versioned benchmark definition, evaluates every automated "
            "control and writes JSON, HTML, CSV and Excel reports in the m365-assessor format."
        ),
    )
    parser.add_argument("-C", "--client-name", help="Client name used in the report folder and file names.")
    parser.add_argument("-O", "--output", help="Output root; a timestamped assessment folder is created inside it.")
    parser.add_argument("--config", help="Configuration file (default: config.json beside this script).")
    parser.add_argument(
        "--profile",
        choices=["auto", "level1", "level2", "level1-server", "level2-server", "level1-workstation", "level2-workstation"],
        help="CIS profile. auto/level2 assess Level 1 and Level 2 for the detected platform type; level1 limits to Level 1.",
    )
    parser.add_argument(
        "--benchmark-path",
        help="Explicit benchmark definition (file name in benchmarks/ or a path). A platform mismatch is reported as a warning.",
    )
    parser.add_argument("--section", action="append", help="Limit to a CIS section number or name (repeatable). Other controls are NOT_APPLICABLE.")
    parser.add_argument("--format", dest="formats", help=f"Comma-separated report formats ({','.join(sorted(SUPPORTED_FORMATS))}).")
    parser.add_argument("--include-manual", action="store_true", help="List manual CIS recommendations as NOT_ASSESSED items.")
    parser.add_argument("--skip-filesystem-scan", action="store_true", help="Skip the full filesystem walk (its controls become NOT_ASSESSED).")
    parser.add_argument("--list-benchmarks", action="store_true", help="List installed benchmark definitions and exit.")
    parser.add_argument("--list-checks", action="store_true", help="List the controls of the selected definition and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be assessed without collecting evidence.")
    parser.add_argument("--report-from", metavar="JSON", help="Regenerate every report from an existing assessment JSON file.")
    parser.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation when not running as root.")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def load_config(path: str | None) -> dict[str, Any]:
    config_path = Path(path) if path else PROJECT_DIR / "config.json"
    if not config_path.is_file():
        if path:
            raise FileNotFoundError(f"Configuration file does not exist: {config_path}")
        return {}
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for key in ("report_formats", "benchmarks_directory"):
        if key not in config:
            raise ValueError(f"Configuration file is missing required property '{key}'.")
    return config


def safe_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("._-")
    if not normalized:
        raise ValueError("Names used in report paths must contain at least one letter or number.")
    return normalized[:80]


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _formats(args: argparse.Namespace, config: dict[str, Any]) -> set[str]:
    raw = args.formats.split(",") if args.formats else config.get("report_formats", sorted(SUPPORTED_FORMATS))
    selected = {item.strip().lower() for item in raw if item.strip()}
    if not selected or selected - SUPPORTED_FORMATS:
        raise ValueError(f"--format must contain one or more of: {', '.join(sorted(SUPPORTED_FORMATS))}")
    return selected


def _settings(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    settings = dict(config.get("site_policy", {}))
    settings["command_timeout_seconds"] = config.get("command_timeout_seconds", 60)
    scan = dict(config.get("filesystem_scan", {}))
    if args.skip_filesystem_scan:
        scan["enabled"] = False
    settings["filesystem_scan"] = scan
    return settings


def _configure_logging(log_file: Path | None) -> None:
    LOG.setLevel(logging.INFO)
    for handler in list(LOG.handlers):
        LOG.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    LOG.addHandler(console)
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(formatter)
        LOG.addHandler(handler)


def _chown_to_invoker(paths: list[Path]) -> None:
    """Give reports to the sudo invoker so they can be read without root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    for path in paths:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError as exc:
            LOG.warning("Unable to hand %s to the invoking user: %s", path, exc)


def report_from(args: argparse.Namespace) -> int:
    source = Path(args.report_from)
    document = AssessmentDocument.from_dict(json.loads(source.read_text(encoding="utf-8")))
    output = Path(args.output) if args.output else source.parent
    stem = source.name[:-5] if source.name.endswith(".json") else source.stem
    for name, path in generate_reports(document, output, _formats(args, {}) if args.formats else None, stem).items():
        print(f"[+] Generated {name}: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.report_from:
            return report_from(args)
        formats = _formats(args, config)
    except (OSError, ValueError, KeyError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    _configure_logging(None)
    benchmarks_dir = PROJECT_DIR / config.get("benchmarks_directory", "benchmarks")
    system = System(settings=_settings(config, args))

    if args.list_benchmarks:
        print(f"{'File':<34} {'Benchmark':<34} {'Version':<8} {'OS':<14} {'Automated':>9}")
        for entry in load_catalog(benchmarks_dir):
            platform_info = entry.get("platform", {})
            os_label = f"{platform_info.get('os_id', '')} {'/'.join(platform_info.get('version_ids', []))}"
            print(f"{entry['file_name']:<34} {entry['name']:<34} {entry['version']:<8} {os_label:<14} {entry['automated_control_count']:>9}")
        return 0

    try:
        info = detect_platform(system)
        entry, warnings = select_benchmark(system, benchmarks_dir, info, args.benchmark_path)
        definition = load_definition(entry["path"])
        profile, allowed_profiles = resolve_profile(args.profile or config.get("profile", "auto"), info.platform_type, definition["benchmark"]["profiles"])
    except (OSError, ValueError, DefinitionError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    benchmark = definition["benchmark"]
    kind = info.platform_type

    if args.list_checks:

        def profiles(item: dict[str, Any]) -> str:
            # 'Level 1 (L1) - Corporate/Enterprise Environment (general use)' -> 'Level 1 (L1)'
            return ", ".join(name.split(" - ")[0] if "(L" in name else name for name in item["profiles"])

        print(f"{'Check ID':<16} {'CIS':<11} {'Severity':<9} {'Profiles':<44} Title")
        for control in definition["controls"]:
            print(f"{control['id']:<16} {control['cis_id']:<11} {control['severity']:<9} {profiles(control):<44} {control['title']}")
        for manual in definition.get("manual_recommendations", []):
            print(f"{manual['id']:<16} {manual['cis_id']:<11} {'Manual':<9} {profiles(manual):<44} {manual['title']}")
        return 0

    if args.dry_run:
        plan = {
            "host": {"hostname": system.hostname(), "platform": info.label, "kind": info.kind, "platform_type": kind},
            "benchmark": {"name": benchmark["name"], "version": benchmark["version"], "file": entry["file_name"], "warnings": warnings},
            "profile": profile,
            "sections": args.section or "all",
            "automated_controls": len(definition["controls"]),
            "manual_recommendations": len(definition.get("manual_recommendations", [])),
            "checks": [f"{c['id']} ({c['cis_id']}) {c['title']}" for c in definition["controls"]],
            "required_privileges": [PRIVILEGE_NOTE[info.kind == "esxi"]],
            "read_only_commands": ESXI_COMMANDS if info.kind == "esxi" else COMMANDS_USED,
            "report_formats": sorted(formats),
            "note": "No evidence was collected and no command was executed against the system configuration.",
        }
        print(json.dumps(plan, indent=2))
        return 0

    if not system.is_root:
        print(f"[!] Not running as root: {PRIVILEGE_NOTE[info.kind == 'esxi']}; affected controls will be NOT_ASSESSED.", file=sys.stderr)
        if _interactive() and not args.yes:
            answer = input("Continue with a limited, non-root assessment? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("Assessment cancelled; no evidence was collected.")
                return 1

    try:
        client = args.client_name or config.get("client_name")
        if not client:
            if not _interactive():
                raise ValueError("Client name is required for report naming; use --client-name.")
            client = input("Client name: ").strip()
        client_safe = safe_name(client)
        output_root = args.output
        if output_root is None and _interactive():
            default = config.get("output_directory", "reports")
            output_root = input(f"Output root folder [{default}]: ").strip() or default
        output_root = Path(output_root or config.get("output_directory", "reports")).expanduser()
        if ".." in output_root.parts:
            raise ValueError("Output folder cannot contain parent traversal ('..').")
        host_safe = safe_name(system.hostname())
    except (OSError, ValueError, EOFError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    stem = f"{client_safe}-{host_safe}-{info.report_tag}-assessment-{stamp}"
    output_directory = output_root.resolve() / stem
    old_umask = os.umask(0o077) if hasattr(os, "umask") else None
    paths: dict[str, Path] = {}
    failed_formats: list[str] = []
    try:
        output_directory.mkdir(parents=True, exist_ok=False)
        log_file = output_directory / f"{TOOL_NAME}.log"
        _configure_logging(log_file)
        LOG.info("Report directory: %s", output_directory)
        LOG.info("Detected %s (%s, %s).", info.label or info.pretty_name, info.kind, info.platform_type)
        for warning in warnings:
            LOG.warning(warning)
        LOG.info(
            "Selected %s v%s (%s) with profile %s; %d automated controls.",
            benchmark["name"], benchmark["version"], entry["file_name"], profile, len(definition["controls"]),
        )
        started = utc_now()
        engine = Engine(
            system,
            definition,
            profile=profile,
            allowed_profiles=allowed_profiles,
            sections=args.section,
            include_manual=args.include_manual or bool(config.get("include_manual")),
            platform_tags=info.tags,
            progress=console_progress,
        )
        results = engine.run()
        document = build_document(
            engine,
            results,
            host=describe_host(system, info, profile),
            execution=describe_execution(system),
            client_name=client.strip(),
            started_at=started,
            definition_file=entry["file_name"],
            definition_sha256=entry["sha256"],
        )
        if warnings:
            next(iter(document.benchmark_results.values()))["warnings"] = warnings
        for report_format in [name for name in ("json", "html", "csv", "xlsx", "consolidated") if name in formats]:
            try:
                paths.update(generate_reports(document, output_directory, {report_format}, stem))
            except Exception as exc:  # noqa: BLE001 - keep the other report formats
                failed_formats.append(report_format)
                LOG.error("Unable to write the %s report: %s: %s", report_format, type(exc).__name__, exc)
    except Exception as exc:  # noqa: BLE001 - report the failure with context, then exit non-zero
        LOG.error("Assessment failed: %s: %s", type(exc).__name__, exc)
        return 1
    finally:
        if old_umask is not None:
            os.umask(old_umask)
    _chown_to_invoker([output_directory, log_file, *paths.values()])
    counts = {status: 0 for status in STATUSES}
    for result in results:
        counts[result.status] += 1
    LOG.info("%d controls evaluated: %s", len(results), ", ".join(f"{key}={value}" for key, value in counts.items() if value))
    LOG.info("Pass percentage %.1f%%, coverage %.1f%%.", document.summary.pass_percentage, document.summary.coverage_percentage)
    for name, path in paths.items():
        LOG.info("Report generated (%s): %s", name, path)
    return 1 if failed_formats and not paths else 0
