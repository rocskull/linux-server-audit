"""Helpers shared by the report writers."""

from __future__ import annotations

import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from lsa.model import AssessmentDocument, CheckResult

def report_title(document: AssessmentDocument) -> str:
    host = document.host
    if (host.os_id or "") == "esxi":
        return "VMware ESXi Security Assessment"
    if (host.platform or "").startswith("Proxmox"):
        return "Proxmox VE Security Assessment"
    return "Linux Server Security Assessment"


def platform_label(document: AssessmentDocument) -> str:
    host = document.host
    return host.platform or host.os_pretty_name or host.os_name or "Linux"


def collection_method(document: AssessmentDocument) -> str:
    if (document.host.os_id or "") == "esxi":
        return "Local ESXi Shell commands (esxcli get/list, vim-cmd host and VM queries) and registered VMs' .vmx files."
    return "Local files, /proc and /sys, and read-only commands (systemctl, sshd -T, auditctl -l, apt-config, aa-status, ufw)."


def validate_report_filename(filename: str, suffix: str) -> str:
    if Path(filename).name != filename or not filename.casefold().endswith(suffix.casefold()):
        raise ValueError(f"Report filename must be a simple {suffix} filename")
    return filename


@contextmanager
def atomic_report_path(destination: Path) -> Iterator[Path]:
    """Write to a private temporary file, then move it into place."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.stem}-", suffix=".tmp", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        yield temporary
        if hasattr(os, "chmod"):
            os.chmod(temporary, 0o600)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def mapping_text(check: CheckResult, framework: str = "CIS") -> str:
    """'CIS Debian Linux 13 | 1.1.0 | 1.1.1.1', the m365-assessor mapping layout."""
    for item in check.benchmark:
        if item.framework.casefold() == framework.casefold():
            return f"{item.framework} {item.benchmark} | {item.version} | {item.control}"
    return "; ".join(f"{i.framework} {i.benchmark} | {i.version} | {i.control}" for i in check.benchmark)


def all_mappings_text(check: CheckResult) -> str:
    return "; ".join(f"{item.framework} {item.version} {item.control}" for item in check.benchmark)


def host_label(document: AssessmentDocument) -> str:
    return document.host.fqdn or document.host.hostname


def frameworks_text(document: AssessmentDocument) -> str:
    return ", ".join(f"{item.name} {item.version}" for item in document.assessment.frameworks)


def profile_level(check: CheckResult, profile: str) -> str:
    """Level of the recommendation within the assessed platform type.

    Linux profiles read 'Level 1 - Server'; ESXi profiles read
    'Level 1 (L1) - Corporate/Enterprise Environment (general use)'. Both are
    reduced to 'Level 1'.
    """
    kind = "Workstation" if "Workstation" in profile else "Server"
    candidates = [item for item in check.profiles if item.endswith(kind)] or list(check.profiles)
    levels = []
    for item in candidates:
        match = re.match(r"Level \d", item)
        level = match.group(0) if match else item
        if level not in levels:
            levels.append(level)
    return ", ".join(levels)


def neutralise_formula(value: str) -> str:
    """Prefix spreadsheet formula triggers so CSV cells open as plain text."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value
