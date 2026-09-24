"""Host detection and benchmark selection.

The tool runs on Linux servers (including Proxmox VE, which is Debian based)
and on VMware ESXi hosts. It detects which it is running on and selects the
matching versioned benchmark definition. A version mismatch never stops the
assessment: the closest definition of the same platform family is used and the
mismatch is recorded as a warning in the report, so the same tool can be run
unattended across a mixed estate.

Benchmark compatibility lives in each definition (operating system ID and
versions), so supporting another release means adding a definition and its
catalog entry rather than changing code. ``catalog.json`` stores SHA-256
hashes; a stale or missing catalog falls back to reading the definitions.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import platform as py_platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lsa.model import ExecutionContext, HostInfo
from lsa.system import EvidenceUnavailable, System

DISPLAY_MANAGERS = ("gdm3", "gdm", "lightdm", "sddm", "xdm", "lxdm", "slim")


@dataclass
class PlatformInfo:
    kind: str  # "linux", "esxi" or "unknown"
    os_id: str
    version: str
    pretty_name: str
    family: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    label: str = ""
    platform_type: str = "Server"
    name: str = ""

    @property
    def major(self) -> str:
        return self.version.split(".")[0] if self.version else ""

    @property
    def report_tag(self) -> str:
        if self.kind == "esxi":
            return "esxi"
        if "proxmox" in self.tags:
            return "proxmox"
        return "linux"


# ------------------------------------------------------------------- detection
def is_esxi(system: System) -> bool:
    if system.real_root and hasattr(os, "uname") and os.uname().sysname == "VMkernel":
        return True
    return system.is_file("/etc/vmware/esx.conf") and (system.is_file("/bin/vmware") or system.is_file("/bin/esxcli"))


def esxi_version(system: System) -> tuple[str, str]:
    """(version, product line) such as ('8.0.2', 'VMware ESXi 8.0.2 build-22380479')."""

    def build() -> tuple[str, str]:
        command = system.which("vmware")
        if command:
            result = system.run([command, "-v"], collector="host")
            match = re.search(r"ESXi\s+(\d+(?:\.\d+)*)", result.stdout)
            if match:
                return match.group(1), result.stdout.strip().splitlines()[0]
        command = system.which("esxcli")
        if command:
            result = system.run([command, "--formatter=csv", "system", "version", "get"], collector="host")
            rows = _csv(result.stdout)
            if rows and rows[0].get("version"):
                return rows[0]["version"], f"VMware ESXi {rows[0]['version']} {rows[0].get('build', '')}".strip()
        release = os.uname().release if system.real_root and hasattr(os, "uname") else ""
        return release, f"VMware ESXi {release}".strip()

    return system.cached("esxi-version", "host", build)


def proxmox_version(system: System) -> str | None:
    def build() -> str | None:
        installed = False
        try:
            packages = system.packages()
        except EvidenceUnavailable:
            packages = {}
        for name in ("pve-manager", "proxmox-ve"):
            if name in packages:
                installed = True
        if not installed and not system.is_dir("/etc/pve") and not system.which("pveversion"):
            return None
        command = system.which("pveversion")
        if command and system.real_root:
            result = system.run([command], collector="host")
            match = re.search(r"pve-manager/(\d+(?:\.\d+)*)", result.stdout)
            if match:
                return match.group(1)
        if "pve-manager" in packages:
            return packages["pve-manager"].version.split("-")[0]
        return ""

    return system.cached("proxmox-version", "host", build)


def platform_type(system: System) -> str:
    """Workstation when a display manager or graphical default target exists."""
    try:
        if any(system.package_installed(name) for name in DISPLAY_MANAGERS):
            return "Workstation"
    except EvidenceUnavailable:
        pass
    default_target = system.host_path("/etc/systemd/system/default.target")
    if os.path.islink(default_target) and os.readlink(default_target).endswith("graphical.target"):
        return "Workstation"
    return "Server"


def detect_platform(system: System) -> PlatformInfo:
    def build() -> PlatformInfo:
        if is_esxi(system):
            version, product = esxi_version(system)
            return PlatformInfo("esxi", "esxi", version, product, ["esxi"], set(), product, "Hypervisor", "VMware ESXi")
        try:
            release = system.os_release()
        except EvidenceUnavailable:
            release = {}
        os_id = release.get("ID", "").lower()
        if not os_id:
            return PlatformInfo("unknown", "", "", sys.platform, [], set(), sys.platform, "Server", sys.platform)
        family = [os_id] + release.get("ID_LIKE", "").lower().split()
        version = release.get("VERSION_ID", "")
        pretty = release.get("PRETTY_NAME") or f"{os_id} {version}".strip()
        info = PlatformInfo("linux", os_id, version, pretty, family, set(), pretty, platform_type(system), release.get("NAME", os_id))
        pve = proxmox_version(system)
        if pve is not None:
            info.tags.add("proxmox")
            info.label = f"Proxmox VE {pve} ({pretty})".replace("VE  (", "VE (")
        return info

    return system.cached("platform", "host", build)


def _csv(text: str) -> list[dict[str, str]]:
    """esxcli CSV rows keyed by lower-case column names without spaces."""
    rows = csv.DictReader(io.StringIO(text.strip()))
    return [
        {re.sub(r"[^a-z0-9]", "", key.lower()): (value or "").strip() for key, value in row.items() if isinstance(key, str) and key.strip()}
        for row in rows
    ]


def virtualization(system: System, info: PlatformInfo) -> str | None:
    if info.kind == "esxi":
        return "bare-metal hypervisor"
    command = system.which("systemd-detect-virt")
    if command and system.real_root:
        result = system.run([command], collector="host")
        value = result.stdout.strip()
        if value:
            return value
    if system.exists("/.dockerenv") or system.exists("/run/.containerenv"):
        return "container"
    return None


def ip_addresses(system: System, info: PlatformInfo) -> list[str]:
    if not system.real_root:
        return []
    if info.kind == "esxi":
        command = system.which("esxcli")
        if not command:
            return []
        result = system.run([command, "--formatter=csv", "network", "ip", "interface", "ipv4", "get"], collector="network")
        return [row.get("ipv4address", "") for row in _csv(result.stdout) if row.get("ipv4address") not in (None, "", "0.0.0.0")]
    command = system.which("ip")
    if not command:
        return []
    result = system.run([command, "-o", "addr", "show", "scope", "global"], collector="network")
    return re.findall(r"\binet6?\s+([0-9a-fA-F:.]+)/", result.stdout)


def fqdn(system: System, info: PlatformInfo) -> str | None:
    if not system.real_root:
        return None
    if info.kind == "esxi":
        command = system.which("esxcli")
        if command:
            result = system.run([command, "--formatter=csv", "system", "hostname", "get"], collector="host")
            rows = _csv(result.stdout)
            if rows and rows[0].get("fullyqualifieddomainname"):
                return rows[0]["fullyqualifieddomainname"]
        return None
    command = system.which("hostname")
    if command:
        result = system.run([command, "--fqdn"], collector="host", timeout=5)
        value = result.stdout.strip()
        if result.ok and value:
            return value
    return None


def machine_id(system: System, info: PlatformInfo) -> str | None:
    if info.kind == "esxi" and system.real_root:
        command = system.which("esxcli")
        if command:
            result = system.run([command, "system", "uuid", "get"], collector="host")
            if result.ok and result.stdout.strip():
                return result.stdout.strip()
    return system.machine_id()


def describe_host(system: System, info: PlatformInfo, profile: str) -> HostInfo:
    return HostInfo(
        hostname=system.hostname(),
        fqdn=fqdn(system, info),
        machine_id=machine_id(system, info),
        os_id=info.os_id or None,
        os_name=info.name or None,
        os_version=info.version or None,
        os_pretty_name=info.pretty_name,
        kernel=system.kernel_release(),
        architecture=system.architecture(),
        virtualization=virtualization(system, info),
        ip_addresses=ip_addresses(system, info),
        platform_type=info.platform_type,
        profile=profile,
        platform=info.label,
    )


def describe_execution(system: System) -> ExecutionContext:
    uid = os.getuid() if hasattr(os, "getuid") else None
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    identity = None
    if euid is not None:
        try:
            import pwd

            identity = pwd.getpwuid(euid).pw_name
        except (ImportError, KeyError):
            identity = "root" if euid == 0 else str(euid)
    return ExecutionContext(
        method="local",
        identity=identity,
        uid=uid,
        effective_uid=euid,
        is_root=system.is_root,
        sudo_user=os.environ.get("SUDO_USER"),
        python_version=py_platform.python_version(),
    )


# ----------------------------------------------------------------- catalog
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_catalog(directory: Path) -> list[dict[str, Any]]:
    """Benchmark metadata, verified against the definition files' hashes."""
    definitions = sorted(directory.glob("CIS_*.json"))
    catalog_path = directory / "catalog.json"
    if catalog_path.is_file():
        try:
            entries = json.loads(catalog_path.read_text(encoding="utf-8"))["benchmarks"]
            current = len(entries) == len(definitions) and all(
                (directory / entry["file_name"]).is_file() and _sha256(directory / entry["file_name"]) == entry["sha256"]
                for entry in entries
            )
            if current:
                return [{**entry, "path": str(directory / entry["file_name"])} for entry in entries]
            print(f"[!] {catalog_path} is stale; reading metadata from the definitions.", file=sys.stderr)
        except (OSError, ValueError, KeyError) as exc:
            print(f"[!] {catalog_path} is invalid ({exc}); reading metadata from the definitions.", file=sys.stderr)
    entries = []
    for path in definitions:
        try:
            benchmark = json.loads(path.read_text(encoding="utf-8"))["benchmark"]
        except (OSError, ValueError, KeyError) as exc:
            print(f"[!] Skipping invalid benchmark file {path.name}: {exc}", file=sys.stderr)
            continue
        entries.append({**benchmark, "file_name": path.name, "sha256": _sha256(path), "path": str(path)})
    return entries


def _entry_os(entry: dict[str, Any]) -> str:
    return str(entry.get("platform", {}).get("os_id", "")).lower()


def _entry_versions(entry: dict[str, Any]) -> list[str]:
    return [str(item) for item in entry.get("platform", {}).get("version_ids", [])]


def compatible(entry: dict[str, Any], os_id: str | None, version_id: str | None) -> bool:
    if (os_id or "").lower() != _entry_os(entry):
        return False
    versions = _entry_versions(entry)
    if not versions:
        return True
    major = (version_id or "").split(".")[0]
    return (version_id in versions) or (major in versions)


def _version_key(entry: dict[str, Any]) -> tuple[int, ...]:
    return tuple(int(part) if part.isdigit() else 0 for part in str(entry.get("version", "0")).split("."))


def _closeness(entry: dict[str, Any], major: str) -> tuple[int, tuple[int, ...]]:
    """Rank definitions by distance between their OS version and the host's.

    When the host version is unknown every definition is equally close and the
    newest one wins.
    """
    majors = []
    for version in _entry_versions(entry):
        try:
            majors.append(int(version.split(".")[0]))
        except ValueError:
            continue
    newest_first = (-max(majors, default=0),) + tuple(-part for part in _version_key(entry))
    try:
        host = int(major)
    except ValueError:
        return (0, newest_first)
    return (min((abs(item - host) for item in majors), default=99), newest_first)


def _describe(entry: dict[str, Any]) -> str:
    versions = "/".join(_entry_versions(entry))
    return f"{entry['name']} v{entry['version']} ({_entry_os(entry)} {versions})".strip()


def select_benchmark(
    system: System,
    directory: Path,
    info: PlatformInfo,
    explicit: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return (catalog entry, warnings); never fails on a version mismatch."""
    warnings: list[str] = []
    host = info.label or info.pretty_name or "this host"
    if explicit:
        path = Path(explicit)
        if not path.is_absolute() and not path.is_file():
            path = directory / explicit
        if not path.is_file():
            raise FileNotFoundError(f"The requested benchmark definition does not exist: {explicit}")
        benchmark = json.loads(path.read_text(encoding="utf-8"))["benchmark"]
        entry = {**benchmark, "file_name": path.name, "sha256": _sha256(path), "path": str(path)}
        if not compatible(entry, info.os_id, info.version):
            warnings.append(f"{_describe(entry)} was selected explicitly but this host is {host}; controls that do not apply may be reported.")
        return entry, warnings
    catalog = load_catalog(directory)
    if not catalog:
        raise ValueError(f"No benchmark definitions were found in {directory}.")
    exact = [entry for entry in catalog if compatible(entry, info.os_id, info.version)]
    if exact:
        return max(exact, key=_version_key), warnings
    if info.kind == "esxi":
        family = [entry for entry in catalog if _entry_os(entry) == "esxi"]
    elif info.kind == "linux":
        family = [entry for entry in catalog if _entry_os(entry) in info.family]
        if not family:
            family = [entry for entry in catalog if _entry_os(entry) != "esxi"]
    else:
        family = []
    if not family:
        raise ValueError(
            f"This host ({host}) is neither a supported Linux distribution nor VMware ESXi, and no installed benchmark definition covers it."
        )
    selected = min(family, key=lambda entry: _closeness(entry, info.major))
    warnings.append(
        f"No benchmark definition matches {host} exactly; the closest available definition, {_describe(selected)}, was used. "
        "Review results for controls that differ between releases."
    )
    return selected, warnings
