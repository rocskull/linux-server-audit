"""Kernel module, kernel parameter and wireless interface checks."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from lsa.checks.common import failed, join_limited, passed, provider, verdict
from lsa.system import EvidenceUnavailable, System

MODPROBE_DIRS = ("/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d")
SYSCTL_DIRS = ("/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d")
DISABLED_INSTALL = re.compile(r"^(/usr)?/bin/(true|false)(\s|$)")


def normalize_module(name: str) -> str:
    return name.replace("-", "_")


@dataclass
class ModprobeConfig:
    source: str
    blacklist: set[str] = field(default_factory=set)
    install: dict[str, list[str]] = field(default_factory=dict)

    def disabled(self, module: str) -> bool:
        return any(DISABLED_INSTALL.match(command) for command in self.install.get(normalize_module(module), []))


def modprobe_config(system: System) -> ModprobeConfig:
    def build() -> ModprobeConfig:
        text = None
        origin = "modprobe.d configuration files"
        modprobe = system.which("modprobe")
        if modprobe and system.real_root:
            result = system.run([modprobe, "--showconfig"], collector="kernel")
            if result.ok:
                text, origin = result.stdout, "modprobe --showconfig"
        if text is None:
            chosen: dict[str, str] = {}
            for directory in MODPROBE_DIRS:
                for path in system.glob(directory, "*.conf"):
                    chosen.setdefault(os.path.basename(path), path)
            text = "\n".join(system.read_text(chosen[name]) or "" for name in sorted(chosen))
        config = ModprobeConfig(origin)
        for line in text.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] == "blacklist":
                config.blacklist.add(normalize_module(parts[1]))
            elif len(parts) >= 3 and parts[0] == "install":
                config.install.setdefault(normalize_module(parts[1]), []).append(" ".join(parts[2:]))
        system.record(
            "kernel",
            "modprobe",
            {"source": origin, "blacklist": sorted(config.blacklist), "install": config.install},
        )
        return config

    return system.cached("modprobe-config", "kernel", build)


def module_locations(system: System, paths: list[str]) -> list[str]:
    """Kernel module directories that contain the module (CIS availability test)."""
    found = []
    for base in ("/usr/lib/modules", "/lib/modules"):
        for version in system.listdir(base) or []:
            for relative in paths:
                directory = f"{base}/{version}/kernel/{relative}"
                if system.is_dir(directory) and system.listdir(directory):
                    found.append(system.realpath(directory))
    return sorted(set(found))


@provider("kernel_module")
def kernel_module(system: System, check: dict) -> object:
    module = check["module"]
    normalized = normalize_module(module)
    locations = module_locations(system, check.get("paths", []))
    if not locations:
        return passed(
            f"The {module} module is not present in any installed kernel module tree "
            "(not built or compiled into the kernel), which CIS treats as compliant.",
            module=module,
            available=False,
        )
    config = modprobe_config(system)
    loaded = normalized in system.loaded_modules()
    blacklisted = normalized in config.blacklist
    disabled = config.disabled(module)
    problems = []
    if loaded:
        problems.append("it is currently loaded")
    if not blacklisted:
        problems.append(f"there is no 'blacklist {normalized}' entry")
    if not disabled:
        problems.append(f"there is no 'install {normalized} /bin/false' (or /bin/true) entry")
    evidence = {
        "module": module,
        "available_in": locations,
        "loaded": loaded,
        "blacklisted": blacklisted,
        "install_commands": config.install.get(normalized, []),
        "configuration_source": config.source,
    }
    if problems:
        return failed(f"The {module} module is available and " + "; ".join(problems) + ".", [module], **evidence)
    return passed(f"The {module} module is available but unloaded, deny-listed and mapped to a disabled install command.", **evidence)


# ------------------------------------------------------------------- sysctl
def _sysctl_key(raw: str) -> str:
    key = raw.strip().lstrip("-").strip()
    slash, dot = key.find("/"), key.find(".")
    if slash != -1 and (dot == -1 or slash < dot):
        key = key.replace("/", ".")
    return key.lower()


def _sysctl_files(system: System) -> list[str]:
    def build() -> list[str]:
        files = None
        if system.real_root:
            for candidate in ("/usr/lib/systemd/systemd-sysctl", "/lib/systemd/systemd-sysctl"):
                if system.is_file(candidate):
                    result = system.run([candidate, "--cat-config"], collector="kernel")
                    if result.ok:
                        files = re.findall(r"(?m)^#\s*(/\S+\.conf)\s*$", result.stdout)
                    break
        if files is None:
            chosen: dict[str, str] = {}
            for directory in SYSCTL_DIRS:
                for path in system.glob(directory, "*.conf"):
                    chosen.setdefault(os.path.basename(path), path)
            files = [chosen[name] for name in sorted(chosen)]
        system.record("kernel", "sysctl_files", files)
        return files

    return system.cached("sysctl-files", "kernel", build)


def _ufw_sysctl_file(system: System) -> str | None:
    enabled = False
    for line in system.lines("/etc/ufw/ufw.conf") or []:
        match = re.match(r"^\s*ENABLED\s*=\s*\"?(\w+)", line)
        if match:
            enabled = match.group(1).lower() == "yes"
    if not enabled:
        return None
    for line in system.lines("/etc/default/ufw") or []:
        match = re.match(r"^\s*IPT_SYSCTL\s*=\s*\"?([^\"\s]+)", line)
        if match and system.is_file(match.group(1)):
            return match.group(1)
    return None


def sysctl_configured(system: System, name: str) -> dict:
    """Effective boot-time value and every file that sets the parameter.

    Precedence follows the CIS audit: the UFW sysctl file (when UFW is
    enabled), then /etc/sysctl.conf, then systemd-sysctl files in reverse
    load order. The first file found wins.
    """
    wanted = name.lower()
    ordered: list[str] = []
    ufw_file = _ufw_sysctl_file(system)
    if ufw_file:
        ordered.append(ufw_file)
    ordered.append("/etc/sysctl.conf")
    ordered.extend(reversed(_sysctl_files(system)))
    seen: set[str] = set()
    entries = []
    for path in ordered:
        real = system.realpath(path)
        if real in seen or not system.is_file(path):
            continue
        seen.add(real)
        value = None
        for line in system.lines(path) or []:
            stripped = line.strip()
            if not stripped or stripped[0] in "#;" or "=" not in stripped:
                continue
            key, _, raw_value = stripped.partition("=")
            if _sysctl_key(key) == wanted:
                value = " ".join(raw_value.split())
        if value is not None:
            entries.append({"file": path, "value": value, "ufw": path == ufw_file})
    effective = entries[0] if entries else None
    return {"value": effective["value"] if effective else None, "file": effective["file"] if effective else None, "entries": entries}


@provider("sysctl")
def sysctl(system: System, check: dict) -> object:
    name = check["parameter"]
    expected = [str(value) for value in check["expected"]]
    expected_text = " or ".join(expected)
    running = system.sysctl_running(name)
    configured = sysctl_configured(system, name)
    problems = []
    if running is None:
        problems.append(f"{name} is not available in the running kernel")
    elif running not in expected:
        problems.append(f"the running value is {running}")
    if configured["value"] is None:
        problems.append("it is not set in any sysctl configuration file applied at boot")
    elif configured["value"] not in expected:
        problems.append(f"the effective configured value is {configured['value']} in {configured['file']}")
    conflicting = [f"{entry['file']} ({entry['value']})" for entry in configured["entries"][1:] if entry["value"] not in expected]
    evidence = {
        "parameter": name,
        "expected": expected,
        "running_value": running,
        "configured_value": configured["value"],
        "configured_in": configured["file"],
        "configuration_entries": configured["entries"],
    }
    if problems:
        return failed(f"{name} should be {expected_text}, but " + "; ".join(problems) + ".", [name], **evidence)
    note = f" Lower-precedence files also set other values: {join_limited(conflicting)}." if conflicting else ""
    return passed(f"{name} is {running} at runtime and {configured['value']} in {configured['file']}.{note}", **evidence)


# ----------------------------------------------------------------- wireless
@provider("wireless_interfaces")
def wireless_interfaces(system: System, check: dict) -> object:
    interfaces = [name for name in system.listdir("/sys/class/net") or [] if system.is_dir(f"/sys/class/net/{name}/wireless")]
    if not interfaces:
        return passed("No wireless network interfaces are present.", interfaces=[])
    modules = set()
    for interface in interfaces:
        link = f"/sys/class/net/{interface}/device/driver/module"
        if system.exists(link):
            modules.add(os.path.basename(system.realpath(link)))
    config = modprobe_config(system)
    loaded_modules = system.loaded_modules()
    problems, details = [], {}
    modprobe = system.which("modprobe")
    for module in sorted(modules):
        normalized = normalize_module(module)
        loadable = not config.disabled(module)
        if modprobe and system.real_root:
            result = system.run([modprobe, "-n", "-v", module], collector="kernel")
            loadable = not re.search(r"^\s*install\s+(/usr)?/bin/(true|false)", result.stdout, re.MULTILINE)
        loaded = normalized in loaded_modules
        blacklisted = normalized in config.blacklist
        details[module] = {"loadable": loadable, "loaded": loaded, "blacklisted": blacklisted}
        if loadable:
            problems.append(f"{module} is loadable")
        if loaded:
            problems.append(f"{module} is loaded")
        if not blacklisted:
            problems.append(f"{module} is not deny-listed")
    if not modules:
        raise EvidenceUnavailable("Wireless interfaces exist but their driver modules could not be identified")
    return verdict(
        problems,
        f"Wireless interfaces ({', '.join(interfaces)}) use drivers that are disabled and deny-listed.",
        prefix="Wireless interface drivers remain usable: ",
        affected=sorted(modules),
        interfaces=interfaces,
        drivers=details,
    )
