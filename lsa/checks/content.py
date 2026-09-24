"""Banner, bootloader, core dump and GNOME Display Manager checks."""

from __future__ import annotations

import os
import re
import shutil
import tempfile

from lsa.checks.common import (
    as_int,
    failed,
    join_limited,
    os_identity_pattern,
    passed,
    provider,
    resolve_targets,
    source,
)
from lsa.system import EvidenceUnavailable, System

PAM_MOTD_SERVICES = ("sshd", "login", "su", "gdm-password")
GDM_CONFIG_FILES = ("/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf", "/etc/gdm/custom.conf", "/etc/gdm/daemon.conf")


# ------------------------------------------------------------------- banners
def _pam_motd_paths(system: System, services: tuple[str, ...] | None) -> list[str]:
    files = []
    if services is None:
        files = system.glob("/etc/pam.d", "*", files_only=True)
    else:
        for service in services:
            for directory in ("/etc/pam.d", "/usr/lib/pam.d"):
                if system.is_file(f"{directory}/{service}"):
                    files.append(f"{directory}/{service}")
                    break
    paths = []
    for path in files:
        for line in system.lines(path) or []:
            if services is not None and not re.match(r"^\s*session\s+(required|optional)\s+pam_motd\.so\b", line, re.I):
                continue
            if line.lstrip().startswith("#"):
                continue
            for match in re.finditer(r"""\bmotd=("[^"]+"|'[^']+'|\S+)""", line):
                paths.append(match.group(1).strip("\"'"))
    return list(dict.fromkeys(paths))


@source("pam_motd_files")
def pam_motd_files(system: System) -> list[str]:
    """Files named by motd= on pam_motd in the login services CIS audits."""
    return [path for path in _pam_motd_paths(system, PAM_MOTD_SERVICES) if system.is_file(path)]


@source("pam_motd_files_all")
def pam_motd_files_all(system: System) -> list[str]:
    """Every motd= file referenced from /etc/pam.d (CIS 1.6.9)."""
    return [path for path in _pam_motd_paths(system, None) if system.exists(path)]


@provider("banner_content")
def banner_content(system: System, check: dict) -> object:
    paths, _missing = resolve_targets(system, check["targets"])
    pattern = os_identity_pattern(system)
    matches = []
    for path in paths:
        if not system.is_file(path):
            continue
        for number, line in enumerate(system.lines(path) or [], 1):
            if pattern.search(line):
                matches.append(f"{path}:{number}: {line.strip()[:120]}")
    evidence = {"files": paths, "disclosures": matches, "os_identifier": system.os_id()}
    if check.get("require_configured") and not paths:
        return failed(check.get("missing_message", "No banner file is configured."), [], **evidence)
    if matches:
        return failed(
            "Banner text discloses system details (\\m, \\r, \\s, \\v escapes or the OS name): " + join_limited(matches, 4) + ".",
            sorted({item.split(":", 1)[0] for item in matches}),
            **evidence,
        )
    if not paths:
        return passed(check.get("empty_message", "No banner files exist, so no system details are disclosed."), **evidence)
    return passed(f"{join_limited(paths, 5)} contain no OS name or escape sequences that reveal system details.", **evidence)


# -------------------------------------------------------------------- GRUB
def grub_configs(system: System) -> list[str]:
    def build() -> list[str]:
        paths = system.walk_files("/boot", name_pattern="grub.cfg")
        system.record("boot", "grub_configs", paths)
        return paths

    return system.cached("grub-configs", "boot", build)


def _grub_linux_lines(system: System) -> dict[str, list[str]]:
    lines = {}
    for path in grub_configs(system):
        lines[path] = [line.strip() for line in system.lines(path) or [] if re.match(r"^\s*linux", line)]
    return lines


@provider("bootloader_password")
def bootloader_password(system: System, check: dict) -> object:
    path = "/boot/grub/grub.cfg"
    text = system.read_text(path)
    if text is None:
        raise EvidenceUnavailable(f"{path} was not found; verify equivalent protection for the bootloader in use")
    superusers = re.findall(r'(?m)^set superusers\s*=\s*"?([^"\n]*)"?', text)
    passwords = re.findall(r"(?m)^\s*password_pbkdf2\s+(\S+)\s+grub\.pbkdf2\.sha512\.", text)
    evidence = {"file": path, "superusers": superusers, "pbkdf2_users": passwords}
    problems = []
    if not superusers:
        problems.append("no 'set superusers' line")
    if not passwords:
        problems.append("no password_pbkdf2 (grub.pbkdf2.sha512) entry")
    if problems:
        return failed(f"The GRUB bootloader is not password protected: {'; '.join(problems)} in {path}.", [path], **evidence)
    return passed(f"GRUB superuser(s) {', '.join(superusers)} are protected with PBKDF2 password hashes.", **evidence)


@provider("grub_cmdline")
def grub_cmdline(system: System, check: dict) -> object:
    lines = _grub_linux_lines(system)
    if not lines:
        # systemd-boot installs (for example Proxmox VE on ZFS with UEFI, managed
        # by proxmox-boot-tool) keep the kernel command line in /etc/kernel/cmdline.
        kernel_cmdline = (system.read_text("/etc/kernel/cmdline") or "").strip()
        if kernel_cmdline:
            lines = {"/etc/kernel/cmdline": [kernel_cmdline]}
    cmdline = (system.read_text("/proc/cmdline") or "").strip()
    evidence = {"boot_configs": list(lines), "running_kernel_cmdline": cmdline}
    if not lines:
        raise EvidenceUnavailable("No grub.cfg under /boot and no /etc/kernel/cmdline were found; verify the kernel command line for the bootloader in use")
    problems = []
    required = check.get("require_pattern")
    forbidden = check.get("forbid_pattern")
    for path, entries in lines.items():
        if not entries:
            continue
        for entry in entries:
            if required and not re.search(required, entry):
                problems.append(f"{path}: '{entry[:90]}' lacks {check['describe']}")
            if forbidden and re.search(forbidden, entry):
                problems.append(f"{path}: '{entry[:90]}' contains {check['describe']}")
    if not any(lines.values()):
        raise EvidenceUnavailable("No kernel entries (linux lines) were found in grub.cfg")
    if problems:
        return failed(f"{len(problems)} boot entr(ies) are not compliant: {join_limited(problems, 3)}.", sorted(lines), **evidence)
    verb = "include" if required else "do not include"
    return passed(f"All {sum(len(v) for v in lines.values())} kernel command line entries in {', '.join(lines)} {verb} {check['describe']}.", **evidence)


# ----------------------------------------------------------------- core dumps
@provider("core_dump_limit")
def core_dump_limit(system: System, check: dict) -> object:
    files = ["/etc/security/limits.conf"] + system.glob("/etc/security/limits.d", "*", files_only=True)
    entries = []
    for path in files:
        for line in system.lines(path) or []:
            match = re.match(r"^\s*\*\s+hard\s+core\s+(\S+)", line, re.IGNORECASE)
            if match:
                entries.append((path, match.group(1)))
    evidence = {"entries": [f"{path}: * hard core {value}" for path, value in entries]}
    if not entries:
        return failed("No '* hard core 0' limit is configured in limits.conf or limits.d.", ["/etc/security/limits.conf"], **evidence)
    nonzero = [f"{path} ({value})" for path, value in entries if value != "0"]
    if nonzero:
        return failed(f"A core dump hard limit above 0 is configured: {', '.join(nonzero)}.", [p for p, v in entries if v != "0"], **evidence)
    return passed(f"The hard core dump limit for all users is 0 ({entries[-1][0]}).", **evidence)


@provider("apport_disabled")
def apport_disabled(system: System, check: dict) -> object:
    problems = []
    evidence: dict = {"apport_installed": system.package_installed("apport")}
    if system.package_installed("apport"):
        for line in system.lines("/etc/default/apport") or []:
            if re.match(r"^\s*enabled\s*=\s*[^0]", line, re.IGNORECASE):
                problems.append(f"/etc/default/apport sets '{line.strip()}'")
        state = system.unit("apport.service")
        evidence["apport_service"] = state.active_state
        if state.active:
            problems.append("apport.service is active")
    if problems:
        return failed("Automatic error reporting is enabled: " + "; ".join(problems) + ".", ["apport"], **evidence)
    if not evidence["apport_installed"]:
        return passed("apport is not installed, so crash reports are not collected automatically.", **evidence)
    return passed("apport is installed but disabled and not running.", **evidence)


# ------------------------------------------------------------------------ GDM
def gsettings(system: System, schema: str, key: str) -> tuple[str, str]:
    """System-wide (writable, value) for a GSettings key.

    gsettings runs with an empty temporary HOME so the result reflects the
    dconf system databases and locks rather than any personal settings.
    """

    def build() -> tuple[str, str]:
        command = system.command("gsettings")
        home = tempfile.mkdtemp(prefix="lsa-gsettings-")
        try:
            env = {
                "HOME": home,
                "XDG_CONFIG_HOME": os.path.join(home, ".config"),
                "XDG_RUNTIME_DIR": home,
                "DCONF_PROFILE": "user",
                "DBUS_SESSION_BUS_ADDRESS": "disabled:",
                "GSETTINGS_BACKEND": "dconf",
            }
            writable = system.run([command, "writable", schema, key], collector="desktop", env=env)
            value = system.run([command, "get", schema, key], collector="desktop", env=env)
        finally:
            shutil.rmtree(home, ignore_errors=True)
        if not writable.ok or not value.ok:
            failing = writable if not writable.ok else value
            raise EvidenceUnavailable(f"Unable to read {schema} {key}: {failing.describe()}")
        return writable.stdout.strip(), value.stdout.strip()

    return system.cached(f"gsettings:{schema}:{key}", "desktop", build)


def _gsettings_value_ok(value: str, rule: dict) -> bool:
    op = rule["op"]
    number = as_int(value.split()[-1]) if value else None
    if op == "equals":
        return value.strip().lower() == str(rule["value"]).lower()
    if op == "nonempty_string":
        return value.strip() not in ("''", '""', "")
    if op == "max":
        return number is not None and number <= int(rule["value"])
    if op == "range":
        return number is not None and int(rule["min"]) <= number <= int(rule["max"])
    raise ValueError(f"Unsupported gsettings rule '{op}'")


@provider("gsettings")
def gsettings_check(system: System, check: dict) -> object:
    problems, observed = [], {}
    for item in check["keys"]:
        writable, value = gsettings(system, item["schema"], item["key"])
        label = f"{item['schema']} {item['key']}"
        observed[label] = {"writable": writable, "value": value}
        if item.get("locked", True) and writable != "false":
            problems.append(f"{label} is not locked (users can change it)")
        if not _gsettings_value_ok(value, item["rule"]):
            problems.append(f"{label} is {value} (expected {item['expected']})")
    if problems:
        return failed("; ".join(problems) + ".", list(observed), settings=observed)
    return passed("System-wide GNOME settings are configured and locked: " + ", ".join(f"{k} = {v['value']}" for k, v in observed.items()) + ".", settings=observed)


def _ini_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        header = re.match(r"^\[(.+)\]$", stripped)
        if header:
            current = header.group(1).strip().lower()
            continue
        if stripped and not stripped.startswith(("#", ";")):
            sections.setdefault(current, []).append(stripped)
    return sections


@provider("gdm_config")
def gdm_config(system: System, check: dict) -> object:
    section, key, value = check["section"].lower(), check["key"].lower(), check["value"].lower()
    found = []
    existing = [path for path in GDM_CONFIG_FILES if system.is_file(path)]
    for path in existing:
        for line in _ini_sections(system.read_text(path) or "").get(section, []):
            name, _, setting = line.partition("=")
            if name.strip().lower() == key:
                found.append((path, setting.strip().lower()))
    matching = [path for path, setting in found if setting == value]
    evidence = {"files": existing, "settings": [f"{path}: [{check['section']}] {check['key']}={setting}" for path, setting in found]}
    if check["expect"] == "absent":
        if matching:
            return failed(f"[{check['section']}] {check['key']}={check['value']} is set in {', '.join(matching)}.", matching, **evidence)
        return passed(f"[{check['section']}] {check['key']}={check['value']} is not set in any GDM configuration file.", **evidence)
    if matching:
        return passed(f"[{check['section']}] {check['key']}={check['value']} is set in {', '.join(matching)}.", **evidence)
    where = ", ".join(existing) if existing else "any GDM configuration file (none exist)"
    return failed(f"[{check['section']}] {check['key']}={check['value']} is not set in {where}.", existing or ["/etc/gdm3/custom.conf"], **evidence)
