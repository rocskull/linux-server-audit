"""systemd configuration, journald, rsyslog and time synchronization checks."""

from __future__ import annotations

import os
import re

from lsa.checks.common import as_bool, failed, join_limited, passed, provider
from lsa.system import EvidenceUnavailable, System

SYSTEMD_CONFIG_DIRS = ("/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd", "/lib/systemd")
RSYSLOG_FILES = ("/etc/rsyslog.conf",)


# ------------------------------------------------------------ systemd config
def systemd_config_files(system: System, name: str) -> list[str]:
    """Files systemd reads for ``systemd/<name>``, lowest precedence first."""

    def build() -> list[str]:
        files = None
        analyze = system.which("systemd-analyze")
        if analyze and system.real_root:
            result = system.run([analyze, "cat-config", f"systemd/{name}"], collector="logging")
            if result.ok:
                files = re.findall(r"(?m)^#\s*(/\S+\.conf)\s*$", result.stdout)
        if files is None:
            files = []
            for directory in SYSTEMD_CONFIG_DIRS:
                if system.is_file(f"{directory}/{name}"):
                    files.append(f"{directory}/{name}")
                    break
            chosen: dict[str, str] = {}
            for directory in SYSTEMD_CONFIG_DIRS:
                for path in system.glob(f"{directory}/{name}.d", "*.conf", files_only=True):
                    chosen.setdefault(os.path.basename(path), path)
            files.extend(chosen[key] for key in sorted(chosen))
        return files

    return system.cached(f"systemd-config:{name}", "logging", build)


def systemd_option(system: System, name: str, section: str, option: str) -> dict:
    """Effective value of a unit-file style option and where it came from."""
    files = systemd_config_files(system, name)
    value, where, entries = None, None, []
    for path in files:
        current = ""
        for line in system.lines(path) or []:
            stripped = line.strip()
            header = re.match(r"^\[(.+)\]$", stripped)
            if header:
                current = header.group(1)
                continue
            if current != section or not stripped or stripped[0] in "#;":
                continue
            key, sep, raw = stripped.partition("=")
            if sep and key.strip() == option:
                value, where = raw.strip(), path
                entries.append({"file": path, "value": value})
    default = None
    if value is None:
        for base in ("/etc/systemd", "/usr/lib/systemd", "/lib/systemd"):
            text = system.read_text(f"{base}/{name}")
            if text is None:
                continue
            in_section = False
            for line in text.splitlines():
                stripped = line.strip()
                header = re.match(r"^\[(.+)\]$", stripped)
                if header:
                    in_section = header.group(1) == section
                    continue
                match = re.match(rf"^#?\s*{re.escape(option)}\s*=\s*(\S*)", stripped)
                if in_section and match:
                    default = match.group(1)
                    break
            if default is not None:
                break
    return {"value": value, "file": where, "entries": entries, "default": default, "files": files}


def _matches(value: str | None, expected: list[str]) -> bool:
    if value is None:
        return False
    wanted = [item.lower() for item in expected]
    if value.lower() in wanted:
        return True
    boolean = as_bool(value)
    return boolean is not None and any(as_bool(item) is boolean for item in wanted)


@provider("systemd_config")
def systemd_config(system: System, check: dict) -> object:
    name, section, option = check["config"], check["section"], check["option"]
    expected = [str(item) for item in check["expected"]]
    package = check.get("package")
    if package and not system.package_installed(package):
        return passed(f"{package} is not installed, which CIS treats as compliant for {option}.", package=package, installed=False)
    result = systemd_option(system, name, section, option)
    evidence = {"config": f"systemd/{name}", "section": section, "option": option, **result}
    shown = " or ".join(expected)
    if result["value"] is not None:
        if _matches(result["value"], expected):
            return passed(f"{option}={result['value']} is set in {result['file']}.", **evidence)
        return failed(f"{option} is {result['value']} in {result['file']}; it should be {shown}.", [result["file"]], **evidence)
    default = result["default"] if result["default"] is not None else check.get("builtin_default")
    evidence["effective_default"] = default
    if default is not None and _matches(default, expected):
        return passed(
            f"{option} is not set explicitly; the default ({option}={default}) is compliant. Setting it explicitly is recommended.",
            **evidence,
        )
    return failed(f"{option} is not set in systemd/{name} and the default ({default or 'unknown'}) is not {shown}.", [f"/etc/systemd/{name}"], **evidence)


@provider("journald_to_rsyslog")
def journald_to_rsyslog(system: System, check: dict) -> object:
    result = systemd_option(system, "journald.conf", "Journal", "ForwardToSyslog")
    states = system.units(["rsyslog.service", "systemd-journald.service"])
    problems = []
    if not _matches(result["value"], ["yes"]):
        problems.append(f"ForwardToSyslog is {result['value'] or 'not set'} in the journald configuration")
    for name, state in states.items():
        if not (state.exists and state.active):
            problems.append(f"{name} is {state.active_state or 'not active'}")
    evidence = {"ForwardToSyslog": result["value"], "set_in": result["file"], "units": {n: s.active_state for n, s in states.items()}}
    if problems:
        return failed("journald does not forward to a running rsyslog: " + "; ".join(problems) + ".", ["/etc/systemd/journald.conf"], **evidence)
    return passed(f"journald forwards to rsyslog (ForwardToSyslog=yes in {result['file']}) and both services are active.", **evidence)


# ------------------------------------------------------------------- rsyslog
def rsyslog_lines(system: System) -> list[tuple[str, int, str]]:
    def build() -> list[tuple[str, int, str]]:
        files = [path for path in RSYSLOG_FILES if system.is_file(path)] + system.glob("/etc/rsyslog.d", "*.conf", files_only=True)
        lines = []
        for path in files:
            for number, line in enumerate(system.lines(path) or [], 1):
                lines.append((path, number, line))
        system.record("logging", "rsyslog_files", files)
        return lines

    return system.cached("rsyslog-lines", "logging", build)


@provider("rsyslog_file_create_mode")
def rsyslog_file_create_mode(system: System, check: dict) -> object:
    entries = []
    for path, number, line in rsyslog_lines(system):
        match = re.match(r"^\s*\$FileCreateMode\s+(0[0-7]{3})\b", line, re.IGNORECASE) or re.search(
            r"^[^#]*\bFileCreateMode\s*=\s*\"(0[0-7]{3})\"", line, re.IGNORECASE
        )
        if match:
            entries.append((f"{path}:{number}", match.group(1)))
    evidence = {"entries": [f"{where} {mode}" for where, mode in entries]}
    if not entries:
        return failed("No $FileCreateMode directive is configured, so rsyslog creates log files with mode 0644.", ["/etc/rsyslog.conf"], **evidence)
    bad = [f"{where} ({mode})" for where, mode in entries if int(mode, 8) & 0o137]
    if bad:
        return failed(f"rsyslog creates log files with a mode less restrictive than 0640: {', '.join(bad)}.", [w for w, m in entries if int(m, 8) & 0o137], **evidence)
    return passed(f"rsyslog creates log files with mode {entries[-1][1]}.", **evidence)


@provider("rsyslog_no_remote_input")
def rsyslog_no_remote_input(system: System, check: dict) -> object:
    patterns = [
        r"^\s*module\(load=\"?imtcp\"?\)",
        r"^\s*input\(type=\"?imtcp\"?\b",
        r"^\s*module\(load=\"?imudp\"?\)",
        r"^\s*input\(type=\"?imudp\"?\b",
        r"^\s*\$ModLoad\s+imtcp\b",
        r"^\s*\$InputTCPServerRun\b",
        r"^\s*\$ModLoad\s+imudp\b",
        r"^\s*\$UDPServerRun\b",
    ]
    regex = re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)
    matches = [f"{path}:{number}: {line.strip()}" for path, number, line in rsyslog_lines(system) if regex.search(line)]
    if matches:
        return failed(f"rsyslog accepts remote log input: {join_limited(matches, 4)}.", sorted({m.split(':', 1)[0] for m in matches}), matches=matches)
    return passed("rsyslog does not load the imtcp or imudp network input modules.", matches=[])


@provider("rsyslog_gtls")
def rsyslog_gtls(system: System, check: dict) -> object:
    drivers = []
    for path, number, line in rsyslog_lines(system):
        match = re.search(r"^[^#]*StreamDriver\s*=\s*\"?(\w+)\"?", line, re.IGNORECASE) or re.search(
            r"^\s*\$DefaultNetstreamDriver\s+(\w+)", line, re.IGNORECASE
        )
        if match:
            drivers.append((f"{path}:{number}", match.group(1).lower()))
    evidence = {"stream_drivers": [f"{where} {driver}" for where, driver in drivers]}
    if not drivers:
        return failed("No rsyslog StreamDriver is configured, so forwarded logs are not protected with TLS (gtls).", ["/etc/rsyslog.conf"], **evidence)
    other = [f"{where} ({driver})" for where, driver in drivers if driver != "gtls"]
    if other:
        return failed(f"rsyslog uses a non-gtls stream driver: {', '.join(other)}.", [w for w, d in drivers if d != "gtls"], **evidence)
    return passed("rsyslog network streams use the gtls (TLS) driver.", **evidence)


# ----------------------------------------------------------- time services
@provider("single_time_daemon")
def single_time_daemon(system: System, check: dict) -> object:
    states = system.units(["systemd-timesyncd.service", "chrony.service"])
    in_use = [name for name, state in states.items() if state.enabled or state.active]
    evidence = {name: {"unit_file_state": s.unit_file_state, "active_state": s.active_state} for name, s in states.items()}
    if len(in_use) == 1:
        return passed(f"Exactly one time synchronization daemon is in use: {in_use[0]}.", units=evidence)
    if not in_use:
        return failed("No time synchronization daemon (systemd-timesyncd or chrony) is enabled or active.", list(states), units=evidence)
    return failed(f"More than one time synchronization daemon is in use: {', '.join(in_use)}.", in_use, units=evidence)


@provider("timesyncd_servers")
def timesyncd_servers(system: System, check: dict) -> object:
    approved = [item.lower() for item in system.settings.get("approved_time_servers", [])]
    found = {}
    for option in ("NTP", "FallbackNTP"):
        result = systemd_option(system, "timesyncd.conf", "Time", option)
        if result["value"]:
            found[option] = (result["value"], result["file"])
    evidence = {"servers": {key: value[0] for key, value in found.items()}, "configured_in": {key: value[1] for key, value in found.items()}, "approved_time_servers": approved}
    if not found:
        return failed("Neither NTP nor FallbackNTP is set in the systemd-timesyncd configuration.", ["/etc/systemd/timesyncd.conf"], **evidence)
    servers = [server for value, _ in found.values() for server in value.split()]
    if approved:
        unapproved = [server for server in servers if server.lower() not in approved]
        if unapproved:
            return failed(f"systemd-timesyncd uses servers that are not on the approved list: {', '.join(unapproved)}.", unapproved, **evidence)
    shown = "; ".join(f"{key}={value[0]}" for key, value in found.items())
    suffix = "" if approved else " Confirm these are the site-approved time sources."
    return passed(f"systemd-timesyncd is configured with {shown}.{suffix}", **evidence)


def chrony_files(system: System) -> list[str]:
    files = ["/etc/chrony/chrony.conf"] if system.is_file("/etc/chrony/chrony.conf") else []
    for line in system.lines("/etc/chrony/chrony.conf") or []:
        match = re.match(r"^\s*(confdir|sourcedir)\s+(\S+)", line)
        if not match:
            continue
        location = match.group(2)
        if system.is_dir(location):
            files.extend(system.glob(location, "*", files_only=True))
        else:
            directory, _, pattern = location.rpartition("/")
            files.extend(system.glob(directory or "/", pattern or "*", files_only=True))
    return list(dict.fromkeys(files))


@provider("chrony_sources")
def chrony_sources(system: System, check: dict) -> object:
    entries = []
    for path in chrony_files(system):
        for number, line in enumerate(system.lines(path) or [], 1):
            if re.match(r"^\s*(server|pool)(\s+|\s*:\s*).+", line, re.IGNORECASE):
                entries.append(f"{path}:{number}: {line.strip()}")
    approved = [item.lower() for item in system.settings.get("approved_time_servers", [])]
    evidence = {"sources": entries, "approved_time_servers": approved}
    if not entries:
        return failed("chrony has no server or pool directive in its configuration.", ["/etc/chrony/chrony.conf"], **evidence)
    if approved:
        hosts = [entry.split(":", 2)[2].split()[1] for entry in entries if len(entry.split(":", 2)[2].split()) > 1]
        unapproved = [host for host in hosts if host.lower() not in approved]
        if unapproved:
            return failed(f"chrony uses time sources that are not on the approved list: {', '.join(unapproved)}.", unapproved, **evidence)
    return passed(f"chrony is configured with {len(entries)} time source(s): {join_limited([e.split(': ', 1)[-1] for e in entries], 3)}.", **evidence)


@provider("chrony_user")
def chrony_user(system: System, check: dict) -> object:
    processes = []
    for pid in system.listdir("/proc") or []:
        if not pid.isdigit():
            continue
        try:
            comm = (system.read_text(f"/proc/{pid}/comm") or "").strip()
        except EvidenceUnavailable:
            continue
        if comm != "chronyd":
            continue
        status = system.read_text(f"/proc/{pid}/status") or ""
        match = re.search(r"(?m)^Uid:\s+\d+\s+(\d+)", status)
        if match:
            processes.append((pid, system.user_name(int(match.group(1)))))
    evidence = {"chronyd_processes": [f"pid {pid} user {user}" for pid, user in processes]}
    wrong = [f"pid {pid} runs as {user}" for pid, user in processes if user != "_chrony"]
    if wrong:
        return failed(f"chronyd is not running as _chrony: {', '.join(wrong)}.", [f"chronyd (pid {p})" for p, u in processes if u != "_chrony"], **evidence)
    if not processes:
        return passed("No chronyd process is running, so none runs with elevated privileges (see the chrony service control).", **evidence)
    return passed("chronyd runs as the unprivileged _chrony user.", **evidence)
