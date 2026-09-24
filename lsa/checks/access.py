"""sudo, su and PAM checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lsa.checks.common import describe_rule, failed, join_limited, passed, provider, rule_ok
from lsa.system import EvidenceUnavailable, System

PAM_COMMON = (
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-session",
    "/etc/pam.d/common-session-noninteractive",
)


# ---------------------------------------------------------------------- sudo
def sudoers_lines(system: System) -> list[tuple[str, int, str]]:
    """Every line of /etc/sudoers and /etc/sudoers.d (recursively, as CIS greps)."""

    def build() -> list[tuple[str, int, str]]:
        files = []
        if system.exists("/etc/sudoers"):
            files.append("/etc/sudoers")
        files.extend(system.walk_files("/etc/sudoers.d"))
        lines: list[tuple[str, int, str]] = []
        for path in files:
            text = system.read_text(path)
            if text is None:
                continue
            pending, start = "", 0
            for number, line in enumerate(text.splitlines(), 1):
                if not pending:
                    start = number
                if line.endswith("\\"):
                    pending += line[:-1] + " "
                    continue
                lines.append((path, start, pending + line))
                pending = ""
            if pending:
                lines.append((path, start, pending))
        system.record("sudo", "files", files)
        return lines

    return system.cached("sudoers", "sudo", build)


def _defaults_matches(system: System, option_regex: str) -> list[str]:
    pattern = re.compile(r"^\s*Defaults\s+([^#\n\r]+,\s*)?" + option_regex, re.IGNORECASE)
    return [f"{path}:{number}: {line.strip()}" for path, number, line in sudoers_lines(system) if pattern.search(line)]


@provider("sudo_use_pty")
def sudo_use_pty(system: System, check: dict) -> object:
    negated = _defaults_matches(system, r"!use_pty\b")
    enabled = _defaults_matches(system, r"use_pty\b")
    evidence = {"use_pty": enabled, "negated": negated}
    if negated:
        return failed(f"sudo disables use_pty: {join_limited(negated, 3)}.", [item.split(":", 1)[0] for item in negated], **evidence)
    if not enabled:
        return failed("No 'Defaults use_pty' entry exists in /etc/sudoers or /etc/sudoers.d.", ["/etc/sudoers"], **evidence)
    return passed(f"sudo is configured with use_pty ({enabled[0]}).", **evidence)


@provider("sudo_logfile")
def sudo_logfile(system: System, check: dict) -> object:
    sudo_rs = system.package_installed("sudo-rs")
    implementation = "sudo-rs" if sudo_rs else "classic sudo"
    logfile = _defaults_matches(system, r"logfile\s*=\s*[\"']?\S+")
    evidence: dict = {"implementation": implementation, "logfile_defaults": logfile}
    if not sudo_rs and logfile:
        return passed(f"Classic sudo writes a dedicated log file ({logfile[-1]}).", **evidence)
    journalctl = system.which("journalctl")
    if journalctl and system.real_root:
        result = system.run([journalctl, "-t", "sudo", "-t", "sudo-rs", "-n", "5", "--no-pager", "-q"], collector="sudo")
        if result.ok and result.stdout.strip():
            evidence["journal_events"] = len(result.stdout.strip().splitlines())
            return passed("sudo events are being recorded in the systemd journal.", **evidence)
    auth_log = system.read_text("/var/log/auth.log") or ""
    if re.search(r"\b(sudo|sudo-rs)\[[0-9]+\]:", auth_log):
        evidence["auth_log_events"] = True
        return passed("sudo events are being recorded in /var/log/auth.log.", **evidence)
    raise EvidenceUnavailable(
        f"No sudo log file is configured ({implementation}) and no sudo events were found in the journal or "
        "/var/log/auth.log; run a sudo command and re-assess to confirm logging"
    )


@provider("sudo_forbidden")
def sudo_forbidden(system: System, check: dict) -> object:
    pattern = re.compile(r"^\s*[^#].*" + check["pattern"], re.IGNORECASE)
    matches = [f"{path}:{number}: {line.strip()}" for path, number, line in sudoers_lines(system) if pattern.search(line)]
    evidence = {"matches": matches}
    if matches:
        return failed(f"{check['label']} is used in sudoers: {join_limited(matches, 3)}.", sorted({m.split(':', 1)[0] for m in matches}), **evidence)
    return passed(f"No uncommented sudoers entry uses {check['label']}.", **evidence)


@provider("sudo_timestamp_timeout")
def sudo_timestamp_timeout(system: System, check: dict) -> object:
    maximum = int(check.get("max", 15))
    pattern = re.compile(r"^\s*Defaults\s+([^#\n\r]+,\s*)?timestamp_timeout\s*=\s*(-?[0-9]+)", re.IGNORECASE)
    entries = []
    for path, number, line in sudoers_lines(system):
        match = pattern.search(line)
        if match:
            entries.append((f"{path}:{number}", int(match.group(2))))
    evidence = {"entries": [f"{where} timestamp_timeout={value}" for where, value in entries]}
    if not entries:
        return failed("timestamp_timeout is not explicitly configured in sudoers.", ["/etc/sudoers"], **evidence)
    bad = [f"{where} ({value})" for where, value in entries if value < 0 or value > maximum]
    if bad:
        return failed(f"timestamp_timeout must be between 0 and {maximum} minutes: {', '.join(bad)}.", [w for w, v in entries if v < 0 or v > maximum], **evidence)
    return passed(f"sudo re-authentication timeout is {entries[-1][1]} minute(s).", **evidence)


@provider("su_restricted")
def su_restricted(system: System, check: dict) -> object:
    lines = pam_lines(system, "/etc/pam.d/su")
    wheel = [line for line in lines if line.type == "auth" and line.control in ("required", "requisite") and line.module.endswith("pam_wheel.so")]
    evidence: dict = {"pam_wheel": [line.raw for line in wheel]}
    configured = [line for line in wheel if "use_uid" in line.args and any(arg.startswith("group=") for arg in line.args)]
    if not configured:
        return failed("/etc/pam.d/su does not require pam_wheel.so with use_uid and group=<group>.", ["/etc/pam.d/su"], **evidence)
    group_name = next(arg.split("=", 1)[1] for arg in configured[0].args if arg.startswith("group="))
    evidence["group"] = group_name
    group = next((entry for entry in system.group() if entry.name == group_name), None)
    if group is None:
        return failed(f"pam_wheel restricts su to group {group_name}, but that group does not exist.", [group_name], **evidence)
    evidence["members"] = list(group.members)
    if group.members:
        return failed(f"su is restricted to group {group_name}, which has members: {', '.join(group.members)}.", list(group.members), **evidence)
    return passed(f"su is restricted by pam_wheel to the empty group {group_name}.", **evidence)


# ----------------------------------------------------------------------- PAM
@dataclass
class PamLine:
    file: str
    number: int
    type: str
    control: str
    module: str
    args: list[str]
    raw: str


def pam_lines(system: System, path: str) -> list[PamLine]:
    def build() -> list[PamLine]:
        text = system.read_text(path)
        if text is None:
            return []
        parsed = []
        for number, line in enumerate(text.splitlines(), 1):
            body = line.split("#", 1)[0].strip()
            if not body or body.startswith("@"):
                continue
            match = re.match(r"^-?(\w+)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$", body)
            if not match:
                continue
            parsed.append(
                PamLine(path, number, match.group(1).lower(), match.group(2), match.group(3), match.group(4).split(), body)
            )
        system.record("pam", path, [item.raw for item in parsed])
        return parsed

    return system.cached(f"pam:{path}", "pam", build)


def module_lines(system: System, files: tuple[str, ...] | list[str], module: str, pam_type: str | None = None) -> list[PamLine]:
    found = []
    for path in files:
        for line in pam_lines(system, path):
            if line.module.split("/")[-1] == module and (pam_type is None or line.type == pam_type):
                found.append(line)
    return found


def module_args(lines: list[PamLine]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        for arg in line.args:
            name, _, value = arg.partition("=")
            values[name.lower()] = value
    return values


def conf_values(system: System, path: str) -> dict[str, str]:
    """name = value / bare-flag files such as faillock.conf and pwhistory.conf."""
    values: dict[str, str] = {}
    for line in system.lines(path) or []:
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        name, sep, value = body.partition("=")
        values[name.strip().lower()] = value.strip() if sep else ""
    return values


@provider("pam_module_enabled")
def pam_module_enabled(system: System, check: dict) -> object:
    missing, found = [], []
    for requirement in check["requirements"]:
        lines = module_lines(system, [requirement["file"]], requirement["module"], requirement.get("type"))
        wanted_args = requirement.get("args", [])
        matches = [line for line in lines if all(arg in line.args for arg in wanted_args)]
        label = f"{requirement['file']}: {requirement.get('type', '')} {requirement['module']} {' '.join(wanted_args)}".replace("  ", " ")
        if matches:
            found.append(f"{requirement['file']}:{matches[0].number}: {matches[0].raw}")
        else:
            missing.append(label.strip())
    evidence = {"present": found, "missing": missing}
    if missing:
        return failed(f"Required PAM entries are missing: {join_limited(missing, 5)}.", sorted({m.split(':', 1)[0] for m in missing}), **evidence)
    return passed(f"{check['module_label']} is enabled in the PAM stack ({len(found)} entr{'y' if len(found) == 1 else 'ies'}).", **evidence)


@provider("faillock_option")
def faillock_option(system: System, check: dict) -> object:
    option = check["option"]
    rule = check["rule"]
    conf = conf_values(system, "/etc/security/faillock.conf")
    args = module_args(module_lines(system, ["/etc/pam.d/common-auth"], "pam_faillock.so", "auth"))
    evidence = {"faillock_conf": conf.get(option), "module_argument": args.get(option)}
    problems = []
    if option not in conf:
        problems.append(f"{option} is not set in /etc/security/faillock.conf")
    elif not rule_ok(conf[option], rule):
        problems.append(f"/etc/security/faillock.conf sets {option} = {conf[option]}")
    if option in args and not rule_ok(args[option], rule):
        problems.append(f"the pam_faillock.so argument {option}={args[option]} overrides the configuration")
    if problems:
        return failed(f"{option} should be {describe_rule(rule)}: " + "; ".join(problems) + ".", ["/etc/security/faillock.conf"], **evidence)
    return passed(f"pam_faillock {option} is {conf[option]} in /etc/security/faillock.conf and not overridden.", **evidence)


@provider("faillock_root")
def faillock_root(system: System, check: dict) -> object:
    conf = conf_values(system, "/etc/security/faillock.conf")
    args = module_args(module_lines(system, ["/etc/pam.d/common-auth"], "pam_faillock.so", "auth"))
    minimum = int(check.get("min_root_unlock_time", 60))
    evidence = {"even_deny_root": "even_deny_root" in conf, "root_unlock_time": conf.get("root_unlock_time"), "module_root_unlock_time": args.get("root_unlock_time")}
    problems = []
    if "even_deny_root" not in conf and "root_unlock_time" not in conf:
        problems.append("neither even_deny_root nor root_unlock_time is set in /etc/security/faillock.conf")
    for where, value in (("faillock.conf", conf.get("root_unlock_time")), ("pam_faillock.so argument", args.get("root_unlock_time"))):
        if value is not None and not rule_ok(value, {"op": "min", "value": minimum}):
            problems.append(f"{where} sets root_unlock_time={value} (minimum {minimum})")
    if problems:
        return failed("Failed-login lockout does not cover root: " + "; ".join(problems) + ".", ["/etc/security/faillock.conf"], **evidence)
    return passed("pam_faillock also locks the root account after failed attempts.", **evidence)


def pwquality_conf(system: System) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Effective pwquality settings: pwquality.conf overrides pwquality.conf.d."""
    values: dict[str, tuple[str, str]] = {}
    files = system.glob("/etc/security/pwquality.conf.d", "*.conf", files_only=True)
    for path in files:
        for name, value in conf_values(system, path).items():
            values[name] = (value, path)
    for name, value in conf_values(system, "/etc/security/pwquality.conf").items():
        values[name] = (value, "/etc/security/pwquality.conf")
    return values, ["/etc/security/pwquality.conf"] + files


@provider("pwquality_option")
def pwquality_option(system: System, check: dict) -> object:
    option = check["option"]
    conf, files = pwquality_conf(system)
    args = module_args(module_lines(system, ["/etc/pam.d/common-password"], "pam_pwquality.so", "password"))
    configured = conf.get(option)
    evidence = {"configuration_value": configured[0] if configured else None, "configured_in": configured[1] if configured else None, "module_argument": args.get(option), "files": files}
    if check.get("flag"):
        if configured or option in args:
            where = configured[1] if configured else "the pam_pwquality.so arguments"
            return passed(f"{option} is enabled in {where}.", **evidence)
        return failed(f"{option} is not enabled in pwquality.conf, pwquality.conf.d or the pam_pwquality.so arguments.", ["/etc/security/pwquality.conf"], **evidence)
    rule = check["rule"]
    problems = []
    if configured is None:
        if check.get("required", True):
            problems.append(f"{option} is not set in pwquality.conf or pwquality.conf.d")
    elif not rule_ok(configured[0], rule):
        problems.append(f"{configured[1]} sets {option} = {configured[0]}")
    if option in args and not rule_ok(args[option], rule):
        problems.append(f"the pam_pwquality.so argument {option}={args[option]} overrides the configuration")
    if problems:
        return failed(f"{option} should be {describe_rule(rule)}: " + "; ".join(problems) + ".", ["/etc/security/pwquality.conf"], **evidence)
    if configured is None:
        return passed(f"{option} is not overridden, so the secure default applies.", **evidence)
    return passed(f"{option} = {configured[0]} ({configured[1]}).", **evidence)


@provider("pwhistory_option")
def pwhistory_option(system: System, check: dict) -> object:
    option = check["option"]
    conf = conf_values(system, "/etc/security/pwhistory.conf")
    args = module_args(module_lines(system, ["/etc/pam.d/common-password"], "pam_pwhistory.so", "password"))
    evidence = {"pwhistory_conf": conf.get(option), "module_argument": args.get(option)}
    in_conf, in_args = option in conf, option in args
    if in_conf and in_args:
        return failed(
            f"{option} is set in both /etc/security/pwhistory.conf and the pam_pwhistory.so arguments; CIS requires one location.",
            ["/etc/security/pwhistory.conf", "/etc/pam.d/common-password"],
            **evidence,
        )
    if not (in_conf or in_args):
        return failed(f"{option} is not set in /etc/security/pwhistory.conf or on pam_pwhistory.so.", ["/etc/security/pwhistory.conf"], **evidence)
    where = "/etc/security/pwhistory.conf" if in_conf else "the pam_pwhistory.so arguments"
    value = conf.get(option) if in_conf else args.get(option)
    if "rule" in check and not rule_ok(value, check["rule"]):
        return failed(f"{option} is {value} in {where}; it should be {describe_rule(check['rule'])}.", [where], **evidence)
    shown = f"{option}={value}" if value else option
    return passed(f"{shown} is configured in {where}.", **evidence)


@provider("pam_unix_args")
def pam_unix_args(system: System, check: dict) -> object:
    files = check.get("files", list(PAM_COMMON))
    lines = module_lines(system, files, "pam_unix.so", check.get("pam_type"))
    evidence = {"pam_unix_lines": [f"{line.file}:{line.number}: {line.raw}" for line in lines]}
    if "forbid" in check:
        pattern = re.compile(check["forbid"])
        offending = [f"{line.file}:{line.number}" for line in lines if any(pattern.fullmatch(arg) for arg in line.args)]
        if offending:
            return failed(f"pam_unix.so uses {check['label']} in {', '.join(offending)}.", sorted({o.split(':')[0] for o in offending}), **evidence)
        return passed(f"No pam_unix.so entry uses {check['label']}.", **evidence)
    if not lines:
        return failed(f"No {check.get('pam_type', '')} pam_unix.so entry was found in {', '.join(files)}.".replace("  ", " "), files, **evidence)
    wanted = check["require_any"]
    missing = [f"{line.file}:{line.number}" for line in lines if not any(arg in wanted for arg in line.args)]
    if missing:
        return failed(f"pam_unix.so password entries lack {' or '.join(wanted)}: {', '.join(missing)}.", sorted({m.split(':')[0] for m in missing}), **evidence)
    return passed(f"Every pam_unix.so password entry includes {' or '.join(wanted)}.", **evidence)
