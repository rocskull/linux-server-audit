"""Linux audit framework and AIDE checks."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

from lsa.checks.access import sudoers_lines
from lsa.checks.common import cap, failed, join_limited, passed, provider, source
from lsa.checks.filesystem import filesystem_scan
from lsa.system import EvidenceUnavailable, System

AUDIT_TOOLS = ("auditctl", "aureport", "ausearch", "auditd", "augenrules")
UNSET_VALUES = {"unset", "-1", "4294967295"}
ERRNO = {"eacces": "13", "eperm": "1"}
FIELD_RE = re.compile(r"^([A-Za-z0-9_]+)(!=|>=|<=|&=|=|>|<|&)(.*)$")


# --------------------------------------------------------------- auditd.conf
def auditd_conf(system: System) -> dict[str, str] | None:
    def build() -> dict[str, str] | None:
        lines = system.lines("/etc/audit/auditd.conf")
        if lines is None:
            return None
        values = {}
        for line in lines:
            body = line.split("#", 1)[0].strip()
            if "=" in body:
                key, _, value = body.partition("=")
                values[key.strip().lower()] = value.strip()
        system.record("auditd", "auditd_conf", values)
        return values

    return system.cached("auditd-conf", "auditd", build)


@provider("auditd_conf")
def auditd_conf_check(system: System, check: dict) -> object:
    values = auditd_conf(system)
    if values is None:
        return failed("/etc/audit/auditd.conf does not exist; install and configure auditd.", ["/etc/audit/auditd.conf"])
    problems, observed = [], {}
    for setting in check["settings"]:
        key = setting["key"]
        value = values.get(key)
        observed[key] = value
        if value is None:
            problems.append(f"{key} is not set")
        elif setting.get("numeric"):
            if not re.fullmatch(r"\d+", value):
                problems.append(f"{key} = {value} is not a number of megabytes")
        elif value.lower() not in [item.lower() for item in setting["allowed"]]:
            problems.append(f"{key} = {value} (expected {' or '.join(setting['allowed'])})")
    if problems:
        return failed("auditd.conf is not compliant: " + "; ".join(problems) + ".", ["/etc/audit/auditd.conf"], settings=observed)
    shown = ", ".join(f"{key} = {value}" for key, value in observed.items())
    return passed(f"auditd.conf sets {shown}.", settings=observed)


def audit_log_directory(system: System) -> str | None:
    values = auditd_conf(system)
    if values is None:
        return None
    return os.path.dirname(values.get("log_file", "/var/log/audit/audit.log")) or "/var/log/audit"


@source("audit_log_files")
def audit_log_files(system: System) -> list[str]:
    directory = audit_log_directory(system)
    if directory is None:
        raise EvidenceUnavailable("/etc/audit/auditd.conf was not found; auditd does not appear to be installed")
    return system.glob(directory, "*", files_only=True)


@source("audit_log_directory")
def audit_log_directory_source(system: System) -> list[str]:
    directory = audit_log_directory(system)
    if directory is None:
        raise EvidenceUnavailable("/etc/audit/auditd.conf was not found; auditd does not appear to be installed")
    return [directory] if system.is_dir(directory) else []


@source("audit_config_files")
def audit_config_files(system: System) -> list[str]:
    return system.walk_files("/etc/audit", name_pattern="*.conf") + system.walk_files("/etc/audit", name_pattern="*.rules")


@source("audit_tools")
def audit_tools(system: System) -> list[str]:
    return [f"/sbin/{tool}" for tool in AUDIT_TOOLS if system.exists(f"/sbin/{tool}")]


@provider("audit_log_group")
def audit_log_group(system: System, check: dict) -> object:
    values = auditd_conf(system)
    if values is None:
        return failed("/etc/audit/auditd.conf does not exist; install and configure auditd.", ["/etc/audit/auditd.conf"])
    allowed = {"adm", "root"}
    log_group = values.get("log_group", "root")
    problems = []
    if log_group.lower() not in allowed:
        problems.append(f"auditd.conf sets log_group = {log_group}")
    directory = audit_log_directory(system) or "/var/log/audit"
    files = [path for path in system.walk_files(directory, follow_links=True) if not path.startswith(directory + "/lost+found")]
    wrong = []
    for path in files:
        meta = system.meta(path)
        if meta is not None and system.group_name(meta.gid) not in allowed:
            wrong.append(f"{path} (group {system.group_name(meta.gid)})")
    if wrong:
        problems.append(f"audit logs are group-owned outside root/adm: {join_limited(wrong, 5)}")
    evidence = {"log_group": log_group, "log_directory": directory, "files_checked": len(files), "non_compliant": wrong}
    if problems:
        return failed("Audit log group ownership is not restricted: " + "; ".join(problems) + ".", [w.split(" ")[0] for w in wrong] or ["/etc/audit/auditd.conf"], **evidence)
    return passed(f"log_group is {log_group} and all {len(files)} audit log file(s) are group-owned by root or adm.", **evidence)


# --------------------------------------------------------------- audit rules
@dataclass
class AuditRule:
    raw: str
    origin: str
    kind: str = "control"
    actions: frozenset = frozenset()
    arch: str | None = None
    syscalls: set[str] = field(default_factory=set)
    fields: list[tuple[str, str, str]] = field(default_factory=list)
    path: str | None = None
    path_field: str | None = None
    perms: set[str] = field(default_factory=set)
    key: str | None = None
    options: list[str] = field(default_factory=list)


def parse_rule(line: str, origin: str) -> AuditRule | None:
    body = line.split("#", 1)[0].strip()
    if not body:
        return None
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    rule = AuditRule(raw=body, origin=origin)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token in ("-a", "-A"):
            rule.kind = "syscall"
            rule.actions = frozenset(item.strip() for item in value.split(","))
            index += 2
        elif token == "-w":
            rule.kind, rule.path, rule.path_field = "watch", value, "watch"
            index += 2
        elif token == "-p":
            rule.perms = set(value)
            index += 2
        elif token == "-k":
            rule.key = value
            index += 2
        elif token == "-S":
            rule.syscalls.update(item for item in value.split(",") if item)
            index += 2
        elif token in ("-F", "-C"):
            match = FIELD_RE.match(value)
            if match:
                name, op, raw_value = match.group(1).lower(), match.group(2), match.group(3)
                if name == "arch":
                    rule.arch = raw_value
                elif name in ("path", "dir") and token == "-F":
                    rule.path, rule.path_field = raw_value, name
                elif name == "perm":
                    rule.perms = set(raw_value)
                elif name == "key":
                    rule.key = raw_value
                else:
                    rule.fields.append((name, op, raw_value))
            index += 2
        else:
            rule.options.append(token)
            index += 1
    return rule


def disk_rules(system: System) -> list[AuditRule]:
    def build() -> list[AuditRule]:
        rules = []
        for path in system.glob("/etc/audit/rules.d", "*.rules", files_only=True):
            for number, line in enumerate(system.lines(path) or [], 1):
                rule = parse_rule(line, f"{path}:{number}")
                if rule:
                    rules.append(rule)
        system.record("auditd", "rules_on_disk", [f"{r.origin}: {r.raw}" for r in rules][:2000])
        return rules

    return system.cached("audit-rules-disk", "auditd", build)


def loaded_rules(system: System) -> list[AuditRule]:
    def build() -> list[AuditRule]:
        command = system.command("auditctl")
        result = system.run([command, "-l"], collector="auditd")
        text = result.stdout + result.stderr
        if not result.ok:
            if not system.is_root or "must be root" in text or "Operation not permitted" in text:
                raise EvidenceUnavailable(f"Reading the loaded audit rules requires root ({result.describe()})", "root")
            raise EvidenceUnavailable(f"Unable to read the loaded audit rules: {result.describe()}")
        rules = []
        for number, line in enumerate(result.stdout.splitlines(), 1):
            if line.strip() == "No rules":
                continue
            rule = parse_rule(line, f"auditctl -l:{number}")
            if rule:
                rules.append(rule)
        system.record("auditd", "rules_loaded", [rule.raw for rule in rules][:2000])
        return rules

    return system.cached("audit-rules-loaded", "auditd", build)


def _required_archs(system: System) -> tuple[list[str], str]:
    machine = system.architecture()
    if machine in ("x86_64", "amd64"):
        return ["b64", "b32"], "b64"
    if machine in ("aarch64", "arm64", "ppc64le", "ppc64", "s390x", "riscv64"):
        return ["b64"], "b64"
    return ["b32"], "b32"


def _field_matches(rule_field: tuple[str, str, str], wanted: tuple[str, str, str], uid_min: int) -> bool:
    name, op, value = rule_field
    want_name, want_op, want_value = wanted
    if want_value == "UID_MIN":
        if name == want_name and op == ">=":
            try:
                return int(value) <= uid_min
            except ValueError:
                return False
        return False
    if want_value == "unset":
        return name == want_name and op == want_op and value.lower() in UNSET_VALUES
    if want_name in ("uid", "euid") and want_value in ("uid", "euid"):
        return op == want_op == "!=" and {name, value} == {want_name, want_value}
    if want_name == "exit":
        errno = lambda item: ERRNO.get(item.lstrip("-").lower(), item.lstrip("-"))  # noqa: E731
        return name == "exit" and op == want_op and errno(value) == errno(want_value)
    if re.fullmatch(r"0x[0-9a-f]+|\d+", want_value, re.IGNORECASE):
        try:
            return name == want_name and op == want_op and int(value, 0) == int(want_value, 0)
        except ValueError:
            return False
    return name == want_name and op == want_op and value.lower() == want_value.lower()


def _fields_ok(rule: AuditRule, wanted: list[list[str]], uid_min: int) -> bool:
    return all(any(_field_matches(item, tuple(requirement), uid_min) for item in rule.fields) for requirement in wanted)


def _exit_rule(rule: AuditRule) -> bool:
    return rule.kind == "syscall" and rule.actions == frozenset({"always", "exit"})


def _norm(path: str | None) -> str:
    value = (path or "").rstrip("/") or "/"
    return "/run/" + value[len("/var/run/"):] if value.startswith("/var/run/") else value


def _watch_found(rules: list[AuditRule], path: str, perms: str, wanted_fields: list[list[str]], uid_min: int) -> AuditRule | None:
    for rule in rules:
        if _norm(rule.path) != _norm(path) or not set(perms) <= rule.perms:
            continue
        if rule.kind == "watch" and not wanted_fields:
            return rule
        if _exit_rule(rule) and rule.path_field in ("path", "dir") and (not rule.syscalls or "all" in rule.syscalls):
            if _fields_ok(rule, wanted_fields, uid_min):
                return rule
    return None


def _syscall_found(rules: list[AuditRule], arch: str, native: str, syscall: str, wanted_fields: list[list[str]], uid_min: int) -> AuditRule | None:
    for rule in rules:
        if not _exit_rule(rule) or rule.path:
            continue
        if (rule.arch or native) != arch:
            continue
        if syscall not in rule.syscalls and "all" not in rule.syscalls:
            continue
        if _fields_ok(rule, wanted_fields, uid_min):
            return rule
    return None


def _sudo_logfile(system: System) -> str | None:
    value = None
    pattern = re.compile(r"^\s*Defaults\s+([^#]+,\s*)?logfile\s*=\s*[\"']?([^\"',\s]+)", re.IGNORECASE)
    for _path, _number, line in sudoers_lines(system):
        match = pattern.search(line)
        if match:
            value = match.group(2)
    return value


def _missing_requirements(system: System, check: dict, rules: list[AuditRule]) -> tuple[list[str], list[str]]:
    uid_min = system.uid_min()
    archs, native = _required_archs(system)
    missing, satisfied = [], []
    for watch in check.get("watches", []):
        path = watch["path"]
        if path == "@sudo_logfile":
            path = _sudo_logfile(system) or ""
        if watch.get("if_exists") and not system.exists(path):
            continue
        perms = watch.get("perms", "wa")
        fields = watch.get("fields", [])
        found = _watch_found(rules, path, perms, fields, uid_min)
        label = f"-F path={path} -F perm={perms}" + "".join(f" -F {''.join(item).replace('UID_MIN', str(uid_min))}" for item in fields)
        (satisfied if found else missing).append(label if not found else f"{label} ({found.origin})")
    for group in check.get("syscalls", []):
        fields = group.get("fields", [])
        for arch in archs:
            absent = [name for name in group["names"] if _syscall_found(rules, arch, native, name, fields, uid_min) is None]
            label = f"-F arch={arch} -S {','.join(group['names'])}" + "".join(f" {'-C' if item[2] in ('uid', 'euid') else '-F'} {''.join(item).replace('UID_MIN', str(uid_min))}" for item in fields)
            if absent:
                missing.append(f"{label} (missing {','.join(absent)})")
            else:
                satisfied.append(label)
    return missing, satisfied


@provider("audit_rules")
def audit_rules(system: System, check: dict) -> object:
    if any(item["path"] == "@sudo_logfile" for item in check.get("watches", [])) and _sudo_logfile(system) is None:
        return failed("sudo has no dedicated logfile configured (Defaults logfile=...), so its modification cannot be audited.", ["/etc/sudoers"])
    disk = disk_rules(system)
    disk_missing, disk_ok = _missing_requirements(system, check, disk)
    evidence: dict = {"on_disk_missing": disk_missing, "on_disk_present": disk_ok}
    loaded_error = None
    try:
        loaded = loaded_rules(system)
    except EvidenceUnavailable as exc:
        loaded, loaded_error = None, exc
    if loaded is not None:
        loaded_missing, loaded_ok = _missing_requirements(system, check, loaded)
        evidence.update(loaded_missing=loaded_missing, loaded_present=loaded_ok)
    else:
        loaded_missing = []
        evidence["loaded_rules"] = f"unavailable: {loaded_error.reason}"
    problems = []
    if disk_missing:
        problems.append(f"/etc/audit/rules.d lacks {join_limited(disk_missing, 4)}")
    if loaded_missing:
        problems.append(f"the running audit configuration lacks {join_limited(loaded_missing, 4)}")
    if problems:
        return failed("Required audit rules are missing: " + "; ".join(problems) + ".", disk_missing + loaded_missing, **evidence)
    if loaded is None:
        raise EvidenceUnavailable(f"The on-disk audit rules are compliant but the running rules could not be verified: {loaded_error.reason}", loaded_error.permission)
    return passed(f"All required audit rules are present on disk and loaded ({len(disk_ok)} rule requirement(s)).", **evidence)


def _rule_mentions(rules: list[AuditRule], path: str) -> bool:
    return any(_norm(rule.path) == path for rule in rules)


@provider("audit_privileged_commands")
def audit_privileged_commands(system: System, check: dict) -> object:
    scan = filesystem_scan(system)
    if not scan.privileged_mounts:
        # Never pass on an empty inventory: it means no filesystem qualified, not that nothing needs auditing.
        raise EvidenceUnavailable(
            "No filesystem qualified for the setuid/setgid inventory (device-backed and mounted without nosuid or noexec); "
            "review the root filesystem type and mount options"
        )
    files = scan.privileged
    disk = disk_rules(system)
    missing_disk = [path for path in files if not _rule_mentions(disk, path)]
    try:
        loaded = loaded_rules(system)
        missing_loaded = [path for path in files if not _rule_mentions(loaded, path)]
        loaded_error = None
    except EvidenceUnavailable as exc:
        loaded, missing_loaded, loaded_error = None, [], exc
    evidence = {
        "privileged_files": files[:1000],
        "not_in_rules_files": missing_disk[:1000],
        "not_in_loaded_rules": missing_loaded[:1000],
        "partitions_scanned": scan.privileged_mounts,
    }
    if missing_disk or missing_loaded:
        parts = []
        if missing_disk:
            parts.append(f"{len(missing_disk)} not in /etc/audit/rules.d (e.g. {join_limited(missing_disk, 3)})")
        if missing_loaded:
            parts.append(f"{len(missing_loaded)} not in the running rules (e.g. {join_limited(missing_loaded, 3)})")
        return failed(f"Of {len(files)} setuid/setgid program(s): " + "; ".join(parts) + ".", cap(sorted(set(missing_disk + missing_loaded))), **evidence)
    if loaded is None:
        raise EvidenceUnavailable(f"On-disk rules cover all {len(files)} privileged programs but the running rules could not be read: {loaded_error.reason}", loaded_error.permission)
    return passed(f"All {len(files)} setuid/setgid program(s) are audited on disk and in the running configuration.", **evidence)


@provider("audit_rules_directive")
def audit_rules_directive(system: System, check: dict) -> object:
    directive = check["directive"]
    matches = [rule for rule in disk_rules(system) if rule.options[: len(directive)] == directive]
    evidence = {"matches": [f"{rule.origin}: {rule.raw}" for rule in matches]}
    shown = " ".join(directive)
    if matches:
        return passed(f"'{shown}' is present in the audit rules ({matches[-1].origin}).", **evidence)
    return failed(f"No '{shown}' directive exists in /etc/audit/rules.d/*.rules.", ["/etc/audit/rules.d"], **evidence)


# ----------------------------------------------------------------------- AIDE
@provider("aide_audit_tools")
def aide_audit_tools(system: System, check: dict) -> object:
    aide = system.which("aide")
    if aide is None:
        return failed("The aide command was not found; install AIDE.", ["aide"])
    config = next((path for path in ("/etc/aide/aide.conf", "/etc/aide.conf") if system.is_file(path)), None)
    if config is None:
        return failed("No aide.conf was found.", ["/etc/aide/aide.conf"])
    required = check.get("options", ["p", "i", "n", "u", "g", "s", "b", "acl", "xattrs", "sha512"])
    tool_dir = system.realpath("/sbin")
    problems, details = [], {}
    for tool in AUDIT_TOOLS:
        path = f"{tool_dir}/{tool}"
        if not system.exists(path):
            continue
        result = system.run([aide, "--config", config, "-p", f"f:{path}"], collector="integrity")
        output = result.stdout + result.stderr
        details[tool] = output.strip()[:400]
        missing = [item for item in required if not re.search(r"(\s|\+)" + re.escape(item) + r"(\s|\+|$)", output)]
        if missing:
            problems.append(f"{tool} lacks {','.join(missing)}")
    evidence = {"aide_config": config, "rule_output": details}
    if not details:
        return failed("No audit tools were found to verify.", ["auditd"], **evidence)
    if problems:
        return failed("AIDE does not protect every audit tool with the required attributes: " + "; ".join(problems) + ".", list(details), **evidence)
    return passed(f"AIDE monitors {', '.join(details)} with {'+'.join(required)}.", **evidence)
