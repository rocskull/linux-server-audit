"""OpenSSH server checks based on the effective ``sshd -T`` configuration."""

from __future__ import annotations

import re

from lsa.checks.common import as_int, describe_rule, failed, passed, provider, rule_ok, source
from lsa.system import EvidenceUnavailable, System


def primary_address(system: System) -> str:
    def build() -> str:
        command = system.which("ip")
        if command and system.real_root:
            result = system.run([command, "-o", "-4", "addr", "show", "scope", "global"], collector="network")
            match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", result.stdout)
            if match:
                return match.group(1)
        return "127.0.0.1"

    return system.cached("primary-address", "network", build)


def sshd_contexts(system: System) -> list[str]:
    """Connection contexts evaluated with ``sshd -T -C``.

    CIS audits the running configuration as the root user connecting from the
    local host name and address. Additional contexts for users covered by
    Match blocks can be configured through ``sshd_match_contexts``.
    """
    contexts = [f"user=root,host={system.hostname()},addr={primary_address(system)}"]
    contexts.extend(str(item) for item in system.settings.get("sshd_match_contexts", []) if str(item).strip())
    return contexts


def sshd_config(system: System, context: str) -> dict[str, list[str]]:
    def build() -> dict[str, list[str]]:
        sshd = system.command("sshd")
        result = system.run([sshd, "-T", "-C", context], collector="ssh")
        if not result.ok:
            detail = result.describe()
            if not system.is_root:
                raise EvidenceUnavailable(f"'sshd -T' requires root to read the host keys ({detail})", "root")
            raise EvidenceUnavailable(f"'sshd -T' could not produce the effective configuration: {detail}")
        values: dict[str, list[str]] = {}
        for line in result.stdout.splitlines():
            key, _, value = line.strip().partition(" ")
            if key:
                values.setdefault(key.lower(), []).append(value.strip())
        system.record(
            "ssh",
            f"effective[{context}]",
            {key: value if len(value) > 1 else value[0] for key, value in sorted(values.items())},
        )
        return values

    return system.cached(f"sshd-T:{context}", "ssh", build)


def sshd_primary(system: System) -> dict[str, list[str]]:
    return sshd_config(system, sshd_contexts(system)[0])


def sshd_config_files(system: System) -> list[str]:
    """sshd_config and every file reached through Include directives."""

    def build() -> list[str]:
        files: list[str] = []

        def visit(path: str) -> None:
            if path in files or not system.is_file(path):
                return
            files.append(path)
            for line in system.lines(path) or []:
                match = re.match(r"^\s*Include\s+(.+)$", line, re.IGNORECASE)
                if not match:
                    continue
                for pattern in match.group(1).split():
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    directory, _, name = pattern.rpartition("/")
                    for item in system.glob(directory or "/", name, files_only=True):
                        visit(item)

        visit("/etc/ssh/sshd_config")
        system.record("ssh", "configuration_files", files)
        return files

    return system.cached("sshd-config-files", "ssh", build)


def _include_directories(system: System) -> list[str]:
    directories = ["/etc/ssh/sshd_config.d"]
    for path in sshd_config_files(system):
        for line in system.lines(path) or []:
            match = re.match(r"^\s*Include\s+(.+)$", line, re.IGNORECASE)
            if match:
                for pattern in match.group(1).split():
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    directories.append(pattern.rpartition("/")[0])
    return list(dict.fromkeys(directories))


@source("sshd_config_dropins")
def sshd_config_dropins(system: System) -> list[str]:
    files = [path for path in sshd_config_files(system) if path != "/etc/ssh/sshd_config"]
    for directory in _include_directories(system):
        files.extend(system.glob(directory, "*.conf", files_only=True))
    return list(dict.fromkeys(files))


@source("sshd_include_dirs")
def sshd_include_dirs(system: System) -> list[str]:
    return [path for path in _include_directories(system) if system.is_dir(path)]


@source("sshd_private_hostkeys")
def sshd_private_hostkeys(system: System) -> list[str]:
    return [path for path in sshd_primary(system).get("hostkey", []) if system.is_file(path)]


@source("sshd_public_hostkeys")
def sshd_public_hostkeys(system: System) -> list[str]:
    return [f"{path}.pub" for path in sshd_primary(system).get("hostkey", []) if system.is_file(f"{path}.pub")]


@source("sshd_banner")
def sshd_banner(system: System) -> list[str]:
    banner = (sshd_primary(system).get("banner") or ["none"])[0]
    return [banner] if banner.startswith("/") and system.exists(banner) else []


def _evaluate(value: list[str] | None, rule: dict) -> tuple[bool, str]:
    current = value[0] if value else None
    op = rule["op"]
    if op == "no_weak":
        offered = [item.strip().lower() for item in (current or "").split(",") if item.strip()]
        weak = [item for item in offered if item in {w.lower() for w in rule["values"]}]
        return not weak, ", ".join(weak) if weak else (current or "")
    if op == "maxstartups":
        # CIS: split start:rate:full and fail when any part exceeds 10:30:60.
        numbers = [as_int(item) for item in (current or "").split(":")]
        ok = bool(numbers) and numbers[0] is not None and all(
            number is None or number <= limit for number, limit in zip(numbers, rule["limits"])
        )
        return ok, current or ""
    if op == "present":
        return bool(value), "; ".join(value or [])
    return rule_ok(current, rule), current if current is not None else "not set"


@provider("sshd_option")
def sshd_option(system: System, check: dict) -> object:
    problems, observed = [], {}
    contexts = sshd_contexts(system)
    for context in contexts:
        values = sshd_config(system, context)
        for setting in check["settings"]:
            option = setting["option"].lower()
            ok, shown = _evaluate(values.get(option), setting["rule"])
            label = option if len(contexts) == 1 else f"{option} [{context}]"
            observed[label] = values.get(option, ["not set"])[0] if len(values.get(option, [])) <= 1 else values[option]
            if not ok:
                expected = setting.get("expected") or describe_rule(setting["rule"])
                if setting["rule"]["op"] == "no_weak":
                    problems.append(f"{label} allows weak algorithm(s): {shown}")
                else:
                    problems.append(f"{label} is {shown or 'not set'} (expected {expected})")
    config_limit = check.get("config_file_limit")
    if config_limit:
        keyword = config_limit["keyword"]
        for path in sshd_config_files(system):
            for number, line in enumerate(system.lines(path) or [], 1):
                match = re.match(rf"^\s*{keyword}\s+\"?(\d+)", line, re.IGNORECASE)
                if match and int(match.group(1)) > int(config_limit["max"]):
                    problems.append(f"{path}:{number} sets {keyword} {match.group(1)} (for example inside a Match block)")
    evidence = {"effective_settings": observed, "contexts": contexts}
    if check.get("informational"):
        evidence["note"] = check["informational"]
    if problems:
        return failed("; ".join(problems) + ".", sorted(observed), **evidence)
    shown = ", ".join(f"{key} {value}" for key, value in observed.items())
    return passed(f"Effective sshd configuration: {shown}.", **evidence)


@provider("sshd_access")
def sshd_access(system: System, check: dict) -> object:
    values = sshd_primary(system)
    configured = {key: values[key] for key in ("allowusers", "allowgroups", "denyusers", "denygroups") if values.get(key)}
    if configured:
        shown = "; ".join(f"{key} {' '.join(items)}" for key, items in configured.items())
        return passed(f"sshd restricts access with {shown}; confirm the lists match site policy.", access_lists=configured)
    return failed(
        "No AllowUsers, AllowGroups, DenyUsers or DenyGroups directive limits which accounts may log in over SSH.",
        ["sshd"],
        access_lists={},
    )


@provider("sshd_banner_configured")
def sshd_banner_configured(system: System, check: dict) -> object:
    from lsa.checks.common import os_identity_pattern

    banner = (sshd_primary(system).get("banner") or ["none"])[0]
    if not banner.startswith("/"):
        return failed("sshd has no Banner configured (Banner none).", ["sshd"], banner=banner)
    if not system.is_file(banner):
        return failed(f"sshd Banner points to {banner}, which does not exist.", [banner], banner=banner)
    pattern = os_identity_pattern(system)
    matches = [f"{banner}:{n}: {line.strip()[:120]}" for n, line in enumerate(system.lines(banner) or [], 1) if pattern.search(line)]
    if matches:
        return failed(f"The sshd banner discloses system details: {'; '.join(matches[:3])}.", [banner], banner=banner, disclosures=matches)
    return passed(f"sshd displays {banner}, which contains no OS name or escape sequences; confirm the wording meets site policy.", banner=banner)
