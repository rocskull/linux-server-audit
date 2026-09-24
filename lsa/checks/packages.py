"""Package, systemd unit and APT repository checks."""

from __future__ import annotations

import re

from lsa.checks.common import as_bool, failed, join_limited, passed, provider, source
from lsa.system import EvidenceUnavailable, System

STANDARD_KEYRING_DIRS = ("/usr/share/keyrings/", "/etc/apt/trusted.gpg.d/")


# ------------------------------------------------------------------ packages
@provider("package_installed")
def package_installed(system: System, check: dict) -> object:
    sets = check.get("any_of") or [check["packages"]]
    evidence = {"alternatives": sets, "installed": {name: system.packages()[name].version for s in sets for name in s if system.package_installed(name)}}
    for option in sets:
        if all(system.package_installed(name) for name in option):
            versions = ", ".join(f"{name} {system.packages()[name].version}" for name in option)
            return passed(f"Installed: {versions}.", **evidence)
    missing = [" + ".join(name for name in option if not system.package_installed(name)) for option in sets]
    wanted = " or ".join(" + ".join(option) for option in sets)
    return failed(f"Required package(s) are not installed ({wanted}); missing: {'; '.join(missing)}.", [wanted], **evidence)


@provider("package_absent")
def package_absent(system: System, check: dict) -> object:
    found = [name for name in check.get("packages", []) if system.package_installed(name)]
    for pattern in check.get("patterns", []):
        found.extend(system.packages_matching(pattern))
    found = sorted(set(found))
    listed = check.get("packages", []) + [f"/{p}/" for p in check.get("patterns", [])]
    evidence = {"checked": listed, "installed": {name: system.packages()[name].version for name in found}}
    if found:
        return failed(f"Installed but should be removed: {', '.join(found)}.", found, **evidence)
    return passed(f"None of {join_limited(listed)} is installed.", **evidence)


def debian_version_compare(left: str, right: str) -> int:
    """Compare two Debian versions like ``dpkg --compare-versions``."""

    def split(version: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in version:
            head, version = version.split(":", 1)
            epoch = int(head) if head.isdigit() else 0
        upstream, revision = version, "0"
        if "-" in version:
            upstream, revision = version.rsplit("-", 1)
        return epoch, upstream, revision

    def order(char: str) -> int:
        if char == "" or "0" <= char <= "9":
            return 0
        if "a" <= char.lower() <= "z":
            return ord(char)
        if char == "~":
            return -1
        return ord(char) + 256

    def digit(text: str, index: int) -> bool:
        return index < len(text) and "0" <= text[index] <= "9"

    def verrevcmp(a: str, b: str) -> int:
        i = j = 0
        while i < len(a) or j < len(b):
            first_diff = 0
            while (i < len(a) and not digit(a, i)) or (j < len(b) and not digit(b, j)):
                ac = order(a[i] if i < len(a) else "")
                bc = order(b[j] if j < len(b) else "")
                if ac != bc:
                    return ac - bc
                i += 1
                j += 1
            while i < len(a) and a[i] == "0":
                i += 1
            while j < len(b) and b[j] == "0":
                j += 1
            while digit(a, i) and digit(b, j):
                if not first_diff:
                    first_diff = ord(a[i]) - ord(b[j])
                i += 1
                j += 1
            if digit(a, i):
                return 1
            if digit(b, j):
                return -1
            if first_diff:
                return first_diff
        return 0

    left_epoch, left_upstream, left_revision = split(left)
    right_epoch, right_upstream, right_revision = split(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    for a, b in ((left_upstream, right_upstream), (left_revision, right_revision)):
        result = verrevcmp(a, b)
        if result:
            return 1 if result > 0 else -1
    return 0


def apt_policy(system: System, package: str) -> dict[str, str | None]:
    def build() -> dict[str, str | None]:
        result = system.run([system.command("apt-cache"), "policy", "--", package], collector="apt")
        if not result.ok:
            raise EvidenceUnavailable(f"Unable to read the APT candidate version: {result.describe()}")
        installed = re.search(r"(?m)^\s+Installed:\s*(\S+)", result.stdout)
        candidate = re.search(r"(?m)^\s+Candidate:\s*(\S+)", result.stdout)
        return {
            "installed": installed.group(1) if installed else None,
            "candidate": candidate.group(1) if candidate else None,
        }

    return system.cached(f"apt-policy:{package}", "apt", build)


@provider("package_current")
def package_current(system: System, check: dict) -> object:
    package = check["package"]
    if not system.package_installed(package):
        return failed(f"{package} is not installed.", [package], package=package)
    policy = apt_policy(system, package)
    installed = system.packages()[package].version
    candidate = policy["candidate"]
    lists = system.glob("/var/lib/apt/lists", "*_Packages*")
    evidence = {"package": package, "installed": installed, "candidate": candidate, "package_index_files": len(lists)}
    if not candidate or candidate == "(none)" or not lists:
        raise EvidenceUnavailable(
            f"No APT candidate version is known for {package}; refresh the package lists (apt update) and re-run"
        )
    if debian_version_compare(candidate, installed) > 0:
        return failed(f"{package} {installed} is installed but {candidate} is available.", [package], **evidence)
    return passed(f"{package} {installed} is the newest version known to APT (as of the last package list refresh).", **evidence)


# --------------------------------------------------------------------- units
def _unit_problems(state, want_enabled: list[str] | None, want_active: bool | None) -> list[str]:
    problems = []
    if want_enabled is not None and state.unit_file_state not in want_enabled:
        current = state.unit_file_state or ("not found" if not state.exists else "unknown")
        problems.append(f"{state.name} is {current} (expected {' or '.join(want_enabled)})")
    if want_active is True and not state.active:
        problems.append(f"{state.name} is {state.active_state or 'not active'} (expected active)")
    return problems


@provider("unit_state")
def unit_state(system: System, check: dict) -> object:
    specs = check["units"]
    states = system.units([item["name"] for item in specs])
    evidence = {name: {"unit_file_state": s.unit_file_state, "active_state": s.active_state, "load_state": s.load_state} for name, s in states.items()}
    if check.get("mode") == "any_existing":
        existing = [item for item in specs if states[item["name"]].exists]
        if not existing:
            names = " / ".join(item["name"] for item in specs)
            return failed(f"No {names} unit exists on this system.", [names], units=evidence)
        specs = existing
    problems = []
    for item in specs:
        enabled = item.get("enabled_states") or (["enabled", "enabled-runtime"] if item.get("enabled", True) else None)
        problems.extend(_unit_problems(states[item["name"]], enabled, item.get("active", True)))
    if problems:
        return failed("; ".join(problems) + ".", [item["name"] for item in specs], units=evidence)
    names = ", ".join(item["name"] for item in specs)
    return passed(f"{names} {'is' if len(specs) == 1 else 'are'} enabled and running as required.", units=evidence)


@provider("units_not_in_use")
def units_not_in_use(system: System, check: dict) -> object:
    names = check["units"]
    states = system.units(names)
    evidence = {name: {"unit_file_state": s.unit_file_state, "active_state": s.active_state} for name, s in states.items()}
    violations = []
    for name, state in states.items():
        if state.enabled:
            violations.append(f"{name} is enabled")
        if state.active:
            violations.append(f"{name} is active")
    if violations:
        return failed("; ".join(violations) + ".", [name for name in names if states[name].enabled or states[name].active], units=evidence)
    return passed(f"{', '.join(names)} {'is' if len(names) == 1 else 'are'} neither enabled nor active.", units=evidence)


@provider("service_not_in_use")
def service_not_in_use(system: System, check: dict) -> object:
    installed_groups = []
    checked = []
    for group in check["groups"]:
        names = [name for name in group.get("packages", []) if system.package_installed(name)]
        checked.extend(group.get("packages", []))
        if group.get("package_pattern"):
            names.extend(system.packages_matching(group["package_pattern"]))
            checked.append(f"/{group['package_pattern']}/")
        if names:
            installed_groups.append((group, sorted(set(names))))
    if not installed_groups:
        return passed(f"{join_limited(checked)} {'is' if len(checked) == 1 else 'are'} not installed.", packages_checked=checked)
    packages = sorted({name for _, names in installed_groups for name in names})
    units = [unit for group, _ in installed_groups for unit in group.get("units", [])]
    states = system.units(units)
    evidence = {
        "installed_packages": {name: system.packages()[name].version for name in packages},
        "units": {name: {"unit_file_state": s.unit_file_state, "active_state": s.active_state} for name, s in states.items()},
    }
    violations = []
    for name, state in states.items():
        if state.enabled:
            violations.append(f"{name} is enabled")
        if state.active:
            violations.append(f"{name} is active")
    if violations:
        return failed(f"{', '.join(packages)} installed and {'; '.join(violations)}.", packages, **evidence)
    return passed(
        f"{', '.join(packages)} {'is' if len(packages) == 1 else 'are'} installed but {', '.join(units)} "
        f"{'is' if len(units) == 1 else 'are'} neither enabled nor active; confirm the package is still required.",
        **evidence,
    )


# ----------------------------------------------------------------------- APT
def apt_config(system: System) -> dict[str, str]:
    def build() -> dict[str, str]:
        result = system.run([system.command("apt-config"), "dump"], collector="apt")
        if not result.ok:
            raise EvidenceUnavailable(f"Unable to read the APT configuration: {result.describe()}")
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.match(r'^(\S+?)\s+"(.*)";\s*$', line)
            if match:
                values[match.group(1).lower()] = match.group(2)
        system.record(
            "apt",
            "security_settings",
            {key: value for key, value in values.items() if key.startswith(("acquire::allow", "acquire::check", "apt::install-"))},
        )
        return values

    return system.cached("apt-config", "apt", build)


@provider("apt_config")
def apt_config_check(system: System, check: dict) -> object:
    values = apt_config(system)
    problems, observed = [], {}
    for setting in check["settings"]:
        key, wanted = setting["key"], bool(setting["value"])
        actual = values.get(key.lower())
        observed[key] = actual
        if actual is None:
            problems.append(f"{key} is not explicitly configured")
        elif as_bool(actual) is not wanted:
            problems.append(f'{key} is "{actual}"')
    wanted_text = ", ".join(f'{s["key"]} "{1 if s["value"] else 0}"' for s in check["settings"])
    if problems:
        return failed(f"APT should set {wanted_text}, but " + "; ".join(problems) + ".", [s["key"] for s in check["settings"]], settings=observed)
    return passed(f"APT sets {wanted_text}.", settings=observed)


def _source_files(system: System, scope: str) -> list[str]:
    if scope == "sources.list":
        return ["/etc/apt/sources.list"] if system.is_file("/etc/apt/sources.list") else []
    return system.glob("/etc/apt/sources.list.d", "*.list", files_only=True) + system.glob(
        "/etc/apt/sources.list.d", "*.sources", files_only=True
    )


@provider("apt_sources_https")
def apt_sources_https(system: System, check: dict) -> object:
    files = _source_files(system, check["scope"])
    insecure = []
    for path in files:
        lines = system.lines(path) or []
        if path.endswith(".sources"):
            for stanza in "\n".join(lines).split("\n\n"):
                if re.search(r"(?im)^\s*Enabled:\s*no\b", stanza):
                    continue
                for match in re.finditer(r"(?im)^\s*URIs:\s*(.+)$", stanza):
                    for uri in match.group(1).split():
                        if uri.lower().startswith("http://"):
                            insecure.append(f"{path}: {uri}")
        else:
            for number, line in enumerate(lines, 1):
                match = re.match(r"^\s*deb(-src)?\s+(\[[^\]]*\]\s+)?(http://\S+)", line, re.IGNORECASE)
                if match:
                    insecure.append(f"{path}:{number}: {match.group(3)}")
    evidence = {"files": files, "plain_http_entries": insecure}
    if not files:
        return passed(f"No repository definitions exist in {check['scope']}.", **evidence)
    if insecure:
        return failed(f"{len(insecure)} repository entr(ies) use plain HTTP: {join_limited(insecure, 5)}.", insecure, **evidence)
    return passed(f"All repositories defined in {join_limited(files, 5)} use HTTPS or a non-HTTP transport.", **evidence)


@source("apt_keyring_files")
def apt_keyring_files(system: System) -> list[str]:
    files = []
    for directory in STANDARD_KEYRING_DIRS:
        files.extend(system.walk_files(directory.rstrip("/"), name_pattern="*gpg", follow_links=True))
    return files


@source("apt_signed_by_keys")
def apt_signed_by_keys(system: System) -> list[str]:
    files = []
    candidates = []
    for path in ["/etc/apt/sources.list"] + _source_files(system, "sources.list.d"):
        text = system.read_text(path) or ""
        candidates.extend(re.findall(r"(?i)\bSigned-By\b\s*[=:]\s*(/[^\s\]]+)", text))
    for candidate in sorted(set(candidates)):
        if not system.exists(candidate):
            continue
        resolved = system.realpath(candidate)
        if resolved.startswith(STANDARD_KEYRING_DIRS):
            continue
        files.append(resolved)
    return files
