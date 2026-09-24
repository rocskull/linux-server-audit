"""Local account, password policy and user environment checks."""

from __future__ import annotations

import os
import re
import stat as stat_module
import time

from lsa.checks.common import (
    cap,
    describe_rule,
    failed,
    join_limited,
    max_mode_text,
    passed,
    provider,
    require_root,
    rule_ok,
)
from lsa.system import EvidenceUnavailable, System

REMOTE_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb3", "fuse.sshfs", "afs", "ncpfs", "glusterfs", "ceph"}
SYSTEM_ACCOUNT_EXCEPTIONS = {"root", "halt", "sync", "shutdown", "nfsnobody"}


# --------------------------------------------------------- password policy
@provider("password_aging")
def password_aging(system: System, check: dict) -> object:
    key, field, rule = check["login_defs"], check["field"], check["rule"]
    configured = system.login_defs().get(key)
    problems = []
    if configured is None:
        problems.append(f"{key} is not set in /etc/login.defs")
    elif not rule_ok(configured, rule):
        problems.append(f"/etc/login.defs sets {key} {configured}")
    users = [entry for entry in system.shadow() if entry.hashed]
    bad = [f"{entry.name} ({getattr(entry, field) or 'empty'})" for entry in users if not rule_ok(getattr(entry, field) or None, rule)]
    if bad:
        problems.append(f"{len(bad)} account(s) with a password have a non-compliant value: {join_limited(bad, 8)}")
    evidence = {"login_defs": {key: configured}, "accounts_with_passwords": len(users), "non_compliant_accounts": bad}
    if problems:
        return failed(f"{key} should be {describe_rule(rule)}: " + "; ".join(problems) + ".", [item.split(" ")[0] for item in bad] or ["/etc/login.defs"], **evidence)
    return passed(f"{key} is {configured} and all {len(users)} account(s) with a password comply.", **evidence)


@provider("encrypt_method")
def encrypt_method(system: System, check: dict) -> object:
    value = system.login_defs().get("ENCRYPT_METHOD")
    allowed = [item.upper() for item in check["allowed"]]
    evidence = {"ENCRYPT_METHOD": value}
    if value is None:
        return failed("ENCRYPT_METHOD is not set in /etc/login.defs.", ["/etc/login.defs"], **evidence)
    if value.upper() not in allowed:
        return failed(f"ENCRYPT_METHOD is {value}; it should be {' or '.join(allowed)}.", ["/etc/login.defs"], **evidence)
    return passed(f"New passwords are hashed with {value.upper()}.", **evidence)


def _useradd_inactive(system: System) -> str:
    command = system.which("useradd")
    if command and system.real_root:
        result = system.run([command, "-D"], collector="accounts")
        match = re.search(r"(?m)^INACTIVE=(-?\d+)", result.stdout)
        if result.ok and match:
            return match.group(1)
    for line in system.lines("/etc/default/useradd") or []:
        match = re.match(r"^\s*INACTIVE\s*=\s*(-?\d+)", line)
        if match:
            return match.group(1)
    return "-1"


@provider("inactive_lock")
def inactive_lock(system: System, check: dict) -> object:
    rule = {"op": "range", "min": 0, "max": int(check.get("max", 45))}
    default = _useradd_inactive(system)
    problems = []
    if not rule_ok(default, rule):
        problems.append(f"the useradd default INACTIVE is {default}")
    users = [entry for entry in system.shadow() if entry.hashed]
    bad = [f"{entry.name} ({entry.inactive or 'empty'})" for entry in users if not rule_ok(entry.inactive or None, rule)]
    if bad:
        problems.append(f"{len(bad)} account(s) have a non-compliant inactivity period: {join_limited(bad, 8)}")
    evidence = {"useradd_default_inactive": default, "non_compliant_accounts": bad}
    if problems:
        return failed(f"Inactive password lock should be {describe_rule(rule)} days: " + "; ".join(problems) + ".", [item.split(" ")[0] for item in bad] or ["/etc/default/useradd"], **evidence)
    return passed(f"Accounts are locked after at most {default} day(s) of password inactivity.", **evidence)


@provider("password_change_past")
def password_change_past(system: System, check: dict) -> object:
    today = int(time.time() // 86400)
    future = []
    for entry in system.shadow():
        if not entry.hashed:
            continue
        try:
            days = int(entry.lastchg)
        except ValueError:
            continue
        if days > today:
            future.append(f"{entry.name} ({time.strftime('%Y-%m-%d', time.gmtime(days * 86400))})")
    if future:
        return failed(f"Last password change is in the future for: {', '.join(future)}.", [item.split(" ")[0] for item in future], accounts=future)
    return passed("No account has a last password change date in the future.", accounts=[])


# ------------------------------------------------------------ root/system
@provider("uid_zero")
def uid_zero(system: System, check: dict) -> object:
    names = [entry.name for entry in system.passwd() if entry.uid == 0]
    extra = [name for name in names if name != "root"]
    if extra or names != ["root"]:
        return failed(f"UID 0 is assigned to: {', '.join(names) or 'no account'}; only root may use UID 0.", extra or ["root"], uid0_accounts=names)
    return passed("root is the only account with UID 0.", uid0_accounts=names)


@provider("gid_zero_users")
def gid_zero_users(system: System, check: dict) -> object:
    names = [entry.name for entry in system.passwd() if entry.gid == 0 and not re.match(r"^(sync|shutdown|halt|operator)", entry.name)]
    extra = [name for name in names if name != "root"]
    root = next((entry for entry in system.passwd() if entry.name == "root"), None)
    problems = []
    if extra:
        problems.append(f"accounts with primary GID 0: {', '.join(extra)}")
    if root is None or root.gid != 0:
        problems.append("root does not have primary GID 0")
    if problems:
        return failed("; ".join(problems) + ".", extra or ["root"], gid0_accounts=names)
    return passed("root is the only account whose primary group is GID 0.", gid0_accounts=names)


@provider("gid_zero_groups")
def gid_zero_groups(system: System, check: dict) -> object:
    names = [entry.name for entry in system.group() if entry.gid == 0]
    extra = [name for name in names if name != "root"]
    if extra:
        return failed(f"Groups other than root use GID 0: {', '.join(extra)}.", extra, gid0_groups=names)
    return passed("The root group is the only group with GID 0.", gid0_groups=names)


@provider("root_access")
def root_access(system: System, check: dict) -> object:
    entry = next((item for item in system.shadow() if item.name == "root"), None)
    status = entry.status if entry else "missing"
    if status in ("P", "L"):
        meaning = "a password is set" if status == "P" else "the account is locked"
        return passed(f"root access is controlled: {meaning} (passwd -S status {status}).", status=status)
    return failed("root has no password and is not locked (passwd -S status NP)." if status == "NP" else "root has no /etc/shadow entry.", ["root"], status=status)


def root_login_path(system: System) -> str:
    def build() -> str:
        require_root(system, "Evaluating root's login PATH")
        root = next((entry for entry in system.passwd() if entry.name == "root"), None)
        shell = root.shell if root and os.path.basename(root.shell) in ("bash", "sh", "dash", "zsh", "ksh") else "/bin/bash"
        supath = system.login_defs().get("ENV_SUPATH", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        env = {"HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": shell, "PATH": supath.split("=", 1)[-1], "TERM": "dumb"}
        result = system.run([shell, "-l", "-c", 'printf "%s" "$PATH"'], collector="accounts", env=env, timeout=20)
        if not result.ok and not result.stdout:
            raise EvidenceUnavailable(f"Unable to evaluate root's login environment: {result.describe()}")
        path = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        system.record("accounts", "root_login_path", path)
        return path

    return system.cached("root-path", "accounts", build)


@provider("root_path")
def root_path(system: System, check: dict) -> object:
    value = root_login_path(system)
    problems = []
    if "::" in value:
        problems.append("contains an empty directory (::)")
    if value.startswith(":"):
        problems.append("starts with an empty directory (:)")
    if re.search(r":\s*$", value):
        problems.append("ends with a trailing (:)")
    if re.search(r"(^\s*|:)\.(:|\s*$)", value):
        problems.append("contains the current working directory (.)")
    offending = []
    for entry in [item for item in value.split(":") if item and item != "."]:
        meta = system.meta(entry)
        if meta is None or not meta.is_dir:
            problems.append(f"{entry} is not a directory")
            offending.append(entry)
            continue
        owner = system.user_name(meta.uid)
        if owner != "root":
            problems.append(f"{entry} is owned by {owner}")
            offending.append(entry)
        if meta.permissions & 0o022:
            problems.append(f"{entry} is mode {meta.octal} (should be 0755 or more restrictive)")
            offending.append(entry)
    if problems:
        return failed(f"root's PATH ({value}) " + "; ".join(problems) + ".", sorted(set(offending)) or ["root PATH"], path=value)
    return passed(f"Every directory in root's PATH ({value}) exists, is owned by root and is not group/world-writable.", path=value)


def umask_value(text: str) -> int | None:
    """Mask bits of a umask argument (octal or u=,g=,o= symbolic form)."""
    text = text.strip().strip("\"'")
    if re.fullmatch(r"[0-7]{1,4}", text):
        return int(text, 8) & 0o777
    if re.fullmatch(r"([ugoa]*=[rwx]*,?)+", text):
        allowed = {"u": 0, "g": 0, "o": 0}
        for clause in text.split(","):
            if not clause:
                continue
            who, _, perms = clause.partition("=")
            bits = (4 if "r" in perms else 0) | (2 if "w" in perms else 0) | (1 if "x" in perms else 0)
            for target in (who or "a").replace("a", "ugo"):
                allowed[target] = bits
        return 0o777 & ~((allowed["u"] << 6) | (allowed["g"] << 3) | allowed["o"])
    return None


def _umask_findings(system: System, files: list[str], pattern: str) -> tuple[list[str], list[str]]:
    compliant, violations = [], []
    regex = re.compile(pattern, re.IGNORECASE)
    for path in files:
        for number, line in enumerate(system.lines(path) or [], 1):
            match = regex.match(line)
            if not match:
                continue
            value = match.group(1)
            mask = umask_value(value)
            where = f"{path}:{number}: {line.strip()}"
            if mask is None:
                if "+" in value and re.search(r"[go]\+|a\+", value):
                    violations.append(where)
                continue
            (compliant if mask & 0o027 == 0o027 else violations).append(where)
    return compliant, violations


@provider("root_umask")
def root_umask(system: System, check: dict) -> object:
    compliant, violations = _umask_findings(system, ["/root/.profile", "/root/.bashrc"], r"^\s*umask\s+(\S+)")
    evidence = {"compliant": compliant, "non_compliant": violations}
    if violations:
        return failed(f"root's shell startup files set a umask less restrictive than 0027: {join_limited(violations, 3)}.", [v.split(":", 1)[0] for v in violations], **evidence)
    return passed("root's .profile and .bashrc do not set a umask less restrictive than 0027.", **evidence)


@provider("default_umask")
def default_umask(system: System, check: dict) -> object:
    files = ["/etc/profile"] + system.glob("/etc/profile.d", "*.sh", files_only=True)
    compliant, violations = _umask_findings(system, files, r"^\s*umask\s+(\S+)")
    login_defs = system.login_defs().get("UMASK")
    evidence = {"profile_umask": compliant + violations, "login_defs_UMASK": login_defs}
    if login_defs is not None:
        mask = umask_value(login_defs)
        entry = f"/etc/login.defs: UMASK {login_defs}"
        (compliant if mask is not None and mask & 0o027 == 0o027 else violations).append(entry)
    if violations:
        return failed(f"A system-wide umask less restrictive than 027 is configured: {join_limited(violations, 4)}.", sorted({v.split(':', 1)[0] for v in violations}), **evidence)
    if not compliant:
        return failed("No system-wide umask is configured, so the default 022 applies.", ["/etc/login.defs"], **evidence)
    return passed(f"The system-wide umask is 027 or more restrictive ({join_limited(compliant, 3)}).", **evidence)


@provider("system_account_shells")
def system_account_shells(system: System, check: dict) -> object:
    shells = set(system.valid_shells())
    uid_min = system.uid_min()
    offending = [
        f"{entry.name} ({entry.shell})"
        for entry in system.passwd()
        if entry.name not in SYSTEM_ACCOUNT_EXCEPTIONS and (entry.uid < uid_min or entry.uid == 65534) and entry.shell in shells
    ]
    evidence = {"uid_min": uid_min, "valid_shells": sorted(shells), "service_accounts_with_shell": offending}
    if offending:
        return failed(f"System accounts have a valid login shell: {join_limited(offending, 8)}.", [item.split(" ")[0] for item in offending], **evidence)
    return passed("No system account (UID below UID_MIN or 65534) has a valid login shell.", **evidence)


@provider("nologin_accounts_locked")
def nologin_accounts_locked(system: System, check: dict) -> object:
    shells = set(system.valid_shells())
    status = {entry.name: entry.status for entry in system.shadow()}
    unlocked = [
        f"{entry.name} ({status.get(entry.name, 'no shadow entry')})"
        for entry in system.passwd()
        if entry.name != "root" and entry.shell not in shells and status.get(entry.name) != "L"
    ]
    evidence = {"unlocked_accounts_without_shell": unlocked}
    if unlocked:
        return failed(f"Accounts without a valid login shell are not locked: {join_limited(unlocked, 8)}.", [item.split(" ")[0] for item in unlocked], **evidence)
    return passed("Every non-root account without a valid login shell is locked.", **evidence)


@provider("nologin_not_in_shells")
def nologin_not_in_shells(system: System, check: dict) -> object:
    entries = [line.strip() for line in system.lines("/etc/shells") or [] if not line.lstrip().startswith("#") and "/nologin" in line]
    if entries:
        return failed(f"/etc/shells lists nologin: {', '.join(entries)}.", ["/etc/shells"], entries=entries)
    return passed("/etc/shells does not list nologin.", entries=[])


@provider("shell_timeout")
def shell_timeout(system: System, check: dict) -> object:
    maximum = int(check.get("max", 900))
    files = system.glob("/etc", "*bashrc", files_only=True) + ["/etc/profile"] + system.glob("/etc/profile.d", "*.sh", files_only=True)
    readonly_re = re.compile(r"^\s*((typeset|declare)\s+-[a-z]*r[a-z]*\s+TMOUT=\d+|([^#\n\r]+)?\breadonly\s+(-\w+\s+)?TMOUT\b)")
    export_re = re.compile(r"^\s*((typeset|declare)\s+-[a-z]*x[a-z]*\s+TMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)")
    value_re = re.compile(r"^([^#\n\r]+)?\bTMOUT=(\d+)\b")
    problems, good, details = [], [], {}
    for path in files:
        lines = system.lines(path) or []
        relevant = [line for line in lines if re.search(r"^([^#\n\r]+)?\bTMOUT\b", line)]
        if not relevant:
            continue
        values = [int(match.group(2)) for line in relevant for match in [value_re.search(line)] if match]
        readonly = any(readonly_re.search(line) for line in relevant)
        exported = any(export_re.search(line) for line in relevant)
        details[path] = {"values": values, "readonly": readonly, "exported": exported}
        if not values:
            problems.append(f"{path} references TMOUT without setting a value")
            continue
        for value in values:
            if value <= 0 or value > maximum:
                problems.append(f"{path} sets TMOUT={value}")
        if not readonly:
            problems.append(f"{path} does not make TMOUT readonly")
        if not exported:
            problems.append(f"{path} does not export TMOUT")
        if all(0 < value <= maximum for value in values) and readonly and exported:
            good.append(f"{path} (TMOUT={values[-1]})")
    evidence = {"files": details}
    if not details:
        return failed("TMOUT is not configured in /etc/profile, /etc/profile.d or /etc/*bashrc.", ["/etc/profile"], **evidence)
    if problems:
        return failed(f"Shell timeout is not correctly configured: {'; '.join(problems)}.", sorted(details), **evidence)
    return passed(f"Idle shells time out: {', '.join(good)} (readonly and exported).", **evidence)


# ----------------------------------------------------------- local users
@provider("shadowed_passwords")
def shadowed_passwords(system: System, check: dict) -> object:
    offending = [entry.name for entry in system.passwd() if entry.password != "x"]
    if offending:
        return failed(f"Accounts not using shadowed passwords: {', '.join(offending)}.", offending, accounts=offending)
    return passed("Every account in /etc/passwd uses a shadowed password (x).", accounts=[])


@provider("shadow_not_empty")
def shadow_not_empty(system: System, check: dict) -> object:
    offending = [entry.name for entry in system.shadow() if entry.status == "NP"]
    if offending:
        return failed(f"Accounts with an empty password field: {', '.join(offending)}.", offending, accounts=offending)
    return passed("No account in /etc/shadow has an empty password field.", accounts=[])


@provider("passwd_groups_exist")
def passwd_groups_exist(system: System, check: dict) -> object:
    gids = {entry.gid for entry in system.group()}
    offending = [f"{entry.name} (GID {entry.gid})" for entry in system.passwd() if entry.gid not in gids]
    if offending:
        return failed(f"Primary groups missing from /etc/group: {', '.join(offending)}.", [item.split(" ")[0] for item in offending], accounts=offending)
    return passed("Every primary GID in /etc/passwd exists in /etc/group.", accounts=[])


@provider("shadow_group_empty")
def shadow_group_empty(system: System, check: dict) -> object:
    group = next((entry for entry in system.group() if entry.name == "shadow"), None)
    if group is None:
        return passed("There is no shadow group.", members=[], primary=[])
    primary = [entry.name for entry in system.passwd() if entry.gid == group.gid]
    problems = []
    if group.members:
        problems.append(f"the shadow group has members: {', '.join(group.members)}")
    if primary:
        problems.append(f"accounts use shadow as their primary group: {', '.join(primary)}")
    evidence = {"members": list(group.members), "primary": primary}
    if problems:
        return failed("; ".join(problems).capitalize() + ".", list(group.members) + primary, **evidence)
    return passed("The shadow group has no members and is no account's primary group.", **evidence)


@provider("duplicates")
def duplicates(system: System, check: dict) -> object:
    kind = check["kind"]
    if kind in ("uid", "user"):
        pairs = [(str(entry.uid) if kind == "uid" else entry.name, entry.name) for entry in system.passwd()]
        source_name = "/etc/passwd"
    else:
        pairs = [(str(entry.gid) if kind == "gid" else entry.name, entry.name) for entry in system.group()]
        source_name = "/etc/group"
    seen: dict[str, list[str]] = {}
    for key, name in pairs:
        seen.setdefault(key, []).append(name)
    dupes = {key: names for key, names in seen.items() if len(names) > 1}
    label = {"uid": "UID", "gid": "GID", "user": "user name", "group": "group name"}[kind]
    if dupes:
        detail = [f"{label} {key}: {', '.join(names)}" for key, names in dupes.items()]
        return failed(f"Duplicate {label}s exist in {source_name}: {'; '.join(detail)}.", sorted(dupes), duplicates=dupes)
    return passed(f"No duplicate {label}s exist in {source_name}.", duplicates={})


def interactive_users(system: System) -> list:
    shells = set(system.valid_shells())
    return [entry for entry in system.passwd() if entry.shell in shells and entry.home]


def _home_fstype(system: System, home: str) -> str:
    best, fstype = "", ""
    for mount in system.mounts():
        target = mount.target.rstrip("/") or "/"
        if (home == target or home.startswith(target.rstrip("/") + "/") or target == "/") and len(target) >= len(best):
            best, fstype = target, mount.fstype
    return fstype


@provider("home_directories")
def home_directories(system: System, check: dict) -> object:
    problems, affected = [], []
    users = interactive_users(system)
    for entry in users:
        meta = system.meta(entry.home)
        if meta is None or not meta.is_dir:
            problems.append(f"{entry.name}: home {entry.home} does not exist")
            affected.append(entry.home)
            continue
        owner = system.user_name(meta.uid)
        if owner != entry.name:
            problems.append(f"{entry.name}: {entry.home} is owned by {owner}")
            affected.append(entry.home)
        if meta.permissions & 0o027:
            problems.append(f"{entry.name}: {entry.home} is mode {meta.octal} (should be 0750 or more restrictive)")
            affected.append(entry.home)
    evidence = {"interactive_users": [entry.name for entry in users], "problems": problems}
    if problems:
        return failed(f"Interactive user home directories are not secured: {join_limited(problems, 6)}.", cap(sorted(set(affected))), **evidence)
    return passed(f"All {len(users)} interactive user home director(ies) exist, are owned by their user and are 0750 or more restrictive.", **evidence)


def _walk_dot_entries(system: System, home: str, want_dirs: bool) -> list[str]:
    """Paths named .* below a home directory without crossing filesystems."""
    base = system.host_path(home)
    try:
        device = os.lstat(base).st_dev
    except OSError:
        return []
    found = []
    stack = [base]
    while stack:
        directory = stack.pop()
        try:
            iterator = os.scandir(directory)
        except PermissionError:
            raise EvidenceUnavailable(f"Permission denied reading {system.logical_path(directory)}", "root") from None
        except OSError:
            continue
        with iterator:
            for entry in iterator:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if info.st_dev != device:
                    continue
                is_dir = stat_module.S_ISDIR(info.st_mode)
                if entry.name.startswith(".") and (is_dir if want_dirs else stat_module.S_ISREG(info.st_mode)):
                    found.append(system.logical_path(entry.path))
                if is_dir:
                    stack.append(entry.path)
    return sorted(found)


def _primary_group(system: System, entry) -> str:
    return system.group_name(entry.gid)


@provider("dot_files")
def dot_files(system: System, check: dict) -> object:
    problems, affected, warnings, skipped = [], [], [], []
    for entry in interactive_users(system):
        fstype = _home_fstype(system, entry.home)
        if fstype in REMOTE_FS:
            skipped.append(f"{entry.name} ({entry.home} on {fstype})")
            continue
        if not system.is_dir(entry.home):
            continue
        group = _primary_group(system, entry)
        for path in _walk_dot_entries(system, entry.home, want_dirs=False):
            name = os.path.basename(path)
            if name in (".forward", ".rhosts"):
                problems.append(f"{path} exists")
                affected.append(path)
                continue
            mask = 0o177 if name in (".netrc", ".bash_history") else 0o133
            meta = system.meta(path)
            if meta is None:
                continue
            issues = []
            if meta.permissions & mask:
                issues.append(f"mode {meta.octal} (should be {max_mode_text(mask)} or more restrictive)")
            owner = system.user_name(meta.uid)
            if owner != entry.name:
                issues.append(f"owner {owner}")
            file_group = system.group_name(meta.gid)
            if file_group != group:
                issues.append(f"group {file_group} (should be {group})")
            if issues:
                problems.append(f"{path} {', '.join(issues)}")
                affected.append(path)
            elif name == ".netrc":
                warnings.append(f"{path} exists; confirm it is permitted by site policy")
    evidence = {"problems": problems[:500], "warnings": warnings, "skipped_remote_homes": skipped}
    if problems:
        return failed(f"{len(problems)} dot file issue(s) in interactive user homes: {join_limited(problems, 5)}.", cap(affected), **evidence)
    note = f" Note: {'; '.join(warnings)}." if warnings else ""
    return passed(f"Interactive users' dot files have no .forward/.rhosts files and appropriate access.{note}", **evidence)


@provider("dot_directories")
def dot_directories(system: System, check: dict) -> object:
    problems, affected, skipped = [], [], []
    for entry in interactive_users(system):
        fstype = _home_fstype(system, entry.home)
        if fstype in REMOTE_FS:
            skipped.append(f"{entry.name} ({entry.home} on {fstype})")
            continue
        if not system.is_dir(entry.home):
            continue
        group = _primary_group(system, entry)
        for path in _walk_dot_entries(system, entry.home, want_dirs=True):
            mask = 0o077 if os.path.basename(path) == ".ssh" else 0o027
            meta = system.meta(path)
            if meta is None:
                continue
            issues = []
            if meta.permissions & mask:
                issues.append(f"mode {meta.octal} (should be {max_mode_text(mask)} or more restrictive)")
            owner = system.user_name(meta.uid)
            if owner != entry.name:
                issues.append(f"owner {owner}")
            dir_group = system.group_name(meta.gid)
            if dir_group != group:
                issues.append(f"group {dir_group} (should be {group})")
            if issues:
                problems.append(f"{path} {', '.join(issues)}")
                affected.append(path)
    evidence = {"problems": problems[:500], "skipped_remote_homes": skipped}
    if problems:
        return failed(f"{len(problems)} dot director(ies) in interactive user homes are not secured: {join_limited(problems, 5)}.", cap(affected), **evidence)
    return passed("Dot directories in interactive user homes are owned by the user, group-owned by the primary group and not over-permissive.", **evidence)
