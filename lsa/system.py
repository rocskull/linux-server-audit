"""Read-only access to the audited host.

Every probe used by the check providers goes through :class:`System`. It caches
evidence so each command or file is read once per assessment, converts
permission problems into :class:`EvidenceUnavailable` (reported as
NOT_ASSESSED, never as FAIL), and records each evidence source as a collector
execution for the report's coverage and raw-evidence views.

Nothing here writes to the audited system. Commands are started with a fixed
PATH, the C locale, no standard input and a timeout.
"""

from __future__ import annotations

import fnmatch
import os
import re
import socket
import stat as stat_module
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Iterable, TypeVar

from lsa.model import CollectorExecution, utc_now

T = TypeVar("T")

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
COMMAND_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
INSTALLED_STATES = {
    "installed",
    "half-configured",
    "unpacked",
    "half-installed",
    "triggers-awaited",
    "triggers-pending",
}

COLLECTORS: dict[str, tuple[str, str]] = {
    "host": ("Host and operating system facts", "system"),
    "accounts": ("Local accounts, groups and password policy", "accounts"),
    "packages": ("Debian package inventory", "packages"),
    "apt": ("APT configuration and repositories", "packages"),
    "systemd": ("systemd unit states", "services"),
    "kernel": ("Kernel modules and parameters", "kernel"),
    "mounts": ("Mount table", "filesystem"),
    "filesystem": ("Filesystem permission scan", "filesystem"),
    "files": ("Configuration file inspection", "configuration"),
    "boot": ("Bootloader configuration", "boot"),
    "apparmor": ("AppArmor status", "security"),
    "ssh": ("OpenSSH server effective configuration", "ssh"),
    "sudo": ("sudo configuration", "access"),
    "pam": ("PAM configuration", "access"),
    "logging": ("journald and rsyslog configuration", "logging"),
    "auditd": ("Linux audit framework", "auditing"),
    "firewall": ("Uncomplicated Firewall", "network"),
    "network": ("Network interfaces and listening sockets", "network"),
    "desktop": ("GNOME Display Manager settings", "desktop"),
    "time": ("Time synchronization", "services"),
    "integrity": ("AIDE file integrity checking", "integrity"),
    "processes": ("Process table", "system"),
    "esxi_host": ("ESXi host configuration and services (vim-cmd hostsvc, esxcli system)", "host"),
    "esxi_settings": ("ESXi advanced settings", "configuration"),
    "esxi_software": ("ESXi image profile acceptance and VIB inventory", "software"),
    "esxi_network": ("ESXi standard virtual switches and port groups", "network"),
    "esxi_storage": ("ESXi iSCSI adapters", "storage"),
    "esxi_accounts": ("ESXi local accounts and permissions", "accounts"),
    "esxi_vms": ("Registered virtual machines and their .vmx files", "virtual machines"),
}


class EvidenceUnavailable(Exception):
    """Evidence required by a check could not be read.

    ``permission`` names the privilege that would normally resolve the gap
    (``root``) so the coverage report can say why a control was not assessed.
    """

    def __init__(self, reason: str, permission: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.permission = permission


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0

    def describe(self) -> str:
        command = " ".join(self.argv)
        if self.error:
            return f"'{command}' {self.error}"
        detail = (self.stderr or self.stdout).strip().splitlines()
        suffix = f": {detail[-1][:300]}" if detail else ""
        return f"'{command}' exited with status {self.returncode}{suffix}"


class SubprocessRunner:
    """Runs read-only commands with a clean environment and a timeout."""

    def __init__(self, default_timeout: float = 60) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        argv: list[str],
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        environment = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
        if env:
            environment.update(env)
        limit = timeout or self.default_timeout
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=limit,
                env=environment,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(argv, None, "", "", "was not found")
        except PermissionError:
            return CommandResult(argv, None, "", "", "could not be executed (permission denied)")
        except subprocess.TimeoutExpired:
            return CommandResult(argv, None, "", "", f"timed out after {limit:g} seconds")
        except OSError as exc:
            return CommandResult(argv, None, "", "", f"failed to start: {exc.strerror or exc}")
        return CommandResult(
            argv,
            completed.returncode,
            completed.stdout.decode("utf-8", "replace"),
            completed.stderr.decode("utf-8", "replace"),
        )


@dataclass(frozen=True)
class FileMeta:
    path: str
    mode: int
    uid: int
    gid: int
    is_dir: bool
    is_file: bool
    is_link: bool = False

    @property
    def permissions(self) -> int:
        return stat_module.S_IMODE(self.mode)

    @property
    def octal(self) -> str:
        return format(self.permissions, "04o")


@dataclass(frozen=True)
class PasswdEntry:
    name: str
    password: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


@dataclass(frozen=True)
class GroupEntry:
    name: str
    password: str
    gid: int
    members: tuple[str, ...]


@dataclass(frozen=True)
class ShadowEntry:
    """A shadow record without the password hash.

    ``status`` follows ``passwd -S``: L (locked, field starts with ! or *),
    NP (empty) or P (usable password). ``hashed`` mirrors the CIS awk filter
    ``$2 ~ /^\\$.+\\$/`` used to select accounts that have a real password.
    Numeric fields keep their raw text because CIS compares them the way awk
    does, where an empty field behaves as zero.
    """

    name: str
    status: str
    hashed: bool
    lastchg: str
    minimum: str
    maximum: str
    warn: str
    inactive: str
    expire: str


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    status: str
    architecture: str


@dataclass(frozen=True)
class UnitState:
    name: str
    load_state: str
    active_state: str
    unit_file_state: str

    @property
    def enabled(self) -> bool:
        return self.unit_file_state in ("enabled", "enabled-runtime")

    @property
    def active(self) -> bool:
        return self.active_state == "active"

    @property
    def exists(self) -> bool:
        return self.load_state not in ("not-found", "")


@dataclass(frozen=True)
class Mount:
    target: str
    source: str
    fstype: str
    options: tuple[str, ...]
    device: str

    def has_option(self, option: str) -> bool:
        return option in self.options


@dataclass
class _CollectorState:
    execution: CollectorExecution
    successes: int = 0
    failures: int = 0
    errors: int = 0


class System:
    """Cached, read-only view of the host being assessed."""

    def __init__(
        self,
        root: str = "/",
        runner: Any | None = None,
        settings: dict[str, Any] | None = None,
        *,
        is_root: bool | None = None,
        meta_overrides: dict[str, tuple[int, int, int]] | None = None,
    ) -> None:
        self.root = os.path.abspath(root)
        self.settings = settings or {}
        self.runner = runner or SubprocessRunner(float(self.settings.get("command_timeout_seconds", 60)))
        self._is_root = is_root
        self._meta_overrides = meta_overrides or {}
        self._cache: dict[str, Any] = {}
        self._collectors: dict[str, _CollectorState] = {}
        self._tracking: set[str] | None = None
        self._units: dict[str, UnitState] = {}

    # ------------------------------------------------------------------ paths
    @property
    def real_root(self) -> bool:
        return self.root in ("/", os.path.abspath(os.sep))

    def host_path(self, path: str) -> str:
        if self.real_root:
            return path
        return os.path.join(self.root, path.lstrip("/"))

    def logical_path(self, host_path: str) -> str:
        if self.real_root:
            return host_path
        relative = os.path.relpath(host_path, self.root).replace(os.sep, "/")
        return "/" if relative == "." else "/" + relative

    # ------------------------------------------------------------- collectors
    def begin_tracking(self) -> None:
        self._tracking = set()

    def end_tracking(self) -> set[str]:
        used = self._tracking or set()
        self._tracking = None
        return used

    def _state(self, collector: str) -> _CollectorState:
        state = self._collectors.get(collector)
        if state is None:
            name, area = COLLECTORS.get(collector, (collector, "system"))
            execution = CollectorExecution(
                collector_id=collector,
                name=name,
                area=area,
                status="SUCCESS",
                started_at=utc_now(),
                completed_at=utc_now(),
            )
            state = _CollectorState(execution)
            self._collectors[collector] = state
        return state

    def use(self, collector: str) -> None:
        self._state(collector)
        if self._tracking is not None:
            self._tracking.add(collector)

    def count(self, collector: str, objects: int) -> None:
        self._state(collector).execution.objects_collected += objects

    def record(self, collector: str, key: str, value: Any) -> None:
        self._state(collector).execution.data[key] = value

    def note_error(self, collector: str, message: str) -> None:
        errors = self._state(collector).execution.api_errors
        if message not in errors:
            errors.append(message)

    def cached(self, key: str, collector: str, builder: Callable[[], T]) -> T:
        """Build evidence once; later callers get the same value or error."""
        self.use(collector)
        if key in self._cache:
            value = self._cache[key]
            if isinstance(value, EvidenceUnavailable):
                raise value
            return value
        state = self._state(collector)
        try:
            value = builder()
        except EvidenceUnavailable as exc:
            state.failures += 1
            self.note_error(collector, exc.reason)
            if state.execution.limitation_reason is None:
                state.execution.limitation_reason = exc.reason
            self._cache[key] = exc
            raise
        except Exception as exc:  # noqa: BLE001 - recorded, then re-raised as ERROR
            state.errors += 1
            self.note_error(collector, f"{key}: {type(exc).__name__}: {exc}")
            raise
        finally:
            state.execution.completed_at = utc_now()
        state.successes += 1
        self._cache[key] = value
        return value

    def collectors(self) -> dict[str, CollectorExecution]:
        output: dict[str, CollectorExecution] = {}
        for collector_id in sorted(self._collectors):
            state = self._collectors[collector_id]
            execution = state.execution
            execution.pages_collected = state.successes + state.failures + state.errors
            if state.errors and not state.successes:
                execution.status = "ERROR"
            elif (state.failures or state.errors) and state.successes:
                execution.status = "PARTIAL"
            elif state.failures or state.errors:
                execution.status = "NOT_ASSESSED"
            else:
                execution.status = "SUCCESS"
            output[collector_id] = execution
        return output

    # --------------------------------------------------------------- identity
    @property
    def is_root(self) -> bool:
        if self._is_root is not None:
            return self._is_root
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)

    # ------------------------------------------------------------------ files
    def read_text(self, path: str, *, missing_ok: bool = True, max_bytes: int = 16_000_000) -> str | None:
        self.use("files")
        host = self.host_path(path)
        try:
            with open(host, "rb") as handle:
                data = handle.read(max_bytes)
        except (FileNotFoundError, NotADirectoryError):
            if missing_ok:
                return None
            raise EvidenceUnavailable(f"{path} does not exist") from None
        except PermissionError:
            raise EvidenceUnavailable(f"Permission denied reading {path}", "root") from None
        except IsADirectoryError:
            raise EvidenceUnavailable(f"{path} is a directory, not a file") from None
        except OSError as exc:
            raise EvidenceUnavailable(f"Unable to read {path}: {exc.strerror or exc}") from None
        self.count("files", 1)
        return data.decode("utf-8", "replace")

    def lines(self, path: str, *, missing_ok: bool = True) -> list[str] | None:
        text = self.read_text(path, missing_ok=missing_ok)
        return None if text is None else text.splitlines()

    def meta(self, path: str, *, follow: bool = True) -> FileMeta | None:
        override = self._meta_overrides.get(path)
        host = self.host_path(path)
        try:
            info = os.stat(host, follow_symlinks=follow)
            is_link = os.path.islink(host)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            raise EvidenceUnavailable(f"Permission denied reading the attributes of {path}", "root") from None
        except OSError as exc:
            raise EvidenceUnavailable(f"Unable to stat {path}: {exc.strerror or exc}") from None
        mode, uid, gid = info.st_mode, info.st_uid, info.st_gid
        if override:
            permissions, uid, gid = override
            mode = stat_module.S_IFMT(info.st_mode) | permissions
        return FileMeta(
            path=path,
            mode=mode,
            uid=uid,
            gid=gid,
            is_dir=stat_module.S_ISDIR(mode),
            is_file=stat_module.S_ISREG(mode),
            is_link=is_link,
        )

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.host_path(path))

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(self.host_path(path))

    def is_file(self, path: str) -> bool:
        return os.path.isfile(self.host_path(path))

    def realpath(self, path: str) -> str:
        return self.logical_path(os.path.realpath(self.host_path(path)))

    def listdir(self, path: str) -> list[str] | None:
        """Names in a directory, or None when it does not exist."""
        host = self.host_path(path)
        try:
            return sorted(os.listdir(host))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            raise EvidenceUnavailable(f"Permission denied listing {path}", "root") from None
        except OSError as exc:
            raise EvidenceUnavailable(f"Unable to list {path}: {exc.strerror or exc}") from None

    def glob(self, directory: str, pattern: str = "*", *, files_only: bool = False) -> list[str]:
        """Entries of one directory matching a shell pattern, sorted by name.

        Unlike :func:`glob.glob` this raises when the directory cannot be
        read, so an unreadable drop-in directory is never mistaken for an
        empty one.
        """
        names = self.listdir(directory)
        if names is None:
            return []
        matches = []
        for name in names:
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            path = directory.rstrip("/") + "/" + name
            if files_only and not self.is_file(path):
                continue
            matches.append(path)
        return matches

    def walk_files(
        self,
        directory: str,
        *,
        name_pattern: str = "*",
        max_depth: int | None = None,
        follow_links: bool = False,
    ) -> list[str]:
        """Regular files below a directory, like ``find DIR [-maxdepth N] -type f``."""
        base = self.host_path(directory)
        if not os.path.isdir(base):
            return []
        results: list[str] = []
        denied: list[str] = []

        def on_error(error: OSError) -> None:
            denied.append(self.logical_path(getattr(error, "filename", None) or base))

        for current, dirs, names in os.walk(base, onerror=on_error, followlinks=follow_links):
            relative = os.path.relpath(current, base)
            depth = 0 if relative == "." else relative.count(os.sep) + 1
            if max_depth is not None and depth + 1 >= max_depth:
                dirs[:] = []
            if max_depth is not None and depth + 1 > max_depth:
                continue
            for name in names:
                full = os.path.join(current, name)
                if fnmatch.fnmatchcase(name, name_pattern) and os.path.isfile(full):
                    results.append(self.logical_path(full))
        if denied:
            raise EvidenceUnavailable(f"Permission denied reading {', '.join(sorted(set(denied))[:5])}", "root")
        return sorted(results)

    # --------------------------------------------------------------- commands
    def which(self, name: str) -> str | None:
        if name.startswith("/"):
            return name if self.is_file(name) else None
        for directory in COMMAND_DIRS:
            candidate = f"{directory}/{name}"
            if os.path.isfile(self.host_path(candidate)):
                return candidate
        return None

    def run(
        self,
        argv: list[str],
        *,
        collector: str,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        self.use(collector)
        result = self.runner.run(argv, timeout=timeout, env=env)
        if result.error:
            self.note_error(collector, result.describe())
        executed = self._state(collector).execution.data.setdefault("commands_executed", [])
        command_line = " ".join(argv)
        if command_line not in executed:
            executed.append(command_line)
        return result

    def command(self, name: str) -> str:
        """Path of a required command, or EvidenceUnavailable."""
        path = self.which(name)
        if path is None:
            raise EvidenceUnavailable(f"The '{name}' command is not installed")
        return path

    # ------------------------------------------------------------- host facts
    def os_release(self) -> dict[str, str]:
        def build() -> dict[str, str]:
            text = self.read_text("/etc/os-release") or self.read_text("/usr/lib/os-release")
            if text is None:
                raise EvidenceUnavailable("/etc/os-release was not found")
            values: dict[str, str] = {}
            for line in text.splitlines():
                match = re.match(r"^\s*([A-Z0-9_]+)=(.*)$", line)
                if match:
                    value = match.group(2).strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    values[match.group(1)] = value
            self.record("host", "os_release", values)
            return values

        return self.cached("os-release", "host", build)

    def os_id(self) -> str:
        try:
            return self.os_release().get("ID", "linux").lower()
        except EvidenceUnavailable:
            return "linux"

    def hostname(self) -> str:
        def build() -> str:
            if self.real_root:
                return socket.gethostname()
            return (self.read_text("/etc/hostname") or "localhost").strip() or "localhost"

        return self.cached("hostname", "host", build)

    def machine_id(self) -> str | None:
        def build() -> str | None:
            text = self.read_text("/etc/machine-id")
            return text.strip() if text and text.strip() else None

        return self.cached("machine-id", "host", build)

    def architecture(self) -> str:
        def build() -> str:
            if self.real_root:
                return os.uname().machine if hasattr(os, "uname") else "unknown"
            return str(self.settings.get("test_architecture", "x86_64"))

        return self.cached("architecture", "host", build)

    def kernel_release(self) -> str:
        def build() -> str:
            if self.real_root and hasattr(os, "uname"):
                return os.uname().release
            return str(self.settings.get("test_kernel", "unknown"))

        return self.cached("kernel-release", "host", build)

    # --------------------------------------------------------------- accounts
    def passwd(self) -> list[PasswdEntry]:
        def build() -> list[PasswdEntry]:
            lines = self.lines("/etc/passwd")
            if lines is None:
                raise EvidenceUnavailable("/etc/passwd was not found")
            entries = []
            for line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                entries.append(
                    PasswdEntry(
                        parts[0], parts[1], _int(parts[2], -1), _int(parts[3], -1), parts[4], parts[5], parts[6]
                    )
                )
            self.count("accounts", len(entries))
            self.record(
                "accounts",
                "users",
                [{"name": e.name, "uid": e.uid, "gid": e.gid, "home": e.home, "shell": e.shell} for e in entries],
            )
            return entries

        return self.cached("passwd", "accounts", build)

    def group(self) -> list[GroupEntry]:
        def build() -> list[GroupEntry]:
            lines = self.lines("/etc/group")
            if lines is None:
                raise EvidenceUnavailable("/etc/group was not found")
            entries = []
            for line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                members = tuple(item for item in parts[3].split(",") if item)
                entries.append(GroupEntry(parts[0], parts[1], _int(parts[2], -1), members))
            self.count("accounts", len(entries))
            self.record(
                "accounts", "groups", [{"name": e.name, "gid": e.gid, "members": list(e.members)} for e in entries]
            )
            return entries

        return self.cached("group", "accounts", build)

    def shadow(self) -> list[ShadowEntry]:
        def build() -> list[ShadowEntry]:
            lines = self.lines("/etc/shadow")
            if lines is None:
                raise EvidenceUnavailable("/etc/shadow was not found")
            entries = []
            for line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = (line.split(":") + [""] * 9)[:9]
                password = parts[1]
                if password.startswith(("!", "*")):
                    status = "L"
                elif password == "":
                    status = "NP"
                else:
                    status = "P"
                entries.append(
                    ShadowEntry(
                        name=parts[0],
                        status=status,
                        hashed=bool(re.match(r"^\$.+\$", password)),
                        lastchg=parts[2],
                        minimum=parts[3],
                        maximum=parts[4],
                        warn=parts[5],
                        inactive=parts[6],
                        expire=parts[7],
                    )
                )
            self.record("accounts", "shadow_status", {e.name: e.status for e in entries})
            return entries

        return self.cached("shadow", "accounts", build)

    def login_defs(self) -> dict[str, str]:
        def build() -> dict[str, str]:
            values: dict[str, str] = {}
            for line in self.lines("/etc/login.defs") or []:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split(None, 1)
                values[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
            self.record("accounts", "login_defs", values)
            return values

        return self.cached("login.defs", "accounts", build)

    def uid_min(self) -> int:
        return _int(self.login_defs().get("UID_MIN", "1000"), 1000)

    def user_name(self, uid: int) -> str:
        for entry in self._safe_passwd():
            if entry.uid == uid:
                return entry.name
        if self.real_root:
            try:
                import pwd

                return pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                pass
        return f"UNKNOWN({uid})"

    def group_name(self, gid: int) -> str:
        for entry in self._safe_group():
            if entry.gid == gid:
                return entry.name
        if self.real_root:
            try:
                import grp

                return grp.getgrgid(gid).gr_name
            except (KeyError, ImportError):
                pass
        return f"UNKNOWN({gid})"

    def uid_known(self, uid: int) -> bool:
        return not self.user_name(uid).startswith("UNKNOWN(")

    def gid_known(self, gid: int) -> bool:
        return not self.group_name(gid).startswith("UNKNOWN(")

    def _safe_passwd(self) -> list[PasswdEntry]:
        try:
            return self.passwd()
        except EvidenceUnavailable:
            return []

    def _safe_group(self) -> list[GroupEntry]:
        try:
            return self.group()
        except EvidenceUnavailable:
            return []

    def valid_shells(self) -> list[str]:
        """Login shells from /etc/shells, excluding any ending in nologin (CIS)."""

        def build() -> list[str]:
            shells = []
            for line in self.lines("/etc/shells") or []:
                stripped = line.strip()
                if stripped.startswith("/") and os.path.basename(stripped) != "nologin":
                    shells.append(stripped)
            return shells

        return self.cached("valid-shells", "accounts", build)

    # --------------------------------------------------------------- packages
    def packages(self) -> dict[str, Package]:
        def build() -> dict[str, Package]:
            text = self.read_text("/var/lib/dpkg/status")
            if text is None:
                raise EvidenceUnavailable("The dpkg status database (/var/lib/dpkg/status) was not found")
            packages: dict[str, Package] = {}
            for stanza in re.split(r"\n\s*\n", text):
                fields_: dict[str, str] = {}
                for line in stanza.splitlines():
                    if line[:1] in (" ", "\t") or ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    fields_[key.strip()] = value.strip()
                name = fields_.get("Package")
                words = fields_.get("Status", "").split()
                state = words[-1] if words else ""
                if not name or state not in INSTALLED_STATES:
                    continue
                packages[name] = Package(name, fields_.get("Version", ""), state, fields_.get("Architecture", ""))
            self.count("packages", len(packages))
            self.record("packages", "installed", {name: item.version for name, item in sorted(packages.items())})
            return packages

        return self.cached("dpkg-status", "packages", build)

    def package_installed(self, name: str) -> bool:
        return name in self.packages()

    def packages_matching(self, pattern: str) -> list[str]:
        regex = re.compile(pattern, re.IGNORECASE)
        return sorted(name for name in self.packages() if regex.search(name))

    # ---------------------------------------------------------------- systemd
    def systemd_running(self) -> bool:
        return os.path.isdir(self.host_path("/run/systemd/system"))

    def units(self, names: Iterable[str]) -> dict[str, UnitState]:
        requested = [name for name in dict.fromkeys(names)]
        missing = [name for name in requested if name not in self._units]
        self.use("systemd")
        if missing:
            if "systemd-unavailable" in self._cache:
                raise self._cache["systemd-unavailable"]
            if not self.systemd_running():
                error = EvidenceUnavailable(
                    "systemd is not the running init system, so unit states cannot be queried"
                )
                self._cache["systemd-unavailable"] = error
                self.note_error("systemd", error.reason)
                self._state("systemd").failures += 1
                raise error
            systemctl = self.command("systemctl")
            result = self.run(
                [systemctl, "show", "--no-pager", "--property=Id,LoadState,ActiveState,UnitFileState", "--", *missing],
                collector="systemd",
            )
            if not result.ok:
                self._state("systemd").failures += 1
                raise EvidenceUnavailable(f"Unable to query systemd: {result.describe()}")
            blocks = [block for block in re.split(r"\n\s*\n", result.stdout.strip()) if block.strip()]
            if len(blocks) != len(missing):
                self._state("systemd").failures += 1
                raise EvidenceUnavailable("systemctl show returned an unexpected number of unit records")
            for name, block in zip(missing, blocks):
                values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
                self._units[name] = UnitState(
                    name,
                    values.get("LoadState", ""),
                    values.get("ActiveState", ""),
                    values.get("UnitFileState", ""),
                )
            self._state("systemd").successes += 1
            self.count("systemd", len(missing))
            self.record(
                "systemd",
                "units",
                {
                    name: {
                        "load": state.load_state,
                        "active": state.active_state,
                        "unit_file": state.unit_file_state,
                    }
                    for name, state in sorted(self._units.items())
                },
            )
        return {name: self._units[name] for name in requested}

    def unit(self, name: str) -> UnitState:
        return self.units([name])[name]

    # ------------------------------------------------------------ kernel/sysctl
    def sysctl_running(self, name: str) -> str | None:
        def build() -> str | None:
            path = "/proc/sys/" + name.replace(".", "/")
            text = self.read_text(path)
            return None if text is None else " ".join(text.split())

        return self.cached(f"sysctl-running:{name}", "kernel", build)

    def loaded_modules(self) -> set[str]:
        def build() -> set[str]:
            text = self.read_text("/proc/modules")
            if text is None:
                return set()
            modules = {line.split()[0] for line in text.splitlines() if line.strip()}
            self.record("kernel", "loaded_modules", sorted(modules))
            return modules

        return self.cached("loaded-modules", "kernel", build)

    # ------------------------------------------------------------------ mounts
    def mounts(self) -> list[Mount]:
        def build() -> list[Mount]:
            text = self.read_text("/proc/self/mountinfo")
            mounts: list[Mount] = []
            if text:
                for line in text.splitlines():
                    left, _, right = line.partition(" - ")
                    left_parts, right_parts = left.split(), right.split()
                    if len(left_parts) < 6 or len(right_parts) < 2:
                        continue
                    options = set(left_parts[5].split(","))
                    if len(right_parts) >= 3:
                        options |= set(right_parts[2].split(","))
                    mounts.append(
                        Mount(
                            target=_unescape_mount(left_parts[4]),
                            source=_unescape_mount(right_parts[1]),
                            fstype=right_parts[0],
                            options=tuple(sorted(options)),
                            device=left_parts[2],
                        )
                    )
            else:
                for line in self.lines("/proc/mounts") or []:
                    parts = line.split()
                    if len(parts) >= 4:
                        mounts.append(
                            Mount(_unescape_mount(parts[1]), parts[0], parts[2], tuple(sorted(parts[3].split(","))), "")
                        )
            if not mounts:
                raise EvidenceUnavailable("The kernel mount table could not be read")
            self.count("mounts", len(mounts))
            self.record(
                "mounts",
                "mounts",
                [{"target": m.target, "source": m.source, "fstype": m.fstype, "options": list(m.options)} for m in mounts],
            )
            return mounts

        return self.cached("mounts", "mounts", build)

    def mount_at(self, target: str) -> Mount | None:
        found = None
        for mount in self.mounts():
            if mount.target == target:
                found = mount
        return found

    def nodev_filesystems(self) -> set[str]:
        def build() -> set[str]:
            types = set()
            for line in self.lines("/proc/filesystems") or []:
                parts = line.split()
                if len(parts) == 2 and parts[0] == "nodev":
                    types.add(parts[1])
            return types

        return self.cached("proc-filesystems", "mounts", build)


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def parse_int(value: str | None) -> int | None:
    """Integer value of a field; None when empty or not numeric.

    CIS audits compare shadow fields with awk, where an empty field is a
    string and fails every bounded comparison, so callers treat None as
    non-compliant.
    """
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None
