"""Mount, file permission, filesystem scan and log file checks."""

from __future__ import annotations

import fnmatch
import os
import re
import stat as stat_module
import time
from dataclasses import dataclass, field

from lsa.checks.common import (
    cap,
    describe_meta,
    failed,
    join_limited,
    max_mode_text,
    mode_mask,
    not_applicable,
    passed,
    permission_problems,
    provider,
    resolve_targets,
    source,
)
from lsa.system import EvidenceUnavailable, System

PSEUDO_FS = {
    "proc", "sysfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "securityfs", "debugfs",
    "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc",
    "rpc_pipefs", "nsfs", "efivarfs", "selinuxfs", "ramfs", "fuse.lxcfs", "fuse.portal",
}
# The CIS exclusions plus network and cluster filesystems (CephFS, GlusterFS,
# FUSE network mounts) that Proxmox VE nodes mount as shared guest storage.
GENERAL_EXCLUDE_FS = re.compile(r"^(nfs|proc|cifs|smb|vfat|iso9660|efivarfs|selinuxfs|ncpfs|ceph|glusterfs|9p|virtiofs|lustre|gpfs|afs|davfs|fuse\.)")
GENERAL_EXCLUDE_TARGET = re.compile(r"^(/run|/tmp|/var/tmp)(/|$)")
# ZFS is listed as 'nodev' in /proc/filesystems although datasets hold local
# data; without this a ZFS root (common on Proxmox VE) would be left out of the
# setuid/setgid inventory, as happens with the literal CIS script.
DEVICELESS_LOCAL_FS = {"zfs"}
# Proxmox VE container volumes (ZFS subvolumes mounted on the node) belong to
# the guests, whose shifted UIDs would otherwise all be reported as unowned.
GUEST_VOLUME = re.compile(r"(^|/)(subvol|basevol)-\d+-disk-\d+$")
# The same volumes on directory storage, and container root filesystems.
GUEST_PATH = re.compile(r"^(.*/(subvol|basevol)-\d+-disk-\d+\.subvol|/var/lib/lxc/[^/]+/rootfs)$")
PRUNE_PATTERNS = ("*/containers/storage/*", "*/containerd/*", "*/kubelet/*", "/sys/*", "/snap/*", "/boot/efi/*")
LIST_LIMIT = 10_000


# -------------------------------------------------------------------- mounts
@provider("mount_exists")
def mount_exists(system: System, check: dict) -> object:
    path = check["path"]
    mount = system.mount_at(path)
    if mount is None:
        return failed(f"{path} is not a separate mount; it shares the filesystem of its parent directory.", [path], path=path)
    evidence = {"path": path, "source": mount.source, "fstype": mount.fstype, "options": list(mount.options)}
    unit = check.get("unit")
    if unit:
        try:
            state = system.unit(unit)
        except EvidenceUnavailable as exc:
            evidence["unit_state"] = f"unavailable: {exc.reason}"
        else:
            evidence["unit_state"] = state.unit_file_state
            if state.unit_file_state in ("masked", "masked-runtime", "disabled"):
                return failed(
                    f"{path} is mounted ({mount.fstype}) but {unit} is {state.unit_file_state}, so it may not be mounted at boot.",
                    [unit],
                    **evidence,
                )
    return passed(f"{path} is a separate {mount.fstype} mount from {mount.source}.", **evidence)


@provider("mount_option")
def mount_option(system: System, check: dict) -> object:
    path, option = check["path"], check["option"]
    mount = system.mount_at(path)
    if mount is None:
        return not_applicable(
            f"{path} is not a separate mount, so the {option} option cannot be applied; the separate-partition control covers this.",
            path=path,
        )
    evidence = {"path": path, "fstype": mount.fstype, "options": list(mount.options)}
    if mount.has_option(option):
        return passed(f"{path} is mounted with {option}.", **evidence)
    return failed(f"{path} is mounted without the {option} option (options: {','.join(mount.options)}).", [path], **evidence)


# ---------------------------------------------------------- file permissions
@provider("file_permissions")
def file_permissions(system: System, check: dict) -> object:
    """Mode, owner and group of fixed paths, globs, finds or dynamic sources.

    A target may override ``mask``/``max_mode``, ``owners`` and ``groups``
    when CIS applies a different requirement to part of the file set.
    """
    prerequisite = check.get("prerequisite")
    if prerequisite and not system.exists(prerequisite["path"]):
        return failed(prerequisite["message"], [prerequisite["path"]], prerequisite=prerequisite["path"])
    base_mask = mode_mask(check)
    expected_type = check.get("file_type")
    violations: dict[str, list[str]] = {}
    inspected = []
    missing: list[str] = []
    for target in check["targets"]:
        mask = mode_mask(target) if ("mask" in target or "max_mode" in target) else base_mask
        owners = target.get("owners", check.get("owners"))
        groups = target.get("groups", check.get("groups"))
        paths, target_missing = resolve_targets(system, [target])
        missing_rule = target.get("missing", check.get("missing", "pass"))
        for path in target_missing:
            if missing_rule == "unassessed":
                raise EvidenceUnavailable(f"{path} does not exist; verify the equivalent file for this system")
            if missing_rule == "fail":
                violations[path] = ["does not exist"]
            else:
                missing.append(path)
        for path in paths:
            if path in violations or any(item["path"] == path for item in inspected):
                continue
            meta = system.meta(path)
            if meta is None:
                continue
            problems = permission_problems(system, meta, mask, owners, groups)
            if expected_type == "dir" and not meta.is_dir:
                problems.append("is not a directory")
            if expected_type == "file" and not meta.is_file:
                problems.append("is not a regular file")
            inspected.append(describe_meta(system, meta))
            if problems:
                violations[path] = problems
    mask = base_mask
    owners, groups = check.get("owners"), check.get("groups")
    evidence = {"inspected": inspected[:500], "absent": missing, "expected_max_mode": max_mode_text(mask) if mask else None}
    if owners:
        evidence["expected_owners"] = owners
    if groups:
        evidence["expected_groups"] = groups
    if violations:
        detail = [f"{path} {', '.join(problems)}" for path, problems in violations.items()]
        checked = len(inspected) + sum(1 for problems in violations.values() if problems == ["does not exist"])
        return failed(
            f"{len(violations)} of {checked} path(s) are not compliant: {join_limited(detail, 8)}.",
            cap(list(violations)),
            **evidence,
        )
    if not inspected:
        if check.get("require_targets"):
            return failed(check.get("empty_message", "None of the required files exist."), missing, **evidence)
        return passed(check.get("empty_message", "None of the listed files exist, so there is nothing to secure."), **evidence)
    requirement = []
    if mask:
        requirement.append(f"mode {max_mode_text(mask)} or more restrictive")
    if owners:
        requirement.append(f"owner {' or '.join(owners)}")
    if groups:
        requirement.append(f"group {' or '.join(groups)}")
    names = join_limited([item["path"] for item in inspected], 5)
    return passed(f"All {len(inspected)} checked path(s) meet {', '.join(requirement)}: {names}.", **evidence)


# ------------------------------------------------------------ filesystem scan
@dataclass
class ScanResult:
    world_writable_files: list[str] = field(default_factory=list)
    world_writable_dirs: list[str] = field(default_factory=list)
    unowned: list[str] = field(default_factory=list)
    ungrouped: list[str] = field(default_factory=list)
    privileged: list[str] = field(default_factory=list)
    general_mounts: list[str] = field(default_factory=list)
    privileged_mounts: list[str] = field(default_factory=list)
    guest_volumes: list[str] = field(default_factory=list)
    entries: int = 0
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    seconds: float = 0.0


def filesystem_scan(system: System) -> ScanResult:
    """One traversal serving CIS 6.2.3.10, 7.1.11 and 7.1.12.

    Mount selection follows the CIS scripts: world-writable and ownership
    checks cover local, non-pseudo filesystems except /run, /tmp and
    /var/tmp with the CIS prune paths; the privileged-command inventory
    covers device-backed filesystems mounted without noexec or nosuid. ZFS
    counts as device-backed, and network filesystems and Proxmox VE guest
    volumes are skipped (see the constants above).
    """

    def build() -> ScanResult:
        settings = system.settings.get("filesystem_scan") or {}
        if settings.get("enabled", True) is False:
            raise EvidenceUnavailable("The filesystem scan was disabled by configuration (--skip-filesystem-scan)")
        started = time.monotonic()
        effective: dict[str, object] = {}
        for mount in system.mounts():
            effective[mount.target] = mount
        nodev = system.nodev_filesystems() - DEVICELESS_LOCAL_FS
        flags: dict[str, list[bool]] = {}
        guest_volumes = []
        for target, mount in effective.items():
            if GUEST_VOLUME.search(mount.source) or GUEST_VOLUME.search(target):
                guest_volumes.append(target)
                continue
            general = (
                mount.fstype not in PSEUDO_FS
                and not GENERAL_EXCLUDE_FS.match(mount.fstype)
                and not GENERAL_EXCLUDE_TARGET.match(target)
            )
            privileged = mount.fstype not in nodev and not GENERAL_EXCLUDE_FS.match(mount.fstype) and not ({"noexec", "nosuid"} & set(mount.options))
            if general or privileged:
                flags[target] = [general, privileged]
        prune = re.compile("|".join(fnmatch.translate(item) for item in PRUNE_PATTERNS + tuple(settings.get("exclude_paths", []))))
        known_uids = {entry.uid for entry in system.passwd()}
        known_gids = {entry.gid for entry in system.group()}
        uid_cache: dict[int, bool] = {}
        gid_cache: dict[int, bool] = {}

        def uid_known(uid: int) -> bool:
            if uid in known_uids:
                return True
            if uid not in uid_cache:
                uid_cache[uid] = system.uid_known(uid)
            return uid_cache[uid]

        def gid_known(gid: int) -> bool:
            if gid in known_gids:
                return True
            if gid not in gid_cache:
                gid_cache[gid] = system.gid_known(gid)
            return gid_cache[gid]

        result = ScanResult(
            general_mounts=sorted(t for t, f in flags.items() if f[0]),
            privileged_mounts=sorted(t for t, f in flags.items() if f[1]),
            guest_volumes=sorted(guest_volumes),
        )
        visited: set[tuple[int, int]] = set()

        def add(bucket: list[str], path: str) -> None:
            if len(bucket) < LIST_LIMIT:
                bucket.append(path)
            else:
                result.truncated = True

        for target in sorted(flags):
            general, privileged = flags[target]
            host_target = system.host_path(target)
            try:
                root_info = os.lstat(host_target)
            except OSError as exc:
                result.errors.append(f"{target}: {exc.strerror or exc}")
                continue
            if (root_info.st_dev, root_info.st_ino) in visited:
                continue
            visited.add((root_info.st_dev, root_info.st_ino))
            stack: list[tuple[str, bool]] = [(host_target, False)]
            while stack:
                directory, pruned = stack.pop()
                try:
                    iterator = os.scandir(directory)
                except OSError as exc:
                    if len(result.errors) < 100:
                        result.errors.append(f"{system.logical_path(directory)}: {exc.strerror or exc}")
                    continue
                with iterator:
                    for entry in iterator:
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if info.st_dev == 0 and os.name == "nt":  # Windows DirEntry leaves st_dev unset (test runs)
                                info = os.lstat(entry.path)
                        except OSError:
                            continue
                        if info.st_dev != root_info.st_dev:
                            continue
                        result.entries += 1
                        mode = info.st_mode
                        is_dir = stat_module.S_ISDIR(mode)
                        is_file = stat_module.S_ISREG(mode)
                        if not (is_dir or is_file):
                            continue
                        logical = system.logical_path(entry.path)
                        if is_dir and GUEST_PATH.match(logical):
                            add(result.guest_volumes, logical)
                            continue
                        entry_pruned = pruned or bool(prune.match(logical))
                        if general and not entry_pruned:
                            if mode & 0o002:
                                if is_file:
                                    add(result.world_writable_files, logical)
                                elif not mode & 0o1000:
                                    add(result.world_writable_dirs, logical)
                            if not uid_known(info.st_uid):
                                add(result.unowned, logical)
                            if not gid_known(info.st_gid):
                                add(result.ungrouped, logical)
                        if privileged and is_file and mode & 0o6000:
                            add(result.privileged, logical)
                        if is_dir:
                            key = (info.st_dev, info.st_ino)
                            if key in visited:
                                continue
                            visited.add(key)
                            if entry_pruned and not privileged:
                                continue
                            stack.append((entry.path, entry_pruned))
        for bucket in (result.world_writable_files, result.world_writable_dirs, result.unowned, result.ungrouped, result.privileged):
            bucket.sort()
        result.seconds = round(time.monotonic() - started, 2)
        system.count("filesystem", result.entries)
        system.record(
            "filesystem",
            "summary",
            {
                "entries_examined": result.entries,
                "seconds": result.seconds,
                "general_mounts": result.general_mounts,
                "privileged_mounts": result.privileged_mounts,
                "guest_volumes_skipped": result.guest_volumes,
                "world_writable_files": len(result.world_writable_files),
                "world_writable_directories_without_sticky_bit": len(result.world_writable_dirs),
                "unowned": len(result.unowned),
                "ungrouped": len(result.ungrouped),
                "setuid_setgid_files": len(result.privileged),
                "truncated": result.truncated,
                "errors": result.errors[:20],
            },
        )
        system.record("filesystem", "setuid_setgid_files", result.privileged[:2000])
        return result

    return system.cached("filesystem-scan", "filesystem", build)


@source("privileged_files")
def privileged_files(system: System) -> list[str]:
    return filesystem_scan(system).privileged


@provider("world_writable")
def world_writable(system: System, check: dict) -> object:
    scan = filesystem_scan(system)
    affected = scan.world_writable_files + scan.world_writable_dirs
    evidence = {
        "world_writable_files": scan.world_writable_files[:1000],
        "world_writable_directories_without_sticky_bit": scan.world_writable_dirs[:1000],
        "mounts_scanned": scan.general_mounts,
        "entries_examined": scan.entries,
        "scan_errors": scan.errors[:20],
    }
    problems = []
    if scan.world_writable_files:
        problems.append(f"{len(scan.world_writable_files)} world-writable file(s) (e.g. {join_limited(scan.world_writable_files, 3)})")
    if scan.world_writable_dirs:
        problems.append(
            f"{len(scan.world_writable_dirs)} world-writable director(ies) without the sticky bit (e.g. {join_limited(scan.world_writable_dirs, 3)})"
        )
    if problems:
        return failed("Found " + " and ".join(problems) + ".", cap(affected), **evidence)
    return passed(
        f"No world-writable files or unprotected world-writable directories were found on {len(scan.general_mounts)} local filesystem(s).",
        **evidence,
    )


@provider("unowned_files")
def unowned_files(system: System, check: dict) -> object:
    scan = filesystem_scan(system)
    evidence = {
        "unowned": scan.unowned[:1000],
        "ungrouped": scan.ungrouped[:1000],
        "mounts_scanned": scan.general_mounts,
        "entries_examined": scan.entries,
    }
    problems = []
    if scan.unowned:
        problems.append(f"{len(scan.unowned)} path(s) without a valid owner (e.g. {join_limited(scan.unowned, 3)})")
    if scan.ungrouped:
        problems.append(f"{len(scan.ungrouped)} path(s) without a valid group (e.g. {join_limited(scan.ungrouped, 3)})")
    if problems:
        return failed("Found " + " and ".join(problems) + ".", cap(sorted(set(scan.unowned + scan.ungrouped))), **evidence)
    return passed(f"Every file and directory on {len(scan.general_mounts)} local filesystem(s) has a known owner and group.", **evidence)


# ------------------------------------------------------------------ log files
def _log_rule(system: System, path: str, owner: str) -> tuple[int, set[str], set[str], bool]:
    """CIS 6.1.3.1 mask and allowed owner/group sets for a log file.

    The final flag marks the default rule, where a root-owned file or one owned
    by a service account may keep its current owner and group.
    """
    name = os.path.basename(path)
    if os.path.basename(os.path.dirname(path)) == "apt":
        return 0o133, {"root"}, {"root", "adm"}, False
    if name in ("lastlog", "wtmp", "btmp", "README") or re.match(r"^(lastlog\.|wtmp[.-]|btmp[.-])", name):
        return 0o113, {"root"}, {"root", "utmp"}, False
    if re.match(r"^(cloud-init\.log|localmessages|waagent\.log)", name):
        return 0o133, {"root", "syslog"}, {"root", "adm"}, False
    if name in ("secure", "auth.log", "syslog", "messages") or re.match(r"^secure([.-].*|.*\..*)$", name):
        return 0o137, {"root", "syslog"}, {"root", "adm"}, False
    if name in ("SSSD", "sssd"):
        return 0o117, {"root", "SSSD"}, {"root", "SSSD"}, False
    if name in ("gdm", "gdm3"):
        return 0o117, {"root"}, {"root", "gdm", "gdm3"}, False
    if name.endswith(".journal") or name.endswith(".journal~"):
        return 0o137, {"root"}, {"root", "systemd-journal"}, False
    return 0o137, {"root", "syslog"}, {"root", "adm"}, True


@provider("log_files_access")
def log_files_access(system: System, check: dict) -> object:
    files = system.walk_files("/var/log", follow_links=True)
    shells = {line.strip() for line in system.lines("/etc/shells") or [] if line.strip().startswith("/")}
    users = {entry.name: entry.shell for entry in system.passwd()}
    violations: dict[str, list[str]] = {}
    for path in files:
        meta = system.meta(path)
        if meta is None:
            continue
        owner = system.user_name(meta.uid)
        group = system.group_name(meta.gid)
        if not (meta.permissions & 0o137 or owner != "root" or group != "root"):
            continue
        mask, owners, groups, default_rule = _log_rule(system, path, owner)
        if default_rule and (owner == "root" or users.get(owner) not in shells):
            owners = owners | {owner}
            groups = groups | {group}
        problems = []
        if meta.permissions & mask:
            problems.append(f"mode {meta.octal} (should be {max_mode_text(mask)} or more restrictive)")
        if owner not in owners:
            problems.append(f"owner {owner} (should be {' or '.join(sorted(owners))})")
        if group not in groups:
            problems.append(f"group {group} (should be {' or '.join(sorted(groups))})")
        if problems:
            violations[path] = problems
    evidence = {"files_examined": len(files), "non_compliant": {path: problems for path, problems in list(violations.items())[:500]}}
    if violations:
        detail = [f"{path} {', '.join(problems)}" for path, problems in violations.items()]
        return failed(
            f"{len(violations)} of {len(files)} log file(s) under /var/log have excessive access: {join_limited(detail, 5)}.",
            cap(list(violations)),
            **evidence,
        )
    return passed(f"All {len(files)} log file(s) under /var/log have appropriate mode, owner and group.", **evidence)
