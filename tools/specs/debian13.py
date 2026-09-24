"""Check specification for the CIS Debian Linux 13 Benchmark v1.1.0.

The CIS PDF supplies control identity (recommendation number, title, profile
applicability, automated/manual status and framework mappings); the builder
reads those from the document. This module supplies what the tool does with
each automated recommendation: the provider and its parameters, a
risk-based severity, and independently written guidance text.

Severity reflects exploitability and impact on a typical server, not the CIS
profile level: Critical for direct authentication bypass, High for exposed
remote attack surface or privilege boundaries, Medium for hardening that
blocks common attack techniques, Low for defense in depth and disclosure.
"""

from __future__ import annotations

from typing import Any

MAN = "https://manpages.debian.org/trixie/{}"


def man(page: str) -> str:
    return MAN.format(page)


BENCHMARK = {
    "id": "debian-linux-13",
    "framework": "CIS",
    "name": "CIS Debian Linux 13 Benchmark",
    "short_name": "Debian Linux 13",
    "version": "1.1.0",
    "published": "2026-08-26",
    "source_document": "CIS_Debian_Linux_13_Benchmark_v1.1.0.pdf",
    "output_file": "CIS_Debian_Linux_13_1.1.0.json",
    "platform": {"os_id": "debian", "version_ids": ["13"], "architectures": ["x86_64"]},
    "profiles": ["Level 1 - Server", "Level 2 - Server", "Level 1 - Workstation", "Level 2 - Workstation"],
}

# Longest matching CIS prefix wins: (prefix, section, category, check-id code).
SECTIONS = [
    ("1.1.1", "Initial Setup", "Filesystem Kernel Modules", "KMOD"),
    ("1.1.2", "Initial Setup", "Filesystem Partitions", "PART"),
    ("1.2", "Initial Setup", "Package Management", "APT"),
    ("1.3", "Initial Setup", "Mandatory Access Control", "MAC"),
    ("1.4", "Initial Setup", "Bootloader", "BOOT"),
    ("1.5", "Initial Setup", "Process Hardening", "PROC"),
    ("1.6", "Initial Setup", "Warning Banners", "BANNER"),
    ("1.7", "Initial Setup", "GNOME Display Manager", "GDM"),
    ("2.1", "Services", "Server Services", "SVC"),
    ("2.2", "Services", "Client Services", "CLIENT"),
    ("2.3", "Services", "Time Synchronization", "TIME"),
    ("2.4", "Services", "Job Schedulers", "CRON"),
    ("3.1", "Network", "Network Devices", "NETDEV"),
    ("3.2", "Network", "Network Kernel Modules", "NETMOD"),
    ("3.3", "Network", "Network Kernel Parameters", "SYSCTL"),
    ("4.1", "Host Based Firewall", "Uncomplicated Firewall", "UFW"),
    ("5.1", "Access Control", "SSH Server", "SSH"),
    ("5.2", "Access Control", "Privilege Escalation", "PRIV"),
    ("5.3", "Access Control", "Pluggable Authentication Modules", "PAM"),
    ("5.4.1", "Access Control", "Shadow Password Suite", "PWD"),
    ("5.4.2", "Access Control", "Root and System Accounts", "ROOT"),
    ("5.4.3", "Access Control", "User Environment", "ENV"),
    ("6.1.1", "Logging and Auditing", "journald", "JOURNAL"),
    ("6.1.2", "Logging and Auditing", "rsyslog", "RSYSLOG"),
    ("6.1.3", "Logging and Auditing", "Log Files", "LOGFILE"),
    ("6.2.1", "Logging and Auditing", "auditd Service", "AUDITD"),
    ("6.2.2", "Logging and Auditing", "Audit Data Retention", "AUDRET"),
    ("6.2.3", "Logging and Auditing", "Audit Rules", "AUDRULE"),
    ("6.2.4", "Logging and Auditing", "Audit File Access", "AUDPERM"),
    ("6.3", "Logging and Auditing", "Integrity Checking", "AIDE"),
    ("7.1", "System Maintenance", "System File Permissions", "FPERM"),
    ("7.2", "System Maintenance", "Local Users and Groups", "USER"),
]

CONTROLS: dict[str, dict[str, Any]] = {}
MANUAL: dict[str, dict[str, Any]] = {}
# CIS number -> {platform tag: note appended to the observation on that platform}.
NOTES: dict[str, dict[str, str]] = {}

SSH = [{"type": "sshd_installed"}]
CRON = [{"type": "cron_installed"}]
GDM = [{"type": "gdm_installed"}]
SUDO = [{"type": "package_installed", "packages": ["sudo", "sudo-rs"]}]
IPV4 = [{"type": "not_router"}]
IPV6 = [{"type": "ipv6_enabled"}]
RSYSLOG = [{"type": "logging_method", "method": "rsyslog"}]
AUID = [["auid", ">=", "UID_MIN"], ["auid", "!=", "unset"]]
RELOAD_SSH = "then run 'systemctl reload ssh'."
AUGENRULES = "Load the rules with 'augenrules --load' (a reboot is required when the audit configuration is immutable)."


def add(cis_id: str, severity: str, check: dict, description: str, rationale: str, impact: str, recommendation: str, remediation: str, references: list[str], applies_if: list[dict] | None = None) -> None:
    if cis_id in CONTROLS:
        raise ValueError(f"Duplicate specification for {cis_id}")
    CONTROLS[cis_id] = {
        "severity": severity,
        "check": check,
        "description": description,
        "rationale": rationale,
        "business_impact": impact,
        "recommendation": recommendation,
        "remediation": remediation,
        "references": references,
        "applies_if": applies_if or [],
    }


def manual(cis_id: str, guidance: str, remediation: str, references: list[str] | None = None) -> None:
    MANUAL[cis_id] = {"guidance": guidance, "remediation": remediation, "references": references or []}


# =========================================================== 1 Initial Setup
def kmod(cis_id: str, module: str, paths: list[str], purpose: str, severity: str = "Low", impact: str | None = None) -> None:
    add(
        cis_id,
        severity,
        {"type": "kernel_module", "module": module, "paths": paths},
        f"Checks that the {module} kernel module ({purpose}) cannot be used: it is either absent, or unloaded, deny-listed and mapped to a disabled install command.",
        "Kernel code that the system never needs still enlarges its attack surface; making the module unloadable removes it as an attack path.",
        impact or f"An attacker who can present crafted {purpose.split(' (')[0]} content could trigger automatic loading of {module} and exploit a driver flaw to crash the host or gain kernel privileges.",
        f"Disable the {module} module unless a documented business need requires it.",
        f"Create /etc/modprobe.d/{module}.conf containing 'install {module} /bin/false' and 'blacklist {module}', then unload it with 'modprobe -r {module}'.",
        [man("modprobe.d.5")],
    )


kmod("1.1.1.1", "cramfs", ["fs/cramfs"], "a compressed read-only filesystem for embedded devices")
kmod("1.1.1.2", "freevxfs", ["fs/freevxfs"], "the Veritas VxFS filesystem used by HP-UX")
kmod("1.1.1.3", "hfs", ["fs/hfs"], "the legacy Apple HFS filesystem")
kmod("1.1.1.4", "hfsplus", ["fs/hfsplus"], "the Apple HFS+ filesystem")
kmod("1.1.1.5", "jffs2", ["fs/jffs2"], "the JFFS2 flash filesystem")
kmod(
    "1.1.1.6",
    "overlay",
    ["fs/overlayfs"],
    "the OverlayFS union filesystem",
    impact="OverlayFS has a history of privilege-escalation flaws reachable by unprivileged users; note that Docker, Podman and containerd depend on it, so document an exception on container hosts.",
)
kmod(
    "1.1.1.7",
    "squashfs",
    ["fs/squashfs"],
    "the SquashFS compressed read-only filesystem",
    impact="A crafted SquashFS image can exploit filesystem driver flaws; note that snap packages and some live-boot tooling depend on SquashFS.",
)
kmod("1.1.1.8", "udf", ["fs/udf"], "the Universal Disk Format used by optical media")
kmod(
    "1.1.1.9",
    "firewire-core",
    ["drivers/firewire"],
    "the IEEE 1394 FireWire bus driver",
    severity="Medium",
    impact="FireWire devices have direct memory access, so a physically attached device can read or modify memory, bypassing screen locks and disk encryption.",
)
kmod(
    "1.1.1.10",
    "usb-storage",
    ["drivers/usb/storage"],
    "USB mass-storage support",
    severity="Medium",
    impact="USB storage allows data to be copied off the host without network controls and allows malicious media to be introduced.",
)
manual(
    "1.1.1.11",
    "Review filesystem kernel modules that are loaded or loadable but not used by any mounted filesystem, and deny-list those without a business need.",
    "Compare 'findmnt -Dkerno fstype', 'lsmod' and the modules under /usr/lib/modules/*/kernel/fs; add 'install <module> /bin/false' and 'blacklist <module>' entries for unused ones.",
    [man("modprobe.d.5")],
)


def separate_mount(cis_id: str, path: str, severity: str, unit: str | None = None) -> None:
    extra = f" and {unit} is not masked or disabled" if unit else ""
    add(
        cis_id,
        severity,
        {"type": "mount_exists", "path": path, **({"unit": unit} if unit else {})},
        f"Checks that {path} is its own mount (a tmpfs or a separate partition){extra}.",
        f"A dedicated {path} filesystem contains resource exhaustion and allows restrictive mount options for the data it holds.",
        f"If {path} fills up it can exhaust the root filesystem, and restrictive mount options such as nodev, nosuid and noexec cannot be applied to it.",
        f"Mount {path} as a separate filesystem.",
        (
            f"Debian 13 mounts /tmp as a tmpfs through tmp.mount: run 'systemctl unmask tmp.mount' and 'systemctl enable tmp.mount', or add an /etc/fstab entry for {path}."
            if unit
            else f"Create a dedicated partition or logical volume for {path}, migrate the data during a maintenance window and add it to /etc/fstab."
        ),
        [man("fstab.5"), man("systemd.mount.5")],
    )


OPTION_TEXT = {
    "nodev": ("device files", "Device files created on this filesystem could give direct access to disks or kernel memory."),
    "nosuid": ("setuid and setgid programs", "A setuid program placed on this filesystem could be used to escalate privileges."),
    "noexec": ("executable programs", "Malicious binaries dropped here by an attacker or a compromised service could be executed directly."),
}


def mount_option(cis_id: str, path: str, option: str, severity: str) -> None:
    what, impact = OPTION_TEXT[option]
    add(
        cis_id,
        severity,
        {"type": "mount_option", "path": path, "option": option},
        f"Checks that {path}, when it is a separate mount, is mounted with {option}, which blocks {what} on it.",
        f"{path} does not need {what}, so the {option} option removes an avenue for abuse at no functional cost.",
        impact,
        f"Mount {path} with the {option} option.",
        f"Add {option} to the options of the {path} entry in /etc/fstab (or to a systemd mount override for {path}), then run 'mount -o remount {path}'.",
        [man("mount.8"), man("fstab.5")],
    )


separate_mount("1.1.2.1.1", "/tmp", "Medium", unit="tmp.mount")
mount_option("1.1.2.1.2", "/tmp", "nodev", "Medium")
mount_option("1.1.2.1.3", "/tmp", "nosuid", "Medium")
mount_option("1.1.2.1.4", "/tmp", "noexec", "Medium")
separate_mount("1.1.2.2.1", "/dev/shm", "Medium")
mount_option("1.1.2.2.2", "/dev/shm", "nodev", "Medium")
mount_option("1.1.2.2.3", "/dev/shm", "nosuid", "Medium")
mount_option("1.1.2.2.4", "/dev/shm", "noexec", "Medium")
separate_mount("1.1.2.3.1", "/home", "Low")
mount_option("1.1.2.3.2", "/home", "nodev", "Low")
mount_option("1.1.2.3.3", "/home", "nosuid", "Low")
separate_mount("1.1.2.4.1", "/var", "Low")
mount_option("1.1.2.4.2", "/var", "nodev", "Low")
mount_option("1.1.2.4.3", "/var", "nosuid", "Low")
separate_mount("1.1.2.5.1", "/var/tmp", "Low")
mount_option("1.1.2.5.2", "/var/tmp", "nodev", "Medium")
mount_option("1.1.2.5.3", "/var/tmp", "nosuid", "Medium")
mount_option("1.1.2.5.4", "/var/tmp", "noexec", "Medium")
separate_mount("1.1.2.6.1", "/var/log", "Low")
mount_option("1.1.2.6.2", "/var/log", "nodev", "Low")
mount_option("1.1.2.6.3", "/var/log", "nosuid", "Low")
mount_option("1.1.2.6.4", "/var/log", "noexec", "Low")
separate_mount("1.1.2.7.1", "/var/log/audit", "Low")
mount_option("1.1.2.7.2", "/var/log/audit", "nodev", "Low")
mount_option("1.1.2.7.3", "/var/log/audit", "nosuid", "Low")
mount_option("1.1.2.7.4", "/var/log/audit", "noexec", "Low")

# ------------------------------------------------------------ 1.2 APT
manual(
    "1.2.1.1",
    "Verify that every deb/deb-src entry and deb822 stanza pins its repository to a dedicated keyring with Signed-By.",
    "Add '[signed-by=/usr/share/keyrings/<vendor>.gpg]' to .list entries or a 'Signed-By:' field to .sources stanzas, referencing a keyring for that repository only.",
    [man("sources.list.5")],
)
add(
    "1.2.1.2",
    "Low",
    {"type": "apt_config", "settings": [{"key": "APT::Install-Recommends", "value": False}, {"key": "APT::Install-Suggests", "value": False}]},
    "Checks that APT does not automatically install recommended or suggested packages.",
    "Installing only explicitly requested packages keeps the software inventory minimal and reviewable.",
    "Weak dependencies silently add software, services and code paths that nobody chose to deploy or maintain.",
    "Configure APT to install only hard dependencies.",
    "Create /etc/apt/apt.conf.d/60-cis-weak-deps containing 'APT::Install-Recommends \"0\";' and 'APT::Install-Suggests \"0\";'.",
    [man("apt.conf.5")],
)
add(
    "1.2.1.3",
    "Medium",
    {"type": "file_permissions", "targets": [{"source": "apt_keyring_files"}, {"source": "apt_signed_by_keys"}], "max_mode": "0644", "owners": ["root"], "groups": ["root"]},
    "Checks that APT keyring files in /usr/share/keyrings, /etc/apt/trusted.gpg.d and any Signed-By location are root-owned and no more permissive than 0644.",
    "Repository signing keys decide which packages the system trusts.",
    "A user who can modify a trusted keyring can make the system accept and install attacker-signed packages as root.",
    "Restrict APT keyring files to root ownership and mode 0644 or stricter.",
    "Run 'chown root:root <keyring>' and 'chmod u-x,go-wx <keyring>' for each reported file.",
    [man("apt-secure.8")],
)


def apt_directory(cis_id: str, path: str, severity: str, purpose: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "file_permissions", "targets": [{"path": path}], "max_mode": "0755", "owners": ["root"], "groups": ["root"], "file_type": "dir"},
        f"Checks that {path} is owned by root:root and no more permissive than 0755.",
        f"{path} holds {purpose}; only root should be able to add or replace entries in it.",
        f"A writable {path} lets an unprivileged user change which repositories or credentials APT uses, leading to installation of malicious packages.",
        f"Restrict {path} to root ownership and mode 0755 or stricter.",
        f"Run 'chown root:root {path}' and 'chmod 0755 {path}'.",
        [man("apt.conf.5"), man("sources.list.5")],
    )


apt_directory("1.2.1.4", "/etc/apt/trusted.gpg.d", "Medium", "trusted repository signing keys")
apt_directory("1.2.1.5", "/etc/apt/auth.conf.d", "Low", "repository login credentials")
add(
    "1.2.1.6",
    "Medium",
    {"type": "file_permissions", "targets": [{"glob": "/etc/apt/auth.conf.d/*", "files_only": True}], "max_mode": "0640", "owners": ["root"], "groups": ["root"]},
    "Checks that files in /etc/apt/auth.conf.d are root-owned and no more permissive than 0640.",
    "These files contain credentials for authenticated package repositories.",
    "Readable repository credentials can be reused to access private package feeds or pivot into the software supply chain.",
    "Restrict repository credential files to root with mode 0640 or stricter.",
    "Run 'chown root:root /etc/apt/auth.conf.d/*' and 'chmod 0640 /etc/apt/auth.conf.d/*'.",
    [man("apt_auth.conf.5")],
)
apt_directory("1.2.1.7", "/usr/share/keyrings", "Medium", "vendor repository keyrings")
apt_directory("1.2.1.8", "/etc/apt/sources.list.d", "Medium", "repository definitions")
add(
    "1.2.1.9",
    "Medium",
    {"type": "file_permissions", "targets": [{"glob": "/etc/apt/sources.list.d/*", "files_only": True}], "max_mode": "0644", "owners": ["root"], "groups": ["root"]},
    "Checks that repository definition files in /etc/apt/sources.list.d are root-owned and no more permissive than 0644.",
    "Repository definitions determine where packages are downloaded from.",
    "A user who can edit a repository file can redirect package installation to an attacker-controlled mirror.",
    "Restrict repository definition files to root with mode 0644 or stricter.",
    "Run 'chown root:root /etc/apt/sources.list.d/*' and 'chmod u-x,go-wx /etc/apt/sources.list.d/*'.",
    [man("sources.list.5")],
)
for cis_id, scope, where in (("1.2.1.10", "sources.list", "/etc/apt/sources.list"), ("1.2.1.11", "sources.list.d", "/etc/apt/sources.list.d")):
    add(
        cis_id,
        "Low",
        {"type": "apt_sources_https", "scope": scope},
        f"Checks that no repository in {where} uses plain HTTP.",
        "HTTPS protects package metadata and downloads from eavesdropping and tampering in transit, complementing signature checks.",
        "Over HTTP an on-path attacker can observe which packages are installed and attempt downgrade or freeze attacks against the package metadata.",
        "Use HTTPS repository URIs.",
        f"Change 'http://' URIs in {where} to 'https://' (for example https://deb.debian.org/debian) and run 'apt update'.",
        [man("sources.list.5")],
    )


def apt_bool(cis_id: str, key: str, value: bool, severity: str, what: str, impact: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "apt_config", "settings": [{"key": key, "value": value}]},
        f"Checks that {key} is explicitly set to \"{1 if value else 0}\" in the APT configuration.",
        f"{what} Explicit configuration prevents a later configuration file from silently changing the behaviour.",
        impact,
        f"Set {key} to \"{1 if value else 0}\" explicitly.",
        f"Create /etc/apt/apt.conf.d/60-cis-{key.split('::')[-1].lower()} containing '{key} \"{'true' if value else 'false'}\";' and remove conflicting settings.",
        [man("apt.conf.5"), man("apt-secure.8")],
    )


apt_bool("1.2.1.12", "Acquire::AllowInsecureRepositories", False, "Medium", "Unsigned repositories bypass APT's package authentication.", "Allowing unsigned repositories lets an attacker who controls a mirror or the network deliver arbitrary packages.")
apt_bool("1.2.1.13", "Acquire::AllowWeakRepositories", False, "Medium", "Weakly signed repositories rely on broken digest or signature algorithms.", "Weak signatures can be forged, allowing tampered package metadata to be accepted.")
apt_bool("1.2.1.14", "Acquire::AllowDowngradeToInsecureRepositories", False, "Medium", "A signed repository must never be downgraded to an unsigned one.", "A downgrade lets an attacker strip signatures from a previously trusted repository and serve malicious packages.")
apt_bool("1.2.1.15", "Acquire::Check-Date", True, "Low", "Date checks reject stale or future-dated Release files.", "Without date validation, replayed old metadata can keep the system on vulnerable package versions.")
manual(
    "1.2.2.1",
    "Verify that security updates and patches are applied according to the patch management policy.",
    "Run 'apt update' followed by 'apt upgrade' (or your configuration management workflow) and reboot when a new kernel is installed.",
    [man("apt.8")],
)

# ------------------------------------------------------------ 1.3 AppArmor
add(
    "1.3.1.1",
    "Medium",
    {"type": "package_installed", "packages": ["apparmor", "apparmor-utils"]},
    "Checks that the apparmor and apparmor-utils packages are installed.",
    "AppArmor provides mandatory access control that confines services beyond ordinary file permissions.",
    "Without AppArmor a compromised service can use every privilege of its Unix account instead of a narrow profile.",
    "Install AppArmor and its management utilities.",
    "Run 'apt install apparmor apparmor-utils'.",
    [man("apparmor.7")],
)
add(
    "1.3.1.2",
    "High",
    {"type": "apparmor_enabled"},
    "Checks that AppArmor is not disabled on the kernel command line, that apparmor.service is enabled and active, and that profiles are loaded.",
    "Mandatory access control only protects the system when it is enforced at boot and at runtime.",
    "With AppArmor disabled, every confined service runs unconfined, so a single exploited daemon has far wider access to files and capabilities.",
    "Enable AppArmor at boot and keep its profiles loaded.",
    "Remove apparmor=0 from GRUB_CMDLINE_LINUX and /etc/default/grub.d/apparmor.cfg, run 'update-grub', then 'systemctl enable --now apparmor'.",
    [man("apparmor.7"), man("aa-status.8")],
)
add(
    "1.3.1.3",
    "Medium",
    {"type": "apparmor_enforcing"},
    "Checks that every loaded AppArmor profile is in enforce mode and that no process with a defined profile runs unconfined.",
    "Profiles in complain mode only log violations; they do not block them.",
    "Services whose profiles are not enforced can perform actions their profile would deny, so an exploit is not contained.",
    "Enforce all AppArmor profiles after validating them.",
    "Run 'aa-enforce /etc/apparmor.d/*' after testing, develop real rules for stub profiles, and restart processes reported as unconfined.",
    [man("aa-enforce.8"), man("aa-status.8")],
)
add(
    "1.3.1.4",
    "Medium",
    {"type": "sysctl", "parameter": "kernel.apparmor_restrict_unprivileged_unconfined", "expected": ["1"]},
    "Checks that kernel.apparmor_restrict_unprivileged_unconfined is 1 at runtime and in the sysctl configuration.",
    "The setting stops unprivileged, unconfined processes from changing into less restricted AppArmor profiles.",
    "Without it an unprivileged attacker can escape AppArmor restrictions, for example to reach unprivileged user namespaces.",
    "Enable kernel.apparmor_restrict_unprivileged_unconfined.",
    "Add 'kernel.apparmor_restrict_unprivileged_unconfined = 1' to /etc/sysctl.d/60-cis.conf and run 'sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1'.",
    [man("sysctl.d.5")],
)

# ------------------------------------------------------------ 1.4 Bootloader
add(
    "1.4.1",
    "Medium",
    {"type": "bootloader_password"},
    "Checks that GRUB defines a superuser protected by a PBKDF2 password hash.",
    "A bootloader password stops console users from editing boot entries or passing kernel parameters.",
    "Anyone with console access could boot into single-user mode or add init=/bin/bash and obtain a root shell without credentials.",
    "Protect the GRUB configuration with a superuser password.",
    "Generate a hash with 'grub-mkpasswd-pbkdf2', add 'set superusers=\"<user>\"' and 'password_pbkdf2 <user> <hash>' to /etc/grub.d/40_custom, then run 'update-grub'.",
    ["https://www.gnu.org/software/grub/manual/grub/html_node/Authentication-and-authorisation.html"],
)
add(
    "1.4.2",
    "Medium",
    {"type": "file_permissions", "targets": [{"path": "/boot/grub/grub.cfg", "missing": "unassessed"}], "max_mode": "0600", "owners": ["root"], "groups": ["root"]},
    "Checks that /boot/grub/grub.cfg is owned by root:root and no more permissive than 0600.",
    "The GRUB configuration contains boot parameters and may contain password hashes.",
    "Readable or writable bootloader configuration exposes password hashes for offline cracking and allows boot parameters to be altered.",
    "Restrict the GRUB configuration to root with mode 0600.",
    "Run 'chown root:root /boot/grub/grub.cfg' and 'chmod u-x,go-rwx /boot/grub/grub.cfg' (repeat after update-grub regenerates it).",
    [man("update-grub.8")],
)

# ------------------------------------------------------------ 1.5 Process hardening
def sysctl(cis_id: str, name: str, expected: list[str], severity: str, purpose: str, impact: str, applies_if: list[dict] | None = None) -> None:
    shown = " or ".join(expected)
    value = expected[0]
    flush = " and 'sysctl -w net.ipv4.route.flush=1'" if name.startswith("net.ipv4") else (" and 'sysctl -w net.ipv6.route.flush=1'" if name.startswith("net.ipv6") else "")
    add(
        cis_id,
        severity,
        {"type": "sysctl", "parameter": name, "expected": expected},
        f"Checks that {name} is {shown} both in the running kernel and in the sysctl configuration applied at boot.",
        purpose,
        impact,
        f"Set {name} to {shown} persistently.",
        f"Add '{name} = {value}' to /etc/sysctl.d/60-cis.conf, remove or correct conflicting entries in other sysctl files, then run 'sysctl -w {name}={value}'{flush}.",
        [man("sysctl.d.5"), "https://docs.kernel.org/admin-guide/sysctl/index.html"],
        applies_if,
    )


sysctl("1.5.1", "fs.protected_hardlinks", ["1"], "Medium", "Hard-link protection stops users from creating links to files they do not own.", "Without it an attacker can exploit time-of-check/time-of-use races in privileged programs through crafted hard links.")
sysctl("1.5.2", "fs.protected_symlinks", ["1"], "Medium", "Symlink protection restricts following symlinks in world-writable sticky directories.", "Without it a local attacker can plant symlinks in /tmp to trick privileged processes into overwriting arbitrary files.")
sysctl("1.5.3", "kernel.yama.ptrace_scope", ["1", "2", "3"], "Medium", "Yama restricts which processes may attach to others with ptrace.", "With unrestricted ptrace, any compromised process can read the memory of other processes owned by the same user, including credentials and keys.")
sysctl("1.5.4", "fs.suid_dumpable", ["0"], "Medium", "Setuid programs should not produce core dumps.", "Core dumps of privileged programs can contain password hashes, keys and other secrets readable from disk.")
sysctl("1.5.5", "kernel.dmesg_restrict", ["1"], "Low", "Restricting the kernel log to privileged users limits information disclosure.", "Kernel messages reveal addresses and hardware details that help attackers tune kernel exploits.")
add(
    "1.5.6",
    "Low",
    {"type": "package_absent", "packages": ["prelink"]},
    "Checks that prelink is not installed.",
    "prelink modifies binaries in place, which defeats address randomization and file integrity monitoring.",
    "Prelinked binaries weaken ASLR and cause integrity tools such as AIDE to report changes that hide real tampering.",
    "Remove prelink.",
    "Run 'prelink -ua' to restore binaries, then 'apt purge prelink'.",
    [man("prelink.8")],
)
add(
    "1.5.7",
    "Low",
    {"type": "apport_disabled"},
    "Checks that the Apport automatic error reporting service is not enabled or running.",
    "Crash reports can capture memory contents of the crashing process.",
    "Automatically collected crash reports may contain credentials or personal data and have historically been abused for local privilege escalation.",
    "Disable automatic error reporting.",
    "Set 'enabled=0' in /etc/default/apport and run 'systemctl --now disable apport', or remove the apport package.",
    [man("apport.1")],
)
sysctl("1.5.8", "kernel.kptr_restrict", ["1", "2"], "Low", "Hiding kernel pointers from unprivileged users limits information disclosure.", "Exposed kernel addresses defeat kernel address randomization and simplify kernel exploits.")
sysctl("1.5.9", "kernel.randomize_va_space", ["2"], "High", "Full address space layout randomization places stacks, heaps and libraries at unpredictable addresses.", "Without ASLR, memory-corruption exploits against any service become far more reliable.")
add(
    "1.5.10",
    "Medium",
    {"type": "core_dump_limit"},
    "Checks that a hard core file size limit of 0 applies to all users ('* hard core 0') and that no entry allows larger core files.",
    "Preventing core dumps keeps process memory, which may hold secrets, from being written to disk.",
    "Core files can expose passwords, keys and session tokens held in the memory of crashing programs.",
    "Set a hard core size limit of 0 for all users.",
    "Add '* hard core 0' to a file such as /etc/security/limits.d/60-cis.conf and remove entries that allow core files.",
    [man("limits.conf.5")],
)
for cis_id, option, expected, default in (("1.5.11", "ProcessSizeMax", ["0"], "2G"), ("1.5.12", "Storage", ["none"], "external")):
    add(
        cis_id,
        "Medium",
        {"type": "systemd_config", "config": "coredump.conf", "section": "Coredump", "option": option, "expected": expected, "package": "systemd-coredump", "builtin_default": default},
        f"Checks that systemd-coredump sets {option}={expected[0]} (compliant automatically when systemd-coredump is not installed).",
        "systemd-coredump should neither process nor store core dumps on production systems.",
        "Stored core dumps can disclose secrets from process memory and consume disk space.",
        f"Set {option}={expected[0]} for systemd-coredump.",
        f"Create /etc/systemd/coredump.conf.d/60-cis.conf containing '[Coredump]' and '{option}={expected[0]}', then run 'systemctl daemon-reload'.",
        [man("coredump.conf.5")],
    )

# ------------------------------------------------------------ 1.6 Banners
BANNER_WHY = "Login banners should state authorized-use terms without disclosing the operating system or kernel version."
BANNER_IMPACT = "Banners that reveal the OS name and version help attackers select exploits and fingerprint the host before authenticating."


def banner(cis_id: str, targets: list[dict], what: str, remediation: str, **extra: Any) -> None:
    add(
        cis_id,
        "Low",
        {"type": "banner_content", "targets": targets, **{k: v for k, v in extra.items() if k != "applies_if"}},
        f"Checks that {what} contains no \\m, \\r, \\s or \\v escape sequences and no reference to the operating system name.",
        BANNER_WHY,
        BANNER_IMPACT,
        f"Replace {what} with an authorized-use notice that does not identify the platform.",
        remediation,
        [man("issue.5"), man("motd.5")],
        extra.get("applies_if"),
    )


banner("1.6.1", [{"path": "/etc/motd"}, {"glob": "/etc/motd.d/*", "files_only": True}], "the message of the day (/etc/motd and /etc/motd.d)", "Edit or remove /etc/motd and files in /etc/motd.d so they contain only site-approved text.")
banner("1.6.2", [{"path": "/etc/issue"}, {"glob": "/usr/lib/issue.d/*", "files_only": True}, {"glob": "/etc/issue.d/*", "files_only": True}, {"glob": "/run/issue.d/*", "files_only": True}], "the local login banner (/etc/issue and issue.d)", "Write the approved notice to /etc/issue, for example: echo 'Authorized users only. All activity may be monitored and reported.' > /etc/issue.")
banner("1.6.3", [{"path": "/etc/issue.net"}], "the remote login banner (/etc/issue.net)", "Write the approved notice to /etc/issue.net, for example: echo 'Authorized users only. All activity may be monitored and reported.' > /etc/issue.net.")
banner("1.6.4", [{"source": "pam_motd_files"}], "every file shown by pam_motd (motd= in the sshd, login, su and gdm-password PAM stacks)", "Edit the files referenced by motd= in /etc/pam.d, or disable the dynamic MOTD scripts in /etc/update-motd.d that write system details to /run/motd.dynamic.")
banner(
    "1.6.5",
    [{"source": "sshd_banner"}],
    "the file configured as the sshd Banner",
    "Point Banner at an approved notice file (for example /etc/issue.net) and remove OS details from it, " + RELOAD_SSH,
    require_configured=True,
    missing_message="sshd has no Banner file configured, so no warning banner is shown before SSH authentication.",
    applies_if=SSH,
)


def banner_access(cis_id: str, targets: list[dict], what: str, applies_if: list[dict] | None = None) -> None:
    add(
        cis_id,
        "Low",
        {"type": "file_permissions", "targets": targets, "max_mode": "0644", "owners": ["root"], "groups": ["root"]},
        f"Checks that {what} is owned by root:root and no more permissive than 0644.",
        "Only root should be able to change the text presented to users at login.",
        "A writable banner lets an unprivileged user alter legal notices or display misleading instructions to other users.",
        f"Restrict {what} to root with mode 0644 or stricter.",
        "Run 'chown root:root <file>' and 'chmod u-x,go-wx <file>' for each reported file.",
        [man("chmod.1")],
        applies_if,
    )


banner_access(
    "1.6.6",
    [{"path": "/etc/motd"}, {"path": "/run/motd"}, {"path": "/usr/lib/motd"}, {"glob": "/etc/motd.d/*"}, {"glob": "/run/motd.d/*"}, {"glob": "/usr/lib/motd.d/*"}, {"glob": "/etc/update-motd.d/*"}],
    "every MOTD file (including /etc/update-motd.d scripts, which CIS expects to be non-executable)",
)
banner_access("1.6.7", [{"path": "/etc/issue"}, {"glob": "/usr/lib/issue.d/*"}, {"glob": "/etc/issue.d/*"}, {"glob": "/run/issue.d/*"}], "/etc/issue and the issue.d files")
banner_access("1.6.8", [{"path": "/etc/issue.net"}], "/etc/issue.net")
banner_access("1.6.9", [{"source": "pam_motd_files_all"}], "every file referenced by pam_motd motd= arguments")
banner_access("1.6.10", [{"source": "sshd_banner"}], "the sshd Banner file", SSH)
for cis_id, unit in (("1.6.11", "update-notifier-motd.service"), ("1.6.12", "update-notifier-motd.timer")):
    add(
        cis_id,
        "Low",
        {"type": "service_not_in_use", "groups": [{"packages": ["update-notifier-common"], "units": [unit]}]},
        f"Checks that {unit} is neither enabled nor active (compliant when update-notifier-common is not installed, the Debian 13 default).",
        "Dynamic MOTD update notices reveal patch status to anyone who logs in.",
        "Announcing pending updates tells an attacker which vulnerabilities are likely still present.",
        f"Disable {unit}.",
        f"Run 'systemctl --now mask {unit}' or remove update-notifier-common.",
        [man("systemctl.1")],
    )

# ------------------------------------------------------------ 1.7 GDM
def gsettings(cis_id: str, severity: str, keys: list[dict], what: str, why: str, impact: str, recommendation: str, remediation: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "gsettings", "keys": keys},
        f"Checks that {what}, and that each setting is locked system-wide.",
        why,
        impact,
        recommendation,
        remediation,
        [man("dconf.7"), man("gsettings.1")],
        GDM,
    )


gsettings(
    "1.7.1",
    "Low",
    [
        {"schema": "org.gnome.login-screen", "key": "banner-message-enable", "rule": {"op": "equals", "value": "true"}, "expected": "true"},
        {"schema": "org.gnome.login-screen", "key": "banner-message-text", "rule": {"op": "nonempty_string"}, "expected": "an approved notice"},
    ],
    "the GDM login banner is enabled with approved text",
    "A warning banner at the graphical login states the terms of authorized use.",
    "Without a banner the organization weakens its legal position when prosecuting or disciplining misuse.",
    "Enable and lock an approved GDM login banner.",
    "Add banner-message-enable=true and banner-message-text='<notice>' under [org/gnome/login-screen] in /etc/dconf/db/local.d/, lock both keys in /etc/dconf/db/local.d/locks/, and run 'dconf update'.",
)
gsettings(
    "1.7.2",
    "Low",
    [{"schema": "org.gnome.login-screen", "key": "disable-user-list", "rule": {"op": "equals", "value": "true"}, "expected": "true"}],
    "the GDM user list is disabled",
    "Hiding the user list forces users to type their user name.",
    "A visible user list discloses valid account names to anyone at the console, halving the work of password guessing.",
    "Disable and lock the GDM user list.",
    "Add disable-user-list=true under [org/gnome/login-screen] in /etc/dconf/db/local.d/, lock it in /etc/dconf/db/local.d/locks/, and run 'dconf update'.",
)
gsettings(
    "1.7.3",
    "Medium",
    [
        {"schema": "org.gnome.desktop.session", "key": "idle-delay", "rule": {"op": "range", "min": 1, "max": 900}, "expected": "1-900 seconds"},
        {"schema": "org.gnome.desktop.screensaver", "key": "lock-delay", "rule": {"op": "max", "value": 5}, "expected": "5 seconds or less"},
    ],
    "the screen locks after at most 15 minutes of inactivity and within 5 seconds of blanking",
    "Automatic screen locking protects unattended sessions.",
    "An unlocked, unattended session gives anyone nearby the logged-in user's access.",
    "Configure and lock an idle screen lock of 15 minutes or less.",
    "Set idle-delay=uint32 900 under [org/gnome/desktop/session] and lock-delay=uint32 5 under [org/gnome/desktop/screensaver] in /etc/dconf/db/local.d/, lock both keys, and run 'dconf update'.",
)
gsettings(
    "1.7.4",
    "Medium",
    [
        {"schema": "org.gnome.desktop.media-handling", "key": "automount", "rule": {"op": "equals", "value": "false"}, "expected": "false"},
        {"schema": "org.gnome.desktop.media-handling", "key": "automount-open", "rule": {"op": "equals", "value": "false"}, "expected": "false"},
    ],
    "GNOME automount of removable media is disabled",
    "Removable media should only be mounted deliberately.",
    "Automatic mounting exposes filesystem drivers to untrusted media and eases introduction of malware or data theft.",
    "Disable and lock GNOME automount.",
    "Set automount=false and automount-open=false under [org/gnome/desktop/media-handling] in /etc/dconf/db/local.d/, lock both keys, and run 'dconf update'.",
)
gsettings(
    "1.7.5",
    "Medium",
    [{"schema": "org.gnome.desktop.media-handling", "key": "autorun-never", "rule": {"op": "equals", "value": "true"}, "expected": "true"}],
    "GNOME autorun of removable media is disabled",
    "Software on removable media should never run automatically.",
    "Autorun lets malicious media execute code as soon as it is inserted.",
    "Disable and lock GNOME autorun.",
    "Set autorun-never=true under [org/gnome/desktop/media-handling] in /etc/dconf/db/local.d/, lock the key, and run 'dconf update'.",
)
add(
    "1.7.6",
    "Medium",
    {"type": "gdm_config", "section": "xdmcp", "key": "Enable", "value": "true", "expect": "absent"},
    "Checks that XDMCP is not enabled in the GDM configuration.",
    "XDMCP sends graphical login sessions, including credentials, over the network without encryption.",
    "Credentials and session contents can be captured on the network, and the display manager is exposed to remote attack.",
    "Disable XDMCP.",
    "Remove 'Enable=true' from the [xdmcp] section of /etc/gdm3/custom.conf and /etc/gdm3/daemon.conf.",
    [man("gdm3.8")],
    GDM,
)
add(
    "1.7.7",
    "Low",
    {"type": "gdm_config", "section": "daemon", "key": "WaylandEnable", "value": "false", "expect": "present"},
    "Checks that GDM sets WaylandEnable=false in its [daemon] configuration, as CIS prescribes for Xwayland.",
    "CIS recommends a single, known display-server configuration for GDM.",
    "An unmanaged display-server stack increases the graphical attack surface exposed through the display manager.",
    "Set WaylandEnable=false for GDM.",
    "Add 'WaylandEnable=false' under [daemon] in /etc/gdm3/custom.conf and restart GDM during a maintenance window.",
    [man("gdm3.8")],
    GDM,
)

# =========================================================== 2 Services
def service(cis_id: str, groups: list[dict], name: str, severity: str, why: str, impact: str) -> None:
    packages = [p for g in groups for p in g.get("packages", [])] or [g.get("package_pattern", "") for g in groups]
    units = [u for g in groups for u in g.get("units", [])]
    add(
        cis_id,
        severity,
        {"type": "service_not_in_use", "groups": groups},
        f"Checks that the {name} ({', '.join(packages)}) is not installed or, when another package requires it, that {', '.join(units)} are neither enabled nor active.",
        why,
        impact,
        f"Remove the {name} unless it is required and approved.",
        f"Run 'apt purge {' '.join(p for p in packages if p)}'; if a dependency requires the package, run 'systemctl --now mask {' '.join(units)}'.",
        [man("systemctl.1")],
    )


service("2.1.1", [{"packages": ["autofs"], "units": ["autofs.service"]}], "automounter", "Low", "autofs mounts filesystems, including removable media and network shares, on demand.", "Automatic mounting lets users introduce untrusted media and exposes filesystem drivers to crafted content.")
service("2.1.2", [{"packages": ["avahi-daemon"], "units": ["avahi-daemon.socket", "avahi-daemon.service"]}], "Avahi mDNS/DNS-SD daemon", "Medium", "Avahi advertises and discovers services on the local network.", "Service advertisements disclose host details and the daemon adds a network listener that has had remote vulnerabilities.")
service("2.1.3", [{"package_pattern": "kea", "units": ["kea-dhcp-ddns-server.service", "kea-dhcp4-server.service", "kea-dhcp6-server.service"]}], "Kea DHCP server", "Medium", "A DHCP server is only needed on hosts that assign network configuration.", "A rogue or exposed DHCP service can redirect clients to attacker-controlled gateways and DNS servers.")
service("2.1.4", [{"packages": ["bind9"], "units": ["named.service"]}], "BIND DNS server", "Medium", "A DNS server is only needed on hosts that provide name resolution.", "An unmanaged DNS server can be abused for amplification attacks or cache poisoning and adds a remotely reachable service.")
service("2.1.5", [{"packages": ["dnsmasq"], "units": ["dnsmasq.service"]}], "dnsmasq DNS/DHCP service", "Medium", "dnsmasq provides DNS and DHCP services that most servers do not need.", "dnsmasq has had remotely exploitable vulnerabilities and can hand out malicious network settings.")
service("2.1.6", [{"packages": ["vsftpd"], "units": ["vsftpd.service"]}], "FTP server", "Medium", "FTP transfers data and, unless wrapped in TLS, credentials in clear text.", "FTP credentials and files can be intercepted on the network, and anonymous or misconfigured FTP exposes data.")
service("2.1.7", [{"packages": ["slapd"], "units": ["slapd.service"]}], "OpenLDAP server", "Medium", "An LDAP directory server is only needed on directory hosts.", "An unmanaged directory service can disclose account data or accept unauthorized changes.")
service("2.1.8", [{"packages": ["dovecot-imapd", "dovecot-pop3d"], "units": ["dovecot.socket", "dovecot.service"]}], "IMAP/POP3 server", "Medium", "Mail access services are only needed on mail servers.", "An exposed mail access service invites password guessing and may accept clear-text logins.")
service("2.1.9", [{"packages": ["nfs-kernel-server"], "units": ["nfs-server.service"]}], "NFS server", "Medium", "NFS exports filesystems to other hosts.", "Mis-scoped NFS exports expose data and can allow file changes from other hosts with weak authentication.")
service("2.1.10", [{"packages": ["ypserv"], "units": ["ypserv.service"]}], "NIS server", "High", "NIS is an obsolete directory protocol with no meaningful authentication or encryption.", "NIS maps, including password hashes, can be retrieved by any host that can reach the server.")
service("2.1.11", [{"packages": ["cups"], "units": ["cups.socket", "cups.service"]}], "CUPS print server", "Low", "Printing services are rarely needed on servers.", "CUPS adds a network-facing service that has had remote code execution vulnerabilities.")
service("2.1.12", [{"packages": ["rpcbind"], "units": ["rpcbind.socket", "rpcbind.service"]}], "rpcbind portmapper", "Medium", "rpcbind maps RPC services to ports and is only needed for NFS and other RPC services.", "rpcbind discloses RPC services, can be abused for reflection attacks and widens the remote attack surface.")
service("2.1.13", [{"packages": ["rsync"], "units": ["rsync.service"]}], "rsync daemon", "Medium", "The rsync daemon serves files over an unencrypted protocol; rsync over SSH does not need it.", "An rsync daemon can expose or accept files without strong authentication or encryption.")
service("2.1.14", [{"packages": ["samba"], "units": ["smbd.service"]}], "Samba file server", "Medium", "SMB file sharing is only needed on file servers.", "Samba is a frequent target of remote exploits and misconfigured shares expose data.")
service("2.1.15", [{"packages": ["snmpd"], "units": ["snmpd.service"]}], "SNMP agent", "Medium", "SNMP exposes system information for monitoring and older versions authenticate with clear-text community strings.", "Default or weak community strings disclose detailed configuration and may allow configuration changes.")
service("2.1.16", [{"package_pattern": "^telnetd", "units": ["inetutils-inetd.service"]}], "Telnet server", "High", "Telnet transmits sessions, including credentials, in clear text.", "Anyone on the network path can capture Telnet credentials and hijack sessions.")
service("2.1.17", [{"packages": ["tftpd-hpa"], "units": ["tftpd-hpa.service"]}], "TFTP server", "High", "TFTP has no authentication and is only needed for network boot services.", "Any host that can reach TFTP can read (and possibly write) the files it serves.")
service("2.1.18", [{"packages": ["squid"], "units": ["squid.service"]}], "Squid web proxy", "Medium", "A web proxy is only needed on dedicated proxy hosts.", "An unmanaged proxy can be abused to relay attacks or bypass network egress controls.")
service("2.1.19", [{"packages": ["apache2"], "units": ["apache2.socket", "apache2.service"]}, {"packages": ["nginx"], "units": ["nginx.service"]}], "web server", "Medium", "Web servers should only run on hosts whose role is to serve web content.", "An unmanaged web server adds a remotely reachable service and may expose default content or files.")
service("2.1.20", [{"packages": ["xinetd"], "units": ["xinetd.service"]}], "xinetd super-server", "Medium", "xinetd starts legacy network services on demand.", "Legacy services started by xinetd are often insecure and easy to overlook.")
add(
    "2.1.21",
    "Low",
    {"type": "package_absent", "packages": ["xserver-common"]},
    "Checks that the X Window System server (xserver-common) is not installed on a server.",
    "Servers rarely need a graphical display server.",
    "The X server is large, runs with elevated privileges and adds local attack surface without serving a business purpose.",
    "Remove the X Window System from servers.",
    "Run 'apt purge xserver-common' after confirming no graphical workloads depend on it.",
    ["https://wiki.debian.org/Xorg"],
)
add(
    "2.1.22",
    "Medium",
    {"type": "mta_local_only"},
    "Checks that nothing listens on SMTP ports 25, 465 or 587 on a non-loopback address and that the MTA is configured for local-only delivery.",
    "Servers usually only need to send mail, not accept it from the network.",
    "A network-reachable MTA can be abused as an open relay or exploited remotely.",
    "Restrict the mail transfer agent to the loopback interface.",
    "For Postfix set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf and restart postfix; for Exim run 'dpkg-reconfigure exim4-config' and choose local delivery on 127.0.0.1 and ::1.",
    [man("postconf.5")],
)
manual(
    "2.1.23",
    "Review every listening socket ('ss -plntu') and confirm each service is required and approved.",
    "Stop, mask or remove services that are not approved, or restrict their listening addresses.",
    [man("ss.8")],
)


def client(cis_id: str, packages: list[str], name: str, severity: str, why: str, impact: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "package_absent", "packages": packages},
        f"Checks that the {name} ({', '.join(packages)}) is not installed.",
        why,
        impact,
        f"Remove the {name}.",
        f"Run 'apt purge {' '.join(packages)}'.",
        [man("apt.8")],
    )


client("2.2.1", ["nis"], "NIS client", "Medium", "The NIS client depends on an insecure, obsolete directory protocol.", "NIS clients trust unauthenticated directory data, allowing account spoofing on the network.")
client("2.2.2", ["rsh-client"], "rsh client", "High", "rsh, rcp and rlogin authenticate by host name and send data in clear text.", "rsh sessions can be intercepted or spoofed, exposing credentials and data.")
client("2.2.3", ["talk"], "talk client", "Low", "talk is an unauthenticated, clear-text chat tool with no business use on servers.", "It adds legacy network code that serves no purpose on a managed server.")
client("2.2.4", ["telnet", "inetutils-telnet", "telnet-ssl"], "Telnet client", "Medium", "Telnet sessions are unencrypted.", "Users who connect with Telnet expose their credentials on the network.")
client("2.2.5", ["ldap-utils"], "LDAP client utilities", "Low", "LDAP command-line tools are rarely needed on servers.", "Directory query tools make reconnaissance of the directory easier for an attacker already on the host.")
client("2.2.6", ["ftp", "tnftp", "atftp", "inetutils-ftp", "ftp-ssl"], "FTP/TFTP client", "Medium", "FTP clients transfer credentials and data without encryption.", "FTP use exposes credentials and data to network interception.")

add(
    "2.3.1.1",
    "Medium",
    {"type": "single_time_daemon"},
    "Checks that exactly one of systemd-timesyncd and chrony is enabled or running.",
    "Accurate, consistent time is required for log correlation, authentication protocols and certificate validation.",
    "No time source makes logs unreliable in an investigation; two competing daemons cause clock instability.",
    "Run exactly one time synchronization daemon.",
    "Enable one daemon ('systemctl enable --now systemd-timesyncd' or install chrony) and disable or remove the other.",
    [man("systemd-timesyncd.service.8"), man("chronyd.8")],
)
add(
    "2.3.2.1",
    "Medium",
    {"type": "timesyncd_servers"},
    "Checks that systemd-timesyncd has NTP or FallbackNTP servers configured (and, if approved_time_servers is set, that only approved servers are used).",
    "Time should come from authoritative, site-approved sources.",
    "Unapproved or default time sources can be spoofed or unavailable, skewing logs and breaking time-dependent security controls.",
    "Configure systemd-timesyncd with the approved time servers.",
    "Create /etc/systemd/timesyncd.conf.d/60-cis.conf with '[Time]', 'NTP=<approved servers>' and 'FallbackNTP=<approved servers>', then 'systemctl restart systemd-timesyncd'.",
    [man("timesyncd.conf.5")],
    [{"type": "time_daemon", "daemon": "timesyncd"}],
)
add(
    "2.3.2.2",
    "Medium",
    {"type": "unit_state", "units": [{"name": "systemd-timesyncd.service", "enabled": True, "active": True}]},
    "Checks that systemd-timesyncd.service is enabled and running.",
    "The configured time source only helps if the daemon runs.",
    "A stopped time daemon lets the clock drift, undermining logs and time-based authentication.",
    "Enable and start systemd-timesyncd.",
    "Run 'systemctl unmask systemd-timesyncd.service' and 'systemctl --now enable systemd-timesyncd.service'.",
    [man("systemd-timesyncd.service.8")],
    [{"type": "time_daemon", "daemon": "timesyncd"}],
)
add(
    "2.3.3.1",
    "Medium",
    {"type": "chrony_sources"},
    "Checks that chrony has at least one server or pool directive in chrony.conf or its included source files.",
    "chrony needs an authoritative source to synchronize against.",
    "Without a configured source the clock drifts, undermining logs and time-dependent controls.",
    "Configure chrony with the approved time servers.",
    "Add 'server <approved-host> iburst' or 'pool <approved-pool> iburst' lines to /etc/chrony/sources.d/60-cis.sources and run 'chronyc reload sources'.",
    [man("chrony.conf.5")],
    [{"type": "time_daemon", "daemon": "chrony"}],
)
add(
    "2.3.3.2",
    "Medium",
    {"type": "chrony_user"},
    "Checks that every running chronyd process runs as the unprivileged _chrony user.",
    "chronyd processes network input and should run with minimal privileges.",
    "A chronyd running as root turns any parsing flaw in its network code into full system compromise.",
    "Run chronyd as _chrony.",
    "Ensure /etc/chrony/chrony.conf does not override 'user _chrony' and that /etc/default/chrony does not pass -u root, then restart chrony.",
    [man("chronyd.8")],
    [{"type": "time_daemon", "daemon": "chrony"}],
)
add(
    "2.3.3.3",
    "Medium",
    {"type": "unit_state", "units": [{"name": "chrony.service", "enabled": True, "active": True}]},
    "Checks that chrony.service is enabled and running.",
    "The configured time source only helps if the daemon runs.",
    "A stopped time daemon lets the clock drift, undermining logs and time-based authentication.",
    "Enable and start chrony.",
    "Run 'systemctl unmask chrony.service' and 'systemctl --now enable chrony.service'.",
    [man("chronyd.8")],
    [{"type": "time_daemon", "daemon": "chrony"}],
)

add(
    "2.4.1.1",
    "Medium",
    {"type": "unit_state", "mode": "any_existing", "units": [{"name": "cron.service", "enabled": True, "active": True}, {"name": "crond.service", "enabled": True, "active": True}]},
    "Checks that the cron daemon is enabled and active when cron is installed.",
    "Scheduled maintenance and security jobs depend on cron running.",
    "If cron is stopped, scheduled integrity checks, log rotation and updates silently stop.",
    "Enable and start cron.",
    "Run 'systemctl unmask cron' and 'systemctl --now enable cron'.",
    [man("cron.8")],
    CRON,
)


def cron_path(cis_id: str, path: str, is_dir: bool) -> None:
    kind = "directory" if is_dir else "file"
    add(
        cis_id,
        "Medium",
        {"type": "file_permissions", "targets": [{"path": path}], "max_mode": "0700", "owners": ["root"], "groups": ["root"], **({"file_type": "dir"} if is_dir else {})},
        f"Checks that the cron {kind} {path} is owned by root:root and grants no access to group or other.",
        f"{path} defines jobs that run as root.",
        f"A user who can read {path} learns scheduled privileged activity; one who can write it can run commands as root.",
        f"Restrict {path} to root.",
        f"Run 'chown root:root {path}' and 'chmod og-rwx {path}'.",
        [man("crontab.5")],
        CRON,
    )


cron_path("2.4.1.2", "/etc/crontab", False)
cron_path("2.4.1.3", "/etc/cron.hourly", True)
cron_path("2.4.1.4", "/etc/cron.daily", True)
cron_path("2.4.1.5", "/etc/cron.weekly", True)
cron_path("2.4.1.6", "/etc/cron.monthly", True)
cron_path("2.4.1.7", "/etc/cron.yearly", True)
cron_path("2.4.1.8", "/etc/cron.d", True)
add(
    "2.4.1.9",
    "Medium",
    {
        "type": "file_permissions",
        "targets": [{"path": "/etc/cron.allow", "missing": "fail"}, {"path": "/etc/cron.deny"}],
        "max_mode": "0640",
        "owners": ["root"],
        "groups": ["root", "crontab"],
    },
    "Checks that /etc/cron.allow exists and, like any /etc/cron.deny, is owned by root, group root or crontab, and no more permissive than 0640.",
    "An allow list limits crontab use to named accounts.",
    "Without an allow list any account, including compromised service accounts, can schedule persistent jobs.",
    "Create a restrictive /etc/cron.allow listing only approved users.",
    "Run 'touch /etc/cron.allow', 'chown root:crontab /etc/cron.allow' and 'chmod 0640 /etc/cron.allow'; apply the same ownership and mode to /etc/cron.deny if it exists.",
    [man("crontab.1")],
    CRON,
)
add(
    "2.4.2.1",
    "Medium",
    {
        "type": "file_permissions",
        "targets": [{"path": "/etc/at.allow", "missing": "fail"}, {"path": "/etc/at.deny"}],
        "max_mode": "0640",
        "owners": ["root"],
        "groups": ["root", "daemon"],
    },
    "Checks that /etc/at.allow exists and, like any /etc/at.deny, is owned by root, group root or daemon, and no more permissive than 0640.",
    "An allow list limits use of at to named accounts.",
    "Without an allow list any account can schedule jobs with at to maintain persistence.",
    "Create a restrictive /etc/at.allow listing only approved users.",
    "Run 'touch /etc/at.allow', 'chown root:daemon /etc/at.allow' and 'chmod 0640 /etc/at.allow'; apply the same to /etc/at.deny if it exists.",
    [man("at.allow.5")],
    [{"type": "package_installed", "packages": ["at"]}],
)
