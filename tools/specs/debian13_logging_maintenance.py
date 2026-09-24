"""CIS Debian Linux 13 v1.1.0 specification: sections 6 (Logging and Auditing) and 7 (System Maintenance)."""

from __future__ import annotations

from specs.debian13 import AUGENRULES, AUID, RSYSLOG, add, man, manual

# =========================================================== 6.1 Logging
add(
    "6.1.1.1.1",
    "Medium",
    {"type": "unit_state", "units": [{"name": "systemd-journald.service", "enabled": False, "active": True}]},
    "Checks that systemd-journald.service is active.",
    "journald collects kernel, service and authentication logs.",
    "Without journald most local logging stops and security events are lost.",
    "Keep systemd-journald running.",
    "Run 'systemctl unmask systemd-journald' and 'systemctl start systemd-journald'; journald is a static unit started on demand by its sockets.",
    [man("systemd-journald.service.8")],
)
add(
    "6.1.1.1.2",
    "Medium",
    {"type": "units_not_in_use", "units": ["systemd-journal-remote.socket", "systemd-journal-remote.service"]},
    "Checks that systemd-journal-remote.socket and .service are neither enabled nor active.",
    "A log client should send logs, not accept them from other hosts.",
    "An active journal-remote listener accepts log data from the network, which can be abused to flood or forge logs.",
    "Disable systemd-journal-remote on log clients.",
    "Run 'systemctl --now mask systemd-journal-remote.socket systemd-journal-remote.service'.",
    [man("systemd-journal-remote.service.8")],
)
add(
    "6.1.1.1.3",
    "Medium",
    {"type": "journald_to_rsyslog"},
    "Checks that journald forwards to rsyslog (ForwardToSyslog=yes) and that rsyslog and journald are both active, when rsyslog is the logging method.",
    "rsyslog only receives journal messages when journald forwards them.",
    "Without forwarding, events captured by journald never reach rsyslog files or remote collectors.",
    "Configure journald to forward to rsyslog.",
    "Create /etc/systemd/journald.conf.d/60-cis.conf with '[Journal]' and 'ForwardToSyslog=yes', then 'systemctl reload-or-restart systemd-journald'.",
    [man("journald.conf.5")],
    RSYSLOG,
)
manual(
    "6.1.1.1.4",
    "Confirm that journald log files under /var/log/journal and /run/log/journal have permissions that follow site policy.",
    "Review systemd-tmpfiles rules for the journal (for example /usr/lib/tmpfiles.d/systemd.conf) and override them in /etc/tmpfiles.d if needed.",
    [man("tmpfiles.d.5")],
)
manual(
    "6.1.1.1.5",
    "Confirm that journald rotation (SystemMaxUse, SystemKeepFree, SystemMaxFileSize, MaxRetentionSec) follows site policy.",
    "Set the rotation options in /etc/systemd/journald.conf.d/60-cis.conf and restart systemd-journald.",
    [man("journald.conf.5")],
)
add(
    "6.1.1.1.6",
    "Medium",
    {"type": "systemd_config", "config": "journald.conf", "section": "Journal", "option": "Storage", "expected": ["persistent"], "builtin_default": "auto"},
    "Checks that journald Storage is persistent.",
    "Persistent storage keeps logs across reboots.",
    "Volatile logs are lost on reboot, which is often exactly when an investigator needs them.",
    "Set journald Storage=persistent.",
    "Create /etc/systemd/journald.conf.d/60-cis.conf with '[Journal]' and 'Storage=persistent', then 'systemctl reload-or-restart systemd-journald'.",
    [man("journald.conf.5")],
)
add(
    "6.1.1.1.7",
    "Low",
    {"type": "systemd_config", "config": "journald.conf", "section": "Journal", "option": "Compress", "expected": ["yes"], "builtin_default": "yes"},
    "Checks that journald compresses large journal entries (Compress=yes).",
    "Compression keeps more history within the same disk budget.",
    "Uncompressed journals fill their size limit sooner, shortening retained history.",
    "Set journald Compress=yes.",
    "Add 'Compress=yes' under [Journal] in /etc/systemd/journald.conf.d/60-cis.conf and restart systemd-journald.",
    [man("journald.conf.5")],
)
add(
    "6.1.2.1",
    "Medium",
    {"type": "package_installed", "packages": ["rsyslog"]},
    "Checks that rsyslog is installed when it is the chosen logging method.",
    "rsyslog provides flexible local logging and remote forwarding.",
    "If rsyslog is the logging design but is missing, logs are not written or forwarded as intended.",
    "Install rsyslog.",
    "Run 'apt install rsyslog'.",
    [man("rsyslogd.8")],
    RSYSLOG,
)
add(
    "6.1.2.2",
    "Medium",
    {"type": "unit_state", "units": [{"name": "rsyslog.service", "enabled": True, "active": True}]},
    "Checks that rsyslog.service is enabled and active.",
    "Logging only works while the daemon runs.",
    "A stopped rsyslog silently drops logs and remote forwarding.",
    "Enable and start rsyslog.",
    "Run 'systemctl unmask rsyslog' and 'systemctl --now enable rsyslog'.",
    [man("rsyslogd.8")],
    RSYSLOG,
)
add(
    "6.1.2.3",
    "Medium",
    {"type": "rsyslog_file_create_mode"},
    "Checks that rsyslog sets $FileCreateMode to 0640 or more restrictive.",
    "Log files often contain sensitive operational and authentication data.",
    "With the default mode 0644 any local user can read system logs.",
    "Set $FileCreateMode 0640.",
    "Add '$FileCreateMode 0640' to /etc/rsyslog.d/60-cis.conf and restart rsyslog.",
    [man("rsyslog.conf.5")],
    RSYSLOG,
)
for cis_id, guidance, remediation in (
    ("6.1.2.4", "Confirm that rsyslog writes the required facilities and severities to appropriate log files.", "Define the site's logging rules in /etc/rsyslog.d/ and restart rsyslog."),
    ("6.1.2.5", "Confirm that rsyslog forwards logs to a central log host.", "Add an omfwd action (for example action(type=\"omfwd\" target=\"<loghost>\" port=\"6514\" protocol=\"tcp\" ...)) to /etc/rsyslog.d/ and restart rsyslog."),
    ("6.1.2.7", "Confirm that logrotate rotates and retains logs according to site policy.", "Review /etc/logrotate.conf and /etc/logrotate.d/ and adjust rotation frequency and retention."),
    ("6.1.2.10", "Confirm that rsyslog TLS forwarding uses the site's CA certificate and verifies the log host.", "Set DefaultNetstreamDriverCAFile and StreamDriverAuthMode=x509/name with the approved CA in /etc/rsyslog.d/."),
):
    manual(cis_id, guidance, remediation, [man("rsyslog.conf.5")])
add(
    "6.1.2.6",
    "Medium",
    {"type": "rsyslog_no_remote_input"},
    "Checks that rsyslog does not load the imtcp or imudp network input modules.",
    "Only designated log servers should accept logs from the network.",
    "A listening rsyslog accepts spoofed log entries and can be flooded to exhaust disk space.",
    "Disable network log reception on log clients.",
    "Remove imtcp/imudp module loads and inputs ($ModLoad imtcp, $InputTCPServerRun, module(load=\"imudp\") and similar) from /etc/rsyslog.conf and /etc/rsyslog.d/, then restart rsyslog.",
    [man("rsyslog.conf.5")],
    RSYSLOG,
)
add(
    "6.1.2.8",
    "Low",
    {"type": "package_installed", "packages": ["rsyslog-gnutls"]},
    "Checks that rsyslog-gnutls is installed so rsyslog can use TLS.",
    "TLS protects forwarded logs in transit.",
    "Without TLS support, forwarded logs travel in clear text and can be read or altered.",
    "Install rsyslog-gnutls.",
    "Run 'apt install rsyslog-gnutls'.",
    [man("rsyslogd.8")],
    RSYSLOG,
)
add(
    "6.1.2.9",
    "Medium",
    {"type": "rsyslog_gtls"},
    "Checks that rsyslog network streams use the gtls (TLS) stream driver.",
    "Log forwarding should be encrypted and authenticated.",
    "Clear-text log forwarding lets an attacker read, drop or inject log entries on the network.",
    "Use the gtls driver for rsyslog forwarding.",
    "Set StreamDriver=\"gtls\" with StreamDriverMode=\"1\" and an x509 authentication mode on forwarding actions in /etc/rsyslog.d/, then restart rsyslog.",
    [man("rsyslog.conf.5")],
    RSYSLOG,
)
add(
    "6.1.3.1",
    "Medium",
    {"type": "log_files_access"},
    "Checks that every file under /var/log meets the CIS mode, owner and group rules for its type (for example 0640 root:adm for syslog files, 0664 root:utmp for wtmp).",
    "Log files contain security-relevant and sometimes sensitive data.",
    "Over-permissive log files let local users read authentication records or tamper with evidence.",
    "Restrict log file permissions and ownership.",
    "Correct the reported files with chmod/chown (for example 'chmod u-x,g-wx,o-rwx <file>') and fix the creating service or logrotate 'create' directive so new files keep those permissions.",
    [man("logrotate.8")],
)

# =========================================================== 6.2 auditd
add(
    "6.2.1.1",
    "Medium",
    {"type": "package_installed", "packages": ["auditd", "audispd-plugins"]},
    "Checks that auditd and audispd-plugins are installed.",
    "The Linux audit framework records security-relevant events for accountability and forensics.",
    "Without auditd, changes to users, permissions and security configuration are not recorded.",
    "Install auditd and its dispatcher plugins.",
    "Run 'apt install auditd audispd-plugins'.",
    [man("auditd.8")],
)
add(
    "6.2.1.2",
    "Medium",
    {"type": "unit_state", "units": [{"name": "auditd.service", "enabled": True, "active": True}]},
    "Checks that auditd.service is enabled and active.",
    "Audit rules only produce records while auditd runs.",
    "A stopped auditd means security-relevant activity goes unrecorded.",
    "Enable and start auditd.",
    "Run 'systemctl unmask auditd' and 'systemctl --now enable auditd'.",
    [man("auditd.8")],
)
add(
    "6.2.1.3",
    "Low",
    {"type": "grub_cmdline", "require_pattern": r"(^|\s)audit=1(\s|$)", "describe": "audit=1"},
    "Checks that every GRUB kernel entry includes audit=1.",
    "audit=1 enables auditing before auditd starts, so early boot processes are audited.",
    "Processes started before auditd would otherwise be unauditable, hiding early-boot persistence.",
    "Enable auditing at boot.",
    "Add 'audit=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run 'update-grub'.",
    [man("auditd.8")],
)
add(
    "6.2.1.4",
    "Low",
    {"type": "grub_cmdline", "require_pattern": r"(^|\s)audit_backlog_limit=\d+(\s|$)", "describe": "audit_backlog_limit=<N>"},
    "Checks that every GRUB kernel entry sets audit_backlog_limit.",
    "A larger backlog prevents audit records from being lost during boot bursts.",
    "With the default backlog of 64, audit events can be dropped before auditd starts.",
    "Set audit_backlog_limit on the kernel command line.",
    "Add 'audit_backlog_limit=8192' to GRUB_CMDLINE_LINUX in /etc/default/grub and run 'update-grub'.",
    [man("auditd.8")],
)
add(
    "6.2.2.1",
    "Low",
    {"type": "auditd_conf", "settings": [{"key": "max_log_file", "numeric": True}]},
    "Checks that max_log_file is explicitly set in /etc/audit/auditd.conf (the value is reported for review against site policy).",
    "Audit log size should be sized deliberately for the retention requirement.",
    "Undersized audit logs rotate away evidence before it is collected.",
    "Set max_log_file according to the retention policy.",
    "Set 'max_log_file = <MB>' in /etc/audit/auditd.conf and restart auditd.",
    [man("auditd.conf.5")],
)
add(
    "6.2.2.2",
    "Medium",
    {"type": "auditd_conf", "settings": [{"key": "max_log_file_action", "allowed": ["keep_logs"]}]},
    "Checks that max_log_file_action is keep_logs.",
    "Audit logs should be rotated, never overwritten or deleted automatically.",
    "Automatic deletion destroys audit evidence, which an attacker can trigger by generating noise.",
    "Keep rotated audit logs.",
    "Set 'max_log_file_action = keep_logs' in /etc/audit/auditd.conf and restart auditd.",
    [man("auditd.conf.5")],
)
add(
    "6.2.2.3",
    "Medium",
    {"type": "auditd_conf", "settings": [{"key": "disk_full_action", "allowed": ["halt", "single"]}, {"key": "disk_error_action", "allowed": ["syslog", "single", "halt"]}]},
    "Checks that disk_full_action is halt or single and disk_error_action is syslog, single or halt.",
    "The system must not continue unaudited when the audit disk is full or failing.",
    "Continuing without auditing lets an attacker fill the disk and then act unrecorded.",
    "Configure fail-safe actions for audit storage problems.",
    "Set 'disk_full_action = single' and 'disk_error_action = single' (or halt) in /etc/audit/auditd.conf and restart auditd.",
    [man("auditd.conf.5")],
)
add(
    "6.2.2.4",
    "Medium",
    {"type": "auditd_conf", "settings": [{"key": "space_left_action", "allowed": ["email", "exec", "single", "halt"]}, {"key": "admin_space_left_action", "allowed": ["single", "halt"]}]},
    "Checks that space_left_action is email, exec, single or halt and admin_space_left_action is single or halt.",
    "Administrators must be warned before audit storage runs out.",
    "Without warnings the audit disk fills unnoticed and auditing stops or the system halts unexpectedly.",
    "Configure low-space warnings and actions for auditd.",
    "Set 'space_left_action = email' (with a working MTA) and 'admin_space_left_action = single' in /etc/audit/auditd.conf and restart auditd.",
    [man("auditd.conf.5")],
)


def audit(cis_id: str, severity: str, check: dict, what: str, why: str, impact: str, rules: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "audit_rules", **check},
        f"Checks that audit rules recording {what} exist in /etc/audit/rules.d and in the loaded ruleset.",
        why,
        impact,
        f"Audit {what}.",
        f"Add to /etc/audit/rules.d/50-cis.rules: {rules} " + AUGENRULES,
        [man("audit.rules.7"), man("auditctl.8")],
    )


def watch(paths: list[str], perms: str = "wa", **extra: object) -> list[dict]:
    return [{"path": path, "perms": perms, **extra} for path in paths]


def watch_rules(paths: list[str], key: str) -> str:
    return " ".join(f"'-a always,exit -F arch=b64 -F {'dir' if path.endswith(('.d', '/')) or path in ('/etc/apparmor', '/etc/netplan', '/etc/NetworkManager') else 'path'}={path} -F perm=wa -k {key}'" for path in paths)


def syscall_rules(names: str, key: str, fields: str = "-F auid>=1000 -F auid!=unset") -> str:
    return f"'-a always,exit -F arch=b64 -S {names} {fields} -k {key}' and the same rule with arch=b32."


audit("6.2.3.1", "Medium", {"watches": watch(["/etc/sudoers", "/etc/sudoers.d"])}, "changes to /etc/sudoers and /etc/sudoers.d", "Changes to sudo rules alter who can gain root.", "Unrecorded sudoers changes can hide the creation of privileged backdoors.", watch_rules(["/etc/sudoers", "/etc/sudoers.d"], "scope"))
audit(
    "6.2.3.2",
    "Medium",
    {"syscalls": [{"names": ["execve", "execveat"], "fields": [["uid", "!=", "euid"], ["auid", "!=", "unset"]]}]},
    "commands executed as another user (for example through sudo)",
    "Commands run with a different effective user are privileged actions that need attribution.",
    "Without these records, actions taken through sudo or setuid programs cannot be traced to the user.",
    "'-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve,execveat -k user_emulation' and the same rule with arch=b32.",
)
audit("6.2.3.3", "Medium", {"watches": watch(["@sudo_logfile"])}, "changes to the sudo log file", "The sudo log is evidence of privileged activity.", "An attacker could edit the sudo log to hide their actions.", "'-a always,exit -F arch=b64 -F path=<sudo logfile> -F perm=wa -k sudo_log_file' (the path from Defaults logfile=).")
audit(
    "6.2.3.4",
    "Medium",
    {"syscalls": [{"names": ["adjtimex", "settimeofday"]}, {"names": ["clock_settime"], "fields": [["a0", "=", "0x0"]]}], "watches": watch(["/etc/localtime"])},
    "changes to the system date, time and time zone",
    "Time changes can disguise the sequence of events in logs.",
    "An attacker could shift the clock to confuse log correlation and forensic timelines.",
    "'-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change', '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change' (both also for arch=b32) and '-a always,exit -F arch=b64 -F path=/etc/localtime -F perm=wa -k time-change'.",
)
audit("6.2.3.5", "Medium", {"syscalls": [{"names": ["sethostname", "setdomainname"]}]}, "changes to the host and domain name", "The host identity is used in logs and network trust.", "Renaming the host can mislead log correlation and monitoring.", syscall_rules("sethostname,setdomainname", "system-locale", ""))
audit("6.2.3.6", "Medium", {"watches": watch(["/etc/issue", "/etc/issue.net"])}, "changes to /etc/issue and /etc/issue.net", "Login banners carry the organization's legal notice.", "Unrecorded banner changes could remove legal notices or display misleading instructions.", watch_rules(["/etc/issue", "/etc/issue.net"], "system-locale"))
audit("6.2.3.7", "Medium", {"watches": watch(["/etc/hosts", "/etc/hostname"])}, "changes to /etc/hosts and /etc/hostname", "Local name resolution and host identity affect where traffic goes.", "An attacker could redirect connections by editing /etc/hosts without leaving a trace.", watch_rules(["/etc/hosts", "/etc/hostname"], "system-locale"))
audit(
    "6.2.3.8",
    "Medium",
    {"watches": watch(["/etc/network/interfaces", "/etc/network/interfaces.d", "/etc/netplan"], if_exists=True)},
    "changes to network configuration files (/etc/network and /etc/netplan, where present)",
    "Network configuration changes can expose the host or bypass segmentation.",
    "Unrecorded network changes can open new paths into or out of the host.",
    watch_rules(["/etc/network/interfaces", "/etc/network/interfaces.d", "/etc/netplan/"], "system-locale"),
)
audit("6.2.3.9", "Medium", {"watches": watch(["/etc/NetworkManager"], if_exists=True)}, "changes to /etc/NetworkManager (when NetworkManager is installed)", "NetworkManager configuration controls interfaces, VPNs and DNS.", "Unrecorded changes can silently reroute traffic or add connections.", watch_rules(["/etc/NetworkManager/"], "system-locale"))
add(
    "6.2.3.10",
    "Medium",
    {"type": "audit_privileged_commands"},
    "Checks that every setuid/setgid program on device-backed filesystems mounted without noexec or nosuid is covered by an audit rule on disk and in the loaded ruleset.",
    "Privileged programs are the main route to privilege escalation.",
    "Use of setuid programs, including exploit attempts against them, goes unrecorded.",
    "Audit execution of every setuid/setgid program.",
    "Generate rules such as '-a always,exit -F path=<program> -F perm=x -F auid>=1000 -F auid!=unset -k privileged' for each program (for example with find ... -perm /6000), write them to /etc/audit/rules.d/50-privileged.rules and " + AUGENRULES.lower(),
    [man("audit.rules.7")],
)
audit(
    "6.2.3.11",
    "Medium",
    {
        "syscalls": [
            {"names": ["creat", "open", "openat", "truncate", "ftruncate"], "fields": [["exit", "=", "-EACCES"]] + AUID},
            {"names": ["creat", "open", "openat", "truncate", "ftruncate"], "fields": [["exit", "=", "-EPERM"]] + AUID},
        ]
    },
    "unsuccessful file access attempts (EACCES and EPERM)",
    "Repeated access failures indicate probing for sensitive files.",
    "Attempts to read or modify protected files go unnoticed.",
    "'-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access', the same with exit=-EPERM, and both for arch=b32.",
)
audit("6.2.3.12", "Medium", {"watches": watch(["/etc/group"])}, "changes to /etc/group", "Group membership controls access, including administrative groups.", "Adding a user to a privileged group could go unrecorded.", watch_rules(["/etc/group"], "identity"))
audit("6.2.3.13", "Medium", {"watches": watch(["/etc/passwd"])}, "changes to /etc/passwd", "The account database defines who can log in.", "Creation of backdoor accounts could go unrecorded.", watch_rules(["/etc/passwd"], "identity"))
audit("6.2.3.14", "Medium", {"watches": watch(["/etc/gshadow", "/etc/shadow"])}, "changes to /etc/shadow and /etc/gshadow", "The shadow files hold password hashes and ageing data.", "Password or lockout changes made by an attacker could go unrecorded.", watch_rules(["/etc/shadow", "/etc/gshadow"], "identity"))
audit("6.2.3.15", "Medium", {"watches": watch(["/etc/security/opasswd"])}, "changes to /etc/security/opasswd", "The password history file supports password reuse controls.", "Tampering with password history could go unrecorded.", watch_rules(["/etc/security/opasswd"], "identity"))
audit("6.2.3.16", "Medium", {"watches": watch(["/etc/nsswitch.conf"])}, "changes to /etc/nsswitch.conf", "nsswitch.conf decides where accounts and hosts are resolved from.", "An attacker could add a rogue directory source for accounts without a trace.", watch_rules(["/etc/nsswitch.conf"], "identity"))
audit("6.2.3.17", "Medium", {"watches": watch(["/etc/pam.conf", "/etc/pam.d"])}, "changes to /etc/pam.conf and /etc/pam.d", "PAM configuration decides how every login is authenticated.", "A PAM backdoor, such as a module accepting any password, could be installed unnoticed.", watch_rules(["/etc/pam.conf", "/etc/pam.d"], "identity"))
audit("6.2.3.18", "Medium", {"syscalls": [{"names": ["chmod", "fchmod", "fchmodat", "fchmodat2"], "fields": AUID}]}, "permission changes made with chmod-family system calls", "Permission changes can expose files or enable execution.", "Loosened permissions on sensitive files could go unrecorded.", syscall_rules("chmod,fchmod,fchmodat,fchmodat2", "perm_mod"))
audit("6.2.3.19", "Medium", {"syscalls": [{"names": ["chown", "fchown", "lchown", "fchownat"], "fields": AUID}]}, "ownership changes made with chown-family system calls", "Ownership changes can hand files to an attacker-controlled account.", "Transfers of ownership of sensitive files could go unrecorded.", syscall_rules("chown,fchown,lchown,fchownat", "perm_mod"))
audit(
    "6.2.3.20",
    "Medium",
    {"syscalls": [{"names": ["setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr"], "fields": AUID}]},
    "extended attribute changes",
    "Extended attributes carry ACLs and security labels.",
    "ACL or label changes that widen access could go unrecorded.",
    syscall_rules("setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr", "perm_mod"),
)
audit("6.2.3.21", "Medium", {"syscalls": [{"names": ["mount"], "fields": AUID}]}, "filesystem mounts by users", "Mounting media or filesystems can introduce or exfiltrate data.", "Data could be copied to removable or network filesystems without a record.", syscall_rules("mount", "mounts"))
audit("6.2.3.22", "Medium", {"watches": watch(["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"])}, "changes to the session records (utmp, wtmp and btmp)", "Session records show who logged in and when.", "An attacker could erase evidence of their logins.", watch_rules(["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"], "session"))
audit("6.2.3.23", "Medium", {"watches": watch(["/var/log/lastlog", "/var/run/faillock"])}, "changes to the login and lockout records (lastlog and faillock)", "These files record last logins and failed attempts.", "Evidence of logins and brute-force attempts could be removed without trace.", watch_rules(["/var/log/lastlog", "/var/run/faillock"], "logins"))
audit("6.2.3.24", "Medium", {"syscalls": [{"names": ["unlink", "unlinkat"], "fields": AUID}]}, "file deletions by users (unlink)", "File deletion can destroy data or evidence.", "Deletion of logs, data or tooling could go unrecorded.", syscall_rules("unlink,unlinkat", "delete"))
audit("6.2.3.25", "Medium", {"syscalls": [{"names": ["rename", "renameat", "renameat2"], "fields": AUID}]}, "file renames by users", "Renaming can hide or replace files.", "Replacement of binaries or concealment of files could go unrecorded.", syscall_rules("rename,renameat,renameat2", "delete"))
audit("6.2.3.26", "Medium", {"watches": watch(["/etc/apparmor", "/etc/apparmor.d"])}, "changes to AppArmor configuration", "AppArmor policy confines services.", "Weakening of mandatory access control could go unrecorded.", watch_rules(["/etc/apparmor/", "/etc/apparmor.d/"], "MAC-policy"))
for cis_id, path in (("6.2.3.27", "/usr/bin/chcon"), ("6.2.3.28", "/usr/bin/setfacl"), ("6.2.3.29", "/usr/bin/chacl"), ("6.2.3.30", "/usr/sbin/usermod")):
    name = path.rsplit("/", 1)[1]
    audit(
        cis_id,
        "Medium",
        {"watches": watch([path], perms="x", fields=AUID)},
        f"every execution of {name}",
        f"{name} changes security-relevant attributes or accounts.",
        f"Use of {name} to widen access could go unrecorded.",
        f"'-a always,exit -F path={path} -F perm=x -F auid>=1000 -F auid!=unset -k {'usermod' if name == 'usermod' else 'perm_chng'}'.",
    )
audit("6.2.3.31", "Medium", {"watches": watch(["/usr/bin/kmod"], perms="x", fields=AUID)}, "every execution of kmod (modprobe, insmod, rmmod)", "Loading kernel modules changes kernel behaviour.", "A malicious kernel module (rootkit) could be loaded without a record.", "'-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules'.")
audit("6.2.3.32", "Medium", {"syscalls": [{"names": ["init_module", "finit_module"], "fields": AUID}]}, "kernel module loading (init_module, finit_module)", "Module loading system calls capture loads by any tool.", "A rootkit loaded through a custom loader could go unrecorded.", syscall_rules("init_module,finit_module", "kernel_modules"))
audit("6.2.3.33", "Medium", {"syscalls": [{"names": ["init_module", "finit_module", "delete_module"], "fields": AUID}]}, "kernel module loading and unloading (including delete_module)", "Unloading modules can remove security controls.", "Removal of security-relevant kernel modules could go unrecorded.", syscall_rules("init_module,finit_module,delete_module", "kernel_modules"))
add(
    "6.2.3.34",
    "Low",
    {"type": "audit_rules_directive", "directive": ["-c"]},
    "Checks that the audit rules include '-c' so loading continues past a faulty rule.",
    "A single bad rule should not prevent the rest of the audit policy from loading.",
    "Without -c an error in one rule file can leave the system with an incomplete audit policy.",
    "Continue loading audit rules after errors.",
    "Add '-c' to /etc/audit/rules.d/99-finalize.rules. " + AUGENRULES,
    [man("auditctl.8")],
)
add(
    "6.2.3.35",
    "Medium",
    {"type": "audit_rules_directive", "directive": ["-e", "2"]},
    "Checks that the audit rules end with '-e 2', making the configuration immutable until reboot.",
    "An immutable audit configuration cannot be switched off by an attacker who gains root.",
    "Without immutability an intruder with root can disable auditing before acting.",
    "Make the audit configuration immutable.",
    "Add '-e 2' as the last line of /etc/audit/rules.d/99-finalize.rules and reboot to apply it.",
    [man("auditctl.8")],
)
manual(
    "6.2.3.36",
    "Confirm that the running audit rules match the rules on disk.",
    "Run 'augenrules --check'; if a merge is needed, run 'augenrules --load' (reboot when the configuration is immutable).",
    [man("augenrules.8")],
)

AUDITD_PREREQ = {"path": "/etc/audit/auditd.conf", "message": "/etc/audit/auditd.conf was not found; auditd does not appear to be installed."}


def audit_file(cis_id: str, targets: list[dict], what: str, requirement: dict, text: str, remediation: str, **extra: object) -> None:
    add(
        cis_id,
        "Medium",
        {"type": "file_permissions", "targets": targets, "prerequisite": AUDITD_PREREQ, **requirement, **extra},
        f"Checks that {what} {text}.",
        "Audit data, configuration and tools must be protected from tampering and disclosure.",
        "Users who can read or change audit files can learn the monitoring policy, alter records or disable auditing.",
        f"Ensure {what} {text}.",
        remediation,
        [man("auditd.conf.5")],
    )


audit_file("6.2.4.1", [{"source": "audit_log_files"}], "audit log files", {"max_mode": "0640"}, "are mode 0640 or more restrictive", "Run 'chmod u-x,g-wx,o-rwx <log directory>/*' for the directory named by log_file in auditd.conf.")
audit_file("6.2.4.2", [{"source": "audit_log_files"}], "audit log files", {"owners": ["root"]}, "are owned by root", "Run 'chown root <log directory>/*'.")
add(
    "6.2.4.3",
    "Medium",
    {"type": "audit_log_group"},
    "Checks that auditd.conf sets log_group to root or adm and that audit log files are group-owned by root or adm.",
    "Only administrators and log reviewers should be able to read audit logs.",
    "Other groups could read audit records containing sensitive activity details.",
    "Restrict audit log group ownership to root or adm.",
    "Set 'log_group = adm' in /etc/audit/auditd.conf, run 'chgrp adm <log directory>/*' and restart auditd.",
    [man("auditd.conf.5")],
)
audit_file("6.2.4.4", [{"source": "audit_log_directory"}], "the audit log directory", {"max_mode": "0750"}, "is mode 0750 or more restrictive", "Run 'chmod g-w,o-rwx <log directory>'.", file_type="dir")
audit_file("6.2.4.5", [{"source": "audit_config_files"}], "audit configuration files (*.conf and *.rules under /etc/audit)", {"max_mode": "0640"}, "are mode 0640 or more restrictive", "Run 'find /etc/audit -type f \\( -name \"*.conf\" -o -name \"*.rules\" \\) -exec chmod u-x,g-wx,o-rwx {} +'.")
audit_file("6.2.4.6", [{"source": "audit_config_files"}], "audit configuration files", {"owners": ["root"]}, "are owned by root", "Run 'find /etc/audit -type f \\( -name \"*.conf\" -o -name \"*.rules\" \\) -exec chown root {} +'.")
audit_file("6.2.4.7", [{"source": "audit_config_files"}], "audit configuration files", {"groups": ["root"]}, "are group-owned by root", "Run 'find /etc/audit -type f \\( -name \"*.conf\" -o -name \"*.rules\" \\) -exec chgrp root {} +'.")
audit_file("6.2.4.8", [{"source": "audit_tools"}], "the audit tools (auditctl, aureport, ausearch, auditd, augenrules)", {"max_mode": "0755"}, "are mode 0755 or more restrictive", "Run 'chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules'.", require_targets=True, empty_message="No audit tools were found in /sbin; auditd does not appear to be installed.")
audit_file("6.2.4.9", [{"source": "audit_tools"}], "the audit tools", {"owners": ["root"]}, "are owned by root", "Run 'chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules'.", require_targets=True, empty_message="No audit tools were found in /sbin; auditd does not appear to be installed.")
audit_file("6.2.4.10", [{"source": "audit_tools"}], "the audit tools", {"groups": ["root"]}, "are group-owned by root", "Run 'chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules'.", require_targets=True, empty_message="No audit tools were found in /sbin; auditd does not appear to be installed.")

# =========================================================== 6.3 AIDE
add(
    "6.3.1",
    "Medium",
    {"type": "package_installed", "packages": ["aide", "aide-common"]},
    "Checks that AIDE (aide and aide-common) is installed.",
    "File integrity monitoring detects unauthorized changes to system files.",
    "Without integrity monitoring, replaced binaries and altered configuration can persist undetected.",
    "Install AIDE and initialise its database.",
    "Run 'apt install aide aide-common' and 'aideinit', then move the new database into place as instructed.",
    [man("aide.1")],
)
add(
    "6.3.2",
    "Medium",
    {
        "type": "unit_state",
        "units": [
            {"name": "dailyaidecheck.timer", "enabled": True, "active": True},
            {"name": "dailyaidecheck.service", "enabled_states": ["static", "enabled"], "active": False},
        ],
    },
    "Checks that dailyaidecheck.timer is enabled and active and that dailyaidecheck.service is static or enabled.",
    "Integrity checks only help if they run regularly.",
    "Without scheduled checks, tampering is only found by chance.",
    "Schedule daily AIDE checks.",
    "Run 'systemctl unmask dailyaidecheck.timer dailyaidecheck.service' and 'systemctl --now enable dailyaidecheck.timer'.",
    [man("aide.1")],
)
add(
    "6.3.3",
    "Low",
    {"type": "aide_audit_tools"},
    "Checks that AIDE monitors each audit tool with the p, i, n, u, g, s, b, acl, xattrs and sha512 attributes.",
    "Attackers who tamper with audit tools can hide their activity.",
    "Replaced audit tools can silently drop or falsify audit records.",
    "Protect the audit tools with AIDE.",
    "Add lines such as '/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512' for auditctl, auditd, ausearch, aureport and augenrules to /etc/aide/aide.conf.d/, then update the AIDE database.",
    [man("aide.conf.5")],
)

# =========================================================== 7.1 System files
def system_file(cis_id: str, path: str, max_mode: str, groups: list[str], severity: str, what: str, impact: str) -> None:
    group_text = " or ".join(groups)
    add(
        cis_id,
        severity,
        {"type": "file_permissions", "targets": [{"path": path}], "max_mode": max_mode, "owners": ["root"], "groups": groups},
        f"Checks that {path} is owned by root, group-owned by {group_text}, and no more permissive than {max_mode}.",
        f"{path} {what}.",
        impact,
        f"Restrict {path} to root:{groups[-1]} with mode {max_mode} or stricter.",
        f"Run 'chown root:{groups[-1]} {path}' and 'chmod {max_mode} {path}'.",
        [man("passwd.5") if "passwd" in path else man("shadow.5") if "shadow" in path else man("group.5") if "group" in path else man("shells.5")],
    )


system_file("7.1.1", "/etc/passwd", "0644", ["root"], "High", "defines every local account", "A writable passwd file lets an attacker add accounts or change UIDs to gain root.")
system_file("7.1.2", "/etc/passwd-", "0644", ["root"], "Medium", "is the backup of the account database", "A writable backup can be swapped in to restore attacker-controlled accounts.")
system_file("7.1.3", "/etc/group", "0644", ["root"], "High", "defines group membership", "A writable group file lets an attacker add themselves to privileged groups.")
system_file("7.1.4", "/etc/group-", "0644", ["root"], "Medium", "is the backup of the group database", "A writable backup can be swapped in to restore attacker-controlled memberships.")
system_file("7.1.5", "/etc/shadow", "0640", ["root", "shadow"], "High", "holds password hashes", "Readable password hashes can be cracked offline to obtain passwords.")
system_file("7.1.6", "/etc/shadow-", "0640", ["root", "shadow"], "High", "is the backup of the password hash database", "Readable backup hashes can be cracked offline just like the live file.")
system_file("7.1.7", "/etc/gshadow", "0640", ["root", "shadow"], "High", "holds group passwords and administrators", "Readable or writable group shadow data can expose or grant group privileges.")
system_file("7.1.8", "/etc/gshadow-", "0640", ["root", "shadow"], "High", "is the backup of the group shadow database", "Readable or writable backup data can expose or grant group privileges.")
system_file("7.1.9", "/etc/shells", "0644", ["root"], "Low", "lists the valid login shells", "A writable shells file lets an attacker declare arbitrary programs as valid login shells.")
add(
    "7.1.10",
    "Medium",
    {"type": "file_permissions", "targets": [{"path": "/etc/security/opasswd"}, {"path": "/etc/security/opasswd.old"}], "max_mode": "0600", "owners": ["root"], "groups": ["root"]},
    "Checks that /etc/security/opasswd and opasswd.old, if present, are root:root and no more permissive than 0600.",
    "These files store previous password hashes for reuse checks.",
    "Readable old password hashes can be cracked and reveal patterns in users' current passwords.",
    "Restrict the password history files to root with mode 0600.",
    "Run 'chown root:root /etc/security/opasswd*' and 'chmod 0600 /etc/security/opasswd*'.",
    [man("pam_pwhistory.8")],
)
add(
    "7.1.11",
    "High",
    {"type": "world_writable"},
    "Checks local filesystems (excluding /run, /tmp, /var/tmp and container storage) for world-writable files and for world-writable directories without the sticky bit.",
    "Only directories designed for shared use should be world-writable, and they need the sticky bit.",
    "Any user can modify world-writable files, which can lead to code execution or privilege escalation if privileged processes use them.",
    "Remove world write access and set the sticky bit on shared directories.",
    "Run 'chmod o-w <file>' for each reported file and 'chmod a+t <directory>' (or remove o+w) for each reported directory.",
    [man("chmod.1")],
)
add(
    "7.1.12",
    "Medium",
    {"type": "unowned_files"},
    "Checks local filesystems for files and directories whose owner or group does not exist.",
    "Orphaned files are typically left by deleted accounts or extracted archives.",
    "A new account that reuses the orphaned UID or GID silently gains access to those files.",
    "Assign orphaned files to a valid owner and group or remove them.",
    "Review each reported path and run 'chown <user>:<group> <path>' or delete it.",
    [man("chown.1")],
)
manual(
    "7.1.13",
    "Review the setuid and setgid programs on the system and confirm each is expected and approved.",
    "List them with 'find / -xdev -type f -perm /6000' (the filesystem scan evidence also lists them) and remove the special bits from unapproved programs with 'chmod u-s,g-s <file>'.",
    [man("chmod.1")],
)

# =========================================================== 7.2 Users and groups
def user_check(cis_id: str, check_type: str, severity: str, description: str, why: str, impact: str, recommendation: str, remediation: str, page: str, **extra: object) -> None:
    add(cis_id, severity, {"type": check_type, **extra}, description, why, impact, recommendation, remediation, [man(page)])


user_check("7.2.1", "shadowed_passwords", "Critical", "Checks that every account in /etc/passwd uses a shadowed password ('x').", "Password hashes must be kept in the root-only shadow file.", "A hash left in world-readable /etc/passwd can be cracked offline by any user.", "Move password hashes into /etc/shadow.", "Run 'pwconv' and investigate why the account was not shadowed.", "pwconv.8")
user_check("7.2.2", "shadow_not_empty", "Critical", "Checks that no account in /etc/shadow has an empty password field.", "Every account must require authentication or be locked.", "An account with an empty password can be used without any credential.", "Lock or set passwords for accounts with empty password fields.", "Run 'passwd -l <user>' for each reported account and investigate how the empty password was set.", "shadow.5")
user_check("7.2.3", "passwd_groups_exist", "Low", "Checks that every primary GID in /etc/passwd exists in /etc/group.", "Accounts should reference defined groups.", "A later group created with the missing GID would silently gain those users' group access.", "Correct primary groups that do not exist.", "Create the missing group or assign a valid primary group with 'usermod -g <group> <user>'.", "group.5")
user_check("7.2.4", "shadow_group_empty", "High", "Checks that the shadow group has no members and is no account's primary group.", "Members of the shadow group can read password hashes.", "Accounts in the shadow group can read /etc/shadow and crack every password offline.", "Remove all members from the shadow group.", "Run 'gpasswd -d <user> shadow' for members and change primary groups with 'usermod -g <group> <user>'.", "group.5")
user_check("7.2.5", "duplicates", "High", "Checks that no two accounts in /etc/passwd share a UID.", "Accounts sharing a UID are the same user to the kernel.", "Actions cannot be attributed and one account silently has the other's access.", "Give every account a unique UID.", "Assign unique UIDs with 'usermod -u <uid> <user>' and fix file ownership accordingly.", "passwd.5", kind="uid")
user_check("7.2.6", "duplicates", "Medium", "Checks that no two groups in /etc/group share a GID.", "Groups sharing a GID grant the same file access.", "Members of one group silently receive the other group's access.", "Give every group a unique GID.", "Assign unique GIDs with 'groupmod -g <gid> <group>' and fix file group ownership.", "group.5", kind="gid")
user_check("7.2.7", "duplicates", "High", "Checks that no user name appears twice in /etc/passwd.", "Duplicate names make authentication and auditing ambiguous.", "The first matching entry wins, so a duplicate can shadow or impersonate an account.", "Remove duplicate user names.", "Rename or remove the duplicate entries with 'usermod -l' or 'userdel'.", "passwd.5", kind="user")
user_check("7.2.8", "duplicates", "Medium", "Checks that no group name appears twice in /etc/group.", "Duplicate group names make access control ambiguous.", "Access decisions may use an unexpected GID for the group.", "Remove duplicate group names.", "Rename or remove the duplicate entries with 'groupmod -n' or 'groupdel'.", "group.5", kind="group")
user_check("7.2.9", "home_directories", "Medium", "Checks that each interactive user's home directory exists, is owned by that user and is mode 0750 or more restrictive.", "Home directories hold personal data, keys and shell startup files.", "Other users could read private data or plant malicious startup files in accessible home directories.", "Secure interactive users' home directories.", "Create missing homes with 'mkhomedir_helper <user>', then 'chown <user> <home>' and 'chmod 0750 <home>'.", "mkhomedir_helper.8")
user_check("7.2.10", "dot_files", "Medium", "Checks interactive users' dot files: no .forward or .rhosts files, .netrc and .bash_history no more than 0600, other dot files no more than 0644, all owned by the user and the user's primary group.", "Dot files control shells, mail forwarding and stored credentials.", "Writable startup files let others run code as the user; .rhosts and .netrc can grant or reveal access.", "Secure or remove sensitive dot files in user homes.", "Remove .forward and .rhosts files, and run 'chmod go-w' (or 'chmod 0600' for .netrc and .bash_history) and 'chown <user>:<group>' on the reported files.", "chmod.1")
user_check("7.2.11", "dot_directories", "Medium", "Checks interactive users' dot directories: .ssh no more than 0700, others no more than 0750, all owned by the user and the user's primary group.", "Dot directories hold SSH keys, application credentials and configuration.", "Accessible dot directories expose private keys and tokens or allow others to plant configuration.", "Secure dot directories in user homes.", "Run 'chmod 0700 <home>/.ssh', 'chmod g-w,o-rwx <dir>' for others and 'chown <user>:<group> <dir>' for the reported directories.", "chmod.1")
