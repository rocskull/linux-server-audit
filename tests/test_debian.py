"""Debian 13 definition evaluated against a small synthetic server.

The fixture is deliberately incomplete: most commands are unavailable, so the
test proves that every provider turns missing evidence into NOT_ASSESSED (or a
reasoned verdict) instead of an evaluation ERROR, and spot-checks verdicts
that the fixture does determine.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from lsa.model import ERROR, FAIL, NOT_APPLICABLE, PASS
from lsa.system import CommandResult, System
from tests.support import DEBIAN_13, SETTINGS, TempRoot, assess, linux_host, statuses, write

PACKAGES = {
    "openssh-server": "1:10.0p1-7", "openssh-client": "1:10.0p1-7", "sudo": "1.9.16p2-3", "systemd": "257.7-1",
    "systemd-timesyncd": "257.7-1", "rsyslog": "8.2504.0-1", "auditd": "1:4.0.2-2", "apparmor": "4.1.0-1",
    "ufw": "0.36.2-9", "libpam-pwquality": "1.4.5-5", "libpam-runtime": "1.7.0-5", "libpam-modules": "1.7.0-5",
    "cron": "3.0pl1-197", "login": "1:4.16.0-2", "passwd": "1:4.16.0-2", "procps": "2:4.0.4-9",
}
ENABLED_UNITS = {"ssh.service", "auditd.service", "apparmor.service", "ufw.service", "systemd-timesyncd.service", "rsyslog.service", "cron.service", "systemd-journald.service"}

SSHD_T = """port 22
addressfamily any
listenaddress 0.0.0.0:22
permitrootlogin yes
pubkeyauthentication yes
passwordauthentication yes
permitemptypasswords no
hostbasedauthentication no
ignorerhosts yes
permituserenvironment no
x11forwarding yes
allowtcpforwarding yes
gatewayports no
maxauthtries 6
maxsessions 10
maxstartups 10:30:100
logingracetime 120
clientaliveinterval 0
clientalivecountmax 3
loglevel INFO
usepam yes
disableforwarding no
banner none
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,diffie-hellman-group14-sha1
"""


def systemctl_show(argv: list[str]) -> CommandResult:
    units = argv[argv.index("--") + 1 :]
    blocks = []
    for unit in units:
        if unit in ENABLED_UNITS:
            blocks.append(f"Id={unit}\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n")
        else:
            blocks.append(f"Id={unit}\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n")
    return CommandResult(argv, 0, "\n".join(blocks), "")


def build_debian(root: Path, proxmox: bool = False) -> System:
    packages = dict(PACKAGES, **({"pve-manager": "9.0.6", "proxmox-ve": "9.0.0"} if proxmox else {}))
    runner = linux_host(root, DEBIAN_13, packages)
    if proxmox:
        write(root, "etc/pve/.version", "")
    files = {
        "etc/hostname": "deb13\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "etc/group": "root:x:0:\nadm:x:4:\nsudo:x:27:alice\nshadow:x:42:\nnogroup:x:65534:\nalice:x:1000:\n",
        "etc/shadow": "root:$y$j9T$salt$hash:19800:0:99999:7:::\ndaemon:*:19800:0:99999:7:::\nsync:*:19800:0:99999:7:::\n"
        "nobody:*:19800:0:99999:7:::\nalice:$y$j9T$salt$hash:19800:1:365:7:30::\n",
        "etc/gshadow": "root:*::\nsudo:*::alice\nshadow:*::\n",
        "etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\nUID_MIN 1000\nENCRYPT_METHOD YESCRYPT\nUMASK 022\n",
        "etc/shells": "/bin/sh\n/bin/bash\n/usr/bin/bash\n",
        "etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
        "etc/sudoers": "Defaults env_reset\nDefaults use_pty\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
        "etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n",
        "etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure yescrypt\n",
        "etc/pam.d/common-account": "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\n",
        "etc/pam.d/su": "auth sufficient pam_rootok.so\n",
        "etc/security/pwquality.conf": "# minlen = 8\n",
        "etc/audit/auditd.conf": "log_file = /var/log/audit/audit.log\nmax_log_file = 8\nmax_log_file_action = ROTATE\nspace_left_action = SYSLOG\nadmin_space_left_action = SUSPEND\ndisk_full_action = SUSPEND\n",
        "etc/audit/rules.d/cis.rules": "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d -p wa -k scope\n",
        "etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\nGRUB_CMDLINE_LINUX=""\n',
        "boot/grub/grub.cfg": "linux /vmlinuz root=/dev/sda1 ro quiet\n",
        "etc/modprobe.d/cramfs.conf": "install cramfs /bin/false\nblacklist cramfs\n",
        "etc/sysctl.conf": "net.ipv4.ip_forward = 0\n",
        "etc/systemd/journald.conf": "[Journal]\n#Storage=auto\n",
        "etc/rsyslog.conf": "$FileCreateMode 0640\n*.* /var/log/syslog\n",
        "etc/issue": "Authorized uses only. All activity may be monitored and reported.\n",
        "etc/issue.net": "Debian GNU/Linux \\n\n",
        "etc/motd": "",
        "etc/crontab": "SHELL=/bin/sh\n",
        "etc/profile": "umask 022\n",
        "etc/bash.bashrc": "",
        "proc/sys/net/ipv4/ip_forward": "0\n",
        "proc/sys/net/ipv4/conf/all/send_redirects": "1\n",
        "proc/sys/kernel/randomize_va_space": "2\n",
        "proc/modules": "",
        "proc/filesystems": "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\n\text4\n",
        "proc/self/mountinfo": "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
        "23 22 0:21 / /tmp rw,nosuid,nodev,relatime shared:2 - tmpfs tmpfs rw\n"
        "24 22 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw\n",
        "home/alice/.bashrc": "",
        "root/.bashrc": "",
        "var/log/syslog": "",
    }
    for path, content in files.items():
        write(root, path, content)
    (root / "run/systemd/system").mkdir(parents=True, exist_ok=True)
    (root / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    (root / "etc/sudoers.d").mkdir(parents=True, exist_ok=True)
    for name in ("systemctl", "sshd", "auditctl", "modprobe", "aa-status", "ufw", "apt-config", "useradd"):
        write(root, f"usr/sbin/{name}")
    runner.handle("systemctl show", systemctl_show)
    runner.handle("sshd -T", lambda argv: CommandResult(argv, 0, SSHD_T, ""))
    runner.add("auditctl -l", "-w /etc/sudoers -p wa -k scope\n")
    runner.add("modprobe --showconfig", "blacklist cramfs\ninstall cramfs /bin/false\n")
    runner.add("aa-status", "apparmor module is loaded.\n42 profiles are loaded.\n40 profiles are in enforce mode.\n2 profiles are in complain mode.\n0 processes are unconfined but have a profile defined.\n")
    runner.add("ufw status verbose", "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
    runner.add("apt-config dump", 'APT::Get::AllowUnauthenticated "false";\n')
    runner.add("useradd -D", "GROUP=100\nHOME=/home\nINACTIVE=-1\nSHELL=/bin/sh\n")
    settings = dict(SETTINGS)
    settings["filesystem_scan"] = {"enabled": True, "exclude_paths": []}
    overrides = {
        "/etc/shadow": (0o640, 0, 42),
        "/etc/gshadow": (0o640, 0, 42),
        "/etc/passwd": (0o644, 0, 0),
        "/etc/group": (0o644, 0, 0),
        "/etc/ssh/sshd_config": (0o600, 0, 0),
        "/etc/crontab": (0o644, 0, 0),
    }
    return System(str(root), runner, settings, is_root=True, meta_overrides=overrides)


class DebianSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._root = TempRoot()
        root = cls._root.__enter__()
        cls.document, cls.definition, cls.warnings = assess(build_debian(root), include_manual=True)
        cls.results = statuses(cls.document, cls.definition)

    @classmethod
    def tearDownClass(cls):
        cls._root.__exit__(None, None, None)

    def test_every_control_has_one_result_and_none_errored(self):
        self.assertEqual(self.warnings, [])
        automated = len(self.definition["controls"])
        self.assertEqual(len(self.results), automated)
        errors = {item.check_id: item.observation for item in self.document.checks if item.status == ERROR}
        self.assertEqual(errors, {})

    def test_spot_verdicts(self):
        expected = {
            "5.1.22": FAIL,  # PermitRootLogin yes
            "5.1.11": PASS,  # HostbasedAuthentication no (reported by sshd -T)
            "5.1.12": PASS,  # IgnoreRhosts yes
            "5.2.2": PASS,  # Defaults use_pty
            "1.1.1.1": PASS,  # cramfs deny-listed with install /bin/false
            "1.7.1": NOT_APPLICABLE,  # GDM is not installed
        }
        titles = {control["cis_id"]: control["title"] for control in self.definition["controls"]}
        for cis_id, status in expected.items():
            with self.subTest(cis_id=cis_id, title=titles.get(cis_id)):
                self.assertEqual(self.results[cis_id], status)

    def test_plain_debian_has_no_proxmox_notes(self):
        self.assertFalse([item.check_id for item in self.document.checks if "Note (Proxmox VE)" in item.observation])

    def test_summary_arithmetic_matches_m365(self):
        summary = self.document.summary
        assessed = summary.pass_count + summary.fail_count + summary.warning_count
        self.assertEqual(summary.pass_percentage, round(100 * summary.pass_count / assessed, 2))
        self.assertEqual(len(self.document.findings), summary.fail_count + summary.warning_count)


class ProxmoxFilesystemScanTests(unittest.TestCase):
    def test_zfs_root_is_inventoried_and_guest_and_network_storage_skipped(self):
        from lsa.checks.filesystem import filesystem_scan

        with TempRoot() as root:
            system = build_debian(root, proxmox=True)
            write(root, "proc/filesystems", "nodev\tsysfs\nnodev\tproc\nnodev\tzfs\nnodev\tceph\nnodev\tfuse\n\tvfat\n")
            write(
                root,
                "proc/self/mountinfo",
                "22 1 0:25 / / rw,relatime shared:1 - zfs rpool/ROOT/pve-1 rw,xattr,noacl\n"
                "40 22 0:40 / /rpool/data/subvol-101-disk-0 rw,relatime shared:9 - zfs rpool/data/subvol-101-disk-0 rw,xattr,posixacl\n"
                "41 22 0:41 / /mnt/pve/cephfs rw,relatime shared:10 - ceph 10.0.0.1,10.0.0.2:/ rw,name=admin\n"
                "42 22 0:42 / /etc/pve rw,nosuid,nodev,relatime shared:11 - fuse /dev/fuse rw,user_id=0,group_id=0\n",
            )
            write(root, "rpool/data/subvol-101-disk-0/etc/passwd", "root:x:0:0::/root:/bin/sh\n")
            write(root, "var/lib/vz/images/102/subvol-102-disk-0.subvol/etc/passwd", "root:x:0:0::/root:/bin/sh\n")
            (root / "mnt/pve/cephfs").mkdir(parents=True)
            scan = filesystem_scan(system)
        self.assertEqual(scan.privileged_mounts, ["/"])
        self.assertIn("/", scan.general_mounts)
        self.assertIn("/etc/pve", scan.general_mounts)
        self.assertNotIn("/mnt/pve/cephfs", scan.general_mounts)
        self.assertIn("/rpool/data/subvol-101-disk-0", scan.guest_volumes)
        self.assertIn("/var/lib/vz/images/102/subvol-102-disk-0.subvol", scan.guest_volumes)


class ProxmoxTests(unittest.TestCase):
    def test_proxmox_node_gets_context_notes_and_title(self):
        from lsa.reporting.common import report_title

        with TempRoot() as root:
            document, definition, warnings = assess(build_debian(root, proxmox=True))
        self.assertEqual(warnings, [])
        self.assertEqual(report_title(document), "Proxmox VE Security Assessment")
        self.assertTrue(document.host.platform.startswith("Proxmox VE 9.0.6"))
        by_cis = {control["id"]: control["cis_id"] for control in definition["controls"]}
        observations = {by_cis[item.check_id]: item.observation for item in document.checks}
        self.assertIn("Note (Proxmox VE): Proxmox VE provides its own firewall", observations["4.1.1"])
        self.assertIn("Note (Proxmox VE)", observations["5.1.22"])
        self.assertNotIn("Note (Proxmox VE)", observations["5.1.11"])
        self.assertNotIn(ERROR, {item.status for item in document.checks})
