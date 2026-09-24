"""CIS Debian Linux 13 v1.1.0 specification: sections 3 (Network), 4 (Firewall) and 5 (Access Control)."""

from __future__ import annotations

from specs.debian13 import IPV4, IPV6, RELOAD_SSH, SSH, SUDO, add, kmod, man, manual, sysctl

# =========================================================== 3 Network
manual(
    "3.1.1",
    "Confirm whether IPv6 is required and record the decision; if it is not required disable it, otherwise configure it securely.",
    "To disable IPv6 add 'ipv6.disable=1' to GRUB_CMDLINE_LINUX and run 'update-grub', or set net.ipv6.conf.all.disable_ipv6 = 1 and net.ipv6.conf.default.disable_ipv6 = 1 in /etc/sysctl.d/.",
    ["https://docs.kernel.org/networking/ipv6.html"],
)
add(
    "3.1.2",
    "Medium",
    {"type": "wireless_interfaces"},
    "Checks that the driver module of any wireless interface is not loaded, not loadable and deny-listed.",
    "Servers should not have active wireless interfaces.",
    "An active wireless interface can bridge the server to an uncontrolled network, bypassing firewalls and monitoring.",
    "Disable wireless interfaces on servers.",
    "Run 'nmcli radio all off' if NetworkManager is used, then add 'install <driver> /bin/false' and 'blacklist <driver>' for each wireless driver in /etc/modprobe.d/.",
    [man("modprobe.d.5")],
)
add(
    "3.1.3",
    "Medium",
    {"type": "service_not_in_use", "groups": [{"packages": ["bluez"], "units": ["bluetooth.service"]}]},
    "Checks that the Bluetooth stack (bluez) is not installed or, when required as a dependency, that bluetooth.service is neither enabled nor active.",
    "Servers rarely have a legitimate need for Bluetooth.",
    "Bluetooth exposes the host to nearby attackers and has a history of remotely exploitable flaws.",
    "Remove or disable Bluetooth.",
    "Run 'apt purge bluez'; if it is a required dependency run 'systemctl --now mask bluetooth.service'.",
    [man("bluetoothd.8")],
)
for cis_id, module, name in (
    ("3.2.1", "atm", "Asynchronous Transfer Mode networking"),
    ("3.2.2", "can", "Controller Area Network protocol"),
    ("3.2.3", "dccp", "Datagram Congestion Control Protocol"),
    ("3.2.4", "rds", "Reliable Datagram Sockets protocol"),
    ("3.2.5", "sctp", "Stream Control Transmission Protocol"),
    ("3.2.6", "tipc", "Transparent Inter-Process Communication protocol"),
):
    kmod(
        cis_id,
        module,
        [f"net/{module}"],
        f"the {name}",
        severity="Medium",
        impact=f"Unprivileged users can make the kernel load the {module} protocol by opening a socket, exposing rarely used code that has contained privilege-escalation and remote vulnerabilities.",
    )
manual(
    "3.2.7",
    "Review network protocol modules that are loadable but unused and deny-list those without a business need.",
    "Compare 'lsmod' with the modules under /usr/lib/modules/*/kernel/net and add 'install <module> /bin/false' and 'blacklist <module>' for unused protocols.",
    [man("modprobe.d.5")],
)

ROUTER_NOTE = IPV4
sysctl("3.3.1.1", "net.ipv4.ip_forward", ["0"], "Medium", "A host that is not a router must not forward packets between interfaces.", "IP forwarding lets the host route traffic between networks, bypassing network segmentation.", ROUTER_NOTE)
sysctl("3.3.1.2", "net.ipv4.conf.all.forwarding", ["0"], "Medium", "Per-interface forwarding must be disabled on hosts that are not routers.", "Forwarding on any interface lets the host bridge network segments.", ROUTER_NOTE)
sysctl("3.3.1.3", "net.ipv4.conf.default.forwarding", ["0"], "Medium", "New interfaces must not inherit packet forwarding.", "Interfaces added later would forward traffic between networks.", ROUTER_NOTE)
sysctl("3.3.1.4", "net.ipv4.conf.all.send_redirects", ["0"], "Medium", "Only routers need to send ICMP redirects.", "A compromised host sending redirects can reroute other hosts' traffic through an attacker.", ROUTER_NOTE)
sysctl("3.3.1.5", "net.ipv4.conf.default.send_redirects", ["0"], "Medium", "New interfaces must not send ICMP redirects.", "Interfaces added later could be used to redirect neighbours' traffic.", ROUTER_NOTE)
sysctl("3.3.1.6", "net.ipv4.icmp_ignore_bogus_error_responses", ["1"], "Low", "Bogus ICMP error responses should be ignored rather than logged.", "Floods of bogus ICMP errors can fill logs and hide real events.", ROUTER_NOTE)
sysctl("3.3.1.7", "net.ipv4.icmp_echo_ignore_broadcasts", ["1"], "Medium", "The host should not answer broadcast pings.", "Answering broadcast echo requests makes the host an amplifier in Smurf denial-of-service attacks.", ROUTER_NOTE)
sysctl("3.3.1.8", "net.ipv4.conf.all.accept_redirects", ["0"], "Medium", "ICMP redirects can alter the routing table.", "An attacker on the local network can redirect traffic through a host they control to intercept it.", ROUTER_NOTE)
sysctl("3.3.1.9", "net.ipv4.conf.default.accept_redirects", ["0"], "Medium", "New interfaces must not accept ICMP redirects.", "Interfaces added later would accept routing changes from the network.", ROUTER_NOTE)
sysctl("3.3.1.10", "net.ipv4.conf.all.secure_redirects", ["0"], "Medium", "Even redirects from listed gateways can be spoofed.", "A spoofed gateway redirect can route traffic through an attacker.", ROUTER_NOTE)
sysctl("3.3.1.11", "net.ipv4.conf.default.secure_redirects", ["0"], "Medium", "New interfaces must not accept gateway redirects.", "Interfaces added later would accept spoofable routing changes.", ROUTER_NOTE)
sysctl("3.3.1.12", "net.ipv4.conf.all.rp_filter", ["1"], "Medium", "Strict reverse-path filtering drops packets with spoofed source addresses.", "Without it, spoofed traffic can reach services and aid denial-of-service or trust-exploitation attacks.", ROUTER_NOTE)
sysctl("3.3.1.13", "net.ipv4.conf.default.rp_filter", ["1"], "Medium", "New interfaces must use strict reverse-path filtering.", "Interfaces added later would accept spoofed source addresses.", ROUTER_NOTE)
sysctl("3.3.1.14", "net.ipv4.conf.all.accept_source_route", ["0"], "Medium", "Source-routed packets let the sender choose the path through the network.", "Source routing can bypass firewalls and network segmentation.", ROUTER_NOTE)
sysctl("3.3.1.15", "net.ipv4.conf.default.accept_source_route", ["0"], "Medium", "New interfaces must reject source-routed packets.", "Interfaces added later would accept attacker-chosen routes.", ROUTER_NOTE)
sysctl("3.3.1.16", "net.ipv4.conf.all.log_martians", ["1"], "Low", "Logging packets with impossible addresses helps detect spoofing.", "Spoofing and misrouting attempts go unnoticed.", ROUTER_NOTE)
sysctl("3.3.1.17", "net.ipv4.conf.default.log_martians", ["1"], "Low", "New interfaces should log packets with impossible addresses.", "Spoofing on interfaces added later goes unnoticed.", ROUTER_NOTE)
sysctl("3.3.1.18", "net.ipv4.tcp_syncookies", ["1"], "Medium", "SYN cookies keep the TCP stack responsive during SYN floods.", "A SYN flood can exhaust connection resources and make services unavailable.", ROUTER_NOTE)
sysctl("3.3.1.19", "net.ipv4.conf.all.route_localnet", ["0"], "Medium", "Loopback addresses must not be routable from external interfaces.", "Routing 127.0.0.0/8 externally can expose services that bind only to localhost.", ROUTER_NOTE)
sysctl("3.3.2.1", "net.ipv6.conf.all.forwarding", ["0"], "Medium", "A host that is not a router must not forward IPv6 packets.", "IPv6 forwarding lets the host route traffic between networks, bypassing segmentation.", IPV6 + IPV4)
sysctl("3.3.2.2", "net.ipv6.conf.default.forwarding", ["0"], "Medium", "New interfaces must not inherit IPv6 forwarding.", "Interfaces added later would forward IPv6 traffic between networks.", IPV6 + IPV4)
sysctl("3.3.2.3", "net.ipv6.conf.all.accept_redirects", ["0"], "Medium", "IPv6 redirects can alter the routing table.", "An attacker on the local network can redirect IPv6 traffic through a host they control.", IPV6)
sysctl("3.3.2.4", "net.ipv6.conf.default.accept_redirects", ["0"], "Medium", "New interfaces must not accept IPv6 redirects.", "Interfaces added later would accept routing changes from the network.", IPV6)
sysctl("3.3.2.5", "net.ipv6.conf.all.accept_source_route", ["0"], "Medium", "Source-routed IPv6 packets let the sender choose the path.", "Source routing can bypass firewalls and network segmentation.", IPV6)
sysctl("3.3.2.6", "net.ipv6.conf.default.accept_source_route", ["0"], "Medium", "New interfaces must reject source-routed IPv6 packets.", "Interfaces added later would accept attacker-chosen routes.", IPV6)
sysctl("3.3.2.7", "net.ipv6.conf.all.accept_ra", ["0"], "Medium", "Router advertisements reconfigure addresses and default routes.", "A rogue router advertisement can redirect all IPv6 traffic through an attacker.", IPV6)
sysctl("3.3.2.8", "net.ipv6.conf.default.accept_ra", ["0"], "Medium", "New interfaces must ignore router advertisements.", "Interfaces added later could be reconfigured by rogue router advertisements.", IPV6)

# =========================================================== 4 Firewall
add(
    "4.1.1",
    "High",
    {"type": "package_installed", "packages": ["ufw"]},
    "Checks that Uncomplicated Firewall (ufw) is installed.",
    "A host firewall limits which services are reachable, independent of network firewalls.",
    "Without a host firewall every listening service is exposed to any host that can route to the server.",
    "Install ufw (or document the equivalent host firewall in use).",
    "Run 'apt install ufw'.",
    [man("ufw.8")],
)
add(
    "4.1.2",
    "High",
    {"type": "ufw_service"},
    "Checks that ufw.service is enabled and active and that 'ufw status' reports Status: active.",
    "The firewall only protects the host while its rules are loaded.",
    "An installed but inactive firewall leaves every listening service exposed.",
    "Enable UFW and its service.",
    "Allow required inbound services first (for example 'ufw allow proto tcp from <admin-net> to any port 22'), then run 'ufw enable' and 'systemctl --now enable ufw'.",
    [man("ufw.8")],
)
for cis_id, direction, severity, allowed, why in (
    ("4.1.3", "incoming", "High", ["deny", "reject"], "Inbound traffic should be denied unless a rule explicitly allows it."),
    ("4.1.4", "outgoing", "Medium", ["deny", "reject"], "Outbound traffic should be limited to approved destinations to hinder data exfiltration and command-and-control."),
    ("4.1.5", "routed", "Medium", ["deny", "reject"], "Traffic routed through the host should be denied by default."),
):
    add(
        cis_id,
        severity,
        {"type": "ufw_default", "direction": direction, "allowed": allowed},
        f"Checks that UFW is active and its default {direction} policy is deny or reject.",
        why,
        f"A permissive default {direction} policy allows any traffic that no rule explicitly blocks.",
        f"Set the UFW default {direction} policy to deny.",
        f"Create allow rules for required traffic, then run 'ufw default deny {direction}'.",
        [man("ufw.8")],
    )

# =========================================================== 5.1 SSH
add(
    "5.1.1",
    "Medium",
    {
        "type": "file_permissions",
        "targets": [{"path": "/etc/ssh/sshd_config", "max_mode": "0600"}, {"source": "sshd_config_dropins", "mask": "0077"}],
        "owners": ["root"],
        "groups": ["root"],
    },
    "Checks that /etc/ssh/sshd_config is root:root with mode 0600 or stricter and that included .conf drop-ins are root:root with no group or other access.",
    "The SSH daemon configuration controls how every remote login is authenticated.",
    "A user who can change the sshd configuration can enable weak authentication or root login; readable files reveal the access policy.",
    "Restrict the sshd configuration files to root.",
    "Run 'chown root:root /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf' and 'chmod u-x,og-rwx' on each file.",
    [man("sshd_config.5")],
    SSH,
)
add(
    "5.1.2",
    "Medium",
    {"type": "file_permissions", "targets": [{"source": "sshd_include_dirs"}], "mask": "0077", "owners": ["root"], "groups": ["root"], "file_type": "dir"},
    "Checks that /etc/ssh/sshd_config.d and any other Include directory are root:root with no group or other access.",
    "Drop-in directories can add or override sshd settings.",
    "A writable drop-in directory lets an unprivileged user add an sshd configuration that weakens authentication.",
    "Restrict the sshd drop-in directories to root.",
    "Run 'chown root:root /etc/ssh/sshd_config.d' and 'chmod 0700 /etc/ssh/sshd_config.d'.",
    [man("sshd_config.5")],
    SSH,
)
add(
    "5.1.3",
    "High",
    {"type": "file_permissions", "targets": [{"source": "sshd_private_hostkeys"}], "max_mode": "0600", "owners": ["root"], "groups": ["root"]},
    "Checks that every private SSH host key used by sshd is root:root with mode 0600.",
    "Host private keys prove the server's identity to clients.",
    "A stolen host key lets an attacker impersonate the server and intercept SSH sessions and credentials.",
    "Restrict private host keys to root with mode 0600.",
    "Run 'chown root:root /etc/ssh/ssh_host_*_key' and 'chmod 0600 /etc/ssh/ssh_host_*_key'.",
    [man("sshd.8")],
    SSH,
)
add(
    "5.1.4",
    "Low",
    {"type": "file_permissions", "targets": [{"source": "sshd_public_hostkeys"}], "max_mode": "0644", "owners": ["root"], "groups": ["root"]},
    "Checks that every public SSH host key is root:root and no more permissive than 0644.",
    "Public host keys must not be replaceable by other users.",
    "A modified public host key can confuse key verification and host-based trust.",
    "Restrict public host keys to root with mode 0644 or stricter.",
    "Run 'chown root:root /etc/ssh/ssh_host_*_key.pub' and 'chmod u-x,go-wx /etc/ssh/ssh_host_*_key.pub'.",
    [man("sshd.8")],
    SSH,
)
add(
    "5.1.5",
    "Medium",
    {"type": "sshd_access"},
    "Checks that sshd restricts logins with AllowUsers, AllowGroups, DenyUsers or DenyGroups.",
    "Explicit access lists limit SSH logins to accounts with a business need.",
    "Without an access list every local account with a password or key, including service accounts, can attempt SSH logins.",
    "Restrict SSH logins to approved users or groups.",
    "Add for example 'AllowGroups ssh-users' to /etc/ssh/sshd_config.d/60-cis.conf above any Match block, " + RELOAD_SSH,
    [man("sshd_config.5")],
    SSH,
)
add(
    "5.1.6",
    "Low",
    {"type": "sshd_banner_configured"},
    "Checks that sshd presents a Banner file and that the banner does not disclose the operating system.",
    "A pre-authentication banner states the terms of authorized use.",
    "Without a banner the organization weakens its legal position against unauthorized access; a revealing banner aids fingerprinting.",
    "Configure an approved SSH banner.",
    "Add 'Banner /etc/issue.net' to /etc/ssh/sshd_config.d/60-cis.conf, place an approved notice in that file, " + RELOAD_SSH,
    [man("sshd_config.5")],
    SSH,
)


def sshd(cis_id: str, severity: str, settings: list[dict], what: str, why: str, impact: str, directive: str, **extra: dict) -> None:
    check = {"type": "sshd_option", "settings": settings, **extra}
    add(
        cis_id,
        severity,
        check,
        f"Checks the effective sshd configuration (sshd -T in the root/local-host context CIS uses) to confirm that {what}.",
        why,
        impact,
        f"Set {directive} in the sshd configuration.",
        f"Add '{directive}' to /etc/ssh/sshd_config.d/60-cis.conf above any Include or Match entries (sshd uses the first value it reads), " + RELOAD_SSH,
        [man("sshd_config.5")],
        SSH,
    )


WEAK_CIPHERS = ["3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se"]
WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]
WEAK_MACS = [
    "hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96", "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
]
sshd(
    "5.1.7",
    "High",
    [{"option": "ciphers", "rule": {"op": "no_weak", "values": WEAK_CIPHERS}}],
    "no CBC, arcfour or other weak cipher is offered",
    "Weak and CBC-mode ciphers have known cryptographic weaknesses.",
    "Weak ciphers can allow recovery of plaintext from captured SSH sessions.",
    "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com",
    informational="If chacha20-poly1305@openssh.com is offered, confirm OpenSSH includes the CVE-2023-48795 (Terrapin) strict key exchange fix; Debian 13 does.",
)
sshd(
    "5.1.8",
    "Medium",
    [{"option": "clientaliveinterval", "rule": {"op": "positive"}, "expected": "greater than 0"}, {"option": "clientalivecountmax", "rule": {"op": "positive"}, "expected": "greater than 0"}],
    "ClientAliveInterval and ClientAliveCountMax are both greater than zero",
    "Keep-alive probes let sshd detect and close dead or abandoned sessions.",
    "Abandoned sessions stay open indefinitely and can be hijacked or reused.",
    "ClientAliveInterval 15 and ClientAliveCountMax 3",
)
sshd("5.1.9", "Medium", [{"option": "disableforwarding", "rule": {"op": "equals", "value": "yes"}}], "DisableForwarding is yes", "Port, agent, X11 and stream-local forwarding can tunnel traffic through the server.", "SSH forwarding can bypass network controls and expose internal services to remote users.", "DisableForwarding yes")
sshd("5.1.10", "Low", [{"option": "gssapiauthentication", "rule": {"op": "equals", "value": "no"}}], "GSSAPIAuthentication is no", "GSSAPI authentication adds complexity and attack surface when Kerberos is not used.", "Unneeded authentication methods increase the code reachable before authentication.", "GSSAPIAuthentication no")
sshd("5.1.11", "Medium", [{"option": "hostbasedauthentication", "rule": {"op": "equals", "value": "no"}}], "HostbasedAuthentication is no", "Host-based authentication trusts other hosts instead of verifying users.", "A compromise of any trusted host grants SSH access to this server without user credentials.", "HostbasedAuthentication no")
sshd("5.1.12", "Medium", [{"option": "ignorerhosts", "rule": {"op": "equals", "value": "yes"}}], "IgnoreRhosts is yes", ".rhosts and .shosts files grant access based on host names.", "Legacy trust files could let users grant password-less access from arbitrary hosts.", "IgnoreRhosts yes")
sshd(
    "5.1.13",
    "High",
    [{"option": "kexalgorithms", "rule": {"op": "no_weak", "values": WEAK_KEX}}],
    "no SHA-1 based Diffie-Hellman key exchange is offered",
    "SHA-1 based key exchange algorithms are cryptographically weak.",
    "Weak key exchange lowers the cost of attacking captured sessions and invites downgrade attacks.",
    "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
)
manual(
    "5.1.14",
    "Confirm that post-quantum hybrid key exchange (mlkem768x25519-sha256 on OpenSSH 9.9+, and sntrup761x25519-sha512) is offered by sshd.",
    "Include the post-quantum algorithms at the front of KexAlgorithms in /etc/ssh/sshd_config.d/60-cis.conf and reload ssh.",
    [man("sshd_config.5")],
)
sshd("5.1.15", "Low", [{"option": "logingracetime", "rule": {"op": "range", "min": 1, "max": 60}, "expected": "1-60 seconds"}], "LoginGraceTime is between 1 and 60 seconds", "A short login grace period limits unauthenticated connections held open.", "Long grace periods let attackers tie up connection slots and slow brute-force detection.", "LoginGraceTime 60")
sshd("5.1.16", "Low", [{"option": "loglevel", "rule": {"op": "in", "values": ["VERBOSE", "INFO"]}, "expected": "VERBOSE or INFO"}], "LogLevel is VERBOSE or INFO", "SSH logins, including key fingerprints, must be logged for accountability.", "Too little SSH logging leaves unauthorized access undetected and hampers investigations.", "LogLevel VERBOSE")
sshd(
    "5.1.17",
    "High",
    [{"option": "macs", "rule": {"op": "no_weak", "values": WEAK_MACS}}],
    "no MD5, RIPEMD-160, truncated SHA-1 or 64-bit UMAC message authentication code is offered",
    "Weak MACs undermine the integrity protection of SSH traffic.",
    "Weak integrity protection makes tampering with SSH sessions more feasible.",
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
)
sshd("5.1.18", "Medium", [{"option": "maxauthtries", "rule": {"op": "max", "value": 4}}], "MaxAuthTries is 4 or less", "Limiting authentication attempts per connection slows password guessing.", "Many attempts per connection make brute-force attacks faster and quieter.", "MaxAuthTries 4")
sshd(
    "5.1.19",
    "Low",
    [{"option": "maxsessions", "rule": {"op": "max", "value": 10}}],
    "MaxSessions is 10 or less and no configuration file (including Match blocks) sets it higher",
    "Limiting sessions per connection bounds resource use.",
    "Unlimited multiplexed sessions allow resource exhaustion from a single connection.",
    "MaxSessions 10",
    config_file_limit={"keyword": "MaxSessions", "max": 10},
)
sshd("5.1.20", "Medium", [{"option": "maxstartups", "rule": {"op": "maxstartups", "limits": [10, 30, 60]}, "expected": "10:30:60 or more restrictive"}], "MaxStartups is 10:30:60 or more restrictive", "MaxStartups throttles concurrent unauthenticated connections.", "Without throttling an attacker can exhaust connection slots and deny legitimate administrative access.", "MaxStartups 10:30:60")
sshd("5.1.21", "Critical", [{"option": "permitemptypasswords", "rule": {"op": "equals", "value": "no"}}], "PermitEmptyPasswords is no", "Accounts with empty passwords must never be reachable over SSH.", "Any account with an empty password could be logged into remotely without credentials.", "PermitEmptyPasswords no")
sshd("5.1.22", "High", [{"option": "permitrootlogin", "rule": {"op": "equals", "value": "no"}}], "PermitRootLogin is no", "Administrators should log in with named accounts and escalate with sudo.", "Direct root login removes accountability and makes root the single target of password and key attacks.", "PermitRootLogin no")
sshd("5.1.23", "Medium", [{"option": "permituserenvironment", "rule": {"op": "equals", "value": "no"}}], "PermitUserEnvironment is no", "User-supplied environment variables can alter program behaviour at login.", "Users could set variables such as LD_PRELOAD to bypass restrictions on their SSH sessions.", "PermitUserEnvironment no")
sshd("5.1.24", "Medium", [{"option": "usepam", "rule": {"op": "equals", "value": "yes"}}], "UsePAM is yes", "PAM enforces account, password and session policy for SSH logins.", "Without PAM, lockout, password quality and session controls do not apply to SSH.", "UsePAM yes")

# =========================================================== 5.2 Privilege escalation
add(
    "5.2.1",
    "Medium",
    {"type": "package_installed", "any_of": [["sudo"], ["sudo-rs"], ["libsss-sudo", "sssd"]]},
    "Checks that sudo or sudo-rs is installed (or libsss-sudo with sssd when sudoers come from a directory).",
    "sudo provides accountable, least-privilege administration instead of shared root logins.",
    "Without sudo, administrators share the root password and actions cannot be attributed to individuals.",
    "Install sudo or sudo-rs.",
    "Run 'apt install sudo' (or 'apt install sudo-rs').",
    [man("sudo.8")],
)
add(
    "5.2.2",
    "Medium",
    {"type": "sudo_use_pty"},
    "Checks that sudoers explicitly sets 'Defaults use_pty' and never negates it.",
    "Running commands in a pseudo-terminal stops them from injecting input into the invoking terminal after sudo exits.",
    "Without use_pty a malicious command run with sudo can keep running and push keystrokes into the administrator's terminal.",
    "Set Defaults use_pty.",
    "Run 'visudo -f /etc/sudoers.d/60-cis' and add 'Defaults use_pty'; remove any '!use_pty'.",
    [man("sudoers.5")],
    SUDO,
)
add(
    "5.2.3",
    "Medium",
    {"type": "sudo_logfile"},
    "Checks that sudo activity is logged, either to a dedicated logfile (classic sudo) or to the journal/auth.log.",
    "A record of privileged commands supports accountability and investigation.",
    "Without a sudo log, privileged actions cannot be reconstructed after an incident.",
    "Ensure sudo usage is logged.",
    "For classic sudo run 'visudo -f /etc/sudoers.d/60-cis' and add 'Defaults logfile=\"/var/log/sudo.log\"'; for sudo-rs confirm sudo events reach journald or rsyslog.",
    [man("sudoers.5")],
    SUDO,
)
add(
    "5.2.4",
    "Medium",
    {"type": "sudo_forbidden", "pattern": r"\bNOPASSWD\s*:", "label": "NOPASSWD"},
    "Checks that no sudoers rule uses the NOPASSWD tag.",
    "Re-entering a password before privilege escalation confirms the user is present.",
    "With NOPASSWD, anyone who gains a user's session, even without the password, obtains that user's sudo privileges.",
    "Remove NOPASSWD from sudoers rules.",
    "Edit the reported files with 'visudo' and remove the NOPASSWD tags (automation accounts should use tightly scoped, documented exceptions).",
    [man("sudoers.5")],
    SUDO,
)
add(
    "5.2.5",
    "High",
    {"type": "sudo_forbidden", "pattern": r"!authenticate\b", "label": "!authenticate"},
    "Checks that no sudoers entry disables authentication with !authenticate.",
    "sudo must re-authenticate users before granting privileges.",
    "Disabling authentication turns any compromised user session into immediate root access.",
    "Remove !authenticate from sudoers.",
    "Edit the reported files with 'visudo' and remove every '!authenticate' entry.",
    [man("sudoers.5")],
    SUDO,
)
add(
    "5.2.6",
    "Low",
    {"type": "sudo_timestamp_timeout", "max": 15},
    "Checks that sudo's timestamp_timeout is explicitly set to between 0 and 15 minutes.",
    "A bounded credential cache limits how long sudo stays unlocked after authentication.",
    "A long or unlimited timeout lets anyone at an unattended terminal run privileged commands.",
    "Set timestamp_timeout to 15 minutes or less.",
    "Run 'visudo -f /etc/sudoers.d/60-cis' and add 'Defaults timestamp_timeout=15'.",
    [man("sudoers.5")],
    SUDO,
)
add(
    "5.2.7",
    "Medium",
    {"type": "su_restricted"},
    "Checks that /etc/pam.d/su requires pam_wheel.so with use_uid and a group= argument naming an empty group.",
    "Restricting su forces administrators to use sudo, which is logged and scoped.",
    "Unrestricted su lets any user who learns the root password become root without an audit trail.",
    "Restrict su to an empty, dedicated group.",
    "Run 'groupadd sugroup' and add 'auth required pam_wheel.so use_uid group=sugroup' to /etc/pam.d/su.",
    [man("pam_wheel.8")],
)

# =========================================================== 5.3 PAM
for cis_id, package, severity in (("5.3.1.1", "libpam-runtime", "Medium"), ("5.3.1.2", "libpam-modules", "Medium"), ("5.3.1.3", "libpam-pwquality", "Medium"), ("5.3.1.4", "cracklib-runtime", "Low")):
    add(
        cis_id,
        severity,
        {"type": "package_current", "package": package},
        f"Checks that {package} is installed and that APT knows of no newer version.",
        "Authentication modules must include the latest security fixes.",
        f"An outdated {package} can leave known authentication vulnerabilities unpatched.",
        f"Install the latest {package}.",
        f"Run 'apt update' and 'apt install {package}' (or 'apt upgrade').",
        [man("apt.8")],
    )


def pam_enabled(cis_id: str, module: str, requirements: list[dict], label: str, why: str, impact: str, remediation: str) -> None:
    add(
        cis_id,
        "Medium",
        {"type": "pam_module_enabled", "requirements": requirements, "module_label": label},
        f"Checks that {module} is present in the required Debian common PAM stacks.",
        why,
        impact,
        f"Enable {module} in the common PAM configuration.",
        remediation,
        [man(f"{module.replace('.so', '')}.8"), man("pam-auth-update.8")],
    )


pam_enabled(
    "5.3.2.1",
    "pam_unix.so",
    [
        {"file": "/etc/pam.d/common-account", "type": "account", "module": "pam_unix.so"},
        {"file": "/etc/pam.d/common-auth", "type": "auth", "module": "pam_unix.so"},
        {"file": "/etc/pam.d/common-password", "type": "password", "module": "pam_unix.so"},
        {"file": "/etc/pam.d/common-session", "type": "session", "module": "pam_unix.so"},
        {"file": "/etc/pam.d/common-session-noninteractive", "type": "session", "module": "pam_unix.so"},
    ],
    "pam_unix",
    "pam_unix provides standard password authentication and account checks.",
    "If pam_unix is missing from a stack, local password, expiry or session controls may silently stop applying.",
    "Run 'pam-auth-update --enable unix'.",
)
pam_enabled(
    "5.3.2.2",
    "pam_faillock.so",
    [
        {"file": "/etc/pam.d/common-auth", "type": "auth", "module": "pam_faillock.so", "args": ["preauth"]},
        {"file": "/etc/pam.d/common-auth", "type": "auth", "module": "pam_faillock.so", "args": ["authfail"]},
        {"file": "/etc/pam.d/common-account", "type": "account", "module": "pam_faillock.so"},
    ],
    "pam_faillock",
    "pam_faillock locks accounts after repeated failed authentication attempts.",
    "Without account lockout, online password guessing against local accounts is unlimited.",
    "Create pam-auth-update profiles for faillock and faillock_notify under /usr/share/pam-configs (preauth, authfail and account entries) and run 'pam-auth-update --enable faillock --enable faillock_notify'.",
)
pam_enabled(
    "5.3.2.3",
    "pam_pwquality.so",
    [{"file": "/etc/pam.d/common-password", "type": "password", "module": "pam_pwquality.so"}],
    "pam_pwquality",
    "pam_pwquality enforces password strength when passwords are changed.",
    "Without it users can choose trivially guessable passwords.",
    "Install libpam-pwquality and run 'pam-auth-update --enable pwquality'.",
)
pam_enabled(
    "5.3.2.4",
    "pam_pwhistory.so",
    [{"file": "/etc/pam.d/common-password", "type": "password", "module": "pam_pwhistory.so"}],
    "pam_pwhistory",
    "pam_pwhistory prevents reuse of recent passwords.",
    "Without history enforcement users can cycle back to compromised passwords.",
    "Create a pwhistory profile in /usr/share/pam-configs (password requisite pam_pwhistory.so use_authtok) and run 'pam-auth-update --enable pwhistory'.",
)
add(
    "5.3.3.1.1",
    "Medium",
    {"type": "faillock_option", "option": "deny", "rule": {"op": "range", "min": 1, "max": 5}},
    "Checks that /etc/security/faillock.conf sets deny to 5 or fewer failures and that no pam_faillock.so argument overrides it with 0 or more than 5.",
    "Locking accounts after a few failures stops online password guessing.",
    "A high or disabled failure limit lets attackers keep guessing passwords.",
    "Lock accounts after at most 5 failed attempts.",
    "Set 'deny = 5' in /etc/security/faillock.conf and remove deny= arguments from pam_faillock.so lines in /etc/pam.d/common-auth.",
    [man("faillock.conf.5")],
)
add(
    "5.3.3.1.2",
    "Medium",
    {"type": "faillock_option", "option": "unlock_time", "rule": {"op": "zero_or_min", "value": 900}},
    "Checks that /etc/security/faillock.conf sets unlock_time to 0 (manual unlock) or at least 900 seconds and that no pam_faillock.so argument overrides it with a shorter time.",
    "A lockout period long enough to deter guessing makes lockout effective.",
    "A short unlock time lets automated guessing resume almost immediately.",
    "Set unlock_time to 900 seconds or more (or 0).",
    "Set 'unlock_time = 900' in /etc/security/faillock.conf and remove unlock_time= arguments shorter than 900 from /etc/pam.d/common-auth.",
    [man("faillock.conf.5")],
)
add(
    "5.3.3.1.3",
    "Medium",
    {"type": "faillock_root", "min_root_unlock_time": 60},
    "Checks that faillock.conf sets even_deny_root and/or root_unlock_time, and that any root_unlock_time is at least 60 seconds.",
    "The root account is the most valuable target for password guessing.",
    "If root is exempt from lockout, its password can be guessed without limit wherever root can authenticate.",
    "Apply failed-login lockout to root.",
    "Add 'even_deny_root' and 'root_unlock_time = 60' to /etc/security/faillock.conf.",
    [man("faillock.conf.5")],
)


def pwquality(cis_id: str, option: str, severity: str, check: dict, what: str, why: str, impact: str, setting: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "pwquality_option", "option": option, **check},
        f"Checks that {what}, honouring pwquality precedence (module arguments, then pwquality.conf, then pwquality.conf.d).",
        why,
        impact,
        f"Configure {setting} for pam_pwquality.",
        f"Add '{setting}' to /etc/security/pwquality.conf.d/50-cis.conf and remove conflicting {option} values from pwquality.conf and the pam_pwquality.so arguments in /etc/pam.d/common-password.",
        [man("pwquality.conf.5")],
    )


pwquality("5.3.3.2.1", "difok", "Medium", {"rule": {"op": "min", "value": 2}, "required": True}, "difok is set to 2 or more", "New passwords should differ meaningfully from the previous one.", "Users can make trivial changes to an old, possibly compromised password.", "difok = 2")
pwquality("5.3.3.2.2", "minlen", "High", {"rule": {"op": "min", "value": 14}, "required": True}, "the minimum password length is 14 or more", "Password length is the strongest single factor in resistance to guessing and cracking.", "Short passwords can be cracked quickly from captured hashes or guessed online.", "minlen = 14")
manual(
    "5.3.3.2.3",
    "Confirm that password complexity (minclass and/or the dcredit, ucredit, lcredit and ocredit credits) follows site policy.",
    "Set for example 'minclass = 3' in /etc/security/pwquality.conf.d/50-cis.conf according to the password policy.",
    [man("pwquality.conf.5")],
)
pwquality("5.3.3.2.4", "maxrepeat", "Low", {"rule": {"op": "range", "min": 1, "max": 3}, "required": True}, "maxrepeat is between 1 and 3", "Limiting repeated characters removes an easy way to reach the length requirement.", "Passwords such as 'aaaaaaaaaaaaaa' satisfy length but are trivially guessed.", "maxrepeat = 3")
pwquality("5.3.3.2.5", "maxsequence", "Low", {"rule": {"op": "range", "min": 1, "max": 3}, "required": True}, "maxsequence is between 1 and 3", "Limiting monotonic sequences removes predictable patterns.", "Passwords such as '12345678901234' satisfy length but are among the first guessed.", "maxsequence = 3")
pwquality("5.3.3.2.6", "dictcheck", "Medium", {"rule": {"op": "not_equal", "value": 0}, "required": False}, "the dictionary check is not disabled", "Dictionary words are the first candidates in password guessing.", "Passwords based on dictionary words are cracked quickly.", "dictcheck = 1")
pwquality("5.3.3.2.7", "enforcing", "Medium", {"rule": {"op": "not_equal", "value": 0}, "required": False}, "password quality rules are enforced rather than only warned about", "Quality checks must reject weak passwords, not just warn.", "In warn-only mode users can still set weak passwords.", "enforcing = 1")
pwquality("5.3.3.2.8", "enforce_for_root", "Medium", {"flag": True}, "password quality rules also apply when root sets passwords", "Administrators setting passwords should meet the same quality bar.", "Weak passwords set by root for users or itself bypass the policy.", "enforce_for_root")


def pwhistory(cis_id: str, option: str, severity: str, check: dict, what: str, why: str, impact: str, setting: str) -> None:
    add(
        cis_id,
        severity,
        {"type": "pwhistory_option", "option": option, **check},
        f"Checks that {what}, configured in exactly one place (pwhistory.conf or the pam_pwhistory.so arguments).",
        why,
        impact,
        f"Configure {setting} for pam_pwhistory.",
        f"Set '{setting}' in /etc/security/pwhistory.conf (or on the pam_pwhistory.so line, but not both) and keep pam_pwhistory.so enabled in /etc/pam.d/common-password.",
        [man("pam_pwhistory.8"), man("pwhistory.conf.5")],
    )


pwhistory("5.3.3.3.1", "remember", "Medium", {"rule": {"op": "min", "value": 24}}, "the last 24 or more passwords are remembered", "Password history stops users from cycling back to old passwords.", "Users can return to a password that was previously exposed.", "remember = 24")
pwhistory("5.3.3.3.2", "enforce_for_root", "Low", {}, "password history is also enforced for root", "Root should follow the same reuse rules.", "Root could reuse an exposed password.", "enforce_for_root")
pwhistory("5.3.3.3.3", "use_authtok", "Low", {}, "pam_pwhistory uses the password already accepted by earlier modules (use_authtok)", "Using the token from the stack ensures every module checks the same password.", "Without use_authtok the history check may prompt separately or evaluate a different value.", "use_authtok")
add(
    "5.3.3.4.1",
    "High",
    {"type": "pam_unix_args", "forbid": "nullok", "label": "nullok"},
    "Checks that pam_unix.so is not given the nullok argument in any common PAM stack.",
    "nullok allows authentication to accounts with empty passwords.",
    "Any account with an empty password field could be logged into without credentials.",
    "Remove nullok from pam_unix.so.",
    "Remove 'nullok' from the pam_unix.so lines in /usr/share/pam-configs/unix (or /etc/pam.d/common-*) and run 'pam-auth-update --enable unix'.",
    [man("pam_unix.8")],
)
add(
    "5.3.3.4.2",
    "Low",
    {"type": "pam_unix_args", "forbid": r"remember=\d+", "label": "remember=N"},
    "Checks that pam_unix.so is not given the remember= argument.",
    "Password history belongs in pam_pwhistory, which stores it more securely than pam_unix.",
    "pam_unix history uses the legacy /etc/security/opasswd handling and duplicates policy in a weaker place.",
    "Remove remember= from pam_unix.so and use pam_pwhistory.",
    "Remove 'remember=<N>' from the pam_unix.so lines in /usr/share/pam-configs/unix and run 'pam-auth-update --enable unix'.",
    [man("pam_unix.8")],
)
add(
    "5.3.3.4.3",
    "Medium",
    {"type": "pam_unix_args", "require_any": ["sha512", "yescrypt"], "files": ["/etc/pam.d/common-password"], "pam_type": "password"},
    "Checks that every pam_unix.so password entry specifies sha512 or yescrypt.",
    "Strong, slow password hashing resists offline cracking.",
    "Weak hashes allow stolen password databases to be cracked quickly.",
    "Use yescrypt (or sha512) for pam_unix password hashing.",
    "Add 'yescrypt' to the pam_unix.so password line in /usr/share/pam-configs/unix and run 'pam-auth-update --enable unix'.",
    [man("pam_unix.8")],
)
add(
    "5.3.3.4.4",
    "Low",
    {"type": "pam_unix_args", "require_any": ["use_authtok"], "files": ["/etc/pam.d/common-password"], "pam_type": "password"},
    "Checks that every pam_unix.so password entry includes use_authtok.",
    "use_authtok makes pam_unix set the password that earlier modules (such as pwquality) already approved.",
    "Without it the quality checks could be bypassed by a separate prompt.",
    "Add use_authtok to pam_unix.so password entries.",
    "Add 'use_authtok' to the pam_unix.so password line in /usr/share/pam-configs/unix and run 'pam-auth-update --enable unix'.",
    [man("pam_unix.8")],
)

# =========================================================== 5.4 Accounts
add(
    "5.4.1.1",
    "Medium",
    {"type": "password_aging", "login_defs": "PASS_MAX_DAYS", "field": "maximum", "rule": {"op": "range", "min": 1, "max": 365}},
    "Checks that PASS_MAX_DAYS in /etc/login.defs and the maximum age of every account with a password are between 1 and 365 days.",
    "Periodic password expiry limits how long a compromised password remains useful.",
    "Passwords that never expire give an attacker indefinite access after a single compromise.",
    "Set a maximum password age of 365 days or less.",
    "Set 'PASS_MAX_DAYS 365' in /etc/login.defs and run 'chage --maxdays 365 <user>' for each reported account.",
    [man("login.defs.5"), man("chage.1")],
)
manual(
    "5.4.1.2",
    "Confirm that PASS_MIN_DAYS and each account's minimum password age are greater than 0 in line with site policy.",
    "Set 'PASS_MIN_DAYS 1' in /etc/login.defs and run 'chage --mindays 1 <user>' for existing accounts.",
    [man("login.defs.5")],
)
add(
    "5.4.1.3",
    "Low",
    {"type": "password_aging", "login_defs": "PASS_WARN_AGE", "field": "warn", "rule": {"op": "min", "value": 7}},
    "Checks that PASS_WARN_AGE and each account's password expiry warning are 7 days or more.",
    "Advance warning lets users change passwords before they expire.",
    "Users surprised by expiry tend to choose weak replacement passwords or get locked out.",
    "Warn users at least 7 days before password expiry.",
    "Set 'PASS_WARN_AGE 7' in /etc/login.defs and run 'chage --warndays 7 <user>' for each reported account.",
    [man("login.defs.5"), man("chage.1")],
)
add(
    "5.4.1.4",
    "Medium",
    {"type": "encrypt_method", "allowed": ["SHA512", "YESCRYPT"]},
    "Checks that ENCRYPT_METHOD in /etc/login.defs is SHA512 or YESCRYPT.",
    "The shadow tools use this algorithm when they set passwords.",
    "A weak algorithm lets stolen password hashes be cracked quickly.",
    "Use YESCRYPT (or SHA512) for password hashing.",
    "Set 'ENCRYPT_METHOD YESCRYPT' in /etc/login.defs.",
    [man("login.defs.5")],
)
add(
    "5.4.1.5",
    "Low",
    {"type": "inactive_lock", "max": 45},
    "Checks that the useradd default INACTIVE and the inactivity period of every account with a password are between 0 and 45 days.",
    "Accounts whose passwords have expired should be disabled after a short grace period.",
    "Dormant accounts with expired passwords remain a target that nobody is watching.",
    "Lock accounts 45 days or less after password expiry.",
    "Run 'useradd -D -f 45' and 'chage --inactive 45 <user>' for each reported account.",
    [man("useradd.8"), man("chage.1")],
)
add(
    "5.4.1.6",
    "Low",
    {"type": "password_change_past"},
    "Checks that no account with a password has a last-change date in the future.",
    "A future change date breaks password ageing for that account.",
    "Accounts with future change dates never reach expiry, defeating password ageing.",
    "Correct future password change dates.",
    "Investigate the reported accounts and reset the date with 'chage --lastday <YYYY-MM-DD> <user>' or force a password change.",
    [man("chage.1")],
)
add(
    "5.4.2.1",
    "Critical",
    {"type": "uid_zero"},
    "Checks that root is the only account with UID 0.",
    "Any UID 0 account has full root privileges.",
    "An extra UID 0 account is a hidden root backdoor that bypasses controls aimed at root.",
    "Remove or renumber any non-root UID 0 account.",
    "Investigate each reported account, then delete it or assign a new UID with 'usermod -u <uid> <user>'.",
    [man("passwd.5")],
)
add(
    "5.4.2.2",
    "High",
    {"type": "gid_zero_users"},
    "Checks that root is the only account whose primary group is GID 0 (sync, shutdown, halt and operator are excluded, as in CIS).",
    "Membership of the root group grants access to root-group-owned files.",
    "Accounts in GID 0 can read or modify sensitive root-group files.",
    "Assign non-root accounts a different primary group.",
    "Run 'usermod -g <group> <user>' for each reported account.",
    [man("usermod.8")],
)
add(
    "5.4.2.3",
    "High",
    {"type": "gid_zero_groups"},
    "Checks that the root group is the only group with GID 0.",
    "Another group with GID 0 is effectively the root group under a different name.",
    "Members of a duplicate GID 0 group gain root-group access without appearing in the root group.",
    "Renumber or remove duplicate GID 0 groups.",
    "Run 'groupmod -g <gid> <group>' or remove the group after moving its members.",
    [man("group.5")],
)
add(
    "5.4.2.4",
    "High",
    {"type": "root_access"},
    "Checks that the root account either has a password set or is locked (passwd -S status P or L).",
    "Root access must always require authentication.",
    "A root account with no password could be entered without credentials.",
    "Set a strong root password or lock the root account.",
    "Run 'passwd root' to set a strong password, or 'usermod -L root' if root logins are not needed.",
    [man("passwd.1")],
)
add(
    "5.4.2.5",
    "High",
    {"type": "root_path"},
    "Checks that root's login PATH has no empty or current-directory entries and that every entry is an existing, root-owned directory without group or other write access.",
    "Root runs commands by name; every PATH entry must be trustworthy.",
    "A writable or relative PATH entry lets an attacker plant a trojan that root executes, leading to full compromise.",
    "Make root's PATH contain only secure, root-owned directories.",
    "Correct PATH in /root/.profile, /root/.bashrc and /etc/profile, and run 'chown root:root' and 'chmod go-w' on each reported directory.",
    ["https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html"],
)
add(
    "5.4.2.6",
    "Low",
    {"type": "root_umask"},
    "Checks that /root/.profile and /root/.bashrc do not set a umask less restrictive than 0027.",
    "root's umask decides the default permissions of files root creates.",
    "A permissive root umask creates files that other users can read or modify.",
    "Set root's umask to 0027 or stricter.",
    "Set 'umask 0027' in /root/.profile and /root/.bashrc and remove less restrictive umask lines.",
    [man("umask.1p")],
)
add(
    "5.4.2.7",
    "Medium",
    {"type": "system_account_shells"},
    "Checks that system accounts (UID below UID_MIN, or 65534) other than root, halt, sync, shutdown and nfsnobody have no valid login shell.",
    "Service accounts should never be usable for interactive logins.",
    "A service account with a shell can be used for interactive access if its credentials or keys leak.",
    "Set a nologin shell on system accounts.",
    "Run 'usermod -s /usr/sbin/nologin <user>' for each reported account.",
    [man("nologin.8")],
)
add(
    "5.4.2.8",
    "Medium",
    {"type": "nologin_accounts_locked"},
    "Checks that every non-root account without a valid login shell is locked (passwd -S status L).",
    "Accounts that are not meant for login should not have usable passwords.",
    "An unlocked non-login account could still authenticate to services that do not check the shell.",
    "Lock accounts that have no valid login shell.",
    "Run 'usermod -L <user>' for each reported account.",
    [man("usermod.8")],
)
add(
    "5.4.3.1",
    "Low",
    {"type": "nologin_not_in_shells"},
    "Checks that /etc/shells does not list nologin.",
    "/etc/shells lists shells that are valid for login; nologin is not one.",
    "Listing nologin can let restricted accounts be treated as having a valid shell by FTP and other services.",
    "Remove nologin from /etc/shells.",
    "Delete any '/usr/sbin/nologin' or '/sbin/nologin' line from /etc/shells.",
    [man("shells.5")],
)
add(
    "5.4.3.2",
    "Low",
    {"type": "shell_timeout", "max": 900},
    "Checks that TMOUT is set to 900 seconds or less, readonly and exported in /etc/profile, /etc/profile.d or /etc/bash.bashrc.",
    "An idle shell timeout closes unattended interactive sessions.",
    "Unattended root or user shells can be used by anyone with physical or session access.",
    "Configure a readonly, exported TMOUT of 900 seconds or less.",
    "Create /etc/profile.d/60-cis-tmout.sh containing 'TMOUT=900', 'readonly TMOUT' and 'export TMOUT', and remove other TMOUT settings.",
    ["https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html"],
)
add(
    "5.4.3.3",
    "Medium",
    {"type": "default_umask"},
    "Checks that every umask in /etc/profile and /etc/profile.d/*.sh, and UMASK in /etc/login.defs, is 027 or more restrictive, and that a system-wide umask is configured.",
    "The default umask decides whether new files are readable by other users.",
    "A permissive default umask exposes users' new files to everyone on the system.",
    "Set a system-wide umask of 027 or stricter.",
    "Set 'UMASK 027' in /etc/login.defs and create /etc/profile.d/60-cis-umask.sh containing 'umask 027'; correct any less restrictive umask lines.",
    [man("login.defs.5"), man("pam_umask.8")],
)
