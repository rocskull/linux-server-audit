"""Applicability conditions for ``applies_if`` in benchmark definitions.

A condition returns ``(True, "")`` when the control applies or
``(False, reason)`` when CIS says the recommendation can be skipped, which
the engine reports as NOT_APPLICABLE with that reason.
"""

from __future__ import annotations

from lsa.checks.common import condition
from lsa.system import EvidenceUnavailable, System

CRON_PACKAGES = ("cron", "cronie", "systemd-cron")


@condition("package_installed")
def package_installed(system: System, spec: dict) -> tuple[bool, str]:
    names = spec["packages"]
    if any(system.package_installed(name) for name in names):
        return True, ""
    return False, f"{' / '.join(names)} is not installed, so this recommendation does not apply"


@condition("sshd_installed")
def sshd_installed(system: System, spec: dict) -> tuple[bool, str]:
    if system.package_installed("openssh-server") or system.which("sshd"):
        return True, ""
    return False, "The OpenSSH server is not installed; CIS section 5.1 only applies to systems running sshd"


@condition("cron_installed")
def cron_installed(system: System, spec: dict) -> tuple[bool, str]:
    if any(system.package_installed(name) for name in CRON_PACKAGES):
        return True, ""
    return False, "cron is not installed, so the cron recommendations can be skipped"


@condition("gdm_installed")
def gdm_installed(system: System, spec: dict) -> tuple[bool, str]:
    if system.package_installed("gdm3") or system.package_installed("gdm"):
        return True, ""
    return False, "GNOME Display Manager is not installed, so CIS section 1.7 can be skipped"


@condition("not_router")
def not_router(system: System, spec: dict) -> tuple[bool, str]:
    if system.settings.get("network_router"):
        return False, "The system is declared a network router (network_router=true); CIS exempts routers"
    return True, ""


@condition("ipv6_enabled")
def ipv6_enabled(system: System, spec: dict) -> tuple[bool, str]:
    if not ipv6_active(system):
        return False, "IPv6 is disabled on this system, so the IPv6 parameter recommendations do not apply"
    return True, ""


def ipv6_active(system: System) -> bool:
    """IPv6 state using the CIS f_ipv6_chk logic."""
    disable = system.read_text("/sys/module/ipv6/parameters/disable")
    if disable is not None and disable.strip() != "0":
        return False
    if not system.is_dir("/proc/sys/net/ipv6"):
        return False
    all_disabled = system.sysctl_running("net.ipv6.conf.all.disable_ipv6")
    default_disabled = system.sysctl_running("net.ipv6.conf.default.disable_ipv6")
    return not (all_disabled == "1" and default_disabled == "1")


@condition("time_daemon")
def time_daemon(system: System, spec: dict) -> tuple[bool, str]:
    wanted = spec["daemon"]
    active = time_daemon_in_use(system)
    if active == wanted:
        return True, ""
    label = {"timesyncd": "systemd-timesyncd", "chrony": "chrony"}
    current = label.get(active or "", "no time synchronization daemon")
    return False, f"{current} is the time synchronization method in use; the {label[wanted]} subsection is skipped"


def time_daemon_in_use(system: System) -> str | None:
    chrony = system.package_installed("chrony")
    timesyncd = system.package_installed("systemd-timesyncd")
    if chrony and timesyncd:
        try:
            states = system.units(["chrony.service", "systemd-timesyncd.service"])
        except EvidenceUnavailable:
            return "chrony"
        if states["systemd-timesyncd.service"].enabled or states["systemd-timesyncd.service"].active:
            if not (states["chrony.service"].enabled or states["chrony.service"].active):
                return "timesyncd"
        return "chrony"
    if chrony:
        return "chrony"
    if timesyncd:
        return "timesyncd"
    return None


@condition("logging_method")
def logging_method(system: System, spec: dict) -> tuple[bool, str]:
    wanted = spec["method"]
    method = logging_method_in_use(system)
    if method == wanted:
        return True, ""
    return False, f"{method} is the logging method in use (logging_method setting or detection); {wanted} guidance is skipped"


def logging_method_in_use(system: System) -> str:
    configured = str(system.settings.get("logging_method", "auto")).lower()
    if configured in ("rsyslog", "journald"):
        return configured
    if not system.package_installed("rsyslog"):
        return "journald"
    try:
        state = system.unit("rsyslog.service")
    except EvidenceUnavailable:
        return "rsyslog"
    return "rsyslog" if state.enabled or state.active else "journald"


@condition("path_exists")
def path_exists(system: System, spec: dict) -> tuple[bool, str]:
    if system.exists(spec["path"]):
        return True, ""
    return False, f"{spec['path']} does not exist"
