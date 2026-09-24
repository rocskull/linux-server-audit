"""Check specification for the CIS VMware ESXi 8.0 Benchmark v1.4.0.

The CIS PDF supplies control identity; this module maps each automated
recommendation to a topic in :mod:`specs.esxi_common` with a risk-based
severity. Manual recommendations (hardware, vCenter Server, guest and
organisational checks) are listed in reports with a generic review note.
"""

from __future__ import annotations

from typing import Any

from specs.esxi_common import PROFILES, REFERENCES, ControlSet

BENCHMARK = {
    "id": "vmware-esxi-8.0",
    "framework": "CIS",
    "name": "CIS VMware ESXi 8.0 Benchmark",
    "short_name": "VMware ESXi 8.0",
    "version": "1.4.0",
    "published": "2026-08-27",
    "source_document": "CIS_VMware_ESXi_8.0_Benchmark_v1.4.0_PDF.pdf",
    "output_file": "CIS_VMware_ESXi_8.0_1.4.0.json",
    "platform": {"os_id": "esxi", "version_ids": ["8"], "architectures": ["x86_64"]},
    "profiles": PROFILES,
}
ID_PREFIX = "ESX8"
AUTO_MANUAL_GUIDANCE = True
MANUAL_REFERENCES = REFERENCES

# Longest matching CIS prefix wins: (prefix, section, category, check-id code).
SECTIONS = [
    ("1", "Hardware", "Host Hardware", "HW"),
    ("2", "Base", "Host Software and Base Configuration", "BASE"),
    ("3", "Management", "Host Management Access", "MGMT"),
    ("4", "Logging", "Host Logging", "LOG"),
    ("5", "Network", "Virtual Networking", "NET"),
    ("6.1", "Features", "CIM", "CIM"),
    ("6.2", "Features", "Core Storage", "STOR"),
    ("6.3", "Features", "iSCSI", "ISCSI"),
    ("6.4", "Features", "SNMP", "SNMP"),
    ("6.5", "Features", "SSH Daemon", "SSHD"),
    ("7", "Virtual Machines", "Virtual Machine Configuration", "VM"),
    ("8", "VMware Tools", "VMware Tools", "TOOLS"),
]

_set = ControlSet()

# 2 Base
_set.acceptance_level("2.4", "High")
_set.ntp("2.6", "Medium")
_set.share_salting("2.10", "Low")

# 3 Management
_set.ssh_disabled("3.1", "High")
_set.shell_disabled("3.2", "Medium")
_set.mob_disabled("3.3", "Medium")
_set.dcui_timeout("3.7", "Low")
_set.shell_interactive_timeout("3.8", "Low")
_set.shell_timeout("3.9", "Low")
_set.lock_failures("3.12", "Medium")
_set.unlock_time("3.13", "Low")
_set.lockdown("3.20", strict=False, severity="Medium")
_set.lockdown("3.21", strict=True, severity="Low")

# 4 Logging
_set.remote_syslog("4.2", "Medium")

# 5 Network
_set.vswitch_policy("5.6", "forged", "Medium")
_set.vswitch_policy("5.7", "mac", "Medium")
_set.vswitch_policy("5.8", "promiscuous", "High")
_set.native_vlan("5.9", "Low")
_set.vgt("5.10", "Medium")

# 6 Features
_set.iscsi_chap("6.3.1", "Medium")

# 7 Virtual machines
_set.enable_3d("7.4", "Low", missing_ok=True)
_set.console_connections("7.6", "Low")
_set.pci_passthrough("7.7", "Medium")
_set.device_edit("7.8", "Medium")
_set.device_connect("7.9", "Medium")
_set.device_absent("7.12", "usb", "Medium")
_set.device_absent("7.13", "serial", "Low")
_set.device_absent("7.14", "parallel", "Low")
_set.device_absent("7.15", "cdrom", "Low")
_set.device_absent("7.16", "floppy", "Low")
_set.console_dnd("7.17", "Medium")
_set.console_copy("7.18", "Medium")
_set.console_paste("7.19", "Medium")
_set.disk_shrink("7.21", "Low")
_set.disk_wiper("7.22", "Low")
_set.host_info("7.24", "Low")
_set.log_keep_old("7.26", "Low")
_set.log_rotate_size("7.27", "Low")

CONTROLS: dict[str, dict[str, Any]] = _set.controls
MANUAL: dict[str, dict[str, Any]] = {}
