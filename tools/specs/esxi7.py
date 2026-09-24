"""Check specification for the CIS VMware ESXi 7.0 Benchmark v1.6.0.

The CIS PDF supplies control identity; this module maps each automated
recommendation to a topic in :mod:`specs.esxi_common` with a risk-based
severity. Manual recommendations (vCenter Server, certificate, directory and
organisational checks) are listed in reports with a generic review note.
"""

from __future__ import annotations

from typing import Any

from specs.esxi_common import GUEST_FEATURES, PROFILES, REFERENCES, ControlSet

BENCHMARK = {
    "id": "vmware-esxi-7.0",
    "framework": "CIS",
    "name": "CIS VMware ESXi 7.0 Benchmark",
    "short_name": "VMware ESXi 7.0",
    "version": "1.6.0",
    "published": "2026-08-27",
    "source_document": "CIS VMWare ESXi 7 Benchmark V1.6.0 PDF.pdf",
    "output_file": "CIS_VMware_ESXi_7.0_1.6.0.json",
    "platform": {"os_id": "esxi", "version_ids": ["7"], "architectures": ["x86_64"]},
    "profiles": PROFILES,
}
ID_PREFIX = "ESX7"
AUTO_MANUAL_GUIDANCE = True
MANUAL_REFERENCES = REFERENCES

# Longest matching CIS prefix wins: (prefix, section, category, check-id code).
SECTIONS = [
    ("1", "Install", "Host Software", "INST"),
    ("2", "Communication", "Host Communication", "COMM"),
    ("3", "Logging", "Host Logging", "LOG"),
    ("4", "Access", "Host Access", "ACC"),
    ("5", "Console", "Host Console", "CONS"),
    ("6", "Storage", "Storage", "STOR"),
    ("7", "vNetwork", "Virtual Networking", "NET"),
    ("8.1", "Virtual Machines", "VM Communication", "VMCOM"),
    ("8.2", "Virtual Machines", "VM Devices", "VMDEV"),
    ("8.3", "Virtual Machines", "VM Guest", "VMGST"),
    ("8.4", "Virtual Machines", "VM Monitor", "VMMON"),
    ("8.5", "Virtual Machines", "VM Resources", "VMRES"),
    ("8.6", "Virtual Machines", "VM Storage", "VMSTO"),
    ("8.7", "Virtual Machines", "VM Tools", "VMTLS"),
]

_set = ControlSet()

# 1 Install
_set.acceptance_level("1.2", "High")
_set.share_salting("1.4", "Low")

# 2 Communication
_set.ntp("2.1", "Medium")
_set.mob_disabled("2.3", "Medium")

# 3 Logging
_set.coredump_network("3.1", "Low")
_set.remote_syslog("3.3", "Medium")

# 4 Access
_set.nonroot_admin("4.1", "Medium")
_set.lock_failures("4.3", "Medium")
_set.unlock_time("4.4", "Low")

# 5 Console
_set.dcui_timeout("5.1", "Low")
_set.shell_disabled("5.2", "Medium")
_set.ssh_disabled("5.3", "High")
_set.lockdown("5.5", strict=False, severity="Medium")
_set.lockdown("5.6", strict=True, severity="Low")
_set.shell_interactive_timeout("5.8", "Low")
_set.shell_timeout("5.9", "Low")

# 6 Storage
_set.iscsi_chap("6.1", "Medium")

# 7 vNetwork
_set.vswitch_policy("7.1", "forged", "Medium")
_set.vswitch_policy("7.2", "mac", "Medium")
_set.vswitch_policy("7.3", "promiscuous", "High")
_set.native_vlan("7.4", "Low")
_set.vgt("7.6", "Medium")

# 8 Virtual machines
_set.console_connections("8.1.1", "Low")
_set.device_absent("8.2.1", "floppy", "Low")
_set.device_absent("8.2.2", "cdrom", "Low")
_set.device_absent("8.2.3", "parallel", "Low")
_set.device_absent("8.2.4", "serial", "Low")
_set.device_absent("8.2.5", "usb", "Medium")
_set.device_edit("8.2.6", "Medium")
_set.device_connect("8.2.7", "Medium")
_set.pci_passthrough("8.2.8", "Medium")

for _cis_id, _key in zip([f"8.4.{number}" for number in range(2, 21)], GUEST_FEATURES):
    _set.guest_feature(_cis_id, _key, "Low")

_set.console_copy("8.4.21", "Medium")
_set.console_dnd("8.4.22", "Medium")
_set.console_gui_options("8.4.23", "Low")
_set.console_paste("8.4.24", "Medium")
_set.enable_3d("8.5.2", "Low", missing_ok=False)
_set.nonpersistent_disks("8.6.1", "Low")
_set.disk_shrink("8.6.2", "Low")
_set.disk_wiper("8.6.3", "Low")
_set.log_keep_old("8.7.1", "Low")
_set.host_info("8.7.2", "Low")
_set.log_rotate_size("8.7.3", "Low")

CONTROLS: dict[str, dict[str, Any]] = _set.controls
MANUAL: dict[str, dict[str, Any]] = {}
