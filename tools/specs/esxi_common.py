"""Check specifications shared by the CIS VMware ESXi 7.0 and 8.0 benchmarks.

Both benchmarks assess the same host settings and virtual machine options
under different recommendation numbers. :class:`ControlSet` records each
automated recommendation with its provider parameters, a risk-based severity
and independently written guidance; the version modules only decide which
topic applies to which CIS number and how severe a gap is.

Severity reflects impact on a typical hypervisor, not the CIS profile level:
High for direct compromise paths into the hypervisor (unsigned code, a
persistent root shell, traffic interception), Medium for controls that stop
common attack techniques or protect accountability, Low for defense in depth.
"""

from __future__ import annotations

from typing import Any

L1 = "Level 1 (L1) - Corporate/Enterprise Environment (general use)"
L2 = "Level 2 (L2) - High Security/Sensitive Data Environment (limited functionality)"
PROFILES = [L1, L2]
SCG = "https://github.com/vmware/vcf-security-and-compliance-guidelines"
REFERENCES = [SCG]

VMS = [{"type": "vms_present"}]
ISCSI = [{"type": "iscsi_present"}]
VSWITCH = [{"type": "standard_vswitch_present"}]

VMX_HOW = (
    "Power off the virtual machine, open Edit Settings > VM Options > Advanced > Edit Configuration in the vSphere Client "
    "and set {key} to {value} (PowerCLI: Get-VM <name> | New-AdvancedSetting -Name {key} -Value {value} -Force). "
    "The setting takes effect at the next power-on."
)
DEVICE_HOW = (
    "Power off the virtual machine and remove the {label} in Edit Settings (PowerCLI example: {powercli}). "
    "Re-add a device temporarily only when an administrator needs it."
)

# Descriptions of the VMware Tools isolation options named by ESXi 7.0 section 8.4.
GUEST_FEATURES = {
    "isolation.tools.ghi.autologon.disable": "Guest Host Interaction automatic logon",
    "isolation.bios.bbs.disable": "BIOS Boot Specification (BBS) interface",
    "isolation.tools.ghi.protocolhandler.info.disable": "Guest Host Interaction protocol handler information",
    "isolation.tools.unity.taskbar.disable": "Unity taskbar",
    "isolation.tools.unityActive.disable": "Unity active mode",
    "isolation.tools.unity.windowContents.disable": "Unity window contents",
    "isolation.tools.unity.push.update.disable": "Unity push updates",
    "isolation.tools.vmxDnDVersionGet.disable": "drag-and-drop version query",
    "isolation.tools.guestDnDVersionSet.disable": "drag-and-drop version setting",
    "isolation.ghi.host.shellAction.disable": "Guest Host Interaction shell actions",
    "isolation.tools.dispTopoRequest.disable": "display topology requests",
    "isolation.tools.trashFolderState.disable": "trash folder state",
    "isolation.tools.ghi.trayicon.disable": "Guest Host Interaction tray icon",
    "isolation.tools.unity.disable": "Unity",
    "isolation.tools.unityInterlockOperation.disable": "Unity interlock operations",
    "isolation.tools.getCreds.disable": "GetCreds credential requests",
    "isolation.tools.hgfsServerSet.disable": "Host Guest File System (HGFS) server",
    "isolation.tools.ghi.launchmenu.change": "Guest Host Interaction launch menu changes",
    "isolation.tools.memSchedFakeSampleStats.disable": "memSchedFakeSampleStats memory statistics",
}


def _setting(key: str, rule: dict[str, Any], expected: str) -> dict[str, Any]:
    return {"key": key, "rule": rule, "expected": expected}


def _advanced_how(key: str, value: str, integer: bool = True) -> str:
    option = "-i" if integer else "-s"
    return (
        f"Run 'esxcli system settings advanced set -o /{key.replace('.', '/')} {option} {value}' in the ESXi Shell, "
        f"or change {key} under Configure > System > Advanced System Settings in the vSphere Client."
    )


class ControlSet:
    """Automated recommendations of one ESXi benchmark, keyed by CIS number."""

    def __init__(self) -> None:
        self.controls: dict[str, dict[str, Any]] = {}

    def add(
        self,
        cis_id: str,
        severity: str,
        check: dict[str, Any],
        description: str,
        rationale: str,
        impact: str,
        recommendation: str,
        remediation: str,
        applies_if: list[dict[str, Any]] | None = None,
        references: list[str] | None = None,
    ) -> None:
        if cis_id in self.controls:
            raise ValueError(f"Duplicate specification for {cis_id}")
        self.controls[cis_id] = {
            "severity": severity,
            "check": check,
            "description": description,
            "rationale": rationale,
            "business_impact": impact,
            "recommendation": recommendation,
            "remediation": remediation,
            "references": references or REFERENCES,
            "applies_if": applies_if or [],
        }

    # ------------------------------------------------------------ software
    def acceptance_level(self, cis_id: str, severity: str = "High") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_acceptance"},
            "Checks that the host image profile acceptance level, and the acceptance level of every installed VIB, is PartnerSupported, VMwareAccepted or VMwareCertified.",
            "The acceptance level decides which software bundles the host will install. CommunitySupported bundles are not tested or signed by VMware or a partner, yet run with full privileges in the hypervisor.",
            "Unsigned or community VIBs can place kernel-level malware or unstable drivers in the hypervisor, compromising every virtual machine on the host; malicious VIBs have been used by attackers as a persistence mechanism.",
            "Keep the host acceptance level at PartnerSupported or higher and remove installed VIBs below that level.",
            "Review the VIBs reported below PartnerSupported ('esxcli software vib list'), remove those without a supported replacement with 'esxcli software vib remove -n <name>', then run 'esxcli software acceptance set --level=PartnerSupported'.",
        )

    def share_salting(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("Mem.ShareForceSalting", {"op": "equals", "value": "2"}, "2")]},
            "Checks that Mem.ShareForceSalting is 2, so transparent page sharing only shares memory between virtual machines that have the same salt value (by default, only within one virtual machine).",
            "Research has shown that memory pages shared between virtual machines can be used as a timing side channel to infer another virtual machine's memory contents.",
            "A malicious or compromised virtual machine could use page-sharing side channels to recover secrets, such as cryptographic keys, from other virtual machines on the host.",
            "Set Mem.ShareForceSalting to 2.",
            _advanced_how("Mem.ShareForceSalting", "2") + " Virtual machines pick up the change when they are powered on or migrated.",
        )

    # -------------------------------------------------------------- time
    def ntp(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_ntp"},
            "Checks that NTP servers are configured, the NTP service is running and its startup policy is 'Start and stop with host'. When approved_time_servers is set in config.json, every configured server must be on that list.",
            "Accurate and consistent time is needed to correlate logs across systems, validate certificates and authenticate against Active Directory.",
            "Clock drift makes host logs unreliable for incident timelines and can break directory authentication and certificate validation.",
            "Configure at least two authoritative NTP sources and set the NTP service to start and stop with the host.",
            "In the vSphere Client select the host > Configure > System > Time Configuration, edit Network Time Protocol, add the servers and set the startup policy to 'Start and stop with host'. From the ESXi Shell (7.0 Update 1 and later): 'esxcli system ntp set --server=<ntp1> --server=<ntp2> --enabled=true'.",
        )

    # ------------------------------------------------------- access paths
    def ssh_disabled(self, cis_id: str, severity: str = "High") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_service_disabled", "service": "TSM-SSH", "label": "SSH", "audit_channel": True},
            "Checks that the SSH service startup policy is 'Start and stop manually', so SSH is only available while an administrator has started it for a specific task.",
            "Standing SSH access to the hypervisor bypasses vCenter Server role-based access control and gives a direct root shell on the host.",
            "An attacker with stolen or guessed credentials gets an interactive root shell on the hypervisor and can encrypt or delete every virtual machine; enabling SSH is a common step in ESXi ransomware attacks.",
            "Keep SSH stopped with a manual startup policy and start it only for time-limited maintenance, together with the ESXi Shell timeouts.",
            "In the vSphere Client (or the VMware Host Client) select the host > Configure > System > Services > SSH > Edit Startup Policy > 'Start and stop manually', and stop the service once this assessment has finished.",
        )

    def shell_disabled(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_service_disabled", "service": "TSM", "label": "ESXi Shell", "audit_channel": True},
            "Checks that the ESXi Shell service startup policy is 'Start and stop manually', so the local shell is only available while an administrator has started it.",
            "The ESXi Shell gives unrestricted root access from the server console or its remote management controller, outside vCenter Server permissions.",
            "Anyone reaching the console or the hardware management controller (for example through a weak iLO/iDRAC password) could use a running ESXi Shell to take full control of the host.",
            "Keep the ESXi Shell stopped with a manual startup policy and start it only for troubleshooting.",
            "In the vSphere Client (or the VMware Host Client) select the host > Configure > System > Services > ESXi Shell > Edit Startup Policy > 'Start and stop manually', and stop the service when it is not in use.",
        )

    def mob_disabled(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_mob_disabled"},
            "Checks that Config.HostAgent.plugins.solo.enableMob is false, so the Managed Object Browser web interface is disabled (falling back to the reverse proxy endpoint list when the option cannot be read).",
            "The Managed Object Browser exposes the host's object model over HTTPS and lets authenticated users view and change configuration outside the normal management tools. It exists for debugging.",
            "An attacker holding host credentials can use the MOB from a web browser to explore and change host configuration, and the extra endpoint enlarges the host's attack surface.",
            "Disable the Managed Object Browser and enable it only temporarily for troubleshooting.",
            "In the vSphere Client select the host > Configure > System > Advanced System Settings and set Config.HostAgent.plugins.solo.enableMob to false. The benchmark notes that this must be changed from the vSphere interface and cannot be changed while the host is in lockdown mode.",
        )

    def dcui_timeout(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("UserVars.DcuiTimeOut", {"op": "range", "min": 1, "max": 600}, "1 to 600 seconds")]},
            "Checks that UserVars.DcuiTimeOut is between 1 and 600 seconds, so idle Direct Console User Interface sessions are logged out automatically (0 disables the timeout).",
            "A console session left logged in can be used by anyone with access to the physical console or the remote management controller.",
            "An abandoned DCUI session lets someone at the console change management networking, restart agents or enable the shell without authenticating.",
            "Set UserVars.DcuiTimeOut to 600 seconds or less.",
            _advanced_how("UserVars.DcuiTimeOut", "600"),
        )

    def shell_interactive_timeout(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("UserVars.ESXiShellInteractiveTimeOut", {"op": "range", "min": 1, "max": 300}, "1 to 300 seconds")]},
            "Checks that UserVars.ESXiShellInteractiveTimeOut is between 1 and 300 seconds, so idle ESXi Shell and SSH sessions are closed automatically (0 disables the timeout).",
            "Idle privileged shell sessions can be taken over by anyone with access to the administrator's workstation or the console.",
            "An unattended root shell on the hypervisor gives full control of the host and all of its virtual machines to whoever reaches it.",
            "Set UserVars.ESXiShellInteractiveTimeOut to 300 seconds or less.",
            _advanced_how("UserVars.ESXiShellInteractiveTimeOut", "300"),
        )

    def shell_timeout(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("UserVars.ESXiShellTimeOut", {"op": "range", "min": 1, "max": 3600}, "1 to 3600 seconds")]},
            "Checks that UserVars.ESXiShellTimeOut is between 1 and 3600 seconds, so the ESXi Shell and SSH services stop accepting new logins automatically after being started (0 leaves them available indefinitely).",
            "Shell services started for maintenance are easily forgotten; an automatic timeout closes that window.",
            "Shell services left running after maintenance keep a direct root login path to the hypervisor open to attackers.",
            "Set UserVars.ESXiShellTimeOut to 3600 seconds or less.",
            _advanced_how("UserVars.ESXiShellTimeOut", "3600"),
        )

    def lock_failures(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("Security.AccountLockFailures", {"op": "range", "min": 1, "max": 5}, "1 to 5")]},
            "Checks that Security.AccountLockFailures is between 1 and 5, so a local account is locked after at most five consecutive failed logins (0 disables lockout).",
            "Account lockout limits online password guessing against local accounts through SSH, the Host Client and the API.",
            "Without lockout an attacker can guess local passwords, including root's, at an unlimited rate.",
            "Set Security.AccountLockFailures to 5 or fewer attempts.",
            _advanced_how("Security.AccountLockFailures", "5"),
        )

    def unlock_time(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("Security.AccountUnlockTime", {"op": "min", "value": 900}, "900 seconds or more")]},
            "Checks that Security.AccountUnlockTime is at least 900 seconds, so a locked account stays locked for 15 minutes or longer.",
            "A short unlock time lets password guessing continue at a high rate despite lockout.",
            "Brute-force attempts can resume shortly after each lockout, eroding the protection lockout provides.",
            "Set Security.AccountUnlockTime to 900 seconds.",
            _advanced_how("Security.AccountUnlockTime", "900"),
        )

    def lockdown(self, cis_id: str, strict: bool, severity: str) -> None:
        if strict:
            self.add(
                cis_id,
                severity,
                {"type": "esxi_lockdown", "allowed": ["lockdownStrict"]},
                "Checks that the host is in strict lockdown mode, which also stops the Direct Console User Interface service.",
                "Strict lockdown removes the DCUI as a management path, so the host is managed only through vCenter Server and by Exception Users.",
                "In normal lockdown mode anyone at the physical or remote console with DCUI access can still change the host's configuration.",
                "Enable strict lockdown mode where losing DCUI access is acceptable and a tested recovery procedure exists.",
                "In the vSphere Client select the host > Configure > System > Security Profile > Lockdown Mode > Edit and choose Strict. Confirm vCenter Server connectivity and the Exception Users list first: a host that loses vCenter Server while in strict lockdown can become unmanageable until it is reinstalled.",
            )
            return
        self.add(
            cis_id,
            severity,
            {"type": "esxi_lockdown", "allowed": ["lockdownNormal", "lockdownStrict"]},
            "Checks that lockdown mode is enabled (normal or strict), so the host is managed through vCenter Server, the DCUI and the Exception Users only.",
            "Lockdown mode forces administration through vCenter Server, where role-based access control, auditing and alarms apply, and blocks direct logins with local credentials.",
            "Without lockdown mode anyone holding local credentials can manage the host directly, bypassing vCenter Server permissions and auditing.",
            "Enable normal lockdown mode on hosts managed by vCenter Server and keep the Exception Users list to service accounts that require direct access.",
            "In the vSphere Client select the host > Configure > System > Security Profile > Lockdown Mode > Edit and choose Normal. Lockdown mode needs vCenter Server; for a standalone host, record a documented exception instead.",
        )

    # ------------------------------------------------------------ logging
    def remote_syslog(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_advanced", "settings": [_setting("Syslog.global.logHost", {"op": "present"}, "at least one remote syslog collector")]},
            "Checks that Syslog.global.logHost names at least one remote syslog collector.",
            "Logs held only on the host are lost when it fails and can be altered or deleted by an attacker who compromises it.",
            "Without remote logging, investigations of host compromise, ransomware deployment or configuration tampering lack trustworthy evidence.",
            "Send host logs to a central syslog collector or SIEM, preferably over TLS.",
            "Run 'esxcli system syslog config set --loghost=ssl://<collector>:1514', 'esxcli system syslog reload' and 'esxcli network firewall ruleset set -r syslog -e true', or set Syslog.global.logHost under Advanced System Settings.",
        )

    def coredump_network(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_coredump_network"},
            "Checks that a network dump collector is configured and enabled, so kernel core dumps are sent off the host.",
            "Core dumps are needed to diagnose host failures; a central collector keeps them available when local storage is small or unavailable.",
            "Without a central dump location the cause of a host crash may be lost, and dumps containing virtual machine memory stay on local storage.",
            "Configure ESXi Dump Collector, or another network dump target, and enable it.",
            "Run 'esxcli system coredump network set -v vmk0 -i <collector IP> -o 6500', then 'esxcli system coredump network set -e true', and confirm with 'esxcli system coredump network check'.",
        )

    # ----------------------------------------------------------- accounts
    def nonroot_admin(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_nonroot_admin"},
            "Checks that at least one named account other than root, dcui and vpxuser holds the Administrator role on the host.",
            "Named administrator accounts make host actions attributable to individuals and let the shared root password be kept in a vault for emergencies.",
            "When every administrator uses root, host logs cannot show who made a change and the root password has to be shared widely.",
            "Create a named administrator account for each host administrator (or use directory accounts) and reserve root for break-glass use.",
            "In the VMware Host Client open Manage > Security & users > Users > Add user, then grant the account the Administrator role through Host > Actions > Permissions. Enable shell access for the account only if shell administration is required.",
        )

    # ------------------------------------------------------------ network
    def vswitch_policy(self, cis_id: str, policy: str, severity: str) -> None:
        label, option, what, impact = {
            "forged": (
                "Forged transmits",
                "--allow-forged-transmits=false",
                "frames whose source MAC address differs from the virtual NIC's own address",
                "A compromised virtual machine could impersonate other systems' MAC addresses to intercept traffic or evade network access controls.",
            ),
            "mac": (
                "MAC address changes",
                "--allow-mac-change=false",
                "a guest changing its effective MAC address and receiving frames for the new address",
                "A compromised virtual machine could take over another system's MAC address and receive traffic intended for it.",
            ),
            "promiscuous": (
                "Promiscuous mode",
                "--allow-promiscuous=false",
                "a virtual NIC receiving every frame on the port group rather than only frames addressed to it",
                "A compromised virtual machine in promiscuous mode can capture other virtual machines' traffic, including credentials sent without encryption.",
            ),
        }[policy]
        self.add(
            cis_id,
            severity,
            {"type": "esxi_vswitch_security", "policy": policy, "label": label},
            f"Checks that {label.lower()} ({what}) is set to Reject on every standard vSwitch and port group.",
            f"Rejecting {label.lower()} keeps each virtual machine to its assigned identity and traffic on the virtual switch.",
            impact,
            f"Set {label} to Reject on every standard vSwitch and port group unless a documented workload, such as nested virtualization or a network appliance, requires otherwise.",
            f"Run 'esxcli network vswitch standard policy security set -v <vSwitch> {option}' and, for port groups that override the switch policy, 'esxcli network vswitch standard portgroup policy security set -p \"<port group>\" {option}', or edit the switch security policy in the vSphere Client.",
            applies_if=VSWITCH,
        )

    def native_vlan(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_portgroup_vlan", "native_vlan": True, "what": "the physical network's native VLAN"},
            "Checks that no standard port group uses the physical switches' native VLAN (VLAN 1 unless another ID is set as esxi_native_vlan in config.json).",
            "Physical switches send native VLAN traffic untagged; virtual machines on it are exposed to VLAN-hopping attacks and to devices on unconfigured switch ports.",
            "Virtual machines on the native VLAN can reach, or be reached from, network segments that should be separated.",
            "Place port groups on dedicated VLANs other than the native VLAN.",
            "Change the VLAN ID with 'esxcli network vswitch standard portgroup set -p \"<port group>\" --vlan-id <id>' or in the port group settings, after confirming that the upstream switch ports carry that VLAN.",
            applies_if=VSWITCH,
        )

    def vgt(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_portgroup_vlan", "forbid": ["4095"], "what": "VLAN 4095 (Virtual Guest Tagging)", "note_vlans": ["0"]},
            "Checks that no standard port group uses VLAN 4095, which passes every VLAN tag to the guest (Virtual Guest Tagging), unless the port group is listed in esxi_vgt_portgroups in config.json. Port groups on VLAN 0 are listed for review.",
            "With Virtual Guest Tagging the guest operating system chooses its VLANs, so network separation depends on the guest instead of the virtual switch.",
            "A compromised virtual machine on a VGT port group can tag its traffic onto any VLAN trunked to the host and reach segments it should not.",
            "Use VLAN 4095 only for virtual machines that need guest tagging, such as virtual routers or firewalls, and document them.",
            "Assign a specific VLAN ID with 'esxcli network vswitch standard portgroup set -p \"<port group>\" --vlan-id <id>', or record approved guest-tagging port groups in config.json.",
            applies_if=VSWITCH,
        )

    # ------------------------------------------------------------ storage
    def iscsi_chap(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "esxi_iscsi_chap"},
            "Checks that every iSCSI adapter requires CHAP in both directions (unidirectional and mutual CHAP level 'required').",
            "Mutual CHAP authenticates the storage target to the host as well as the host to the target, so a rogue target cannot present storage to the host.",
            "Without mutual CHAP an attacker on the storage network could impersonate the iSCSI target or initiator to read, alter or substitute virtual disks.",
            "Configure bidirectional CHAP with unique secrets on every iSCSI adapter.",
            "In the vSphere Client select the host > Configure > Storage Adapters > the iSCSI adapter > Properties > Authentication > Edit and choose 'Use bidirectional CHAP'. Avoid typing CHAP secrets on the ESXi command line, where shell history can record them.",
            applies_if=ISCSI,
        )

    # ---------------------------------------------------- virtual machines
    def vmx(
        self,
        cis_id: str,
        key: str,
        value: str,
        severity: str,
        subject: str,
        rationale: str,
        impact: str,
        missing_ok: bool = False,
    ) -> None:
        default = " or leaves it unset (the default is equivalent)" if missing_ok else ""
        self.add(
            cis_id,
            severity,
            {"type": "vmx_setting", "key": key, "expected": value, "missing_ok": missing_ok},
            f"Checks that every registered virtual machine sets {key} = {value}{default}, which {subject}.",
            rationale,
            impact,
            f"Set {key} to {value} on every virtual machine" + (" or leave it at its default." if missing_ok else "."),
            VMX_HOW.format(key=key, value=value),
            applies_if=VMS,
        )

    def guest_feature(self, cis_id: str, key: str, severity: str = "Low") -> None:
        feature = GUEST_FEATURES[key]
        self.vmx(
            cis_id,
            key,
            "TRUE",
            severity,
            f"disables the VMware Tools {feature} interface",
            "These VMware Tools interfaces support desktop-hypervisor features (Unity, drag and drop, Guest Host Interaction) that vSphere does not use; disabling them removes guest-to-host communication channels.",
            "Every unused guest-to-host interface is additional attack surface that a compromised guest could probe for a way out of the virtual machine.",
        )

    def device_absent(self, cis_id: str, device: str, severity: str) -> None:
        regex, label, powercli, impact, cdrom = {
            "floppy": (r"^floppy\d+$", "a floppy drive", "Get-VM <name> | Get-FloppyDrive | Remove-FloppyDrive", "An unused floppy device adds emulation code that the guest can reach and can be used to attach media images.", False),
            "cdrom": (r"^(ide|sata)\d+:\d+$", "a CD/DVD drive", "Get-VM <name> | Get-CDDrive | Remove-CDDrive", "A connected ISO image or host optical drive can bring unapproved software into the guest or be used to move data.", True),
            "parallel": (r"^parallel\d+$", "a parallel port", "remove the parallel port in Edit Settings", "A parallel port can be backed by a host file, creating an unmonitored data path out of the virtual machine.", False),
            "serial": (r"^serial\d+$", "a serial port", "remove the serial port in Edit Settings", "A serial port can be backed by a network connection or host file, creating an unmonitored data path out of the virtual machine.", False),
            "usb": (r"^(usb|usb_xhci|ehci)$", "a USB controller", "Get-VM <name> | Get-UsbDevice | Remove-UsbDevice, then remove the controller in Edit Settings", "USB passthrough lets devices attached to the host or an administrator's client be connected to the guest, bypassing data-transfer controls.", False),
        }[device]
        check: dict[str, Any] = {"type": "vmx_device_absent", "device_regex": regex, "label": label}
        if cdrom:
            check["cdrom_only"] = True
        self.add(
            cis_id,
            severity,
            check,
            f"Checks that no registered virtual machine has {label} present (the matching .present option is absent or FALSE).",
            "Each virtual device is emulation code in the hypervisor that the guest can interact with; removing devices the workload does not use reduces attack surface.",
            impact,
            f"Remove {label} from virtual machines that do not need it.",
            DEVICE_HOW.format(label=label.split(" ", 1)[1], powercli=powercli),
            applies_if=VMS,
        )

    def pci_passthrough(self, cis_id: str, severity: str = "Medium") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "vmx_device_absent", "device_regex": r"^pcipassthru\d+$", "label": "a PCI/PCIe passthrough device"},
            "Checks that no registered virtual machine has a PCI or PCIe passthrough device (DirectPath I/O or Dynamic DirectPath I/O) present.",
            "Passthrough gives the guest direct access to physical hardware, including DMA, bypassing the hypervisor's device isolation.",
            "A compromised guest with a passthrough device may read or corrupt host memory through DMA or device firmware attacks; such virtual machines also cannot use vMotion.",
            "Use PCI passthrough only for documented workloads that require it, such as GPU compute, and review those virtual machines regularly.",
            "Power off the virtual machine and remove the PCI device in Edit Settings.",
            applies_if=VMS,
        )

    def nonpersistent_disks(self, cis_id: str, severity: str = "Low") -> None:
        self.add(
            cis_id,
            severity,
            {"type": "vmx_disk_mode", "modes": ["independent-nonpersistent", "nonpersistent"]},
            "Checks that no virtual disk uses a non-persistent mode, in which all changes are discarded when the virtual machine is powered off.",
            "Non-persistent disks erase every change, including an intruder's traces, when the virtual machine restarts.",
            "Evidence of a compromise inside the guest disappears when the virtual machine is restarted, defeating investigation.",
            "Use non-persistent disks only where discarding all changes is intended, such as kiosks or training labs, and document those virtual machines.",
            "Power off the virtual machine and change the disk mode to Dependent or Independent - Persistent in Edit Settings (PowerCLI: Get-VM <name> | Get-HardDisk | Set-HardDisk -Persistence Persistent).",
            applies_if=VMS,
        )

    # Individual VM options shared by both benchmark versions.
    def console_copy(self, cis_id: str, severity: str = "Medium") -> None:
        self.vmx(cis_id, "isolation.tools.copy.disable", "TRUE", severity, "blocks copying from the guest through the remote console",
                 "Copy and paste through the remote console moves data between the guest and an administrator's workstation outside network and data-loss controls.",
                 "Sensitive data could be copied out of the virtual machine, or untrusted content into it, without passing through any monitored channel.", missing_ok=True)

    def console_paste(self, cis_id: str, severity: str = "Medium") -> None:
        self.vmx(cis_id, "isolation.tools.paste.disable", "TRUE", severity, "blocks pasting into the guest through the remote console",
                 "Copy and paste through the remote console moves data between the guest and an administrator's workstation outside network and data-loss controls.",
                 "Untrusted content could be pasted into the guest, or sensitive data moved out, without passing through any monitored channel.", missing_ok=True)

    def console_dnd(self, cis_id: str, severity: str = "Medium") -> None:
        self.vmx(cis_id, "isolation.tools.dnd.disable", "TRUE", severity, "blocks drag and drop between the remote console and the guest",
                 "Drag and drop through the remote console transfers files between the guest and an administrator's workstation outside network controls.",
                 "Files could be moved into or out of the virtual machine without passing through malware scanning or data-loss controls.", missing_ok=True)

    def console_gui_options(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "isolation.tools.setGUIOptions.enable", "FALSE", severity, "stops the guest from enabling console copy and paste options",
                 "The GUI options channel lets the guest turn clipboard sharing back on; keeping it disabled preserves the copy and paste restrictions.",
                 "A guest could re-enable clipboard sharing and move data between the virtual machine and an administrator's workstation.", missing_ok=True)

    def device_edit(self, cis_id: str, severity: str = "Medium") -> None:
        self.vmx(cis_id, "isolation.device.edit.disable", "TRUE", severity, "stops users and processes in the guest from modifying or disconnecting virtual devices",
                 "Without this setting, VMware Tools lets non-privileged guest users disconnect or change devices such as network adapters and CD/DVD drives.",
                 "A guest user could disconnect a network adapter or other device, disrupting monitoring, backups or service availability.")

    def device_connect(self, cis_id: str, severity: str = "Medium") -> None:
        self.vmx(cis_id, "isolation.device.connectable.disable", "TRUE", severity, "stops users and processes in the guest from connecting removable virtual devices",
                 "Without this setting, VMware Tools lets non-privileged guest users connect devices, overriding decisions made by administrators.",
                 "A guest user could reconnect a disconnected network adapter or attach media, bypassing the administrator's configuration.")

    def disk_shrink(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "isolation.tools.diskShrink.disable", "TRUE", severity, "blocks guest-initiated virtual disk shrinking",
                 "Disk shrinking can be started by non-privileged users in the guest and makes the virtual disk unavailable while it runs.",
                 "Repeated shrink operations from inside the guest can make the virtual machine's disks unavailable, causing a denial of service.")

    def disk_wiper(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "isolation.tools.diskWiper.disable", "TRUE", severity, "blocks guest-initiated virtual disk wiping",
                 "Disk wiping can be started by non-privileged users in the guest and makes the virtual disk unavailable while it runs.",
                 "Repeated wipe operations from inside the guest can make the virtual machine's disks unavailable, causing a denial of service.")

    def console_connections(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "RemoteDisplay.maxConnections", "1", severity, "limits the virtual machine console to one concurrent remote connection",
                 "Multiple simultaneous console connections let a second user watch or interact with an administrator's session.",
                 "Another console user could observe information displayed during an administrator's session or interfere with it.")

    def host_info(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "tools.guestlib.enableHostInfo", "FALSE", severity, "stops VMware Tools from giving the guest performance information about the host",
                 "Host performance and configuration details are not needed by guests and help an attacker in a guest learn about the hypervisor.",
                 "Information about the host helps an attacker inside a guest plan further attacks on the hypervisor or other workloads.", missing_ok=True)

    def log_keep_old(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "log.keepOld", "10", severity, "keeps ten rotated vmware.log files",
                 "A fixed number of rotated logs keeps enough history for troubleshooting without letting log files accumulate on the datastore.",
                 "Uncontrolled virtual machine log retention can consume datastore space; too little retention loses troubleshooting history.")

    def log_rotate_size(self, cis_id: str, severity: str = "Low") -> None:
        self.vmx(cis_id, "log.rotateSize", "1024000", severity, "rotates vmware.log once it reaches about 1 MB",
                 "Size-based rotation stops a single virtual machine's log from growing without limit.",
                 "A guest that triggers excessive logging could fill the datastore, affecting every virtual machine stored on it.")

    def enable_3d(self, cis_id: str, severity: str = "Low", missing_ok: bool = False) -> None:
        self.vmx(cis_id, "mks.enable3d", "FALSE", severity, "disables hardware-accelerated 3D graphics",
                 "3D acceleration exposes additional graphics emulation code in the hypervisor to the guest.",
                 "Flaws in virtual graphics devices have allowed guest-to-host escapes; disabling unneeded 3D support removes that attack surface.", missing_ok=missing_ok)
