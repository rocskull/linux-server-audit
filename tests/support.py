"""Test doubles: a scripted command runner and synthetic host file trees.

The ESXi fixtures reproduce the output formats of ``vmware -v``,
``vim-cmd`` data object dumps and ``esxcli --formatter=csv`` (alphabetical
columns with a trailing comma), so the ESXi providers can be exercised without
a live host.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from lsa.engine import Engine, build_document, load_definition, resolve_profile
from lsa.model import AssessmentDocument, ExecutionContext, utc_now
from lsa.platform import describe_host, detect_platform, select_benchmark
from lsa.system import CommandResult, System

PROJECT = Path(__file__).resolve().parent.parent
BENCHMARKS = PROJECT / "benchmarks"
SETTINGS = json.loads((PROJECT / "config.json").read_text(encoding="utf-8"))["site_policy"]


class FakeRunner:
    """Answers commands from a table keyed by 'name arg1 arg2 ...'."""

    def __init__(self) -> None:
        self.responses: dict[str, CommandResult] = {}
        self.handlers: list[tuple[str, Callable[[list[str]], CommandResult]]] = []
        self.calls: list[str] = []
        self.fail_all: str | None = None

    @staticmethod
    def key(argv: list[str]) -> str:
        return " ".join([argv[0].rsplit("/", 1)[-1], *argv[1:]])

    def add(self, command: str, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        argv = command.split(" ")
        self.responses[command] = CommandResult(argv, returncode, stdout, stderr)

    def handle(self, prefix: str, function: Callable[[list[str]], CommandResult]) -> None:
        self.handlers.append((prefix, function))

    def run(self, argv: list[str], timeout: float | None = None, env: dict[str, str] | None = None) -> CommandResult:
        key = self.key(argv)
        self.calls.append(key)
        if self.fail_all is not None:
            return CommandResult(argv, 1, "", self.fail_all)
        if key in self.responses:
            result = self.responses[key]
            return CommandResult(argv, result.returncode, result.stdout, result.stderr)
        for prefix, function in self.handlers:
            if key.startswith(prefix):
                return function(argv)
        return CommandResult(argv, 127, "", f"{argv[0]}: not available in this test fixture")


def write(root: Path, path: str, content: str = "") -> Path:
    target = root / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:  # Path.write_text(newline=) needs 3.10
        handle.write(content)
    return target


def csv_output(rows: list[dict[str, Any]]) -> str:
    """esxcli --formatter=csv layout: sorted columns, trailing comma on every line."""
    columns = sorted({key for row in rows for key in row}) if rows else []
    lines = [",".join(columns) + ","] if columns else [""]
    for row in rows:
        cells = []
        for column in columns:
            value = str(row.get(column, ""))
            cells.append(f'"{value}"' if "," in value or " " in value else value)
        lines.append(",".join(cells) + ",")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- ESXi
def _vim_service(key: str, label: str, running: bool, policy: str) -> str:
    return (
        "         (vim.host.Service) {\n"
        f'            key = "{key}",\n'
        f'            label = "{label}",\n'
        "            required = false,\n"
        "            uninstallable = false,\n"
        f"            running = {'true' if running else 'false'},\n"
        '            ruleset = (string) [\n               "sshServer"\n            ],\n'
        f'            policy = "{policy}",\n'
        "            sourcePackage = (vim.host.Service.SourcePackage) {\n"
        '               sourcePackageName = "esx-base",\n'
        '               description = "This VIB contains all of the base functionality of vSphere ESXi."\n'
        "            }\n"
        "         },\n"
    )


def hostconfig(version: str, services: dict[str, tuple[str, bool, str]], lockdown: str, ntp: list[str]) -> str:
    servers = ",\n".join(f'            "{item}"' for item in ntp)
    service_text = "".join(_vim_service(key, *value) for key, value in services.items())
    return (
        "(vim.host.ConfigInfo) {\n"
        "   host = 'vim.HostSystem:ha-host',\n"
        "   product = (vim.AboutInfo) {\n"
        '      name = "VMware ESXi",\n'
        f'      fullName = "VMware ESXi {version} build-22380479",\n'
        f'      version = "{version}",\n'
        "   },\n"
        "   firewall = (vim.host.FirewallInfo) {\n"
        "      ruleset = (vim.host.Ruleset) [\n"
        "         (vim.host.Ruleset) {\n"
        '            key = "sshServer",\n'
        '            label = "SSH Server",\n'
        "            required = true,\n"
        "            rule = (vim.host.Ruleset.Rule) [\n"
        "               (vim.host.Ruleset.Rule) {\n"
        "                  port = 22,\n"
        '                  direction = "inbound",\n'
        "               }\n"
        "            ],\n"
        '            service = "",\n'
        "            enabled = true,\n"
        "         }\n"
        "      ]\n"
        "   },\n"
        "   dateTimeInfo = (vim.host.DateTimeInfo) {\n"
        "      timeZone = (vim.host.DateTimeSystem.TimeZone) {\n"
        '         key = "UTC",\n'
        '         name = "UTC",\n'
        "         gmtOffset = 0\n"
        "      },\n"
        '      systemClockProtocol = "ntp",\n'
        "      ntpConfig = (vim.host.NtpConfig) {\n"
        f"         server = (string) [\n{servers}\n         ],\n"
        '         configFile = (string) [\n            "restrict default nomodify notrap nopeer noquery"\n         ]\n'
        "      },\n"
        "   },\n"
        "   service = (vim.host.ServiceInfo) {\n"
        "      service = (vim.host.Service) [\n"
        f"{service_text}"
        "      ]\n"
        "   },\n"
        f'   lockdownMode = "{lockdown}",\n'
        "}\n"
    )


def advopt(key: str, value: Any) -> str:
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int):
        rendered = str(value)
    else:
        rendered = f'"{value}"'
    return (
        "(vim.option.OptionValue) [\n"
        "   (vim.option.OptionValue) {\n"
        f'      key = "{key}",\n'
        f"      value = {rendered}\n"
        "   }\n"
        "]\n"
    )


INSECURE_VM = {
    "config.version": "8",
    "virtualHW.version": "19",
    "displayName": "web01",
    "floppy0.present": "TRUE",
    "sata0.present": "TRUE",
    "sata0:0.present": "TRUE",
    "sata0:0.deviceType": "cdrom-image",
    "scsi0:0.present": "TRUE",
    "scsi0:0.fileName": "web01.vmdk",
    "scsi0:1.present": "TRUE",
    "scsi0:1.mode": "independent-nonpersistent",
    "usb_xhci.present": "TRUE",
    "pciPassthru0.present": "TRUE",
    "isolation.tools.copy.disable": "FALSE",
}

HARDENED_VM = {
    "config.version": "8",
    "virtualHW.version": "19",
    "displayName": "db server 02",
    "floppy0.present": "FALSE",
    "scsi0:0.present": "TRUE",
    "scsi0:0.fileName": "db server 02.vmdk",
    "scsi0:0.mode": "persistent",
    "sata0:0.present": "TRUE",
    "sata0:0.deviceType": "disk",
    "RemoteDisplay.maxConnections": "1",
    "isolation.device.edit.disable": "TRUE",
    "isolation.device.connectable.disable": "TRUE",
    "isolation.tools.diskShrink.disable": "TRUE",
    "isolation.tools.diskWiper.disable": "TRUE",
    "mks.enable3d": "FALSE",
    "log.keepOld": "10",
    "log.rotateSize": "1024000",
    "tools.guestlib.enableHostInfo": "FALSE",
    "isolation.tools.copy.disable": "TRUE",
    "isolation.tools.paste.disable": "TRUE",
    "isolation.tools.dnd.disable": "TRUE",
    "isolation.tools.setGUIOptions.enable": "FALSE",
    "isolation.tools.ghi.autologon.disable": "TRUE",
    "isolation.bios.bbs.disable": "TRUE",
    "isolation.tools.ghi.protocolhandler.info.disable": "TRUE",
    "isolation.tools.unity.taskbar.disable": "TRUE",
    "isolation.tools.unityActive.disable": "TRUE",
    "isolation.tools.unity.windowContents.disable": "TRUE",
    "isolation.tools.unity.push.update.disable": "TRUE",
    "isolation.tools.vmxDnDVersionGet.disable": "TRUE",
    "isolation.tools.guestDnDVersionSet.disable": "TRUE",
    "isolation.ghi.host.shellAction.disable": "TRUE",
    "isolation.tools.dispTopoRequest.disable": "TRUE",
    "isolation.tools.trashFolderState.disable": "TRUE",
    "isolation.tools.ghi.trayicon.disable": "TRUE",
    "isolation.tools.unity.disable": "TRUE",
    "isolation.tools.unityInterlockOperation.disable": "TRUE",
    "isolation.tools.getCreds.disable": "TRUE",
    "isolation.tools.hgfsServerSet.disable": "TRUE",
    "isolation.tools.ghi.launchmenu.change": "TRUE",
    "isolation.tools.memSchedFakeSampleStats.disable": "TRUE",
}


def _vmx(values: dict[str, str]) -> str:
    return '.encoding = "UTF-8"\n' + "".join(f'{key} = "{value}"\n' for key, value in values.items())


def esxi_host(root: Path, *, version: str = "8.0.2", hardened: bool = False, vms: bool = True, iscsi: bool = True, vswitch: bool = True) -> FakeRunner:
    """Build a synthetic ESXi host under ``root`` and return its command runner."""
    for path in ("etc/vmware/esx.conf", "bin/vmware", "bin/esxcli", "bin/vim-cmd"):
        write(root, path)
    runner = FakeRunner()
    runner.add("vmware -v", f"VMware ESXi {version} build-22380479\n")
    services = {
        "DCUI": ("Direct Console UI", True, "on"),
        "TSM": ("ESXi Shell", False, "off"),
        "TSM-SSH": ("SSH", True, "off" if hardened else "on"),
        "ntpd": ("NTP Daemon", hardened, "on" if hardened else "off"),
        "slpd": ("slpd", False, "off"),
    }
    lockdown = "lockdownStrict" if hardened else "lockdownDisabled"
    runner.add("vim-cmd hostsvc/hostconfig", hostconfig(version, services, lockdown, ["10.0.0.10", "10.0.0.11"] if hardened else []))
    options = {
        "Mem.ShareForceSalting": 2,
        "Config.HostAgent.plugins.solo.enableMob": False,
        "UserVars.DcuiTimeOut": 600,
        "UserVars.ESXiShellInteractiveTimeOut": 300 if hardened else 0,
        "UserVars.ESXiShellTimeOut": 3600 if hardened else 0,
        "Security.AccountLockFailures": 5,
        "Security.AccountUnlockTime": 900,
        "Syslog.global.logHost": "ssl://siem.example.net:1514" if hardened else "",
    }
    for key, value in options.items():
        runner.add(f"vim-cmd hostsvc/advopt/view {key}", advopt(key, value))
    runner.add("esxcli software acceptance get", "PartnerSupported\n")
    vibs = [
        {"AcceptanceLevel": "VMwareCertified", "CreationDate": "2023-09-04", "ID": "VMware_bootbank_esx-base_8.0.2", "InstallDate": "2023-10-10", "Name": "esx-base", "Platforms": "host", "Status": "", "Vendor": "VMware", "Version": "8.0.2-0.0.22380479"},
        {"AcceptanceLevel": "PartnerSupported", "CreationDate": "2023-05-01", "ID": "DEL_bootbank_dellemc-osname-idrac", "InstallDate": "2023-10-10", "Name": "dellemc-osname-idrac", "Platforms": "host", "Status": "", "Vendor": "DEL", "Version": "7.0.0.29"},
    ]
    if not hardened:
        vibs.append({"AcceptanceLevel": "CommunitySupported", "CreationDate": "2022-01-01", "ID": "community_usbnic", "InstallDate": "2023-10-10", "Name": "vmkusb-nic-fling", "Platforms": "host", "Status": "", "Vendor": "VMW", "Version": "1.12-1"})
    runner.add("esxcli --formatter=csv software vib list", csv_output(vibs))
    switches = [{"BeaconEnabled": "false", "Class": "cswitch", "MTU": "1500", "Name": "vSwitch0", "NumPorts": "2560", "Portgroups": "VM Network, Management Network", "Uplinks": "vmnic0", "UsedPorts": "4"}] if vswitch else []
    groups = [
        {"ActiveClients": "1", "Name": "Management Network", "VLANID": "0", "VirtualSwitch": "vSwitch0"},
        {"ActiveClients": "2", "Name": "VM Network", "VLANID": "20", "VirtualSwitch": "vSwitch0"},
    ]
    if not hardened:
        groups += [
            {"ActiveClients": "1", "Name": "Trunk", "VLANID": "4095", "VirtualSwitch": "vSwitch0"},
            {"ActiveClients": "0", "Name": "Legacy", "VLANID": "1", "VirtualSwitch": "vSwitch0"},
        ]
    if not vswitch:
        groups = []
    runner.add("esxcli --formatter=csv network vswitch standard list", csv_output(switches))
    runner.add("esxcli --formatter=csv network vswitch standard portgroup list", csv_output(groups))
    insecure = not hardened
    runner.add(
        "esxcli --formatter=csv network vswitch standard policy security get -v vSwitch0",
        csv_output([{"AllowForgedTransmits": str(insecure).lower(), "AllowMACAddressChange": str(insecure).lower(), "AllowPromiscuous": "false"}]),
    )
    for group in groups:
        runner.add(
            f"esxcli --formatter=csv network vswitch standard portgroup policy security get -p {group['Name']}",
            csv_output([{
                "AllowForgedTransmits": str(insecure).lower(),
                "AllowMACAddressChange": "false",
                "AllowPromiscuous": "false",
                "OverrideVswitchAllowForgedTransmits": "false",
                "OverrideVswitchAllowMACAddressChange": "true",
                "OverrideVswitchAllowPromiscuous": "false",
            }]),
        )
    adapters = [{"Adapter": "vmhba65", "Description": "iSCSI Software Adapter", "Driver": "iscsi_vmk", "State": "online", "UID": "iqn.1998-01.com.vmware:esx01"}] if iscsi else []
    runner.add("esxcli --formatter=csv iscsi adapter list", csv_output(adapters))
    level = "required" if hardened else "prohibited"
    for direction in ("uni", "mutual"):
        runner.add(
            f"esxcli --formatter=csv iscsi adapter auth chap get -A vmhba65 -d {direction}",
            csv_output([{"Direction": direction, "Level": level, "Name": "esx01" if hardened else "", "ParameterSource": "local"}]),
        )
    coredump = {"Enabled": "true", "HostVNic": "vmk0", "IsUsingIPv6": "false", "NetworkServerIP": "10.0.0.30", "NetworkServerPort": "6500"} if hardened else {"Enabled": "false", "HostVNic": "", "IsUsingIPv6": "false", "NetworkServerIP": "", "NetworkServerPort": "0"}
    runner.add("esxcli --formatter=csv system coredump network get", csv_output([coredump]))
    accounts = [{"Description": "Administrator", "UserID": "root"}, {"Description": "DCUI User", "UserID": "dcui"}, {"Description": "VMware VirtualCenter administration account", "UserID": "vpxuser"}]
    permissions = [
        {"IsGroup": "false", "Principal": "root", "Role": "Admin", "RoleDescription": "Full access rights"},
        {"IsGroup": "false", "Principal": "dcui", "Role": "Admin", "RoleDescription": "Full access rights"},
        {"IsGroup": "false", "Principal": "vpxuser", "Role": "Admin", "RoleDescription": "Full access rights"},
    ]
    if hardened:
        accounts.append({"Description": "Named administrator", "UserID": "jsmith-adm"})
        permissions.append({"IsGroup": "false", "Principal": "jsmith-adm", "Role": "Admin", "RoleDescription": "Full access rights"})
    runner.add("esxcli --formatter=csv system account list", csv_output(accounts))
    runner.add("esxcli --formatter=csv system permission list", csv_output(permissions))
    listing = "Vmid        Name                           File                               Guest OS          Version   Annotation\n"
    if vms:
        machines = [("1", "web01", "web01/web01.vmx", INSECURE_VM if not hardened else HARDENED_VM), ("2", "db server 02", "db server 02/db server 02.vmx", HARDENED_VM), ("3", "vCLS-a1b2", "vCLS-a1b2/vCLS-a1b2.vmx", {"floppy0.present": "TRUE"})]
        for vmid, name, path, values in machines:
            listing += f"{vmid:<11} {name:<30} [datastore1] {path:<34} ubuntu64Guest     vmx-19    \n"
            write(root, f"vmfs/volumes/datastore1/{path}", _vmx(values))
        listing += "Multi-line annotation continues here\n"
    runner.add("vim-cmd vmsvc/getallvms", listing)
    return runner


def esxi_system(root: Path, *, is_root: bool = True, **options: Any) -> System:
    runner = esxi_host(root, **options)
    return System(str(root), runner, dict(SETTINGS), is_root=is_root)


# ------------------------------------------------------------------ Linux
def linux_host(root: Path, os_release: str, packages: dict[str, str] | None = None) -> FakeRunner:
    write(root, "etc/os-release", os_release)
    stanzas = []
    for name, version in (packages or {}).items():
        stanzas.append(f"Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\n")
    write(root, "var/lib/dpkg/status", "\n".join(stanzas))
    return FakeRunner()


DEBIAN_13 = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\nVERSION="13 (trixie)"\nID=debian\n'
DEBIAN_12 = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian\n'
UBUNTU_24 = 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n'
ROCKY_9 = 'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\nNAME="Rocky Linux"\nVERSION_ID="9.4"\nID="rocky"\nID_LIKE="rhel centos fedora"\n'


# ------------------------------------------------------------- execution
def assess(system: System, profile: str = "auto", include_manual: bool = False) -> tuple[AssessmentDocument, dict[str, Any], list[str]]:
    """Detect, select, evaluate and build the document the way the CLI does."""
    info = detect_platform(system)
    entry, warnings = select_benchmark(system, BENCHMARKS, info)
    definition = load_definition(entry["path"])
    selected, allowed = resolve_profile(profile, info.platform_type, definition["benchmark"]["profiles"])
    engine = Engine(system, definition, profile=selected, allowed_profiles=allowed, include_manual=include_manual, platform_tags=info.tags)
    started = utc_now()
    results = engine.run()
    document = build_document(
        engine,
        results,
        host=describe_host(system, info, selected),
        execution=ExecutionContext(method="local", identity="root", uid=0, effective_uid=0, is_root=system.is_root, sudo_user=None, python_version="test"),
        client_name="Test Client",
        started_at=started,
        definition_file=entry["file_name"],
        definition_sha256=entry["sha256"],
    )
    if warnings:
        next(iter(document.benchmark_results.values()))["warnings"] = warnings
    return document, definition, warnings


def statuses(document: AssessmentDocument, definition: dict[str, Any]) -> dict[str, str]:
    """CIS recommendation number -> status."""
    by_id = {control["id"]: control["cis_id"] for control in definition["controls"]}
    return {by_id[item.check_id]: item.status for item in document.checks if item.check_id in by_id}


class TempRoot:
    """Context manager giving a fresh temporary directory as a Path."""

    def __enter__(self) -> Path:
        self._directory = tempfile.TemporaryDirectory(prefix="lsa-test-")
        return Path(self._directory.name)

    def __exit__(self, *exc_info: Any) -> None:
        self._directory.cleanup()
