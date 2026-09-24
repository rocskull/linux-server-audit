"""VMware ESXi host and virtual machine checks.

Evidence is read locally from the ESXi Shell with read-only commands:
``esxcli --formatter=csv`` get/list namespaces, ``vim-cmd hostsvc/hostconfig``
and ``hostsvc/advopt/view`` for host configuration and advanced options, and
``vim-cmd vmsvc/getallvms`` plus each registered VM's .vmx file for virtual
machine settings. Nothing is changed on the host.
"""

from __future__ import annotations

import csv
import fnmatch
import io
import re
from dataclasses import dataclass

from lsa.checks.common import as_bool, as_int, cap, condition, describe_rule, failed, join_limited, passed, provider, rule_ok
from lsa.system import EvidenceUnavailable, System

ACCEPTABLE_LEVELS = ("VMwareCertified", "VMwareAccepted", "PartnerSupported")
# Service key -> init script, used only when vim-cmd cannot report services.
INIT_SCRIPTS = {"TSM-SSH": "SSH", "TSM": "ESXShell", "ntpd": "ntpd", "slpd": "slpd", "snmpd": "snmpd", "sfcbd-watchdog": "sfcbd-watchdog"}
LOCKDOWN_LABELS = {"lockdownDisabled": "disabled", "lockdownNormal": "normal", "lockdownStrict": "strict"}


# ------------------------------------------------------------------ commands
def _command(system: System, name: str) -> str:
    path = system.which(name)
    if path is None:
        raise EvidenceUnavailable(f"The ESXi '{name}' command was not found; run the assessment from the ESXi Shell")
    return path


def _failure(system: System, what: str, result_text: str) -> EvidenceUnavailable:
    if not system.is_root:
        return EvidenceUnavailable(f"{what} requires root ({result_text})", "root")
    return EvidenceUnavailable(f"{what} failed: {result_text}")


def column(name: str) -> str:
    """Normalised column name: 'VLAN ID', 'VLANID' and 'VlanId' all become 'vlanid'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def parse_csv(text: str) -> list[dict[str, str]]:
    """Rows of esxcli CSV output keyed by normalised column names.

    esxcli ends every line with a comma; the resulting empty column is dropped.
    """
    rows = csv.DictReader(io.StringIO(text.strip()))
    return [{column(key): (value or "").strip() for key, value in row.items() if isinstance(key, str) and column(key)} for row in rows]


def esxcli(system: System, *args: str, formatter: str | None = "csv", collector: str = "esxi_host") -> str:
    def build() -> str:
        argv = [_command(system, "esxcli")]
        if formatter:
            argv.append(f"--formatter={formatter}")
        argv.extend(args)
        result = system.run(argv, collector=collector)
        if not result.ok:
            raise _failure(system, f"esxcli {' '.join(args)}", result.describe())
        return result.stdout

    return system.cached("esxcli:" + "|".join((formatter or "plain",) + args), collector, build)


def esxcli_rows(system: System, *args: str, collector: str = "esxi_host") -> list[dict[str, str]]:
    return parse_csv(esxcli(system, *args, collector=collector))


def vimcmd(system: System, *args: str, collector: str = "esxi_host") -> str:
    def build() -> str:
        result = system.run([_command(system, "vim-cmd"), *args], collector=collector)
        if not result.ok:
            raise _failure(system, f"vim-cmd {' '.join(args)}", result.describe())
        return result.stdout

    return system.cached("vim-cmd:" + "|".join(args), collector, build)


def host_config(system: System) -> str:
    return vimcmd(system, "hostsvc/hostconfig")


def _vim_value(raw: str) -> str | None:
    """Value of a vim-cmd data object field: quotes, type tags and <unset> removed."""
    value = raw.strip().rstrip(",").strip()
    value = re.sub(r"^\((?:long|int|short|string|boolean|byte)\)\s*", "", value)
    if value in ("<unset>", ""):
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def advanced_option(system: System, key: str) -> str | None:
    """Current value of an advanced setting such as UserVars.DcuiTimeOut."""

    def build() -> str | None:
        errors = []
        try:
            output = vimcmd(system, "hostsvc/advopt/view", key, collector="esxi_settings")
            match = re.search(r"(?m)^\s*value = (.*)$", output)
            if match:
                return _vim_value(match.group(1))
            errors.append("vim-cmd returned no value")
        except EvidenceUnavailable as exc:
            errors.append(exc.reason)
        try:
            rows = esxcli_rows(system, "system", "settings", "advanced", "list", "-o", "/" + key.replace(".", "/"), collector="esxi_settings")
        except EvidenceUnavailable as exc:
            errors.append(exc.reason)
            rows = []
        if rows:
            row = rows[0]
            if row.get("type", "").lower() == "string":
                return row.get("stringvalue", "")
            return row.get("intvalue") or row.get("stringvalue", "")
        raise EvidenceUnavailable(f"The advanced setting {key} could not be read ({'; '.join(errors) or 'no value returned'})")

    value = system.cached(f"advopt:{key}", "esxi_settings", build)
    system.record("esxi_settings", key, value)
    return value


@dataclass
class Service:
    key: str
    label: str
    running: bool
    policy: str


SERVICE_BLOCK = re.compile(
    r'key = "(?P<key>[^"]+)",\s*label = "(?P<label>[^"]*)",'
    r'(?:(?!key = ").)*?running = (?P<running>true|false),'
    r'(?:(?!key = ").)*?policy = "(?P<policy>[^"]*)"',
    re.DOTALL,
)


def services(system: System) -> dict[str, Service]:
    """Host services with running state and startup policy (on, off or automatic)."""

    def build() -> dict[str, Service]:
        found: dict[str, Service] = {}
        try:
            text = host_config(system)
        except EvidenceUnavailable:
            text = ""
        for match in SERVICE_BLOCK.finditer(text):
            found[match.group("key")] = Service(match.group("key"), match.group("label"), match.group("running") == "true", match.group("policy"))
        if not found:
            chkconfig = system.which("chkconfig")
            for key, script in INIT_SCRIPTS.items():
                if not system.is_file(f"/etc/init.d/{script}"):
                    continue
                status = system.run([f"/etc/init.d/{script}", "status"], collector="esxi_host")
                running = "is running" in status.stdout and "not running" not in status.stdout
                policy = "unknown"
                if chkconfig:
                    listing = system.run([chkconfig, "--list", script], collector="esxi_host")
                    match = re.search(rf"(?m)^{re.escape(script)}\s+(on|off)\b", listing.stdout)
                    if match:
                        policy = match.group(1)
                found[key] = Service(key, script, running, policy)
        if not found:
            raise EvidenceUnavailable("ESXi service states could not be read from 'vim-cmd hostsvc/hostconfig' or the init scripts")
        system.record("esxi_host", "services", {k: {"label": s.label, "running": s.running, "policy": s.policy} for k, s in sorted(found.items())})
        return found

    return system.cached("esxi-services", "esxi_host", build)


def lockdown_mode(system: System) -> str:
    def build() -> str:
        try:
            match = re.search(r'lockdownMode = "(\w+)"', host_config(system))
            if match:
                return match.group(1)
        except EvidenceUnavailable:
            pass
        output = vimcmd(system, "-U", "dcui", "vimsvc/auth/lockdown_is_enabled")
        return "lockdownNormal" if output.strip().lower() == "true" else "lockdownDisabled"

    mode = system.cached("esxi-lockdown", "esxi_host", build)
    system.record("esxi_host", "lockdown_mode", mode)
    return mode


# ----------------------------------------------------------------- VM helpers
@dataclass
class VirtualMachine:
    vmid: str
    name: str
    vmx: str


VM_LINE = re.compile(r"^\s*(\d+)\s+(.*?)\s+\[([^\]]+)\]\s+(\S.*?\.vmx)(?:\s|$)")


def virtual_machines(system: System) -> list[VirtualMachine]:
    """Registered virtual machines; templates (.vmtx) are not listed."""

    def build() -> list[VirtualMachine]:
        output = vimcmd(system, "vmsvc/getallvms", collector="esxi_vms")
        vms = []
        for line in output.splitlines()[1:]:
            match = VM_LINE.match(line)
            if match:
                vmid, name, datastore, path = match.groups()
                vms.append(VirtualMachine(vmid, name.strip(), f"/vmfs/volumes/{datastore}/{path.strip()}"))
        system.count("esxi_vms", len(vms))
        system.record("esxi_vms", "registered", [{"vmid": vm.vmid, "name": vm.name, "vmx": vm.vmx} for vm in vms])
        return vms

    return system.cached("esxi-vms", "esxi_vms", build)


def assessed_vms(system: System) -> tuple[list[VirtualMachine], list[str]]:
    """(VMs in scope, excluded VM names) after the esxi_excluded_vms patterns."""
    patterns = system.settings.get("esxi_excluded_vms", [])
    included, excluded = [], []
    for vm in virtual_machines(system):
        if any(fnmatch.fnmatchcase(vm.name.lower(), str(pattern).lower()) for pattern in patterns):
            excluded.append(vm.name)
        else:
            included.append(vm)
    return included, excluded


def vmx_settings(system: System, path: str) -> dict[str, str]:
    """Settings of a .vmx file with lower-cased keys (VMX keys are case-insensitive)."""

    def build() -> dict[str, str]:
        text = system.read_text(path, missing_ok=False) or ""
        values = {}
        for line in text.splitlines():
            match = re.match(r'^\s*([^=#\s][^=]*?)\s*=\s*"?(.*?)"?\s*$', line)
            if match:
                values[match.group(1).strip().lower()] = match.group(2)
        return values

    return system.cached(f"vmx:{path}", "esxi_vms", build)


@dataclass
class VmScan:
    vms: list[tuple[VirtualMachine, dict[str, str]]]
    unreadable: list[str]
    excluded: list[str]

    def evidence(self) -> dict[str, object]:
        return {"vms_checked": [vm.name for vm, _ in self.vms], "unreadable_vms": self.unreadable, "excluded_vms": self.excluded}


def _vm_scan(system: System) -> VmScan:
    vms, excluded = assessed_vms(system)
    readable, unreadable = [], []
    for vm in vms:
        try:
            readable.append((vm, vmx_settings(system, vm.vmx)))
        except EvidenceUnavailable as exc:
            unreadable.append(f"{vm.name} ({exc.reason})")
    if unreadable and not readable:
        raise EvidenceUnavailable(f"No VM configuration file could be read: {join_limited(unreadable, 3)}")
    return VmScan(readable, unreadable, excluded)


def _vm_verdict(scan: VmScan, offending: dict[str, str], success: str, problem: str, **evidence: object) -> object:
    notes = ""
    if scan.unreadable:
        notes += f" {len(scan.unreadable)} VM configuration file(s) could not be read: {join_limited(scan.unreadable, 3)}."
    if scan.excluded:
        notes += f" Excluded by configuration: {join_limited(scan.excluded, 5)}."
    evidence = {**evidence, **scan.evidence()}
    total = len(scan.vms)
    if offending:
        details = [f"{name} ({detail})" if detail else name for name, detail in offending.items()]
        return failed(f"{len(offending)} of {total} VM(s) {problem}: {join_limited(details, 6)}.{notes}", cap(list(offending)), **evidence)
    return passed(f"{success} ({total} VM(s) checked).{notes}", **evidence)


def _vmx_matches(value: str, expected: str) -> bool:
    if expected.lower() in ("true", "false"):
        return as_bool(value) is (expected.lower() == "true")
    number, target = as_int(value), as_int(expected)
    if number is not None and target is not None:
        return number == target
    return value.strip().lower() == expected.strip().lower()


# ------------------------------------------------------------------ conditions
@condition("vms_present")
def vms_present(system: System, spec: dict) -> tuple[bool, str]:
    vms, excluded = assessed_vms(system)
    if vms:
        return True, ""
    if excluded:
        return False, f"Every registered virtual machine is excluded by configuration ({join_limited(excluded, 5)})"
    return False, "No virtual machines are registered on this host, so virtual machine settings cannot apply"


@condition("iscsi_present")
def iscsi_present(system: System, spec: dict) -> tuple[bool, str]:
    if esxcli_rows(system, "iscsi", "adapter", "list", collector="esxi_storage"):
        return True, ""
    return False, "No iSCSI adapter is configured on this host"


@condition("standard_vswitch_present")
def standard_vswitch_present(system: System, spec: dict) -> tuple[bool, str]:
    if _vswitches(system):
        return True, ""
    return False, "This host has no standard vSwitch; distributed switch policies are managed and assessed in vCenter Server"


# ---------------------------------------------------------------- host checks
@provider("esxi_advanced")
def esxi_advanced(system: System, check: dict) -> object:
    problems, observed = [], {}
    for setting in check["settings"]:
        value = advanced_option(system, setting["key"])
        observed[setting["key"]] = value
        if not rule_ok(value, setting["rule"]):
            expected = setting.get("expected") or describe_rule(setting["rule"])
            shown = value if value not in (None, "") else "not set"
            problems.append(f"{setting['key']} is {shown} (expected {expected})")
    if problems:
        return failed("; ".join(problems) + ".", list(observed), settings=observed)
    return passed("; ".join(f"{key} = {value}" for key, value in observed.items()) + ".", settings=observed)


@provider("esxi_mob_disabled")
def esxi_mob_disabled(system: System, check: dict) -> object:
    try:
        value = advanced_option(system, "Config.HostAgent.plugins.solo.enableMob")
    except EvidenceUnavailable:
        value = None
    if value is not None:
        if as_bool(value) is False:
            return passed("Config.HostAgent.plugins.solo.enableMob is false; the Managed Object Browser is disabled.", enableMob=value)
        return failed(f"Config.HostAgent.plugins.solo.enableMob is {value}; the Managed Object Browser is enabled.", ["Managed Object Browser"], enableMob=value)
    listing = vimcmd(system, "proxysvc/service_list")
    if re.search(r'serverNamespace = "/mob"', listing):
        return failed("The /mob endpoint is registered with the host reverse proxy, so the Managed Object Browser is reachable.", ["Managed Object Browser"])
    return passed("The enableMob option is absent and /mob is not registered with the host reverse proxy.")


@provider("esxi_acceptance")
def esxi_acceptance(system: System, check: dict) -> object:
    level = esxcli(system, "software", "acceptance", "get", formatter=None, collector="esxi_software").strip()
    vibs = esxcli_rows(system, "software", "vib", "list", collector="esxi_software")
    weak = {row.get("name", "?"): row.get("acceptancelevel", "") for row in vibs if row.get("acceptancelevel") not in ACCEPTABLE_LEVELS}
    system.count("esxi_software", len(vibs))
    system.record("esxi_software", "acceptance_level", level)
    system.record("esxi_software", "vibs", {row.get("name", "?"): {"version": row.get("version"), "vendor": row.get("vendor"), "acceptance": row.get("acceptancelevel")} for row in vibs})
    evidence = {"host_acceptance_level": level, "vib_count": len(vibs), "vibs_below_partner_supported": weak}
    problems = []
    if level not in ACCEPTABLE_LEVELS:
        problems.append(f"the host acceptance level is {level or 'unknown'}")
    if weak:
        problems.append(f"{len(weak)} installed VIB(s) are below PartnerSupported: {join_limited([f'{k} ({v})' for k, v in weak.items()], 5)}")
    if problems:
        return failed("Software below PartnerSupported can be or is installed: " + "; ".join(problems) + ".", list(weak) or ["host acceptance level"], **evidence)
    return passed(f"The host acceptance level is {level} and all {len(vibs)} installed VIBs are PartnerSupported or higher.", **evidence)


def _ntp_servers(system: System) -> list[str]:
    try:
        block = re.search(r"ntpConfig = \(vim\.host\.NtpConfig\) \{(.*?)\}", host_config(system), re.DOTALL)
        if block:
            server_list = re.search(r"server = \(string\) \[(.*?)\]", block.group(1), re.DOTALL)
            if server_list:
                return re.findall(r'"([^"]+)"', server_list.group(1))
    except EvidenceUnavailable:
        pass
    servers = []
    for line in system.lines("/etc/ntp.conf") or []:
        match = re.match(r"^\s*server\s+(\S+)", line)
        if match and not match.group(1).startswith("127.127."):
            servers.append(match.group(1))
    return servers


@provider("esxi_ntp")
def esxi_ntp(system: System, check: dict) -> object:
    servers = _ntp_servers(system)
    service = services(system).get("ntpd")
    approved = [str(item).lower() for item in system.settings.get("approved_time_servers", [])]
    evidence = {"ntp_servers": servers, "ntpd_running": service.running if service else None, "ntpd_policy": service.policy if service else None}
    problems = []
    if not servers:
        problems.append("no NTP servers are configured")
    if service is None:
        problems.append("the NTP daemon (ntpd) service was not found")
    else:
        if not service.running:
            problems.append("the NTP service is not running")
        if service.policy != "on":
            problems.append(f"the NTP service startup policy is '{service.policy}' (expected 'on', start and stop with host)")
    if approved:
        unapproved = [server for server in servers if server.lower() not in approved]
        if unapproved:
            problems.append(f"servers not on the approved list: {', '.join(unapproved)}")
    if problems:
        return failed("NTP time synchronization is not configured as required: " + "; ".join(problems) + ".", ["ntpd"], **evidence)
    return passed(f"NTP is running, starts with the host and uses {', '.join(servers)}.", **evidence)


@provider("esxi_service_disabled")
def esxi_service_disabled(system: System, check: dict) -> object:
    key = check["service"]
    service = services(system).get(key)
    if service is None:
        return passed(f"The {check['label']} service ({key}) is not present on this host.", service=key)
    evidence = {"service": key, "label": service.label, "policy": service.policy, "running": service.running}
    running_note = ""
    if service.running:
        running_note = " It is currently running"
        running_note += " (expected if this assessment was started through it); stop it when the assessment is complete." if check.get("audit_channel") else "."
    if service.policy != "off":
        return failed(f"The {service.label} startup policy is '{service.policy}'; it should be 'Start and stop manually' (off).{running_note}", [service.label], **evidence)
    return passed(f"The {service.label} startup policy is 'Start and stop manually'.{running_note}", **evidence)


@provider("esxi_lockdown")
def esxi_lockdown(system: System, check: dict) -> object:
    mode = lockdown_mode(system)
    allowed = check["allowed"]
    evidence = {"lockdown_mode": mode}
    if mode in allowed:
        return passed(f"Lockdown mode is {LOCKDOWN_LABELS.get(mode, mode)}.", **evidence)
    wanted = " or ".join(LOCKDOWN_LABELS.get(item, item) for item in allowed)
    return failed(f"Lockdown mode is {LOCKDOWN_LABELS.get(mode, mode)}; it should be {wanted}.", ["lockdown mode"], **evidence)


@provider("esxi_coredump_network")
def esxi_coredump_network(system: System, check: dict) -> object:
    rows = esxcli_rows(system, "system", "coredump", "network", "get")
    row = rows[0] if rows else {}
    enabled = as_bool(row.get("enabled"))
    server = row.get("networkserverip", "")
    evidence = {"network_coredump": row}
    if enabled and server:
        return passed(f"Core dumps are sent to the network dump collector {server}:{row.get('networkserverport', '')} through {row.get('hostvnic', '')}.", **evidence)
    if server:
        return failed(f"A network dump collector ({server}) is configured but not enabled.", ["coredump"], **evidence)
    return failed("No network dump collector is configured for ESXi core dumps.", ["coredump"], **evidence)


@provider("esxi_nonroot_admin")
def esxi_nonroot_admin(system: System, check: dict) -> object:
    accounts = [row.get("userid", "") for row in esxcli_rows(system, "system", "account", "list", collector="esxi_accounts")]
    permissions = esxcli_rows(system, "system", "permission", "list", collector="esxi_accounts")
    system.record("esxi_accounts", "accounts", accounts)
    system.record("esxi_accounts", "permissions", permissions)
    admins = [
        row.get("principal", "")
        for row in permissions
        if row.get("role", "").lower() == "admin"
        and as_bool(row.get("isgroup")) is not True
        and row.get("principal", "").lower() not in ("root", "dcui", "vpxuser")
    ]
    local_admins = [name for name in admins if name in accounts]
    evidence = {"local_accounts": accounts, "admin_principals": admins}
    note = " Shell access for the account is not verified by this check."
    if local_admins:
        return passed(f"Named local administrator account(s) exist: {', '.join(local_admins)}.{note}", **evidence)
    if admins:
        return passed(f"Named administrator principal(s) exist: {', '.join(admins)} (directory accounts); keep a local break-glass account as well.{note}", **evidence)
    return failed("No named account other than root holds the Administrator role; administration relies on the shared root account.", ["root"], **evidence)


def _vswitches(system: System) -> list[dict[str, str]]:
    return esxcli_rows(system, "network", "vswitch", "standard", "list", collector="esxi_network")


def _portgroups(system: System) -> list[dict[str, str]]:
    return esxcli_rows(system, "network", "vswitch", "standard", "portgroup", "list", collector="esxi_network")


def _policy_value(row: dict[str, str], word: str) -> str | None:
    """The effective 'Allow ...' value whose column mentions ``word`` (not the override flags)."""
    for key, value in row.items():
        if key.startswith("allow") and word in key:
            return value
    return None


@provider("esxi_vswitch_security")
def esxi_vswitch_security(system: System, check: dict) -> object:
    word, label = check["policy"], check["label"]
    offending, observed = [], {}
    targets = [("vSwitch", switch.get("name", "")) for switch in _vswitches(system)]
    targets += [("port group", group.get("name", "")) for group in _portgroups(system)]
    for kind, name in targets:
        if kind == "vSwitch":
            command = ("network", "vswitch", "standard", "policy", "security", "get", "-v", name)
        else:
            command = ("network", "vswitch", "standard", "portgroup", "policy", "security", "get", "-p", name)
        rows = esxcli_rows(system, *command, collector="esxi_network")
        value = _policy_value(rows[0], word) if rows else None
        observed[f"{kind} {name}"] = value
        if value is None:
            raise EvidenceUnavailable(f"The {label.lower()} policy of {kind} {name} could not be read from esxcli")
        if as_bool(value) is not False:
            offending.append(f"{kind} {name}")
    evidence = {"policies": observed, "policy": word}
    if offending:
        return failed(f"{label} is not set to Reject on: {join_limited(offending, 6)}.", cap(offending), **evidence)
    return passed(f"{label} is set to Reject on every standard vSwitch and port group ({len(observed)} checked).", **evidence)


@provider("esxi_portgroup_vlan")
def esxi_portgroup_vlan(system: System, check: dict) -> object:
    forbidden = {str(item) for item in check.get("forbid", [])}
    if check.get("native_vlan"):
        forbidden.add(str(system.settings.get("esxi_native_vlan", 1)))
    approved = {str(item).lower() for item in system.settings.get("esxi_vgt_portgroups", [])}
    noted_vlans = {str(item) for item in check.get("note_vlans", [])}
    groups = _portgroups(system)
    offending: dict[str, str] = {}
    noted = []
    for group in groups:
        vlan, name = group.get("vlanid", ""), group.get("name", "")
        if vlan in forbidden and not (vlan == "4095" and name.lower() in approved):
            offending[name] = f"VLAN {vlan} on {group.get('virtualswitch', '')}"
        elif vlan in noted_vlans:
            noted.append(name)
    evidence = {
        "port_groups": [{"name": g.get("name"), "vlan": g.get("vlanid"), "vswitch": g.get("virtualswitch")} for g in groups],
        "forbidden_vlans": sorted(forbidden),
        "approved_vgt_port_groups": sorted(approved),
    }
    note = ""
    if noted:
        note = (
            f" Port groups on VLAN {'/'.join(sorted(noted_vlans))} (untagged by the vSwitch): {join_limited(noted, 6)}; "
            "the benchmark title also mentions this value, so confirm the upstream switch ports assign the intended VLAN."
        )
    if offending:
        details = [f"{name} ({detail})" for name, detail in offending.items()]
        return failed(f"Port groups use {check['what']}: {join_limited(details, 6)}.{note}", cap(list(offending)), **evidence)
    return passed(f"No standard port group uses {check['what']} ({len(groups)} checked).{note}", **evidence)


@provider("esxi_iscsi_chap")
def esxi_iscsi_chap(system: System, check: dict) -> object:
    adapters = esxcli_rows(system, "iscsi", "adapter", "list", collector="esxi_storage")
    offending: dict[str, str] = {}
    observed = {}
    for adapter in adapters:
        name = adapter.get("adapter", "")
        levels = {}
        for direction in ("uni", "mutual"):
            rows = esxcli_rows(system, "iscsi", "adapter", "auth", "chap", "get", "-A", name, "-d", direction, collector="esxi_storage")
            levels[direction] = rows[0].get("level", "") if rows else ""
        observed[name] = levels
        if levels["uni"].lower() != "required" or levels["mutual"].lower() != "required":
            offending[name] = f"uni: {levels['uni'] or 'none'}, mutual: {levels['mutual'] or 'none'}"
    if offending:
        details = [f"{name} ({detail})" for name, detail in offending.items()]
        return failed(f"iSCSI adapters without required bidirectional CHAP: {', '.join(details)}.", list(offending), chap=observed)
    return passed(f"All {len(adapters)} iSCSI adapter(s) require bidirectional (mutual) CHAP.", chap=observed)


# ---------------------------------------------------------------- VM checks
@provider("vmx_setting")
def vmx_setting(system: System, check: dict) -> object:
    key, expected = check["key"], str(check["expected"])
    missing_ok = bool(check.get("missing_ok"))
    scan = _vm_scan(system)
    offending, values = {}, {}
    for vm, settings in scan.vms:
        value = settings.get(key.lower())
        values[vm.name] = value
        if value is None:
            if not missing_ok:
                offending[vm.name] = "not set"
        elif not _vmx_matches(value, expected):
            offending[vm.name] = value
    default = " or leaves it unset (default)" if missing_ok else ""
    return _vm_verdict(scan, offending, f"Every VM sets {key} = {expected}{default}", f"do not set {key} = {expected}", setting=key, values=values)


@provider("vmx_device_absent")
def vmx_device_absent(system: System, check: dict) -> object:
    pattern = re.compile(check["device_regex"], re.IGNORECASE)
    cdrom_only = bool(check.get("cdrom_only"))
    scan = _vm_scan(system)
    offending, found = {}, {}
    for vm, settings in scan.vms:
        devices = []
        for key, value in settings.items():
            if not key.endswith(".present") or as_bool(value) is not True:
                continue
            device = key[: -len(".present")]
            if not pattern.match(device):
                continue
            if cdrom_only and "cdrom" not in settings.get(f"{device}.devicetype", "").lower():
                continue
            devices.append(device)
        if devices:
            found[vm.name] = sorted(devices)
            offending[vm.name] = ", ".join(sorted(devices))
    return _vm_verdict(scan, offending, f"No VM has {check['label']} present", f"have {check['label']} present", devices=found)


@provider("vmx_disk_mode")
def vmx_disk_mode(system: System, check: dict) -> object:
    modes = {mode.lower() for mode in check.get("modes", ["independent-nonpersistent"])}
    pattern = re.compile(r"^(scsi|sata|nvme|ide)\d+:\d+\.mode$")
    scan = _vm_scan(system)
    offending, found = {}, {}
    for vm, settings in scan.vms:
        disks = sorted(key[: -len(".mode")] for key, value in settings.items() if pattern.match(key) and value.strip().lower() in modes)
        if disks:
            found[vm.name] = disks
            offending[vm.name] = ", ".join(disks)
    return _vm_verdict(scan, offending, "No VM disk uses a non-persistent mode", "use non-persistent disks", disks=found)
