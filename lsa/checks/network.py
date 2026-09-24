"""Host firewall and network service exposure checks."""

from __future__ import annotations

import ipaddress
import re
import socket

from lsa.checks.common import failed, passed, provider
from lsa.system import EvidenceUnavailable, System

UFW_POLICY_WORDS = {"DROP": "deny", "REJECT": "reject", "ACCEPT": "allow"}
UFW_CONFIG_KEYS = {"incoming": "DEFAULT_INPUT_POLICY", "outgoing": "DEFAULT_OUTPUT_POLICY", "routed": "DEFAULT_FORWARD_POLICY"}


# ---------------------------------------------------------------------- UFW
def ufw_config_policies(system: System) -> dict[str, str]:
    values = {}
    for line in system.lines("/etc/default/ufw") or []:
        match = re.match(r'^\s*(DEFAULT_\w+_POLICY)\s*=\s*"?(\w+)"?', line)
        if match:
            values[match.group(1)] = UFW_POLICY_WORDS.get(match.group(2).upper(), match.group(2).lower())
    return {direction: values.get(key, "") for direction, key in UFW_CONFIG_KEYS.items()}


def ufw_status(system: System) -> dict:
    def build() -> dict:
        command = system.command("ufw")
        result = system.run([command, "status", "verbose"], collector="firewall")
        text = result.stdout + result.stderr
        if "need to be root" in text:
            raise EvidenceUnavailable("Reading the UFW status requires root", "root")
        if not result.ok:
            raise EvidenceUnavailable(f"Unable to read the UFW status: {result.describe()}")
        status = re.search(r"(?m)^Status:\s*(\w+)", result.stdout)
        policies = {}
        default = re.search(r"(?m)^Default:\s*(.+)$", result.stdout)
        if default:
            for policy, direction in re.findall(r"(\w+)\s*\((\w+)\)", default.group(1)):
                policies[direction.lower()] = policy.lower()
        state = {"status": status.group(1).lower() if status else "unknown", "policies": policies}
        system.record("firewall", "ufw", state)
        return state

    return system.cached("ufw-status", "firewall", build)


@provider("ufw_service")
def ufw_service(system: System, check: dict) -> object:
    if not system.package_installed("ufw"):
        return failed("ufw is not installed, so no host firewall service is configured through UFW.", ["ufw"])
    problems = []
    unit = system.unit("ufw.service")
    if not unit.enabled:
        problems.append(f"ufw.service is {unit.unit_file_state or 'not installed'}")
    if not unit.active:
        problems.append(f"ufw.service is {unit.active_state or 'not active'}")
    status = ufw_status(system)
    if status["status"] != "active":
        problems.append(f"'ufw status' reports {status['status']}")
    evidence = {"unit_file_state": unit.unit_file_state, "active_state": unit.active_state, "ufw_status": status["status"]}
    if problems:
        return failed("UFW is not enforcing: " + "; ".join(problems) + ".", ["ufw"], **evidence)
    return passed("ufw.service is enabled and active and UFW reports Status: active.", **evidence)


@provider("ufw_default")
def ufw_default(system: System, check: dict) -> object:
    direction = check["direction"]
    allowed = check["allowed"]
    if not system.package_installed("ufw"):
        return failed(f"ufw is not installed, so no default {direction} policy is enforced.", ["ufw"])
    status = ufw_status(system)
    configured = ufw_config_policies(system)
    policy = status["policies"].get(direction, "")
    evidence = {"ufw_status": status["status"], "reported_policy": policy, "configured_policies": configured}
    if status["status"] != "active":
        return failed(
            f"UFW is {status['status']}, so the default {direction} policy (configured: {configured.get(direction) or 'unset'}) is not enforced.",
            ["ufw"],
            **evidence,
        )
    if direction == "routed" and policy == "disabled":
        policy = configured.get("routed", "")
        evidence["policy_source"] = "/etc/default/ufw (kernel forwarding is disabled)"
    if policy in allowed:
        return passed(f"The UFW default {direction} policy is {policy}.", **evidence)
    return failed(
        f"The UFW default {direction} policy is {policy or 'not set'}; it should be {' or '.join(allowed)}.", ["ufw"], **evidence
    )


# ---------------------------------------------------------------- listeners
def listening_sockets(system: System) -> list[tuple[str, str, int]]:
    def build() -> list[tuple[str, str, int]]:
        sockets = []
        for proto, path, family in (("tcp", "/proc/net/tcp", socket.AF_INET), ("tcp6", "/proc/net/tcp6", socket.AF_INET6)):
            for line in (system.lines(path) or [])[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "0A":
                    continue
                address_hex, port_hex = parts[1].split(":")
                raw = bytes.fromhex(address_hex)
                if family == socket.AF_INET:
                    address = socket.inet_ntop(family, raw[::-1])
                else:
                    address = socket.inet_ntop(family, b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4)))
                sockets.append((proto, address, int(port_hex, 16)))
        system.record("network", "listening_tcp", sorted({f"{a}:{p}" for _, a, p in sockets}))
        return sockets

    return system.cached("listening-sockets", "network", build)


def is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def _interfaces_loopback_only(value: str) -> bool:
    tokens = [token for token in re.split(r"[\s,;<]+", value) if token and token != "="]
    if not tokens:
        return False
    for token in tokens:
        lowered = token.lower()
        if lowered in ("loopback-only", "localhost", "localhost.localdomain"):
            continue
        if not is_loopback(lowered):
            return False
    return True


@provider("mta_local_only")
def mta_local_only(system: System, check: dict) -> object:
    ports = check.get("ports", [25, 465, 587])
    exposed = [f"{address}:{port}" for _, address, port in listening_sockets(system) if port in ports and not is_loopback(address)]
    problems = [f"port {item} is listening on a non-loopback address" for item in exposed]
    evidence: dict = {"non_loopback_listeners": exposed}
    interfaces = None
    postconf = system.which("postconf")
    exim = system.which("exim4") or system.which("exim")
    if postconf:
        result = system.run([postconf, "-n", "inet_interfaces"], collector="network")
        interfaces = result.stdout.split("=", 1)[1].strip() if "=" in result.stdout else None
        evidence["mta"] = "postfix"
    elif exim:
        result = system.run([exim, "-bP", "local_interfaces"], collector="network")
        interfaces = result.stdout.split("=", 1)[1].strip() if "=" in result.stdout else None
        evidence["mta"] = "exim"
    elif system.is_file("/etc/mail/sendmail.cf"):
        addresses = re.findall(r"Addr=([^,\s]+)", system.read_text("/etc/mail/sendmail.cf") or "")
        interfaces = ",".join(addresses) if addresses else None
        evidence["mta"] = "sendmail"
    evidence["mta_interfaces"] = interfaces
    if interfaces:
        if re.search(r"\ball\b", interfaces, re.IGNORECASE):
            problems.append(f"the MTA is bound to all interfaces ({interfaces})")
        elif not _interfaces_loopback_only(interfaces):
            problems.append(f"the MTA is bound to non-loopback interfaces ({interfaces})")
    if problems:
        return failed("The mail transfer agent accepts network connections: " + "; ".join(problems) + ".", exposed or [evidence.get("mta", "MTA")], **evidence)
    detail = f"; MTA interfaces: {interfaces}" if interfaces else ("; no MTA configuration detected" if "mta" not in evidence else "")
    return passed(f"Nothing listens on ports {', '.join(map(str, ports))} outside loopback{detail}.", **evidence)
