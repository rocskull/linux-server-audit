"""AppArmor mandatory access control checks."""

from __future__ import annotations

import re

from lsa.checks.common import failed, passed, provider
from lsa.checks.content import grub_configs
from lsa.system import EvidenceUnavailable, System


def apparmor_status(system: System) -> dict:
    def build() -> dict:
        command = system.which("aa-status") or system.which("apparmor_status")
        if command is None:
            raise EvidenceUnavailable("aa-status/apparmor_status is not installed (apparmor package)")
        result = system.run([command], collector="apparmor")
        text = result.stdout + result.stderr
        if result.error:
            raise EvidenceUnavailable(f"Unable to read AppArmor status: {result.describe()}")
        if result.returncode == 4 or "enough privilege" in text:
            raise EvidenceUnavailable("Reading the AppArmor profile set requires root", "root")
        if result.returncode == 3 or "filesystem is not mounted" in text:
            raise EvidenceUnavailable("The AppArmor control files are not available (securityfs not mounted)")
        counts = {}
        for match in re.finditer(r"(?m)^(\d+) (profiles|processes) (?:are|have) (.+?)\.?\s*$", result.stdout):
            counts[f"{match.group(2)} {match.group(3)}"] = int(match.group(1))
        status = {
            "exit_code": result.returncode,
            "module_loaded": "module is loaded" in text,
            "counts": counts,
        }
        system.record("apparmor", "status", status)
        return status

    return system.cached("apparmor-status", "apparmor", build)


@provider("apparmor_enabled")
def apparmor_enabled(system: System, check: dict) -> object:
    problems = []
    evidence: dict = {}
    for path in grub_configs(system):
        for line in system.lines(path) or []:
            if re.match(r"^\s*linux", line) and "apparmor=0" in line:
                problems.append(f"{path} boots a kernel with apparmor=0")
                break
    grub_default = system.read_text("/etc/default/grub.d/apparmor.cfg") or ""
    if "apparmor=0" in grub_default:
        problems.append("/etc/default/grub.d/apparmor.cfg sets apparmor=0")
    state = system.unit("apparmor.service")
    evidence["apparmor_service"] = {"unit_file_state": state.unit_file_state, "active_state": state.active_state}
    if not state.enabled:
        problems.append(f"apparmor.service is {state.unit_file_state or 'not installed'}")
    if not state.active:
        problems.append(f"apparmor.service is {state.active_state or 'not active'}")
    status = apparmor_status(system)
    loaded = status["counts"].get("profiles loaded", 0)
    evidence["profiles_loaded"] = loaded
    evidence["aa_status_exit_code"] = status["exit_code"]
    if loaded <= 0:
        problems.append("no AppArmor profiles are loaded")
    if problems:
        return failed("AppArmor is not fully enabled: " + "; ".join(problems) + ".", ["apparmor"], **evidence)
    return passed(f"AppArmor is enabled at boot and runtime with {loaded} profile(s) loaded.", **evidence)


@provider("apparmor_enforcing")
def apparmor_enforcing(system: System, check: dict) -> object:
    counts = apparmor_status(system)["counts"]
    loaded = counts.get("profiles loaded", 0)
    enforcing = counts.get("profiles in enforce mode", 0)
    problems = []
    if loaded == 0:
        problems.append("no profiles are loaded")
    if enforcing != loaded:
        problems.append(f"only {enforcing} of {loaded} loaded profiles are in enforce mode")
    for mode in ("complain", "prompt", "kill", "unconfined"):
        count = counts.get(f"profiles in {mode} mode", 0)
        if count:
            problems.append(f"{count} profile(s) in {mode} mode")
    unconfined = counts.get("processes unconfined but have a profile defined", 0)
    if unconfined:
        problems.append(f"{unconfined} process(es) are unconfined although a profile is defined")
    evidence = {"counts": counts}
    if counts.get("profiles in complain mode", 0):
        try:
            stubs = [path for path in system.walk_files("/etc/apparmor.d") if "This profile exist only to give a name" in (system.read_text(path) or "")]
        except EvidenceUnavailable:
            stubs = []
        evidence["stub_profiles"] = stubs
    if problems:
        return failed("AppArmor is not enforcing every profile: " + "; ".join(problems) + ".", ["apparmor"], **evidence)
    return passed(f"All {loaded} AppArmor profiles are in enforce mode and no profiled process is unconfined.", **evidence)
