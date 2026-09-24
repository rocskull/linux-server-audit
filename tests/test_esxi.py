"""ESXi 7.0 and 8.0 definitions evaluated against synthetic hosts."""

from __future__ import annotations

import unittest

from lsa.model import ERROR, FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS
from tests.support import TempRoot, assess, esxi_system, statuses

# Verdicts for the insecure fixture: SSH enabled at boot, no NTP, no remote
# syslog, lockdown disabled, forged transmits/MAC changes accepted, VLAN 4095
# and native VLAN 1 port groups, CHAP prohibited, a CommunitySupported VIB and
# one VM ('web01') with legacy devices, passthrough and no isolation options.
ESXI8_INSECURE = {
    "2.4": FAIL, "2.6": FAIL, "2.10": PASS,
    "3.1": FAIL, "3.2": PASS, "3.3": PASS, "3.7": PASS, "3.8": FAIL, "3.9": FAIL,
    "3.12": PASS, "3.13": PASS, "3.20": FAIL, "3.21": FAIL,
    "4.2": FAIL,
    "5.6": FAIL, "5.7": FAIL, "5.8": PASS, "5.9": FAIL, "5.10": FAIL,
    "6.3.1": FAIL,
    "7.4": PASS, "7.6": FAIL, "7.7": FAIL, "7.8": FAIL, "7.9": FAIL, "7.12": FAIL, "7.13": PASS, "7.14": PASS,
    "7.15": FAIL, "7.16": FAIL, "7.17": PASS, "7.18": FAIL, "7.19": PASS, "7.21": FAIL, "7.22": FAIL,
    "7.24": PASS, "7.26": FAIL, "7.27": FAIL,
}

ESXI7_INSECURE = {
    "1.2": FAIL, "1.4": PASS, "2.1": FAIL, "2.3": PASS, "3.1": FAIL, "3.3": FAIL,
    "4.1": FAIL, "4.3": PASS, "4.4": PASS,
    "5.1": PASS, "5.2": PASS, "5.3": FAIL, "5.5": FAIL, "5.6": FAIL, "5.8": FAIL, "5.9": FAIL,
    "6.1": FAIL,
    "7.1": FAIL, "7.2": FAIL, "7.3": PASS, "7.4": FAIL, "7.6": FAIL,
    "8.1.1": FAIL, "8.2.1": FAIL, "8.2.2": FAIL, "8.2.3": PASS, "8.2.4": PASS, "8.2.5": FAIL, "8.2.6": FAIL,
    "8.2.7": FAIL, "8.2.8": FAIL,
    **{f"8.4.{number}": FAIL for number in range(2, 21)},
    "8.4.21": FAIL, "8.4.22": PASS, "8.4.23": PASS, "8.4.24": PASS,
    "8.5.2": FAIL, "8.6.1": FAIL, "8.6.2": FAIL, "8.6.3": FAIL, "8.7.1": FAIL, "8.7.2": PASS, "8.7.3": FAIL,
}


class EsxiDefinitionTests(unittest.TestCase):
    def run_host(self, version: str, **options):
        with TempRoot() as root:
            system = esxi_system(root, version=version, **options)
            return assess(system)

    def assert_statuses(self, actual: dict, expected: dict) -> None:
        self.assertEqual(set(actual), set(expected), "every automated control must have an expected verdict")
        wrong = {cis: (actual[cis], status) for cis, status in expected.items() if actual[cis] != status}
        self.assertEqual(wrong, {}, "controls with an unexpected status (actual, expected)")

    def test_esxi8_insecure_host(self):
        document, definition, warnings = self.run_host("8.0.2")
        self.assertEqual(warnings, [])
        self.assertEqual(definition["benchmark"]["id"], "vmware-esxi-8.0")
        self.assert_statuses(statuses(document, definition), ESXI8_INSECURE)
        self.assertEqual(document.host.platform_type, "Hypervisor")
        self.assertTrue(document.host.platform.startswith("VMware ESXi 8.0.2"))

    def test_esxi8_hardened_host_passes_everything(self):
        document, definition, _ = self.run_host("8.0.2", hardened=True)
        results = statuses(document, definition)
        self.assertEqual({cis for cis, status in results.items() if status != PASS}, set())

    def test_esxi7_insecure_host(self):
        document, definition, warnings = self.run_host("7.0.3")
        self.assertEqual(warnings, [])
        self.assertEqual(definition["benchmark"]["id"], "vmware-esxi-7.0")
        self.assert_statuses(statuses(document, definition), ESXI7_INSECURE)

    def test_esxi7_hardened_host_passes_everything(self):
        document, definition, _ = self.run_host("7.0.3", hardened=True)
        results = statuses(document, definition)
        self.assertEqual({cis for cis, status in results.items() if status != PASS}, set())

    def test_findings_explain_the_gap(self):
        document, definition, _ = self.run_host("8.0.2")
        by_cis = {control["id"]: control["cis_id"] for control in definition["controls"]}
        checks = {by_cis[item.check_id]: item for item in document.checks}
        self.assertIn("'on'", checks["3.1"].observation)
        self.assertIn("currently running", checks["3.1"].observation)
        self.assertIn("vmkusb-nic-fling", checks["2.4"].observation)
        self.assertEqual(checks["5.10"].affected_resources, ["Trunk"])
        self.assertIn("Management Network", checks["5.10"].observation)
        self.assertEqual(checks["7.16"].affected_resources, ["web01"])
        self.assertIn("vCLS-a1b2", checks["7.16"].observation)
        self.assertEqual(checks["7.15"].evidence["devices"], {"web01": ["sata0:0"]})

    def test_hosts_without_vms_iscsi_or_standard_switches(self):
        document, definition, _ = self.run_host("8.0.2", vms=False, iscsi=False, vswitch=False)
        results = statuses(document, definition)
        for cis in ("7.6", "7.16", "7.26", "6.3.1", "5.6", "5.9", "5.10"):
            self.assertEqual(results[cis], NOT_APPLICABLE, cis)
        self.assertEqual(results["3.1"], FAIL)

    def test_level1_profile_marks_level2_controls_not_applicable(self):
        with TempRoot() as root:
            document, definition, _ = assess(esxi_system(root), profile="level1")
        results = statuses(document, definition)
        self.assertEqual(results["3.21"], NOT_APPLICABLE)
        self.assertEqual(results["7.15"], NOT_APPLICABLE)
        self.assertEqual(results["3.20"], FAIL)

    def test_non_root_run_is_not_assessed_never_failed(self):
        with TempRoot() as root:
            system = esxi_system(root, is_root=False)
            system.runner.fail_all = "Permission denied"
            document, definition, _ = assess(system)
        results = statuses(document, definition)
        self.assertEqual(set(results.values()), {NOT_ASSESSED})
        root_gaps = [area for area in document.coverage if "root" in area.missing_permissions]
        self.assertTrue(root_gaps)

    def test_no_evaluation_errors_and_manual_items_listed(self):
        with TempRoot() as root:
            document, definition, _ = assess(esxi_system(root), include_manual=True)
        self.assertNotIn(ERROR, {item.status for item in document.checks})
        self.assertEqual(len(document.checks), len(definition["controls"]) + len(definition["manual_recommendations"]))
