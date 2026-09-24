"""Platform detection and benchmark selection across a mixed estate.

The same tool runs unattended on Proxmox VE and VMware ESXi hosts, so a host
whose release has no exact definition must still be assessed (with a warning)
rather than stopping the run.
"""

from __future__ import annotations

import unittest

from lsa.engine import resolve_profile
from lsa.platform import detect_platform, select_benchmark
from lsa.system import System
from tests.support import BENCHMARKS, DEBIAN_12, DEBIAN_13, ROCKY_9, SETTINGS, UBUNTU_24, FakeRunner, TempRoot, esxi_host, linux_host, write


def linux(root, os_release, packages=None, pve=False):
    runner = linux_host(root, os_release, packages)
    if pve:
        write(root, "etc/pve/.version", "")
    return System(str(root), runner, dict(SETTINGS), is_root=True)


class DetectionTests(unittest.TestCase):
    def select(self, system):
        info = detect_platform(system)
        entry, warnings = select_benchmark(system, BENCHMARKS, info)
        return info, entry, warnings

    def test_esxi8_selects_esxi8_definition(self):
        with TempRoot() as root:
            system = System(str(root), esxi_host(root, version="8.0.3"), dict(SETTINGS), is_root=True)
            info, entry, warnings = self.select(system)
        self.assertEqual((info.kind, info.report_tag, info.platform_type), ("esxi", "esxi", "Hypervisor"))
        self.assertEqual(entry["id"], "vmware-esxi-8.0")
        self.assertEqual(warnings, [])

    def test_esxi7_selects_esxi7_definition(self):
        with TempRoot() as root:
            system = System(str(root), esxi_host(root, version="7.0.3"), dict(SETTINGS), is_root=True)
            _, entry, warnings = self.select(system)
        self.assertEqual(entry["id"], "vmware-esxi-7.0")
        self.assertEqual(warnings, [])

    def test_older_and_newer_esxi_use_closest_definition_with_warning(self):
        for version, expected in (("6.7.0", "vmware-esxi-7.0"), ("9.0.0", "vmware-esxi-8.0")):
            with self.subTest(version=version), TempRoot() as root:
                system = System(str(root), esxi_host(root, version=version), dict(SETTINGS), is_root=True)
                _, entry, warnings = self.select(system)
                self.assertEqual(entry["id"], expected)
                self.assertEqual(len(warnings), 1)
                self.assertIn("closest", warnings[0])

    def test_unknown_esxi_version_uses_newest_definition(self):
        with TempRoot() as root:
            system = System(str(root), esxi_host(root), dict(SETTINGS), is_root=True)
            system.runner.fail_all = "unavailable"
            info, entry, warnings = self.select(system)
        self.assertEqual(info.kind, "esxi")
        self.assertEqual(entry["id"], "vmware-esxi-8.0")
        self.assertEqual(len(warnings), 1)

    def test_debian13_exact_match(self):
        with TempRoot() as root:
            info, entry, warnings = self.select(linux(root, DEBIAN_13))
        self.assertEqual((info.kind, info.report_tag), ("linux", "linux"))
        self.assertEqual(entry["id"], "debian-linux-13")
        self.assertEqual(warnings, [])

    def test_proxmox_ve8_on_debian12_is_assessed_with_debian13_and_a_warning(self):
        with TempRoot() as root:
            system = linux(root, DEBIAN_12, {"pve-manager": "8.2.4", "proxmox-ve": "8.2.0"}, pve=True)
            info, entry, warnings = self.select(system)
        self.assertIn("proxmox", info.tags)
        self.assertEqual(info.report_tag, "proxmox")
        self.assertEqual(info.label, "Proxmox VE 8.2.4 (Debian GNU/Linux 12 (bookworm))")
        self.assertEqual(entry["id"], "debian-linux-13")
        self.assertEqual(len(warnings), 1)

    def test_proxmox_ve9_on_debian13_matches_exactly(self):
        with TempRoot() as root:
            info, entry, warnings = self.select(linux(root, DEBIAN_13, {"pve-manager": "9.0.6"}, pve=True))
        self.assertEqual(info.report_tag, "proxmox")
        self.assertEqual(entry["id"], "debian-linux-13")
        self.assertEqual(warnings, [])

    def test_other_linux_distributions_never_stop_the_run(self):
        for release in (UBUNTU_24, ROCKY_9):
            with self.subTest(release=release.splitlines()[0]), TempRoot() as root:
                info, entry, warnings = self.select(linux(root, release))
                self.assertEqual(info.kind, "linux")
                self.assertEqual(entry["id"], "debian-linux-13")
                self.assertEqual(len(warnings), 1)

    def test_host_without_os_identity_is_rejected_clearly(self):
        with TempRoot() as root:
            system = System(str(root), FakeRunner(), dict(SETTINGS), is_root=True)
            info = detect_platform(system)
            self.assertEqual(info.kind, "unknown")
            with self.assertRaises(ValueError):
                select_benchmark(system, BENCHMARKS, info)


class ProfileTests(unittest.TestCase):
    ESXI = ["Level 1 (L1) - Corporate/Enterprise Environment (general use)", "Level 2 (L2) - High Security/Sensitive Data Environment (limited functionality)"]
    LINUX = ["Level 1 - Server", "Level 2 - Server", "Level 1 - Workstation", "Level 2 - Workstation"]

    def test_esxi_levels(self):
        name, allowed = resolve_profile("auto", "Hypervisor", self.ESXI)
        self.assertEqual(name, self.ESXI[1])
        self.assertEqual(allowed, set(self.ESXI))
        name, allowed = resolve_profile("level1", "Hypervisor", self.ESXI)
        self.assertEqual((name, allowed), (self.ESXI[0], {self.ESXI[0]}))

    def test_linux_levels(self):
        self.assertEqual(resolve_profile("auto", "Server", self.LINUX), ("Level 2 - Server", {"Level 1 - Server", "Level 2 - Server"}))
        self.assertEqual(resolve_profile("level1", "Workstation", self.LINUX), ("Level 1 - Workstation", {"Level 1 - Workstation"}))
        with self.assertRaises(ValueError):
            resolve_profile("level3", "Server", self.LINUX)
