"""Proxmox VE context for the CIS Debian Linux 13 controls.

Proxmox VE nodes are Debian servers, so the Debian benchmark applies to them,
but a few recommendations conflict with how Proxmox VE clusters operate. When
the tool detects Proxmox VE it appends these notes to the observation of the
affected controls. The CIS verdict itself is unchanged, so any exception stays
visible and has to be accepted deliberately.
"""

from __future__ import annotations

from specs.debian13 import NOTES


def note(cis_ids: list[str], text: str) -> None:
    for cis_id in cis_ids:
        NOTES.setdefault(cis_id, {})["proxmox"] = text


note(
    ["1.1.1.6"],
    "Docker or Podman running inside LXC containers relies on OverlayFS in the node's kernel; confirm no container needs it before deny-listing the module.",
)
note(
    ["1.2.1.10", "1.2.1.11"],
    "The Proxmox VE documentation configures the no-subscription and Ceph repositories as http://download.proxmox.com; APT still verifies them "
    "through signed Release files. Switch them to https:// where the mirror supports it, or record an exception.",
)
note(
    ["1.4.1", "1.4.2"],
    "Proxmox VE installed on ZFS with UEFI boots through systemd-boot (managed by proxmox-boot-tool), where GRUB settings do not apply; "
    "there, protect the boot process with a firmware (UEFI) setup password and Secure Boot.",
)
note(
    ["6.2.1.3", "6.2.1.4"],
    "On systemd-boot installs the kernel command line comes from /etc/kernel/cmdline; apply changes with 'proxmox-boot-tool refresh'.",
)
note(
    ["2.1.12"],
    "Proxmox VE needs rpcbind when the node mounts NFSv3 storage; keep it only where NFS storage is configured and restrict it with the Proxmox VE firewall.",
)
note(
    ["3.3.1.1", "3.3.1.2", "3.3.1.3", "3.3.2.1", "3.3.2.2"],
    "Forwarding is needed only when the node routes or masquerades guest traffic (routed or NAT setups, SDN); nodes that only bridge guests through vmbr interfaces do not need it.",
)
note(
    ["4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5"],
    "Proxmox VE provides its own firewall (pve-firewall) and UFW conflicts with it, so do not install UFW on a node. Enforce host filtering "
    "with the Proxmox VE firewall instead: enable it at datacenter and node level with a default-deny input policy ('pve-firewall status' shows whether it is running).",
)
note(
    ["5.1.22"],
    "Proxmox VE cluster nodes use key-based root SSH between members (migration, replication, joining nodes). The usual compromise is "
    "'PermitRootLogin prohibit-password' with root access limited to the cluster network through a Match Address block.",
)
note(
    ["5.1.5"],
    "On Proxmox VE cluster nodes AllowUsers/AllowGroups must still admit root from the other cluster nodes, or migration and replication fail.",
)
note(
    ["5.1.9"],
    "Proxmox VE secure (default) live migration tunnels guest state through SSH socket forwarding between cluster nodes; DisableForwarding yes "
    "breaks it unless forwarding is re-allowed for root from cluster node addresses in a Match block.",
)
