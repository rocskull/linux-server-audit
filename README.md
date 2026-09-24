# Linux Security Audit

Read-only CIS configuration assessment for Linux servers (including Proxmox VE)
and VMware ESXi hosts. The tool runs locally on the host being assessed, detects
the platform, selects the matching versioned benchmark definition, evaluates
every automated CIS recommendation and writes reports in the
**m365-assessor** format: an `AssessmentDocument` JSON file, an HTML dashboard,
a findings CSV, an eight-sheet Excel workbook and a four-sheet consolidated
(Monkey365 layout) workbook.

It is the Linux and ESXi counterpart of `windows-security-audit`: controls live
in data-driven JSON definitions generated from the CIS PDFs, and a small
library of check providers evaluates them.

## Supported platforms

| Platform | Benchmark definition | Automated controls | Manual recommendations |
| --- | --- | ---: | ---: |
| Debian 13 and Proxmox VE 9 | CIS Debian Linux 13 Benchmark v1.1.0 | 333 | 17 |
| Proxmox VE 8 (Debian 12) and other Debian-family releases | CIS Debian Linux 13 v1.1.0 (closest match, with a warning) | 333 | 17 |
| VMware ESXi 8.0 | CIS VMware ESXi 8.0 Benchmark v1.4.0 | 38 | 96 |
| VMware ESXi 7.0 | CIS VMware ESXi 7.0 Benchmark v1.6.0 | 61 | 29 |

Manual recommendations need evidence the host cannot provide (vCenter Server,
hardware, guest operating systems or organisational records). They are listed
in the report's limitations and, with `--include-manual`, as `NOT_ASSESSED`
items.

### Mixed estates

The same folder can be copied to every host and run unattended. Detection never
stops the run because a platform is absent:

- **ESXi** is recognised by the VMkernel (`uname`) or `/etc/vmware/esx.conf` with
  the `esxcli`/`vmware` binaries, and assessed with the ESXi definition for its
  major version.
- **Linux** is identified from `/etc/os-release`. **Proxmox VE** is recognised by
  the `pve-manager`/`proxmox-ve` packages, `/etc/pve` or `pveversion`; the node
  is assessed with the Debian benchmark and the report is titled *Proxmox VE
  Security Assessment*.
- When no definition matches the release exactly (for example Proxmox VE 8 on
  Debian 12, or ESXi 6.7), the closest definition of the same platform family
  is used and a warning is written to the log and to the JSON
  `benchmark_results.<id>.warnings`. Only a host that is neither Linux nor ESXi
  is rejected.

## Requirements

- Python 3.8 or newer, standard library only. This matches the interpreter
  bundled with ESXi 7.0 and 8.0; nothing needs to be installed on the host.
- Root. Without root, evidence that needs privileges is reported as
  `NOT_ASSESSED` (never as a failure) and the coverage sheet names the missing
  privilege.

## Running an assessment

### Debian and Proxmox VE

```bash
sudo python3 linux_security_audit.py --client-name Contoso --output /var/tmp/assessments
```

Reports are written to
`/var/tmp/assessments/Contoso-<host>-proxmox-assessment-<yyyyMMdd-HHmmss>/`
(`-linux-` on plain Debian). When started with `sudo` the report folder is
handed back to the invoking user.

### VMware ESXi

1. Start the SSH service for the duration of the assessment (Host Client >
   Manage > Services > TSM-SSH > Start).
2. Copy this folder to a datastore, not to the host's RAM disk:
   `scp -r linux-server-audit root@esx01:/vmfs/volumes/datastore1/`
3. Run it from the ESXi Shell:

   ```sh
   cd /vmfs/volumes/datastore1/linux-server-audit
   python linux_security_audit.py --client-name Contoso --output /vmfs/volumes/datastore1/assessments
   ```

4. Copy the report folder back and delete it from the datastore, then stop
   SSH again.

Because SSH is running during the assessment, the SSH control reports the
service as running; the verdict is based on its startup policy, which should be
*Start and stop manually*.

### Useful options

| Option | Purpose |
| --- | --- |
| `-C`, `--client-name` | Client name used in folder and file names (required when not interactive). |
| `-O`, `--output` | Output root; a timestamped assessment folder is created inside it. |
| `--profile` | `auto` (default: Level 1 and Level 2), `level1`, `level2`, or an explicit Linux profile such as `level1-server`. |
| `--section` | Limit to CIS sections by number or name (repeatable); other controls become `NOT_APPLICABLE`. |
| `--format` | Comma-separated subset of `json,html,csv,xlsx,consolidated`. |
| `--include-manual` | Also list manual recommendations as `NOT_ASSESSED` items. |
| `--skip-filesystem-scan` | Skip the full filesystem walk used by the SUID/SGID, world-writable and unowned-file controls (they become `NOT_ASSESSED`). |
| `--benchmark-path` | Force a definition; a platform mismatch is reported as a warning. |
| `--list-benchmarks`, `--list-checks` | Show the installed definitions, or the controls that would be assessed. |
| `--dry-run` | Show the plan (platform, benchmark, controls, commands) without collecting evidence. |
| `--report-from FILE.json` | Regenerate all report formats from an existing assessment JSON file. |
| `-y`, `--yes` | Do not ask for confirmation when not running as root. |

## Configuration

`config.json` beside the script supplies defaults:

| Key | Meaning |
| --- | --- |
| `report_formats`, `output_directory`, `benchmarks_directory` | Report selection and locations. |
| `client_name`, `profile`, `include_manual` | Defaults for the matching command-line options. |
| `command_timeout_seconds` | Timeout for each read-only command (default 60). |
| `filesystem_scan.enabled`, `filesystem_scan.exclude_paths` | Control the filesystem walk. |
| `site_policy.network_router` | Set to `true` on hosts that route traffic; the host-only network parameter controls (3.3.x) are then not applicable, as the benchmark exempts routers. |
| `site_policy.logging_method` | `auto`, `journald` or `rsyslog`, deciding which logging controls apply. |
| `site_policy.approved_time_servers` | When set, every configured NTP server must be on this list. |
| `site_policy.sshd_match_contexts` | Extra `sshd -T -C` contexts (such as `user=backup,host=h,addr=10.0.0.5`) to evaluate Match blocks. |
| `site_policy.esxi_native_vlan` | The physical switches' native VLAN (default 1). |
| `site_policy.esxi_vgt_portgroups` | Port groups approved to use VLAN 4095 (Virtual Guest Tagging). |
| `site_policy.esxi_excluded_vms` | VM name patterns excluded from VM checks (default `vCLS*`, the vSphere Cluster Services system VMs). |

## Reports

Each run creates `<client>-<host>-<linux|proxmox|esxi>-assessment-<timestamp>/`
containing:

| File | Content |
| --- | --- |
| `<stem>.json` | The `AssessmentDocument` (m365-assessor schema, with `host` and `execution` in place of the tenant blocks). |
| `<stem>.html` | Dashboard: summary tiles, risk distribution, priority remediation, coverage, findings, all controls, limitations. |
| `<stem>-findings.csv` | One row per failed control and affected resource. |
| `<stem>.xlsx` | Executive Summary, Finding Register, Good Controls, Not Assessed, Permission Coverage, Framework Mapping, Raw Evidence, Methodology. |
| `<stem>-consolidated.xlsx` | Monkey365-style client workbook: Executive Summary, Finding Register, Good Controls, Raw Data. |
| `linux-security-audit.log` | Run log, including any benchmark-selection warning. |

Statuses and scoring follow m365-assessor exactly: `PASS`, `FAIL`, `WARNING`,
`NOT_APPLICABLE` (outside the profile or scope, or not relevant to the host),
`NOT_ASSESSED` (evidence unavailable, or a manual recommendation) and `ERROR`
(a defect while evaluating a control). Pass percentage is PASS / (PASS + FAIL +
WARNING); coverage is assessed / (assessed + NOT_ASSESSED + ERROR). Every
control produces exactly one result.

Each control carries a risk-based severity (Critical, High, Medium, Low) that
reflects exploitability and impact on the platform rather than the CIS level,
a stable check ID (`LNX-SSH-022`, `ESX8-MGMT-001`, `ESX7-VMDEV-004`) and
mappings to the CIS benchmark, CIS Controls v8 and, where the benchmark lists
them, NIST SP 800-53 Rev. 5.

Report files are written with mode 0600 inside a 0700 folder. The tool never
reads password hashes, private keys or secret file contents into reports, and
all text is neutralised against spreadsheet formula injection.

## How evidence is collected

Everything is read-only: files, `/proc` and `/sys`, and query commands such as
`systemctl show`, `sshd -T`, `auditctl -l`, `apt-config dump`, `aa-status` and
`ufw status verbose` on Linux, and `esxcli --formatter=csv … get/list`,
`vim-cmd hostsvc/hostconfig`, `vim-cmd hostsvc/advopt/view` and the registered
VMs' `.vmx` files on ESXi. Commands run with a fixed `PATH`, the C locale, no
standard input and a timeout. `--dry-run` lists the commands for the detected
platform.

## Platform notes

### Proxmox VE

A few Debian recommendations conflict with how Proxmox VE clusters work. On a
Proxmox node the tool keeps the CIS verdict and appends a *Note (Proxmox VE)* to
the observation of 21 controls, including:

- **UFW (4.1.x):** Proxmox VE has its own firewall (`pve-firewall`), and UFW
  conflicts with it; host filtering should be enforced with the Proxmox VE
  firewall instead.
- **SSH (5.1.5, 5.1.9, 5.1.22):** cluster nodes need key-based root SSH between
  members, and secure live migration uses SSH forwarding.
- **IP forwarding (3.3.x):** needed only for routed, NAT or SDN setups.
- **rpcbind (2.1.12):** needed for NFSv3 storage.
- **Boot (1.4.x, 6.2.1.3–4):** ZFS/UEFI installs boot through systemd-boot, and
  the kernel command line is then read from `/etc/kernel/cmdline`.

Guest data is not assessed as part of the node: container volumes and shared
storage mounts are excluded from the filesystem walk (see below). Run the tool
inside a Linux guest to assess that guest.

### VMware ESXi

- Host settings come from the ESXi Shell. Distributed switches, vCenter roles
  and hardware controls are outside the host's view and remain manual.
- VM controls read each registered VM's `.vmx` file. Hosts without VMs, iSCSI
  adapters or standard vSwitches report those controls as `NOT_APPLICABLE`.
- Lockdown mode requires vCenter Server. On a standalone host the lockdown
  controls fail and should be recorded as an accepted exception.

## Interpretation choices

The benchmarks' audit procedures are implemented by their intent rather than
by string-matching their example commands:

- **sshd** is evaluated from `sshd -T` for root connecting from the host's
  primary address, plus any configured Match contexts.
- **Audit rules** are compared semantically on disk and in the loaded rule set
  (`auditctl -l`): a watch equals the matching `-F path=`/`dir=` syscall rule,
  64- and 32-bit rules are both required on x86_64, `auid!=unset`, `-1` and
  `4294967295` are equivalent, field order is ignored, and `/var/run` equals
  `/run`.
- **Missing software** is compliant where CIS says so; for example, a kernel
  module that is not built for the running kernel, or an option of a package
  that is not installed.
- **Empty numeric fields** in `/etc/shadow` are non-compliant, as with the awk
  comparisons in the CIS scripts.
- **Filesystem walk:** one traversal serves the SUID/SGID, world-writable and
  unowned-file controls. ZFS counts as a local filesystem (the literal CIS
  script skips it because `/proc/filesystems` lists it as `nodev`, which would
  leave a ZFS root out of the setuid/setgid inventory). Network and cluster
  filesystems (NFS, CIFS, CephFS, GlusterFS, FUSE network mounts) and Proxmox VE
  container volumes (`subvol-*-disk-*`) are skipped. An empty setuid/setgid
  inventory is reported as `NOT_ASSESSED`, never as a pass.
- **ESXi thresholds** accept stricter values: `Security.AccountLockFailures`
  1–5, `Security.AccountUnlockTime` of at least 900 seconds, timeouts of 1 up to
  the limit (0, which disables the timeout, fails), and strict lockdown
  satisfies the normal-lockdown control.
- **ESXi VLANs:** the VGT control fails VLAN 4095, as its audit procedure says.
  Port groups on VLAN 0, which the title also mentions but which means
  "untagged" on a standard vSwitch, are listed for review instead.
- **VMX defaults:** options whose absence equals the secure default
  (clipboard, drag and drop, GUI options, host information, and 3D graphics on
  ESXi 8) pass when unset. Options the benchmark requires to be set explicitly
  fail when unset. USB covers `usb`, `usb_xhci` and `ehci` controllers,
  CD/DVD covers IDE and SATA drives with a CD-ROM device type, and non-persistent
  disks include the legacy `nonpersistent` mode.

## Validation status

- The unit tests (`python -m unittest discover -s tests -t .`) pass on Python
  3.8.10 and 3.12. They assert every ESXi 7 and ESXi 8 verdict against synthetic
  insecure and hardened hosts, and cover platform selection (including Proxmox
  VE 8 and 9), non-root runs, a Debian smoke run with no evaluation errors, and
  all report formats. Excel opens the generated workbooks without repairs.
- The ESXi providers were built from the documented output formats of
  `esxcli --formatter=csv` and `vim-cmd`. Their parsing is tolerant of column
  naming, but no live ESXi host was available, so review the first live ESXi
  report closely. Anything the tool could not read is reported as
  `NOT_ASSESSED` with the reason, never as a failure.

## Project layout

```
linux_security_audit.py        entry point (Python 3.8+)
config.json                    defaults and site policy
benchmarks/                    versioned definitions and catalog.json (SHA-256)
lsa/cli.py                     command line, run folder and logging
lsa/platform.py                platform detection and benchmark selection
lsa/engine.py                  definition validation and control evaluation
lsa/system.py                  read-only, cached access to files and commands
lsa/checks/                    check providers, conditions and path sources
lsa/model.py                   AssessmentDocument model (m365-assessor schema)
lsa/reporting/                 JSON, HTML, CSV and Excel writers (no dependencies)
tools/build_benchmark_definition.py   builds definitions from CIS PDFs
tools/specs/                   per-benchmark check specifications and guidance
tests/                         unit tests with synthetic hosts
docs/benchmark-definitions.md  definition schema, providers and build process
```

## Maintaining benchmark definitions

Definitions are generated, not hand-edited:

```bash
pip install pymupdf    # or pypdf
python tools/build_benchmark_definition.py --spec debian13 --pdf CIS_Debian_Linux_13_Benchmark_v1.1.0.pdf
python tools/build_benchmark_definition.py --spec esxi8 --pdf CIS_VMware_ESXi_8.0_Benchmark_v1.4.0_PDF.pdf
python tools/build_benchmark_definition.py --spec esxi7 --pdf "CIS VMWare ESXi 7 Benchmark V1.6.0 PDF.pdf"
```

The builder takes control identity from the PDF (numbers, titles, profiles,
Automated/Manual status, CIS Controls v8 and NIST mappings) and everything else
from `tools/specs/`. It fails if an automated recommendation has no
specification or a specification has no matching recommendation, validates the
result with the runtime loader and refreshes `benchmarks/catalog.json`. See
[docs/benchmark-definitions.md](docs/benchmark-definitions.md) for the schema
and for adding a benchmark.

Guidance text is written independently; the CIS documents remain
authoritative. Review the CIS terms of use before redistributing benchmark
material.
