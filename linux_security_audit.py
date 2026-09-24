#!/usr/bin/env python3
"""Linux Security Audit: read-only CIS assessment with m365-assessor format reports.

Run locally on the host being assessed. On Linux servers, including Proxmox VE:

    sudo python3 linux_security_audit.py --client-name Contoso --output /var/tmp/assessments

On VMware ESXi, from the ESXi Shell or an SSH session as root:

    python /vmfs/volumes/datastore1/linux-security-audit/linux_security_audit.py \
        --client-name Contoso --output /vmfs/volumes/datastore1/assessments

The platform is detected automatically. Only the Python 3.8+ standard library
is required, which matches the interpreter bundled with ESXi 7.0 and 8.0.
"""

import sys

if sys.version_info < (3, 8):
    sys.exit("linux-security-audit requires Python 3.8 or newer.")

import os  # noqa: E402
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lsa.cli import main  # noqa: E402

if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Output piped into a command that stopped reading (e.g. '--list-checks | head').
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
