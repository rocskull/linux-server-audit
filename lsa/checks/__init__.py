"""Check providers, applicability conditions and path sources.

Importing this package registers every provider so the engine can validate a
benchmark definition before any evidence is collected.
"""

from lsa.checks import (  # noqa: F401 - imported for registration
    access,
    accounts,
    auditd,
    conditions,
    content,
    esxi,
    filesystem,
    kernel,
    logs,
    network,
    packages,
    security,
    ssh,
)
from lsa.checks.common import CONDITIONS, PROVIDERS, SOURCES, Outcome

__all__ = ["CONDITIONS", "PROVIDERS", "SOURCES", "Outcome"]
