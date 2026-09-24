"""Shared types and helpers for check providers.

A provider receives the :class:`~lsa.system.System` and the ``check`` object
from a benchmark definition and returns an :class:`Outcome`. Providers read
evidence only; they raise :class:`~lsa.system.EvidenceUnavailable` when a
required source cannot be read, which the engine reports as NOT_ASSESSED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from lsa.model import FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS
from lsa.system import EvidenceUnavailable, FileMeta, System

MAX_AFFECTED = 200


@dataclass
class Outcome:
    status: str
    observation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    affected: list[str] = field(default_factory=list)


Provider = Callable[[System, dict], Outcome]
Condition = Callable[[System, dict], "tuple[bool, str]"]
Source = Callable[[System], "list[str]"]

PROVIDERS: dict[str, Provider] = {}
CONDITIONS: dict[str, Condition] = {}
SOURCES: dict[str, Source] = {}


def provider(name: str) -> Callable[[Provider], Provider]:
    def register(function: Provider) -> Provider:
        if name in PROVIDERS:
            raise ValueError(f"Duplicate provider '{name}'")
        PROVIDERS[name] = function
        return function

    return register


def condition(name: str) -> Callable[[Condition], Condition]:
    def register(function: Condition) -> Condition:
        CONDITIONS[name] = function
        return function

    return register


def source(name: str) -> Callable[[Source], Source]:
    def register(function: Source) -> Source:
        SOURCES[name] = function
        return function

    return register


def passed(observation: str, **evidence: Any) -> Outcome:
    return Outcome(PASS, observation, evidence)


def failed(observation: str, affected: list[str] | None = None, **evidence: Any) -> Outcome:
    return Outcome(FAIL, observation, evidence, list(affected or []))


def not_applicable(observation: str, **evidence: Any) -> Outcome:
    return Outcome(NOT_APPLICABLE, observation, evidence)


def not_assessed(observation: str, **evidence: Any) -> Outcome:
    return Outcome(NOT_ASSESSED, observation, evidence)


def verdict(problems: list[str], success: str, prefix: str = "", affected: list[str] | None = None, **evidence: Any) -> Outcome:
    """PASS with ``success`` or FAIL listing every problem."""
    if problems:
        return failed(_sentence(prefix + "; ".join(problems)), affected or [], **evidence)
    return passed(success, **evidence)


def _sentence(text: str) -> str:
    text = text.strip()
    if not text:
        return text
    text = text[0].upper() + text[1:]
    return text if text.endswith(".") else text + "."


def cap(items: list[str], limit: int = MAX_AFFECTED) -> list[str]:
    if len(items) <= limit:
        return items
    return items[:limit] + [f"... and {len(items) - limit} more (see evidence)"]


def join_limited(items: list[str], limit: int = 10) -> str:
    items = list(items)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


# ---------------------------------------------------------------- permissions
def mode_mask(check: dict) -> int:
    """Permission bits that must not be set.

    Definitions give either ``max_mode`` ("0640 or more restrictive") or an
    explicit CIS ``mask``. Special bits are outside the mask, as in CIS.
    """
    if "mask" in check:
        return int(str(check["mask"]), 8)
    if "max_mode" in check:
        return 0o777 & ~int(str(check["max_mode"]), 8)
    return 0


def max_mode_text(mask: int) -> str:
    return format(0o777 & ~mask, "04o")


def permission_problems(
    system: System,
    meta: FileMeta,
    mask: int,
    owners: list[str] | None,
    groups: list[str] | None,
) -> list[str]:
    problems = []
    if mask and meta.permissions & mask:
        problems.append(f"mode {meta.octal} (should be {max_mode_text(mask)} or more restrictive)")
    if owners:
        owner = system.user_name(meta.uid)
        if owner not in owners:
            problems.append(f"owner {owner} (should be {' or '.join(owners)})")
    if groups:
        group = system.group_name(meta.gid)
        if group not in groups:
            problems.append(f"group {group} (should be {' or '.join(groups)})")
    return problems


def describe_meta(system: System, meta: FileMeta) -> dict[str, Any]:
    return {
        "path": meta.path,
        "mode": meta.octal,
        "owner": system.user_name(meta.uid),
        "group": system.group_name(meta.gid),
        "type": "directory" if meta.is_dir else "file" if meta.is_file else "other",
    }


# ------------------------------------------------------------------- targets
def resolve_targets(system: System, targets: list[dict]) -> tuple[list[str], list[str]]:
    """Expand target specifications into (existing paths, missing fixed paths)."""
    existing: list[str] = []
    missing: list[str] = []
    for target in targets:
        if "path" in target:
            path = target["path"]
            (existing if system.exists(path) else missing).append(path)
        elif "glob" in target:
            directory, _, pattern = target["glob"].rpartition("/")
            existing.extend(system.glob(directory or "/", pattern, files_only=bool(target.get("files_only"))))
        elif "find" in target:
            for name in target.get("names", ["*"]):
                existing.extend(
                    system.walk_files(
                        target["find"],
                        name_pattern=name,
                        max_depth=target.get("max_depth"),
                        follow_links=bool(target.get("follow_links")),
                    )
                )
        elif "source" in target:
            function = SOURCES.get(target["source"])
            if function is None:
                raise ValueError(f"Unknown path source '{target['source']}'")
            existing.extend(function(system))
        else:
            raise ValueError(f"Unsupported target specification: {target}")
    return list(dict.fromkeys(existing)), list(dict.fromkeys(missing))


# --------------------------------------------------------------------- values
TRUE_WORDS = {"1", "yes", "true", "on", "enable", "enabled", "y"}
FALSE_WORDS = {"0", "no", "false", "off", "disable", "disabled", "n"}


def as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = str(value).strip().strip("\"'").lower()
    if lowered in TRUE_WORDS:
        return True
    if lowered in FALSE_WORDS:
        return False
    return None


def as_int(value: Any) -> int | None:
    try:
        return int(str(value).strip().strip("\"'"))
    except (TypeError, ValueError):
        return None


def rule_ok(value: Any, rule: dict) -> bool:
    """Evaluate a value against a definition rule.

    Supported operators: equals (case-insensitive), in, min, max, range,
    positive, zero_or_min, not_equal, bool and present (any non-empty value).
    """
    op = rule["op"]
    if op == "present":
        return value is not None and str(value).strip() not in ("", "<unset>")
    if op == "equals":
        return value is not None and str(value).strip().lower() == str(rule["value"]).lower()
    if op == "in":
        return value is not None and str(value).strip().lower() in {str(v).lower() for v in rule["values"]}
    if op == "bool":
        return as_bool(value) is rule["value"]
    number = as_int(value)
    if op == "not_equal":
        if value is None:
            return True
        return number is None or number != int(rule["value"])
    if number is None:
        return False
    if op == "min":
        return number >= int(rule["value"])
    if op == "max":
        return number <= int(rule["value"])
    if op == "range":
        return int(rule["min"]) <= number <= int(rule["max"])
    if op == "positive":
        return number > 0
    if op == "zero_or_min":
        return number == 0 or number >= int(rule["value"])
    raise ValueError(f"Unsupported rule operator '{op}'")


def describe_rule(rule: dict) -> str:
    op = rule["op"]
    if op == "present":
        return "a configured value"
    if op == "equals":
        return f"{rule['value']}"
    if op == "in":
        return " or ".join(str(v) for v in rule["values"])
    if op == "bool":
        return "enabled" if rule["value"] else "disabled"
    if op == "min":
        return f"{rule['value']} or more"
    if op == "max":
        return f"{rule['value']} or less"
    if op == "range":
        return f"between {rule['min']} and {rule['max']}"
    if op == "positive":
        return "greater than 0"
    if op == "not_equal":
        return f"anything but {rule['value']}"
    if op == "zero_or_min":
        return f"0 (never) or {rule['value']} or more"
    return op


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def uncommented(lines: list[str]) -> list[str]:
    return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def os_identity_pattern(system: System) -> re.Pattern[str]:
    """Escape sequences and the OS identifier that banners must not disclose."""
    os_id = re.escape(system.os_id())
    return re.compile(r"(\\v|\\r|\\m|\\s|\b" + os_id + r"\b)", re.IGNORECASE)


def require_root(system: System, what: str) -> None:
    if not system.is_root:
        raise EvidenceUnavailable(f"{what} requires root privileges", "root")
