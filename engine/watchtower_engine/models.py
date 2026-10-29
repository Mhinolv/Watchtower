"""Records shared by the engine and the Swift app.

The JSON field names here are a contract with `Sources/WatchtowerCore/Models.swift`.
Do not rename them. Add new fields as optional and bump SCHEMA_VERSION only for
changes that old readers cannot ignore.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

SCHEMA_VERSION = 1

REFRESH_STATUSES = ("running", "complete", "partial", "failed", "cancelled")
COVERAGE_STATES = ("complete", "partial", "failed", "stale", "not_run")
ITEM_STATES = (
    "up_to_date",
    "update_available",
    "vulnerable",
    "unknown",
    "error",
    "pinned",
    "manual",
)

# Paths inside these roots may appear in an owner-facing `error`. Others are redacted.
DEFAULT_SCAN_ROOTS = ("~/Projects", "~/Real", "~/Applications", "/Applications")

ERROR_MAX_CHARS = 80


def utc_now() -> str:
    """Current time as ISO 8601 UTC with second precision, for example 2026-10-29T19:56:37Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(value: str, allowed: tuple[str, ...], field: str) -> None:
    if value not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}, not {value!r}")


# An absolute or home-relative path that starts a token, without a final "." or ":".
# Excludes "and/or" and URLs.
_PATH_RE = re.compile(r"(?<![\w.:/~])~?/[^\s'\"`,;()\[\]]*[^\s'\"`,;()\[\].:]")


def _under_roots(path: str, roots: tuple[str, ...]) -> bool:
    full = os.path.normpath(os.path.expanduser(path))
    for root in roots:
        base = os.path.normpath(os.path.expanduser(root))
        if full == base or full.startswith(base + os.sep):
            return True
    return False


def owner_error(text: str | None, roots: tuple[str, ...] = DEFAULT_SCAN_ROOTS) -> str | None:
    """Make `text` safe for the `error` field.

    One line, ERROR_MAX_CHARS or fewer, and no paths from outside the scan roots.
    Put the full text in `detail` instead.
    """
    if text is None:
        return None
    line = " ".join(text.split())
    line = _PATH_RE.sub(lambda m: m.group(0) if _under_roots(m.group(0), roots) else "<path>", line)
    if len(line) > ERROR_MAX_CHARS:
        line = line[: ERROR_MAX_CHARS - 3].rstrip() + "..."
    return line or None


@dataclass
class RefreshRecord:
    id: int
    status: str
    started_at: str
    finished_at: str | None = None
    # Finish time of the newest `complete` refresh up to this one. Only a complete refresh changes it.
    last_complete_at: str | None = None
    error: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        _check(self.status, REFRESH_STATUSES, "status")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CoverageRecord:
    source: str
    label: str
    state: str
    last_success_at: str | None = None
    error: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        _check(self.state, COVERAGE_STATES, "state")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ItemRecord:
    id: str
    source: str
    name: str
    state: str
    kind: str | None = None
    installed_version: str | None = None
    latest_version: str | None = None
    project: str | None = None
    seen_at: str | None = None
    error: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        _check(self.state, ITEM_STATES, "state")

    def to_dict(self) -> dict:
        return asdict(self)
