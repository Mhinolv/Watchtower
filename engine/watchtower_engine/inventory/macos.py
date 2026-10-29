"""The macOS version and build, read from SystemVersion.plist.

The engine reads one file. It starts no program, so it does not call `sw_vers`.
"""
from __future__ import annotations

from pathlib import Path

from ..models import CoverageRecord, ItemRecord
from .homebrew import SourceResult
from .plist import read_plist, text

SOURCE = "macos"
LABEL = "macOS"
SYSTEM_VERSION_PLIST = Path("/System/Library/CoreServices/SystemVersion.plist")

NOTE_UPDATE = "Update macOS in System Settings."
ERROR_UNREADABLE = "macOS version could not be read."


def collect(plist_path: str | Path = SYSTEM_VERSION_PLIST) -> SourceResult:
    """One item for macOS. The `build` attribute holds the build, for example `24B83`."""
    try:
        info = read_plist(plist_path)
        version = text(info.get("ProductVersion"))
        build = text(info.get("ProductBuildVersion"))
        if version is None:
            raise ValueError("ProductVersion is missing")
    except (OSError, ValueError) as exc:
        return SourceResult(
            CoverageRecord(SOURCE, LABEL, "failed", error=ERROR_UNREADABLE, detail=repr(exc)), []
        )
    extra = text(info.get("ProductVersionExtra"))  # A Rapid Security Response, for example "(a)"
    attributes = {"build": build} if build else {}
    if extra:
        attributes["extra"] = extra
    item = ItemRecord(
        id="macos",
        source=SOURCE,
        name="macOS",
        state="manual",
        kind="os",
        installed_version=f"{version} {extra}" if extra else version,
        note=NOTE_UPDATE,
        attributes=attributes,
    )
    return SourceResult(CoverageRecord(SOURCE, LABEL, "complete"), [item])
