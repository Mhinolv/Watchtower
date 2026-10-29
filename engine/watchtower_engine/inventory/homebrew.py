"""Installed Homebrew formulae and casks, compared with the public catalogs.

The engine runs one read-only command: `brew info --json=v2 --installed`, with
HOMEBREW_NO_AUTO_UPDATE=1 so that Homebrew does not update itself or its taps.
It never runs `brew upgrade`, `brew update`, builds or install scripts.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..feeds.homebrew import Catalog, Fetch, http_fetch, load_catalog
from ..models import CoverageRecord, ItemRecord, utc_now

SOURCE = "homebrew"
LABEL = "Homebrew"
CORE_TAPS = {"formula": "homebrew/core", "cask": "homebrew/cask"}
BREW_PATHS = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
BREW_TIMEOUT_SECONDS = 120
BREW_ENV = {
    "HOMEBREW_NO_AUTO_UPDATE": "1",
    "HOMEBREW_NO_ANALYTICS": "1",
    "HOMEBREW_NO_ENV_HINTS": "1",
    "HOMEBREW_NO_COLOR": "1",
}

# Owner-facing text. The Design notes of #3 fix these strings.
NOTE_PINNED = "Pinned with brew pin. Watchtower does not update pinned items."
NOTE_SELF_UPDATE = "This app updates itself. The Homebrew version can be behind the app."
NOTE_NO_TAP = "Watchtower cannot check tap {tap}."
NOTE_NO_TAP_NAME = "Watchtower cannot check a package that has no tap."
NOTE_NOT_IN_CATALOG = "The Homebrew catalog has no entry for {name}."
NOTE_NO_VERSION = "Watchtower cannot compare this version."
ERROR_CATALOG = "Homebrew catalog did not load."
ERROR_NOT_INSTALLED = "Homebrew is not installed."
ERROR_LIST = "Homebrew did not list the installed packages."


@dataclass
class SourceResult:
    coverage: CoverageRecord
    items: list[ItemRecord]

    def to_dict(self) -> dict:
        return {"coverage": self.coverage.to_dict(), "items": [i.to_dict() for i in self.items]}


# Versions


def version_key(version: str) -> tuple:
    """Order Homebrew versions: numbers compare as numbers, `_1` revisions and `,build` parts count."""
    return tuple((1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[A-Za-z]+", version))


def _comparable(version: str | None) -> bool:
    return bool(version) and version != "latest" and not version.startswith("HEAD")


def _newer(candidate: str, installed: str) -> bool:
    return candidate != installed and version_key(candidate) > version_key(installed)


# Installed list


def find_brew() -> str | None:
    found = shutil.which("brew")
    if found:
        return found
    return next((p for p in BREW_PATHS if os.access(p, os.X_OK)), None)


def read_installed(brew: str, run: Callable = subprocess.run) -> dict:
    """Return the parsed `brew info --json=v2 --installed` output."""
    proc = run(
        [brew, "info", "--json=v2", "--installed"],
        capture_output=True,
        text=True,
        timeout=BREW_TIMEOUT_SECONDS,
        env={**os.environ, **BREW_ENV},
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"brew info exited {proc.returncode}: {proc.stderr.strip()[-500:]}")
    data = json.loads(proc.stdout)
    if not isinstance(data, dict):
        raise ValueError("brew info output is not a JSON object")
    return data


def _current_keg(formula: dict) -> str | None:
    """The linked keg, else the newest installed version. Older retained kegs are ignored."""
    versions = [i.get("version") for i in formula.get("installed") or [] if i.get("version")]
    if formula.get("linked_keg") in versions:
        return formula["linked_keg"]
    return max(versions, key=version_key, default=None)


# Items


def _base(kind: str, entry: dict, installed: str | None) -> ItemRecord:
    name = entry.get("name") if kind == "formula" else entry.get("token")
    full = entry.get("full_name") if kind == "formula" else entry.get("full_token")
    tap = entry.get("tap")
    return ItemRecord(
        id=f"{kind}:{full or name}",
        source=SOURCE,
        name=name,
        state="unknown",
        kind=kind,
        installed_version=installed,
        origin=tap if tap and tap != CORE_TAPS[kind] else None,
    )


def _apply_catalog(item: ItemRecord, kind: str, tap: str | None, found: dict | None,
                   candidate: str | None, catalog: Catalog) -> ItemRecord:
    """Set state, latest version, source age and error from one catalog entry."""
    if tap != CORE_TAPS[kind]:
        item.state = "manual"
        item.note = NOTE_NO_TAP.format(tap=tap) if tap else NOTE_NO_TAP_NAME
        return item
    if not catalog.loaded:
        item.state = "error"
        item.error = catalog.error
        item.detail = catalog.detail
        return item
    item.source_at = catalog.fetched_at
    if not catalog.fresh:
        # Old data keeps its badge. The UI adds "Version data is from <source_at>."
        item.error = catalog.error
        item.detail = catalog.detail
    if found is None:
        item.note = NOTE_NOT_IN_CATALOG.format(name=item.name)
        return item
    item.latest_version = candidate
    return item


def formula_item(formula: dict, catalog: Catalog) -> ItemRecord:
    installed = _current_keg(formula)
    item = _base("formula", formula, installed)
    tap = formula.get("tap")
    found = catalog.lookup(formula.get("full_name"), formula.get("name"))
    candidate = None
    if found and found.get("stable"):
        candidate = found["stable"] + (f"_{found['revision']}" if found.get("revision") else "")
    _apply_catalog(item, "formula", tap, found, candidate, catalog)
    if item.state == "manual" or item.state == "error":
        return item
    if formula.get("pinned"):
        item.state = "pinned"
        item.note = NOTE_PINNED
    elif found is None:
        pass
    elif not (_comparable(installed) and _comparable(candidate)):
        item.note = NOTE_NO_VERSION
    else:
        item.state = "update_available" if _newer(candidate, installed) else "up_to_date"
    return item


def cask_item(cask: dict, catalog: Catalog) -> ItemRecord:
    installed = cask.get("installed")
    item = _base("cask", cask, installed)
    tap = cask.get("tap")
    found = catalog.lookup(cask.get("full_token"), cask.get("token"))
    candidate = found.get("version") if found else None
    _apply_catalog(item, "cask", tap, found, candidate, catalog)
    if item.state == "manual" or item.state == "error" or found is None:
        return item
    auto = found.get("auto_updates") or cask.get("auto_updates")
    if not (_comparable(installed) and _comparable(candidate)):
        item.note = NOTE_NO_VERSION
    elif auto and installed != candidate:
        # The app may be newer than the Homebrew receipt. Do not claim an update.
        item.note = NOTE_SELF_UPDATE
    else:
        item.state = "update_available" if _newer(candidate, installed) else "up_to_date"
    return item


def _sort_key(item: ItemRecord) -> tuple:
    return (item.state != "update_available", item.name.lower(), item.id)


# Collect


def collect(
    data_dir: Path,
    brew: str | None = None,
    run: Callable = subprocess.run,
    fetch: Fetch = http_fetch,
    now: Callable[[], str] = utc_now,
) -> SourceResult:
    """Read installed formulae and casks and compare them with the catalogs.

    Coverage is `complete` only if the installed list and every needed catalog loaded fresh.
    """
    brew = brew or find_brew()
    if brew is None:
        return SourceResult(CoverageRecord(SOURCE, LABEL, "not_run", error=ERROR_NOT_INSTALLED), [])
    try:
        installed = read_installed(brew, run)
    except Exception as exc:
        return SourceResult(CoverageRecord(SOURCE, LABEL, "failed", error=ERROR_LIST, detail=repr(exc)), [])

    formulae = installed.get("formulae") or []
    casks = [c for c in installed.get("casks") or [] if c.get("installed")]
    catalogs = {}
    if formulae:
        catalogs["formula"] = load_catalog("formula", data_dir, fetch, now)
    if casks:
        catalogs["cask"] = load_catalog("cask", data_dir, fetch, now)

    items = [formula_item(f, catalogs["formula"]) for f in formulae]
    items += [cask_item(c, catalogs["cask"]) for c in casks]
    items.sort(key=_sort_key)

    stale = [c for c in catalogs.values() if not c.fresh]
    if not stale:
        coverage = CoverageRecord(SOURCE, LABEL, "complete")
    else:
        state = "failed" if all(not c.loaded for c in catalogs.values()) else "partial"
        detail = "\n".join(c.detail for c in stale if c.detail)
        coverage = CoverageRecord(SOURCE, LABEL, state, error=ERROR_CATALOG, detail=detail)
    return SourceResult(coverage, items)
