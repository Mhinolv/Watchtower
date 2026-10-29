"""One refresh: run every source, then save the result in the store.

The app runs `watchtower refresh`. Progress goes to stderr as JSON lines
({"schema_version", "progress": {"done", "total", "source"}}). The final state goes to stdout.
SIGTERM stops the refresh: it is saved as `cancelled` and every source keeps its previous data.
"""
from __future__ import annotations

import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .feeds.homebrew import http_fetch
from .inventory.homebrew import SourceResult
from .models import CoverageRecord, ItemRecord
from .store import Store

ERROR_SOURCE = "{label} check did not finish."
ERROR_ALL_FAILED = "No source finished."
ERROR_SOME_FAILED = "Some sources did not finish."


class Cancelled(Exception):
    """The owner stopped the refresh."""


@dataclass
class Source:
    source: str
    label: str
    collect: Callable[[], SourceResult]


Progress = Callable[[int, int, str], None]


def osv_items(result) -> list[ItemRecord]:
    """One `vulnerable` item for each package match. Findings (#8) will replace this view."""
    items = []
    for m in result.matches:
        items.append(ItemRecord(
            id=f"{m.ecosystem}:{m.name}@{m.version}:{m.project}/{m.lockfile}",
            source="osv",
            name=m.name,
            state="vulnerable",
            kind=m.ecosystem,
            installed_version=m.version,
            project=m.project,
            attributes={"lockfile": m.lockfile, "advisories": ", ".join(m.advisory_ids),
                        "aliases": ", ".join(m.aliases)},
        ))
    return items


def default_sources(data_dir: Path) -> list[Source]:
    """Homebrew, Applications, macOS and OSV. `brew info` and the catalogs run once."""
    from .inventory import apps, homebrew, macos
    from .scanners import osv
    from .scope import list_projects

    runs: dict[tuple, object] = {}
    fetches: dict[str, object] = {}

    def run_once(args, **kwargs):
        key = tuple(args)
        if key not in runs:
            runs[key] = subprocess.run(args, **kwargs)
        return runs[key]

    def fetch_once(url, headers):
        if url not in fetches:
            fetches[url] = http_fetch(url, headers)
        return fetches[url]

    def osv_source() -> SourceResult:
        result = osv.collect(data_dir, list_projects(data_dir).projects)
        return SourceResult(result.coverage, osv_items(result))

    return [
        Source(homebrew.SOURCE, homebrew.LABEL,
               lambda: homebrew.collect(data_dir, run=run_once, fetch=fetch_once)),
        Source(apps.SOURCE, apps.LABEL, lambda: apps.collect_live(data_dir, run=run_once, fetch=fetch_once)),
        Source(macos.SOURCE, macos.LABEL, macos.collect),
        Source(osv.SOURCE, osv.LABEL, osv_source),
    ]


def run_refresh(store: Store, sources: list[Source], progress: Progress = lambda *a: None,
                guard: "StopOnSigterm | None" = None) -> dict:
    """Run the sources in order and save the result. Raises Cancelled after it saves a stop."""
    refresh = store.begin_refresh()
    coverage: list[CoverageRecord] = []
    items: list[ItemRecord] = []
    try:
        for done, src in enumerate(sources):
            progress(done, len(sources), src.label)
            try:
                result = src.collect()
            except Cancelled:
                raise
            except Exception as exc:  # One source must not stop the others.
                result = SourceResult(CoverageRecord(src.source, src.label, "failed",
                                                     error=ERROR_SOURCE.format(label=src.label),
                                                     detail=repr(exc)), [])
            coverage.append(result.coverage)
            items.extend(result.items)
        if guard:
            guard.armed = False  # From here on, a stop must not cut the save short.
        progress(len(sources), len(sources), "")
    except Cancelled:
        store.finish_refresh(refresh.id, "cancelled")
        raise
    failed = [c for c in coverage if c.state in ("failed", "partial")]
    if coverage and all(c.state == "failed" for c in coverage):
        status, error = "failed", ERROR_ALL_FAILED
    elif failed:
        status, error = "partial", ERROR_SOME_FAILED
    else:
        status, error = "complete", None
    detail = "\n".join(f"{c.source}: {c.error}" for c in failed if c.error) or None
    store.finish_refresh(refresh.id, status, coverage=coverage, items=items, error=error, detail=detail)
    return store.state()


class StopOnSigterm:
    """Turn SIGTERM into Cancelled while sources run. The final save is never cut short."""

    def __init__(self):
        self.armed = True

    def __enter__(self):
        self.previous = signal.signal(signal.SIGTERM, self._handle)
        return self

    def _handle(self, signum, frame):
        if self.armed:
            self.armed = False
            raise Cancelled()

    def __exit__(self, *exc):
        signal.signal(signal.SIGTERM, self.previous)
