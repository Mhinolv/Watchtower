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


@dataclass
class ScanSourceResult(SourceResult):
    """A source result that also carries the OSV scan. The store turns the scan into findings."""

    osv: object = None
    kev: object = None
    github: object = None
    epss: object = None


def advisory_id_groups(data_dir: Path, scans: list) -> list[set[str]]:
    """The advisory ids of each finding: from this refresh's scan and from the unresolved findings.

    Only these ids go to GitHub. No package name, version or path goes with them.
    """
    groups: list[set[str]] = []
    for scan in scans:
        for m in scan.matches:
            groups += [set(g["ids"]) for g in m.advisories] or [set(m.advisory_ids) | set(m.aliases)]
    with Store(data_dir) as store:
        groups += [set(f.advisory_ids) for f in store.findings() if f.status != "resolved"]
    return groups


def default_sources(data_dir: Path) -> list[Source]:
    """Homebrew, Applications, macOS, runtimes, SOFA, endoflife.date, running versions, OSV, KEV, GitHub and EPSS.

    `brew info` and the catalogs run once.
    """
    from .feeds import endoflife, epss, github, kev, sofa
    from . import settings
    from .inventory import apps, homebrew, macos, running, runtimes, sparkle
    from .scanners import osv
    from .scope import discovery_coverage, list_projects

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

    scans: list = []  # The OSV result of this refresh. The GitHub source reads its advisory ids.
    inventory: list = []  # The macOS, runtime and app items of this refresh. SOFA and endoflife.date update them in place.

    probed: list = []  # The app, Homebrew formula and runtime items. The running-version check updates them in place (#17).

    def keep(result: SourceResult) -> SourceResult:
        inventory.extend(result.items)
        probed.extend(result.items)
        return result

    def keep_probed(result: SourceResult) -> SourceResult:
        probed.extend(result.items)
        return result

    def running_source() -> SourceResult:
        return running.collect(probed, settings.check_running_versions(data_dir), run_once)

    def sofa_source() -> SourceResult:
        return SourceResult(sofa.check(inventory, data_dir), [])

    def endoflife_source() -> SourceResult:
        return SourceResult(endoflife.check(inventory, data_dir), [])

    def osv_source() -> SourceResult:
        found = list_projects(data_dir)
        result = osv.collect(data_dir, found.projects)
        scans.append(result)
        out = ScanSourceResult(result.coverage, [], result)
        out.extra_coverage = [discovery_coverage(found)]  # The Projects row: a cut walk is a gap (#88).
        return out

    def kev_source() -> SourceResult:
        data = kev.load(data_dir)
        return ScanSourceResult(data.coverage(), [], kev=data)

    def github_source() -> SourceResult:
        data = github.load(data_dir, advisory_id_groups(data_dir, scans))
        return ScanSourceResult(data.coverage(), [], github=data)

    def epss_source() -> SourceResult:
        # The request has no CVE. The ids only choose which rows to keep from the bulk file.
        cves = {i for group in advisory_id_groups(data_dir, scans) for i in group if epss.is_cve(i)}
        data = epss.load(data_dir, cves)
        return ScanSourceResult(data.coverage(), [], epss=data)

    return [
        Source(homebrew.SOURCE, homebrew.LABEL,
               lambda: keep_probed(homebrew.collect(data_dir, run=run_once, fetch=fetch_once))),
        Source(apps.SOURCE, apps.LABEL, lambda: keep(apps.collect_live(
            data_dir, run=run_once, fetch=fetch_once,
            sparkle_check=lambda targets: sparkle.check(targets, data_dir)))),
        Source(macos.SOURCE, macos.LABEL, lambda: keep(macos.collect())),
        Source(runtimes.SOURCE, runtimes.LABEL, lambda: keep(runtimes.collect())),
        Source(sofa.SOURCE, sofa.LABEL, sofa_source),
        Source(endoflife.SOURCE, endoflife.LABEL, endoflife_source),
        Source(running.SOURCE, running.LABEL, running_source),
        Source(osv.SOURCE, osv.LABEL, osv_source),
        Source(kev.SOURCE, kev.LABEL, kev_source),
        Source(github.SOURCE, github.LABEL, github_source),
        Source(epss.SOURCE, epss.LABEL, epss_source),
    ]


def run_refresh(store: Store, sources: list[Source], progress: Progress = lambda *a: None,
                guard: "StopOnSigterm | None" = None, actor: str = "app") -> dict:
    """Run the sources in order and save the result. Raises Cancelled after it saves a stop.

    `actor` marks the refresh record: `app` or the agent name (#111).
    """
    refresh = store.begin_refresh(actor)
    coverage: list[CoverageRecord] = []
    items: list[ItemRecord] = []
    scan = kev = github = epss = None
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
            coverage.extend(getattr(result, "extra_coverage", []))  # For example Sparkle feeds (#14).
            items.extend(result.items)
            scan = getattr(result, "osv", None) or scan
            kev = getattr(result, "kev", None) or kev
            github = getattr(result, "github", None) or github
            epss = getattr(result, "epss", None) or epss
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
    store.finish_refresh(refresh.id, status, coverage=coverage, items=items, error=error, detail=detail,
                         scan=scan, kev=kev, github=github, epss=epss)
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
