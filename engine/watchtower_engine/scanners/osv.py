"""Offline OSV-Scanner lockfile scan for the active projects.

The engine runs the pinned scanner (release_pin.py) with `--offline`: it reads the local
databases and makes no network requests. It scans `package-lock.json` (npm), `uv.lock`
(PyPI) and `Cargo.lock` (crates.io, #15) only. It never runs fix, resolve or call-analysis commands.
Scanner output is untrusted data: the engine checks its shape and keeps only known fields.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .. import net
from ..discovery import Project, display_path
from ..feeds.osv_database import STALE_AFTER_DAYS, Database, age_days, db_root, update_database
from ..models import CoverageRecord, utc_now
from .release_pin import Asset, ChecksumError, ScannerUnavailable, asset_for, ensure_scanner, verify

SOURCE = "osv"
LABEL = "OSV"
SCAN_TIMEOUT_SECONDS = 600

# Lockfile name -> OSV ecosystem. Only these are scanned.
SUPPORTED = {"package-lock.json": "npm", "uv.lock": "PyPI", "Cargo.lock": "crates.io"}
# Lockfiles that Watchtower lists but does not scan yet.
NOT_SUPPORTED = frozenset({
    "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "poetry.lock", "Pipfile.lock",
    "Package.resolved", "go.sum", "Gemfile.lock", "composer.lock",
})
# Exit codes of OSV-Scanner: 0 no findings, 1 findings, 128 no packages. 127 is a general error.
OK_EXIT_CODES = (0, 1, 128)

# Owner-facing text from the #7 Design notes.
TEXT_STALE = "OSV database is {days} days old. Results can miss new advisories."
TEXT_MISSING = "OSV database is not downloaded. Projects were not scanned."
TEXT_CHECKSUM = "OSV-Scanner failed its checksum. Watchtower did not run it."
TEXT_UNREADABLE = "OSV-Scanner output was not readable."
TEXT_NO_SCANNER = "OSV-Scanner is not downloaded. Projects were not scanned."
TEXT_SCAN_FAILED = "OSV-Scanner stopped with an error."
TEXT_NOT_UPDATED = "OSV database did not update. Results use the last copy."
NOTE_NO_LOCKFILE = "No lockfile. Watchtower scans lockfiles only."
NOTE_NOT_SUPPORTED = "not supported yet"
NOTE_NO_DATABASE = "OSV database is not downloaded"
NOTE_NOT_RUN = "OSV-Scanner did not run"


@dataclass
class Lockfile:
    path: str  # Relative to the project, for example `web/package-lock.json`.
    ecosystem: str | None
    status: str  # scanned, not_scanned, not_supported
    note: str | None = None
    full_path: str = field(default="", repr=False)

    def to_dict(self) -> dict:
        return {"path": self.path, "ecosystem": self.ecosystem, "status": self.status, "note": self.note}


@dataclass
class ProjectScan:
    name: str
    path: str  # Display path, for example ~/Projects/web.
    lockfiles: list[Lockfile]
    note: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "path": self.path, "note": self.note,
                "lockfiles": [lf.to_dict() for lf in self.lockfiles]}


@dataclass
class Match:
    """One vulnerable package in one lockfile. The fields that #8 needs."""

    project: str
    project_path: str
    lockfile: str
    name: str
    ecosystem: str
    version: str
    dependency_path: list[str] | None  # None: OSV-Scanner gives no path for these lockfiles.
    advisory_ids: list[str]
    aliases: list[str]
    # One entry for each advisory group: {ids, title, severity, fixed_in}. See `advisory_groups`.
    advisories: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OsvResult:
    coverage: CoverageRecord
    projects: list[ProjectScan]
    matches: list[Match]
    databases: list[Database]

    def to_dict(self) -> dict:
        return {
            "coverage": self.coverage.to_dict(),
            "databases": [d.to_dict() for d in self.databases],
            "projects": [p.to_dict() for p in self.projects],
            "matches": [m.to_dict() for m in self.matches],
        }


class UnreadableOutput(ValueError):
    pass


# Plan


def plan(projects: list[Project]) -> list[ProjectScan]:
    """Lockfile rows for each active project. Manifests that are not lockfiles are ignored."""
    scans = []
    for p in projects:
        if p.state != "active":
            continue
        lockfiles = []
        for rel in p.manifests:
            base = os.path.basename(rel)
            if base in SUPPORTED:
                lockfiles.append(Lockfile(rel, SUPPORTED[base], "not_scanned", NOTE_NOT_RUN,
                                          os.path.join(p.real_path or p.path, rel)))
            elif base in NOT_SUPPORTED:
                lockfiles.append(Lockfile(rel, None, "not_supported", NOTE_NOT_SUPPORTED))
        scans.append(ProjectScan(p.name, display_path(p.path), lockfiles,
                                 None if lockfiles else NOTE_NO_LOCKFILE))
    return scans


# Scanner output


def _strings(value, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise UnreadableOutput(f"{what} is not a list of strings")
    return value


def severity_label(score) -> str:
    """CVSS base score (a number or text such as `7.2`) or a GHSA word to critical/high/medium/low/unknown."""
    if isinstance(score, str):
        word = score.strip().lower()
        if word in ("critical", "high", "low"):
            return word
        if word == "moderate" or word == "medium":
            return "medium"
        try:
            score = float(word)
        except ValueError:
            return "unknown"
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "unknown"


SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    """`fixed` versions that the advisory lists for package `name`. Ignores any other shape."""
    def norm(n: str) -> str:
        return n.lower().replace("_", "-")

    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(pkg, dict) or norm(str(pkg.get("name", ""))) != norm(name):
            continue
        for rng in affected.get("ranges") or []:
            for event in (rng.get("events") if isinstance(rng, dict) else None) or []:
                value = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(value, str) and value:
                    fixed.append(value)
    return fixed


def advisory_groups(entry: dict, name: str) -> list[dict]:
    """One dict for each group of advisories that are the same issue.

    `ids` holds every id of the group, with aliases (CVE, GHSA, OSV). Scanner output is untrusted:
    optional fields with the wrong type are ignored.
    """
    vulns = {v["id"]: v for v in entry.get("vulnerabilities") or []}
    groups = [g for g in entry.get("groups") or [] if isinstance(g, dict) and isinstance(g.get("ids"), list)]
    if not groups:
        groups = [{"ids": [i], "aliases": v.get("aliases") or []} for i, v in vulns.items()]
    out = []
    for g in groups:
        members = [vulns[i] for i in g["ids"] if i in vulns]
        ids = {i for i in g["ids"] if isinstance(i, str)}
        for source in (g.get("aliases") or [], *[m.get("aliases") or [] for m in members]):
            ids.update(a for a in source if isinstance(a, str))
        title = next((m["summary"].strip() for m in members
                      if isinstance(m.get("summary"), str) and m["summary"].strip()), None)
        labels = [severity_label(g.get("max_severity"))]
        for m in members:
            specific = m.get("database_specific")
            labels.append(severity_label(specific.get("severity") if isinstance(specific, dict) else None))
        fixed = sorted({f for m in members for f in _fixed_versions(m, name)})
        if ids:
            out.append({"ids": sorted(ids), "title": title,
                        "severity": min(labels, key=SEVERITY_ORDER.index), "fixed_in": fixed})
    return out


def parse_output(text: str) -> dict[str, list[dict]]:
    """Map each scanned source path to its vulnerable packages. Raises UnreadableOutput."""
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise UnreadableOutput(f"not JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        raise UnreadableOutput("no results list")
    found: dict[str, list[dict]] = {}
    for result in data.get("results") or []:
        source = result.get("source") if isinstance(result, dict) else None
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise UnreadableOutput("result without a source path")
        packages = result.get("packages") or []
        if not isinstance(packages, list):
            raise UnreadableOutput("packages is not a list")
        rows = found.setdefault(os.path.realpath(source["path"]), [])
        for entry in packages:
            pkg = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(pkg, dict) or not all(
                isinstance(pkg.get(k), str) for k in ("name", "version", "ecosystem")
            ):
                raise UnreadableOutput("package without name, version and ecosystem")
            vulns = entry.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                raise UnreadableOutput("vulnerabilities is not a list")
            ids, aliases = set(), set()
            for v in vulns:
                if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                    raise UnreadableOutput("vulnerability without an id")
                ids.add(v["id"])
                aliases.update(_strings(v.get("aliases") or [], "aliases"))
            for group in entry.get("groups") or []:
                if isinstance(group, dict):
                    aliases.update(_strings(group.get("aliases") or [], "group aliases"))
            if ids:
                rows.append({
                    "name": pkg["name"], "ecosystem": pkg["ecosystem"], "version": pkg["version"],
                    "advisory_ids": sorted(ids), "aliases": sorted(aliases - ids),
                    "advisories": advisory_groups(entry, pkg["name"]),
                })
    return found


# Run


def run_scanner(scanner: Path, asset: Asset, lockfiles: list[str], data_dir: Path,
                run: Callable = subprocess.run) -> str:
    """Run one offline scan of `lockfiles`. Returns stdout. Checks the digest again first."""
    verify(scanner, asset)
    args = [str(scanner), "scan", "source", "--offline", "--format", "json"]
    for path in lockfiles:
        args += ["--lockfile", path]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", ""),
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(db_root(data_dir)),
    }
    proc = run(args, capture_output=True, text=True, timeout=SCAN_TIMEOUT_SECONDS, env=env,
               stdin=subprocess.DEVNULL, cwd=str(scanner.parent))
    if proc.returncode not in OK_EXIT_CODES:
        raise RuntimeError(f"osv-scanner exited {proc.returncode}: {proc.stderr.strip()[-500:]}")
    return proc.stdout


def _failed(error: str, detail: str | None, projects, databases=()) -> OsvResult:
    return OsvResult(CoverageRecord(SOURCE, LABEL, "failed", error=error, detail=detail),
                     projects, [], list(databases))


def collect(
    data_dir: Path,
    projects: list[Project],
    asset: Asset | None = None,
    download: net.Download | None = None,
    run: Callable = subprocess.run,
    now: Callable[[], str] = utc_now,
) -> OsvResult:
    """Scan the supported lockfiles of the active projects against the local OSV databases."""
    scans = plan(projects)
    lockfiles = [lf for s in scans for lf in s.lockfiles if lf.ecosystem]
    if not lockfiles:
        return OsvResult(CoverageRecord(SOURCE, LABEL, "complete"), scans, [], [])

    # 1. The scanner. Check it first, so a bad scanner costs no database download.
    try:
        asset = asset or asset_for()
        scanner = ensure_scanner(data_dir, asset, download)
    except ChecksumError as exc:
        return _failed(TEXT_CHECKSUM, str(exc), scans)
    except ScannerUnavailable as exc:
        return _failed(TEXT_NO_SCANNER, str(exc), scans)

    # 2. The databases. Each refresh asks for a new copy.
    databases = [update_database(eco, data_dir, download, now)
                 for eco in sorted({lf.ecosystem for lf in lockfiles})]
    loaded = {d.ecosystem for d in databases if d.loaded}
    for lf in lockfiles:
        if lf.ecosystem not in loaded:
            lf.note = NOTE_NO_DATABASE
    ready = [lf for lf in lockfiles if lf.ecosystem in loaded]
    db_detail = "\n".join(d.detail for d in databases if d.detail) or None
    if not ready:
        return _failed(TEXT_MISSING, db_detail, scans, databases)

    # 3. One offline run for every ready lockfile.
    try:
        found = parse_output(run_scanner(scanner, asset, [lf.full_path for lf in ready], data_dir, run))
    except ChecksumError as exc:
        return _failed(TEXT_CHECKSUM, str(exc), scans, databases)
    except UnreadableOutput as exc:
        return _failed(TEXT_UNREADABLE, str(exc), scans, databases)
    except Exception as exc:
        return _failed(TEXT_SCAN_FAILED, repr(exc), scans, databases)

    matches = []
    ready_ids = {id(lf) for lf in ready}
    for scan in scans:
        for lf in scan.lockfiles:
            if id(lf) not in ready_ids:
                continue
            lf.status, lf.note = "scanned", None
            for row in found.get(os.path.realpath(lf.full_path), []):
                matches.append(Match(project=scan.name, project_path=scan.path, lockfile=lf.path,
                                     dependency_path=None, **row))

    # 4. Coverage. A missing database beats a stale one, which beats a failed update.
    used = [d for d in databases if d.loaded]
    oldest = min(d.fetched_at for d in used)
    days = age_days(oldest, now())
    if len(ready) < len(lockfiles):
        state, error = "partial", TEXT_MISSING
    elif days > STALE_AFTER_DAYS:
        state, error = "stale", TEXT_STALE.format(days=int(days))
    elif any(not d.fresh for d in used):
        state, error = "complete", TEXT_NOT_UPDATED
    else:
        state, error = "complete", None
    coverage = CoverageRecord(SOURCE, LABEL, state, error=error, detail=db_detail, source_at=oldest)
    return OsvResult(coverage, scans, matches, databases)
