"""Stable findings from the OSV scans.

A finding is one advisory (with all its aliases) for one package. It has a stable id
`SEC-0001` that no later scan changes or reuses. Its `paths` list every local lockfile that
has the package at a vulnerable version. The tables live in the same SQLite file as the store.

Rules:
- A scan adds new findings, adds or updates paths and moves `last_seen`.
- Aliases merge: a scan that shares any advisory id with a finding of the same package updates it.
- Only a complete scan resolves a finding: OSV coverage `complete` with no error, and the lockfile
  of every path scanned. A partial, stale or failed scan never removes a path or resolves a finding.
- A resolved finding that comes back is open again with the same id.
- The owner can defer a finding (7 or 30 days) or move it to the backlog. A scan never changes that.
  A deferral that has ended counts as open again.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


SOURCE_LABEL = "OSV"
STATUSES = ("open", "deferred", "backlog", "resolved")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
DEFER_DAYS = (7, 30)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    seq INTEGER PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    title TEXT,
    severity TEXT NOT NULL,
    advisory_ids TEXT NOT NULL,
    fixed_versions TEXT NOT NULL,
    status TEXT NOT NULL,
    deferred_until TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    resolved_scan_at TEXT,
    source_at TEXT
);
CREATE TABLE IF NOT EXISTS finding_paths (
    seq INTEGER NOT NULL REFERENCES findings(seq),
    project TEXT NOT NULL,
    project_path TEXT NOT NULL,
    lockfile TEXT NOT NULL,
    version TEXT NOT NULL,
    dependency_path TEXT,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (seq, project_path, lockfile, version)
);
"""

NEXT_STEPS_FIXED = "Update {package} to {fixed} or later in the lockfile."
NEXT_STEPS_NO_FIX = "Check the advisory for a workaround. No fixed version is known."
NEXT_STEP_RESTART = "Restart the dev server after the update."
ERROR_UNKNOWN = "There is no finding {id}."
ERROR_RESOLVED = "{id} is resolved. Only a new scan can open it again."
ERROR_DAYS = "A deferral is 7 or 30 days."


class FindingError(Exception):
    """The owner asked for something that cannot happen. The message is one short sentence."""


def version_key(version: str) -> tuple:
    """Order versions: numbers compare as numbers. Not a full semver, enough to pick a fix."""
    return tuple((1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[A-Za-z]+", version))


def sec_id(seq: int) -> str:
    return f"SEC-{seq:04d}"


def parse_sec_id(text: str) -> int:
    head, _, tail = text.strip().upper().partition("-")
    if head != "SEC" or not tail.isdigit():
        raise FindingError(ERROR_UNKNOWN.format(id=text.strip() or "id"))
    return int(tail)


def _parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FindingPath:
    project: str
    project_path: str
    lockfile: str
    version: str
    dependency_path: list[str] | None
    # Why `Update…` is off for this lockfile, for example a uv project with no environment (#11).
    update_block: str | None = None

    def to_dict(self) -> dict:
        return {"project": self.project, "project_path": self.project_path, "lockfile": self.lockfile,
                "version": self.version, "dependency_path": self.dependency_path,
                "update_block": self.update_block}


@dataclass
class Finding:
    id: str
    ecosystem: str
    package: str
    title: str
    severity: str
    advisory_ids: list[str]
    fixed_in: str | None
    status: str
    deferred_until: str | None
    first_seen: str
    last_seen: str
    resolved_at: str | None
    resolved_scan_at: str | None
    source: str
    source_at: str | None
    paths: list[FindingPath]
    next_steps: list[str]
    # Listed in CISA KEV: {cve, date_added, due_date, ransomware}. None if not listed.
    kev: dict | None = None
    # GitHub lists the package as malware: {advisory_id}. None if not.
    malware: dict | None = None
    # When the source withdrew the advisory. None if it did not.
    withdrawn_at: str | None = None
    # EPSS (#57) for the finding's CVE: {cve, score, percentile, score_date, fetched_at}. `score` is None if the
    # CVE is not in the file. None if the finding has no CVE or EPSS never loaded.
    epss: dict | None = None

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        data["paths"] = [p.to_dict() for p in self.paths]
        return data


# Columns added after the first release of the table (#9). Old stores get them with ALTER TABLE.
ADDED_COLUMNS = ("kev", "malware", "withdrawn_at", "epss")


def migrate(db: sqlite3.Connection) -> None:
    db.executescript(SCHEMA)
    have = {r["name"] for r in db.execute("PRAGMA table_info(findings)")}
    for column in ADDED_COLUMNS:
        if column not in have:
            db.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")


# Scan -> findings


def _worse(a: str, b: str) -> str:
    return a if SEVERITIES.index(a) <= SEVERITIES.index(b) else b


def _observations(matches) -> list[dict]:
    """One dict for each (package, advisory group) with the paths where it was found."""
    merged: list[dict] = []
    for m in matches:
        groups = m.advisories or ([{"ids": sorted(set(m.advisory_ids) | set(m.aliases)), "title": None,
                                    "severity": "unknown", "fixed_in": []}] if m.advisory_ids else [])
        path = FindingPath(m.project, m.project_path, m.lockfile, m.version, m.dependency_path)
        for g in groups:
            ids = set(g["ids"])
            hits = [o for o in merged if o["ecosystem"] == m.ecosystem and o["package"] == m.name
                    and o["ids"] & ids]
            if not hits:
                merged.append({"ecosystem": m.ecosystem, "package": m.name, "ids": ids, "title": g["title"],
                               "severity": g["severity"], "fixed": set(g["fixed_in"]), "paths": [path]})
                continue
            first = hits[0]
            for other in hits[1:]:  # This group joins two earlier ones.
                first["ids"] |= other["ids"]
                first["fixed"] |= other["fixed"]
                first["paths"] += other["paths"]
                first["title"] = first["title"] or other["title"]
                first["severity"] = _worse(first["severity"], other["severity"])
                merged.remove(other)
            first["ids"] |= ids
            first["fixed"] |= set(g["fixed_in"])
            first["title"] = first["title"] or g["title"]
            first["severity"] = _worse(first["severity"], g["severity"])
            first["paths"].append(path)
    return merged


def apply_scan(db: sqlite3.Connection, now: str, scan) -> None:
    """Update the findings from one OSV result. Call it inside the transaction of the refresh."""
    coverage = scan.coverage
    if coverage.state == "failed":
        return  # No scan took place. Nothing is learned and nothing is lost.
    source_at = coverage.source_at
    seen: set[tuple[int, str, str, str]] = set()  # (id, project path, lockfile, version) seen now

    for obs in _observations(scan.matches):
        rows = db.execute(
            "SELECT * FROM findings WHERE ecosystem = ? AND package = ? ORDER BY seq",
            (obs["ecosystem"], obs["package"]),
        ).fetchall()
        hits = [r for r in rows if set(json.loads(r["advisory_ids"])) & obs["ids"]]
        if not hits:
            seq = _next_seq(db)
            db.execute(
                "INSERT INTO findings (seq, ecosystem, package, title, severity, advisory_ids, "
                "fixed_versions, status, first_seen, last_seen, source_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
                (seq, obs["ecosystem"], obs["package"], obs["title"], obs["severity"],
                 json.dumps(sorted(obs["ids"])), json.dumps(sorted(obs["fixed"])), now, now, source_at),
            )
        else:
            seq = _merge(db, hits, obs, now, source_at)
        for p in obs["paths"]:
            seen.add((seq, p.project_path, p.lockfile, p.version))
            db.execute(
                "INSERT INTO finding_paths (seq, project, project_path, lockfile, version, dependency_path, "
                "last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (seq, project_path, lockfile, version) DO UPDATE SET project = excluded.project, "
                "dependency_path = excluded.dependency_path, last_seen = excluded.last_seen",
                (seq, p.project, p.project_path, p.lockfile, p.version,
                 json.dumps(p.dependency_path) if p.dependency_path is not None else None, now),
            )

    if coverage.state == "complete" and coverage.error is None:
        _resolve(db, now, scan, seen)


def _next_seq(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT value FROM meta WHERE key = 'finding_seq'").fetchone()
    seq = int(row["value"]) + 1 if row else 1
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('finding_seq', ?)", (str(seq),))
    return seq


def _merge(db: sqlite3.Connection, hits: list[sqlite3.Row], obs: dict, now: str, source_at) -> int:
    """Fold `obs` and every finding in `hits` into the oldest one, which keeps its id."""
    keep = hits[0]
    ids, fixed = set(obs["ids"]), set(obs["fixed"])
    title, severity = keep["title"] or obs["title"], _worse(keep["severity"], obs["severity"])
    status = keep["status"]
    first_seen = keep["first_seen"]
    for row in hits:
        ids |= set(json.loads(row["advisory_ids"]))
        fixed |= set(json.loads(row["fixed_versions"]))
        title = title or row["title"]
        severity = _worse(severity, row["severity"])
        first_seen = min(first_seen, row["first_seen"])
        if row["seq"] != keep["seq"]:
            if row["status"] == "open":
                status = "open"
            db.execute("UPDATE OR IGNORE finding_paths SET seq = ? WHERE seq = ?", (keep["seq"], row["seq"]))
            db.execute("DELETE FROM finding_paths WHERE seq = ?", (row["seq"],))
            db.execute("DELETE FROM findings WHERE seq = ?", (row["seq"],))
    resolved = status == "resolved"
    if resolved:
        status = "open"  # It came back. The id stays.
    db.execute(
        "UPDATE findings SET title = ?, severity = ?, advisory_ids = ?, fixed_versions = ?, status = ?, "
        "first_seen = ?, last_seen = ?, source_at = ?, resolved_at = CASE WHEN ? THEN NULL ELSE resolved_at END, "
        "resolved_scan_at = CASE WHEN ? THEN NULL ELSE resolved_scan_at END, "
        "deferred_until = CASE WHEN ? = 'open' THEN NULL ELSE deferred_until END WHERE seq = ?",
        (title, severity, json.dumps(sorted(ids)), json.dumps(sorted(fixed)), status, first_seen, now,
         source_at, resolved, resolved, status, keep["seq"]),
    )
    return keep["seq"]


def _resolve(db: sqlite3.Connection, now: str, scan, seen: set[tuple[int, str, str, str]]) -> None:
    """Remove the paths that a scanned lockfile no longer shows. Resolve a finding left with none."""
    scanned = {(p.path, lf.path) for p in scan.projects for lf in p.lockfiles if lf.status == "scanned"}
    changed: set[int] = set()
    for row in db.execute("SELECT * FROM finding_paths").fetchall():
        key = (row["seq"], row["project_path"], row["lockfile"], row["version"])
        if (row["project_path"], row["lockfile"]) not in scanned or key in seen:
            continue  # No evidence for this lockfile, or the scan just saw it.
        db.execute("DELETE FROM finding_paths WHERE seq = ? AND project_path = ? AND lockfile = ? "
                   "AND version = ?", (row["seq"], row["project_path"], row["lockfile"], row["version"]))
        changed.add(row["seq"])
    for seq in changed:
        left = db.execute("SELECT COUNT(*) AS n FROM finding_paths WHERE seq = ?", (seq,)).fetchone()["n"]
        if left == 0:
            db.execute(
                "UPDATE findings SET status = 'resolved', deferred_until = NULL, resolved_at = ?, "
                "resolved_scan_at = ? WHERE seq = ? AND status != 'resolved'", (now, now, seq))


# Enrichment (#9)


def _epss_value(ids: list[str], epss) -> str | None:
    """The EPSS JSON of one finding: its CVE with the highest score. None if the finding has no CVE."""
    cves = sorted({i.strip().upper() for i in ids if i.strip().upper().startswith("CVE-")})
    if not cves:
        return None
    scored = [(epss.scores[c], c) for c in cves if c in epss.scores]
    (score, percentile), cve = max(scored) if scored else ((None, None), cves[0])
    return json.dumps({"cve": cve, "score": score, "percentile": percentile, "score_date": epss.score_date,
                       "fetched_at": epss.fetched_at}, sort_keys=True)


def apply_enrichment(db: sqlite3.Connection, kev=None, github=None, epss=None) -> None:
    """Set the KEV, malware, withdrawn and EPSS marks of the findings. Call it inside the refresh transaction.

    A feed that has no data leaves the old marks as they are. A mark is cleared only if the feed
    answered for every advisory id of the finding. EPSS data from the cache after a failed download still
    answers: earlier scores are never cleared.
    """
    for row in db.execute("SELECT seq, advisory_ids, kev, malware, withdrawn_at, epss FROM findings").fetchall():
        ids = json.loads(row["advisory_ids"])
        kev_value, malware_value, withdrawn = row["kev"], row["malware"], row["withdrawn_at"]
        epss_value = row["epss"]
        if epss is not None and epss.loaded:
            epss_value = _epss_value(ids, epss)
        if kev is not None and kev.loaded:
            hit = next((kev.entries[i.upper()] for i in ids if i.upper() in kev.entries), None)
            kev_value = json.dumps(hit, sort_keys=True) if hit else None
        if github is not None:
            verdict = github.assess(ids)
            if verdict.malware_id:
                malware_value = json.dumps({"advisory_id": verdict.malware_id})
            elif verdict.malware_known:
                malware_value = None
            if verdict.withdrawn_at:
                withdrawn = verdict.withdrawn_at
            elif verdict.withdrawn_known:
                withdrawn = None
        db.execute("UPDATE findings SET kev = ?, malware = ?, withdrawn_at = ?, epss = ? WHERE seq = ?",
                   (kev_value, malware_value, withdrawn, epss_value, row["seq"]))


# Owner actions


def _row(db: sqlite3.Connection, finding_id: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM findings WHERE seq = ?", (parse_sec_id(finding_id),)).fetchone()
    if row is None:
        raise FindingError(ERROR_UNKNOWN.format(id=finding_id.strip()))
    return row


def defer(db: sqlite3.Connection, finding_id: str, days: int, now: str) -> None:
    if days not in DEFER_DAYS:
        raise FindingError(ERROR_DAYS)
    row = _row(db, finding_id)
    if row["status"] == "resolved":
        raise FindingError(ERROR_RESOLVED.format(id=finding_id.strip().upper()))
    until = _format_time(_parse_time(now) + timedelta(days=days))
    db.execute("UPDATE findings SET status = 'deferred', deferred_until = ? WHERE seq = ?", (until, row["seq"]))


def move_to_backlog(db: sqlite3.Connection, finding_id: str) -> None:
    row = _row(db, finding_id)
    if row["status"] == "resolved":
        raise FindingError(ERROR_RESOLVED.format(id=finding_id.strip().upper()))
    db.execute("UPDATE findings SET status = 'backlog', deferred_until = NULL WHERE seq = ?", (row["seq"],))


def reopen(db: sqlite3.Connection, finding_id: str) -> None:
    """Take a deferred or backlog finding back to open."""
    row = _row(db, finding_id)
    if row["status"] == "resolved":
        raise FindingError(ERROR_RESOLVED.format(id=finding_id.strip().upper()))
    db.execute("UPDATE findings SET status = 'open', deferred_until = NULL WHERE seq = ?", (row["seq"],))


# Reads


def _fixed_in(fixed: list[str], versions: list[str]) -> str | None:
    """The lowest fixed version above every affected version, else the highest fixed version."""
    if not fixed:
        return None
    top = max((version_key(v) for v in versions), default=None)
    above = [f for f in fixed if top is None or version_key(f) > top]
    return min(above, key=version_key) if above else max(fixed, key=version_key)


def _next_steps(package: str, fixed_in: str | None, status: str) -> list[str]:
    if status == "resolved":
        return []
    if fixed_in is None:
        return [NEXT_STEPS_NO_FIX]
    return [NEXT_STEPS_FIXED.format(package=package, fixed=fixed_in), NEXT_STEP_RESTART]


def get(db: sqlite3.Connection, now: str, finding_id: str) -> Finding:
    return next(f for f in list_findings(db, now) if f.id == sec_id(parse_sec_id(finding_id)))


def list_findings(db: sqlite3.Connection, now: str) -> list[Finding]:
    """All findings, urgent first: severity, then newest `last_seen`, then id."""
    from .updates import npm as npm_updates  # Not at the top: the modules import the store.
    from .updates import requirements as req_updates
    from .updates import uv as uv_updates

    out = []
    for row in db.execute("SELECT * FROM findings").fetchall():
        paths = [
            FindingPath(p["project"], p["project_path"], p["lockfile"], p["version"],
                        json.loads(p["dependency_path"]) if p["dependency_path"] is not None else None,
                        uv_updates.block_reason(p["project_path"], p["lockfile"])
                        or npm_updates.block_reason(p["project_path"], p["lockfile"])
                        or req_updates.block_reason(p["project_path"], p["lockfile"]))
            for p in db.execute(
                "SELECT * FROM finding_paths WHERE seq = ? ORDER BY project, lockfile, version", (row["seq"],))
        ]
        status, until = row["status"], row["deferred_until"]
        if status == "deferred" and until and until <= now:
            status, until = "open", None  # The deferral ended.
        fixed_in = _fixed_in(json.loads(row["fixed_versions"]), [p.version for p in paths])
        out.append(Finding(
            id=sec_id(row["seq"]), ecosystem=row["ecosystem"], package=row["package"],
            title=row["title"] or f"Known vulnerability in {row['package']}", severity=row["severity"],
            advisory_ids=json.loads(row["advisory_ids"]), fixed_in=fixed_in, status=status,
            deferred_until=until, first_seen=row["first_seen"], last_seen=row["last_seen"],
            resolved_at=row["resolved_at"], resolved_scan_at=row["resolved_scan_at"], source=SOURCE_LABEL,
            source_at=row["source_at"], paths=paths, next_steps=_next_steps(row["package"], fixed_in, status),
            kev=json.loads(row["kev"]) if row["kev"] else None,
            malware=json.loads(row["malware"]) if row["malware"] else None,
            withdrawn_at=row["withdrawn_at"],
            epss=json.loads(row["epss"]) if row["epss"] else None,
        ))
    out.sort(key=lambda f: f.id)
    out.sort(key=lambda f: f.last_seen, reverse=True)
    out.sort(key=lambda f: SEVERITIES.index(f.severity) if f.severity in SEVERITIES else len(SEVERITIES))
    # Malware first, then known exploited, then EPSS high to low (no value last), then severity.
    out.sort(key=lambda f: (f.epss is None or f.epss["score"] is None, -((f.epss or {}).get("score") or 0)))
    out.sort(key=lambda f: f.kev is None)
    out.sort(key=lambda f: f.malware is None)
    return out
