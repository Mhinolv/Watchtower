"""Incident records, the sources that were checked, and the review windows. Saved in the store database.

Rules (owner decisions 2026-10-29 and the Design notes of #12):
- The check runs on demand. A refresh does not run it and it does not run a refresh.
- A review window ends now. It starts 48 hours before the end of the last complete review, or 7 days
  back if there is none. If the last complete review is older than that, the days between are a gap:
  they are shown, and no review covers them.
- A review is complete only if every source of the check finished. A failed source makes it partial:
  the incidents of the other sources are saved, and the label keeps the end date of the last complete review.
- A record never leaves the table because a feed stopped listing it. Nothing here resolves a record.
- A record keeps the strongest status it ever got. A later check does not lower it.
- An incident does not need a CVE. A quiet feed is not proof that no breach happened.
- Statuses: `confirmed` (the vendor says so in its own feed), `possible` (the service matches, impact on the
  owner is not known), `unconfirmed` (no primary source). Nothing here says that the owner is affected.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, Iterable

from ..models import utc_now
from .sources import SOURCES, Cancelled, Item, Source, SourceError, fetch_items

if TYPE_CHECKING:
    from ..feeds.homebrew import Fetch

STATUSES = ("confirmed", "possible", "unconfirmed")
WINDOW_FIRST_DAYS = 7
WINDOW_OVERLAP_HOURS = 48
GAP_KEEP_DAYS = 30
ERROR_SOURCE = "{label}: check failed. The review is not complete."

CONFIRM_PHRASES = (
    "we have confirmed", "we confirmed", "we identified", "we detected", "unauthorized access",
    "was exploited", "been exploited", "actively exploited", "in the wild", "compromised", "security incident",
    "data breach", "were stolen", "was stolen",
)
INCIDENT_WORDS = (
    "breach", "incident", "leak", "phishing", "campaign", "attack", "exploit", "compromis", "unauthorized",
    "vulnerab", "token", "credential", "malware", "ransom", "hijack", "zero-day", "0-day", "stolen", "takeover",
    "exposed",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    seq INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    guid TEXT NOT NULL,
    service TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    published TEXT,
    status TEXT NOT NULL,
    source_name TEXT NOT NULL,
    url TEXT,
    cves TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (source, guid)
);
CREATE TABLE IF NOT EXISTS incident_sources (
    source TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    state TEXT NOT NULL,
    last_success_at TEXT,
    error TEXT,
    note TEXT,
    detail TEXT,
    checked_at TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    state TEXT NOT NULL,
    gap_start TEXT,
    gap_end TEXT
);
"""


def migrate(db: sqlite3.Connection) -> None:
    db.executescript(SCHEMA)


def inc_id(seq: int) -> str:
    return f"INC-{seq:04d}"


# Time


def parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Window:
    start: str
    end: str
    gap_start: str | None = None  # Dates `YYYY-MM-DD`: days that no review covers.
    gap_end: str | None = None


def next_window(last_complete_end: str | None, now: str) -> Window:
    """The window of a check that starts now. See the module text."""
    end = parse_time(now)
    cap = end - timedelta(days=WINDOW_FIRST_DAYS)
    if last_complete_end is None:
        return Window(format_time(cap), now)
    last = parse_time(last_complete_end)
    start = last - timedelta(hours=WINDOW_OVERLAP_HOURS)
    if start >= cap:
        return Window(format_time(start), now)
    gap_start, gap_end = last.date(), cap.date() - timedelta(days=1)
    if gap_start > gap_end:
        return Window(format_time(cap), now)
    return Window(format_time(cap), now, gap_start.isoformat(), gap_end.isoformat())


# Status


def classify(source: Source, title: str, summary: str) -> str | None:
    """The status of an item, or None if it does not read like an incident.

    The text is untrusted. It is only searched for words. Only a primary source can confirm.
    Every item of a notice source (a vendor security release) is a record: it is `possible` unless the text
    says that the vendor knows of an exploit.
    """
    text = f"{title} {summary}".lower()
    if not source.notice and not any(word in text for word in INCIDENT_WORDS):
        return None
    if not source.primary:
        return "unconfirmed"
    return "confirmed" if any(phrase in text for phrase in CONFIRM_PHRASES) else "possible"


def _stronger(a: str, b: str) -> str:
    return a if STATUSES.index(a) <= STATUSES.index(b) else b


# Check


@dataclass
class SourceResult:
    source: Source
    items: list[Item] | None = None  # None: the check failed.
    reason: str | None = None
    detail: str | None = None


Progress = Callable[[int, int, str], None]


def run_check(
    db: sqlite3.Connection,
    now: Callable[[], str] = utc_now,
    fetch: "Fetch | None" = None,
    sources: Iterable[Source] = SOURCES,
    selected: Iterable[str] | None = None,
    progress: Progress = lambda *a: None,
) -> dict:
    """Check the selected sources, save the result in one transaction, return the incident state.

    All requests finish before anything is saved. If the check is stopped (`Cancelled` from `progress`),
    nothing is saved.
    """
    configured = list(sources)
    chosen = [s for s in configured if selected is None or s.key in set(selected)]
    started = now()
    results: list[SourceResult] = []
    for done, source in enumerate(chosen):
        progress(done, len(chosen), source.label)
        try:
            results.append(SourceResult(source, fetch_items(source, fetch)))
        except SourceError as exc:
            results.append(SourceResult(source, None, str(exc), f"GET {source.url}: {exc.__cause__!r}"
                                        if exc.__cause__ else f"GET {source.url}: {exc}"))
    progress(len(chosen), len(chosen), "")
    finished = now()

    last = last_complete_review(db)
    window = next_window(last["window_end"] if last else None, finished)
    all_ok = all(r.items is not None for r in results)
    complete = all_ok and len(chosen) == len(configured)
    state = "complete" if complete else ("failed" if results and not any(r.items is not None for r in results)
                                          else "partial")
    db.execute("BEGIN IMMEDIATE")
    try:
        for r in results:
            _save_source(db, r, finished)
            if r.items is not None:
                _save_items(db, r.source, r.items, window, finished)
        db.execute(
            "INSERT INTO reviews (started_at, finished_at, window_start, window_end, state, gap_start, gap_end) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (started, finished, window.start, window.end, state,
             window.gap_start if complete else None, window.gap_end if complete else None))
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    return incident_state(db, configured, finished)


def _save_source(db: sqlite3.Connection, r: SourceResult, now: str) -> None:
    old = db.execute("SELECT last_success_at FROM incident_sources WHERE source = ?", (r.source.key,)).fetchone()
    if r.items is not None:
        values = ("complete", now, None, None, None)
    else:
        values = ("failed", old["last_success_at"] if old else None, ERROR_SOURCE.format(label=r.source.label),
                  r.reason, r.detail)
    db.execute(
        "INSERT INTO incident_sources (source, label, state, last_success_at, error, note, detail, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (source) DO UPDATE SET label = excluded.label, "
        "state = excluded.state, last_success_at = excluded.last_success_at, error = excluded.error, "
        "note = excluded.note, detail = excluded.detail, checked_at = excluded.checked_at",
        (r.source.key, r.source.label, *values, now))


def _next_seq(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT value FROM meta WHERE key = 'incident_seq'").fetchone()
    seq = int(row["value"]) + 1 if row else 1
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('incident_seq', ?)", (str(seq),))
    return seq


def _save_items(db: sqlite3.Connection, source: Source, items: list[Item], window: Window, now: str) -> None:
    for item in items:
        status = classify(source, item.title, item.summary)
        if status is None:
            continue  # Not an incident.
        row = db.execute("SELECT seq, status, cves FROM incidents WHERE source = ? AND guid = ?",
                         (source.key, item.guid)).fetchone()
        if row is None:
            if item.published is not None and item.published < window.start[:10]:
                continue  # Older than this review. A record that is already saved may still be updated.
            db.execute(
                "INSERT INTO incidents (seq, source, guid, service, title, summary, published, status, source_name, "
                "url, cves, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_next_seq(db), source.key, item.guid, source.service, item.title, item.summary, item.published,
                 status, source.source_name, item.url, json.dumps(item.cves), now, now))
        else:  # Keep the text. Raise the status, never lower it. Add CVEs.
            cves = sorted(set(json.loads(row["cves"])) | set(item.cves))
            db.execute("UPDATE incidents SET status = ?, cves = ?, last_seen = ? WHERE seq = ?",
                       (_stronger(row["status"], status), json.dumps(cves), now, row["seq"]))


# Read


def last_complete_review(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM reviews WHERE state = 'complete' ORDER BY id DESC LIMIT 1").fetchone()


def incident_state(db: sqlite3.Connection, sources: Iterable[Source] = SOURCES, now: str | None = None) -> dict:
    """The incidents, the sources, the last complete review and the gaps, for the app."""
    rows = db.execute("SELECT * FROM incidents").fetchall()
    incidents = [{
        "id": inc_id(r["seq"]), "source": r["source"], "service": r["service"], "title": r["title"],
        "summary": r["summary"], "published": r["published"], "status": r["status"],
        "source_name": r["source_name"], "url": r["url"], "cves": json.loads(r["cves"]),
        "first_seen": r["first_seen"], "last_seen": r["last_seen"],
    } for r in rows]
    incidents.sort(key=lambda i: i["id"])
    incidents.sort(key=lambda i: i["published"] or "", reverse=True)
    saved = {r["source"]: r for r in db.execute("SELECT * FROM incident_sources")}
    source_rows = []
    for s in sources:
        r = saved.get(s.key)
        source_rows.append({
            "source": s.key, "label": s.label, "state": r["state"] if r else "not_run",
            "last_success_at": r["last_success_at"] if r else None, "error": r["error"] if r else None,
            "note": r["note"] if r else None, "detail": r["detail"] if r else None,
            "checked_at": r["checked_at"] if r else None,
        })
    last = last_complete_review(db)
    attempt = db.execute("SELECT * FROM reviews ORDER BY id DESC LIMIT 1").fetchone()
    cutoff = None
    if now:
        cutoff = (parse_time(now) - timedelta(days=GAP_KEEP_DAYS)).date().isoformat()
    gaps = [{"start": r["gap_start"], "end": r["gap_end"]}
            for r in db.execute("SELECT gap_start, gap_end FROM reviews WHERE gap_start IS NOT NULL ORDER BY id")
            if cutoff is None or r["gap_end"] >= cutoff]
    return {
        "incidents": incidents,
        "sources": source_rows,
        "review": {
            "window_start": last["window_start"] if last else None,
            "window_end": last["window_end"] if last else None,
            "last_attempt_state": attempt["state"] if attempt else None,
            "last_attempt_at": attempt["finished_at"] if attempt else None,
        },
        "gaps": gaps,
    }
