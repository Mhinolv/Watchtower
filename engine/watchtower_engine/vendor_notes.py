"""Vendor assessments of findings (#18): backports and affected ranges from a vendor, for example Debian.

A vendor note is extra evidence next to OSV and GitHub. It never replaces them and it never changes
the status of a finding: only a complete scan resolves a finding (see findings.py).

Rules:
- The owner adds a note with its source URL, retrieval time and confidence.
- A note is never deleted. A withdrawn note keeps its text and gets `withdrawn_at`.
- A note is stale after 90 days (owner decision, 2026-10-29). The app shows that from `retrieved_at`
  and `checked_at`. When the owner checks the source again, `checked_at` changes. `retrieved_at` stays.
- Note text comes from vendor pages: it is untrusted data. It is stored and shown as plain text, cut to
  a fixed length, with control characters removed. Only http and https source URLs are kept.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

VERDICTS = ("fixed", "not_affected", "affected")
CONFIDENCES = ("high", "medium", "low")
LIMITS = {"vendor": 80, "statement": 500, "affected_range": 120, "source_url": 500}

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_notes (
    id INTEGER PRIMARY KEY,
    seq INTEGER NOT NULL REFERENCES findings(seq),
    vendor TEXT NOT NULL,
    verdict TEXT NOT NULL,
    statement TEXT NOT NULL,
    affected_range TEXT,
    confidence TEXT NOT NULL,
    source_url TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    added_at TEXT NOT NULL,
    checked_at TEXT,
    withdrawn_at TEXT
);
"""

ERROR_UNKNOWN = "There is no vendor note {id}."
ERROR_VERDICT = "The vendor verdict is fixed, not-affected or affected."
ERROR_CONFIDENCE = "The confidence is high, medium or low."
ERROR_URL = "The source must be an http or https address."
ERROR_EMPTY = "The vendor note needs a {field}."
ERROR_TIME = "The retrieval time must look like 2026-10-29T09:12:00Z."
ERROR_FUTURE = "The retrieval time cannot be in the future."
ERROR_WITHDRAWN = "{id} is withdrawn. Add a new vendor note."


class VendorNoteError(Exception):
    """The note cannot be saved. The message is one short sentence."""


@dataclass
class VendorNote:
    id: str
    vendor: str
    verdict: str
    statement: str
    affected_range: str | None
    confidence: str
    source_url: str
    retrieved_at: str
    added_at: str
    checked_at: str | None
    withdrawn_at: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def migrate(db: sqlite3.Connection) -> None:
    db.executescript(SCHEMA)


def note_id(number: int) -> str:
    return f"VN-{number:04d}"


def parse_note_id(text: str) -> int:
    head, _, tail = text.strip().upper().partition("-")
    if head != "VN" or not tail.isdigit():
        raise VendorNoteError(ERROR_UNKNOWN.format(id=text.strip() or "id"))
    return int(tail)


def clean_text(text: str | None, field: str) -> str | None:
    """Plain text on one line: control characters become spaces, runs of space collapse, cut to the limit."""
    if text is None:
        return None
    text = re.sub(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069]", " ", text)
    text = " ".join(text.split())
    limit = LIMITS[field]
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def clean_url(text: str) -> str:
    url = (text or "").strip()
    parts = urlsplit(url)
    if (parts.scheme.lower() not in ("http", "https") or not parts.hostname or len(url) > LIMITS["source_url"]
            or any(c.isspace() or ord(c) < 32 for c in url)):
        raise VendorNoteError(ERROR_URL)
    return url


def _verdict(text: str) -> str:
    value = (text or "").strip().lower().replace("-", "_").replace(" ", "_")
    if value not in VERDICTS:
        raise VendorNoteError(ERROR_VERDICT)
    return value


def add(db: sqlite3.Connection, seq: int, now: str, *, vendor: str, verdict: str, statement: str,
        confidence: str, source_url: str, affected_range: str | None = None,
        retrieved_at: str | None = None) -> str:
    """Save one note for the finding `seq`. Returns its id. The finding itself does not change."""
    fields = {"vendor": clean_text(vendor, "vendor"), "statement": clean_text(statement, "statement")}
    for field, value in fields.items():
        if not value:
            raise VendorNoteError(ERROR_EMPTY.format(field=field))
    level = (confidence or "").strip().lower()
    if level not in CONFIDENCES:
        raise VendorNoteError(ERROR_CONFIDENCE)
    retrieved = (retrieved_at or now).strip()
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", retrieved):
        raise VendorNoteError(ERROR_TIME)
    if retrieved > now:
        raise VendorNoteError(ERROR_FUTURE)
    cur = db.execute(
        "INSERT INTO vendor_notes (seq, vendor, verdict, statement, affected_range, confidence, source_url, "
        "retrieved_at, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, fields["vendor"], _verdict(verdict), fields["statement"],
         clean_text(affected_range, "affected_range") or None, level, clean_url(source_url), retrieved, now),
    )
    return note_id(cur.lastrowid)


def _note_row(db: sqlite3.Connection, text: str) -> sqlite3.Row:
    row = db.execute("SELECT * FROM vendor_notes WHERE id = ?", (parse_note_id(text),)).fetchone()
    if row is None:
        raise VendorNoteError(ERROR_UNKNOWN.format(id=text.strip()))
    return row


def withdraw(db: sqlite3.Connection, text: str, now: str) -> int:
    """Mark a note withdrawn. It stays in the history. Returns the finding seq."""
    row = _note_row(db, text)
    db.execute("UPDATE vendor_notes SET withdrawn_at = COALESCE(withdrawn_at, ?) WHERE id = ?", (now, row["id"]))
    return row["seq"]


def check(db: sqlite3.Connection, text: str, now: str) -> int:
    """The owner checked the source again: the 90 days start again. Returns the finding seq."""
    row = _note_row(db, text)
    if row["withdrawn_at"]:
        raise VendorNoteError(ERROR_WITHDRAWN.format(id=note_id(row["id"])))
    db.execute("UPDATE vendor_notes SET checked_at = ? WHERE id = ?", (now, row["id"]))
    return row["seq"]


def move(db: sqlite3.Connection, from_seq: int, to_seq: int) -> None:
    """Two findings merged (findings._merge). The notes follow the finding that stays."""
    db.execute("UPDATE vendor_notes SET seq = ? WHERE seq = ?", (to_seq, from_seq))


def for_finding(db: sqlite3.Connection, seq: int) -> list[VendorNote]:
    """Every note of one finding, newest retrieval first. Withdrawn notes are in the list."""
    rows = db.execute("SELECT * FROM vendor_notes WHERE seq = ? ORDER BY retrieved_at DESC, id DESC", (seq,))
    return [VendorNote(note_id(r["id"]), r["vendor"], r["verdict"], r["statement"], r["affected_range"],
                       r["confidence"], r["source_url"], r["retrieved_at"], r["added_at"], r["checked_at"],
                       r["withdrawn_at"]) for r in rows]
