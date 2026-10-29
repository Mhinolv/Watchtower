"""Durable local state in SQLite.

The data folder is `~/Library/Application Support/Watchtower/` (mode 0700).
Set WATCHTOWER_DATA_DIR to use another folder, for example in tests.
Every file in it is mode 0600. Scan data never goes into the repo.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Callable, Iterable

from .models import (
    REFRESH_STATUSES,
    SCHEMA_VERSION,
    CoverageRecord,
    ItemRecord,
    RefreshRecord,
    owner_error,
    utc_now,
)

DB_NAME = "watchtower.sqlite3"
DIR_MODE = 0o700
FILE_MODE = 0o600


class StoreError(Exception):
    """The store cannot be used. The message is one short sentence for the owner."""

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.detail = detail


def default_data_dir() -> Path:
    env = os.environ.get("WATCHTOWER_DATA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / "Library" / "Application Support" / "Watchtower"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` if needed and set it to 0700."""
    path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    os.chmod(path, DIR_MODE)
    return path


def ensure_private_file(path: Path) -> Path:
    """Create `path` if needed and set it to 0600 before anything writes to it."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR, FILE_MODE)
    os.close(fd)
    os.chmod(path, FILE_MODE)
    return path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refreshes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS coverage (
    source TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    state TEXT NOT NULL,
    last_success_at TEXT,
    error TEXT,
    detail TEXT,
    refresh_id INTEGER NOT NULL REFERENCES refreshes(id)
);
CREATE TABLE IF NOT EXISTS items (
    source TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    kind TEXT,
    installed_version TEXT,
    latest_version TEXT,
    project TEXT,
    seen_at TEXT,
    error TEXT,
    detail TEXT,
    PRIMARY KEY (source, id)
);
"""


class Store:
    """Refresh records, coverage for each source, and the current item list."""

    def __init__(self, data_dir: Path | None = None, clock: Callable[[], str] = utc_now):
        self.data_dir = ensure_private_dir(Path(data_dir) if data_dir else default_data_dir())
        self.path = ensure_private_file(self.data_dir / DB_NAME)
        self.clock = clock
        # Autocommit mode. Writes use explicit BEGIN IMMEDIATE / COMMIT.
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _migrate(self) -> None:
        self.db.executescript(_SCHEMA)
        row = self.db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
            )
        elif int(row["value"]) > SCHEMA_VERSION:
            raise StoreError(
                "A newer Watchtower wrote this data.",
                f"Store schema {row['value']} is newer than engine schema {SCHEMA_VERSION}.",
            )

    # Refresh lifecycle

    def begin_refresh(self) -> RefreshRecord:
        """Start a refresh. An older refresh that never finished is marked failed."""
        now = self.clock()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "UPDATE refreshes SET status = 'failed', finished_at = ?, error = ? "
                "WHERE status = 'running'",
                (now, "Refresh did not finish."),
            )
            cur = self.db.execute(
                "INSERT INTO refreshes (status, started_at) VALUES ('running', ?)", (now,)
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return self.refresh(cur.lastrowid)

    def finish_refresh(
        self,
        refresh_id: int,
        status: str,
        coverage: Iterable[CoverageRecord] = (),
        items: Iterable[ItemRecord] = (),
        error: str | None = None,
        detail: str | None = None,
    ) -> RefreshRecord:
        """Save the result of a refresh in one transaction.

        - `last_complete_at` changes only when `status` is `complete`.
        - A source with `complete` coverage gets `last_success_at` = now and its items are replaced.
        - Other sources keep their previous items, and reported items are added or updated.
        - A source that this refresh does not report becomes `stale`.
        If the save fails, nothing from it is kept and the refresh is marked failed.
        """
        if status not in REFRESH_STATUSES or status == "running":
            raise ValueError(f"cannot finish a refresh with status {status!r}")
        current = self.refresh(refresh_id)
        if current is None or current.status != "running":
            raise ValueError(f"refresh {refresh_id} is not running")
        coverage = list(coverage)
        items = list(items)
        now = self.clock()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "UPDATE refreshes SET status = ?, finished_at = ?, error = ?, detail = ? WHERE id = ?",
                (status, now, owner_error(error), detail, refresh_id),
            )
            self._write_coverage(refresh_id, now, coverage)
            self._write_items(now, coverage, items)
            self.db.execute("COMMIT")
        except BaseException as exc:
            self.db.execute("ROLLBACK")
            try:
                self.db.execute(
                    "UPDATE refreshes SET status = 'failed', finished_at = ?, error = ?, detail = ? "
                    "WHERE id = ?",
                    (now, "Watchtower could not save the refresh results.", repr(exc), refresh_id),
                )
            except sqlite3.Error:
                pass  # The next begin_refresh marks it failed. Keep the first error.
            raise
        return self.refresh(refresh_id)

    def _write_coverage(self, refresh_id: int, now: str, coverage: list[CoverageRecord]) -> None:
        reported = {c.source for c in coverage}
        for c in coverage:
            row = self.db.execute(
                "SELECT last_success_at FROM coverage WHERE source = ?", (c.source,)
            ).fetchone()
            last_success = now if c.state == "complete" else (row["last_success_at"] if row else None)
            self.db.execute(
                "INSERT INTO coverage (source, label, state, last_success_at, error, detail, refresh_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (source) DO UPDATE SET label = excluded.label, state = excluded.state, "
                "last_success_at = excluded.last_success_at, error = excluded.error, "
                "detail = excluded.detail, refresh_id = excluded.refresh_id",
                (c.source, c.label, c.state, last_success, owner_error(c.error), c.detail, refresh_id),
            )
        for row in self.db.execute(
            "SELECT source FROM coverage WHERE state IN ('complete', 'partial')"
        ).fetchall():
            if row["source"] not in reported:
                self.db.execute("UPDATE coverage SET state = 'stale' WHERE source = ?", (row["source"],))

    def _write_items(self, now: str, coverage: list[CoverageRecord], items: list[ItemRecord]) -> None:
        for c in coverage:
            if c.state == "complete":
                self.db.execute("DELETE FROM items WHERE source = ?", (c.source,))
        for i in items:
            self.db.execute(
                "INSERT OR REPLACE INTO items (source, id, name, state, kind, installed_version, "
                "latest_version, project, seen_at, error, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    i.source, i.id, i.name, i.state, i.kind, i.installed_version,
                    i.latest_version, i.project, now, owner_error(i.error), i.detail,
                ),
            )

    # Reads

    def refresh(self, refresh_id: int) -> RefreshRecord | None:
        row = self.db.execute("SELECT * FROM refreshes WHERE id = ?", (refresh_id,)).fetchone()
        if row is None:
            return None
        last = self.db.execute(
            "SELECT finished_at FROM refreshes WHERE status = 'complete' AND id <= ? "
            "ORDER BY id DESC LIMIT 1",
            (refresh_id,),
        ).fetchone()
        return RefreshRecord(
            id=row["id"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            last_complete_at=last["finished_at"] if last else None,
            error=row["error"],
            detail=row["detail"],
        )

    def latest_refresh(self) -> RefreshRecord | None:
        row = self.db.execute("SELECT MAX(id) AS id FROM refreshes").fetchone()
        return self.refresh(row["id"]) if row["id"] is not None else None

    def coverage(self) -> list[CoverageRecord]:
        rows = self.db.execute(
            "SELECT source, label, state, last_success_at, error, detail FROM coverage ORDER BY source"
        ).fetchall()
        return [CoverageRecord(**dict(r)) for r in rows]

    def items(self) -> list[ItemRecord]:
        rows = self.db.execute(
            "SELECT id, source, name, state, kind, installed_version, latest_version, project, "
            "seen_at, error, detail FROM items ORDER BY source, id"
        ).fetchall()
        return [ItemRecord(**dict(r)) for r in rows]

    def state(self) -> dict:
        """The current state, as the `state` CLI command prints it (without the envelope)."""
        latest = self.latest_refresh()
        return {
            "refresh": latest.to_dict() if latest else None,
            "coverage": [c.to_dict() for c in self.coverage()],
            "items": [i.to_dict() for i in self.items()],
        }
