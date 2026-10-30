"""The update log: one row for every update attempt, in the store database (mode 0600).

A row records the command, the versions before and after, the output, and the result of
the verification. A row that stays `running` after its engine process ended reads as
`interrupted`.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from .models import owner_error
from .store import Store

# `lockfile_updated`: a Cargo update (#15). The lockfile is checked, nothing installed can be read.
# `pin_updated`: a requirements.txt pin of a package that `.venv` does not have (#96). Nothing was installed.
STATUSES = ("running", "verified", "not_verified", "failed", "plan_changed", "refused", "interrupted",
            "lockfile_updated", "pin_updated")
OUTPUT_MAX_CHARS = 256 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS update_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_key TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT,
    command TEXT NOT NULL,
    before_version TEXT,
    target_version TEXT,
    after_version TEXT,
    status TEXT NOT NULL,
    exit_code INTEGER,
    output TEXT NOT NULL DEFAULT '',
    error TEXT,
    manual_steps TEXT NOT NULL DEFAULT '[]',
    confirmed_major INTEGER NOT NULL DEFAULT 0,
    confirmed_scripts INTEGER NOT NULL DEFAULT 0,
    plan_id TEXT,
    pid INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    result_rows TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass
class Attempt:
    id: int
    item_key: str
    name: str
    kind: str | None
    command: list[str]
    before_version: str | None
    target_version: str | None
    after_version: str | None
    status: str
    exit_code: int | None
    output: str
    error: str | None
    manual_steps: list[str] = field(default_factory=list)
    confirmed_major: bool = False
    confirmed_scripts: bool = False
    plan_id: str | None = None
    started_at: str = ""
    finished_at: str | None = None
    # Lines for the result step, for example the lockfile and the installed version of a uv update.
    result_rows: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class UpdateLog:
    def __init__(self, store: Store):
        self.store = store
        self.db = store.db
        self.db.executescript(_SCHEMA)
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(update_attempts)")}
        if "result_rows" not in have:  # A log from before #11.
            self.db.execute("ALTER TABLE update_attempts ADD COLUMN result_rows TEXT NOT NULL DEFAULT '[]'")

    def begin(self, plan, confirmed_major: bool, confirmed_scripts: bool, status: str = "running",
              error: str | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO update_attempts (item_key, name, kind, command, before_version, target_version, "
            "status, error, manual_steps, confirmed_major, confirmed_scripts, plan_id, pid, started_at, "
            "finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (plan.item_key, plan.name, plan.kind, json.dumps(plan.command), plan.installed_version,
             plan.target_version, status, owner_error(error), json.dumps(plan.manual_steps),
             int(confirmed_major), int(confirmed_scripts), plan.id, os.getpid(), self.store.clock(),
             None if status == "running" else self.store.clock()),
        )
        return cur.lastrowid

    def finish(self, attempt_id: int, status: str, after: str | None, exit_code: int | None, output: str,
               error: str | None = None, result_rows: list[dict] | None = None) -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        self.db.execute(
            "UPDATE update_attempts SET status = ?, after_version = ?, exit_code = ?, output = ?, error = ?, "
            "finished_at = ?, result_rows = ? WHERE id = ?",
            (status, after, exit_code, output[-OUTPUT_MAX_CHARS:], owner_error(error), self.store.clock(),
             json.dumps(result_rows or []), attempt_id),
        )

    def attempts(self, limit: int = 500) -> list[Attempt]:
        rows = self.db.execute("SELECT * FROM update_attempts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            status = r["status"]
            if status == "running" and not _alive(r["pid"]):
                status = "interrupted"
            out.append(Attempt(
                id=r["id"], item_key=r["item_key"], name=r["name"], kind=r["kind"],
                command=json.loads(r["command"]), before_version=r["before_version"],
                target_version=r["target_version"], after_version=r["after_version"], status=status,
                exit_code=r["exit_code"], output=r["output"], error=r["error"],
                manual_steps=json.loads(r["manual_steps"]), confirmed_major=bool(r["confirmed_major"]),
                confirmed_scripts=bool(r["confirmed_scripts"]), plan_id=r["plan_id"],
                started_at=r["started_at"], finished_at=r["finished_at"],
                result_rows=json.loads(r["result_rows"] or "[]"),
            ))
        return out

    def get(self, attempt_id: int) -> Attempt:
        return next(a for a in self.attempts(limit=1_000_000) if a.id == attempt_id)
