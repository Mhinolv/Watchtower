"""Optional Claude web research (#19). The owner starts each run by hand. A refresh never runs it.

Owner decisions (2026-10-29): `claude -p`, a 5-minute limit, only WebSearch and WebFetch, no MCP, no hooks,
public topics only, no usage cap. Web-only claims stay `unconfirmed`.

What leaves the Mac: the fixed prompt below. It names the public topics (`GitHub`, `Google Gmail`, `Apple`) and
nothing else: no path, project, package, inventory, finding or credential. Claude Code then searches the web.

Isolation of the run (all of them, every run):
- `--safe-mode`: no CLAUDE.md, skills, plugins, hooks, MCP servers, custom commands or agents.
- `--tools WebSearch,WebFetch` and `--permission-mode dontAsk`: no other tool exists, and any other request is
  denied without a prompt. `--strict-mcp-config` with an empty MCP config: no MCP server.
- `--no-session-persistence`, `--disable-slash-commands`. The work folder is a new empty private folder in the
  data folder, deleted after the run. The environment has only PATH, HOME, USER, LOGNAME, TMPDIR and LANG.
- Auth is the owner's existing Claude Code login. The sign-in check reads only `loggedIn` of
  `claude auth status --json`. Nothing else of that output is kept or shown.

Claude's output is untrusted data, never instructions: only the JSON fields below are read, with type, length
and format checks. A claim is saved as `unconfirmed` with the source `Web research`. A vendor link that Claude
names is kept as the primary source to check, only if it is https on that vendor's own host. It never confirms a
claim by itself: only the vendor's own incident record (the #12 check) can do that.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from ..models import utc_now
from .sources import CVE_RE, SUMMARY_MAX, TITLE_MAX, clean_text

SOURCE = "claude"
SOURCE_NAME = "Web research"
CLAUDE_PATHS = ("~/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude")
TIME_LIMIT_SECONDS = 300
AUTH_TIMEOUT_SECONDS = 20
WINDOW_DAYS = 14
MAX_CLAIMS = 20
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
URL_MAX = 500

# The public topics, as sent, and the service column of the incident table.
TOPICS = (("GitHub", "GitHub"), ("Google Gmail", "Google / Gmail"), ("Apple", "Apple"))
# A vendor link counts as a primary source only on the vendor's own hosts (and their subdomains).
VENDOR_HOSTS = {
    "GitHub": ("github.com", "github.blog", "githubstatus.com"),
    "Google Gmail": ("google.com", "blog.google", "googleblog.com"),
    "Apple": ("apple.com",),
}
LIMITS_TEXT = "5 minutes. Web search and web fetch only. No MCP, no hooks."

# Owner-facing text (#19 Design notes).
TEXT_NOT_INSTALLED = "Install Claude Code to use Research."
TEXT_SIGNED_OUT = "Sign in to Claude Code, then try again."
TEXT_TIME_LIMIT = "Research stopped at 5 minutes. Nothing was saved."
TEXT_INVALID = "Research results were not valid. Nothing was saved."
TEXT_NO_CLAIMS = "No new claims found. This does not prove that no breach happened."
TEXT_FAILED = "Research did not finish. Nothing was saved."
TEXT_STOPPED = "Research was stopped. Nothing was saved."
TEXT_DONE = "{count} {claims} saved as Unconfirmed."

CLAIM_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["claims"],
    "properties": {"claims": {"type": "array", "maxItems": MAX_CLAIMS, "items": {
        "type": "object", "additionalProperties": False,
        "required": ["product", "title", "summary", "published", "url", "vendor_url"],
        "properties": {
            "product": {"type": "string", "enum": [t for t, _ in TOPICS]},
            "title": {"type": "string", "maxLength": TITLE_MAX},
            "summary": {"type": "string", "maxLength": SUMMARY_MAX},
            "published": {"type": ["string", "null"]},
            "url": {"type": ["string", "null"]},
            "vendor_url": {"type": ["string", "null"]},
        }}}},
}


def topics() -> list[str]:
    return [t for t, _ in TOPICS]


def prompt() -> str:
    """The whole text that Watchtower sends. Built from the fixed topics only."""
    names = ", ".join(topics())
    return (
        f"Find public news from the last {WINDOW_DAYS} days about security incidents, breaches, outages with "
        f"security impact, or actively exploited vulnerabilities for these products: {names}.\n"
        "Use web search and web fetch only. Report each distinct incident once.\n"
        f"For each incident give: the product (exactly one of: {names}), a short title, a one or two sentence "
        "summary, the publication date as YYYY-MM-DD if known, the URL of the article you read, and the URL of the "
        "vendor's own statement (a page on the vendor's own site) if you found one, else null.\n"
        "Do not guess. If you find nothing, return an empty list.\n"
    )


def find_claude() -> str | None:
    found = shutil.which("claude")
    if found:
        return found
    return next((p for p in (os.path.expanduser(x) for x in CLAUDE_PATHS) if os.access(p, os.X_OK)), None)


def claude_env() -> dict:
    """Only what Claude Code needs to find the owner's login. No variable of the owner's shell passes.

    The app starts the engine with no USER (#104). Claude Code needs it to find the login, so it comes from the
    process user id."""
    env = {k: os.environ[k] for k in ("HOME", "USER", "LOGNAME", "TMPDIR") if k in os.environ}
    if "USER" not in env or "LOGNAME" not in env:
        try:
            name = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            name = None
        if name:
            env.setdefault("USER", name)
            env.setdefault("LOGNAME", name)
    return env | {"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}


def command(claude: str) -> list[str]:
    return [claude, "-p", prompt(), "--output-format", "json", "--json-schema", json.dumps(CLAIM_SCHEMA),
            "--safe-mode", "--tools", "WebSearch,WebFetch", "--allowedTools", "WebSearch", "WebFetch",
            "--permission-mode", "dontAsk", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            "--no-session-persistence", "--disable-slash-commands"]


# Availability


Run = Callable[..., subprocess.CompletedProcess]


def status(claude: str | None = None, run: Run | None = None, find: Callable[[], str | None] | None = None) -> dict:
    """`ready`, `not_installed` or `signed_out`, with the topics and limits for the confirm sheet."""
    claude = claude or (find or find_claude)()
    run = run or subprocess.run
    state, text = "ready", None
    if claude is None:
        state, text = "not_installed", TEXT_NOT_INSTALLED
    elif not signed_in(claude, run):
        state, text = "signed_out", TEXT_SIGNED_OUT
    return {"state": state, "text": text, "topics": topics(), "limits": LIMITS_TEXT,
            "time_limit_seconds": TIME_LIMIT_SECONDS}


def signed_in(claude: str, run: Run = subprocess.run) -> bool:
    """Reads only the `loggedIn` field of `claude auth status --json`."""
    try:
        proc = run([claude, "auth", "status", "--json"], capture_output=True, text=True, timeout=AUTH_TIMEOUT_SECONDS,
                   env=claude_env(), stdin=subprocess.DEVNULL)
        data = json.loads(proc.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return isinstance(data, dict) and data.get("loggedIn") is True


# Output


class InvalidOutput(ValueError):
    pass


@dataclass
class Claim:
    product: str
    service: str
    title: str
    summary: str
    published: str | None
    url: str | None
    primary_url: str | None
    cves: list[str]

    @property
    def guid(self) -> str:
        key = f"{self.product}|{' '.join(self.title.lower().split())}|{self.url or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:24]


def safe_url(value, hosts: tuple[str, ...] | None = None) -> str | None:
    """An https URL with no credentials, or None. With `hosts`, the host must be one of them or below one."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    try:
        parts = urlparse(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username or parts.password or not host or len(url) > URL_MAX:
        return None
    if any(c.isspace() or ord(c) < 32 for c in url):
        return None
    if hosts is not None and not any(host == h or host.endswith("." + h) for h in hosts):
        return None
    return url


def parse_output(text: str) -> tuple[list[Claim], int]:
    """The valid claims of a `claude -p --output-format json` result, and the count of dropped claims.

    Raises InvalidOutput if the result is not a successful result with the claims object.
    """
    if len(text.encode()) > MAX_OUTPUT_BYTES:
        raise InvalidOutput("output is too large")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InvalidOutput("output is not JSON") from exc
    if not isinstance(data, dict) or data.get("type") != "result" or data.get("is_error") is not False:
        raise InvalidOutput("not a successful result")
    found = data.get("structured_output")
    if not isinstance(found, dict) and isinstance(data.get("result"), str):
        try:
            found = json.loads(data["result"])
        except ValueError:
            found = None
    rows = found.get("claims") if isinstance(found, dict) else None
    if not isinstance(rows, list):
        raise InvalidOutput("no claims list")
    services = dict(TOPICS)
    claims, dropped = [], 0
    for row in rows[:MAX_CLAIMS]:
        product = row.get("product") if isinstance(row, dict) else None
        title = clean_text(row.get("title"), TITLE_MAX) if isinstance(row, dict) else ""
        if product not in services or not title:
            dropped += 1
            continue
        summary = clean_text(row.get("summary"), SUMMARY_MAX)
        published = row.get("published") if isinstance(row.get("published"), str) else None
        published = published if published and re.fullmatch(r"\d{4}-\d{2}-\d{2}", published) else None
        cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {summary}")})
        claims.append(Claim(product, services[product], title, summary, published, safe_url(row.get("url")),
                            safe_url(row.get("vendor_url"), VENDOR_HOSTS[product]), cves))
    dropped += max(0, len(rows) - MAX_CLAIMS)
    return claims, dropped


# Run


@dataclass
class Outcome:
    state: str  # done, no_claims, time_limit, invalid, signed_out, not_installed, failed, stopped
    text: str
    claims: int = 0
    new: int = 0
    dropped: int = 0
    detail: str | None = None

    def to_dict(self) -> dict:
        return {"state": self.state, "text": self.text, "claims": self.claims, "new": self.new,
                "dropped": self.dropped, "detail": self.detail}


class Stopped(Exception):
    """The owner stopped the run. Nothing is saved."""


def _work_dir(data_dir: Path) -> Path:
    from ..store import ensure_private_dir  # Not at the top: the store imports this package.

    ensure_private_dir(Path(data_dir))
    folder = Path(data_dir) / "research-work"
    shutil.rmtree(folder, ignore_errors=True)
    return ensure_private_dir(folder)


def run_research(db: sqlite3.Connection, data_dir: Path, run: Run | None = None, claude: str | None = None,
                 find: Callable[[], str | None] | None = None, now: Callable[[], str] = utc_now) -> Outcome:
    """One research run. Saves valid claims as `unconfirmed` in one transaction, and the outcome of the run."""
    claude = claude or (find or find_claude)()
    run = run or subprocess.run
    if claude is None:
        return _finish(db, Outcome("not_installed", TEXT_NOT_INSTALLED), now())
    if not signed_in(claude, run):
        return _finish(db, Outcome("signed_out", TEXT_SIGNED_OUT), now())
    work = _work_dir(data_dir)
    try:
        proc = run(command(claude), capture_output=True, text=True, timeout=TIME_LIMIT_SECONDS, env=claude_env(),
                   stdin=subprocess.DEVNULL, cwd=str(work))
    except subprocess.TimeoutExpired:
        return _finish(db, Outcome("time_limit", TEXT_TIME_LIMIT), now())
    except Stopped:
        return _finish(db, Outcome("stopped", TEXT_STOPPED), now())
    except (OSError, subprocess.SubprocessError) as exc:
        return _finish(db, Outcome("failed", TEXT_FAILED, detail=repr(exc)), now())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 and re.search(r"(?i)\blog ?in\b|/login|not logged|authenticat", text):
        return _finish(db, Outcome("signed_out", TEXT_SIGNED_OUT, detail=_tail(proc)), now())
    try:
        claims, dropped = parse_output(proc.stdout or "")
    except InvalidOutput as exc:
        state, message = ("invalid", TEXT_INVALID) if proc.returncode == 0 else ("failed", TEXT_FAILED)
        return _finish(db, Outcome(state, message, detail=f"{exc}. {_tail(proc)}".strip()), now())
    finished = now()
    new = _save_claims(db, claims, finished)
    if not claims:
        return _finish(db, Outcome("no_claims", TEXT_NO_CLAIMS, dropped=dropped), finished)
    count = len(claims)
    return _finish(db, Outcome("done", TEXT_DONE.format(count=count, claims="claim" if count == 1 else "claims"),
                               count, new, dropped), finished)


def _tail(proc: subprocess.CompletedProcess) -> str:
    return f"exit {proc.returncode}: {(proc.stderr or '').strip()[-300:]}"


def _save_claims(db: sqlite3.Connection, claims: list[Claim], now: str) -> int:
    from .records import _next_seq  # The incident numbering of #12.

    new = 0
    db.execute("BEGIN IMMEDIATE")
    try:
        for c in claims:
            row = db.execute("SELECT seq, cves, primary_url FROM incidents WHERE source = ? AND guid = ?",
                             (SOURCE, c.guid)).fetchone()
            if row is None:
                new += 1
                db.execute(
                    "INSERT INTO incidents (seq, source, guid, service, title, summary, published, status, "
                    "source_name, url, cves, first_seen, last_seen, primary_url) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'unconfirmed', ?, ?, ?, ?, ?, ?)",
                    (_next_seq(db), SOURCE, c.guid, c.service, c.title, c.summary, c.published, SOURCE_NAME, c.url,
                     json.dumps(c.cves), now, now, c.primary_url))
            else:  # Keep the text and the status. Add CVEs and a primary link to check.
                cves = sorted(set(json.loads(row["cves"])) | set(c.cves))
                db.execute("UPDATE incidents SET cves = ?, last_seen = ?, primary_url = COALESCE(primary_url, ?) "
                           "WHERE seq = ?", (json.dumps(cves), now, c.primary_url, row["seq"]))
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    return new


def _finish(db: sqlite3.Connection, outcome: Outcome, finished: str) -> Outcome:
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('research_last', ?)",
               (json.dumps(outcome.to_dict() | {"finished_at": finished}),))
    db.commit()
    return outcome


def last_run(db: sqlite3.Connection) -> dict | None:
    row = db.execute("SELECT value FROM meta WHERE key = 'research_last'").fetchone()
    try:
        return json.loads(row["value"]) if row else None
    except ValueError:
        return None
