"""GitHub security advisories for the advisory ids of the findings.

External calls (see README): GET https://api.github.com/advisories?ghsa_id=<id>&type=reviewed,
the same with `type=malware`, and `cve_id=<id>` for a finding that has no GHSA id.
The request holds one advisory id and nothing else: no package name, version, path or project.
The two types are separate requests, because the default list leaves malware out.

Rules:
- A response is followed through its `Link: rel="next"` page, up to MAX_PAGES. A longer list is
  marked incomplete. The engine follows only links on api.github.com.
- A rate limit stops all later requests of this refresh. The cached answers stay and keep their age.
- One refresh sends at most MAX_REQUESTS requests (the public limit is 60 for each hour). An
  answer that is younger than TTL_HOURS is reused. The rest is marked incomplete.
- The cache is `<data dir>/cache/github/advisories.json`.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..models import CoverageRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, Response

SOURCE = "github"
LABEL = "GitHub Advisories"
API = "https://api.github.com/advisories"
API_VERSION = "2026-03-10"
TYPES = ("reviewed", "malware")
PER_PAGE = 100
MAX_PAGES = 3
MAX_REQUESTS = 40
TTL_HOURS = 6
TIMEOUT_SECONDS = 30
MAX_BYTES = 10 * 1024 * 1024
CACHE_FORMAT = 1
ERROR_NOT_LOADED = "GitHub Advisories did not load."
ERROR_INCOMPLETE = "GitHub Advisories are incomplete."


def http_fetch(url: str, headers: dict) -> Response:
    """Like the Homebrew fetch, but an error status comes back as a Response with its headers."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as resp:
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                            resp.read(MAX_BYTES + 1))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read(4096))


class RateLimited(Exception):
    pass


class BadAnswer(Exception):
    """The answer is not a list of advisories, or has an error status. `str()` is a short reason."""


@dataclass
class Lookup:
    """The answer for one (type, id): the advisories that GitHub lists for that id."""

    kind: str  # reviewed or malware
    param: str  # ghsa_id or cve_id
    value: str
    advisories: list[dict] | None = None  # None: never retrieved.
    fetched_at: str | None = None
    incomplete: bool = False


@dataclass
class Assessment:
    """What GitHub says about one finding. `*_known` is False if an answer is missing."""

    malware_id: str | None = None
    malware_known: bool = False
    withdrawn_at: str | None = None
    withdrawn_known: bool = False


@dataclass
class GithubData:
    lookups: dict[str, Lookup] = field(default_factory=dict)
    state: str = "complete"  # complete, partial or failed
    fetched_at: str | None = None  # The oldest answer that is in use.
    reason: str | None = None  # Short reason for the Source row, for example `rate limit`.
    detail: str | None = None

    def coverage(self) -> CoverageRecord:
        error = {"complete": None, "partial": ERROR_INCOMPLETE, "failed": ERROR_NOT_LOADED}[self.state]
        return CoverageRecord(SOURCE, LABEL, self.state, error=error, detail=self.detail,
                              source_at=self.fetched_at, note=self.reason)

    def assess(self, advisory_ids: Iterable[str]) -> Assessment:
        targets = lookup_targets(advisory_ids)
        result = Assessment()
        for kind in TYPES:
            answers = [self.lookups.get(key(kind, p, v)) for p, v in targets]
            known = bool(answers) and all(a is not None and a.advisories is not None for a in answers)
            found = [adv for a in answers if a and a.advisories for adv in a.advisories]
            if kind == "malware":
                live = [a["ghsa_id"] for a in found if not a.get("withdrawn_at")]
                result.malware_id, result.malware_known = (live[0] if live else None), known
            else:
                dates = [a["withdrawn_at"] for a in found if a.get("withdrawn_at")]
                result.withdrawn_at, result.withdrawn_known = (max(dates) if dates else None), known
        return result


def key(kind: str, param: str, value: str) -> str:
    return f"{kind}|{param}={value}"


def lookup_targets(advisory_ids: Iterable[str]) -> list[tuple[str, str]]:
    """The (parameter, id) pairs to ask GitHub about for one finding.

    Every GHSA id, or the CVE ids if the finding has no GHSA id. Other ids (OSV, PYSEC) are not asked.
    """
    ids = sorted({i.strip() for i in advisory_ids if isinstance(i, str)})
    ghsa = [("ghsa_id", "GHSA-" + i[5:].lower()) for i in ids if re.fullmatch(r"(?i)GHSA(-[0-9a-z]{4}){3}", i)]
    if ghsa:
        return ghsa
    return [("cve_id", i.upper()) for i in ids if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", i)]


# Cache


def _cache_path(data_dir: Path) -> Path:
    folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "github")
    return folder / "advisories.json"


def _read_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    lookups = data.get("lookups") if isinstance(data, dict) and data.get("format") == CACHE_FORMAT else None
    return lookups if isinstance(lookups, dict) else {}


def _write_cache(path: Path, lookups: dict) -> None:
    tmp = ensure_private_file(path.with_suffix(".tmp"))
    tmp.write_text(json.dumps({"format": CACHE_FORMAT, "lookups": lookups}))
    os.replace(tmp, path)


def _parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _young(fetched_at: str | None, now: str) -> bool:
    try:
        return fetched_at is not None and (_parse_time(now) - _parse_time(fetched_at)).total_seconds() < TTL_HOURS * 3600
    except ValueError:
        return False


# Requests


def _summary(advisory) -> dict | None:
    """The fields that Watchtower keeps. Output of the API is untrusted: other fields are dropped."""
    if not isinstance(advisory, dict) or not isinstance(advisory.get("ghsa_id"), str):
        return None
    text = lambda k: advisory[k] if isinstance(advisory.get(k), str) else None
    return {"ghsa_id": advisory["ghsa_id"], "cve_id": text("cve_id"), "type": text("type"),
            "severity": text("severity"), "withdrawn_at": text("withdrawn_at"),
            "published_at": text("published_at")}


_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


def next_link(header: str | None) -> str | None:
    """The next page of a `Link` header, only if it is on api.github.com."""
    match = _NEXT.search(header or "")
    url = match.group(1) if match else None
    return url if url and url.startswith("https://api.github.com/") else None


def _check(resp: Response) -> None:
    if resp.status in (403, 429):
        text = resp.body[:4096].lower()
        if resp.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in resp.headers or b"rate limit" in text:
            raise RateLimited()
    if resp.status != 200:
        raise BadAnswer(f"HTTP {resp.status}")


def _fetch_list(fetch: Fetch, kind: str, param: str, value: str, headers: dict) -> tuple[list[dict], bool, int, bool]:
    """All pages of one lookup. Returns (advisories, incomplete, requests sent, rate limit used up)."""
    url = f"{API}?" + urllib.parse.urlencode({param: value, "type": kind, "per_page": PER_PAGE})
    out: list[dict] = []
    sent, exhausted = 0, False
    while url and sent < MAX_PAGES:
        resp = fetch(url, headers)
        sent += 1
        _check(resp)
        try:
            data = json.loads(resp.body)
        except ValueError as exc:
            raise BadAnswer("bad data") from exc
        if not isinstance(data, list):
            raise BadAnswer("bad data")
        out += [s for s in map(_summary, data) if s]
        exhausted = resp.headers.get("x-ratelimit-remaining") == "0"
        url = next_link(resp.headers.get("link"))
        if exhausted:
            break
    return out, url is not None, sent, exhausted


def load(
    data_dir: Path,
    findings_ids: Iterable[Iterable[str]],
    fetch: Fetch = http_fetch,
    now: Callable[[], str] = utc_now,
    max_requests: int = MAX_REQUESTS,
) -> GithubData:
    """Ask GitHub about the advisory ids of each finding, one id and one type at a time."""
    path = _cache_path(data_dir)
    cache = _read_cache(path)
    targets = sorted({t for ids in findings_ids for t in lookup_targets(ids)})
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": API_VERSION}
    data = GithubData()
    sent = 0
    stop: str | None = None  # Set after a rate limit or a network failure: no more requests.
    failures: list[str] = []
    reason: str | None = None
    incomplete: str | None = None
    current = now()

    for kind in TYPES:
        for param, value in targets:
            k = key(kind, param, value)
            old = cache.get(k) if isinstance(cache.get(k), dict) else None
            lookup = Lookup(kind, param, value)
            if old and isinstance(old.get("advisories"), list):
                lookup.advisories, lookup.fetched_at = old["advisories"], old.get("fetched_at")
                lookup.incomplete = bool(old.get("incomplete"))
            if lookup.advisories is not None and _young(lookup.fetched_at, current) and not lookup.incomplete:
                data.lookups[k] = lookup
                continue
            data.lookups[k] = lookup  # The old answer stays if the request fails.
            if stop:
                continue
            if sent >= max_requests:
                incomplete = incomplete or "request limit"
                continue
            try:
                advisories, short, used, exhausted = _fetch_list(fetch, kind, param, value, headers)
            except RateLimited:
                stop, reason = "rate limit", reason or "rate limit"
                failures.append(f"GET {API}?{param}={value}&type={kind}: rate limit")
                sent += 1
                continue
            except BadAnswer as exc:
                failures.append(f"GET {API}?{param}={value}&type={kind}: {exc}")
                reason = reason or str(exc)
                sent += 1
                continue
            except Exception as exc:  # Network failure: it will fail again, so stop.
                stop, reason = "network error", reason or "network error"
                failures.append(f"GET {API}?{param}={value}&type={kind}: {exc!r}")
                sent += 1
                continue
            sent += used
            lookup.advisories, lookup.fetched_at, lookup.incomplete = advisories, now(), short
            if short:
                incomplete = incomplete or "pagination stopped"
            if exhausted:
                stop, reason = "rate limit", reason or "rate limit"
                failures.append("rate limit used up")

    used_times = [l.fetched_at for l in data.lookups.values() if l.advisories is not None and l.fetched_at]
    data.fetched_at = min(used_times) if used_times else (None if failures else current)
    data.detail = "\n".join(failures) or None
    if failures:
        data.state, data.reason = "failed", reason
    elif incomplete:
        data.state, data.reason = "partial", incomplete
    _write_cache(path, {k: {"fetched_at": l.fetched_at, "advisories": l.advisories, "incomplete": l.incomplete}
                        for k, l in data.lookups.items() if l.advisories is not None})
    return data
