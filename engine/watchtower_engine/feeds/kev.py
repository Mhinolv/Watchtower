"""The CISA Known Exploited Vulnerabilities (KEV) catalog.

External calls (see README): GET the CISA file, and if that fails GET the same file from the
official CISA mirror on GitHub. Both are static files. Nothing about this Mac is sent.

The engine keeps the last good copy in `<data dir>/cache/kev/kev.json`. If both sources fail,
it uses that copy and keeps its original age. KEV membership says that an exploit is known.
It does not say that a local version is affected: the finding match does that.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import __version__
from ..models import CoverageRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, http_fetch

SOURCE = "kev"
LABEL = "CISA KEV"
PRIMARY_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
MAX_BYTES = 20 * 1024 * 1024
CACHE_FORMAT = 1
NOTE_MIRROR = "official mirror"
ERROR_NOT_LOADED = "CISA KEV did not load."


@dataclass
class KevData:
    """KEV entries by CVE id. `entries` is empty if there is no data at all."""

    entries: dict[str, dict] = field(default_factory=dict)
    fetched_at: str | None = None  # When the data was fetched. None if there is none.
    fresh: bool = False  # True if this refresh fetched it.
    via_mirror: bool = False
    error: str | None = None
    reason: str | None = None  # Short reason for the Source row, for example `HTTP 403`.
    detail: str | None = None

    @property
    def loaded(self) -> bool:
        return self.fetched_at is not None

    def coverage(self) -> CoverageRecord:
        if self.fresh:
            return CoverageRecord(SOURCE, LABEL, "complete", source_at=self.fetched_at, detail=self.detail,
                                  note=NOTE_MIRROR if self.via_mirror else None)
        return CoverageRecord(SOURCE, LABEL, "failed", error=self.error or ERROR_NOT_LOADED,
                              detail=self.detail, source_at=self.fetched_at, note=self.reason)


def parse(body: bytes) -> dict[str, dict]:
    """KEV entries by upper-case CVE id. Raises ValueError for a body that is not a KEV catalog."""
    if len(body) > MAX_BYTES:
        raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    data = json.loads(body)
    rows = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError("no vulnerabilities list")
    entries: dict[str, dict] = {}
    for row in rows:
        cve = row.get("cveID") if isinstance(row, dict) else None
        if not isinstance(cve, str) or not cve.strip():
            continue
        text = lambda key: row[key].strip() if isinstance(row.get(key), str) and row[key].strip() else None
        entries[cve.strip().upper()] = {
            "cve": cve.strip().upper(),
            "date_added": text("dateAdded"),
            "due_date": text("dueDate"),
            "ransomware": str(row.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
        }
    if not entries:
        raise ValueError("the catalog has no entries")
    return entries


def _cache_path(data_dir: Path) -> Path:
    return ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "kev") / "kev.json"


def _read_cache(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    ok = isinstance(data, dict) and data.get("format") == CACHE_FORMAT and isinstance(data.get("entries"), dict)
    return data if ok and data.get("fetched_at") else None


def _write_cache(path: Path, fetched_at: str, via_mirror: bool, entries: dict) -> None:
    tmp = ensure_private_file(path.with_suffix(".tmp"))
    tmp.write_text(json.dumps({"format": CACHE_FORMAT, "fetched_at": fetched_at, "via_mirror": via_mirror,
                               "entries": entries}))
    os.replace(tmp, path)


def _short_reason(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return f"HTTP {code}"
    if isinstance(exc, ValueError):
        return str(exc) if str(exc).startswith("HTTP ") else "bad data"
    return "network error"


def load(data_dir: Path, fetch: Fetch = http_fetch, now: Callable[[], str] = utc_now) -> KevData:
    """Fetch KEV from CISA, else from the official mirror, else use the cached copy."""
    path = _cache_path(data_dir)
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/json"}
    failures: list[str] = []
    reason = None
    for url in (PRIMARY_URL, MIRROR_URL):
        try:
            resp = fetch(url, headers)
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            entries = parse(resp.body)
        except Exception as exc:  # Network, HTTP, size or parse failure. The next source may work.
            failures.append(f"GET {url}: {exc!r}")
            reason = reason or _short_reason(exc)  # The reason of the first source is the one to show.
            continue
        fetched_at = now()
        via_mirror = url == MIRROR_URL
        _write_cache(path, fetched_at, via_mirror, entries)
        detail = "\n".join(failures) or None  # Why the primary source did not work, if the mirror did.
        return KevData(entries, fetched_at, fresh=True, via_mirror=via_mirror, detail=detail)
    detail = "\n".join(failures)
    cached = _read_cache(path)
    if cached:
        return KevData(cached["entries"], cached["fetched_at"], via_mirror=bool(cached.get("via_mirror")),
                       error=ERROR_NOT_LOADED, reason=reason, detail=detail)
    return KevData(error=ERROR_NOT_LOADED, reason=reason, detail=detail)
