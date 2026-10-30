"""EPSS scores from FIRST (#57): the chance that a CVE is exploited in the next 30 days.

External call (see README): one GET of the public bulk file
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz. The request holds no CVE list, no finding
id and no inventory data. The whole file comes down (about 3 MB gzip) and the engine picks the CVEs of the
findings from it on this Mac.

The engine keeps the last good file in `<data dir>/cache/epss/`. It downloads again only if the copy is
older than one day, so a refresh may use no network. If a download fails, the cached copy stays in use and
keeps its original age: earlier scores are never cleared. Data counts as old after 2 days (`STALE_DAYS`).
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..models import CoverageRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, http_fetch

SOURCE = "epss"
LABEL = "EPSS"
URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_BYTES = 64 * 1024 * 1024  # The gzip file is about 3 MB. The CSV is about 13 MB.
REFRESH_AFTER = timedelta(days=1)
STALE_AFTER = timedelta(days=2)
CACHE_FORMAT = 1
ERROR_NOT_LOADED = "EPSS download failed."
_HEADER = "cve,epss,percentile"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class EpssData:
    """EPSS values by upper-case CVE id for the CVEs that were asked for. Empty if there is no data."""

    scores: dict[str, tuple[float, float]] = field(default_factory=dict)  # cve -> (score, percentile)
    fetched_at: str | None = None  # When the file was downloaded. None if there is no data.
    score_date: str | None = None  # The day of the scores, `2026-10-29`.
    fresh: bool = False  # True if the data was downloaded within the last day (a cache hit counts).
    error: str | None = None
    detail: str | None = None

    @property
    def loaded(self) -> bool:
        return self.fetched_at is not None

    def coverage(self) -> CoverageRecord:
        if self.fresh:
            return CoverageRecord(SOURCE, LABEL, "complete", source_at=self.fetched_at)
        # Earlier scores stay: a failed download with a cached copy is partial, with none it is failed.
        return CoverageRecord(SOURCE, LABEL, "partial" if self.loaded else "failed",
                              error=self.error or ERROR_NOT_LOADED, detail=self.detail, source_at=self.fetched_at)


def is_cve(value: str) -> bool:
    return bool(_CVE.match(value.strip().upper()))


def parse(body: bytes, wanted: Iterable[str] | None = None) -> tuple[dict[str, tuple[float, float]], str | None]:
    """The scores of the wanted CVEs and the score date. `wanted` None keeps every row.

    The body is the gzip file, or the plain CSV. Raises ValueError for anything that is not an EPSS file.
    """
    if body[:2] == b"\x1f\x8b":
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            body = inflater.decompress(body, MAX_BYTES + 1)
        except zlib.error as exc:
            raise ValueError(f"not a gzip file: {exc}") from exc
        if len(body) > MAX_BYTES or inflater.unconsumed_tail:
            raise ValueError(f"file is larger than {MAX_BYTES} bytes")
    elif len(body) > MAX_BYTES:
        raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    want = {w.strip().upper() for w in wanted} if wanted is not None else None
    score_date = None
    header = False
    scores: dict[str, tuple[float, float]] = {}
    rows = 0
    for raw in io.StringIO(body.decode("utf-8", errors="replace")):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):  # `#model_version:v2026.06.15,score_date:2026-10-29T12:03:14Z`
            match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", line)
            score_date = match.group(1) if match else score_date
            continue
        if not header:
            if line.lower() != _HEADER:
                raise ValueError("no EPSS header")
            header = True
            continue
        parts = line.split(",")
        if len(parts) != 3 or not is_cve(parts[0]):
            continue
        try:
            score, percentile = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        if not (0 <= score <= 1 and 0 <= percentile <= 1):
            continue
        rows += 1
        cve = parts[0].strip().upper()
        if want is None or cve in want:
            scores[cve] = (score, percentile)
    if not header or rows == 0:
        raise ValueError("the file has no EPSS rows")
    return scores, score_date


# Cache


def _cache_dir(data_dir: Path) -> Path:
    return ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "epss")


def _read_cache(folder: Path) -> tuple[dict, bytes] | None:
    try:
        meta = json.loads((folder / "epss.json").read_text())
        body = (folder / "epss.csv.gz").read_bytes()
    except (OSError, ValueError):
        return None
    ok = isinstance(meta, dict) and meta.get("format") == CACHE_FORMAT and meta.get("fetched_at")
    return (meta, body) if ok else None


def _write_cache(folder: Path, fetched_at: str, score_date: str | None, body: bytes) -> None:
    for name, data in (("epss.csv.gz", body),
                       ("epss.json", json.dumps({"format": CACHE_FORMAT, "fetched_at": fetched_at,
                                                 "score_date": score_date}).encode())):
        tmp = ensure_private_file((folder / name).with_suffix(".tmp"))
        tmp.write_bytes(data)
        os.replace(tmp, folder / name)


def _moment(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _as_gzip(body: bytes) -> bytes:
    return body if body[:2] == b"\x1f\x8b" else gzip.compress(body)


# Load


def load(data_dir: Path, cves: Iterable[str], fetch: Fetch = http_fetch,
         now: Callable[[], str] = utc_now) -> EpssData:
    """The EPSS values of `cves`. Uses the cached file if it is under a day old, else downloads it.

    The request carries no CVE. If the download fails, the cached file is used with its own age.
    """
    wanted = {c.strip().upper() for c in cves if is_cve(c)}
    folder = _cache_dir(data_dir)
    cached = _read_cache(folder)
    if cached:
        meta, body = cached
        try:
            age = _moment(now()) - _moment(meta["fetched_at"])
            if timedelta(0) <= age < REFRESH_AFTER:
                scores, score_date = parse(body, wanted)
                return EpssData(scores, meta["fetched_at"], score_date or meta.get("score_date"), fresh=True)
        except ValueError:
            cached = None  # A damaged cache is the same as none. Download again.
    try:
        resp = fetch(URL, {"User-Agent": f"Watchtower/{__version__}", "Accept-Encoding": "identity"})
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        scores, score_date = parse(resp.body, wanted)
    except Exception as exc:  # Network, HTTP, size or parse failure. Keep the earlier data.
        detail = f"GET {URL}: {exc!r}"
        if cached:
            meta, body = cached
            try:
                scores, score_date = parse(body, wanted)
                return EpssData(scores, meta["fetched_at"], score_date or meta.get("score_date"),
                                error=ERROR_NOT_LOADED, detail=detail)
            except ValueError:
                pass
        return EpssData(error=ERROR_NOT_LOADED, detail=detail)
    fetched_at = now()
    _write_cache(folder, fetched_at, score_date, _as_gzip(resp.body))
    return EpssData(scores, fetched_at, score_date, fresh=True)
