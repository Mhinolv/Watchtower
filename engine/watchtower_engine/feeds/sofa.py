"""SOFA (MacAdmins) feeds: the latest macOS and Safari releases, with the CVEs that they fix (#58).

External calls (see README): GET the two public bulk feeds below. The requests send a User-Agent
and nothing about this Mac: no version, path, bundle id or finding. The compare runs on this Mac.

The feeds are untrusted data. Only known fields are read, with type and format checks and limits.
The Apple security releases page stays the primary source link. SOFA is a summary of it.

The last good copy of each feed stays in `<data dir>/cache/sofa/feeds.json` (0600). If a feed
fails, the engine uses that copy, keeps its original age, and the coverage is `partial`.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..inventory.homebrew import version_key
from ..models import CoverageRecord, ItemRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, http_fetch

SOURCE = "sofa"
LABEL = "SOFA"
MACOS_URL = "https://sofafeed.macadmins.io/v2/macos_data_feed.json"
SAFARI_URL = "https://sofafeed.macadmins.io/v2/safari_data_feed.json"
FEEDS = {"macos": MACOS_URL, "safari": SAFARI_URL}
PRIMARY_SOURCE = "https://support.apple.com/en-us/100100"
ORIGIN = "SOFA"
SAFARI_BUNDLE_ID = "com.apple.safari"
MAX_BYTES = 10 * 1024 * 1024
MAX_TRACKS = 50
MAX_RELEASES = 200
MAX_CVES = 2000
CACHE_FORMAT = 1

# Owner-facing text (#58 Design notes).
NOTE_FIXES = "{product} {version} fixes {count} {cves}."
NOTE_EXPLOITED = "{version} fixes {count} actively exploited {cves}."
NOTE_NOT_IN_FEED = "This build is not in the SOFA feed (beta or new release)."
ERROR_FAILED = "SOFA feed did not load."
ERROR_SOME = "SOFA did not load. Watchtower used the last copy."

_VERSION = re.compile(r"\d{1,3}(\.\d{1,4}){0,3}")
_BUILD = re.compile(r"[0-9A-Za-z]{3,16}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


# Parse


@dataclass
class Release:
    version: str
    builds: list[str] = field(default_factory=list)
    released: str | None = None  # YYYY-MM-DD
    cves: list[str] = field(default_factory=list)
    exploited: list[str] = field(default_factory=list)


@dataclass
class Track:
    """One major version: `Sequoia 15` or `Safari 26`. `latest` is the newest release."""
    major: int
    latest: Release
    releases: list[Release] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Track":
        latest = Release(**data["latest"])
        return Track(int(data["major"]), latest, [Release(**r) for r in data["releases"]])


def _text(value, pattern: re.Pattern) -> str | None:
    return value.strip() if isinstance(value, str) and pattern.fullmatch(value.strip()) else None


def _release(row) -> Release | None:
    """One release from a feed row. None if the row has no valid version."""
    if not isinstance(row, dict):
        return None
    version = _text(row.get("ProductVersion"), _VERSION)
    if version is None:
        return None
    all_builds = row.get("AllBuilds") if isinstance(row.get("AllBuilds"), list) else []
    builds = [b for b in (_text(x, _BUILD) for x in [row.get("Build"), *all_builds[:MAX_RELEASES]]) if b]
    date = row.get("ReleaseDate")
    released = date[:10] if isinstance(date, str) and _DATE.fullmatch(date[:10]) else None
    cves, exploited = [], []
    table = row.get("CVEs")
    for cve, info in list(table.items())[:MAX_CVES] if isinstance(table, dict) else []:
        if _text(cve, _CVE):
            cves.append(cve.strip())
            # macOS rows say `ActivelyExploited`, Safari rows say `exploited`.
            if isinstance(info, dict) and (info.get("ActivelyExploited") is True or info.get("exploited") is True):
                exploited.append(cve.strip())
    listed = row.get("ActivelyExploitedCVEs")
    for cve in listed[:MAX_CVES] if isinstance(listed, list) else []:
        if _text(cve, _CVE):
            exploited.append(cve.strip())
    return Release(version, list(dict.fromkeys(builds)), released, sorted(set(cves) | set(exploited)),
                   sorted(set(exploited)))


def parse(body: bytes, list_key: str) -> dict[int, Track]:
    """Tracks by major version. `list_key` is `OSVersions` (macOS) or `AppVersions` (Safari).

    Raises ValueError for a body that is not a SOFA feed.
    """
    if len(body) > MAX_BYTES:
        raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    data = json.loads(body)
    rows = data.get(list_key) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError(f"no {list_key} list")
    tracks: dict[int, Track] = {}
    for row in rows[:MAX_TRACKS]:
        if not isinstance(row, dict):
            continue
        latest = _release(row.get("Latest"))
        if latest is None:
            continue
        found = row.get("SecurityReleases")
        releases = [r for r in map(_release, found[:MAX_RELEASES] if isinstance(found, list) else []) if r]
        major = int(latest.version.split(".")[0])
        tracks.setdefault(major, Track(major, latest, releases))
    if not tracks:
        raise ValueError("the feed has no release")
    return tracks


# Compare


def _norm(version: str) -> tuple:
    """`15.0` and `15` are the same version."""
    key = list(version_key(version))
    while len(key) > 1 and key[-1] == (1, 0):
        key.pop()
    return tuple(key)


@dataclass
class Verdict:
    known: bool  # False: the installed build is not in the feed.
    newer: list[Release] = field(default_factory=list)

    @property
    def fixed(self) -> list[str]:
        return sorted({c for r in self.newer for c in r.cves})

    @property
    def exploited(self) -> list[str]:
        return sorted({c for r in self.newer for c in r.exploited})


def compare(track: Track, version: str, build: str | None = None) -> Verdict:
    """The releases of `track` that are newer than the installed version, on this Mac only."""
    releases = list(track.releases)
    if all(_norm(r.version) != _norm(track.latest.version) for r in releases):
        releases.append(track.latest)
    listed = any((build and build in r.builds) or _norm(r.version) == _norm(version) for r in releases)
    if not listed and _norm(version) >= _norm(track.latest.version):
        return Verdict(known=False)  # A beta, or a release that the feed does not have yet.
    return Verdict(True, sorted((r for r in releases if _norm(r.version) > _norm(version)),
                                key=lambda r: _norm(r.version), reverse=True))


def _plural(count: int) -> str:
    return "CVE" if count == 1 else "CVEs"


def apply(item: ItemRecord, product: str, track: Track | None, version: str, build: str | None,
          fetched_at: str | None) -> None:
    """Set state, latest version, note and the `sofa*` attributes of the macOS or Safari item."""
    item.origin = ORIGIN
    item.source_at = fetched_at
    attributes = {k: v for k, v in (item.attributes or {}).items() if not k.startswith("sofa")}
    if fetched_at:
        attributes["sofaChecked"] = fetched_at
    verdict = compare(track, version, build) if track else Verdict(known=False)
    if track:
        latest = track.latest
        item.latest_version = latest.version
        attributes["sofaLatest"] = f"{latest.version} ({latest.builds[0]})" if latest.builds else latest.version
        if latest.released:
            attributes["sofaReleased"] = latest.released
    if verdict.fixed:
        attributes["sofaFixedCves"] = ", ".join(verdict.fixed)
    if verdict.exploited:
        attributes["sofaExploited"] = ", ".join(verdict.exploited)
    item.attributes = attributes
    if not verdict.known:
        item.state, item.note = "unknown", NOTE_NOT_IN_FEED
    elif not verdict.newer:
        item.state, item.note = "up_to_date", None
    elif verdict.exploited:
        count = len(verdict.exploited)
        item.state = "vulnerable"
        item.note = NOTE_EXPLOITED.format(version=track.latest.version, count=count, cves=_plural(count))
    else:
        count = len(verdict.fixed)
        item.state = "update_available"
        item.note = NOTE_FIXES.format(product=product, version=track.latest.version, count=count,
                                      cves=_plural(count))


# Cache


def _cache_path(data_dir: Path) -> Path:
    folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "sofa")
    return folder / "feeds.json"


def _read_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    feeds = data.get("feeds") if isinstance(data, dict) and data.get("format") == CACHE_FORMAT else None
    return feeds if isinstance(feeds, dict) else {}


def _write_cache(path: Path, feeds: dict) -> None:
    tmp = ensure_private_file(path.with_suffix(".tmp"))
    tmp.write_text(json.dumps({"format": CACHE_FORMAT, "feeds": feeds}))
    os.replace(tmp, path)


@dataclass
class Feed:
    tracks: dict[int, Track] = field(default_factory=dict)
    fetched_at: str | None = None  # None: no data at all.
    fresh: bool = False


def _cached(entry) -> Feed:
    try:
        tracks = {int(k): Track.from_dict(v) for k, v in entry["tracks"].items()}
        return Feed(tracks, entry["fetched_at"]) if isinstance(entry["fetched_at"], str) else Feed()
    except (KeyError, TypeError, ValueError, AttributeError):
        return Feed()  # A cache entry from another format: ignore it.


# Check


def _installed(text: str | None) -> str | None:
    """`15.1 (a)` (with a Rapid Security Response) compares as `15.1`."""
    first = (text or "").split(" ")[0]
    return first if _VERSION.fullmatch(first) else None


def is_safari(item: ItemRecord) -> bool:
    return item.source == "apps" and str((item.attributes or {}).get("bundleId", "")).lower() == SAFARI_BUNDLE_ID


def check(items: Iterable[ItemRecord], data_dir: Path, fetch: Fetch = http_fetch,
          now: Callable[[], str] = utc_now) -> CoverageRecord:
    """Fetch both feeds and update the macOS and Safari items in place. Returns the SOFA coverage."""
    path = _cache_path(data_dir)
    saved = _read_cache(path)
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/json"}
    feeds: dict[str, Feed] = {}
    failures: list[str] = []
    for name, url in FEEDS.items():
        try:
            resp = fetch(url, headers)
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            tracks = parse(resp.body, "OSVersions" if name == "macos" else "AppVersions")
        except Exception as exc:  # Network, HTTP, size or parse failure: use the last copy.
            failures.append(f"GET {url}: {exc!r}")
            feeds[name] = _cached(saved.get(name)) if isinstance(saved.get(name), dict) else Feed()
            continue
        feeds[name] = Feed(tracks, now(), fresh=True)
        saved[name] = {"fetched_at": feeds[name].fetched_at,
                       "tracks": {str(k): t.to_dict() for k, t in tracks.items()}}
    if any(f.fresh for f in feeds.values()):
        _write_cache(path, saved)

    for item in items:
        if item.source == "macos" and item.id == "macos":
            name, product = "macos", "macOS"
            build = (item.attributes or {}).get("build")
        elif is_safari(item):
            name, product, build = "safari", "Safari", None
        else:
            continue
        version, feed = _installed(item.installed_version), feeds[name]
        if version is None:
            continue
        if feed.fetched_at:
            apply(item, product, feed.tracks.get(int(version.split(".")[0])), version, build, feed.fetched_at)
        if not feed.fresh:
            item.error, item.detail = ERROR_FAILED, "\n".join(failures) or None

    used = [f.fetched_at for f in feeds.values() if f.fetched_at]
    detail = "\n".join(failures) or None
    if not failures:
        return CoverageRecord(SOURCE, LABEL, "complete", source_at=min(used))
    if not used:
        return CoverageRecord(SOURCE, LABEL, "failed", error=ERROR_FAILED, detail=detail)
    return CoverageRecord(SOURCE, LABEL, "partial", error=ERROR_SOME, detail=detail, source_at=min(used))
