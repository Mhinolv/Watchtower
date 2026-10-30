"""The latest version of a package from its public registry (#81): PyPI and crates.io.

External calls (see README), one GET for each package that the Projects `Dependencies` table shows:
- `https://pypi.org/pypi/<name>/json` (the `info.version` field: the newest release that is not a pre-release).
- `https://index.crates.io/<path>/<name>` (the sparse index: one JSON line for each version).
The request holds the public package name and nothing else: no version, project, path or inventory data.
Registry text is untrusted: only the version field is read, and a version must look like a version.

Answers are cached in `<data dir>/cache/registries/<registry>.json` for one day. If a request fails, the cached
answer is used with its own age and the lookup says it failed: earlier data is never cleared.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..inventory.homebrew import version_key
from ..models import utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, http_fetch

PYPI = "PyPI"
CRATES = "crates.io"
URLS = {PYPI: "https://pypi.org/pypi/{name}/json", CRATES: "https://index.crates.io/{path}"}
TTL = timedelta(days=1)
MAX_LOOKUPS = 80  # Requests in one call. The rest of the packages show no latest version.
MAX_BYTES = 8 * 1024 * 1024
CACHE_FORMAT = 1
ERROR_TEXT = {PYPI: "PyPI did not respond.", CRATES: "crates.io did not respond."}
_VERSION = re.compile(r"^\d+(?:\.\d+){0,3}(?:[-+._]?[0-9A-Za-z]+)*$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


@dataclass
class Latest:
    version: str | None  # None: no version is known.
    fetched_at: str | None  # When the answer came from the registry. None if there is none.
    error: str | None = None  # Set if the request failed, also when an earlier answer is shown.


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def crate_path(name: str) -> str:
    """The sparse index path: `1/a`, `2/ab`, `3/a/abc`, `se/rd/serde`."""
    lower = name.lower()
    if len(lower) <= 2:
        return f"{len(lower)}/{lower}"
    if len(lower) == 3:
        return f"3/{lower[0]}/{lower}"
    return f"{lower[:2]}/{lower[2:4]}/{lower}"


def parse_pypi(body: bytes) -> str | None:
    data = json.loads(body)
    info = data.get("info") if isinstance(data, dict) else None
    version = info.get("version") if isinstance(info, dict) else None
    return version.strip() if isinstance(version, str) and _VERSION.match(version.strip()) else None


def parse_crate(body: bytes) -> str | None:
    """The highest version that is not yanked and not a pre-release (`2.0.0-beta.3` is skipped)."""
    best = None
    for line in body.decode("utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        version = row.get("vers") if isinstance(row, dict) else None
        if (not isinstance(version, str) or row.get("yanked") is True or not _VERSION.match(version)
                or "-" in version or "+" in version):
            continue
        if best is None or version_key(version) > version_key(best):
            best = version
    return best


def _moment(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _cache_path(data_dir: Path, registry: str) -> Path:
    folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "registries")
    return folder / f"{registry.replace('.', '-').lower()}.json"


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    entries = data.get("entries") if isinstance(data, dict) and data.get("format") == CACHE_FORMAT else None
    return entries if isinstance(entries, dict) else {}


def lookup(registry: str, names: Iterable[str], data_dir: Path, fetch: Fetch = http_fetch,
           now: Callable[[], str] = utc_now) -> dict[str, Latest]:
    """The latest version of each package, by the name that the caller gave. Never raises for a failed request."""
    path = _cache_path(data_dir, registry)
    entries = _read(path)
    current = now()
    out: dict[str, Latest] = {}
    sent = 0
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/json"}
    for name in dict.fromkeys(names):
        key = normalize(name)
        cached = entries.get(key) if isinstance(entries.get(key), dict) else None
        fresh = False
        if cached and isinstance(cached.get("fetched_at"), str):
            try:
                fresh = timedelta(0) <= _moment(current) - _moment(cached["fetched_at"]) < TTL
            except ValueError:
                fresh = False
        if fresh:
            out[name] = Latest(cached.get("version"), cached["fetched_at"])
            continue
        error = ERROR_TEXT[registry]
        if sent < MAX_LOOKUPS and _NAME.match(name):  # A name from a manifest is untrusted: it must look like a name.
            sent += 1
            url = URLS[registry].format(name=name, path=crate_path(name))
            try:
                resp = fetch(url, headers)
                if resp.status != 200 or len(resp.body) > MAX_BYTES:
                    raise ValueError(f"HTTP {resp.status}")
                version = parse_pypi(resp.body) if registry == PYPI else parse_crate(resp.body)
                if version is None:
                    raise ValueError("no version")
                entries[key] = {"version": version, "fetched_at": current}
                out[name] = Latest(version, current)
                continue
            except Exception:  # Network, HTTP, size or parse failure. The cached answer stays.
                pass
        out[name] = Latest(cached.get("version") if cached else None, cached.get("fetched_at") if cached else None, error)
    try:
        tmp = ensure_private_file(path.with_suffix(".tmp"))
        tmp.write_text(json.dumps({"format": CACHE_FORMAT, "entries": entries}))
        os.replace(tmp, path)
    except OSError:
        pass
    return out
