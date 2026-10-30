"""Homebrew formula and cask catalogs from the public JSON API.

External calls (see README): GET https://formulae.brew.sh/api/formula.json and
https://formulae.brew.sh/api/cask.json. The full catalogs disclose no package selection.
Nothing about this Mac is sent.

The engine keeps a small index of each catalog in `<data dir>/cache/homebrew/`.
It sends the cached ETag, so an unchanged catalog costs one 304 response.
If a fetch fails, the cached index is used and keeps its original age.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import __version__
from ..models import utc_now
from ..store import ensure_private_dir, ensure_private_file

API = "https://formulae.brew.sh/api"
URLS = {"formula": f"{API}/formula.json", "cask": f"{API}/cask.json"}
TIMEOUT_SECONDS = 30
MAX_BYTES = 200 * 1024 * 1024  # The formula catalog is about 30 MB uncompressed.
CACHE_FORMAT = 2  # 2: cask rows carry homepage, app names and bundle ids (#55).


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes


# fetch(url, headers) -> Response. Tests pass a fake. Raises OSError on network failure.
Fetch = Callable[[str, dict], Response]


def http_fetch(url: str, headers: dict) -> Response:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read(MAX_BYTES + 1)
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, body)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return Response(304, {k.lower(): v for k, v in exc.headers.items()}, b"")
        raise


@dataclass
class Catalog:
    """One catalog index: entries by every name that can find them."""

    kind: str
    entries: dict[str, dict] = field(default_factory=dict)
    rows: list[dict] = field(default_factory=list)
    # When the data was fetched or confirmed unchanged. None if there is no data.
    fetched_at: str | None = None
    # True if this refresh fetched or confirmed the data. False if it is from the cache or missing.
    fresh: bool = False
    error: str | None = None
    detail: str | None = None

    @property
    def loaded(self) -> bool:
        return self.fetched_at is not None

    def lookup(self, *names: str | None) -> dict | None:
        for name in names:
            if name and name in self.entries:
                return self.entries[name]
        return None

    def casks_for_bundle_id(self, bundle_id: str) -> list[dict]:
        """Casks that name this bundle id in an `uninstall quit` or `zap trash` entry."""
        return [r for r in self.rows if bundle_id.lower() in (r.get("bundle_ids") or [])]

    def casks_for_app_name(self, file_name: str) -> list[dict]:
        """Casks with an `app` artifact of this file name, for example `T3 Code.app`."""
        return [r for r in self.rows if file_name.lower() in (r.get("app_names") or [])]


def _index_formulae(raw: list) -> list[dict]:
    out = []
    for f in raw:
        versions = f.get("versions") or {}
        old = f.get("oldnames") or ([f["oldname"]] if f.get("oldname") else [])
        out.append({
            "name": f["name"],
            "full_name": f.get("full_name") or f["name"],
            "tap": f.get("tap"),
            "stable": versions.get("stable"),
            "revision": f.get("revision") or 0,
            "old_names": old,
        })
    return out


_BUNDLE_ID = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){2,}$")
_ID_FOLDERS = ("/Library/Preferences/", "/Library/Caches/", "/Library/HTTPStorages/",
               "/Library/Saved Application State/", "/Library/Containers/")
_ID_SUFFIXES = (".plist", ".savedState")


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [v for v in value or [] if isinstance(v, str)] if isinstance(value, list) else []


def cask_app_names(artifacts: list) -> list[str]:
    """Lower-case file names of the `app` artifacts. A `target` renames the app."""
    names: list[str] = []
    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        for entry in artifact.get("app") or []:
            if isinstance(entry, str):
                names.append(posixpath.basename(entry).lower())
            elif isinstance(entry, dict) and entry.get("target") and names:
                names[-1] = posixpath.basename(str(entry["target"])).lower()
    return sorted(set(names))


def cask_bundle_ids(artifacts: list) -> list[str]:
    """Lower-case bundle ids that a cask names: `uninstall quit` values and ids in `zap trash` paths.

    The catalog has no bundle id field. A zap path such as `~/Library/Preferences/com.example.app.plist`
    names the id of the app that the cask installs.
    """
    ids: set[str] = set()
    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        for stanza in artifact.get("uninstall") or []:
            if isinstance(stanza, dict):
                ids.update(i.lower() for i in _strings(stanza.get("quit")) if _BUNDLE_ID.match(i))
        for stanza in artifact.get("zap") or []:
            if not isinstance(stanza, dict):
                continue
            for path in _strings(stanza.get("trash")):
                if not any(folder in path for folder in _ID_FOLDERS):
                    continue
                base = posixpath.basename(path)
                for suffix in _ID_SUFFIXES:
                    if base.endswith(suffix):
                        base = base[: -len(suffix)]
                if _BUNDLE_ID.match(base):
                    ids.add(base.lower())
    return sorted(ids)


def _index_casks(raw: list) -> list[dict]:
    out = []
    for c in raw:
        artifacts = c.get("artifacts") or []
        out.append({
            "name": c["token"],
            "full_name": c.get("full_token") or c["token"],
            "tap": c.get("tap"),
            "version": c.get("version"),
            "auto_updates": bool(c.get("auto_updates")),
            "old_names": c.get("old_tokens") or [],
            "homepage": c.get("homepage") if isinstance(c.get("homepage"), str) else None,
            "app_names": cask_app_names(artifacts),
            "bundle_ids": cask_bundle_ids(artifacts),
        })
    return out


_INDEXERS = {"formula": _index_formulae, "cask": _index_casks}


def _by_name(rows: list[dict]) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    for row in rows:  # Old names first, so a current name always wins.
        for old in row["old_names"]:
            entries.setdefault(old, row)
    for row in rows:
        entries[row["name"]] = row
        entries[row["full_name"]] = row
    return entries


def _decode_body(resp: Response) -> list:
    body = resp.body
    if len(body) > MAX_BYTES:
        raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    if resp.headers.get("content-encoding") == "gzip":
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        body = inflater.decompress(body, MAX_BYTES + 1)
        if len(body) > MAX_BYTES or inflater.unconsumed_tail:
            raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    data = json.loads(body)
    if not isinstance(data, list):
        raise ValueError("catalog is not a JSON list")
    return data


class CatalogCache:
    def __init__(self, data_dir: Path):
        cache = ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache")
        self.dir = ensure_private_dir(cache / "homebrew")

    def _path(self, kind: str) -> Path:
        return self.dir / f"{kind}.json"

    def read(self, kind: str) -> dict | None:
        try:
            data = json.loads(self._path(kind).read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("format") != CACHE_FORMAT:
            return None
        return data

    def write(self, kind: str, data: dict) -> None:
        path = self._path(kind)
        tmp = ensure_private_file(path.with_suffix(".tmp"))
        with open(tmp, "w") as fh:
            json.dump({"format": CACHE_FORMAT, **data}, fh)
        os.replace(tmp, path)


def load_catalog(
    kind: str,
    data_dir: Path,
    fetch: Fetch = http_fetch,
    now: Callable[[], str] = utc_now,
) -> Catalog:
    """Fetch one catalog, or fall back to the cached index with its original age."""
    cache = CatalogCache(data_dir)
    cached = cache.read(kind)
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept-Encoding": "gzip"}
    if cached and cached.get("etag"):
        headers["If-None-Match"] = cached["etag"]
    try:
        resp = fetch(URLS[kind], headers)
        fetched_at = now()
        if resp.status == 304 and cached:
            rows = cached["rows"]
        elif resp.status == 200:
            rows = _INDEXERS[kind](_decode_body(resp))
        else:
            raise ValueError(f"HTTP {resp.status}")
        cache.write(kind, {"fetched_at": fetched_at, "etag": resp.headers.get("etag"), "rows": rows})
        return Catalog(kind, _by_name(rows), rows, fetched_at, fresh=True)
    except Exception as exc:  # Network, HTTP, size or parse failure. All mean "did not load".
        detail = f"GET {URLS[kind]}: {exc!r}"
        if cached:
            return Catalog(kind, _by_name(cached["rows"]), cached["rows"], cached["fetched_at"], fresh=False,
                           error="Homebrew catalog did not load.", detail=detail)
        return Catalog(kind, error="Homebrew catalog did not load.", detail=detail)
