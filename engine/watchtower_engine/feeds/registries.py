"""The latest version of a package from its public registry (#81): PyPI and crates.io.

External calls (see README), one GET for each package that the Projects `Dependencies` table shows:
- `https://pypi.org/simple/<name>/` with `Accept: application/vnd.pypi.simple.v1+json` (PEP 691) and gzip. The answer
  lists the versions and the files of the project. It is about a third of the size of the full project JSON.
- `https://index.crates.io/<path>/<name>` (the sparse index: one JSON line for each version), in gzip.
The request holds the public package name and nothing else: no version, project, path or inventory data.
Registry text is untrusted: only version strings and the yanked flag of a file are read, and a version must look like one.

The latest version is the highest release that is stable and not yanked. A pre-release (`1.0rc1`, `2.0.0-beta.3`) is
never the latest. If a package has only pre-releases, it has no latest version and the answer says `No stable release.`.

One call asks the registry for at most `max_requests` packages, 5 at a time. The packages that it does not ask are
`pending`: the caller asks again, and the answers that came before are in the cache. Nothing is shown as failed
that was not asked.

Answers are cached in `<data dir>/cache/registries/<registry>.json` for one day. If a request fails, the cached
answer is used with its own age and the lookup says it failed: earlier data is never cleared.
"""
from __future__ import annotations

import json
import os
import re
import zlib
from concurrent.futures import ThreadPoolExecutor
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
URLS = {PYPI: "https://pypi.org/simple/{name}/", CRATES: "https://index.crates.io/{path}"}
ACCEPT = {PYPI: "application/vnd.pypi.simple.v1+json", CRATES: "application/json"}
TTL = timedelta(days=1)
MAX_LOOKUPS = 25  # Requests in one call. The other packages are pending until the next call.
WORKERS = 5  # Requests at the same time.
MAX_BYTES = 8 * 1024 * 1024  # The answer after gzip. A larger answer is refused.
CACHE_FORMAT = 2
ERROR_TEXT = {PYPI: "PyPI did not respond.", CRATES: "crates.io did not respond."}
ERROR_NAME = "The name is not a package name."
NO_STABLE = "No stable release."
_VERSION = re.compile(r"^\d+(?:\.\d+){0,3}(?:[-+._]?[0-9A-Za-z]+)*$")
_PYPI_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.!+_-]{0,63}$")
_STABLE = re.compile(r"^(?:\d+!)?\d+(?:\.\d+)*(?:\.?post\d+)?$", re.IGNORECASE)  # No a, b, rc or dev part.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


@dataclass
class Latest:
    version: str | None  # None: no version is known.
    fetched_at: str | None  # When the answer came from the registry. None if there is none.
    error: str | None = None  # Set if the request failed, also when an earlier answer is shown.
    pending: bool = False  # True: this call did not ask the registry. Nothing failed.
    note: str | None = None  # `No stable release.`: the registry answered and every release is a pre-release or yanked.


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


def is_stable(version: str) -> bool:
    """A PyPI version without an `a`, `b`, `rc` or `dev` part. `1.0.post1` is stable."""
    return _STABLE.match(version) is not None


def _pypi_key(version: str) -> tuple:
    epoch, _, rest = version.rpartition("!")
    match = re.match(r"^(\d+(?:\.\d+)*)(?:\.?post(\d+))?$", rest, re.IGNORECASE)
    release = [int(n) for n in match.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    return (int(epoch or 0), tuple(release), int(match.group(2) or -1))


def _file_version(filename: str) -> str | None:
    """The version in a file name: `name-1.0-py3-none-any.whl` or `name-1.0.tar.gz`."""
    if filename.endswith(".whl"):
        parts = filename.split("-")
        return parts[1] if len(parts) >= 5 else None
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".egg"):
        if filename.endswith(suffix):
            stem = filename[: -len(suffix)]
            return stem.rsplit("-", 1)[1] if "-" in stem else None
    return None


def parse_pypi(body: bytes) -> str | None:
    """The highest stable version of the PEP 691 answer that has a file which is not yanked.

    Returns None if the project has no such version. Raises ValueError if the answer is not in the PEP 691 shape.
    """
    data = json.loads(body)
    versions = data.get("versions") if isinstance(data, dict) else None
    files = data.get("files", []) if isinstance(data, dict) else None
    if not isinstance(versions, list) or not isinstance(files, list):
        raise ValueError("not a PEP 691 answer")
    with_files: set[str] = set()
    live: set[str] = set()
    for f in files:
        version = _file_version(f.get("filename", "")) if isinstance(f, dict) and isinstance(f.get("filename"), str) else None
        if version is None:
            continue
        with_files.add(version)
        if not f.get("yanked"):  # PEP 592: `false`, or a reason text for a yanked file.
            live.add(version)
    best = None
    for version in versions:
        if (not isinstance(version, str) or not _PYPI_VERSION.match(version) or not is_stable(version)
                or (version in with_files and version not in live)):
            continue  # A version with files that are all yanked is not a release to install.
        if best is None or _pypi_key(version) > _pypi_key(best):
            best = version
    return best


def parse_crate(body: bytes) -> str | None:
    """The highest version that is not yanked and not a pre-release (`2.0.0-beta.3` is skipped).

    Returns None if there is none. Raises ValueError if no line is a version row.
    """
    best, rows = None, 0
    for line in body.decode("utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or "vers" not in row:
            continue
        rows += 1
        version = row.get("vers")
        if (not isinstance(version, str) or row.get("yanked") is True or not _VERSION.match(version)
                or "-" in version or "+" in version):
            continue
        if best is None or version_key(version) > version_key(best):
            best = version
    if rows == 0:
        raise ValueError("no version rows")
    return best


def _plain(resp) -> bytes:
    """The body of an answer, from gzip if needed. A body larger than MAX_BYTES after gzip is refused."""
    body = resp.body
    if resp.headers.get("content-encoding", "").lower() == "gzip" or body[:2] == b"\x1f\x8b":
        inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
        body = inflate.decompress(body, MAX_BYTES + 1)
        if inflate.unconsumed_tail:
            raise ValueError("answer is too large")
    if len(body) > MAX_BYTES:
        raise ValueError("answer is too large")
    return body


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


def _ask(registry: str, name: str, fetch: Fetch, headers: dict) -> str | None:
    """One request. Returns the latest stable version, or None. Raises for any failure."""
    resp = fetch(URLS[registry].format(name=name, path=crate_path(name)), headers)
    if resp.status != 200:
        raise ValueError(f"HTTP {resp.status}")
    body = _plain(resp)
    return parse_pypi(body) if registry == PYPI else parse_crate(body)


def lookup(registry: str, names: Iterable[str], data_dir: Path, fetch: Fetch = http_fetch,
           now: Callable[[], str] = utc_now, max_requests: int = MAX_LOOKUPS) -> dict[str, Latest]:
    """The latest version of each package, by the name that the caller gave. Never raises for a failed request.

    Asks the registry for at most `max_requests` packages that the cache does not hold for the last day.
    The other packages come back with `pending` set.
    """
    path = _cache_path(data_dir, registry)
    entries = _read(path)
    current = now()
    out: dict[str, Latest] = {}
    todo: list[str] = []
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": ACCEPT[registry], "Accept-Encoding": "gzip"}
    for name in dict.fromkeys(names):
        key = normalize(name)
        cached = entries.get(key) if isinstance(entries.get(key), dict) else None
        fresh = False
        if cached and isinstance(cached.get("fetched_at"), str):
            try:
                fresh = timedelta(0) <= _moment(current) - _moment(cached["fetched_at"]) < TTL
            except ValueError:
                fresh = False
        old = Latest(cached.get("version"), cached["fetched_at"]) if cached and isinstance(cached.get("fetched_at"), str) else None
        if fresh and old:
            old.note = NO_STABLE if old.version is None else None
            out[name] = old
        elif not _NAME.match(name):  # A name from a manifest is untrusted: it must look like a name.
            out[name] = Latest(None, None, ERROR_NAME)
        else:
            out[name] = old or Latest(None, None)
            out[name].pending = True
            todo.append(name)

    def ask(name: str):
        try:
            return name, _ask(registry, name, fetch, headers), None
        except Exception:  # Network, HTTP, size or parse failure. The cached answer stays.
            return name, None, ERROR_TEXT[registry]

    batch = todo[:max(0, max_requests)]
    if batch:
        with ThreadPoolExecutor(max_workers=min(WORKERS, len(batch))) as pool:
            for name, version, error in pool.map(ask, batch):
                if error:
                    out[name].pending, out[name].error = False, error
                else:
                    entries[normalize(name)] = {"version": version, "fetched_at": current}
                    out[name] = Latest(version, current, note=NO_STABLE if version is None else None)
    try:
        tmp = ensure_private_file(path.with_suffix(".tmp"))
        tmp.write_text(json.dumps({"format": CACHE_FORMAT, "entries": entries}))
        os.replace(tmp, path)
    except OSError:
        pass
    return out
