"""Local OSV vulnerability databases for offline OSV-Scanner runs.

External call (see README): GET https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip
for `npm` and `PyPI` only. The request names the ecosystem. Nothing about this Mac is sent.

Layout, as OSV-Scanner expects it with OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<data dir>/osv:
<data dir>/osv/osv-scanner/<ECOSYSTEM>/all.zip. Retrieval time and SHA-256 go in
<data dir>/osv/databases.json. Every refresh asks for a new copy (owner decision 2026-10-29).
If the download fails, the old copy stays and keeps its original age.
"""
from __future__ import annotations

import base64
import functools
import json
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .. import net
from ..models import utc_now
from ..store import ensure_private_dir, ensure_private_file

URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
ECOSYSTEMS = ("npm", "PyPI")
MAX_BYTES = 2 * 1024 * 1024 * 1024
TIMEOUT_SECONDS = 300
STALE_AFTER_DAYS = 7  # Owner decision 2026-10-29.
META_NAME = "databases.json"
ERROR_NOT_UPDATED = "OSV database did not update."


@dataclass
class Database:
    ecosystem: str
    path: Path
    fetched_at: str | None = None  # None: no usable copy.
    sha256: str | None = None
    fresh: bool = False  # True: this refresh downloaded or confirmed it.
    error: str | None = None
    detail: str | None = None

    @property
    def loaded(self) -> bool:
        return self.fetched_at is not None and self.path.is_file()

    def to_dict(self) -> dict:
        return {"ecosystem": self.ecosystem, "fetched_at": self.fetched_at, "sha256": self.sha256}


def db_root(data_dir: Path) -> Path:
    """The folder for OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY."""
    return Path(data_dir) / "osv"


def age_days(fetched_at: str, now: str) -> float:
    parse = lambda t: datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (parse(now) - parse(fetched_at)).total_seconds() / 86400


def _read_meta(root: Path) -> dict:
    try:
        data = json.loads((root / META_NAME).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_meta(root: Path, meta: dict) -> None:
    path = root / META_NAME
    tmp = ensure_private_file(path.with_suffix(".tmp"))
    tmp.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def _check_md5(path: Path, headers: dict) -> None:
    """Compare with the md5 in Google Cloud Storage's x-goog-hash header, if present."""
    for part in headers.get("x-goog-hash", "").split(","):
        key, _, value = part.strip().partition("=")
        if key == "md5":
            expected = base64.b64decode(value).hex()
            if net.file_digest(path, "md5") != expected:
                raise ValueError("download does not match its x-goog-hash md5")


def update_database(
    ecosystem: str,
    data_dir: Path,
    download: net.Download | None = None,
    now: Callable[[], str] = utc_now,
) -> Database:
    """Download a new copy of one ecosystem database, or keep the old copy on failure."""
    download = download or functools.partial(net.download, max_bytes=MAX_BYTES, timeout=TIMEOUT_SECONDS)
    root = ensure_private_dir(ensure_private_dir(Path(data_dir)) / "osv")
    folder = ensure_private_dir(ensure_private_dir(root / "osv-scanner") / ecosystem)
    path = folder / "all.zip"
    meta = _read_meta(root)
    old = meta.get(ecosystem) if isinstance(meta.get(ecosystem), dict) and path.is_file() else None
    headers = {"If-None-Match": old["etag"]} if old and old.get("etag") else {}
    url = URL.format(ecosystem=ecosystem)
    tmp = ensure_private_file(folder / "all.zip.download")
    try:
        resp = download(url, tmp, headers)
        if resp.status == 304 and old:
            sha = old.get("sha256")
        elif resp.status == 200:
            _check_md5(tmp, resp.headers)
            if not zipfile.is_zipfile(tmp):
                raise ValueError("download is not a zip file")
            sha = net.file_digest(tmp)
            os.replace(tmp, path)
        else:
            raise ValueError(f"HTTP {resp.status}")
        fetched_at = now()
        meta[ecosystem] = {"fetched_at": fetched_at, "sha256": sha, "etag": resp.headers.get("etag")}
        _write_meta(root, meta)
        return Database(ecosystem, path, fetched_at, sha, fresh=True)
    except Exception as exc:  # Network, HTTP, size, digest or format failure.
        detail = f"GET {url}: {exc!r}"
        if old and old.get("fetched_at"):
            return Database(ecosystem, path, old["fetched_at"], old.get("sha256"),
                            error=ERROR_NOT_UPDATED, detail=detail)
        return Database(ecosystem, path, error=ERROR_NOT_UPDATED, detail=detail)
    finally:
        tmp.unlink(missing_ok=True)
