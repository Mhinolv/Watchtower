"""The pinned OSV-Scanner release.

Watchtower runs only this exact release. The SHA-256 digests come from the official
release (https://github.com/google/osv-scanner/releases/tag/v2.7.0): the asset list and
`osv-scanner_SHA256SUMS` agree. The engine checks the digest after every download and
before every run. A mismatch means the scanner never runs.

To move to a new release: change OSV_SCANNER_VERSION and both digests in one reviewed PR.
Never resolve `latest` at run time.
"""
from __future__ import annotations

import functools
import os
import platform
from dataclasses import dataclass
from pathlib import Path

from .. import net
from ..store import ensure_private_dir, ensure_private_file

OSV_SCANNER_VERSION = "2.7.0"
RELEASE_URL = f"https://github.com/google/osv-scanner/releases/download/v{OSV_SCANNER_VERSION}"
MAX_BYTES = 200 * 1024 * 1024  # The macOS assets are about 55 MB.
EXEC_MODE = 0o700


@dataclass(frozen=True)
class Asset:
    name: str
    sha256: str

    @property
    def url(self) -> str:
        return f"{RELEASE_URL}/{self.name}"


# platform.machine() -> asset
ASSETS = {
    "arm64": Asset("osv-scanner_darwin_arm64", "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b"),
    "x86_64": Asset("osv-scanner_darwin_amd64", "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45"),
}


class ChecksumError(Exception):
    """The scanner file does not have the pinned digest. It must not run."""


class ScannerUnavailable(Exception):
    """No verified scanner is present and the download did not work."""


def asset_for(machine: str | None = None) -> Asset:
    machine = machine or platform.machine()
    if machine not in ASSETS:
        raise ScannerUnavailable(f"no pinned OSV-Scanner asset for {machine}")
    return ASSETS[machine]


def scanner_path(data_dir: Path, asset: Asset) -> Path:
    return Path(data_dir) / "tools" / f"{asset.name}-{OSV_SCANNER_VERSION}"


def verify(path: Path, asset: Asset) -> None:
    actual = net.file_digest(path)
    if actual != asset.sha256:
        raise ChecksumError(f"{path.name}: SHA-256 {actual}, pinned {asset.sha256}")


def ensure_scanner(data_dir: Path, asset: Asset, download: net.Download | None = None) -> Path:
    """Return the path of a verified scanner. Download it if it is missing.

    A file that fails the check is deleted and ChecksumError is raised. The next
    refresh downloads a new copy. A download that fails the check never becomes executable.
    """
    download = download or functools.partial(net.download, max_bytes=MAX_BYTES)
    tools = ensure_private_dir(ensure_private_dir(Path(data_dir)) / "tools")
    path = scanner_path(data_dir, asset)
    if path.exists():
        try:
            verify(path, asset)
        except ChecksumError:
            path.unlink(missing_ok=True)
            raise
        os.chmod(path, EXEC_MODE)
        return path
    tmp = ensure_private_file(tools / f"{path.name}.download")
    try:
        try:
            resp = download(asset.url, tmp, {})
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
        except Exception as exc:
            raise ScannerUnavailable(f"GET {asset.url}: {exc!r}") from exc
        verify(tmp, asset)
        os.chmod(tmp, EXEC_MODE)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return path
