"""Streamed HTTPS downloads to a file, and file digests.

Every caller documents its URL in the README. Nothing about this Mac goes in a request.
"""
from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import __version__

CHUNK = 1024 * 1024


@dataclass
class Downloaded:
    status: int
    headers: dict  # Lower-case names.


# download(url, dest, headers) -> Downloaded. Tests pass a fake. Raises OSError or ValueError on failure.
Download = Callable[[str, Path, dict], Downloaded]


def download(url: str, dest: Path, headers: dict, max_bytes: int, timeout: int = 60) -> Downloaded:
    """Write the body of `url` to `dest`, which must exist with mode 0600. A 304 writes nothing."""
    request = urllib.request.Request(url, headers={"User-Agent": f"Watchtower/{__version__}", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp, open(dest, "wb") as out:
            total = 0
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"response is larger than {max_bytes} bytes")
                out.write(chunk)
            return Downloaded(resp.status, {k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return Downloaded(304, {k.lower(): v for k, v in exc.headers.items()})
        raise


def file_digest(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
