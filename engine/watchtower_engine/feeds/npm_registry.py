"""Public npm registry metadata for one package.

External calls (see README): GET https://registry.npmjs.org/<package> (abbreviated metadata)
and GET https://registry.npmjs.org/<package>/<version> (one version, for script names).
Only the package name and a version leave the Mac. The engine never reads .npmrc or tokens.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from .. import __version__

REGISTRY = "https://registry.npmjs.org"
TIMEOUT_SECONDS = 30
MAX_BYTES = 50 * 1024 * 1024
ABBREVIATED = "application/vnd.npm.install-v1+json"

# get_json(url, accept) -> dict. Tests pass a fake. Raises OSError or ValueError on failure.
GetJson = Callable[[str, str], dict]


def get_json(url: str, accept: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": f"Watchtower/{__version__}"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as resp:
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("registry response is too large")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("registry response is not a JSON object")
    return data


def package_url(name: str, version: str | None = None) -> str:
    quoted = urllib.parse.quote(name, safe="@")  # @scope/name -> @scope%2Fname
    return f"{REGISTRY}/{quoted}" + (f"/{urllib.parse.quote(version)}" if version else "")


def versions(name: str, get: GetJson = get_json) -> tuple[list[str], str | None]:
    """All published versions and the `latest` dist-tag."""
    data = get(package_url(name), ABBREVIATED)
    found = list((data.get("versions") or {}).keys())
    return found, (data.get("dist-tags") or {}).get("latest")


def install_scripts(name: str, version: str, get: GetJson = get_json) -> list[str]:
    """Names of the install-time scripts of one version, for example ["postinstall"]."""
    data = get(package_url(name, version), "application/json")
    scripts = data.get("scripts") or {}
    found = [s for s in ("preinstall", "install", "postinstall") if s in scripts]
    if not found and data.get("gypfile"):
        found = ["install"]  # npm runs node-gyp rebuild for a binding.gyp package
    return found
