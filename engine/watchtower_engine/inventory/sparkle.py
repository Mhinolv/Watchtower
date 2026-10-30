"""Sparkle appcasts: the newest version that an app's own update feed offers (#14).

An app with `SUFeedURL` in its Info.plist names its Sparkle feed. The engine reads that
feed and compares it with the installed build. It never installs anything: the owner
uses the app's own Check for Updates command.

External call (see README): GET <SUFeedURL>, HTTPS only, for apps that have one. The
request sends a User-Agent and nothing about this Mac. The appcast is untrusted data:
no DTD or entities, a size limit, and only known fields are read.

The last good result of each feed stays in `<data dir>/cache/sparkle.json` (0600).
A failed check never clears it.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import functools
import platform
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.parsers import expat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .. import __version__
from ..models import CoverageRecord, ItemRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import version_key

SOURCE = "sparkle"
LABEL = "Sparkle feeds"
SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
TIMEOUT_SECONDS = 20
MAX_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 500
ORIGIN = "Sparkle feed"

# Owner-facing text (#14 Design notes).
NOTE_UPDATE = "Use the app's Check for Updates command to install it."
NOTE_OS_TOO_OLD = "{version} needs macOS {minimum}. This Mac has {current}."
NOTE_BETA = "A beta ({version}) is available."
NOTE_NOT_HTTPS = "Watchtower reads HTTPS feeds only."
NOTE_CREDENTIALS = "The feed address has credentials. Watchtower did not read it."
NOTE_LOCAL = "The feed address is on this Mac or a local network. Watchtower did not read it."
ERROR_FAILED = "Feed check failed."
ERROR_SOME = "Some Sparkle feeds did not load."
COVERAGE_NOTE = "{read} of {total} read"

# Query names that carry a secret. A feed URL with one is never read or shown.
_SECRET_PARAMS = {"token", "access_token", "auth", "authorization", "key", "apikey", "api_key", "secret",
                  "password", "passwd", "pwd", "sig", "signature", "session", "sessionid"}


# URL rules


def url_problem(url: str) -> str | None:
    """Why the engine must not read `url`, as an owner note, or None."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host = parts.hostname
    except ValueError:
        return NOTE_NOT_HTTPS
    if parts.scheme.lower() != "https" or not host:
        return NOTE_NOT_HTTPS
    if parts.username or parts.password:
        return NOTE_CREDENTIALS
    names = {k.lower() for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)}
    if names & _SECRET_PARAMS:
        return NOTE_CREDENTIALS
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return NOTE_LOCAL
    ip = host_ip(host)
    if ip is not None and not ip.is_global:
        return NOTE_LOCAL
    return None


def host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address that the OS reads from a numeric host, or None for a host name.

    The OS also reads short and numeric forms (`127.1`, `2130706433`, `0x7f.0.0.1`, `017700000001`, `0`),
    so the engine reads them the same way with `inet_aton` (QA 14-1). An IPv4-mapped IPv6 address
    counts as its IPv4 address.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped or ip


def shown_url(url: str) -> str | None:
    """The feed address for the detail pane. None if it must not be shown (credentials)."""
    return None if url_problem(url) == NOTE_CREDENTIALS else url.strip()


# Fetch

# fetch(url) -> bytes. Tests pass a fake. Raises OSError or ValueError on failure.
FetchFeed = Callable[[str], bytes]


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an address that passes the same URL rules."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if url_problem(newurl):
            raise urllib.error.HTTPError(newurl, code, "redirect to an address that Watchtower does not read",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# resolve(host, port) -> the addresses for a TCP connection. Tests pass a fake.
Resolver = Callable[[str, int], list[str]]


def system_resolve(host: str, port: int) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


class LocalAddress(ValueError):
    """The host name resolves to an address that is not global (#67)."""


def checked_address(host: str, port: int, resolve: Resolver) -> str:
    """The address to connect to. Raises LocalAddress if any address of the host is not global.

    One answer is checked and used, so a second DNS answer cannot move the connection (#67).
    """
    addresses = list(resolve(host, port))
    if not addresses:
        raise OSError(f"{host} has no address")
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError as exc:
            raise LocalAddress(f"{host} resolves to {text!r}, which is not an IP address") from exc
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if not ip.is_global:
            raise LocalAddress(f"{host} resolves to {ip}, which is not a global address")
    return addresses[0].split("%")[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the checked address. TLS still checks the certificate against the host name."""

    def __init__(self, host, *, address: str, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Resolve and check each request host (redirects too) before the connection."""

    def __init__(self, resolve: Resolver):
        super().__init__()
        self._resolve = resolve

    def https_open(self, req):
        parts = urllib.parse.urlsplit(req.full_url)
        address = checked_address(parts.hostname, parts.port or 443, self._resolve)
        return self.do_open(functools.partial(_PinnedHTTPSConnection, address=address), req,
                            context=self._context)


def fetch_feed(url: str, resolve: Resolver = system_resolve) -> bytes:
    # No proxy: the engine connects to the checked address itself (#67).
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SafeRedirects,
                                         _PinnedHTTPSHandler(resolve))
    request = urllib.request.Request(url, headers={"User-Agent": f"Watchtower/{__version__}",
                                                   "Accept": "application/rss+xml, application/xml, text/xml"})
    with opener.open(request, timeout=TIMEOUT_SECONDS) as resp:
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"appcast is larger than {MAX_BYTES} bytes")
    return body


# Parse


@dataclass
class Release:
    build: str  # sparkle:version (compared with CFBundleVersion)
    version: str  # sparkle:shortVersionString, else the build
    minimum_os: str | None = None
    channel: str | None = None  # None: the default (stable) channel


def _text(node, tag: str) -> str | None:
    found = node.find(f"{{{SPARKLE_NS}}}{tag}")
    value = found.text.strip() if found is not None and found.text else ""
    return value or None


def refuse_dtd(data: bytes) -> None:
    """Raise ValueError if the document has a DOCTYPE or an entity declaration, in any encoding.

    Expat reads the encoding of the document (UTF-8, UTF-16 with or without a BOM) the same way as
    the parser below, so a byte search cannot miss what the parser would read (QA 14-1).
    """
    def refuse(*_):
        raise ValueError("appcast has a DTD or entities")

    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError(f"appcast is not XML: {exc}") from exc


def parse_appcast(data: bytes) -> list[Release]:
    """Releases in the appcast. Raises ValueError for a document that is not a safe appcast."""
    refuse_dtd(data)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"appcast is not XML: {exc}") from exc
    releases = []
    for item in root.iter("item"):
        if len(releases) >= MAX_ITEMS:
            break
        enclosure = item.find("enclosure")
        attr = (lambda name: enclosure.get(f"{{{SPARKLE_NS}}}{name}")) if enclosure is not None else (lambda name: None)
        if (attr("os") or "macos").lower() not in ("macos", "osx", "mac"):
            continue  # A Windows or Linux release in a shared feed.
        build = _text(item, "version") or attr("version")
        if not build:
            continue
        version = _text(item, "shortVersionString") or attr("shortVersionString") or build
        releases.append(Release(build=build.strip(), version=version.strip(),
                                minimum_os=_text(item, "minimumSystemVersion"),
                                channel=(_text(item, "channel") or None)))
    if not releases:
        raise ValueError("appcast has no release with a version")
    return releases


# Compare


@dataclass
class Evidence:
    """What one feed says about one app. Saved in the cache and in item attributes."""
    feed: str | None
    build: str
    version: str
    minimum_os: str | None
    channel: str | None
    beta_version: str | None
    checked_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def newest(releases: list[Release], channel: str | None) -> Release | None:
    picked = [r for r in releases if r.channel == channel]
    return max(picked, key=lambda r: version_key(r.build), default=None)


def evidence(url: str, releases: list[Release], now: str) -> Evidence:
    stable = newest(releases, None)
    beta = max((r for r in releases if r.channel), key=lambda r: version_key(r.build), default=None)
    main = stable or beta
    beta_version = beta.version if beta and (stable is None or version_key(beta.build) > version_key(stable.build)) else None
    return Evidence(shown_url(url), main.build, main.version, main.minimum_os, main.channel, beta_version, now)


def macos_version() -> str | None:
    return platform.mac_ver()[0] or None


def apply(item: ItemRecord, installed_build: str | None, ev: Evidence, os_version: str | None) -> None:
    """Set state, latest version and note of an app item from feed evidence."""
    item.origin = ORIGIN
    item.latest_version = ev.version
    item.source_at = ev.checked_at
    attributes = dict(item.attributes or {})
    if ev.feed:
        attributes["sparkleFeed"] = ev.feed
    attributes["sparkleLatest"] = ev.version if ev.version == ev.build else f"{ev.version} ({ev.build})"
    attributes["sparkleChannel"] = (ev.channel or "stable").capitalize()
    if ev.minimum_os:
        attributes["sparkleMinimumOs"] = ev.minimum_os
    attributes["sparkleChecked"] = ev.checked_at
    item.attributes = attributes
    newer = installed_build is not None and version_key(ev.build) > version_key(installed_build)
    if newer and ev.minimum_os and os_version and version_key(ev.minimum_os) > version_key(os_version):
        item.state, item.note = "manual", NOTE_OS_TOO_OLD.format(version=ev.version, minimum=ev.minimum_os,
                                                                current=os_version)
    elif newer and ev.channel is None:
        item.state, item.note = "update_available", NOTE_UPDATE
    elif installed_build is None:
        item.state, item.note = "unknown", None
    else:
        item.state = "up_to_date"
        item.note = NOTE_BETA.format(version=ev.beta_version) if ev.beta_version else None


# Cache


class Cache:
    def __init__(self, data_dir: Path):
        folder = ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache")
        self.path = folder / "sparkle.json"

    def read(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def write(self, data: dict) -> None:
        tmp = ensure_private_file(self.path.with_suffix(".tmp"))
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.path)


# Check the apps


@dataclass
class Target:
    """One app item with a feed URL."""
    item: ItemRecord
    feed_url: str
    installed_build: str | None


@dataclass
class Result:
    coverage: CoverageRecord
    checked: int = 0
    total: int = 0
    failures: list[str] = field(default_factory=list)


def check(targets: list[Target], data_dir: Path, fetch: FetchFeed = fetch_feed,
          now: Callable[[], str] = utc_now, os_version: str | None = None) -> Result:
    """Read each feed and update its item. Keeps the cached evidence when a feed fails."""
    os_version = os_version if os_version is not None else macos_version()
    cache = Cache(data_dir)
    saved = cache.read()
    read = failed = 0
    details = []
    for t in targets:
        key = t.item.id
        problem = url_problem(t.feed_url)
        if problem:
            t.item.state, t.item.note = "unknown", problem
            attributes = dict(t.item.attributes or {})
            if shown_url(t.feed_url):
                attributes["sparkleFeed"] = shown_url(t.feed_url)
            t.item.attributes = attributes
            continue
        try:
            ev = evidence(t.feed_url, parse_appcast(fetch(t.feed_url)), now())
        except LocalAddress:  # The host name resolves to this Mac or a local network (#67).
            t.item.state, t.item.note = "unknown", NOTE_LOCAL
            continue
        except Exception as exc:  # Network, HTTP, size or parse failure.
            failed += 1
            details.append(f"{t.item.name}: {exc!r}")
            old = saved.get(key)
            if isinstance(old, dict):
                try:
                    apply(t.item, t.installed_build, Evidence(**old), os_version)
                except TypeError:
                    pass  # A cache entry from another format: ignore it.
            t.item.error, t.item.detail = ERROR_FAILED, repr(exc)
            continue
        read += 1
        saved[key] = ev.to_dict()
        apply(t.item, t.installed_build, ev, os_version)
    if targets:
        cache.write(saved)
    total = len(targets)
    note = COVERAGE_NOTE.format(read=read, total=total)
    if total == 0:
        coverage = CoverageRecord(SOURCE, LABEL, "not_run", note="No app has a Sparkle feed.")
    elif failed == 0:
        coverage = CoverageRecord(SOURCE, LABEL, "complete", note=note)
    else:
        coverage = CoverageRecord(SOURCE, LABEL, "failed" if read == 0 else "partial", error=ERROR_SOME,
                                  detail="\n".join(details), note=note)
    return Result(coverage, read, total, details)
