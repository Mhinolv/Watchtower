"""The public pages and feeds for the incident check, and a safe parser for each.

External calls (see README): one plain GET for each source, no query and no header about this Mac:
- GitHub security blog feed (RSS).
- Google Workspace status feed (JSON).
- Apple security releases feed (RSS).
Only public product names go out, and only as part of the fixed URL. No path, project, package or
inventory data is ever sent.

Feed text is untrusted data. The parser:
- refuses a document with a DOCTYPE or an entity (no entity expansion), and a body over 5 MB;
- removes markup and control characters from titles and summaries, and cuts them to a fixed length;
- keeps a link only if it is https and on a host of the source;
- never follows a link and never reads an instruction in the text.
"""
from __future__ import annotations

import html
import json
import re
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .. import __version__

if TYPE_CHECKING:  # The store imports this package, so the feed module is loaded only when it is used.
    from ..feeds.homebrew import Fetch, Response

MAX_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 200
TITLE_MAX = 200
SUMMARY_MAX = 600
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class Source:
    key: str
    label: str  # The name in the source row: `GitHub`.
    service: str  # The service of the incident column.
    source_name: str  # The name in the Source column: `GitHub security blog`.
    url: str
    format: str  # rss or google_status
    hosts: tuple[str, ...]  # Links must be on one of these hosts.
    # True if the vendor itself publishes the feed. Only a primary source can confirm an incident.
    primary: bool = True


SOURCES = (
    Source("github", "GitHub", "GitHub", "GitHub security blog", "https://github.blog/security/feed/", "rss",
           ("github.blog", "github.com", "githubstatus.com")),
    Source("google", "Google / Gmail", "Google / Gmail", "Google Workspace status",
           "https://www.google.com/appsstatus/dashboard/incidents.json", "google_status",
           ("google.com", "workspace.google.com", "blog.google")),
    Source("apple", "Apple security", "Apple", "Apple security releases",
           "https://support.apple.com/en_US/rss/securityupdates.rss", "rss", ("support.apple.com", "apple.com")),
)


@dataclass
class Item:
    guid: str
    title: str
    summary: str
    published: str | None  # `2026-10-27` in UTC, or None if the date is unknown.
    url: str | None
    cves: list[str] = field(default_factory=list)


class Cancelled(Exception):
    """The owner stopped the check. Nothing is saved."""


class SourceError(Exception):
    """A source did not give usable data. `str()` is a short reason for the source row."""


# Text


def clean_text(value, limit: int) -> str:
    """Plain text from untrusted markup: no tags, no control characters, one line, cut to `limit`."""
    if not isinstance(value, str):
        return ""
    text = html.unescape(re.sub(r"<[^>]*>", " ", value))
    text = "".join(" " if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c for c in text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def clean_url(value, hosts: tuple[str, ...]) -> str | None:
    if not isinstance(value, str):
        return None
    url = value.strip()
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or not host or len(url) > 500:
        return None
    return url if any(host == h or host.endswith("." + h) for h in hosts) else None


def parse_date(value) -> str | None:
    """A date of any feed style as `YYYY-MM-DD` in UTC, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    moment = None
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        pass
    if moment is None:
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _item(source: Source, guid, title, summary, published, link) -> Item | None:
    title = clean_text(title, TITLE_MAX)
    if not title:
        return None
    summary = clean_text(summary, SUMMARY_MAX)
    url = clean_url(link, source.hosts)
    guid = clean_text(guid, 300) or url or title
    cves = sorted({m.upper() for m in CVE_RE.findall(f"{title} {summary}")})
    return Item(guid=guid, title=title, summary=summary, published=parse_date(published), url=url, cves=cves)


# Parsers


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child_text(node: ET.Element, *names: str) -> str | None:
    for child in node:
        if _local(child.tag) in names and (child.text or "").strip():
            return child.text
    return None


def _link(node: ET.Element) -> str | None:
    for child in node:
        if _local(child.tag) == "link":
            href = child.get("href")
            if href and child.get("rel", "alternate") == "alternate":
                return href
            if (child.text or "").strip():
                return child.text
    return None


def parse_rss(source: Source, body: bytes) -> list[Item]:
    """RSS 2.0 and Atom. Raises SourceError for a document that is not a feed."""
    if b"<!doctype" in body[:100000].lower() or b"<!entity" in body[:100000].lower():
        raise SourceError("bad data")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise SourceError("bad data") from exc
    nodes = [n for n in root.iter() if _local(n.tag) in ("item", "entry")]
    if not nodes and _local(root.tag) not in ("rss", "feed", "RDF"):
        raise SourceError("bad data")
    items = []
    for node in nodes[:MAX_ITEMS]:
        item = _item(source, _child_text(node, "guid", "id"), _child_text(node, "title"),
                     _child_text(node, "description", "summary", "content", "encoded"),
                     _child_text(node, "pubDate", "published", "updated", "date"), _link(node))
        if item:
            items.append(item)
    return items


def parse_google_status(source: Source, body: bytes) -> list[Item]:
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise SourceError("bad data") from exc
    if not isinstance(data, list):
        raise SourceError("bad data")
    items = []
    for row in data[:MAX_ITEMS]:
        if not isinstance(row, dict):
            continue
        update = row.get("most_recent_update")
        text = update.get("text") if isinstance(update, dict) else None
        link = row.get("uri")
        if not (isinstance(link, str) and link.startswith("https://")):  # A relative link is not trusted.
            link = (f"https://www.google.com/appsstatus/dashboard/incidents/{row['id']}"
                    if isinstance(row.get("id"), str) and re.fullmatch(r"[\w.-]{1,60}", row["id"]) else None)
        item = _item(source, row.get("id") or row.get("number"), row.get("external_desc"), text,
                     row.get("begin") or row.get("created"), link)
        if item:
            items.append(item)
    return items


PARSERS = {"rss": parse_rss, "google_status": parse_google_status}


# Fetch


def _reason(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return "rate limit" if code == 429 else f"HTTP {code}"
    return "network error"


def fetch_items(source: Source, fetch: "Fetch | None" = None) -> list[Item]:
    """One plain GET of the source. Raises SourceError with a short reason."""
    if fetch is None:
        from ..feeds.homebrew import http_fetch
        fetch = http_fetch
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/rss+xml, application/json, */*"}
    try:
        resp = fetch(source.url, headers)
    except (SourceError, Cancelled):
        raise
    except Exception as exc:  # Network, HTTP error status or timeout.
        raise SourceError(_reason(exc)) from exc
    if resp.status == 429:
        raise SourceError("rate limit")
    if resp.status != 200:
        raise SourceError(f"HTTP {resp.status}")
    if len(resp.body) > MAX_BYTES:
        raise SourceError("too large")
    return PARSERS[source.format](source, resp.body)
