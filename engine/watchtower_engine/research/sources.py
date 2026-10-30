"""The public pages and feeds for the incident check, and a safe parser for each.

External calls (see README): one plain GET for each source, no query and no header about this Mac:
- GitHub security blog feed (RSS).
- Google Workspace status feed (JSON).
- Apple security releases page (HTML table: name and link, available for, release date).
Only public product names go out, and only as part of the fixed URL. No path, project, package or
inventory data is ever sent.

Feed text is untrusted data. The parser:
- refuses an XML feed with a DOCTYPE or an entity (no entity expansion), and any body over 5 MB;
- reads the Apple page with the standard HTML parser, and takes text and the first link of a table cell only;
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
from html.parser import HTMLParser
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
    format: str  # rss, google_status or apple_releases
    hosts: tuple[str, ...]  # Links must be on one of these hosts.
    # True if the vendor itself publishes the feed. Only a primary source can confirm an incident.
    primary: bool = True
    # True if every item of the source is a vendor notice, for example a security release. It needs no
    # incident word: the notice itself is the record.
    notice: bool = False
    # True if the items are the vendor's own incident records (a status page). Only such a source can give
    # `Confirmed`. A blog or a release page cannot: an advice post is not a confirmation.
    incident_records: bool = False


SOURCES = (
    Source("github", "GitHub", "GitHub", "GitHub security blog", "https://github.blog/security/feed/", "rss",
           ("github.blog", "github.com", "githubstatus.com")),
    Source("google", "Google / Gmail", "Google / Gmail", "Google Workspace status",
           "https://www.google.com/appsstatus/dashboard/incidents.json", "google_status",
           ("google.com", "workspace.google.com", "blog.google"), incident_records=True),
    Source("apple", "Apple security", "Apple", "Apple security releases",
           "https://support.apple.com/en-us/100100", "apple_releases", ("support.apple.com",), notice=True),
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


_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def _apple_date(text: str) -> str | None:
    """`29 Oct 2026` as `2026-10-29`. English month names, no locale."""
    m = re.fullmatch(r"(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{4})", " ".join(text.split()))
    month = _MONTHS.get(m.group(2).lower()) if m else None
    if not m or not month:
        return None
    try:
        return datetime(int(m.group(3)), month, int(m.group(1))).strftime("%Y-%m-%d")
    except ValueError:
        return None


class _TableReader(HTMLParser):
    """Rows of every table: for each cell the text blocks and the first link. Reads text only."""

    BLOCKS = {"p", "div", "li", "br"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[dict]]] = []
        self._depth = 0
        self._row: list[dict] | None = None
        self._cell: dict | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "table":
            self._depth += 1
            if self._depth == 1:
                self.tables.append([])
        elif self._depth == 1 and tag == "tr":
            self._row = []
        elif self._depth == 1 and tag in ("td", "th") and self._row is not None:
            self._cell = {"blocks": [""], "href": None}
        elif self._cell is not None and tag == "a" and self._cell["href"] is None:
            self._cell["href"] = dict(attrs).get("href")
        elif self._cell is not None and tag in self.BLOCKS:
            self._cell["blocks"].append("")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "table":
            self._depth = max(0, self._depth - 1)
        elif self._depth == 1 and tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._cell["blocks"] = [b for b in (" ".join(b.split()) for b in self._cell["blocks"]) if b]
            self._row.append(self._cell)
            self._cell = None
        elif self._depth == 1 and tag == "tr" and self._row is not None and self.tables:
            self.tables[-1].append(self._row)
            self._row = None
        elif self._cell is not None and tag in self.BLOCKS:
            self._cell["blocks"].append("")

    def handle_data(self, data):
        if self._cell is not None and not self._skip:
            self._cell["blocks"][-1] += data


def parse_apple_releases(source: Source, body: bytes) -> list[Item]:
    """The security releases in the table of the Apple page. Raises SourceError if the table is not there.

    The table has a header row (`Name and information link`, `Available for`, `Release date`) and one row for
    each release. A row has no link if Apple publishes no page for it. The cell of the name can hold a note
    such as `This update has no published CVE entries.`
    """
    reader = _TableReader()
    try:
        reader.feed(body.decode("utf-8", errors="replace"))
        reader.close()
    except Exception as exc:  # The standard parser is lenient, but never trust the input.
        raise SourceError("bad data") from exc
    table = next((rows for rows in reader.tables if rows and _is_release_header(rows[0])), None)
    if table is None:
        raise SourceError("bad data")
    items = []
    for row in table[1:MAX_ITEMS + 1]:
        if len(row) < 3 or not row[0]["blocks"]:
            continue
        name = clean_text(row[0]["blocks"][0], TITLE_MAX - 18)
        if not name:
            continue
        available = clean_text(" ".join(row[1]["blocks"]), SUMMARY_MAX)
        notes = clean_text(" ".join(row[0]["blocks"][1:]), 200)
        summary = " ".join(x for x in (f"Available for: {available}." if available else "", notes) if x)
        date = _apple_date(" ".join(row[2]["blocks"]))
        url = clean_url(row[0]["href"], source.hosts)
        item = _item(source, url or f"{name}|{date or ''}", f"Security release: {name}", summary, None, url)
        if item:
            item.published = date
            items.append(item)
    if not items:
        raise SourceError("bad data")
    return items


def _is_release_header(row: list[dict]) -> bool:
    text = " ".join(" ".join(c["blocks"]) for c in row).lower().replace("\xa0", " ")
    return "release date" in text and "available for" in text and "name" in text


PARSERS = {"rss": parse_rss, "google_status": parse_google_status, "apple_releases": parse_apple_releases}


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
