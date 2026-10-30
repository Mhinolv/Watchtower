"""Vendor support status of macOS and the installed runtimes, from endoflife.date (#59).

External call (see README): one GET for each product that this Mac has, `https://endoflife.date/api/v1/products/<product>/`.
The request holds the product name (`nodejs`, `python`, `macos`) and a User-Agent. It never holds a version, a path, a
project, an app name or a finding. The compare runs on this Mac: the installed version picks one release line of the answer.

The answer is untrusted data. Only the release line name, four dates and two flags are read, with format checks and limits.

The last good answer of each product stays in `<data dir>/cache/endoflife/products.json` (0600). If a request fails, the
engine uses that copy with its own age, and the item says so. A failed request never clears earlier data.

The support status is not the update status: the engine does not change `state` or `note` of an item. It writes the
attributes `eolState`, `eolEnd`, `eolCycle`, `eolChecked` and `eolError`.
States: `supported`, `ends_soon` (the end date is within 90 days), `security_only` (active support ended, the end of
life is not here yet), `end_of_life`, `unknown` (no entry or no answer).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..models import CoverageRecord, ItemRecord, utc_now
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Fetch, http_fetch

SOURCE = "endoflife"
LABEL = "endoflife.date"
URL = "https://endoflife.date/api/v1/products/{product}/"
MACOS_PRODUCT = "macos"
ENDS_SOON_DAYS = 90  # Owner decision (#59): the same window as the 90-day vendor note of #18.
MAX_BYTES = 2 * 1024 * 1024
MAX_CYCLES = 300
CACHE_FORMAT = 1

STATES = ("supported", "ends_soon", "security_only", "end_of_life", "unknown")
ATTRIBUTE_KEYS = ("eolState", "eolEnd", "eolCycle", "eolChecked", "eolError")

# Owner-facing text (#59 Design notes).
ERROR_FAILED = "endoflife.date did not respond."
ERROR_SOME = "endoflife.date did not respond. Watchtower used the last copy."
NOTE_NO_ENTRY = "No entry at endoflife.date for: {products}."

_PRODUCT = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_CYCLE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_NUMBERS = re.compile(r"^\d+(?:\.\d+)*")


@dataclass
class Cycle:
    """One release line: `22` for Node.js, `3.12` for Python, `15` for macOS."""
    name: str
    eol_from: str | None = None  # YYYY-MM-DD. None: no end date is known.
    is_eol: bool = False
    eoas_from: str | None = None  # The end of active support: the security-only phase starts.
    is_eoas: bool = False


@dataclass
class Product:
    cycles: list[Cycle] = field(default_factory=list)
    fetched_at: str | None = None  # None: no data.
    fresh: bool = False  # True: this refresh got the answer.


@dataclass
class Status:
    state: str
    end: str | None = None  # The end of life date, if one is known.
    cycle: str | None = None


# Parse


def _day(value) -> str | None:
    return value if isinstance(value, str) and _DATE.match(value) and _valid(value) else None


def _valid(text: str) -> bool:
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def parse(body: bytes) -> list[Cycle]:
    """The release lines of one product answer. Raises ValueError for a body that is not an answer of the API."""
    if len(body) > MAX_BYTES:
        raise ValueError(f"response is larger than {MAX_BYTES} bytes")
    data = json.loads(body)
    result = data.get("result") if isinstance(data, dict) else None
    rows = result.get("releases") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise ValueError("no releases list")
    cycles = []
    for row in rows[:MAX_CYCLES]:
        name = row.get("name") if isinstance(row, dict) else None
        if not isinstance(name, str) or not _CYCLE.match(name):
            continue
        cycles.append(Cycle(name, _day(row.get("eolFrom")), row.get("isEol") is True, _day(row.get("eoasFrom")),
                            row.get("isEoas") is True))
    if not cycles:
        raise ValueError("the answer has no release line")
    return cycles


# Compare


def find_cycle(cycles: Iterable[Cycle], version: str) -> Cycle | None:
    """The release line of an installed version: the longest line name that starts the version, part by part.

    `3.12` fits `3.12.11` and not `3.1.5`. `22` fits `22.9.0`. A version that is not made of numbers has no line.
    """
    found = _NUMBERS.match(version.strip().lstrip("v"))
    if not found:
        return None
    parts = found.group(0).split(".")
    best = None
    for cycle in cycles:
        line = cycle.name.split(".")
        if all(p.isdigit() for p in line) and len(line) <= len(parts) and parts[:len(line)] == line:
            if best is None or len(line) > len(best.name.split(".")):
                best = cycle
    return best


def status(cycle: Cycle, today: date) -> Status:
    """The support state on `today`. A date decides, and the flag only if there is no date (earlier data ages)."""
    end = date.fromisoformat(cycle.eol_from) if cycle.eol_from else None
    active_end = date.fromisoformat(cycle.eoas_from) if cycle.eoas_from else None
    over = end <= today if end else cycle.is_eol
    security = active_end <= today if active_end else cycle.is_eoas
    if over:
        return Status("end_of_life", cycle.eol_from, cycle.name)
    if security:
        return Status("security_only", cycle.eol_from, cycle.name)
    if end and (end - today).days <= ENDS_SOON_DAYS:
        return Status("ends_soon", cycle.eol_from, cycle.name)
    return Status("supported", cycle.eol_from, cycle.name)


# Cache


def _cache_path(data_dir: Path) -> Path:
    folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "cache") / "endoflife")
    return folder / "products.json"


def _read_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    products = data.get("products") if isinstance(data, dict) and data.get("format") == CACHE_FORMAT else None
    return products if isinstance(products, dict) else {}


def _write_cache(path: Path, products: dict) -> None:
    tmp = ensure_private_file(path.with_suffix(".tmp"))
    tmp.write_text(json.dumps({"format": CACHE_FORMAT, "products": products}))
    os.replace(tmp, path)


def _cached(entry) -> Product:
    try:
        cycles = [Cycle(c["name"], c["eol_from"], c["is_eol"], c["eoas_from"], c["is_eoas"]) for c in entry["cycles"]]
        return Product(cycles, entry["fetched_at"]) if isinstance(entry["fetched_at"], str) and cycles else Product()
    except (KeyError, TypeError, ValueError, AttributeError):
        return Product()  # A cache entry of another format: ignore it.


def _entry(cycles: list[Cycle], fetched_at: str) -> dict:
    return {"fetched_at": fetched_at, "cycles": [
        {"name": c.name, "eol_from": c.eol_from, "is_eol": c.is_eol, "eoas_from": c.eoas_from, "is_eoas": c.is_eoas}
        for c in cycles]}


# Items


def product_of(item: ItemRecord) -> str | None:
    """The endoflife.date product of an item, or None if it has none. Only the product name leaves this Mac."""
    if item.source == "macos" and item.id == "macos":
        return MACOS_PRODUCT
    if item.source == "runtimes" and item.kind == "runtime":
        product = (item.attributes or {}).get("eolProduct")
        return product if isinstance(product, str) and _PRODUCT.match(product) else None
    return None


def covers(item: ItemRecord) -> bool:
    """True for the macOS item and every runtime install: they get a support state (`unknown` if no entry fits)."""
    return (item.source == "macos" and item.id == "macos") or (item.source == "runtimes" and item.kind == "runtime")


def _installed(item: ItemRecord) -> str | None:
    """`15.1 (a)` (with a Rapid Security Response) is `15.1`."""
    first = (item.installed_version or "").split(" ")[0]
    return first or None


def apply(item: ItemRecord, product: Product | None, error: str | None, today: date) -> None:
    """Set the `eol*` attributes of one item. The update state and the note stay as they are."""
    attributes = {k: v for k, v in (item.attributes or {}).items() if k not in ATTRIBUTE_KEYS}
    cycle = None
    version = _installed(item)
    if product and product.cycles and version:
        cycle = find_cycle(product.cycles, version)
    if cycle:
        result = status(cycle, today)
        attributes["eolState"] = result.state
        attributes["eolCycle"] = cycle.name
        if result.end:
            attributes["eolEnd"] = result.end
    else:
        attributes["eolState"] = "unknown"
    if product and product.fetched_at:
        attributes["eolChecked"] = product.fetched_at
    if error:
        attributes["eolError"] = error
    item.attributes = attributes


def _is_missing(exc: Exception) -> bool:
    return getattr(exc, "code", None) == 404


def check(items: Iterable[ItemRecord], data_dir: Path, fetch: Fetch = http_fetch,
          now: Callable[[], str] = utc_now) -> CoverageRecord:
    """Ask endoflife.date for each product of the items and set the support attributes in place."""
    items = [i for i in items if covers(i)]
    wanted = sorted({p for p in map(product_of, items) if p})
    path = _cache_path(data_dir)
    saved = _read_cache(path)
    headers = {"User-Agent": f"Watchtower/{__version__}", "Accept": "application/json"}
    products: dict[str, Product] = {}
    failures: list[str] = []
    missing: list[str] = []
    for slug in wanted:
        url = URL.format(product=slug)
        try:
            resp = fetch(url, headers)
            if resp.status == 404:
                missing.append(slug)
                products[slug] = Product()
                saved.pop(slug, None)  # The product is gone from the site: an old copy would mislead.
                continue
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            cycles = parse(resp.body)
        except Exception as exc:  # Network, HTTP, size or parse failure: use the last copy.
            if _is_missing(exc):
                missing.append(slug)
                products[slug] = Product()
                saved.pop(slug, None)
                continue
            failures.append(f"GET {url}: {exc!r}")
            products[slug] = _cached(saved.get(slug)) if isinstance(saved.get(slug), dict) else Product()
            continue
        stamp = now()
        products[slug] = Product(cycles, stamp, fresh=True)
        saved[slug] = _entry(cycles, stamp)
    if wanted:
        try:
            _write_cache(path, saved)
        except OSError:
            pass

    today = date.fromisoformat(now()[:10])
    for item in items:
        slug = product_of(item)
        product = products.get(slug) if slug else None
        failed = bool(product and not product.fresh and slug not in missing)
        apply(item, product, ERROR_FAILED if failed else None, today)

    used = [p.fetched_at for p in products.values() if p.fetched_at]
    detail = "\n".join(failures) or None
    note = NOTE_NO_ENTRY.format(products=", ".join(missing)) if missing else None
    if not failures:
        return CoverageRecord(SOURCE, LABEL, "complete", source_at=min(used) if used else None, note=note, detail=note)
    if not used:
        return CoverageRecord(SOURCE, LABEL, "failed", error=ERROR_FAILED, detail=detail)
    # "Used the last copy" is true only if a failed product had a copy.
    copied = any(p.fetched_at and not p.fresh for s, p in products.items() if s not in missing)
    return CoverageRecord(SOURCE, LABEL, "partial", error=ERROR_SOME if copied else ERROR_FAILED, detail=detail,
                          source_at=min(used))
