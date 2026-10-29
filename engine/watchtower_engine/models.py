"""Records shared by the engine and the Swift app.

The JSON field names here are a contract with `Sources/WatchtowerCore/Models.swift`.
Do not rename them. Add new fields as optional and bump SCHEMA_VERSION only for
changes that old readers cannot ignore.
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

SCHEMA_VERSION = 1

REFRESH_STATUSES = ("running", "complete", "partial", "failed", "cancelled")
COVERAGE_STATES = ("complete", "partial", "failed", "stale", "not_run")
ITEM_STATES = (
    "up_to_date",
    "update_available",
    "vulnerable",
    "unknown",
    "error",
    "pinned",
    "manual",
)

# Paths inside these roots may appear in an owner-facing `error`. Others are redacted.
DEFAULT_SCAN_ROOTS = ("~/Projects", "~/Real", "~/Applications", "/Applications")

ERROR_MAX_CHARS = 80


def utc_now() -> str:
    """Current time as ISO 8601 UTC with second precision, for example 2026-10-29T19:56:37Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(value: str, allowed: tuple[str, ...], field: str) -> None:
    if value not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}, not {value!r}")


# A file:// URL, or an absolute or home-relative path that starts a token.
# A path has no final "." or ":". It excludes "and/or" and https:// URLs.
_PATH_RE = re.compile(
    r"(?<![\w.:/~])(?P<url>file://[^\s'\"`,;()\[\]<>]*[^\s'\"`,;()\[\]<>.:])"
    r"|(?<![\w.:/~])(?P<path>~?/[^\s'\"`,;()\[\]]*[^\s'\"`,;()\[\].:])",
    re.IGNORECASE,
)

# A path can hold spaces ("Application Support"). Where it ends is not clear, so the
# redaction reads on over at most this many words after a space.
_MAX_SPACE_WORDS = 3
_END_PUNCTUATION = ".:,;!?)]}'\"`"
# After a lowercase word, these end the path and the text after them stays.
_HARD_STOP = ":,;)]}"
# After a lowercase word, these end a sentence: the path ended before that word.
_SENTENCE_END = ".!?'\"`"
# A lowercase word like these before a sentence end is not part of a path: `/etc/hosts now.`
_PLAIN_WORDS = frozenset(
    {"now", "again", "then", "here", "there", "too", "instead", "anyway", "later", "today",
     "soon", "once", "twice", "please", "yet"}
)


def _under_roots(path: str, roots: tuple[str, ...]) -> bool:
    full = os.path.normpath(os.path.expanduser(path))
    for root in roots:
        base = os.path.normpath(os.path.expanduser(root))
        if full == base or full.startswith(base + os.sep):
            return True
    return False


def _starts_new_path(word: str) -> bool:
    """True for a word that is a path, a file:// URL or another URL on its own."""
    return word.startswith(("/", "~/")) or "://" in word


def _open_name(path: str) -> bool:
    """True if the last name in `path` can go on after a space with lowercase words.

    `some` in `/Users/me/some folder` can. A capitalized name (`Foo`) or a file name
    with an extension (`system.log`) is taken as complete.
    """
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(name) and not name[:1].isupper() and "." not in name[1:]


def _lowercase_words(words: list[str], quote: str | None = None) -> int:
    """How many of `words` (at most _MAX_SPACE_WORDS, the rest of the line or more) to redact.

    A path in quotes ends at the word with the closing quote. Any other path ends at a
    hard stop (`folder:`) or a sentence end (`folder.`), or at the end of the line.
    A sentence end belongs to the path, unless its word is a plain word of the sentence
    (`now.`). If no end is in sight after _MAX_SPACE_WORDS words, take all of them:
    redact more, not less. Take none at another path, URL or "and/or".
    """
    for i, word in enumerate(words, 1):
        if not word or "/" in word or _starts_new_path(word):
            return 0
        if quote and quote in word:
            return i
        if word[-1] in _HARD_STOP:
            return i
        if word[-1] in _SENTENCE_END:
            return i - 1 if word.rstrip(_SENTENCE_END).lower() in _PLAIN_WORDS else i
    return len(words)


def _extend_path(line: str, start: int, end: int, lowercase: bool = False) -> int:
    """Move `end` over the words that may still belong to a path with spaces.

    Take the words up to the last one that has a "/" (the next folder or file).
    Stop at a word that starts another path or URL. That one is checked on its own.
    If none has, take the capitalized words ("Application Support").
    If `lowercase` and the last name is open, take lowercase words ("some folder").
    If the end is still not clear, redact more, not less.
    """
    while line[end:end + 1] == " ":
        words = line[end + 1:].split(" ")[:_MAX_SPACE_WORDS]
        take = 0
        for i, word in enumerate(words, 1):
            if _starts_new_path(word):
                break  # It is a path of its own. Do not join it to this path.
            if "/" in word and word.lower() != "and/or":
                take = i
        if take == 0:
            for word in words:
                if not (word[:1].isupper() or word[:1].isdigit()) or _starts_new_path(word):
                    break
                take += 1
                if word[-1] in _END_PUNCTUATION:
                    break
        last_resort = False
        if take == 0 and lowercase and _open_name(line[start:end]):
            quote = line[start - 1] if start and line[start - 1] in "'\"`" else None
            take, last_resort = _lowercase_words(words, quote), True
        if take == 0:
            break
        end += 1 + len(" ".join(words[:take]))
        stop = end
        while line[stop - 1] in _END_PUNCTUATION:
            stop -= 1
        if stop != end:
            return stop
        if last_resort:
            break  # Never read on past the words that the lowercase step took.
    return end


def _redact_paths(line: str, roots: tuple[str, ...]) -> str:
    out: list[str] = []
    pos = 0
    for m in _PATH_RE.finditer(line):
        if m.start() < pos:
            continue  # Already inside an earlier path.
        # A file:// URL writes a space as %20, so only a plain path reads on over lowercase words.
        end = _extend_path(line, m.start(), m.end(), lowercase=bool(m.group("path")))
        text = line[m.start():end]
        if m.group("url"):
            # file://host/path, with %20 for a space. The host is not part of the path.
            rest = unquote(text[len("file://"):])
            path = rest[rest.index("/"):] if "/" in rest else ""
        else:
            path = text
        out.append(line[pos:m.start()])
        out.append(text if path and _under_roots(path, roots) else "<path>")
        pos = end
    out.append(line[pos:])
    return "".join(out)


def owner_error(text: str | None, roots: tuple[str, ...] = DEFAULT_SCAN_ROOTS) -> str | None:
    """Make `text` safe for the `error` field.

    One line, ERROR_MAX_CHARS or fewer, and no paths or file:// URLs from outside the
    scan roots. Put the full text in `detail` instead.
    """
    if text is None:
        return None
    line = _redact_paths(" ".join(text.split()), roots)
    if len(line) > ERROR_MAX_CHARS:
        line = line[: ERROR_MAX_CHARS - 3].rstrip() + "..."
    return line or None


@dataclass
class RefreshRecord:
    id: int
    status: str
    started_at: str
    finished_at: str | None = None
    # Finish time of the newest `complete` refresh up to this one. Only a complete refresh changes it.
    last_complete_at: str | None = None
    error: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        _check(self.status, REFRESH_STATUSES, "status")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CoverageRecord:
    source: str
    label: str
    state: str
    last_success_at: str | None = None
    error: str | None = None
    detail: str | None = None
    # When the source's own data was fetched, for example the OSV database. None if not known.
    source_at: str | None = None

    def __post_init__(self) -> None:
        _check(self.state, COVERAGE_STATES, "state")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ItemRecord:
    id: str
    source: str
    name: str
    state: str
    kind: str | None = None
    installed_version: str | None = None
    latest_version: str | None = None
    project: str | None = None
    seen_at: str | None = None
    error: str | None = None
    detail: str | None = None
    # Where the item comes from inside its source, for example a Homebrew tap that is not core.
    origin: str | None = None
    # When the source data for `latest_version` was fetched. Older than seen_at if a cache was used.
    source_at: str | None = None
    # One sentence for the owner about the state, for example why an item is pinned. Not an error.
    note: str | None = None
    # Facts for the detail pane, as text. Each source fixes its keys, for example `bundleId`.
    # Keys are camelCase because the Swift decoder converts snake_case keys, also in dictionaries.
    attributes: dict[str, str] | None = None

    def __post_init__(self) -> None:
        _check(self.state, ITEM_STATES, "state")
        if self.attributes is not None and not all(
            isinstance(k, str) and isinstance(v, str) for k, v in self.attributes.items()
        ):
            raise ValueError("attributes must map text to text")

    def to_dict(self) -> dict:
        return asdict(self)
