"""Read property list files. Nothing here starts a program."""
from __future__ import annotations

import plistlib
from pathlib import Path

MAX_PLIST_BYTES = 5 * 1024 * 1024


def read_plist(path: str | Path) -> dict:
    """Parse one Info.plist or SystemVersion.plist, XML or binary.

    Raises OSError if the file cannot be read, ValueError if it is too large or is not a
    property list with a dictionary at the top.
    """
    with open(path, "rb") as f:
        data = f.read(MAX_PLIST_BYTES + 1)
    if len(data) > MAX_PLIST_BYTES:
        raise ValueError("property list is too large")
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several error types for bad input
        raise ValueError(f"not a property list: {exc!r}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("property list is not a dictionary")
    return parsed


def text(value) -> str | None:
    """A property list value as non-empty text, or None."""
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None
