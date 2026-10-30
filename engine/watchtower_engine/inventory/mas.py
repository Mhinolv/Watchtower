"""Mac App Store apps through `mas` (#13).

Inventory runs two read-only calls: `mas version` and `mas list --json`. It never runs
`mas outdated`, `mas update` or any call that needs sign-in or administrator rights.
The newer-version check belongs to the update plan step (`updates/mas.py`).

Pinned `mas`: 7.0.0 (https://github.com/mas-cli/mas/releases/tag/v7.0.0). Version 7.0.0 added
`--json`: one JSON object per app, with `adamID`, `bundleID`, `name` and `version`.
Watchtower accepts mas 7.x from 7.0.0 up. Any other version is an explicit error state.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable

PINNED_VERSION = "7.0.0"
SUPPORTED_MAJOR = 7
MAS_PATHS = ("/opt/homebrew/bin/mas", "/usr/local/bin/mas")
MAS_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 4 * 1024 * 1024

# Owner-facing text. The Design notes of #13 fix these strings.
NOTE_CHECK = "Watchtower checks App Store versions only when you click Check for Update…"
NOTE_NO_MAS = "Install mas with Homebrew to update App Store apps here."
NOTE_SPOTLIGHT = "Spotlight cannot find App Store apps. App list can be incomplete."
NOTE_NOT_LISTED = "mas does not list this app. Spotlight may not have indexed it."
ERROR_UNSUPPORTED = "mas {version} is not supported. Watchtower needs mas " + PINNED_VERSION + " or a newer 7.x."
ERROR_UNREADABLE = "Watchtower cannot read the output of mas."
ERROR_SIGNED_OUT = "Sign in to the App Store, then try again."
ERROR_ADMIN = "This update needs an administrator. Use the App Store app."

ORIGIN = "App Store"

# Text that mas prints for each limit. The wording is matched loosely and in lower case.
_SPOTLIGHT = ("spotlight", "metadata service", "mdfind", "mds ")
_SIGNED_OUT = ("not signed in", "sign in", "signed in", "apple account", "apple id")
_ADMIN = ("root privileges", "requires root", "need root", "sudo", "administrator", "password is required",
          "a terminal is required", "permission denied", "operation not permitted")


class MasError(Exception):
    """A mas call failed or its output is not in the pinned format. The message is one sentence."""

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.detail = detail


@dataclass(frozen=True)
class MasApp:
    adam_id: str
    bundle_id: str
    name: str
    version: str


@dataclass(frozen=True)
class Outdated:
    adam_id: str
    name: str
    version: str
    new_version: str


@dataclass
class MasInventory:
    # ok, not_installed, unsupported, spotlight, failed
    status: str
    version: str | None = None
    apps: dict[str, MasApp] = field(default_factory=dict)  # lower-case bundle id -> app
    message: str | None = None
    detail: str | None = None


def find_mas() -> str | None:
    return next((p for p in MAS_PATHS if os.access(p, os.X_OK)), None)


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:3])


def is_supported(version: str) -> bool:
    key = version_key(version)
    return bool(key) and key[0] == SUPPORTED_MAJOR and key >= version_key(PINNED_VERSION)


def _mas(mas: str, args: list[str], run: Callable) -> subprocess.CompletedProcess:
    # Same environment as the owner's shell. No sudo, no prompt: stdin is closed.
    return run([mas, *args], capture_output=True, text=True, timeout=MAS_TIMEOUT_SECONDS,
               stdin=subprocess.DEVNULL)


def read_version(mas: str, run: Callable = subprocess.run) -> str:
    """The mas version. Raises MasError if mas does not answer with a version."""
    try:
        proc = _mas(mas, ["version"], run)
    except (OSError, subprocess.SubprocessError) as exc:
        raise MasError(ERROR_UNREADABLE, repr(exc)) from exc
    match = re.search(r"\d+(?:\.\d+)+", proc.stdout or "")
    if proc.returncode != 0 or not match:
        raise MasError(ERROR_UNREADABLE, f"mas version exited {proc.returncode}: {(proc.stderr or '').strip()[-300:]}")
    return match.group(0)


def classify(text: str) -> str | None:
    """Name the limit that a mas message describes: spotlight, signed_out, admin, or None."""
    lower = text.lower()
    for state, words in (("spotlight", _SPOTLIGHT), ("signed_out", _SIGNED_OUT), ("admin", _ADMIN)):
        if any(w in lower for w in words):
            return state
    return None


# Output


def _objects(text: str) -> list[dict]:
    """The JSON objects in mas output: a stream of objects (documented), or one array."""
    if len(text) > MAX_OUTPUT_BYTES:
        raise ValueError("output is too large")
    decoder = json.JSONDecoder()
    objects: list[dict] = []
    index, end = 0, len(text)
    while True:
        while index < end and text[index].isspace():
            index += 1
        if index >= end:
            return objects
        value, index = decoder.raw_decode(text, index)
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, dict):
                raise ValueError("an entry is not an object")
            objects.append(item)


def _text(obj: dict, key: str) -> str:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, (str, int)) or str(value).strip() == "":
        raise ValueError(f"missing {key}")
    return str(value).strip()


def parse_list(text: str) -> list[MasApp]:
    """Read `mas list --json`. Raises ValueError for output that is not in the pinned format."""
    return [MasApp(_text(o, "adamID"), _text(o, "bundleID"), _text(o, "name"), _text(o, "version"))
            for o in _objects(text)]


def parse_outdated(text: str) -> list[Outdated]:
    """Read `mas outdated --json`. Raises ValueError for output that is not in the pinned format."""
    return [Outdated(_text(o, "adamID"), _text(o, "name"), _text(o, "version"), _text(o, "newVersion"))
            for o in _objects(text)]


# Inventory


def read_inventory(mas: str | None, run: Callable = subprocess.run) -> MasInventory:
    """The App Store apps that mas lists. Runs `mas version` and `mas list --json` only."""
    if mas is None:
        return MasInventory("not_installed", message=NOTE_NO_MAS)
    try:
        version = read_version(mas, run)
    except MasError as exc:
        return MasInventory("failed", message=str(exc), detail=exc.detail)
    if not is_supported(version):
        return MasInventory("unsupported", version, message=ERROR_UNSUPPORTED.format(version=version))
    try:
        proc = _mas(mas, ["list", "--json"], run)
    except (OSError, subprocess.SubprocessError) as exc:
        return MasInventory("failed", version, message=ERROR_UNREADABLE, detail=repr(exc))
    if proc.returncode != 0:
        limit = classify((proc.stderr or "") + (proc.stdout or ""))
        detail = f"mas list exited {proc.returncode}: {(proc.stderr or '').strip()[-300:]}"
        if limit == "spotlight":
            return MasInventory("spotlight", version, message=NOTE_SPOTLIGHT, detail=detail)
        return MasInventory("failed", version, message=ERROR_UNREADABLE, detail=detail)
    try:
        apps = parse_list(proc.stdout or "")
    except ValueError as exc:
        return MasInventory("failed", version, message=ERROR_UNREADABLE, detail=repr(exc))
    return MasInventory("ok", version, {a.bundle_id.lower(): a for a in apps})


def label_item(item, inventory: MasInventory | None, bundle_id: str | None) -> None:
    """Mark an app that has an App Store receipt. Row states follow the Design notes of #13."""
    item.origin = ORIGIN
    item.note = NOTE_CHECK
    item.state = "unknown"
    status = inventory.status if inventory else "not_installed"
    app = inventory.apps.get(bundle_id.lower()) if inventory and bundle_id else None
    if app is not None:
        item.attributes = {**(item.attributes or {}), "adamId": app.adam_id}
    if status == "not_installed":
        item.state, item.note = "manual", NOTE_NO_MAS
    elif status == "unsupported":
        item.state, item.error, item.detail = "error", inventory.message, None
    elif status in ("spotlight", "failed"):
        item.note = NOTE_SPOTLIGHT if status == "spotlight" else inventory.message
        item.detail = inventory.detail
    elif app is None:
        item.note = NOTE_NOT_LISTED


def coverage_problem(inventory: MasInventory | None) -> tuple[str, str | None] | None:
    """The `App Store: partial` text for the Coverage popover, or None if mas is fine or missing."""
    if inventory is None or inventory.status in ("ok", "not_installed"):
        return None
    return f"App Store: partial. {inventory.message}", inventory.detail
