"""The version that runs now, apart from the installed version (#17).

The engine lists the running processes with two read-only system tools:
- `ps -axo pid=,comm=`: the pid and the executable path of each process. It reads no arguments, so no token on a
  command line reaches Watchtower.
- `lsappinfo list`: the build number (`CFBundleVersion`) that LaunchServices registered when each app started.

It starts no app, no service and no program of the item (no `node --version`). It reads no browser data, keychain,
credential or email. A process matches an item by the executable path only.

For each app, Homebrew formula and runtime install, the engine writes these item attributes:
- `runningState`: `known`, `unknown_version` (a process was found, its version was not), `none` (no process was
  found in the list), `denied` (the process list could not be read) or `not_checked` (the owner turned the check off).
- `runningVersion` and `runningKind` (`version` or `build`): only for `known`.
- `runningChecked`: when the list was read. Not for `not_checked`.

Unknown stays unknown: a denied or skipped probe never becomes `none`, and `none` is never read as "not deployed".
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable

from ..models import CoverageRecord, ItemRecord, utc_now
from .homebrew import SourceResult, version_key

SOURCE = "running"
LABEL = "Running versions"
TIMEOUT_SECONDS = 15
ATTRIBUTE_KEYS = ("runningState", "runningVersion", "runningKind", "runningChecked")
STATES = ("known", "unknown_version", "none", "denied", "not_checked")

NOTE_DENIED = "process list not readable"
NOTE_OFF = "turned off in Settings"

PS = ["/bin/ps", "-axo", "pid=,comm="]
LSAPPINFO = ["/usr/bin/lsappinfo", "list"]

_PS_LINE = re.compile(r"^\s*(\d+)\s+(/.+?)\s*$")
_CELLAR = re.compile(r"^(?:/opt/homebrew|/usr/local|/home/linuxbrew/\.linuxbrew)/Cellar/([^/]+)/([^/]+)/")
_OPT = re.compile(r"^(?:/opt/homebrew|/usr/local|/home/linuxbrew/\.linuxbrew)/opt/([^/]+)/")
_LS_BUNDLE = re.compile(r'^\s*bundle path="([^"]+)"')
_LS_VERSION = re.compile(r'\bVersion="([^"]*)"')

Run = Callable[..., "subprocess.CompletedProcess"]


class Denied(Exception):
    """The process list could not be read."""


@dataclass
class Snapshot:
    executables: list[str]  # The executable path of each process.
    app_builds: dict[str, str]  # App bundle path -> the build that LaunchServices holds. Missing: not known.


def parse_ps(output: str) -> list[str]:
    return [m.group(2) for m in map(_PS_LINE.match, output.splitlines()) if m]


def parse_lsappinfo(output: str) -> dict[str, str]:
    """Bundle path -> `Version` of each running app. A `[ NULL ]` version is left out."""
    builds: dict[str, str] = {}
    path = None
    for line in output.splitlines():
        found = _LS_BUNDLE.match(line)
        if found:
            path = found.group(1)
            continue
        version = _LS_VERSION.search(line)
        if path and version and "pid =" in line:
            if version.group(1):
                builds.setdefault(path, version.group(1))
            path = None
    return builds


def _call(run: Run, args: list[str]) -> str:
    try:
        proc = run(args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Denied(repr(exc)) from exc
    if proc.returncode != 0:
        raise Denied(f"{args[0]} exited {proc.returncode}")
    return proc.stdout or ""


def snapshot(run: Run = subprocess.run) -> Snapshot:
    """Read the process list. Raises Denied if `ps` cannot. A failed `lsappinfo` only loses the app builds."""
    executables = parse_ps(_call(run, PS))
    if not executables:
        raise Denied("the process list is empty")
    try:
        builds = parse_lsappinfo(_call(run, LSAPPINFO))
    except Denied:
        builds = {}
    return Snapshot(executables, builds)


# Match


def _under(exe: str, folder: str) -> bool:
    return exe.startswith(folder.rstrip("/") + "/")


def _app(item: ItemRecord, snap: Snapshot) -> tuple[str, str | None, str | None] | None:
    """(state, version, kind) of an app, or None if no process runs from its bundle."""
    path = (item.attributes or {}).get("path")
    if not path or not any(_under(e, path) for e in snap.executables):
        return None
    build = snap.app_builds.get(path)
    if build is None:
        return "unknown_version", None, None
    installed_build = (item.attributes or {}).get("build") or item.installed_version  # `build` is left out if it equals the version.
    if build == installed_build and item.installed_version:
        return "known", item.installed_version, "version"  # The same build runs: the same version.
    return "known", build, "build"


def _formula(item: ItemRecord, snap: Snapshot) -> tuple[str, str | None, str | None] | None:
    versions, unversioned = [], False
    for exe in snap.executables:
        cellar = _CELLAR.match(exe)
        if cellar and cellar.group(1) == item.name:
            versions.append(cellar.group(2))
        elif (opt := _OPT.match(exe)) and opt.group(1) == item.name:
            unversioned = True
    if versions:
        return "known", min(versions, key=version_key), "version"  # The oldest one runs: that is the risk.
    return ("unknown_version", None, None) if unversioned else None


def _runtime(item: ItemRecord, snap: Snapshot) -> tuple[str, str | None, str | None] | None:
    path = (item.attributes or {}).get("path")
    if path and item.installed_version and any(_under(e, path) for e in snap.executables):
        return "known", item.installed_version, "version"  # The install folder holds this version.
    return None


def probed(item: ItemRecord) -> Callable | None:
    if item.source == "apps" and (item.attributes or {}).get("path"):
        return _app
    if item.source == "homebrew" and item.kind == "formula":
        return _formula
    if item.source == "runtimes" and item.kind == "runtime":
        return _runtime
    return None


def _set(item: ItemRecord, state: str, version: str | None = None, kind: str | None = None,
         checked: str | None = None) -> None:
    attributes = {k: v for k, v in (item.attributes or {}).items() if k not in ATTRIBUTE_KEYS}
    attributes["runningState"] = state
    if version:
        attributes["runningVersion"], attributes["runningKind"] = version, kind or "version"
    if checked:
        attributes["runningChecked"] = checked
    item.attributes = attributes


def check(items: Iterable[ItemRecord], enabled: bool, run: Run = subprocess.run,
          now: Callable[[], str] = utc_now) -> CoverageRecord:
    """Set the running attributes of the apps, formulae and runtime installs in `items`, in place."""
    targets = [(item, fn) for item in items if (fn := probed(item))]
    if not enabled:
        for item, _ in targets:
            _set(item, "not_checked")
        return CoverageRecord(SOURCE, LABEL, "not_run", note=NOTE_OFF)
    stamp = now()
    try:
        snap = snapshot(run)
    except Denied as exc:
        for item, _ in targets:
            _set(item, "denied", checked=stamp)
        return CoverageRecord(SOURCE, LABEL, "complete", note=NOTE_DENIED, detail=str(exc))
    for item, fn in targets:
        found = fn(item, snap)
        if found is None:
            _set(item, "none", checked=stamp)
        else:
            _set(item, found[0], found[1], found[2], stamp)
    return CoverageRecord(SOURCE, LABEL, "complete", source_at=stamp)


def collect(inventory: list[ItemRecord], enabled: bool, run: Run = subprocess.run) -> SourceResult:
    return SourceResult(check(inventory, enabled, run), [])
