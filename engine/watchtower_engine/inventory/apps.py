"""Installed app bundles in the application folders.

The engine reads `Info.plist` files and the first bytes of each main executable.
It never launches an app, runs a helper inside a bundle or opens any other file.
An app links to a Homebrew cask only if exactly one installed cask claims the app
file name and exactly one copy of that file exists. Any doubt leaves the app unlinked.
"""
from __future__ import annotations

import os
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..discovery import display_path
from ..feeds.homebrew import Fetch, http_fetch
from ..models import CoverageRecord, ItemRecord, utc_now
from .homebrew import SourceResult
from .plist import read_plist, text

SOURCE = "apps"
LABEL = "Applications"
APP_ROOTS = ("/Applications", "~/Applications")
MAX_BUNDLES = 3000

ORIGIN_CASK = "Homebrew cask"
ORIGIN_MANUAL = "Manual"

# Owner-facing text. The Design notes of #4 fix these strings.
NOTE_LINKED = "Linked to cask {token}."
NOTE_MANUAL = "Update this app from its vendor."
NOTE_NO_VERSION = "This app has no version in Info.plist."
NOTE_DUPLICATE = "{count} copies of this app. Paths: {paths}."
ERROR_PLIST = "Info.plist could not be read."
ERROR_ROOT = "Watchtower cannot read {root}."
ERROR_BUNDLES = "{count} apps could not be read."
ERROR_CASKS = "Homebrew casks did not load. Apps show as manual."

ELECTRON_PLIST = "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"

# Chromium and Node major versions of each Electron major version (upstream Electron
# release notes). A newer Electron major version is not listed, so nothing is inferred.
ELECTRON_RUNTIMES = {
    22: (108, 16), 23: (110, 18), 24: (112, 18), 25: (114, 18), 26: (116, 18), 27: (118, 18),
    28: (120, 18), 29: (122, 20), 30: (124, 20), 31: (126, 20), 32: (128, 20), 33: (130, 20),
    34: (132, 20), 35: (134, 22), 36: (136, 22), 37: (138, 22),
}

_CPU_TYPES = {
    7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32",
}
_THIN_MAGIC = {
    b"\xfe\xed\xfa\xce": ">", b"\xfe\xed\xfa\xcf": ">",
    b"\xce\xfa\xed\xfe": "<", b"\xcf\xfa\xed\xfe": "<",
}


# Bundles


@dataclass
class Bundle:
    path: Path
    name: str
    bundle_id: str | None = None
    version: str | None = None
    build: str | None = None
    architecture: str | None = None
    electron: str | None = None
    error: str | None = None  # Set if Info.plist could not be read.
    detail: str | None = None

    @property
    def filename(self) -> str:
        return self.path.name.lower()


def find_bundles(roots: tuple[str, ...]) -> tuple[list[Path], list[tuple[str, OSError]]]:
    """App bundles in each root and in one level of folders below it. Returns (paths, root errors).

    A missing `~/Applications` is normal and is not an error. Bundles are not entered.
    """
    found: list[Path] = []
    errors: list[tuple[str, OSError]] = []
    seen: set[str] = set()
    for label in roots:
        root = Path(os.path.expanduser(label))
        try:
            top = sorted(os.scandir(root), key=lambda e: e.name.lower())
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append((label, exc))
            continue
        for entry in top:
            if entry.name.startswith("."):
                continue
            if entry.name.endswith(".app"):
                candidates = [Path(entry.path)]
            elif entry.is_dir():
                try:
                    candidates = [
                        Path(e.path)
                        for e in sorted(os.scandir(entry.path), key=lambda e: e.name.lower())
                        if e.name.endswith(".app") and not e.name.startswith(".")
                    ]
                except OSError:
                    continue  # An unreadable folder of apps is skipped. Its apps are not counted.
            else:
                continue
            for path in candidates:
                real = os.path.realpath(path)
                if real in seen or not os.path.isdir(real):
                    continue
                seen.add(real)
                found.append(path)
    return found[:MAX_BUNDLES], errors


def _info_plist(path: Path) -> Path | None:
    candidates = [path / "Contents" / "Info.plist"]
    wrapper = path / "Wrapper"  # An iPhone or iPad app that runs on the Mac.
    try:
        candidates += sorted(wrapper.glob("*.app/Info.plist"))
    except OSError:
        pass
    return next((c for c in candidates if c.is_file()), None)


def mach_o_architectures(executable: str | Path) -> str | None:
    """CPU types of a Mach-O file, for example `arm64` or `arm64, x86_64`. Reads 4 KB at most."""
    try:
        with open(executable, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    types: list[int] = []
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        size = 20 if head[:4] == b"\xca\xfe\xba\xbe" else 32
        count = struct.unpack(">I", head[4:8])[0] if len(head) >= 8 else 0
        if 0 < count <= 8:  # Java class files share the magic number and have a larger count.
            types = [
                struct.unpack(">I", head[8 + i * size: 12 + i * size])[0]
                for i in range(count)
                if len(head) >= 12 + i * size
            ]
    elif head[:4] in _THIN_MAGIC and len(head) >= 8:
        types = [struct.unpack(_THIN_MAGIC[head[:4]] + "I", head[4:8])[0]]
    names = sorted({_CPU_TYPES[t] for t in types if t in _CPU_TYPES})
    return ", ".join(names) or None


def electron_version(path: Path) -> str | None:
    """The Electron version from the framework's Info.plist, or None if the app is not Electron."""
    try:
        info = read_plist(path / ELECTRON_PLIST)
    except (OSError, ValueError):
        return None
    return text(info.get("CFBundleShortVersionString")) or text(info.get("CFBundleVersion"))


def electron_runtimes(version: str) -> tuple[str, str] | None:
    """(Chromium major, Node major) inferred from an Electron version, or None if unknown."""
    try:
        chromium, node = ELECTRON_RUNTIMES[int(version.split(".")[0])]
    except (KeyError, ValueError):
        return None
    return str(chromium), str(node)


def read_bundle(path: Path) -> Bundle:
    bundle = Bundle(path=path, name=path.name[: -len(".app")])
    plist = _info_plist(path)
    if plist is None:
        bundle.error, bundle.detail = ERROR_PLIST, "No Info.plist in the bundle."
        return bundle
    try:
        info = read_plist(plist)
    except (OSError, ValueError) as exc:
        bundle.error, bundle.detail = ERROR_PLIST, repr(exc)
        return bundle
    bundle.name = text(info.get("CFBundleDisplayName")) or text(info.get("CFBundleName")) or bundle.name
    bundle.bundle_id = text(info.get("CFBundleIdentifier"))
    bundle.version = text(info.get("CFBundleShortVersionString")) or text(info.get("CFBundleVersion"))
    build = text(info.get("CFBundleVersion"))
    bundle.build = build if build != bundle.version else None
    executable = text(info.get("CFBundleExecutable"))
    if executable and plist.parent.name == "Contents":
        bundle.architecture = mach_o_architectures(plist.parent / "MacOS" / executable)
    bundle.electron = electron_version(path)
    return bundle


# Cask links


def cask_app_names(cask: dict) -> list[str]:
    """Lower-case app file names that an installed cask puts in an application folder."""
    names: list[str] = []
    for artifact in cask.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        for entry in artifact.get("app") or []:
            if isinstance(entry, str):
                names.append(os.path.basename(entry).lower())
            elif isinstance(entry, dict) and entry.get("target") and names:
                names[-1] = os.path.basename(str(entry["target"])).lower()  # Installed under another name.
    return names


def claimants(casks: list[dict]) -> dict[str, list[str]]:
    """App file name -> tokens of the installed casks that claim it."""
    claimed: dict[str, list[str]] = {}
    for cask in casks:
        if not cask.get("installed") or not cask.get("token"):
            continue
        for name in set(cask_app_names(cask)):
            claimed.setdefault(name, []).append(cask["token"])
    return {name: sorted(tokens) for name, tokens in claimed.items()}


# Items


def build_items(
    bundles: list[Bundle],
    casks: list[dict] | None = None,
    cask_items: list[ItemRecord] | None = None,
) -> list[ItemRecord]:
    """One item for each bundle. `casks` is the `casks` list of `brew info --json=v2 --installed`."""
    claimed = claimants(casks or [])
    cask_by_token = {i.name: i for i in cask_items or [] if i.kind == "cask"}
    copies_by_file: dict[str, int] = {}
    by_id: dict[str, list[Bundle]] = {}
    for b in bundles:
        copies_by_file[b.filename] = copies_by_file.get(b.filename, 0) + 1
        if b.bundle_id:
            by_id.setdefault(b.bundle_id.lower(), []).append(b)

    items = []
    for b in bundles:
        item = ItemRecord(
            id=b.bundle_id or f"path:{b.path}",
            source=SOURCE,
            name=b.name,
            state="manual",
            kind="app",
            installed_version=b.version,
            origin=ORIGIN_MANUAL,
            note=NOTE_MANUAL,
        )
        attributes = {"path": str(b.path)}
        for key, value in (("bundleId", b.bundle_id), ("build", b.build),
                           ("architecture", b.architecture)):
            if value:
                attributes[key] = value
        if b.electron:
            attributes["electron"] = b.electron
            runtimes = electron_runtimes(b.electron)
            if runtimes:
                attributes["chromium"], attributes["node"] = runtimes
        item.attributes = attributes

        tokens = claimed.get(b.filename, [])
        if len(tokens) == 1 and copies_by_file[b.filename] == 1:
            token = tokens[0]
            item.origin = ORIGIN_CASK
            item.note = NOTE_LINKED.format(token=token)
            attributes["cask"] = token
            cask = cask_by_token.get(token)
            if cask is None:
                item.state = "unknown"
            else:
                item.state, item.latest_version, item.source_at = cask.state, cask.latest_version, cask.source_at
                if cask.state == "error":
                    item.error = cask.error
        elif len(tokens) > 1:
            item.detail = "Casks that claim this app: " + ", ".join(tokens) + "."
        elif tokens:
            item.detail = f"Cask {tokens[0]} matches more than one copy of this app."

        group = by_id.get(b.bundle_id.lower(), []) if b.bundle_id else []
        if len(group) > 1:
            item.id = f"{b.bundle_id}@{b.path}"
            attributes["copies"] = str(len(group))
            item.note = NOTE_DUPLICATE.format(
                count=len(group), paths=", ".join(display_path(g.path) for g in group)
            )
        if b.error:
            item.state, item.error, item.detail, item.installed_version = "error", b.error, b.detail, None
        elif b.version is None:
            item.state, item.note = "unknown", NOTE_NO_VERSION
        items.append(item)
    items.sort(key=lambda i: (i.name.lower(), i.id))
    return items


# Collect


def collect(
    roots: tuple[str, ...] = APP_ROOTS,
    casks: list[dict] | None = None,
    cask_items: list[ItemRecord] | None = None,
    casks_error: str | None = None,
    casks_detail: str | None = None,
) -> SourceResult:
    """Read the bundles and build the items.

    Coverage is `complete` if every root and bundle was read and the cask list loaded.
    `casks_error` says the cask list did not load: the coverage is then `partial`.
    """
    paths, root_errors = find_bundles(roots)
    bundles = [read_bundle(p) for p in paths]
    items = build_items(bundles, casks, cask_items)

    problems, details = [], []
    for label, exc in root_errors:
        problems.append(ERROR_ROOT.format(root=label))
        details.append(f"{label}: {exc!r}")
    unreadable = [b for b in bundles if b.error]
    if unreadable:
        problems.append(ERROR_BUNDLES.format(count=len(unreadable)))
        details += [f"{b.path}: {b.detail}" for b in unreadable]
    if casks_error:
        problems.append(casks_error)
        if casks_detail:
            details.append(casks_detail)

    if not problems:
        coverage = CoverageRecord(SOURCE, LABEL, "complete")
    else:
        state = "failed" if root_errors and not bundles else "partial"
        coverage = CoverageRecord(SOURCE, LABEL, state, error=" ".join(problems), detail="\n".join(details))
    return SourceResult(coverage, items)


def collect_live(
    data_dir: Path,
    roots: tuple[str, ...] = APP_ROOTS,
    brew: str | None = None,
    run: Callable = subprocess.run,
    fetch: Fetch = http_fetch,
    now: Callable[[], str] = utc_now,
) -> SourceResult:
    """Read the apps and link them to the Homebrew casks.

    Runs `brew info` once. The Homebrew check reuses that answer.
    """
    from . import homebrew

    brew = brew or homebrew.find_brew()
    if brew is None:
        return collect(roots)
    answers: dict[tuple, object] = {}

    def run_once(args, **kwargs):
        key = tuple(args)
        if key not in answers:
            answers[key] = run(args, **kwargs)
        return answers[key]

    try:
        installed = homebrew.read_installed(brew, run_once)
    except Exception as exc:
        return collect(roots, casks_error=ERROR_CASKS, casks_detail=repr(exc))
    casks = [c for c in installed.get("casks") or [] if c.get("installed")]
    cask_items = homebrew.collect(data_dir, brew=brew, run=run_once, fetch=fetch, now=now).items if casks else []
    return collect(roots, casks, [i for i in cask_items if i.kind == "cask"])
