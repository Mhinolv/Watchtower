"""Installed app bundles in the application folders.

The engine reads `Info.plist` files and the first bytes of each main executable.
It never launches an app, runs a helper inside a bundle or opens any other file.
An app links to a Homebrew cask only if exactly one installed cask claims the app
file name and exactly one copy of that file exists. Any doubt leaves the app unlinked.
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..discovery import display_path
from ..feeds.homebrew import Catalog, Fetch, http_fetch, load_catalog
from ..models import CoverageRecord, ItemRecord, utc_now
from .homebrew import NOTE_SELF_UPDATE, SourceResult, version_key
from .plist import read_plist, text

SOURCE = "apps"
LABEL = "Applications"
APP_ROOTS = ("/Applications", "~/Applications")
MAX_BUNDLES = 3000

ORIGIN_CASK = "Homebrew cask"
ORIGIN_MANUAL = "Manual"
ORIGIN_CATALOG = "Homebrew catalog"  # The app has a public cask, but Homebrew did not install it (#55).

# Owner-facing text. The Design notes of #4 fix these strings.
NOTE_LINKED = "Linked to cask {token}."
NOTE_MANUAL = "Update this app from its vendor."
NOTE_NO_VERSION = "This app has no version in Info.plist."
NOTE_DUPLICATE = "{count} copies of this app. Paths: {paths}."
ERROR_PLIST = "Info.plist could not be read."
ERROR_ROOT = "Watchtower cannot read {root}."
ERROR_BUNDLES = "{count} apps could not be read."
ERROR_CASKS = "Homebrew casks did not load. Apps show as manual."
ERROR_CATALOG = "Homebrew catalog did not load."

# Owner-facing text of #55. The Design notes of #55 fix these strings.
NOTE_CATALOG_NEWER = "Homebrew did not install this app. Update it from the vendor."
NOTE_APP_NEWER = "The app is newer than the Homebrew catalog ({latest})."
NOTE_FORMATS = "Version formats differ: {installed} and {latest}."
NOTE_AMBIGUOUS = "More than one cask matches. Watchtower does not guess."
NOTE_SELF_UPDATES = "This app updates itself. Watchtower compares the app version, not the Homebrew record."

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


# Versions


def _marketing(version: str | None) -> str | None:
    """The version without a cask build part: `1.3,200` is `1.3`. `latest` has no version."""
    text = (version or "").split(",")[0].strip()
    return text if re.search(r"\d", text) else None


def compare_versions(installed: str | None, latest: str | None) -> str:
    """`newer` (the catalog is newer), `same`, `older` (the app is newer) or `unknown`.

    Versions with letters in them, or a calendar version (first number of 1000 or more) against a
    plain one, are not comparable. Watchtower does not guess.
    """
    a, b = _marketing(installed), _marketing(latest)
    if a is None or b is None:
        return "unknown"
    if a == b:
        return "same"
    if re.search(r"[A-Za-z]", a + b):
        return "unknown"
    if (int(re.search(r"\d+", a).group()) >= 1000) != (int(re.search(r"\d+", b).group()) >= 1000):
        return "unknown"

    def key(version: str) -> tuple:
        parts = list(version_key(version))
        while parts and parts[-1] == (1, 0):
            parts.pop()
        return tuple(parts)

    ka, kb = key(a), key(b)
    return "same" if ka == kb else "newer" if kb > ka else "older"


def apply_comparison(item: ItemRecord, installed: str | None, latest: str | None, *,
                     not_installed_by_brew: bool, self_updating: bool) -> None:
    """Set the state and the note from the table in the Design notes of #55."""
    result = compare_versions(installed, latest)
    notes: list[str] = []
    if result == "newer":
        item.state = "update_available"
        if not_installed_by_brew:
            notes.append(NOTE_CATALOG_NEWER)
    elif result == "unknown":
        item.state = "unknown"
        notes.append(NOTE_FORMATS.format(installed=installed, latest=latest))
    else:
        item.state = "up_to_date"
        if result == "older":
            notes.append(NOTE_APP_NEWER.format(latest=_marketing(latest)))
    if self_updating:
        notes.append(NOTE_SELF_UPDATES)
    item.note = " ".join(notes) or None


# Catalog match


def match_catalog(bundle: "Bundle", catalog: Catalog, copies: int) -> tuple[str, list[dict]] | None:
    """The public casks for an app: by bundle id first, then by app file name (one copy only)."""
    if bundle.bundle_id:
        rows = catalog.casks_for_bundle_id(bundle.bundle_id)
        if rows:
            return "Bundle ID", rows
    if copies == 1:
        rows = catalog.casks_for_app_name(bundle.filename)
        if rows:
            return "App name", rows
    return None


def apply_catalog_match(item: ItemRecord, bundle: "Bundle", match: tuple[str, list[dict]], catalog: Catalog) -> None:
    """Show the cask version as Latest. The update stays manual: Homebrew did not install the app."""
    matched_by, rows = match
    if len(rows) > 1:
        item.state, item.note = "manual", NOTE_AMBIGUOUS
        item.detail = "Casks that match: " + ", ".join(sorted(r["name"] for r in rows)) + "."
        return
    row = rows[0]
    latest = _marketing(row.get("version"))
    item.origin = ORIGIN_CATALOG
    item.latest_version = latest
    item.source_at = catalog.fetched_at
    item.attributes = {**(item.attributes or {}), "cask": row["name"], "matchedBy": matched_by,
                       "latestFrom": f"Homebrew catalog, cask {row['name']}"}
    if row.get("homepage"):
        item.attributes["homepage"] = row["homepage"]
    if not catalog.fresh:
        # Old data keeps its badge. The UI adds "Version data is from <source_at>."
        item.error, item.detail = catalog.error, catalog.detail
    apply_comparison(item, bundle.version, row.get("version"), not_installed_by_brew=True,
                     self_updating=bool(row.get("auto_updates")))


# Items


def build_items(
    bundles: list[Bundle],
    casks: list[dict] | None = None,
    cask_items: list[ItemRecord] | None = None,
    catalog: Catalog | None = None,
) -> list[ItemRecord]:
    """One item for each bundle. `casks` is the `casks` list of `brew info --json=v2 --installed`.

    `catalog` is the public cask catalog. An app that no installed cask claims can match a catalog
    cask by bundle id or app file name (#55).
    """
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
                if cask.state == "unknown" and cask.note == NOTE_SELF_UPDATE and cask.latest_version and b.version:
                    # The cask updates itself, so the Homebrew receipt can be old. Compare the app (#55).
                    apply_comparison(item, b.version, cask.latest_version, not_installed_by_brew=False,
                                     self_updating=True)
        elif len(tokens) > 1:
            item.detail = "Casks that claim this app: " + ", ".join(tokens) + "."
        elif tokens:
            item.detail = f"Cask {tokens[0]} matches more than one copy of this app."
        elif catalog is not None and catalog.loaded and not b.error and b.version:
            match = match_catalog(b, catalog, copies_by_file[b.filename])
            if match:
                apply_catalog_match(item, b, match, catalog)

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
    catalog_loader: Callable[[], Catalog] | None = None,
) -> SourceResult:
    """Read the bundles and build the items.

    Coverage is `complete` if every root and bundle was read and the cask list loaded.
    `casks_error` says the cask list did not load: the coverage is then `partial`.
    """
    paths, root_errors = find_bundles(roots)
    bundles = [read_bundle(p) for p in paths]
    catalog = catalog_loader() if catalog_loader and bundles else None
    items = build_items(bundles, casks, cask_items, catalog)

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
    if catalog is not None and not catalog.fresh:
        problems.append(ERROR_CATALOG)
        if catalog.detail:
            details.append(catalog.detail)

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

    def catalog_loader() -> Catalog:
        return load_catalog("cask", data_dir, fetch, now)

    brew = brew or homebrew.find_brew()
    if brew is None:
        return collect(roots, catalog_loader=catalog_loader)
    answers: dict[tuple, object] = {}

    def run_once(args, **kwargs):
        key = tuple(args)
        if key not in answers:
            answers[key] = run(args, **kwargs)
        return answers[key]

    try:
        installed = homebrew.read_installed(brew, run_once)
    except Exception as exc:
        return collect(roots, casks_error=ERROR_CASKS, casks_detail=repr(exc), catalog_loader=catalog_loader)
    casks = [c for c in installed.get("casks") or [] if c.get("installed")]
    cask_items = homebrew.collect(data_dir, brew=brew, run=run_once, fetch=fetch, now=now).items if casks else []
    return collect(roots, casks, [i for i in cask_items if i.kind == "cask"], catalog_loader=catalog_loader)
