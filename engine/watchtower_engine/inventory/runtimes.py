"""Runtimes, SDKs and editor extensions that are installed on this Mac (#16).

The engine lists folders and reads small version files. It never runs a program (no `node --version`),
a project build, an install script or a hook, it never starts a service, and it never opens an app
container, a keychain or a credential file. A runtime that a project needs is not a project manifest:
these items never appear in the project list (#2).

Three groups, one item for each install (three Node versions give three items):
- Runtimes: nvm, fnm, Volta, pyenv, rbenv, uv Pythons, the python.org framework, rustup, SDKMAN!, asdf, mise,
  Java virtual machines, Go.
- SDKs: the macOS, iOS and other SDKs of each Xcode and of the Command Line Tools.
- Editor extensions: VS Code, VS Code Insiders, Cursor, Windsurf and VSCodium.
Homebrew installs are not listed here: the Homebrew source has them (#3).

Stable keys for #59 (endoflife.date): every runtime item has the attributes `product` (a stable name such as
`nodejs`, `python`, `ruby`, `go`, `rust`, `java`) and `eolProduct` (the endoflife.date product, only if one fits),
and `installed_version` holds the plain version (`22.9.0`, no leading `v`). `family` names the group of copies
of one thing: the newest copy of a family shows normally, older ones are `Old copy`.

A folder that does not exist is normal and is skipped. A folder that cannot be read is a root error: it is
shown, it makes the coverage `partial`, and it does not stop the other folders or the refresh.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ..discovery import display_path
from ..models import CoverageRecord, ItemRecord
from .homebrew import SourceResult, version_key
from .plist import text

SOURCE = "runtimes"
LABEL = "Runtimes"
GROUPS = {"runtime": "Runtimes", "sdk": "SDKs", "extension": "Editor extensions"}
MAX_ENTRIES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024

NOTE_OLD = "Old copy"
NOTE_NO_VERSION = "Version not found in {file}."
NOTE_NEWEST = "Watchtower does not check updates for this install yet."
ERROR_ROOT = "Cannot read {root}: {reason}."
ERROR_ROOTS = "{count} install folders could not be read."
ERROR_VERSIONS = "{count} versions could not be read."

# product -> (name, endoflife.date product or None). The product name is the stable key (#59).
PRODUCTS = {
    "nodejs": ("Node.js", "nodejs"), "python": ("Python", "python"), "ruby": ("Ruby", "ruby"), "go": ("Go", "go"),
    "rust": ("Rust", "rust"), "java": ("Java", None), "gradle": ("Gradle", "gradle"), "kotlin": ("Kotlin", "kotlin"),
    "maven": ("Maven", None), "scala": ("Scala", None),
}
# The names that asdf, mise and SDKMAN! use for a product.
ALIASES = {"node": "nodejs", "nodejs": "nodejs", "python": "python", "ruby": "ruby", "golang": "go", "go": "go",
           "rust": "rust", "java": "java", "gradle": "gradle", "kotlin": "kotlin", "maven": "maven", "scala": "scala"}

_VERSION = re.compile(r"^v?(\d+(?:\.\d+){1,3}(?:[-+._]?(?:rc|alpha|beta|preview|dev|a|b)\.?\d*)?t?)$", re.IGNORECASE)
_EXT_SUFFIX = re.compile(r"-(?:universal|web|alpine-\w+|darwin-\w+|linux-\w+|win32-\w+)$")
_EXT_FOLDER = re.compile(r"^(?P<id>[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9._-]*?)-"
                         r"(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


@dataclass
class Install:
    kind: str  # runtime, sdk or extension
    name: str
    path: Path
    source: str  # `nvm`, `pyenv`, `Xcode`, `VS Code`
    family: str  # The copies of one thing share it.
    version: str | None = None
    version_error: str | None = None  # `Version not found in <file>.`
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class RootError:
    kind: str
    message: str  # `Cannot read ~/.nvm: permission denied.`


@dataclass
class Scan:
    installs: list[Install] = field(default_factory=list)
    errors: list[RootError] = field(default_factory=list)


# Reading


def _reason(exc: OSError) -> str:
    if isinstance(exc, PermissionError):
        return "permission denied"
    if isinstance(exc, NotADirectoryError):
        return "not a folder"
    return "read error"


def list_dir(path: Path, label: str, kind: str, scan: Scan) -> list[os.DirEntry]:
    """The entries of a folder. A missing folder is normal. Another error becomes a root error."""
    try:
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)[:MAX_ENTRIES]
    except FileNotFoundError:
        return []
    except OSError as exc:
        scan.errors.append(RootError(kind, ERROR_ROOT.format(root=label, reason=_reason(exc))))
        return []
    return entries


def _subdirs(entries: list[os.DirEntry]) -> list[os.DirEntry]:
    """Real folders. A symlink is an alias of another copy (`latest`, `MacOSX.sdk`) and is not a copy."""
    out = []
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                out.append(e)
        except OSError:
            continue
    return out


def _read_regular(path: Path, limit: int = MAX_FILE_BYTES) -> bytes | None:
    """The bytes of a regular file of at most `limit` bytes, else None.

    Every file here can sit in an untrusted folder (an editor extension, a retained install). The file is opened
    without following a symlink (`O_NOFOLLOW`) and without blocking (`O_NONBLOCK`, for a FIFO). It must be a
    regular file: a character device such as /dev/zero, a FIFO, a socket and a folder are refused. The size is
    checked from the open file, and the read stops at `limit` + 1 bytes, so a file that lies about its size cannot
    fill the memory.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        return bytes(data) if len(data) <= limit else None
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_text(path: Path) -> str | None:
    data = _read_regular(path)
    return None if data is None else data.decode("utf-8", errors="replace")


def read_plist(path: Path) -> dict:
    """A property list from a regular file. Raises OSError or ValueError, like `plist.read_plist`."""
    data = _read_regular(Path(path))
    if data is None:
        raise OSError("not a regular file, or too large")
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several error types for bad input
        raise ValueError(f"not a property list: {exc!r}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("property list is not a dictionary")
    return parsed


def _read_json(path: Path) -> dict | None:
    body = _read_text(path)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def plain_version(name: str) -> str | None:
    """`v22.9.0` as `22.9.0`. None for a name that is not a version (`latest`, `system`, `miniconda3`)."""
    m = _VERSION.match(name.strip())
    return m.group(1) if m else None


# Runtimes: folders of versions


@dataclass(frozen=True)
class VersionDir:
    label: str  # The root in an error text: `~/.nvm`.
    path: str  # Below the home folder.
    product: str
    source: str
    inner: str = ""  # A folder inside each version folder that holds the install, for the path.


HOME_DIRS = (
    VersionDir("~/.nvm", ".nvm/versions/node", "nodejs", "nvm"),
    VersionDir("~/.fnm", ".fnm/node-versions", "nodejs", "fnm", "installation"),
    VersionDir("~/.local/share/fnm", ".local/share/fnm/node-versions", "nodejs", "fnm", "installation"),
    VersionDir("~/Library/Application Support/fnm", "Library/Application Support/fnm/node-versions", "nodejs", "fnm",
               "installation"),
    VersionDir("~/.volta", ".volta/tools/image/node", "nodejs", "Volta"),
    VersionDir("~/.pyenv", ".pyenv/versions", "python", "pyenv"),
    VersionDir("~/.rbenv", ".rbenv/versions", "ruby", "rbenv"),
)

_UV_PYTHON = re.compile(r"^cpython-(\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?)(?:\+[a-z]+)?-")


def _product_install(product: str, version: str | None, path: Path, source: str, error: str | None = None) -> Install:
    name, eol = PRODUCTS[product]
    attributes = {"product": product, "path": str(path)}
    if eol:
        attributes["eolProduct"] = eol
    return Install("runtime", name, path, source, family=product, version=version, version_error=error,
                   attributes=attributes)


def scan_version_dir(home: Path, spec: VersionDir, scan: Scan) -> None:
    for entry in _subdirs(list_dir(home / spec.path, spec.label, "runtime", scan)):
        version = plain_version(entry.name)
        if version is None:
            continue  # `system`, `latest`, a conda or pypy folder: not a plain version.
        path = Path(entry.path)
        scan.installs.append(_product_install(spec.product, version, path / spec.inner if spec.inner else path,
                                              spec.source))


def scan_uv_pythons(home: Path, scan: Scan) -> None:
    """uv Pythons: `~/.local/share/uv/python/cpython-3.12.11-macos-aarch64-none`. The folder name has the version.

    uv also keeps a symlink such as `cpython-3.12-macos-aarch64-none`: an alias, not a copy. Hidden entries
    (`.lock`, `.temp`) and other implementations (`pypy-…`) are skipped.
    """
    for entry in _subdirs(list_dir(home / ".local/share/uv/python", "~/.local/share/uv", "runtime", scan)):
        m = _UV_PYTHON.match(entry.name)
        if m:
            scan.installs.append(_product_install("python", m.group(1), Path(entry.path), "uv"))


def scan_python_framework(system: Path, scan: Scan) -> None:
    """The python.org installer: `/Library/Frameworks/Python.framework/Versions/3.13` (`Current` is a symlink).

    The folder name has only the minor version. `Resources/Info.plist` has the full one (`CFBundleVersion`).
    """
    root = system / "Library/Frameworks/Python.framework/Versions"
    for entry in _subdirs(list_dir(root, "/Library/Frameworks/Python.framework", "runtime", scan)):
        path = Path(entry.path)
        version = None
        try:
            info = read_plist(path / "Resources" / "Info.plist")
            version = plain_version(text(info.get("CFBundleVersion")) or "")
        except (OSError, ValueError):
            pass
        scan.installs.append(_product_install("python", version, path, "python.org",
                                              None if version else NOTE_NO_VERSION.format(file="Info.plist")))


def scan_tool_versions(home: Path, root: str, label: str, source: str, scan: Scan) -> None:
    """asdf (`installs/<plugin>/<version>`) and mise (`installs/<tool>/<version>`)."""
    for tool in _subdirs(list_dir(home / root, label, "runtime", scan)):
        product = ALIASES.get(tool.name)
        if product is None:
            continue
        for entry in _subdirs(list_dir(Path(tool.path), label, "runtime", scan)):
            version = plain_version(entry.name)
            if version is not None:
                scan.installs.append(_product_install(product, version, Path(entry.path), source))


def scan_sdkman(home: Path, scan: Scan) -> None:
    for candidate in _subdirs(list_dir(home / ".sdkman/candidates", "~/.sdkman", "runtime", scan)):
        product = ALIASES.get(candidate.name)
        if product is None:
            continue
        for entry in _subdirs(list_dir(Path(candidate.path), "~/.sdkman", "runtime", scan)):  # `current` is a symlink.
            m = re.match(r"^(\d+(?:\.\d+){0,3})(?:[-+.].*)?$", entry.name)  # `21.0.2-tem` is 21.0.2.
            if m:
                scan.installs.append(_product_install(product, m.group(1), Path(entry.path), "SDKMAN!"))


def scan_rustup(home: Path, scan: Scan) -> None:
    """`~/.rustup/toolchains/<channel>-<target>`. The version is in the channel manifest of the toolchain."""
    for entry in _subdirs(list_dir(home / ".rustup/toolchains", "~/.rustup", "runtime", scan)):
        path = Path(entry.path)
        file = "multirust-channel-manifest.toml"
        version = None
        body = _read_text(path / "lib/rustlib" / file)
        # Read as text: the manifest is large and is not parsed as TOML. `[pkg.rust]` has `version = "1.78.0 (…)"`.
        m = re.search(r'\[pkg\.rust\]\s*\n\s*version = "(\d+\.\d+\.\d+)', body) if body else None
        version = m.group(1) if m else None
        if version is None:
            m = re.match(r"^(\d+\.\d+(?:\.\d+)?)-", entry.name)  # A pinned toolchain: `1.78.0-aarch64-apple-darwin`.
            version = m.group(1) if m else None
        error = None if version else NOTE_NO_VERSION.format(file=file)
        install = _product_install("rust", version, path, "rustup", error)
        install.attributes["toolchain"] = entry.name
        scan.installs.append(install)


def scan_jvms(roots: list[tuple[Path, str]], scan: Scan) -> None:
    for base, label in roots:
        for entry in _subdirs(list_dir(base, label, "runtime", scan)):
            if not entry.name.endswith(".jdk"):
                continue
            path = Path(entry.path)
            info = None
            try:
                info = read_plist(path / "Contents" / "Info.plist")
            except (OSError, ValueError):
                pass
            jvm = (info or {}).get("JavaVM")
            version = text(jvm.get("JVMVersion")) if isinstance(jvm, dict) else None
            version = version or (plain_version(text((info or {}).get("CFBundleVersion")) or "") if info else None)
            install = _product_install("java", version, path, "JDK",
                                       None if version else NOTE_NO_VERSION.format(file="Info.plist"))
            vendor = text((info or {}).get("CFBundleName")) if info else None
            if vendor:
                install.attributes["vendor"] = vendor
            scan.installs.append(install)


def _go_version(path: Path) -> tuple[bool, str | None]:
    """(has a VERSION file, the version). The first line reads `go1.22.3`, sometimes with a time after it."""
    body = _read_text(path / "VERSION")
    if body is None:
        return False, None
    m = re.match(r"^go(\d+\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?)\b", body.strip())
    return True, m.group(1) if m else None


def scan_go(system: Path, home: Path, scan: Scan) -> None:
    """`/usr/local/go` and `~/sdk/go<version>`: a folder with a `VERSION` file."""
    candidates = [system / "usr/local/go"]
    candidates += [Path(e.path) for e in _subdirs(list_dir(home / "sdk", "~/sdk", "runtime", scan)) if e.name.startswith("go")]
    for path in candidates:
        present, version = _go_version(path)
        if present:
            scan.installs.append(_product_install("go", version, path, "Go",
                                                  None if version else NOTE_NO_VERSION.format(file="VERSION")))


# SDKs


def _sdk_installs(sdk_dir: Path, source: str, toolchain: str | None, label: str, scan: Scan) -> None:
    for entry in _subdirs(list_dir(sdk_dir, label, "sdk", scan)):
        if not entry.name.endswith(".sdk"):
            continue
        path = Path(entry.path)
        info = None
        try:
            info = read_plist(path / "SDKSettings.plist")
        except (OSError, ValueError):
            pass
        canonical = (text(info.get("CanonicalName")) or "") if info else ""
        display = (text(info.get("DisplayName")) or "") if info else ""
        version = text(info.get("Version")) if info else None
        platform = re.sub(r"[\d.]+$", "", canonical) or re.sub(r"[\d.]+\.sdk$", "", entry.name).lower()
        name = (re.sub(r"\s*[\d.]+$", "", display) or platform) + " SDK"
        attributes = {"product": f"{platform}-sdk", "path": str(path)}
        if canonical:
            attributes["canonicalName"] = canonical
        if toolchain:
            attributes["toolchain"] = toolchain
        scan.installs.append(Install("sdk", name, path, source, family=f"{platform}:{source}", version=version,
                                     version_error=None if version else NOTE_NO_VERSION.format(file="SDKSettings.plist"),
                                     attributes=attributes))


def scan_sdks(system: Path, home: Path, scan: Scan) -> None:
    apps = [system / "Applications", home / "Applications"]
    for base in apps:
        for app in _subdirs(list_dir(base, display_path(base), "sdk", scan)):
            if not (app.name.startswith("Xcode") and app.name.endswith(".app")):
                continue
            contents = Path(app.path) / "Contents"
            try:
                info = read_plist(contents / "version.plist")
                toolchain = f"Xcode {text(info.get('CFBundleShortVersionString'))}" if text(info.get("CFBundleShortVersionString")) else "Xcode"
            except (OSError, ValueError):
                toolchain = "Xcode"
            platforms = contents / "Developer" / "Platforms"
            for platform in _subdirs(list_dir(platforms, display_path(platforms), "sdk", scan)):
                if platform.name.endswith(".platform"):
                    _sdk_installs(Path(platform.path) / "Developer" / "SDKs", "Xcode", toolchain,
                                  display_path(Path(platform.path) / "Developer" / "SDKs"), scan)
    clt = system / "Library" / "Developer" / "CommandLineTools" / "SDKs"
    _sdk_installs(clt, "Command Line Tools", None, display_path(clt), scan)


# Editor extensions

EDITORS = (
    ("VS Code", ".vscode/extensions"), ("VS Code Insiders", ".vscode-insiders/extensions"),
    ("Cursor", ".cursor/extensions"), ("Windsurf", ".windsurf/extensions"), ("VSCodium", ".vscode-oss/extensions"),
)


def parse_extension_folder(name: str) -> tuple[str, str] | None:
    """`ms-python.python-2026.8.0-darwin-arm64` as (`ms-python.python`, `2026.8.0`). None if it is not that shape."""
    m = _EXT_FOLDER.match(_EXT_SUFFIX.sub("", name))
    return (m.group("id").lower(), m.group("version")) if m else None


def scan_extensions(home: Path, scan: Scan) -> None:
    """One install for each extension folder. The manifest is read as text: its code never runs."""
    for editor, rel in EDITORS:
        root = home / rel
        entries = list_dir(root, display_path(root), "extension", scan)
        obsolete = _read_json(root / ".obsolete") or {}  # VS Code keeps a replaced version until it restarts.
        for entry in _subdirs(entries):
            if entry.name.startswith("."):
                continue
            path = Path(entry.path)
            parsed = parse_extension_folder(entry.name)
            manifest = _read_json(path / "package.json")
            version = parsed[1] if parsed else None
            ident = parsed[0] if parsed else None
            if manifest:
                declared = manifest.get("version")
                if isinstance(declared, str) and _VERSION.match(declared.strip()):
                    version = declared.strip()
                if ident is None and isinstance(manifest.get("publisher"), str) and isinstance(manifest.get("name"), str):
                    ident = f"{manifest['publisher']}.{manifest['name']}".lower()
            if ident is None:
                continue  # Not an extension folder.
            attributes = {"product": "vscode-extension", "path": str(path), "editor": editor}
            display = manifest.get("displayName") if manifest else None
            if isinstance(display, str) and display.strip() and len(display) < 120:
                attributes["displayName"] = display.strip()
            if entry.name in obsolete:
                attributes["obsolete"] = "true"
            scan.installs.append(Install("extension", ident, path, editor, family=f"{ident}:{editor}", version=version,
                                         version_error=None if version else NOTE_NO_VERSION.format(file="package.json"),
                                         attributes=attributes))


# Items


def to_items(installs: list[Install]) -> list[ItemRecord]:
    newest: dict[str, tuple] = {}
    copies: dict[str, int] = {}
    for i in installs:
        copies[i.family] = copies.get(i.family, 0) + 1
        if i.version:
            key = version_key(i.version)
            if i.family not in newest or key > newest[i.family]:
                newest[i.family] = key
    items = []
    for i in installs:
        old = bool(i.version) and version_key(i.version) < newest.get(i.family, ())
        item = ItemRecord(
            id=f"{i.kind}:{i.source}:{display_path(i.path)}", source=SOURCE, name=i.name, state="manual",
            kind=i.kind, installed_version=i.version, origin=i.source, attributes=dict(i.attributes))
        item.attributes["path"] = str(i.path)
        item.attributes["family"] = i.family
        item.attributes["group"] = GROUPS[i.kind]
        item.attributes["copies"] = str(copies[i.family])
        if i.version_error:
            item.state, item.note = "unknown", i.version_error
        elif old:
            item.state, item.note = "unknown", NOTE_OLD
            item.attributes["oldCopy"] = "true"
        else:
            item.note = NOTE_NEWEST
        items.append(item)
    # Newest version first inside a name, names in order, groups in order.
    order = list(GROUPS)
    items.sort(key=lambda it: it.id)
    items.sort(key=lambda it: version_key(it.installed_version or ""), reverse=True)
    items.sort(key=lambda it: (order.index(it.kind), it.name.lower()))
    return items


def installs_unreadable(scan: Scan) -> list[Install]:
    return [i for i in scan.installs if i.version_error]


def collect(home: str | os.PathLike | None = None, system_root: str | os.PathLike = "/") -> SourceResult:
    """Scan every known layout. `home` and `system_root` are for tests. Nothing here starts a program."""
    home_path = Path(home) if home else Path(os.path.expanduser("~"))
    system = Path(system_root)
    scan = Scan()
    steps = [
        *(lambda s=spec: scan_version_dir(home_path, s, scan) for spec in HOME_DIRS),
        lambda: scan_uv_pythons(home_path, scan),
        lambda: scan_python_framework(system, scan),
        lambda: scan_tool_versions(home_path, ".asdf/installs", "~/.asdf", "asdf", scan),
        lambda: scan_tool_versions(home_path, ".local/share/mise/installs", "~/.local/share/mise", "mise", scan),
        lambda: scan_sdkman(home_path, scan),
        lambda: scan_rustup(home_path, scan),
        lambda: scan_jvms([(system / "Library/Java/JavaVirtualMachines", "/Library/Java/JavaVirtualMachines"),
                           (home_path / "Library/Java/JavaVirtualMachines", "~/Library/Java/JavaVirtualMachines")], scan),
        lambda: scan_go(system, home_path, scan),
        lambda: scan_sdks(system, home_path, scan),
        lambda: scan_extensions(home_path, scan),
    ]
    for step in steps:
        try:
            step()
        except Exception as exc:  # One layout must not stop the others.
            scan.errors.append(RootError("runtime", f"Cannot read an install folder: {type(exc).__name__}."))
    items = to_items(scan.installs)
    unreadable = [i for i in installs_unreadable(scan)]
    problems = []
    if scan.errors:
        problems.append(ERROR_ROOTS.format(count=len(scan.errors)))
    if unreadable:
        problems.append(ERROR_VERSIONS.format(count=len(unreadable)))
    if not problems:
        return SourceResult(CoverageRecord(SOURCE, LABEL, "complete"), items)
    detail = [f"{GROUPS[e.kind]}: {e.message}" for e in scan.errors]
    detail += [f"{GROUPS[i.kind]}: {i.name} {display_path(i.path)}: {i.version_error}" for i in unreadable]
    state = "failed" if scan.errors and not items else "partial"
    return SourceResult(CoverageRecord(SOURCE, LABEL, state, error=" ".join(problems), detail="\n".join(detail)), items)
