"""Plan and run the update of one direct dependency in a uv project.

The item key is `uv/<package>@<target>|<project path>|<lockfile>`, for example
`uv/httpx@0.27.2|~/Real/tool|uv.lock`. The target is the fixed version of a finding.

What the plan reads: `pyproject.toml`, `uv.lock`, the files of the existing `.venv`, one PyPI
metadata page of the target version, and `uv lock --dry-run` for the lock change.
The one command is `uv sync --upgrade-package <name>==<target> --inexact --no-build ...`:
- It names one package. The engine never runs `uv add`, `uv remove`, `uv lock --upgrade` for all
  packages or `uv sync` without `--upgrade-package`.
- `--no-build` keeps source builds off. If the target has no wheel for this Mac, the plan needs the
  scripts step, and only the second confirmation runs the command without `--no-build`.
- `--inexact` keeps the packages that the lock does not list.
- `UV_PYTHON_DOWNLOADS=never`: uv cannot fetch a Python. Watchtower never creates an environment.
- Watchtower does not edit `pyproject.toml`. If the requirement there does not allow the target,
  the plan is refused.
Success needs both: the new `uv.lock` and the installed package in `.venv` show the target.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..discovery import PROJECT_ROOTS, display_path
from ..feeds.homebrew import Fetch, Response, http_fetch
from ..models import _under_roots
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Change, Plan, is_major_change, version_key

KIND = "uv"
KEY_PREFIX = "uv/"
UV_PATHS = ("~/.local/bin/uv", "/opt/homebrew/bin/uv", "/usr/local/bin/uv", "~/.cargo/bin/uv")
TIMEOUT_SECONDS = 180
PYPI_URL = "https://pypi.org/pypi/{name}/{version}/json"
ALLOWED_CHANGES = {"pyproject.toml", "uv.lock"}

# Refusals: the plan exists, but Update stays off. One sentence for the owner.
REFUSE_NO_UV = "uv is not installed."
REFUSE_KEY = "Watchtower cannot read this update request."
REFUSE_PROJECT = "Watchtower cannot find this uv project in the project folders."
REFUSE_NO_ENV = "No environment found. Watchtower does not create environments."
REFUSE_WORKSPACE = "Watchtower cannot update workspace projects yet."
REFUSE_NOT_DIRECT = "{name} is not a direct dependency of this project. Watchtower updates direct dependencies only."
REFUSE_SOURCE = "{name} does not come from a package index. Watchtower cannot update git or path dependencies."
REFUSE_NOT_LOCKED = "uv.lock has no single version of {name}."
REFUSE_CURRENT = "uv.lock already has {name} {version} or newer."
REFUSE_SPEC = "pyproject.toml requires \"{requirement}\". That does not allow {target}. Change it there first."
REFUSE_UNREADABLE = "Watchtower cannot read the uv plan."
REFUSE_WHEELS = "Watchtower cannot check whether {name} {target} needs a source build."
REFUSE_NO_FILES = "PyPI has no files for {name} {target}."

BUILD_REASON = "{name} needs a source build: no wheel for this platform."
ERROR_FAILED_FILES = "uv changed files that Watchtower did not plan: {files}."
ERROR_ENV = "uv replaced the environment. Watchtower did not plan that."
ERROR_ENV_STILL = "Not verified: the environment still has {version}."
ERROR_ENV_UNKNOWN = "Not verified: Watchtower cannot read the installed version."
ERROR_LOCK_STILL = "The command finished, but uv.lock still has {version}."


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def find_uv() -> str | None:
    found = shutil.which("uv")
    if found:
        return found
    return next((p for p in (os.path.expanduser(x) for x in UV_PATHS) if os.access(p, os.X_OK)), None)


def uv_env() -> dict:
    """A small environment. No UV_* variable of the owner's shell reaches uv."""
    return {
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "HOME": os.environ.get("HOME", ""),
        "LANG": "en_US.UTF-8",
        "NO_COLOR": "1",
        "UV_NO_PROGRESS": "1",
        "UV_PYTHON_DOWNLOADS": "never",
    }


# Key


@dataclass
class Request:
    name: str
    target: str
    project_path: str  # As the finding has it, for example ~/Real/tool.
    lockfile: str  # Relative to the project path, for example `uv.lock` or `app/uv.lock`.

    @property
    def root(self) -> Path:
        """The uv project folder: the folder of the lockfile."""
        return Path(os.path.expanduser(self.project_path)) / Path(self.lockfile).parent


def make_key(name: str, target: str, project_path: str, lockfile: str) -> str:
    return f"{KEY_PREFIX}{name}@{target}|{project_path}|{lockfile}"


def parse_key(item_key: str) -> Request | None:
    if not item_key.startswith(KEY_PREFIX):
        return None
    parts = item_key[len(KEY_PREFIX):].split("|")
    if len(parts) != 3:
        return None
    head, project, lockfile = parts
    name, _, target = head.rpartition("@")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not re.fullmatch(r"[0-9A-Za-z.+!_-]+", target):
        return None
    pure = Path(lockfile)
    if pure.is_absolute() or ".." in pure.parts or pure.name != "uv.lock" or not project.strip():
        return None
    return Request(name, target, project, lockfile)


# Files


def _read_toml(path: Path) -> dict | None:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def locked_versions(lock: dict, name: str) -> list[dict]:
    return [p for p in lock.get("package") or [] if isinstance(p, dict) and normalize(str(p.get("name", ""))) == normalize(name)]


def site_packages(env: Path) -> list[Path]:
    return sorted(p for p in (env / "lib").glob("python3*/site-packages") if p.is_dir())


def installed_version(root: Path, name: str) -> str | None:
    """The version of `name` in `<root>/.venv`, from its dist-info folder. Starts no program."""
    prefix = normalize(name).replace("-", "_")
    for site in site_packages(root / ".venv"):
        for info in sorted(site.glob("*.dist-info")):
            stem = info.name[: -len(".dist-info")]
            dist, _, version = stem.rpartition("-")
            if normalize(dist).replace("-", "_") != prefix:
                continue
            try:
                for line in (info / "METADATA").read_text(errors="replace").splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip()
                    if not line.strip():
                        break
            except OSError:
                pass
            return version or None
    return None


def env_python_minor(root: Path) -> int | None:
    try:
        text = (root / ".venv" / "pyvenv.cfg").read_text(errors="replace")
    except OSError:
        return None
    m = re.search(r"^version(?:_info)?\s*=\s*3\.(\d+)", text, re.MULTILINE)
    return int(m.group(1)) if m else None


def has_environment(root: Path) -> bool:
    return (root / ".venv" / "pyvenv.cfg").is_file()


def in_workspace(root: Path, pyproject: dict) -> bool:
    if ((pyproject.get("tool") or {}).get("uv") or {}).get("workspace") is not None:
        return True
    for parent in list(root.parents)[:4]:
        data = _read_toml(parent / "pyproject.toml") if (parent / "pyproject.toml").is_file() else None
        if data and ((data.get("tool") or {}).get("uv") or {}).get("workspace") is not None:
            return True
    return False


def _file_hash(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


# Requirements


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*?)\s*(;.*)?$")


@dataclass
class Declaration:
    requirement: str  # The text in pyproject.toml.
    spec: str
    group: str | None = None
    extra: str | None = None


def declarations(pyproject: dict, name: str) -> list[Declaration]:
    """Where pyproject.toml declares `name`: dependencies, extras, dependency groups, dev-dependencies."""
    found: list[Declaration] = []

    def scan(items, group=None, extra=None):
        for item in items or []:
            if not isinstance(item, str):
                continue  # An `include-group` table.
            m = _REQ.match(item)
            if m and normalize(m.group(1)) == normalize(name):
                found.append(Declaration(item, (m.group(3) or "").strip(), group, extra))

    project = pyproject.get("project") or {}
    scan(project.get("dependencies"))
    for extra, items in (project.get("optional-dependencies") or {}).items():
        scan(items, extra=extra)
    for group, items in (pyproject.get("dependency-groups") or {}).items():
        scan(items, group=group)
    scan(((pyproject.get("tool") or {}).get("uv") or {}).get("dev-dependencies"), group="dev")
    return found


def _release(version: str) -> tuple[int, ...]:
    parts = []
    for piece in re.split(r"[.+!-]", version.strip().lstrip("vV")):
        m = re.match(r"\d+", piece)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def spec_allows(spec: str, version: str) -> bool:
    """Does a PEP 440 specifier such as `>=0.26,<1` allow `version`? Pre-release rules are not applied."""
    v = _release(version)
    for clause in (c.strip() for c in spec.strip("() ").split(",") if c.strip()):
        m = re.match(r"^(===|==|!=|~=|>=|<=|>|<)\s*(.+)$", clause)
        if not m:
            return False  # A clause that the engine does not know: do not guess.
        op, rhs = m.group(1), m.group(2).strip()
        if rhs.endswith(".*"):
            base = _release(rhs[:-2])
            hit = _cmp(v[: len(base)], base) == 0
            if (op == "==" and not hit) or (op == "!=" and hit) or op not in ("==", "!="):
                return False
            continue
        r = _release(rhs)
        ok = {
            "===": rhs == version, "==": _cmp(v, r) == 0, "!=": _cmp(v, r) != 0, ">=": _cmp(v, r) >= 0,
            "<=": _cmp(v, r) <= 0, ">": _cmp(v, r) > 0, "<": _cmp(v, r) < 0,
            "~=": len(r) >= 2 and _cmp(v, r) >= 0 and _cmp(v[: len(r) - 1], r[:-1]) == 0,
        }[op]
        if not ok:
            return False
    return True


# Wheels


def _mac_version() -> tuple[int, int]:
    parts = (platform.mac_ver()[0] or "0.0").split(".")
    return int(parts[0]), int(parts[1]) if len(parts) > 1 else 0


def wheel_fits(filename: str, minor: int | None, machine: str | None = None, mac: tuple[int, int] | None = None,
               system: str | None = None) -> bool:
    """Does this wheel fit Python 3.<minor> on this Mac? A close match of the PEP 425 tags, not all of it."""
    if not filename.endswith(".whl"):
        return False
    tags = filename[: -len(".whl")].split("-")
    if len(tags) < 5:
        return False
    py, abi, plat = tags[-3].split("."), tags[-2].split("."), tags[-1].split(".")
    machine = machine or platform.machine()
    system = system or platform.system()
    py_ok = False
    for tag in py:
        if tag in ("py3", "py2") and ("py3" in py):
            py_ok = True
        m = re.fullmatch(r"(?:py|cp)3(\d+)", tag)
        if m and minor is not None:
            k = int(m.group(1))
            if tag.startswith("py") and k <= minor:
                py_ok = True
            if tag.startswith("cp") and ((k == minor and ("none" in abi or f"cp3{k}" in abi)) or
                                         (k <= minor and "abi3" in abi)):
                py_ok = True
    if "py3" in py and ("none" in abi):
        py_ok = True
    if not py_ok:
        return False
    if "any" in plat:
        return True
    if system == "Darwin":
        mac = mac or _mac_version()
        for tag in plat:
            m = re.fullmatch(r"macosx_(\d+)_(\d+)_(\w+)", tag)
            if m and (int(m.group(1)), int(m.group(2))) <= mac and m.group(3) in (machine, "universal2"):
                return True
        return False
    return any(t.endswith(machine) and ("linux" in t) for t in plat)


# Plan


def _row(label: str, value: str, items: list[str] | None = None) -> dict:
    row = {"label": label, "value": value}
    if items is not None:
        row["items"] = items
    return row


_CHANGE_RES = (
    ("upgrade", re.compile(r"^\s*(?:Update[d]?|Upgrade[d]?)\s+(\S+)\s+v?(\S+)\s+->\s+v?(\S+)\s*$")),
    ("install", re.compile(r"^\s*(?:Add(?:ed)?|Install(?:ed)?)\s+(\S+)\s+v?(\S+)\s*$")),
    ("remove", re.compile(r"^\s*Remov(?:e|ed)\s+(\S+)\s+v?(\S+)\s*$")),
)


def parse_lock_changes(text: str) -> list[Change]:
    """The package changes in the output of `uv lock --dry-run`. Other lines are ignored."""
    changes: list[Change] = []
    for line in text.splitlines():
        for kind, rx in _CHANGE_RES:
            m = rx.match(line)
            if not m:
                continue
            if kind == "upgrade":
                changes.append(Change(m.group(1), m.group(2), m.group(3), "upgrade"))
            elif kind == "install":
                changes.append(Change(m.group(1), None, m.group(2), "install"))
            else:
                changes.append(Change(m.group(1), m.group(2), None, "remove"))
            break
    return changes


def _change_text(c: Change) -> str:
    if c.change == "install":
        return f"{c.name} {c.after} (new)"
    if c.change == "remove":
        return f"{c.name} {c.before} (removed)"
    return f"{c.name} {c.before} → {c.after}"


def build_command(uv: str, req: Request, decls: list[Declaration], allow_build: bool) -> list[str]:
    command = [uv, "--project", str(req.root), "sync", "--upgrade-package", f"{req.name}=={req.target}", "--inexact"]
    if not allow_build:
        command.append("--no-build")
    for group in sorted({d.group for d in decls if d.group}):
        command += ["--group", group]
    for extra in sorted({d.extra for d in decls if d.extra}):
        command += ["--extra", extra]
    return command


def groups_and_extras_text(decls: list[Declaration]) -> str:
    groups = sorted({d.group for d in decls if d.group})
    extras = sorted({d.extra for d in decls if d.extra})
    return f"Groups: {', '.join(groups) or 'none'}. Extras: {', '.join(extras) or 'none'}."


def _fetch_files(name: str, target: str, fetch: Fetch) -> list[dict] | None:
    """The files of one release from PyPI. None if the page cannot be read."""
    url = PYPI_URL.format(name=urllib.parse.quote(name), version=urllib.parse.quote(target))
    try:
        resp = fetch(url, {"Accept": "application/json"})
        if resp.status != 200:
            return None
        data = json.loads(resp.body)
    except Exception:
        return None
    files = data.get("urls") if isinstance(data, dict) else None
    if not isinstance(files, list):
        return None
    return [f for f in files if isinstance(f, dict) and isinstance(f.get("filename"), str) and not f.get("yanked")]


def make_plan(
    item_key: str,
    uv: str | None = None,
    run: Callable = subprocess.run,
    fetch: Fetch = http_fetch,
    roots: tuple[str, ...] = PROJECT_ROOTS,
    machine: str | None = None,
    mac: tuple[int, int] | None = None,
    system: str | None = None,
) -> Plan:
    """Plan one uv update. A plan with `refusal` set must not run."""
    req = parse_key(item_key)
    if req is None:
        return Plan(item_key, "?", KIND, "?", None, None, [], refusal=REFUSE_KEY)
    uv = uv or find_uv()
    shown = display_path(req.root)
    plan = Plan(item_key, req.name, KIND, normalize(req.name), None, req.target, [uv or "uv"])
    plan.rows = [_row("Project", shown)]

    def refuse(text: str, detail: str | None = None) -> Plan:
        plan.refusal, plan.detail = text, detail
        return plan

    project_dir = Path(os.path.expanduser(req.project_path))
    if not _under_roots(str(project_dir.resolve()), roots) or not (req.root / "uv.lock").is_file():
        return refuse(REFUSE_PROJECT)
    if not req.root.resolve().is_relative_to(project_dir.resolve()):
        return refuse(REFUSE_PROJECT)
    pyproject, lock = _read_toml(req.root / "pyproject.toml"), _read_toml(req.root / "uv.lock")
    if pyproject is None or lock is None:
        return refuse(REFUSE_UNREADABLE, "pyproject.toml or uv.lock is missing or is not valid TOML")
    env_ok = has_environment(req.root)
    plan.rows.append(_row("Environment", ".venv (exists)" if env_ok else ".venv (missing)"))
    if not env_ok:
        return refuse(REFUSE_NO_ENV)
    if in_workspace(req.root, pyproject):
        return refuse(REFUSE_WORKSPACE)
    if uv is None:
        return refuse(REFUSE_NO_UV)

    decls = declarations(pyproject, req.name)
    if not decls:
        return refuse(REFUSE_NOT_DIRECT.format(name=req.name))
    if normalize(req.name) in {normalize(k) for k in ((pyproject.get("tool") or {}).get("uv") or {}).get("sources", {})}:
        return refuse(REFUSE_SOURCE.format(name=req.name))
    entries = locked_versions(lock, req.name)
    if len(entries) != 1 or not entries[0].get("version"):
        return refuse(REFUSE_NOT_LOCKED.format(name=req.name))
    source = entries[0].get("source") or {}
    if "registry" not in source:
        return refuse(REFUSE_SOURCE.format(name=req.name))
    current = str(entries[0]["version"])
    plan.installed_version = current
    installed = installed_version(req.root, req.name)
    if version_key(req.target) <= version_key(current):
        return refuse(REFUSE_CURRENT.format(name=req.name, version=req.target))
    for d in decls:
        if not spec_allows(d.spec, req.target):
            return refuse(REFUSE_SPEC.format(requirement=d.requirement, target=req.target))

    plan.major_change = is_major_change(current, req.target)
    plan.rows += [
        _row("pyproject.toml", "No change"),
        _row("uv.lock", f"{req.name} {current} → {req.target}"),
        _row("Groups and extras", groups_and_extras_text(decls)),
    ]

    # The collateral changes of the lock: what else would move.
    dry = [uv, "--project", str(req.root), "lock", "--upgrade-package", f"{req.name}=={req.target}", "--dry-run"]
    try:
        proc = run(dry, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=uv_env(),
                   stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise ValueError(f"dry run exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        changes = parse_lock_changes(proc.stdout + "\n" + proc.stderr)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return refuse(REFUSE_UNREADABLE, str(exc))
    own = [c for c in changes if normalize(c.name) == normalize(req.name)]
    if not own or own[0].after != req.target:
        return refuse(REFUSE_UNREADABLE, f"uv would not lock {req.name} {req.target}: {[c.to_dict() for c in own]}")
    others = [c for c in changes if normalize(c.name) != normalize(req.name)]
    plan.also_changes = []  # The plan step shows the `Other packages` row instead.
    plan.rows.append(_row("Other packages",
                          "No other packages change." if not others else f"{len(others)} packages",
                          [_change_text(c) for c in others] if others else None))

    # The build policy: wheels only, unless the target has no wheel for this Mac.
    files = _fetch_files(req.name, req.target, fetch)
    if files is None:
        return refuse(REFUSE_WHEELS.format(name=req.name, target=req.target))
    if not files:
        return refuse(REFUSE_NO_FILES.format(name=req.name, target=req.target))
    minor = env_python_minor(req.root)
    needs_build = not any(wheel_fits(f["filename"], minor, machine, mac, system) for f in files)
    plan.rows.append(_row("Build", "Disabled"))
    plan.command = build_command(uv, req, decls, allow_build=False)
    if needs_build:
        plan.scripts = [BUILD_REASON.format(name=req.name)]
        plan.scripts_message = BUILD_REASON.format(name=req.name)
        plan.scripts_command = build_command(uv, req, decls, allow_build=True)
    plan.manual_steps = ["Restart the dev server after the update."]
    digest = hashlib.sha256()
    for part in (_file_hash(req.root / "pyproject.toml"), _file_hash(req.root / "uv.lock"),
                 _file_hash(req.root / ".venv" / "pyvenv.cfg"), installed, req.target):
        digest.update(f"{part}\0".encode())
    plan.fingerprint = digest.hexdigest()[:24]
    return plan


def block_reason(project_path: str, lockfile: str, roots: tuple[str, ...] = PROJECT_ROOTS) -> str | None:
    """Why `Update…` is off for this lockfile before any plan exists, or None. File checks only."""
    root = Path(os.path.expanduser(project_path)) / Path(lockfile).parent
    if Path(lockfile).name != "uv.lock" or not (root / "uv.lock").is_file():
        return None
    if not has_environment(root):
        return REFUSE_NO_ENV
    pyproject = _read_toml(root / "pyproject.toml")
    if pyproject is not None and in_workspace(root, pyproject):
        return REFUSE_WORKSPACE
    return None


# Run


@dataclass
class Snapshot:
    files: dict[str, str | None] = field(default_factory=dict)  # name -> digest of each file in the project folder
    env_cfg: str | None = None
    env_inode: int | None = None


def snapshot(root: Path) -> Snapshot:
    snap = Snapshot()
    try:
        for entry in os.scandir(root):
            if entry.is_file(follow_symlinks=False):
                snap.files[entry.name] = _file_hash(Path(entry.path))
    except OSError:
        pass
    snap.env_cfg = _file_hash(root / ".venv" / "pyvenv.cfg")
    try:
        snap.env_inode = (root / ".venv").stat().st_ino
    except OSError:
        pass
    return snap


def stray_changes(before: Snapshot, after: Snapshot) -> list[str]:
    """Files in the project folder, other than the lockfile, that the run changed, added or removed."""
    names = set(before.files) | set(after.files)
    return sorted(n for n in names if n != "uv.lock" and before.files.get(n) != after.files.get(n))


def env_replaced(before: Snapshot, after: Snapshot) -> bool:
    return (before.env_cfg, before.env_inode) != (after.env_cfg, after.env_inode)


def backup_files(root: Path, data_dir: Path, attempt_id: int) -> Path | None:
    """Copy pyproject.toml and uv.lock to the data folder before the run, so the owner can restore them."""
    try:
        folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "update-backups")
                                    / f"attempt-{attempt_id}")
        for name in ALLOWED_CHANGES:
            src = root / name
            if src.is_file():
                dest = ensure_private_file(folder / name)
                dest.write_bytes(src.read_bytes())
        return folder
    except OSError:
        return None


@dataclass
class Outcome:
    locked: str | None
    installed: str | None
    stray: list[str]
    env_replaced: bool

    def result_rows(self, name: str) -> list[dict]:
        return [_row("Lockfile", f"{name} {self.locked or 'unknown'}"),
                _row("Installed (.venv)", f"{name} {self.installed or 'unknown'}")]


def read_outcome(root: Path, name: str, before: Snapshot) -> Outcome:
    lock = _read_toml(root / "uv.lock") or {}
    entries = locked_versions(lock, name)
    locked = str(entries[0]["version"]) if len(entries) == 1 and entries[0].get("version") else None
    after = snapshot(root)
    return Outcome(locked, installed_version(root, name), stray_changes(before, after), env_replaced(before, after))


def verdict(outcome: Outcome, target: str, name: str, code: int) -> tuple[str, str | None]:
    """The log status and the owner-facing error text for one finished run."""
    if code != 0:
        return "failed", None
    if outcome.stray:
        return "not_verified", ERROR_FAILED_FILES.format(files=", ".join(outcome.stray))
    if outcome.env_replaced:
        return "not_verified", ERROR_ENV
    if outcome.locked != target:
        return "not_verified", ERROR_LOCK_STILL.format(version=outcome.locked or "no version of " + name)
    if outcome.installed == target:
        return "verified", None
    if outcome.installed is None:
        return "not_verified", ERROR_ENV_UNKNOWN
    return "not_verified", ERROR_ENV_STILL.format(version=outcome.installed)


def command_to_run(plan: Plan, confirm_scripts: bool) -> list[str]:
    if plan.scripts and confirm_scripts and plan.scripts_command:
        return list(plan.scripts_command)
    return list(plan.command)
