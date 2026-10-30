"""Plan and run the update of one direct dependency in a Cargo project (#15).

The item key is `cargo/<crate>@<target>|<project path>|<lockfile>`, for example
`cargo/smallvec@1.6.1|~/Projects/tool|Cargo.lock`. The target is the fixed version of a finding.

What the plan reads: `Cargo.toml`, `Cargo.lock` and `cargo update --dry-run` for the lock change.
The one command is `cargo update --manifest-path <Cargo.toml> -p <crate>@<locked> --precise <target>`:
- It names one package. The engine never runs `cargo update` for all packages.
- `cargo update` only resolves versions and writes `Cargo.lock`. It does not compile, so no build
  script runs. Cargo builds the crate on the next `cargo build` that the owner runs.
- Watchtower does not edit `Cargo.toml`. If its requirement does not allow the target (for example an
  exact pin `=1.2.3`), the plan is refused.
- Workspaces, git and path dependencies and an out-of-date `Cargo.lock` are refused.
Success is `lockfile_updated`, never `verified`: no installed crate exists to read again.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..discovery import PROJECT_ROOTS, display_path
from ..models import _under_roots
from ..store import ensure_private_dir, ensure_private_file
from .homebrew import Change, Plan, version_key

KIND = "cargo"
KEY_PREFIX = "cargo/"
ECOSYSTEM = "crates.io"
CARGO_PATHS = ("~/.cargo/bin/cargo", "/opt/homebrew/bin/cargo", "/usr/local/bin/cargo")
TIMEOUT_SECONDS = 300
ALLOWED_CHANGES = {"Cargo.lock"}
LOCK_VERSIONS = (3, 4)
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
STATUS_DONE = "lockfile_updated"

# Refusals: the plan exists, but Update stays off. One sentence for the owner (#15 Design notes).
REFUSE_NO_CARGO = "cargo is not installed."
REFUSE_KEY = "Watchtower cannot read this update request."
REFUSE_PROJECT = "Watchtower cannot find this Cargo project in the project folders."
REFUSE_WORKSPACE = "Cargo workspaces are not supported yet."
REFUSE_LOCK = "Cargo.lock is missing or out of date. Run cargo yourself first."
REFUSE_SOURCE = "Git and path dependencies are not supported."
REFUSE_NOT_DIRECT = "{name} is not a direct dependency of this project. Watchtower updates direct dependencies only."
REFUSE_CURRENT = "Cargo.lock already has {name} {version} or newer."
REFUSE_SPEC = "Cargo.toml requires {name} \"{requirement}\". That does not allow {target}. Change it there first."
REFUSE_UNREADABLE = "Watchtower cannot read the Cargo plan."

BUILD_TEXT = "Not run. Cargo builds on next use."
INSTALLED_TEXT = "not checked. Cargo builds crates on next use."
MANUAL_STEP = "Build or test the project to use the new version."
ERROR_FAILED_FILES = "cargo changed files that Watchtower did not plan: {files}."
ERROR_LOCK_STILL = "The command finished, but Cargo.lock still has {version}."

EVIDENCE_EXACT = "exact_pin"
EVIDENCE_RANGE = "range"


def find_cargo() -> str | None:
    found = shutil.which("cargo")
    if found:
        return found
    return next((p for p in (os.path.expanduser(x) for x in CARGO_PATHS) if os.access(p, os.X_OK)), None)


def cargo_env() -> dict:
    """A small environment. No CARGO_* variable of the owner's shell reaches cargo."""
    home = os.environ.get("HOME", "")
    return {
        "PATH": f"/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:{home}/.cargo/bin",
        "HOME": home,
        "LANG": "en_US.UTF-8",
        "CARGO_TERM_COLOR": "never",
        "CARGO_TERM_PROGRESS_WHEN": "never",
    }


def normalize(name: str) -> str:
    """Cargo treats `-` and `_` in a crate name as the same."""
    return name.replace("_", "-").lower()


# Key


@dataclass
class Request:
    name: str
    target: str
    project_path: str  # As the finding has it, for example ~/Projects/tool.
    lockfile: str  # Relative to the project path, for example `Cargo.lock` or `cli/Cargo.lock`.

    @property
    def root(self) -> Path:
        """The Cargo project folder: the folder of the lockfile."""
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
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) or not re.fullmatch(r"\d+\.\d+\.\d+[0-9A-Za-z.+-]*", target):
        return None
    pure = Path(lockfile)
    if pure.is_absolute() or ".." in pure.parts or pure.name != "Cargo.lock" or not project.strip():
        return None
    return Request(name, target, project, lockfile)


# Files


def _read_toml(path: Path) -> dict | None:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _file_hash(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def in_workspace(root: Path, manifest: dict) -> bool:
    """A workspace root, or a member below one. Watchtower does not update workspaces yet."""
    if "workspace" in manifest:
        return True
    for parent in list(root.parents)[:4]:
        data = _read_toml(parent / "Cargo.toml") if (parent / "Cargo.toml").is_file() else None
        if data and "workspace" in data:
            return True
    return False


# Requirements (Cargo semver)


@dataclass
class Declaration:
    name: str  # The crate name (after `package = ...` renames).
    key: str  # The key in Cargo.toml.
    spec: str | None  # The version requirement, for example `1.0.190` or `=1.0.9`. None for git or path.
    table: str  # dependencies, dev-dependencies or build-dependencies
    source: str  # registry, git, path, workspace, other-registry

    @property
    def evidence(self) -> str:
        if self.source != "registry":
            return self.source
        return EVIDENCE_EXACT if is_exact_pin(self.spec or "") else EVIDENCE_RANGE


def _declaration(key: str, value, table: str) -> Declaration | None:
    if isinstance(value, str):
        return Declaration(key, key, value.strip(), table, "registry")
    if not isinstance(value, dict):
        return None
    name = value.get("package") if isinstance(value.get("package"), str) else key
    spec = value.get("version").strip() if isinstance(value.get("version"), str) else None
    if value.get("workspace") is True:
        source = "workspace"
    elif "git" in value:
        source = "git"
    elif "path" in value:
        source = "path"
    elif "registry" in value:
        source = "other-registry"
    else:
        source = "registry"
    return Declaration(name, key, spec, table, source)


def all_declarations(manifest: dict) -> list[Declaration]:
    """Every dependency in Cargo.toml: normal, dev and build, also the `[target.<cfg>]` tables."""
    tables = [(t, manifest.get(t)) for t in DEPENDENCY_TABLES]
    for cfg in (manifest.get("target") or {}).values():
        if isinstance(cfg, dict):
            tables += [(t, cfg.get(t)) for t in DEPENDENCY_TABLES]
    found = []
    for table, entries in tables:
        for key, value in (entries or {}).items() if isinstance(entries, dict) else []:
            decl = _declaration(key, value, table)
            if decl:
                found.append(decl)
    return found


def declarations(manifest: dict, name: str) -> list[Declaration]:
    return [d for d in all_declarations(manifest) if normalize(d.name) == normalize(name)]


def is_exact_pin(spec: str) -> bool:
    """`=1.2.3` is an exact pin. `1.2.3`, `^1.2`, `~1.2` and `>=1, <2` are ranges."""
    return "," not in spec and bool(re.fullmatch(r"\s*=\s*\d+\.\d+\.\d+\S*\s*", spec))


def _numbers(text: str) -> tuple[int, int | None, int | None]:
    m = re.fullmatch(r"(\d+)(?:\.(\d+|\*))?(?:\.(\d+|\*))?(?:[-+].*)?", text.strip())
    if not m:
        raise ValueError(f"not a version: {text!r}")
    parts = [int(g) if g and g != "*" else None for g in m.groups()]
    return parts[0], parts[1], parts[2]


def _version(text: str) -> tuple[int, int, int]:
    major, minor, patch = _numbers(text)
    return major, minor or 0, patch or 0


def _bounds(op: str, rhs: str) -> tuple[tuple, tuple | None]:
    """The [low, high) range of one comparator. `high` None: no upper bound."""
    major, minor, patch = _numbers(rhs)
    low = (major, minor or 0, patch or 0)
    if op in ("^", ""):
        if major > 0 or minor is None:
            return low, (major + 1, 0, 0)
        if minor > 0 or patch is None:
            return low, (0, minor + 1, 0)
        return low, (0, 0, patch + 1)
    if op == "~":
        return low, (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
    if op == "=":
        if minor is None:
            return low, (major + 1, 0, 0)
        if patch is None:
            return low, (major, minor + 1, 0)
        return low, (major, minor, patch + 1)
    raise ValueError(op)


def spec_allows(spec: str, version: str) -> bool:
    """Does a Cargo version requirement such as `1.0.190`, `=1.0.9` or `>=1, <2` allow `version`?

    Pre-release rules are not applied. A requirement that the engine does not know returns False.
    """
    try:
        v = _version(version)
        for clause in (c.strip() for c in spec.split(",") if c.strip()):
            if clause == "*":
                continue
            m = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?\s*(\S+)", clause)
            if not m:
                return False
            op, rhs = m.group(1) or "", m.group(2)
            if rhs.endswith("*") and op == "":
                op, rhs = "=", rhs.rstrip(".*")  # `1.*` is `=1`, `1.2.*` is `=1.2`.
            if op in (">=", ">", "<=", "<"):
                r = _version(rhs)
                ok = {">=": v >= r, ">": v > r, "<=": v <= r, "<": v < r}[op]
            else:
                low, high = _bounds(op, rhs)
                ok = v >= low and (high is None or v < high)
            if not ok:
                return False
        return True
    except ValueError:
        return False


def is_major_change(before: str | None, after: str | None) -> bool:
    """A Cargo semver-incompatible change: the leftmost non-zero part changes (0.2 -> 0.3 counts)."""
    try:
        a, b = _version(before or ""), _version(after or "")
    except ValueError:
        return False
    key = lambda v: (v[0],) if v[0] else (0, v[1]) if v[1] else v
    return key(b) != key(a) and b > a


# Lock


def lock_packages(lock: dict) -> list[dict]:
    return [p for p in lock.get("package") or [] if isinstance(p, dict) and isinstance(p.get("name"), str)]


def locked_for(lock: dict, decl: Declaration) -> list[str]:
    """The registry versions of `decl` in the lock that its requirement allows."""
    return [str(p.get("version")) for p in lock_packages(lock)
            if normalize(p["name"]) == normalize(decl.name) and str(p.get("source", "")).startswith("registry+")
            and isinstance(p.get("version"), str) and decl.spec is not None and spec_allows(decl.spec, p["version"])]


def lock_problem(manifest: dict | None, lock: dict | None) -> str | None:
    """REFUSE_LOCK if Cargo.lock is missing, of an unknown format, or does not match Cargo.toml."""
    if manifest is None or lock is None or lock.get("version") not in LOCK_VERSIONS:
        return REFUSE_LOCK
    package = manifest.get("package") if isinstance(manifest.get("package"), dict) else {}
    names = {normalize(p["name"]) for p in lock_packages(lock) if "source" not in p}
    if not isinstance(package.get("name"), str) or normalize(package["name"]) not in names:
        return REFUSE_LOCK
    for decl in all_declarations(manifest):
        if decl.source == "registry" and decl.spec is not None and not locked_for(lock, decl):
            return REFUSE_LOCK
    return None


# Dependencies table (Projects detail)


def dependencies(project_dir: Path) -> tuple[list[dict] | None, str | None]:
    """Rows of the `Dependencies` table for a Cargo project at `project_dir`, and a note.

    Reads Cargo.toml and Cargo.lock only. Exact pins and ranges stay separate evidence types.
    """
    manifest = _read_toml(project_dir / "Cargo.toml")
    if manifest is None:
        return None, None
    if in_workspace(project_dir, manifest):
        return None, REFUSE_WORKSPACE
    lock = _read_toml(project_dir / "Cargo.lock")
    note = lock_problem(manifest, lock)
    rows = []
    for decl in sorted(all_declarations(manifest), key=lambda d: (d.name.lower(), d.table)):
        locked = locked_for(lock or {}, decl) if decl.source == "registry" else []
        rows.append({"package": decl.name, "declared": decl.spec or decl.source, "locked": locked[0] if len(locked) == 1 else None,
                     "evidence": decl.evidence, "ecosystem": ECOSYSTEM,
                     "table": None if decl.table == "dependencies" else decl.table})
    return rows, note


def block_reason(project_path: str, lockfile: str, roots: tuple[str, ...] = PROJECT_ROOTS) -> str | None:
    """Why `Update…` is off for this Cargo.lock before any plan exists, or None. File checks only."""
    if Path(lockfile).name != "Cargo.lock":
        return None
    root = Path(os.path.expanduser(project_path)) / Path(lockfile).parent
    manifest = _read_toml(root / "Cargo.toml")
    if manifest is not None and in_workspace(root, manifest):
        return REFUSE_WORKSPACE
    return lock_problem(manifest, _read_toml(root / "Cargo.lock"))


# Plan


def _row(label: str, value: str, items: list[str] | None = None, ok: bool | None = None) -> dict:
    row = {"label": label, "value": value}
    if items is not None:
        row["items"] = items
    if ok is not None:
        row["ok"] = ok
    return row


_CHANGE_RES = (
    ("upgrade", re.compile(r"^\s*(?:Updating|Downgrading)\s+(\S+)\s+v(\S+)\s+->\s+v(\S+)(?:\s+\(.*\))?\s*$")),
    ("install", re.compile(r"^\s*Adding\s+(\S+)\s+v(\S+)(?:\s+\(.*\))?\s*$")),
    ("remove", re.compile(r"^\s*Removing\s+(\S+)\s+v(\S+)(?:\s+\(.*\))?\s*$")),
)


def parse_lock_changes(text: str) -> list[Change]:
    """The package changes in `cargo update` output (stderr). `Updating crates.io index` is not a change."""
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


def build_command(cargo: str, req: Request, current: str, dry_run: bool = False) -> list[str]:
    command = [cargo, "update", "--manifest-path", str(req.root / "Cargo.toml"), "-p", f"{req.name}@{current}",
               "--precise", req.target]
    return command + ["--dry-run"] if dry_run else command


def make_plan(item_key: str, cargo: str | None = None, run: Callable = subprocess.run,
              roots: tuple[str, ...] = PROJECT_ROOTS) -> Plan:
    """Plan one Cargo update. A plan with `refusal` set must not run."""
    req = parse_key(item_key)
    if req is None:
        return Plan(item_key, "?", KIND, "?", None, None, [], refusal=REFUSE_KEY)
    cargo = cargo or find_cargo()
    plan = Plan(item_key, req.name, KIND, normalize(req.name), None, req.target, [cargo or "cargo"])
    plan.rows = [_row("Project", display_path(req.root))]

    def refuse(text: str, detail: str | None = None) -> Plan:
        plan.refusal, plan.detail = text, detail
        return plan

    project_dir = Path(os.path.expanduser(req.project_path))
    if not _under_roots(str(project_dir.resolve()), roots) or not req.root.resolve().is_relative_to(project_dir.resolve()):
        return refuse(REFUSE_PROJECT)
    manifest = _read_toml(req.root / "Cargo.toml")
    if manifest is None:
        return refuse(REFUSE_PROJECT)
    if in_workspace(req.root, manifest):
        return refuse(REFUSE_WORKSPACE)
    lock = _read_toml(req.root / "Cargo.lock")
    problem = lock_problem(manifest, lock)
    if problem:
        return refuse(problem)
    decls = declarations(manifest, req.name)
    if not decls:
        return refuse(REFUSE_NOT_DIRECT.format(name=req.name))
    if any(d.source != "registry" for d in decls):
        return refuse(REFUSE_SOURCE)
    locked = sorted({v for d in decls for v in locked_for(lock, d)}, key=version_key)
    if len(locked) != 1:
        return refuse(REFUSE_UNREADABLE, f"Cargo.lock has {locked or 'no'} versions of {req.name} for Cargo.toml")
    current = locked[0]
    plan.installed_version = current
    if version_key(req.target) <= version_key(current):
        return refuse(REFUSE_CURRENT.format(name=req.name, version=req.target))
    for d in decls:
        if not spec_allows(d.spec or "", req.target):
            return refuse(REFUSE_SPEC.format(name=req.name, requirement=d.spec, target=req.target))
    if cargo is None:
        return refuse(REFUSE_NO_CARGO)

    plan.major_change = is_major_change(current, req.target)
    plan.rows += [_row("Cargo.toml", "No change"), _row("Cargo.lock", f"{req.name} {current} → {req.target}")]

    # The collateral changes of the lock: what else would move. `--dry-run` writes nothing.
    try:
        proc = run(build_command(cargo, req, current, dry_run=True), capture_output=True, text=True,
                   timeout=TIMEOUT_SECONDS, env=cargo_env(), stdin=subprocess.DEVNULL, cwd=str(req.root))
        if proc.returncode != 0:
            raise ValueError(f"dry run exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        changes = parse_lock_changes(proc.stdout + "\n" + proc.stderr)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return refuse(REFUSE_UNREADABLE, str(exc))
    own = [c for c in changes if normalize(c.name) == normalize(req.name)]
    if not own or own[0].after != req.target:
        return refuse(REFUSE_UNREADABLE, f"cargo would not lock {req.name} {req.target}: {[c.to_dict() for c in own]}")
    others = [c for c in changes if normalize(c.name) != normalize(req.name)]
    plan.also_changes = []  # The plan step shows the `Other packages` row instead (as npm and uv).
    plan.rows.append(_row("Other packages",
                          "No other packages change." if not others else
                          ("1 package changes" if len(others) == 1 else f"{len(others)} packages change"),
                          [_change_text(c) for c in others] if others else None))
    plan.rows.append(_row("Build", BUILD_TEXT))
    plan.command = build_command(cargo, req, current)
    plan.manual_steps = [MANUAL_STEP]
    digest = hashlib.sha256()
    for part in (_file_hash(req.root / "Cargo.toml"), _file_hash(req.root / "Cargo.lock"), req.target):
        digest.update(f"{part}\0".encode())
    plan.fingerprint = digest.hexdigest()[:24]
    return plan


# Run


@dataclass
class Snapshot:
    files: dict[str, str | None] = field(default_factory=dict)  # name -> digest of each file in the project folder


def snapshot(root: Path) -> Snapshot:
    snap = Snapshot()
    try:
        for entry in os.scandir(root):
            if entry.is_file(follow_symlinks=False):
                snap.files[entry.name] = _file_hash(Path(entry.path))
    except OSError:
        pass
    return snap


def stray_changes(before: Snapshot, after: Snapshot) -> list[str]:
    """Files in the project folder, other than Cargo.lock, that the run changed, added or removed."""
    names = set(before.files) | set(after.files)
    return sorted(n for n in names if n not in ALLOWED_CHANGES and before.files.get(n) != after.files.get(n))


def backup_files(root: Path, data_dir: Path, attempt_id: int) -> Path | None:
    """Copy Cargo.toml and Cargo.lock to the data folder before the run, so the owner can restore them."""
    try:
        folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "update-backups")
                                    / f"attempt-{attempt_id}")
        for name in ("Cargo.toml", "Cargo.lock"):
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
    stray: list[str]

    def result_rows(self, name: str, target: str | None = None) -> list[dict]:
        """The lockfile line, and the installed line that Cargo cannot give: never checked."""
        return [_row("Lockfile", f"{name} {self.locked or 'unknown'}", ok=self.locked == target),
                _row("Installed", INSTALLED_TEXT)]


def read_outcome(root: Path, name: str, before: Snapshot) -> Outcome:
    """Read Cargo.lock again. The locked version is the one that Cargo.toml allows."""
    manifest, lock = _read_toml(root / "Cargo.toml") or {}, _read_toml(root / "Cargo.lock") or {}
    found = sorted({v for d in declarations(manifest, name) for v in locked_for(lock, d)}, key=version_key)
    return Outcome(found[0] if len(found) == 1 else None, stray_changes(before, snapshot(root)))


def verdict(outcome: Outcome, target: str, name: str, code: int) -> tuple[str, str | None]:
    """The log status and the owner-facing error text for one finished run."""
    if code != 0:
        return "failed", None
    if outcome.stray:
        return "not_verified", ERROR_FAILED_FILES.format(files=", ".join(outcome.stray))
    if outcome.locked != target:
        return "not_verified", ERROR_LOCK_STILL.format(version=outcome.locked or "no single version of " + name)
    return STATUS_DONE, None
