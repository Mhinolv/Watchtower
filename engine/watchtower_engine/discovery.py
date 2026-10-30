"""Find local projects under the owner's project roots.

A project is a folder that sits directly in a project root. The engine lists
file names only. It never opens a manifest, never runs a build or a script,
and never follows a symlink out of the project roots.

Rules for the list:
- One row for one real folder. Symlinks and git worktrees of a listed project add no row.
- A symlink that leads outside the project roots is skipped and reported in `skipped`.
- A root that cannot be read goes in `root_errors`. The other roots still run.
- Manifests are looked up in the project folder and in the folders below it, down to MAX_DEPTH levels (#85).
  A folder is visited once, shallow folders first, and at most MAX_DIRS folders of a project are visited.
  A project that hits the limit is `cut` (#88): its deeper manifests are not listed, and the refresh
  reports the Projects coverage as `partial` with the project name.
  The walk skips hidden folders and dependency or build folders (SKIP_DIRS), and never follows a symlink.
"""
from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

# Project roots, in the form the app shows. Applications are covered by a different source.
PROJECT_ROOTS = ("~/Projects", "~/Real")

PROJECT_STATES = ("active", "inactive", "inaccessible")

# Exact file names. The engine does not open them here.
MANIFEST_NAMES = frozenset(
    {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
        "pyproject.toml", "uv.lock", "poetry.lock", "requirements.txt", "Pipfile", "Pipfile.lock",
        "Package.swift", "Package.resolved",
        "Cargo.toml", "Cargo.lock",
        "go.mod", "go.sum",
        "Gemfile", "Gemfile.lock",
        "composer.json", "composer.lock",
    }
)

# Folders below a project that hold installed or built files, not the project's own manifests.
SKIP_DIRS = frozenset(
    {
        "node_modules", "venv", "env", "build", "dist", "target", "vendor", "Pods",
        "DerivedData", "__pycache__", "site-packages", ".venv", ".build", ".git",
    }
)

# How deep a manifest can be inside a project: 0 is the project folder, 1 a folder directly in it.
MAX_DEPTH = 8
# The most folders that the walk visits in one project. Shallow folders come first.
MAX_DIRS = 5000
NOTE_CUT = "Watchtower stopped after {limit} folders. Deeper manifests are not listed."


@dataclass
class Project:
    name: str
    path: str
    root: str
    manifests: list[str]
    state: str
    # The resolved folder. The inactive choice is stored under it. Not part of the JSON.
    real_path: str = field(default="", repr=False, compare=False)
    # The `Dependencies` table of a Cargo project (#15), and why it is incomplete. None: no table.
    dependencies: list[dict] | None = field(default=None, compare=False)
    dependency_note: str | None = field(default=None, compare=False)
    # The folder limit if the walk stopped at it (#88). None: every folder was walked.
    cut_after: int | None = field(default=None, compare=False)

    @property
    def cut(self) -> bool:
        return self.cut_after is not None

    def __post_init__(self) -> None:
        if self.state not in PROJECT_STATES:
            raise ValueError(f"state must be one of {', '.join(PROJECT_STATES)}, not {self.state!r}")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "root": self.root,
            "manifests": list(self.manifests),
            "state": self.state,
        } | ({"dependencies": self.dependencies, "dependency_note": self.dependency_note}
             if self.dependencies is not None or self.dependency_note is not None else {}) \
          | ({"discovery_note": NOTE_CUT.format(limit=self.cut_after)} if self.cut else {})


@dataclass
class RootError:
    root: str
    kind: str  # missing, permission_denied, not_a_directory, unreadable
    message: str

    def to_dict(self) -> dict:
        return {"root": self.root, "kind": self.kind, "message": self.message}


@dataclass
class Skipped:
    path: str
    reason: str

    def to_dict(self) -> dict:
        return {"path": self.path, "reason": self.reason}


@dataclass
class Discovery:
    projects: list[Project] = field(default_factory=list)
    root_errors: list[RootError] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "projects": [p.to_dict() for p in self.projects],
            "root_errors": [e.to_dict() for e in self.root_errors],
            "skipped": [s.to_dict() for s in self.skipped],
        }


def display_path(path: str | os.PathLike) -> str:
    """`path` with the home folder written as `~`."""
    text = os.fspath(path)
    home = os.path.expanduser("~")
    if text == home:
        return "~"
    if text.startswith(home + os.sep):
        return "~" + text[len(home):]
    return text


def _root_error(label: str, exc: OSError) -> RootError:
    if isinstance(exc, FileNotFoundError):
        return RootError(label, "missing", f"{label} does not exist.")
    if isinstance(exc, NotADirectoryError):
        return RootError(label, "not_a_directory", f"{label} is not a folder.")
    if isinstance(exc, PermissionError):
        return RootError(label, "permission_denied", f"Cannot read {label}: permission denied.")
    return RootError(label, "unreadable", f"Cannot read {label}: read error.")


def manifests_in(folder: str | os.PathLike, max_dirs: int | None = None) -> list[str]:
    """Manifest file names in `folder` and below it, as `walk_manifests` finds them."""
    return walk_manifests(folder, max_dirs)[0]


def walk_manifests(folder: str | os.PathLike, max_dirs: int | None = None) -> tuple[list[str], bool]:
    """Manifest file names in `folder` and in the folders below it, sorted, as paths relative to `folder`.

    Names in `folder` are plain (`package.json`). Names below it carry the folders and use `/`
    (`engine/pyproject.toml`, `crates/core/Cargo.lock`). Raises OSError if `folder` cannot be listed.
    A folder below it that cannot be listed is skipped. The walk lists names only: it opens no file.
    The second value is True if the walk stopped at `max_dirs` folders (MAX_DIRS by default) with folders
    left to visit: the list is then incomplete (#88).
    """
    limit = max_dirs or MAX_DIRS
    found: list[str] = []
    queue: deque[tuple[str, str, int]] = deque([("", os.fspath(folder), 0)])  # (relative path, path, depth)
    visited = 0
    while queue and visited < limit:
        rel, path, depth = queue.popleft()
        try:
            with os.scandir(path) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            if depth == 0:
                raise
            continue
        visited += 1
        for entry in entries:
            try:
                if entry.name in MANIFEST_NAMES and entry.is_file(follow_symlinks=False):
                    found.append(f"{rel}{entry.name}")
                elif (
                    depth < MAX_DEPTH
                    and not entry.name.startswith(".")
                    and entry.name not in SKIP_DIRS
                    and entry.is_dir(follow_symlinks=False)  # A symlink is never followed.
                ):
                    queue.append((f"{rel}{entry.name}/", entry.path, depth + 1))
            except OSError:
                continue
    return sorted(found), bool(queue)


def worktree_main(folder: str) -> str | None:
    """The resolved main repository folder if `folder` is a git worktree, else None.

    A worktree has a `.git` file that reads `gitdir: <repo>/.git/worktrees/<name>`.
    """
    git = os.path.join(folder, ".git")
    if os.path.islink(git) or not os.path.isfile(git):
        return None
    try:
        with open(git, encoding="utf-8", errors="replace") as f:
            first = f.read(4096).splitlines()[0]
    except (OSError, IndexError):
        return None
    if not first.startswith("gitdir:"):
        return None
    gitdir = os.path.realpath(os.path.join(folder, first[len("gitdir:"):].strip()))
    worktrees = os.path.dirname(gitdir)
    dot_git = os.path.dirname(worktrees)
    if os.path.basename(worktrees) != "worktrees" or os.path.basename(dot_git) != ".git":
        return None
    return os.path.dirname(dot_git)


def discover(roots: tuple[str, ...] = PROJECT_ROOTS, inactive=(), max_dirs: int | None = None) -> Discovery:
    """List the projects in `roots`. `inactive` holds resolved paths the owner turned off.

    `max_dirs` is the folder limit for each project (MAX_DIRS by default). Tests set a small one.
    """
    inactive = set(inactive)
    result = Discovery()
    # Resolved root folder -> the root label that owns it. The first label wins.
    real_roots: dict[str, str] = {}
    entries: list[tuple[str, str, bool]] = []  # (root label, name, is symlink)
    for label in roots:
        root = os.path.expanduser(label)
        try:
            with os.scandir(root) as it:
                children = [(label, e.name, e.is_symlink()) for e in it]
        except OSError as exc:
            result.root_errors.append(_root_error(label, exc))
            continue
        real_roots.setdefault(os.path.realpath(root), label)
        entries.extend(children)

    # Group by resolved folder. A symlink to a listed project falls into the same group.
    groups: dict[str, list[str]] = {}
    for label, name, is_link in sorted(entries, key=lambda e: (e[0], e[1])):
        if name.startswith("."):
            continue
        real = os.path.realpath(os.path.join(os.path.expanduser(label), name))
        if not os.path.isdir(real):
            continue
        if os.path.dirname(real) not in real_roots or os.path.basename(real).startswith("."):
            if is_link:
                result.skipped.append(
                    Skipped(display_path(os.path.join(os.path.expanduser(label), name)),
                            "Symlink leads outside the project roots.")
                )
            continue
        groups.setdefault(real, []).append(name)

    for real in sorted(groups):
        main = worktree_main(real)
        if main is not None and main != real and main in groups:
            continue
        label = real_roots[os.path.dirname(real)]
        name = os.path.basename(real)
        path = os.path.join(os.path.expanduser(label), name)
        cut = False
        try:
            (manifests, cut), state = walk_manifests(real, max_dirs), "active"
        except OSError:
            manifests, state = [], "inaccessible"
        if real in inactive:
            state = "inactive"
        result.projects.append(
            Project(name=name, path=path, root=label, manifests=manifests, state=state, real_path=real,
                    cut_after=(max_dirs or MAX_DIRS) if cut else None)
        )

    result.projects.sort(key=lambda p: (p.root, p.name.lower(), p.name))
    return result
