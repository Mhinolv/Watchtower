"""The owner's project choices.

Every project is active until the owner turns it off. The inactive choices live in
`projects.json` in the data folder (mode 0600). Each choice is keyed by the resolved
folder path, so it survives rediscovery, a rename of a symlink and a missing folder.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .discovery import PROJECT_ROOTS, Discovery, Project, discover, display_path
from .models import CoverageRecord
from .store import FILE_MODE, StoreError, default_data_dir, ensure_private_dir

FILE_NAME = "projects.json"
FILE_VERSION = 1


class ScopeError(StoreError):
    """The project choices cannot be read or changed. The message is one short sentence."""


class Scope:
    """Read and write the inactive project choices."""

    def __init__(self, data_dir: str | os.PathLike | None = None):
        self.data_dir = Path(data_dir) if data_dir else default_data_dir()
        self.path = self.data_dir / FILE_NAME

    def inactive(self) -> frozenset[str]:
        """Resolved paths of the inactive projects. A missing file means none."""
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return frozenset()
        except OSError as exc:
            raise ScopeError("Watchtower cannot read the project choices.", repr(exc)) from exc
        try:
            data = json.loads(text)
            version = data.get("version", 1)
            paths = data.get("inactive", [])
            if not isinstance(version, int) or not isinstance(paths, list):
                raise ValueError("unexpected shape")
        except (ValueError, AttributeError) as exc:
            # Do not reset the choices. The owner fixes or removes the file.
            raise ScopeError("The project choices file is not valid.", repr(exc)) from exc
        if version > FILE_VERSION:
            raise ScopeError(
                "A newer Watchtower wrote this data.",
                f"{FILE_NAME} version {version} is newer than {FILE_VERSION}.",
            )
        return frozenset(p for p in paths if isinstance(p, str))

    def set_active(self, real_path: str, active: bool) -> None:
        """Save one choice. Other choices stay as they are."""
        paths = set(self.inactive())
        if active:
            paths.discard(real_path)
        else:
            paths.add(real_path)
        self._write(paths)

    def _write(self, paths: set[str]) -> None:
        ensure_private_dir(self.data_dir)
        payload = json.dumps({"version": FILE_VERSION, "inactive": sorted(paths)}, indent=2) + "\n"
        # Write a private temp file, then replace. A failed write keeps the old choices.
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, prefix=FILE_NAME, suffix=".tmp")
        try:
            os.fchmod(fd, FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


SOURCE = "projects"
LABEL = "Projects"
# The error field is one short line (owner_error). The detail has each project path and the limit.
ERROR_CUT = "Discovery stopped early in {names}. Deeper manifests are not listed."


def discovery_coverage(found: Discovery) -> CoverageRecord:
    """The Projects coverage (#88): `partial` if the walk of an active project stopped at the folder limit."""
    cut = [p for p in found.projects if p.cut and p.state == "active"]
    if not cut:
        return CoverageRecord(SOURCE, LABEL, "complete")
    detail = "\n".join(f"{display_path(p.path)}: stopped after {p.cut_after} folders" for p in cut)
    return CoverageRecord(SOURCE, LABEL, "partial", detail=detail,
                          error=ERROR_CUT.format(names=", ".join(p.name for p in cut)))


def list_projects(data_dir=None, roots: tuple[str, ...] = PROJECT_ROOTS) -> Discovery:
    """Discover the projects and apply the owner's inactive choices."""
    return with_requirements(with_dependencies(discover(roots, inactive=Scope(data_dir).inactive())))


def with_requirements(found: Discovery) -> Discovery:
    """Add the requirements.txt summary to each requirements-only folder (#80). Reads text only."""
    from .scanners import osv, requirements_pins  # Not at the top: the scanner modules import the store.

    names = set(osv.SUPPORTED) | set(osv.NOT_SUPPORTED)
    for project in found.projects:
        rows = requirements_pins.summaries(Path(project.real_path or os.path.expanduser(project.path)),
                                           project.manifests, names)
        project.requirements = rows or None
    return found


def with_dependencies(found: Discovery) -> Discovery:
    """Add the `Dependencies` table to each Cargo project (#15). Reads Cargo.toml and Cargo.lock only."""
    from .updates import cargo  # Not at the top: the update modules import the store.

    for project in found.projects:
        manifests = sorted(m for m in project.manifests if Path(m).name == "Cargo.toml")
        if not manifests:
            continue
        base = Path(project.real_path or os.path.expanduser(project.path))
        rows, notes, workspaces = [], [], []
        for manifest in manifests:
            folder = Path(manifest).parent
            if any(folder.is_relative_to(w) for w in workspaces):
                continue  # A member of a workspace that is already reported.
            found_rows, note = cargo.dependencies(base / folder)
            if note == cargo.REFUSE_WORKSPACE:
                workspaces.append(folder)
            folder = str(folder)
            rows += [{**r, "manifest": manifest} for r in found_rows or []]
            if note:
                notes.append(note if folder == "." else f"{folder}: {note}")
        project.dependencies = rows if rows or not notes else None
        project.dependency_note = " ".join(notes) or None
    return found


def set_project_active(
    path: str, active: bool, data_dir=None, roots: tuple[str, ...] = PROJECT_ROOTS
) -> Project:
    """Mark the project at `path` active or inactive. `path` is the project path or a symlink to it."""
    scope = Scope(data_dir)
    projects = discover(roots, inactive=scope.inactive()).projects
    real = os.path.realpath(os.path.expanduser(path))
    match = next((p for p in projects if p.real_path == real), None)
    if match is None:
        raise ScopeError("That folder is not a project in the project roots.")
    scope.set_active(match.real_path, active)
    return next(p for p in discover(roots, inactive=scope.inactive()).projects if p.real_path == real)
