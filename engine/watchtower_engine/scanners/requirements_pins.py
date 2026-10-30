"""Exact pins of `requirements.txt` in requirements-only projects, for the offline OSV scan (#80).

A requirements-only folder has a `requirements.txt` and no lockfile. The engine reads the file as text
(the #30 parser) and keeps only exact pins (`requests==2.31.0`). It writes them as `name==version`
lines to a private file in the data folder, and OSV-Scanner reads that file with `--offline`.
So only the package name, the ecosystem and the version reach the local OSV database:
- A range (`flask>=2.0,<3`) or an unpinned line is evidence, never a version. It makes no finding.
- Markers, extras, comments and options stay out of the scanned file.
- A file with `-r`/`-c` includes or `--hash` lines is skipped with an explicit note: the scanner would
  follow includes that Watchtower does not check, and #30 cannot update such a file.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..store import ensure_private_dir, ensure_private_file
from ..updates.requirements import FILE_NAME, parse_file, pinned_version, read_file

ECOSYSTEM = "PyPI"
NOTE_SKIPPED = "-r includes or hashes are not supported"
NOTE_UNREADABLE = "cannot be read"
TEXT_SKIPPED = "{count} requirements {projects} skipped."
PINS_FOLDER = "requirements-pins"


@dataclass
class PinsFile:
    pins: list[tuple[str, str]] = field(default_factory=list)  # (name, version) of each exact pin
    other_lines: int = 0  # Ranges and unpinned lines: evidence only.
    skipped: str | None = None  # Why the file is not scanned.


def read(path: Path) -> PinsFile:
    """The exact pins of one requirements file. Reads text only. Runs nothing, opens no other file."""
    text = read_file(path)
    if text is None:
        return PinsFile(skipped=NOTE_UNREADABLE)
    parsed = parse_file(text)
    if parsed.includes or parsed.hashes:
        return PinsFile(skipped=NOTE_SKIPPED)
    out = PinsFile()
    for entry in parsed.entries:
        version = pinned_version(entry.spec)
        if version:
            out.pins.append((entry.name, version))
        else:
            out.other_lines += 1
    return out


def requirements_only(rel: str, manifests: list[str], lockfile_names: set[str]) -> bool:
    """True if `rel` is a requirements.txt and its folder has no lockfile."""
    if os.path.basename(rel) != FILE_NAME:
        return False
    folder = os.path.dirname(rel)
    return not any(os.path.dirname(m) == folder and os.path.basename(m) in lockfile_names for m in manifests)


def write_pins(pins: list[tuple[str, str]], data_dir: Path, index: int) -> Path:
    """Write `name==version` lines to a private file for the scanner. Nothing else goes in it."""
    root = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "osv") / PINS_FOLDER)
    folder = ensure_private_dir(root / str(index))
    path = ensure_private_file(folder / FILE_NAME)
    path.write_text("".join(f"{name}=={version}\n" for name, version in pins))
    return path


def clear_pins(data_dir: Path) -> None:
    shutil.rmtree(Path(data_dir) / "osv" / PINS_FOLDER, ignore_errors=True)


def skipped_text(count: int) -> str:
    return TEXT_SKIPPED.format(count=count, projects="project" if count == 1 else "projects")


def summaries(project_dir: Path, manifests: list[str], lockfile_names: set[str]) -> list[dict]:
    """Rows for the Projects detail: `requirements.txt: 12 exact pins scanned` and the notes."""
    rows = []
    for rel in sorted(manifests):
        if requirements_only(rel, manifests, lockfile_names):
            found = read(project_dir / rel)
            rows.append({"file": rel, "pins": len(found.pins), "other_lines": found.other_lines,
                         "skipped": found.skipped})
    return rows
