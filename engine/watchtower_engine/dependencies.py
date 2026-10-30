"""The direct dependencies of one project, for the Projects `Dependencies` table (#81).

One section for each manifest that an update adapter supports: `requirements.txt` (#30) and `Cargo.toml` (#15).
A manifest is keyed by its path relative to the project folder, so a manifest in a folder below the project
(`capture/Cargo.toml`, #85) has its own section. Reading is file-only: requirements.txt and Cargo.toml and Cargo.lock
are read as text, the `.venv` is read as dist-info folders. Nothing is built or run. The only network calls are the
registry lookups for the latest version (`feeds/registries.py`: the package name only).

A row says what is declared (`Exact pin`, `Range`, kept apart), what is installed (the `.venv` version, or the
`Cargo.lock` version), the latest version, a status, and the key of the update plan for the latest version. A row
that the adapter would refuse has no key and carries the refusal text, the same text that the plan gives.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterable

from .discovery import Project, display_path
from .feeds import registries
from .feeds.homebrew import Fetch, http_fetch
from .inventory.homebrew import version_key
from .models import utc_now
from .updates import cargo as cargo_updates
from .updates import requirements as req_updates
from .updates import uv as uv_updates

SUPPORTED = {"requirements.txt": "requirements", "Cargo.toml": "cargo"}
STATUS_RANK = {"vulnerable": 0, "update_available": 1}


def _status(installed: str | None, latest: str | None) -> str:
    if not installed or not latest:
        return "unknown"
    return "update_available" if version_key(latest) > version_key(installed) else "up_to_date"


def _finding_for(findings, ecosystem: str, name: str, project_display: str):
    """The worst open finding of `name` in this project. `findings` come sorted, worst first."""
    for f in findings:
        if (f.status == "open" and f.ecosystem == ecosystem and registries.normalize(f.package) == registries.normalize(name)
                and any(p.project_path == project_display for p in f.paths)):
            return f
    return None


def _requirements_rows(base: Path, manifest: str) -> tuple[list[dict], str | None]:
    """Raw rows (no latest yet) and the section refusal for one requirements.txt."""
    path = base / manifest
    text = req_updates.read_file(path)
    if text is None:
        return [], req_updates.REFUSE_UNREADABLE
    parsed = req_updates.parse_file(text)
    root = path.parent
    refusal = None
    if parsed.includes or parsed.hashes:
        refusal = req_updates.REFUSE_INCLUDE
    elif parsed.index:
        refusal = req_updates.REFUSE_INDEX
    elif not uv_updates.has_environment(root):
        refusal = req_updates.REFUSE_NO_ENV
    elif not req_updates.has_pip(root):
        refusal = req_updates.REFUSE_NO_PIP
    counts: dict[str, int] = {}
    for e in parsed.entries:
        counts[registries.normalize(e.name)] = counts.get(registries.normalize(e.name), 0) + 1
    rows = []
    for e in parsed.entries:
        installed = uv_updates.installed_version(root, e.name) if uv_updates.has_environment(root) else None
        row_refusal = None
        if counts[registries.normalize(e.name)] > 1:
            row_refusal = req_updates.REFUSE_MULTIPLE.format(name=e.name)
        elif e.evidence == "Exact pin" and e.first != e.last:
            row_refusal = req_updates.REFUSE_MULTILINE.format(name=e.name)
        rows.append({"package": e.name, "declared": e.spec, "evidence": e.evidence.lower().replace(" ", "_"),
                     "installed": installed, "installed_label": ".venv", "table": None, "_entry": e,
                     "_refusal": row_refusal})
    return rows, refusal


def _cargo_rows(base: Path, manifest: str) -> tuple[list[dict], str | None]:
    """Raw rows and the section refusal for one Cargo.toml: a workspace, or a Cargo.lock that does not match."""
    rows, note = cargo_updates.dependencies(base / Path(manifest).parent)
    out = []
    for r in rows or []:
        refusal = None if r["evidence"] in ("exact_pin", "range") else cargo_updates.REFUSE_SOURCE
        out.append({"package": r["package"], "declared": r["declared"], "evidence": r["evidence"], "installed": r["locked"],
                    "installed_label": "locked", "table": r["table"], "_refusal": refusal})
    return out, note


def _update(row: dict, kind: str, manifest: str, project_display: str, section_refusal: str | None) -> None:
    """Set `update_key` or `update_refusal` for a row that has a newer version. The texts are the plan's texts."""
    row["update_key"] = row["update_refusal"] = None
    refusal = section_refusal or row.pop("_refusal", None)
    spec, latest = row["declared"], row["latest"]
    if refusal is None and kind == "requirements" and row["evidence"] == "range" and not uv_updates.spec_allows(spec, latest):
        refusal = req_updates.REFUSE_SPEC.format(requirement=row["_entry"].text, target=latest)
    if refusal is None and kind == "cargo" and not cargo_updates.spec_allows(spec, latest):
        refusal = cargo_updates.REFUSE_SPEC.format(name=row["package"], requirement=spec, target=latest)
    if refusal:
        row["update_refusal"] = refusal
    elif kind == "requirements":
        row["update_key"] = req_updates.make_key(row["package"], latest, project_display, manifest)
    else:
        folder = Path(manifest).parent
        row["update_key"] = cargo_updates.make_key(row["package"], latest, project_display,
                                                   "Cargo.lock" if folder == Path(".") else f"{folder}/Cargo.lock")


def _finish(rows: list[dict], registry: str, latest: dict, findings, project_display: str, manifest: str,
            section_refusal: str | None, kind: str) -> list[dict]:
    for row in rows:
        found = latest.get(row["package"])
        row["latest"], row["latest_error"] = (found.version, found.error) if found else (None, None)
        row["status"] = _status(row["installed"], row["latest"])
        finding = _finding_for(findings, registry, row["package"], project_display)
        row["finding_id"], row["severity"] = (finding.id, finding.severity) if finding else (None, None)
        if finding:
            row["status"] = "vulnerable"
        if row["latest"] and row["installed"] and version_key(row["latest"]) > version_key(row["installed"]):
            _update(row, kind, manifest, project_display, section_refusal)
        else:
            row["update_key"] = row["update_refusal"] = None  # Up to date, or not known: no update.
    for row in rows:
        row.pop("_refusal", None)
        row.pop("_entry", None)
    rows.sort(key=lambda r: (STATUS_RANK.get(r["status"], 2), r["package"].lower()))
    return rows


def project_dependencies(project: Project, findings: Iterable, data_dir: Path, fetch: Fetch = http_fetch,
                         now: Callable[[], str] = utc_now) -> dict:
    """The `Dependencies` sections of one project. Never raises for a failed registry request."""
    base = Path(project.real_path or os.path.expanduser(project.path))
    shown = display_path(project.path)
    findings = list(findings)
    manifests = sorted(m for m in project.manifests if Path(m).name in SUPPORTED)
    raw = []
    for manifest in manifests:
        kind = SUPPORTED[Path(manifest).name]
        rows, refusal = _requirements_rows(base, manifest) if kind == "requirements" else _cargo_rows(base, manifest)
        raw.append((manifest, kind, rows, refusal))
    names = {registries.PYPI: [], registries.CRATES: []}
    for manifest, kind, rows, _ in raw:
        # Only packages that come from the registry are looked up: not git, path or workspace members.
        names[registries.PYPI if kind == "requirements" else registries.CRATES] += [
            r["package"] for r in rows if r["evidence"] in ("exact_pin", "range", "unpinned")]
    looked = {reg: registries.lookup(reg, pkgs, data_dir, fetch, now) for reg, pkgs in names.items() if pkgs}
    sections = []
    for manifest, kind, rows, refusal in raw:
        registry = registries.PYPI if kind == "requirements" else registries.CRATES
        latest = looked.get(registry, {})
        rows = _finish(rows, registry, latest, findings, shown, manifest, refusal, kind)
        used = [latest[r["package"]] for r in rows if r["package"] in latest]
        times = [u.fetched_at for u in used if u.fetched_at]
        sections.append({
            "manifest": manifest, "kind": kind, "rows": rows, "refusal": refusal,
            "latest_source": {"registry": registry, "retrieved_at": min(times) if times else None,
                              "error": next((u.error for u in used if u.error), None)},
        })
    return {"schema_version": 1, "project": shown, "supported": bool(manifests), "sections": sections}
