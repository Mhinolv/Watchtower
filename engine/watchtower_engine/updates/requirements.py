"""Plan and run the update of one direct dependency in a requirements-only project (#30).

The item key is `requirements/<package>@<target>|<project path>|<requirements file>`, for example
`requirements/requests@2.32.3|~/Real/script|requirements.txt`.

A requirements-only project has a `requirements.txt` and an existing `.venv`, and no lockfile.
The one command is `<project>/.venv/bin/python -m pip install --only-binary=:all: <name>==<target>`:
- It names one package. The engine never runs `pip install -r`, `pip install --upgrade` for all
  packages or `pip uninstall`, and it never creates an environment.
- `--only-binary=:all:` keeps source builds off: a source build runs build hooks (setup.py or a
  PEP 517 backend). Planning never runs them. If the target has no wheel for this Mac, the plan needs
  the scripts step, and only the second confirmation runs the command with `--no-binary=<name>`,
  which allows a source build of that package only.
- Planning reads `requirements.txt`, the files of the `.venv`, one PyPI metadata page and, if a wheel
  exists, `pip install --dry-run --report -` (wheels only) for the other packages that would change.

The file edit is exact. An exact pin (`requests==2.31.0`) becomes `requests==2.32.3` and nothing else in the
line or file changes: extras, markers and comments stay. A range (`requests>=2.0`) that already allows the
target stays as it is: the plan says `No change`. A range that does not allow the target is refused.
The file is edited only after the environment shows the target.

Refused: `-r` includes, constraint files, hashes (`--hash`), a package index option, editable and URL
requirements for the package, a package that is not named exactly once, a missing `.venv`, a `.venv` with no pip.
Success needs both: the installed package in `.venv` shows the target and `requirements.txt` shows what the plan said.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..discovery import PROJECT_ROOTS, display_path
from ..feeds.homebrew import Fetch, http_fetch
from ..models import _under_roots
from .homebrew import Change, Plan, is_major_change, version_key
from .uv import (_fetch_files, _file_hash, _row, env_python_minor, has_environment,
                 installed_version, normalize, site_packages, spec_allows, wheel_fits)

KIND = "requirements"
KEY_PREFIX = "requirements/"
FILE_NAME = "requirements.txt"
TIMEOUT_SECONDS = 180
MAX_FILE_BYTES = 1024 * 1024

# Refusals: the plan exists, but Update stays off. One sentence for the owner.
REFUSE_KEY = "Watchtower cannot read this update request."
REFUSE_PROJECT = "Watchtower cannot find this requirements.txt in the project folders."
REFUSE_UNREADABLE = "Watchtower cannot read the requirements plan."
REFUSE_INCLUDE = "requirements.txt with -r includes or hashes is not supported."
REFUSE_INDEX = "requirements.txt sets a package index. Watchtower cannot update it."
REFUSE_NO_ENV = "No environment found. Watchtower does not create environments."
REFUSE_NO_PIP = "The environment has no pip. Watchtower does not install tools into it."
REFUSE_NOT_DIRECT = "{name} is not a requirement of this file. Watchtower updates direct requirements only."
REFUSE_MULTIPLE = "requirements.txt names {name} more than once. Watchtower cannot choose one."
REFUSE_SOURCE = "{name} does not come from a package index. Watchtower cannot update editable, git or URL requirements."
REFUSE_MULTILINE = "The line of {name} continues on the next line. Watchtower cannot edit it."
REFUSE_NOT_INSTALLED = "The environment has no {name}. Watchtower does not install new packages."
REFUSE_CURRENT = "The environment already has {name} {version} or newer."
REFUSE_SPEC = "requirements.txt requires \"{requirement}\". That does not allow {target}. Change it there first."
REFUSE_WHEELS = "Watchtower cannot check whether {name} {target} needs a source build."
REFUSE_NO_FILES = "PyPI has no files for {name} {target}."

BUILD_REASON = "{name} needs a source build: no wheel for this platform."
ERROR_FAILED_FILES = "pip changed files that Watchtower did not plan: {files}."
ERROR_ENV = "pip replaced the environment. Watchtower did not plan that."
ERROR_ENV_STILL = "Not verified: the environment still has {version}."
ERROR_ENV_UNKNOWN = "Not verified: Watchtower cannot read the installed version."
ERROR_FILE_STILL = "Not verified: requirements.txt still says {text}."
ERROR_EDIT = "pip installed {name} {target}, but Watchtower could not edit requirements.txt."


def pip_env() -> dict:
    """A small environment. No PIP_* variable of the owner's shell reaches pip."""
    return {
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "HOME": os.environ.get("HOME", ""),
        "LANG": "en_US.UTF-8",
        "NO_COLOR": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_PROGRESS_BAR": "off",
        "PIP_REQUIRE_VIRTUALENV": "1",
    }


# Key


@dataclass
class Request:
    name: str
    target: str
    project_path: str  # As the finding has it, for example ~/Real/script.
    file: str  # Relative to the project path, for example `requirements.txt`.

    @property
    def root(self) -> Path:
        """The project folder: the folder of the requirements file. The `.venv` is in it."""
        return Path(os.path.expanduser(self.project_path)) / Path(self.file).parent

    @property
    def path(self) -> Path:
        return Path(os.path.expanduser(self.project_path)) / self.file


def make_key(name: str, target: str, project_path: str, file: str = FILE_NAME) -> str:
    return f"{KEY_PREFIX}{name}@{target}|{project_path}|{file}"


def parse_key(item_key: str) -> Request | None:
    if not item_key.startswith(KEY_PREFIX):
        return None
    parts = item_key[len(KEY_PREFIX):].split("|")
    if len(parts) != 3:
        return None
    head, project, file = parts
    name, _, target = head.rpartition("@")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not re.fullmatch(r"[0-9A-Za-z.+!_-]+", target):
        return None
    pure = Path(file)
    if pure.is_absolute() or ".." in pure.parts or pure.name != FILE_NAME or not project.strip():
        return None
    return Request(name, target, project, file)


# The file


@dataclass
class Entry:
    """One requirement line of the file."""

    name: str
    extras: str  # `[socks]` or ``.
    spec: str  # `==2.31.0`, `>=8.0,<9` or ``.
    marker: str  # `python_version < "3.10"` or ``.
    first: int  # Index of the first physical line.
    last: int  # Index of the last physical line. Different from `first` for a continued line.
    text: str  # The requirement without marker and comment: `requests==2.31.0`.

    @property
    def evidence(self) -> str:
        return evidence(self.spec)


@dataclass
class ParsedFile:
    lines: list[str]
    entries: list[Entry]
    includes: bool = False  # -r, --requirement, -c, --constraint
    hashes: bool = False  # --hash
    index: bool = False  # --index-url, --extra-index-url, --find-links, --no-index
    sources: set[str] = None  # Normalized names of editable, git and URL requirements.

    def __post_init__(self) -> None:
        if self.sources is None:
            self.sources = set()


_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_INCLUDE = ("-r", "--requirement", "-c", "--constraint")
_INDEX = ("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--no-index")
_PIN = re.compile(r"^==\s*([^\s,*=!<>~;]+)$")


def evidence(spec: str) -> str:
    """The evidence type of a requirement: `Exact pin`, `Range` or `Unpinned`. They stay distinct."""
    spec = spec.strip()
    if not spec:
        return "Unpinned"
    return "Exact pin" if _PIN.match(spec) else "Range"


def pinned_version(spec: str) -> str | None:
    m = _PIN.match(spec.strip())
    return m.group(1) if m else None


def _logical_lines(lines: list[str]) -> list[tuple[int, int, str]]:
    """(first line, last line, text) with `\\` continuations joined and comments removed, as pip reads them."""
    out: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        first, text = i, lines[i].rstrip("\r\n")
        while text.endswith("\\") and i + 1 < len(lines):
            i += 1
            text = text[:-1] + " " + lines[i].rstrip("\r\n")
        text = re.sub(r"(^|\s+)#.*$", "", text).strip()
        if text:
            out.append((first, i, text))
        i += 1
    return out


def parse_file(text: str) -> ParsedFile:
    """Read a requirements file as text only. It runs nothing and opens no other file."""
    lines = text.splitlines(keepends=True)
    parsed = ParsedFile(lines, [])
    for first, last, line in _logical_lines(lines):
        if "--hash" in line:
            parsed.hashes = True
        if line.startswith("-"):
            option = re.split(r"[\s=]", line, maxsplit=1)[0]
            if option in _INCLUDE or line.startswith(("-r", "-c")) and not line.startswith("--"):
                parsed.includes = True
            elif option in _INDEX or line.startswith(("-i", "-f")) and not line.startswith("--"):
                parsed.index = True
            elif option in ("-e", "--editable"):
                egg = re.search(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if egg:
                    parsed.sources.add(normalize(egg.group(1)))
            continue
        requirement, marker = (line.split(";", 1) + [""])[:2] if " @ " not in line else (line, "")
        requirement = re.split(r"\s--\w", requirement, maxsplit=1)[0].strip()
        m = _NAME.match(requirement)
        if not m:
            continue
        name, extras, rest = m.group(1), m.group(2) or "", m.group(3).strip()
        if rest.startswith("@"):
            parsed.sources.add(normalize(name))
            continue
        parsed.entries.append(Entry(name, extras, rest, marker.strip(), first, last, f"{name}{extras}{rest}".strip()))
    return parsed


def entries_for(parsed: ParsedFile, name: str) -> list[Entry]:
    return [e for e in parsed.entries if normalize(e.name) == normalize(name)]


def edit_line(line: str, entry: Entry, target: str) -> str | None:
    """The physical line with the exact pin of `entry` set to `target`. Nothing else changes. None if no pin."""
    old = pinned_version(entry.spec)
    if old is None:
        return None
    pattern = re.compile(rf"^(\s*{re.escape(entry.name)}\s*(?:\[[^\]]*\])?\s*)==(\s*){re.escape(old)}(?=[\s;#\\]|$)",
                         re.IGNORECASE)
    new, count = pattern.subn(lambda m: f"{m.group(1)}=={m.group(2)}{target}", line, count=1)
    return new if count == 1 else None


def planned_text(entry: Entry, target: str) -> str:
    """`requests==2.31.0 → requests==2.32.3`, or `No change` for a range that allows the target."""
    old = pinned_version(entry.spec)
    if old is None:
        return "No change"
    return f"{entry.name}{entry.extras}=={old} → {entry.name}{entry.extras}=={target}"


def read_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def apply_edit(path: Path, name: str, target: str) -> bool:
    """Set the exact pin of `name` in the file to `target`. A range that allows it stays. True if the file is as planned."""
    text = read_file(path)
    if text is None:
        return False
    parsed = parse_file(text)
    found = entries_for(parsed, name)
    if len(found) != 1 or found[0].first != found[0].last:
        return False
    entry = found[0]
    if pinned_version(entry.spec) == target:
        return True
    if pinned_version(entry.spec) is None:
        return spec_allows(entry.spec, target)
    new = edit_line(parsed.lines[entry.first], entry, target)
    if new is None:
        return False
    lines = list(parsed.lines)
    lines[entry.first] = new
    tmp = path.with_name(path.name + ".watchtower-tmp")
    try:
        mode = path.stat().st_mode & 0o777
        tmp.write_text("".join(lines), encoding="utf-8")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False
    return True


# Environment


def python_path(root: Path) -> Path:
    return root / ".venv" / "bin" / "python"


def has_pip(root: Path) -> bool:
    return any((s / "pip").is_dir() for s in site_packages(root / ".venv"))


def block_reason(project_path: str, file: str, roots: tuple[str, ...] = PROJECT_ROOTS) -> str | None:
    """Why `Update…` is off for this requirements file before any plan exists, or None. File checks only."""
    path = Path(os.path.expanduser(project_path)) / file
    if path.name != FILE_NAME or not path.is_file():
        return None
    text = read_file(path)
    if text is not None:
        parsed = parse_file(text)
        if parsed.includes or parsed.hashes:
            return REFUSE_INCLUDE
    if not has_environment(path.parent):
        return REFUSE_NO_ENV
    return None


def path_evidence(project_path: str, file: str, name: str) -> dict | None:
    """The evidence of a finding path in a requirements.txt (#80), or None for other files. Reads text only.

    `declared` is the requirement as written (`requests==2.31.0`), `evidence` is `Exact pin`, `Range` or
    `Unpinned`, `installed` is the version in `.venv` or None (not checked).
    """
    path = Path(os.path.expanduser(project_path)) / file
    if path.name != FILE_NAME:
        return None
    text = read_file(path)
    entries = entries_for(parse_file(text), name) if text is not None else []
    entry = entries[0] if len(entries) == 1 else None
    installed = installed_version(path.parent, name) if has_environment(path.parent) else None
    return {"declared": entry.text if entry else None, "evidence": entry.evidence if entry else None,
            "installed": installed}


# Plan


def build_command(python: str, name_spec: str, name: str, allow_build: bool) -> list[str]:
    command = [python, "-m", "pip", "install", "--only-binary=:all:"]
    if allow_build:
        command.append(f"--no-binary={name}")  # Later flags win: this package only may build from source.
    return command + ["--disable-pip-version-check", "--no-input", name_spec]


def parse_report(text: str, root: Path) -> list[Change]:
    """The packages that `pip install --dry-run --report -` would install, as changes against the environment."""
    data = json.loads(text)
    items = data.get("install") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("no install list")
    changes: list[Change] = []
    for item in items:
        meta = item.get("metadata") if isinstance(item, dict) else None
        name, version = (meta or {}).get("name"), (meta or {}).get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("an entry has no name or version")
        before = installed_version(root, name)
        if before == version:
            continue
        changes.append(Change(name, before, version, "upgrade" if before else "install"))
    return changes


def _change_text(c: Change) -> str:
    return f"{c.name} {c.after} (new)" if c.change == "install" else f"{c.name} {c.before} → {c.after}"


def make_plan(
    item_key: str,
    run: Callable = subprocess.run,
    fetch: Fetch = http_fetch,
    roots: tuple[str, ...] = PROJECT_ROOTS,
    machine: str | None = None,
    mac: tuple[int, int] | None = None,
    system: str | None = None,
    uv: str | None = None,  # Unused. The caller passes the same options as for uv.
) -> Plan:
    """Plan one requirements update. A plan with `refusal` set must not run."""
    req = parse_key(item_key)
    if req is None:
        return Plan(item_key, "?", KIND, "?", None, None, [], refusal=REFUSE_KEY)
    python = str(python_path(req.root))
    plan = Plan(item_key, req.name, KIND, normalize(req.name), None, req.target, [python])
    plan.rows = [_row("Project", display_path(req.root))]

    def refuse(text: str, detail: str | None = None) -> Plan:
        plan.refusal, plan.detail = text, detail
        return plan

    project_dir = Path(os.path.expanduser(req.project_path))
    try:
        inside = _under_roots(str(project_dir.resolve()), roots) and req.path.is_file() \
            and req.path.resolve().is_relative_to(project_dir.resolve())
    except OSError:
        inside = False
    if not inside:
        return refuse(REFUSE_PROJECT)
    text = read_file(req.path)
    if text is None:
        return refuse(REFUSE_UNREADABLE, "requirements.txt is too large or is not UTF-8 text")
    parsed = parse_file(text)
    if parsed.includes or parsed.hashes:
        return refuse(REFUSE_INCLUDE)
    if parsed.index:
        return refuse(REFUSE_INDEX)
    env_ok = has_environment(req.root)
    plan.rows.append(_row("Environment", ".venv (exists)" if env_ok else ".venv (missing)"))
    if not env_ok or not os.access(python, os.X_OK):
        return refuse(REFUSE_NO_ENV)
    if not has_pip(req.root):
        return refuse(REFUSE_NO_PIP)

    if normalize(req.name) in parsed.sources:
        return refuse(REFUSE_SOURCE.format(name=req.name))
    found = entries_for(parsed, req.name)
    if not found:
        return refuse(REFUSE_NOT_DIRECT.format(name=req.name))
    if len(found) > 1:
        return refuse(REFUSE_MULTIPLE.format(name=req.name))
    entry = found[0]
    current = installed_version(req.root, req.name)
    if current is None:
        return refuse(REFUSE_NOT_INSTALLED.format(name=req.name))
    plan.installed_version = current
    if version_key(req.target) <= version_key(current):
        return refuse(REFUSE_CURRENT.format(name=req.name, version=req.target))
    ev = entry.evidence
    plan.rows.append(_row("requirements.txt", planned_text(entry, req.target)))
    plan.rows.append(_row("Evidence", f"{ev} ({entry.spec})" if entry.spec else ev))
    if ev == "Exact pin" and entry.first != entry.last:
        return refuse(REFUSE_MULTILINE.format(name=req.name))
    if ev != "Exact pin" and not spec_allows(entry.spec, req.target):
        return refuse(REFUSE_SPEC.format(requirement=entry.text, target=req.target))
    plan.rows.append(_row("Lockfile", "No lockfile."))
    plan.major_change = is_major_change(current, req.target)

    # The build policy: wheels only, unless the target has no wheel for this Mac.
    files = _fetch_files(req.name, req.target, fetch)
    if files is None:
        return refuse(REFUSE_WHEELS.format(name=req.name, target=req.target))
    if not files:
        return refuse(REFUSE_NO_FILES.format(name=req.name, target=req.target))
    minor = env_python_minor(req.root)
    needs_build = not any(wheel_fits(f["filename"], minor, machine, mac, system) for f in files)
    spec = f"{entry.name}{entry.extras}=={req.target}"
    plan.command = build_command(python, spec, entry.name, allow_build=False)
    others: list[Change] = []
    if needs_build:
        plan.scripts = [BUILD_REASON.format(name=req.name)]
        plan.scripts_message = BUILD_REASON.format(name=req.name)
        plan.scripts_command = build_command(python, spec, entry.name, allow_build=True)
        plan.rows.append(_row("Other packages", "Not known before the build step"))
    else:
        # A wheels-only dry run: pip reads wheel metadata and runs no build hook.
        dry = [python, "-m", "pip", "install", "--dry-run", "--report", "-", "--quiet", "--only-binary=:all:",
               "--disable-pip-version-check", "--no-input", spec]
        try:
            proc = run(dry, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=pip_env(),
                       stdin=subprocess.DEVNULL, cwd=str(req.root))
            if proc.returncode != 0:
                raise ValueError(f"dry run exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
            changes = parse_report(proc.stdout, req.root)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            return refuse(REFUSE_UNREADABLE, str(exc))
        own = [c for c in changes if normalize(c.name) == normalize(req.name)]
        if len(own) != 1 or own[0].after != req.target:
            return refuse(REFUSE_UNREADABLE, f"pip would not install {req.name} {req.target}: {[c.to_dict() for c in own]}")
        others = [c for c in changes if normalize(c.name) != normalize(req.name)]
        plan.rows.append(_row("Other packages",
                              "No other packages change." if not others else
                              (f"{len(others)} package changes" if len(others) == 1 else f"{len(others)} packages change"),
                              [_change_text(c) for c in others] if others else None))
    plan.rows.append(_row("Build", "Disabled (wheels only)"))
    plan.manual_steps = ["Restart the dev server after the update."]
    digest = hashlib.sha256()
    for part in (_file_hash(req.path), _file_hash(req.root / ".venv" / "pyvenv.cfg"), current, req.target,
                 ";".join(_change_text(c) for c in others)):
        digest.update(f"{part}\0".encode())
    plan.fingerprint = digest.hexdigest()[:24]
    return plan


# Run


def stray_changes(before, after) -> list[str]:
    """Files in the project folder, other than requirements.txt, that the run changed, added or removed."""
    names = set(before.files) | set(after.files)
    return sorted(n for n in names if n != FILE_NAME and before.files.get(n) != after.files.get(n))


def backup_file(path: Path, data_dir: Path, attempt_id: int) -> Path | None:
    """Copy requirements.txt to the data folder before the run, so the owner can restore it."""
    from ..store import ensure_private_dir, ensure_private_file
    try:
        folder = ensure_private_dir(ensure_private_dir(ensure_private_dir(Path(data_dir)) / "update-backups")
                                    / f"attempt-{attempt_id}")
        dest = ensure_private_file(folder / FILE_NAME)
        dest.write_bytes(path.read_bytes())
        return folder
    except OSError:
        return None


@dataclass
class Outcome:
    file_ok: bool
    file_text: str  # What the file says about the package now, for the result row.
    installed: str | None
    stray: list[str]
    env_replaced: bool

    def result_rows(self, name: str, target: str) -> list[dict]:
        return [_row("requirements.txt", self.file_text, ok=self.file_ok),
                _row("Installed (.venv)", f"{name} {self.installed or 'unknown'}", ok=self.installed == target)]


def read_outcome(req: Request, before, after, file_ok: bool | None = None) -> Outcome:
    from .uv import env_replaced
    text = read_file(req.path) or ""
    found = entries_for(parse_file(text), req.name) if text else []
    entry = found[0] if len(found) == 1 else None
    if file_ok is None:
        file_ok = entry is not None and (pinned_version(entry.spec) == req.target if pinned_version(entry.spec)
                                         else spec_allows(entry.spec, req.target))
    shown = f"{entry.name}{entry.extras}{entry.spec}" if entry else "no single line"
    return Outcome(file_ok, shown, installed_version(req.root, req.name), stray_changes(before, after),
                   env_replaced(before, after))


def verdict(outcome: Outcome, target: str, name: str, code: int, edit_failed: bool = False) -> tuple[str, str | None]:
    """The log status and the owner-facing error text for one finished run."""
    if code != 0:
        return "failed", None
    if outcome.stray:
        return "not_verified", ERROR_FAILED_FILES.format(files=", ".join(outcome.stray))
    if outcome.env_replaced:
        return "not_verified", ERROR_ENV
    if outcome.installed is None:
        return "not_verified", ERROR_ENV_UNKNOWN
    if outcome.installed != target:
        return "not_verified", ERROR_ENV_STILL.format(version=outcome.installed)
    if edit_failed:
        return "not_verified", ERROR_EDIT.format(name=name, target=target)
    if not outcome.file_ok:
        return "not_verified", ERROR_FILE_STILL.format(text=outcome.file_text)
    return "verified", None


def command_to_run(plan: Plan, confirm_scripts: bool) -> list[str]:
    if plan.scripts and confirm_scripts and plan.scripts_command:
        return list(plan.scripts_command)
    return list(plan.command)
