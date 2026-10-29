"""Plan and run one Homebrew formula or cask update.

The plan reads `brew info --json=v2` and `brew upgrade --dry-run` for one named package.
Both run with HOMEBREW_NO_AUTO_UPDATE=1, so nothing changes before the owner confirms,
and the real upgrade uses the same Homebrew data as the plan.
The engine never runs `brew upgrade` without a name, `brew update`, or `--greedy`.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from ..inventory.homebrew import BREW_ENV, BREW_TIMEOUT_SECONDS, CORE_TAPS, _current_keg, version_key

UPGRADE_ENV = {**BREW_ENV, "HOMEBREW_NO_INSTALL_CLEANUP": "1"}

# Refusals: the plan exists, but the Update button stays off. One sentence for the owner.
REFUSE_PINNED = "Pinned with brew pin. Watchtower does not update pinned items."
REFUSE_TAP = "Watchtower cannot check tap {tap}."
REFUSE_NOT_INSTALLED = "Homebrew does not list {name} as installed."
REFUSE_CURRENT = "Homebrew has no newer version of {name}."
REFUSE_BEHIND = "Homebrew's local data is behind the catalog. Run brew update in Terminal, then Refresh."
REFUSE_UNREADABLE = "Watchtower cannot read the Homebrew plan."
REFUSE_AUTO_UPDATES = "This app updates itself. Update it from the app."

SCRIPT_BUILD = "it builds from source, because no bottle fits this Mac"
SCRIPT_POST_INSTALL = "the formula runs a post-install step"
SCRIPT_PKG = "the cask runs a package installer"
SCRIPT_INSTALLER = "the cask runs an installer script"

MACOS_NAMES = {26: "tahoe", 15: "sequoia", 14: "sonoma", 13: "ventura", 12: "monterey"}


@dataclass
class Change:
    name: str
    before: str | None
    after: str | None
    change: str  # upgrade, install

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Plan:
    item_key: str
    name: str
    kind: str  # formula, cask
    full_name: str
    installed_version: str | None
    target_version: str | None
    command: list[str]
    also_changes: list[Change] = field(default_factory=list)
    major_change: bool = False
    scripts: list[str] = field(default_factory=list)  # Why the update needs scripts. Empty: disabled.
    manual_steps: list[str] = field(default_factory=list)
    refusal: str | None = None
    detail: str | None = None

    @property
    def id(self) -> str:
        """Changes when anything that the owner confirms changes."""
        keys = {k: v for k, v in self.to_dict(with_id=False).items() if k not in ("detail",)}
        return hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()[:16]

    @property
    def command_text(self) -> str:
        return " ".join(self.command)

    def to_dict(self, with_id: bool = True) -> dict:
        out = {
            "item_key": self.item_key, "name": self.name, "kind": self.kind, "full_name": self.full_name,
            "installed_version": self.installed_version, "target_version": self.target_version,
            "command": list(self.command), "command_text": self.command_text,
            "also_changes": [c.to_dict() for c in self.also_changes], "major_change": self.major_change,
            "scripts": list(self.scripts), "manual_steps": list(self.manual_steps),
            "refusal": self.refusal, "detail": self.detail,
        }
        if with_id:
            out["id"] = self.id
        return out


# Versions


def major(version: str | None) -> int | None:
    m = re.match(r"\D*(\d+)", version or "")
    return int(m.group(1)) if m else None


def is_major_change(before: str | None, after: str | None) -> bool:
    a, b = major(before), major(after)
    return a is not None and b is not None and b > a


# Brew calls


def _brew(brew: str, args: list[str], run: Callable) -> subprocess.CompletedProcess:
    return run([brew, *args], capture_output=True, text=True, timeout=BREW_TIMEOUT_SECONDS,
               env={**os.environ, **UPGRADE_ENV}, stdin=subprocess.DEVNULL)


def read_one(brew: str, kind: str, name: str, run: Callable = subprocess.run) -> dict | None:
    """The `brew info --json=v2` entry for one installed formula or cask, or None."""
    proc = _brew(brew, ["info", "--json=v2", f"--{kind}", name], run)
    if proc.returncode != 0:
        return None
    data = json.loads(proc.stdout)
    entries = data.get("formulae" if kind == "formula" else "casks") or []
    return entries[0] if entries else None


def installed_version(kind: str, entry: dict | None) -> str | None:
    if entry is None:
        return None
    return _current_keg(entry) if kind == "formula" else entry.get("installed")


def candidate_version(kind: str, entry: dict) -> str | None:
    if kind == "cask":
        return entry.get("version")
    stable = (entry.get("versions") or {}).get("stable")
    if not stable:
        return None
    return stable + (f"_{entry['revision']}" if entry.get("revision") else "")


_CHANGE_RE = re.compile(r"^(\S+) (\S+) -> (\S+)$")


def parse_dry_run(text: str) -> list[Change]:
    """Read `brew upgrade --dry-run`. Raises ValueError on a line it does not know."""
    changes: list[Change] = []
    mode = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "HOMEBREW_" in line or line.startswith(("Warning:", "Note:")):
            continue
        if line.startswith("==>"):
            mode = "install" if "install" in line.lower() else "upgrade"
            continue
        m = _CHANGE_RE.match(line)
        if m:
            changes.append(Change(m.group(1), m.group(2), m.group(3), "upgrade"))
            continue
        if mode == "install":
            for part in line.split(","):
                words = part.split()
                if words:
                    changes.append(Change(words[0], None, words[1] if len(words) > 1 else None, "install"))
            continue
        raise ValueError(f"unknown dry-run line: {line!r}")
    return changes


def _macos_major() -> int | None:
    release = platform.mac_ver()[0]
    return int(release.split(".")[0]) if release else None


def needs_build(entry: dict, machine: str | None = None, macos: int | None = None) -> bool:
    """True if no bottle fits this Mac. Homebrew uses a bottle for the same or an older macOS."""
    files = ((entry.get("bottle") or {}).get("stable") or {}).get("files") or {}
    if "all" in files:
        return False
    machine = machine or platform.machine()
    macos = macos or _macos_major()
    prefix = "arm64_" if machine == "arm64" else ""
    fits = {f"{prefix}{name}" for v, name in MACOS_NAMES.items() if macos is None or v <= macos}
    return not (fits & set(files))


def script_reasons(kind: str, entry: dict, machine: str | None = None, macos: int | None = None) -> list[str]:
    reasons = []
    if kind == "formula":
        if needs_build(entry, machine, macos):
            reasons.append(SCRIPT_BUILD)
        if entry.get("post_install_defined"):
            reasons.append(SCRIPT_POST_INSTALL)
    else:
        for artifact in entry.get("artifacts") or []:
            if isinstance(artifact, dict) and "pkg" in artifact and SCRIPT_PKG not in reasons:
                reasons.append(SCRIPT_PKG)
            if isinstance(artifact, dict) and "installer" in artifact and SCRIPT_INSTALLER not in reasons:
                reasons.append(SCRIPT_INSTALLER)
    return reasons


def manual_steps(kind: str, name: str, entry: dict) -> list[str]:
    if kind == "cask":
        app = (entry.get("name") or [name])[0]
        return [f"Quit and reopen {app} if it is open."]
    if entry.get("service"):
        return [f"Restart the {name} service: brew services restart {name}."]
    return []


# Plan


def make_plan(item_key: str, catalog_latest: str | None, brew: str, run: Callable = subprocess.run,
              machine: str | None = None, macos: int | None = None) -> Plan:
    """Plan one update. A plan with `refusal` set must not run."""
    kind, _, full_name = item_key.partition("/")[2].partition(":")
    name = full_name.rsplit("/", 1)[-1]
    command = [brew, "upgrade", f"--{kind}", full_name]
    plan = Plan(item_key, name, kind, full_name, None, None, command)
    if kind not in CORE_TAPS:
        plan.refusal = REFUSE_UNREADABLE
        return plan
    try:
        entry = read_one(brew, kind, full_name, run)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        plan.refusal, plan.detail = REFUSE_UNREADABLE, repr(exc)
        return plan
    current = installed_version(kind, entry)
    if entry is None or current is None:
        plan.refusal = REFUSE_NOT_INSTALLED.format(name=name)
        return plan
    plan.installed_version = current
    plan.target_version = candidate_version(kind, entry)
    plan.manual_steps = manual_steps(kind, name, entry)
    tap = entry.get("tap")
    if tap != CORE_TAPS[kind]:
        plan.refusal = REFUSE_TAP.format(tap=tap or "unknown")
        return plan
    if kind == "formula" and entry.get("pinned"):
        plan.refusal = REFUSE_PINNED
        return plan
    if kind == "cask" and entry.get("auto_updates"):
        plan.refusal = REFUSE_AUTO_UPDATES
        return plan
    target = plan.target_version
    if not target or version_key(target) <= version_key(current):
        plan.refusal = REFUSE_CURRENT.format(name=name)
        if catalog_latest and target and version_key(catalog_latest) > version_key(target):
            plan.refusal = REFUSE_BEHIND
        return plan
    if catalog_latest and version_key(catalog_latest) > version_key(target):
        plan.refusal = REFUSE_BEHIND
        return plan
    plan.major_change = is_major_change(current, target)
    plan.scripts = script_reasons(kind, entry, machine, macos)
    proc = _brew(brew, ["upgrade", "--dry-run", f"--{kind}", full_name], run)
    try:
        if proc.returncode != 0:
            raise ValueError(f"dry run exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        changes = parse_dry_run(proc.stdout + "\n" + proc.stderr)
    except ValueError as exc:
        plan.refusal, plan.detail = REFUSE_UNREADABLE, str(exc)
        return plan
    own = [c for c in changes if c.name in (name, full_name)]
    if own and own[0].after != target:
        plan.refusal, plan.detail = REFUSE_UNREADABLE, f"dry run target {own[0].after}, info target {target}"
        return plan
    plan.also_changes = [c for c in changes if c.name not in (name, full_name)]
    return plan


# Run

# run_streaming(args, env, on_line) -> exit code. Tests pass a fake.
RunStreaming = Callable[[list[str], dict, Callable[[str], None]], int]


def run_streaming(args: list[str], env: dict, on_line: Callable[[str], None], poll: float = 0.2) -> int:
    """Run `args`, report each output line (stdout and stderr together), return the exit code.

    The child writes to a private temp file (0600) in its own session, not to a pipe.
    If this engine stops early, the update goes on to its end: an update cut short can
    break an installation. The log then records `interrupted`.
    """
    fd, path = tempfile.mkstemp(prefix="watchtower-update-", suffix=".log")
    try:
        with os.fdopen(fd, "w") as out, open(path, "r", errors="replace") as reader:
            proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    env=env, start_new_session=True)
            pending = ""
            while True:
                done = proc.poll() is not None
                pending += reader.read()
                *lines, pending = pending.split("\n")
                for line in lines:
                    on_line(line)
                if done:
                    break
                time.sleep(poll)
            if pending:
                on_line(pending)
            return proc.returncode
    finally:
        os.unlink(path)


def upgrade(plan: Plan, on_line: Callable[[str], None], runner: RunStreaming = run_streaming) -> int:
    return runner(list(plan.command), {**os.environ, **UPGRADE_ENV}, on_line)
