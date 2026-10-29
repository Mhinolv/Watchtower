"""Plan, run and verify one direct npm dependency update in one project (#10).

Owner rules: one package only, `--ignore-scripts` on the first confirm, install scripts or a
build only after a separate confirm that names the reason, no `npm audit fix`, no major version
without its own confirm, verify from the lockfile and from node_modules, keep the project as it
was if the install fails.

The plan resolves the new lockfile in a temp copy of package.json and package-lock.json
(`npm install --package-lock-only`), so planning never changes the project or node_modules.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from ..discovery import display_path
from ..feeds import npm_registry
from .homebrew import Change, Plan, RunStreaming, is_major_change, run_streaming

NPM_PATHS = ("/opt/homebrew/bin/npm", "/usr/local/bin/npm")
NPM_TIMEOUT_SECONDS = 300
SAFE_FLAGS = ["--ignore-scripts", "--no-audit", "--no-fund"]
SECTIONS = {"dependencies": "--save-prod", "devDependencies": "--save-dev", "optionalDependencies": "--save-optional"}

REFUSE_WORKSPACE = "Watchtower cannot update workspace projects yet."
REFUSE_GIT = "Watchtower cannot update git dependencies."
REFUSE_SCRIPTS_UNKNOWN = "This package needs scripts that Watchtower cannot check."
REFUSE_NO_PROJECT = "Watchtower cannot find package.json and package-lock.json in this project."
REFUSE_LOCK_VERSION = "Watchtower needs package-lock.json version 2 or 3."
REFUSE_NOT_DIRECT = "Watchtower updates direct dependencies only. {name} comes in through another package."
REFUSE_SPEC = "Watchtower cannot update the version range {spec}."
REFUSE_OTHER_SOURCE = "Watchtower updates packages from the public npm registry only."
REFUSE_CURRENT = "npm has no newer version of {name}."
REFUSE_NO_NPM = "npm is not installed."
REFUSE_REGISTRY = "The npm registry did not answer."
REFUSE_RESOLVE = "npm could not plan this update."

ERROR_SCRIPTS_FAILED = "The install scripts failed (exit code {code})."
NOT_VERIFIED_INSTALLED = "Not verified: the installed package is still {version}."
NOT_VERIFIED_LOCK = "Not verified: the lockfile still has {name} {version}."


# Key: npm|<project folder with package-lock.json>|<package>|<fixed version or ->


def make_key(project_dir: str, package: str, fixed_in: str | None = None) -> str:
    return f"npm|{project_dir}|{package}|{fixed_in or '-'}"


def parse_key(key: str) -> tuple[Path, str, str | None]:
    _, folder, package, fixed = key.split("|", 3)
    return Path(os.path.expanduser(folder)), package, None if fixed == "-" else fixed


# Versions


def semver(version: str) -> tuple:
    """(major, minor, patch, is_release, prerelease) for ordering. Build metadata is ignored."""
    main, _, pre = version.split("+", 1)[0].partition("-")
    nums = [int(n) if n.isdigit() else 0 for n in (main.split(".") + ["0", "0"])[:3]]
    return (*nums, not pre, pre)


def is_release(version: str) -> bool:
    return "-" not in version.split("+", 1)[0]


def choose_target(current: str, published: list[str], latest: str | None, fixed_in: str | None) -> str | None:
    """The newest release in the current major that fixes the advisory, else `latest`."""
    releases = [v for v in published if is_release(v) and re.match(r"^\d+\.\d+\.\d+", v)]
    same_major = [v for v in releases if semver(v)[0] == semver(current)[0]]
    best = max(same_major, key=semver, default=None)
    if best and semver(best) > semver(current) and (fixed_in is None or semver(best) >= semver(fixed_in)):
        return best
    if latest and is_release(latest) and semver(latest) > semver(current):
        return latest
    return None


_SIMPLE_SPEC = re.compile(r"^(\^|~|=)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def new_spec(spec: str, target: str) -> str | None:
    """Keep the range style: `^4.17.1` -> `^4.19.2`, `4.17.1` -> `4.19.2`. None for complex ranges."""
    m = _SIMPLE_SPEC.match(spec.strip())
    return f"{m.group(1) or ''}{target}" if m else None


def _spec_problem(spec: str) -> str | None:
    s = spec.strip()
    if s.startswith(("git", "github:", "gitlab:", "bitbucket:")) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
        return REFUSE_GIT
    if s.startswith(("file:", "link:", "http:", "https:", "npm:", "workspace:")):
        return REFUSE_OTHER_SOURCE
    return None


# Project files


def _read_json(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return data


def _digest(*paths: Path) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(p.read_bytes() if p.exists() else b"")
    return h.hexdigest()[:16]


def lock_changes(old: dict, new: dict, skip: str) -> list[Change]:
    """Every package path in the lockfile that changes, except the target itself."""
    before, after = old.get("packages") or {}, new.get("packages") or {}
    out = []
    for key in sorted(set(before) | set(after)):
        if not key or key == f"node_modules/{skip}":
            continue
        a, b = (before.get(key) or {}).get("version"), (after.get(key) or {}).get("version")
        if a == b:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        out.append(Change(name, a, b, "install" if a is None else "remove" if b is None else "upgrade"))
    return out


def find_npm() -> str | None:
    return shutil.which("npm") or next((p for p in NPM_PATHS if os.access(p, os.X_OK)), None)


def npm_env(npm: str) -> dict:
    """npm needs node next to it on PATH."""
    path = os.pathsep.join([os.path.dirname(npm), "/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"])
    return {**os.environ, "PATH": path, "NO_UPDATE_NOTIFIER": "1", "npm_config_update_notifier": "false"}


# Plan


def make_plan(key: str, npm: str | None = None, run: Callable = subprocess.run,
              get: npm_registry.GetJson = npm_registry.get_json) -> Plan:
    folder, name, fixed_in = parse_key(key)
    manifest, lockfile = folder / "package.json", folder / "package-lock.json"
    npm = npm or find_npm() or "npm"
    plan = Plan(key, name, "npm", name, None, None, [npm, "install", name],
                changes_title="Other packages", scripts_off_text="Disabled (--ignore-scripts)")
    plan.rows = [{"label": "Project", "value": display_path(folder)}]

    def refuse(reason: str, detail: str | None = None) -> Plan:
        plan.refusal, plan.detail = reason, detail
        return plan

    if not (manifest.is_file() and lockfile.is_file()):
        return refuse(REFUSE_NO_PROJECT)
    plan.fingerprint = _digest(manifest, lockfile)
    try:
        pkg, lock = _read_json(manifest), _read_json(lockfile)
    except (OSError, ValueError) as exc:
        return refuse(REFUSE_NO_PROJECT, repr(exc))
    if pkg.get("workspaces") or any(k and not k.startswith("node_modules/") for k in lock.get("packages") or {}):
        return refuse(REFUSE_WORKSPACE)
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        return refuse(REFUSE_LOCK_VERSION)
    section = next((s for s in SECTIONS if name in (pkg.get(s) or {})), None)
    current = ((lock["packages"].get(f"node_modules/{name}") or {}).get("version"))
    plan.installed_version = current
    if section is None:
        return refuse(REFUSE_NOT_DIRECT.format(name=name))
    spec = pkg[section][name]
    if problem := _spec_problem(spec):
        return refuse(problem)
    if current is None:
        return refuse(REFUSE_NO_PROJECT)
    try:
        published, latest = npm_registry.versions(name, get)
    except Exception as exc:  # Network, HTTP, JSON.
        return refuse(REFUSE_REGISTRY, repr(exc))
    target = choose_target(current, published, latest, fixed_in)
    if target is None:
        return refuse(REFUSE_CURRENT.format(name=name))
    spec_after = new_spec(spec, target)
    if spec_after is None:
        return refuse(REFUSE_SPEC.format(spec=spec))
    plan.target_version = target
    plan.major_change = is_major_change(current, target)
    plan.command = [npm, "install", f"{name}@{spec_after}", SECTIONS[section], *SAFE_FLAGS, "--prefix", str(folder)]
    plan.rows += [
        {"label": "package.json", "value": f'"{name}": "{spec}" → "{spec_after}"'},
        {"label": "package-lock.json", "value": f"{name} {current} → {target}"},
    ]

    # Resolve the new lockfile in a temp copy. The project and node_modules stay as they are.
    with tempfile.TemporaryDirectory(prefix="watchtower-npm-") as tmp:
        shutil.copy2(manifest, Path(tmp) / "package.json")
        shutil.copy2(lockfile, Path(tmp) / "package-lock.json")
        args = [npm, "install", f"{name}@{spec_after}", SECTIONS[section], "--package-lock-only", *SAFE_FLAGS,
                "--prefix", tmp]
        try:
            proc = run(args, capture_output=True, text=True, timeout=NPM_TIMEOUT_SECONDS, env=npm_env(npm),
                       stdin=subprocess.DEVNULL)
            if proc.returncode != 0:
                raise RuntimeError(f"npm exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
            new_lock = _read_json(Path(tmp) / "package-lock.json")
        except Exception as exc:
            return refuse(REFUSE_RESOLVE, repr(exc))
    resolved = (new_lock.get("packages", {}).get(f"node_modules/{name}") or {}).get("version")
    if resolved != target:
        return refuse(REFUSE_RESOLVE, f"lockfile resolved {name} to {resolved}, plan target {target}")
    plan.also_changes = lock_changes(lock, new_lock, name)

    # Install scripts: from the lockfile flag, with the names from the registry.
    for key_path, entry in sorted((new_lock.get("packages") or {}).items()):
        if not key_path or not (entry or {}).get("hasInstallScript"):
            continue
        pkg_name = key_path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        old = (lock["packages"].get(key_path) or {}).get("version")
        if old == version:
            continue  # Unchanged: nothing new runs.
        try:
            scripts = npm_registry.install_scripts(pkg_name, version, get)
        except Exception as exc:
            return refuse(REFUSE_SCRIPTS_UNKNOWN, f"{pkg_name}@{version}: {exc!r}")
        if not scripts:
            return refuse(REFUSE_SCRIPTS_UNKNOWN, f"{pkg_name}@{version} has hasInstallScript but no script")
        for script in scripts:
            plan.script_details.append({"package": pkg_name, "version": version, "script": script})
            plan.scripts.append(f"{pkg_name} needs its {script} script")
    if plan.script_details:
        names = sorted({d["package"] for d in plan.script_details})
        plan.rows.append({"label": "Scripts command", "value": " ".join(rebuild_command(plan, names))})

    plan.manual_steps = ["Restart anything that runs this project."]
    if "test" in (pkg.get("scripts") or {}):
        plan.manual_steps.insert(0, "Run the project tests: npm test")
    return plan


def rebuild_command(plan: Plan, names: list[str]) -> list[str]:
    folder, _, _ = parse_key(plan.item_key)
    return [plan.command[0], "rebuild", *names, "--ignore-scripts=false", "--prefix", str(folder)]


# Run and verify


def execute(plan: Plan, on_line: Callable[[str], None], confirm_scripts: bool,
            runner: RunStreaming = run_streaming) -> tuple[int, str | None]:
    """Run the install, then the confirmed scripts. Returns (exit code, error for a script failure).

    If the install fails, package.json and package-lock.json go back to their state before the run.
    """
    folder, _, _ = parse_key(plan.item_key)
    saved = {p: p.read_bytes() for p in (folder / "package.json", folder / "package-lock.json")}
    env = npm_env(plan.command[0])
    code = runner(list(plan.command), env, on_line)
    if code != 0:
        for path, data in saved.items():
            if path.read_bytes() != data:
                path.write_bytes(data)
                on_line(f"Watchtower restored {path.name}.")
        return code, None
    if plan.script_details and confirm_scripts:
        names = sorted({d["package"] for d in plan.script_details})
        code = runner(rebuild_command(plan, names), env, on_line)
        if code != 0:
            return code, ERROR_SCRIPTS_FAILED.format(code=code)
    return 0, None


def verify(plan: Plan) -> tuple[bool, str | None, list[dict], str | None]:
    """Check the lockfile and node_modules separately. Returns (ok, after, checks, error)."""
    folder, name, _ = parse_key(plan.item_key)
    target = plan.target_version
    spec_after = plan.command[2].rsplit("@", 1)[1]
    try:
        lock = _read_json(folder / "package-lock.json")
        pkg = _read_json(folder / "package.json")
    except (OSError, ValueError):
        lock, pkg = {}, {}
    lock_version = ((lock.get("packages") or {}).get(f"node_modules/{name}") or {}).get("version")
    spec_now = next(((pkg.get(s) or {}).get(name) for s in SECTIONS if name in (pkg.get(s) or {})), None)
    try:
        installed = _read_json(folder / "node_modules" / name / "package.json").get("version")
    except (OSError, ValueError):
        installed = None
    lock_ok = lock_version == target and spec_now == spec_after
    installed_ok = installed == target
    checks = [
        {"label": "Lockfile", "value": f"{name} {lock_version or 'missing'}", "ok": lock_ok},
        {"label": "Installed (node_modules)", "value": f"{name} {installed or 'not installed'}", "ok": installed_ok},
    ]
    if not lock_ok:
        return False, lock_version, checks, NOT_VERIFIED_LOCK.format(name=name, version=lock_version or "none")
    if not installed_ok:
        return False, lock_version, checks, NOT_VERIFIED_INSTALLED.format(version=installed or "not installed")
    return True, lock_version, checks, None
