"""One confirmed update: plan, check the plan again, run, verify, log.

Owner rules (2026-10-29):
- The owner sees the exact command and confirms before it runs. No "update all".
- A major version change needs a separate confirmation. So do install scripts or a build.
- Success only if the engine reads the installed version again and it matches the plan.
- Every attempt goes in the update log, also refused and changed plans.
"""
from __future__ import annotations

import signal
import subprocess
from typing import Callable

from .feeds.homebrew import http_fetch
from .inventory import mas as mas_inventory
from .inventory.homebrew import find_brew, version_key
from .store import Store
from .update_log import Attempt, UpdateLog
from .updates import cargo as cargo_updates
from .updates import homebrew as brew_updates
from .updates import mas as mas_updates
from .updates import npm as npm_updates
from .updates import requirements as req_updates
from .updates import uv as uv_updates

ERROR_NOT_UPDATABLE = "Watchtower can update Homebrew formulae and casks only."
ERROR_NO_BREW = "Homebrew is not installed."
ERROR_NEEDS_MAJOR = "A new major version needs its own confirmation."
ERROR_NEEDS_SCRIPTS = "This update needs install scripts. Confirm them first."
ERROR_FAILED = "The update failed (exit code {code})."
ERROR_NOT_VERIFIED = "The command finished, but the installed version is still {version}."
ERROR_OTHER_VERSION = "The command finished, but the installed version is {version}, not {target}."
ERROR_PLAN_CHANGED = "The plan changed. Review the new plan."
ERROR_INTERRUPTED = "The update was interrupted. Refresh to see the installed version."


class UpdateError(Exception):
    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.detail = detail


class Interrupted(Exception):
    pass


def _item(store: Store, item_key: str):
    source, _, item_id = item_key.partition("/")
    return next((i for i in store.items() if i.source == source and i.id == item_id), None)


def plan_update(store: Store, item_key: str, brew: str | None = None, run: Callable = subprocess.run,
                uv: str | None = None, fetch: Callable = http_fetch, uv_options: dict | None = None,
                npm: str | None = None, get=None, mas: str | None = None, cargo: str | None = None,
                **platform) -> brew_updates.Plan:
    if item_key.startswith(cargo_updates.KEY_PREFIX):
        return cargo_updates.make_plan(item_key, cargo, run)
    if item_key.startswith(uv_updates.KEY_PREFIX):
        return uv_updates.make_plan(item_key, uv, run, fetch, **(uv_options or {}))
    if item_key.startswith(req_updates.KEY_PREFIX):
        return req_updates.make_plan(item_key, run, fetch, **(uv_options or {}))
    if item_key.startswith(npm_updates.KEY_PREFIX):
        options = {"get": get} if get else {}
        return npm_updates.make_plan(item_key, npm, run, **options)
    item = _item(store, item_key)
    if mas_updates.is_store_item(item):
        return mas_updates.make_plan(item_key, item.name, (item.attributes or {}).get("adamId"),
                                     item.installed_version, mas or mas_inventory.find_mas(), run)
    if item is None or item.source != "homebrew" or item.kind not in ("formula", "cask"):
        raise UpdateError(ERROR_NOT_UPDATABLE)
    brew = brew or find_brew()
    if brew is None:
        raise UpdateError(ERROR_NO_BREW)
    return brew_updates.make_plan(item_key, item.latest_version, brew, run, **platform)


def _mark_item_updated(store: Store, plan: brew_updates.Plan, after: str) -> None:
    """The stored row shows the new version until the next refresh checks it again."""
    source, _, item_id = plan.item_key.partition("/")
    row = store.db.execute("SELECT latest_version FROM items WHERE source = ? AND id = ?", (source, item_id)).fetchone()
    latest = row["latest_version"] if row else None
    state = "up_to_date" if latest is None or version_key(after) >= version_key(latest) else "update_available"
    store.db.execute("UPDATE items SET installed_version = ?, state = ? WHERE source = ? AND id = ?",
                     (after, state, source, item_id))


def run_update(store: Store, item_key: str, plan_id: str, confirm_major: bool = False,
               confirm_scripts: bool = False, on_line: Callable[[str], None] = lambda line: None,
               brew: str | None = None, run: Callable = subprocess.run,
               runner: brew_updates.RunStreaming = brew_updates.run_streaming,
               uv: str | None = None, fetch: Callable = http_fetch, uv_options: dict | None = None,
               npm: str | None = None, get=None, mas: str | None = None, cargo: str | None = None,
               actor: str = "app", **platform) -> tuple[Attempt, dict]:
    """Run one confirmed update. Returns the logged attempt and the plan that was checked.

    `actor` marks the log row: `app` or the agent name (#111).
    """
    log = UpdateLog(store)
    plan = plan_update(store, item_key, brew, run, uv, fetch, uv_options, npm, get, mas, cargo, **platform)
    if plan.id != plan_id:
        attempt_id = log.begin(plan, confirm_major, confirm_scripts, "plan_changed", ERROR_PLAN_CHANGED, actor)
        return log.get(attempt_id), plan.to_dict()
    refusal = plan.refusal
    if refusal is None and plan.major_change and not confirm_major:
        refusal = ERROR_NEEDS_MAJOR
    if refusal is None and plan.scripts and not confirm_scripts:
        refusal = ERROR_NEEDS_SCRIPTS
    if refusal:
        attempt_id = log.begin(plan, confirm_major, confirm_scripts, "refused", refusal, actor)
        return log.get(attempt_id), plan.to_dict()

    attempt_id = log.begin(plan, confirm_major, confirm_scripts, actor=actor)
    output: list[str] = []

    def line(text: str) -> None:
        output.append(text)
        on_line(text)

    if plan.kind == cargo_updates.KIND:
        return _run_cargo(store, log, plan, attempt_id, line, output, runner)
    if plan.kind == uv_updates.KIND:
        return _run_uv(store, log, plan, attempt_id, confirm_scripts, line, output, runner)
    if plan.kind == req_updates.KIND:
        return _run_requirements(store, log, plan, attempt_id, confirm_scripts, line, output, runner), plan.to_dict()
    if plan.kind == npm_updates.KIND:
        return _run_npm(log, attempt_id, plan, confirm_scripts, line, runner, output), plan.to_dict()

    if plan.kind == mas_updates.KIND:
        return _run_mas(store, log, plan, attempt_id, line, output, runner, run), plan.to_dict()

    try:
        code = brew_updates.upgrade(plan, line, runner)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id), plan.to_dict()

    # Exit status alone is no proof. Read the installed version again.
    try:
        after = brew_updates.installed_version(plan.kind, brew_updates.read_one(plan.command[0], plan.kind,
                                                                                plan.full_name, run))
    except Exception as exc:
        output.append(f"version re-read failed: {exc!r}")
        after = None
    text = "\n".join(output)
    if code != 0:
        log.finish(attempt_id, "failed", after, code, text, ERROR_FAILED.format(code=code))
    elif after == plan.target_version:
        log.finish(attempt_id, "verified", after, code, text)
        _mark_item_updated(store, plan, after)
    else:
        if after is not None and after != plan.installed_version:
            error = ERROR_OTHER_VERSION.format(version=after, target=plan.target_version)
        else:
            error = ERROR_NOT_VERIFIED.format(version=after or "unknown")
        log.finish(attempt_id, "not_verified", after, code, text, error)
    return log.get(attempt_id), plan.to_dict()


def _run_mas(store: Store, log: UpdateLog, plan, attempt_id: int, line, output: list[str], runner, run) -> Attempt:
    """Run `mas update <id>`, then read the installed version again. Success needs the planned version."""
    try:
        code = mas_updates.execute(plan, line, runner)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id)
    item = _item(store, plan.item_key)
    path = (item.attributes or {}).get("path") if item else None
    try:
        after = mas_updates.read_installed(path, plan.full_name, plan.command[0], run)
    except Exception as exc:
        output.append(f"version re-read failed: {exc!r}")
        after = None
    text = "\n".join(output)
    if code != 0:
        log.finish(attempt_id, "failed", after, code, text,
                   mas_updates.failure_message(text) or ERROR_FAILED.format(code=code))
    elif after == plan.target_version:
        log.finish(attempt_id, "verified", after, code, text)
        _mark_item_updated(store, plan, after)
    else:
        if after is not None and after != plan.installed_version:
            error = ERROR_OTHER_VERSION.format(version=after, target=plan.target_version)
        else:
            error = ERROR_NOT_VERIFIED.format(version=after or "unknown")
        log.finish(attempt_id, "not_verified", after, code, text, error)
    return log.get(attempt_id)


def _run_npm(log: UpdateLog, attempt_id: int, plan, confirm_scripts: bool, line, runner, output) -> Attempt:
    """npm: install with --ignore-scripts, then the confirmed scripts. Verify lockfile and node_modules."""
    try:
        code, script_error = npm_updates.execute(plan, line, confirm_scripts, runner)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id)
    ok, after, rows, error = npm_updates.verify(plan)
    text = "\n".join(output)
    if code != 0:
        log.finish(attempt_id, "failed", after, code, text, script_error or ERROR_FAILED.format(code=code), rows)
    elif ok:
        log.finish(attempt_id, "verified", after, code, text, None, rows)
    else:
        log.finish(attempt_id, "not_verified", after, code, text, error, rows)
    return log.get(attempt_id)


def _run_requirements(store: Store, log: UpdateLog, plan, attempt_id: int, confirm_scripts: bool,
                      line: Callable[[str], None], output: list[str], runner) -> Attempt:
    """Run one pip (or uv pip) install, edit requirements.txt only if the environment shows the target, read both again."""
    req = req_updates.parse_key(plan.item_key)
    before = uv_updates.snapshot(req.root)
    backup = req_updates.backup_file(req.path, store.data_dir, attempt_id)
    if backup:
        line(f"Backup of requirements.txt: {backup}")
    if req_updates.is_pin_only(plan):
        # The package is not installed: edit the pin only and run nothing (owner decision on #96).
        line(req_updates.PIN_ONLY_LINE.format(name=req.name))
        edit_failed = not req_updates.apply_edit(req.path, req.name, plan.target_version)
        if not edit_failed:
            line(f"Edited requirements.txt: {next(r['value'] for r in plan.rows if r['label'] == 'requirements.txt')}")
        outcome = req_updates.read_outcome(req, before, uv_updates.snapshot(req.root))
        status, error = req_updates.pin_verdict(outcome, req.name, edit_failed)
        log.finish(attempt_id, status, outcome.installed, None, "\n".join(output), error,
                   req_updates.pin_result_rows(outcome, req.name))
        return log.get(attempt_id)
    command = req_updates.command_to_run(plan, confirm_scripts)
    line("$ " + " ".join(command))
    try:
        code = runner(command, req_updates.run_env(command), line)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id)
    edit_failed = False
    if code == 0 and uv_updates.installed_version(req.root, req.name) == plan.target_version:
        edit_failed = not req_updates.apply_edit(req.path, req.name, plan.target_version)
        if not edit_failed:
            line(f"Edited requirements.txt: {next(r['value'] for r in plan.rows if r['label'] == 'requirements.txt')}")
    outcome = req_updates.read_outcome(req, before, uv_updates.snapshot(req.root))
    status, error = req_updates.verdict(outcome, plan.target_version, req.name, code, edit_failed)
    if status == "failed":
        error = ERROR_FAILED.format(code=code)
    log.finish(attempt_id, status, outcome.installed, code, "\n".join(output), error,
               outcome.result_rows(req.name, plan.target_version))
    return log.get(attempt_id)


def _run_uv(store: Store, log: UpdateLog, plan, attempt_id: int, confirm_scripts: bool,
            line: Callable[[str], None], output: list[str], runner) -> tuple[Attempt, dict]:
    """Run one uv sync, then read the lockfile and the environment again. Success needs both."""
    req = uv_updates.parse_key(plan.item_key)
    root = req.root
    before = uv_updates.snapshot(root)
    backup = uv_updates.backup_files(root, store.data_dir, attempt_id)
    if backup:
        line(f"Backup of pyproject.toml and uv.lock: {backup}")
    command = uv_updates.command_to_run(plan, confirm_scripts)
    line("$ " + " ".join(command))
    try:
        code = runner(command, uv_updates.uv_env(), line)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id), plan.to_dict()
    outcome = uv_updates.read_outcome(root, req.name, before)
    status, error = uv_updates.verdict(outcome, plan.target_version, req.name, code)
    if status == "failed":
        error = ERROR_FAILED.format(code=code)
    log.finish(attempt_id, status, outcome.installed, code, "\n".join(output), error,
               outcome.result_rows(req.name, plan.target_version))
    return log.get(attempt_id), plan.to_dict()


def _run_cargo(store: Store, log: UpdateLog, plan, attempt_id: int, line: Callable[[str], None],
               output: list[str], runner) -> tuple[Attempt, dict]:
    """Run one cargo update, then read Cargo.lock again. Success is `lockfile_updated`, not `verified` (#15)."""
    req = cargo_updates.parse_key(plan.item_key)
    root = req.root
    before = cargo_updates.snapshot(root)
    backup = cargo_updates.backup_files(root, store.data_dir, attempt_id)
    if backup:
        line(f"Backup of Cargo.toml and Cargo.lock: {backup}")
    line("$ " + " ".join(plan.command))
    try:
        code = runner(list(plan.command), cargo_updates.cargo_env(), line)
    except Interrupted:
        log.finish(attempt_id, "interrupted", None, None, "\n".join(output), ERROR_INTERRUPTED)
        raise
    except Exception as exc:
        log.finish(attempt_id, "failed", None, None, "\n".join(output + [repr(exc)]), ERROR_FAILED.format(code="none"))
        return log.get(attempt_id), plan.to_dict()
    outcome = cargo_updates.read_outcome(root, req.name, before)
    status, error = cargo_updates.verdict(outcome, plan.target_version, req.name, code)
    if status == "failed":
        error = ERROR_FAILED.format(code=code)
    log.finish(attempt_id, status, outcome.locked, code, "\n".join(output), error,
               outcome.result_rows(req.name, plan.target_version))
    return log.get(attempt_id), plan.to_dict()


class InterruptOnSigterm:
    """SIGTERM stops the engine, not the running brew. The log records `interrupted`."""

    def __enter__(self):
        self.previous = signal.signal(signal.SIGTERM, self._handle)
        return self

    def _handle(self, signum, frame):
        raise Interrupted()

    def __exit__(self, *exc):
        signal.signal(signal.SIGTERM, self.previous)
