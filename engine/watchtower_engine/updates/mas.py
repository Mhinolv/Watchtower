"""Plan, run and verify one Mac App Store app update through `mas` (#13).

Owner rules: the owner sees the exact command (`mas update <id>`) and confirms it. Success needs
the engine to read the installed version again. `mas outdated` runs here, in the plan step, and
never in the passive inventory. `mas update` uses no package scripts and no hooks, so the plan
says so. A major version needs its own confirmation (the shared #6 rule).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable

from ..inventory import mas as inv
from ..inventory.plist import read_plist, text
from .homebrew import Plan, RunStreaming, is_major_change, run_streaming

KIND = "mas"

REFUSE_CURRENT = "{name} is up to date ({version})."
REFUSE_UNREADABLE = "Watchtower cannot read the output of mas."
REFUSE_NO_ID = "Watchtower does not know the App Store ID of {name}."
SCRIPTS_ROW = {"label": "Scripts", "value": "Not used by App Store updates."}


def is_store_item(item) -> bool:
    return bool(item and item.source == "apps" and item.origin == inv.ORIGIN)


def _refuse(plan: Plan, message: str, detail: str | None = None) -> Plan:
    plan.refusal, plan.detail = message, detail
    return plan


def _limit_message(output: str) -> str | None:
    return {"spotlight": inv.NOTE_SPOTLIGHT, "signed_out": inv.ERROR_SIGNED_OUT,
            "admin": inv.ERROR_ADMIN}.get(inv.classify(output) or "")


def make_plan(item_key: str, name: str, adam_id: str | None, installed: str | None, mas: str | None,
              run: Callable = subprocess.run) -> Plan:
    """The plan for one app. Runs `mas version` and `mas outdated --json <id>` only."""
    plan = Plan(item_key, name, KIND, adam_id or "", installed, None,
                [mas or "mas", "update", adam_id or "<id>"], rows=[dict(SCRIPTS_ROW)])
    if mas is None:
        return _refuse(plan, inv.NOTE_NO_MAS)
    if not inv.is_adam_id(adam_id):
        return _refuse(plan, REFUSE_NO_ID.format(name=name))
    try:
        version = inv.read_version(mas, run)
    except inv.MasError as exc:
        return _refuse(plan, str(exc), exc.detail)
    if not inv.is_supported(version):
        return _refuse(plan, inv.ERROR_UNSUPPORTED.format(version=version))
    try:
        proc = inv._mas(mas, ["outdated", "--json", adam_id], run)
    except (OSError, subprocess.SubprocessError) as exc:
        return _refuse(plan, REFUSE_UNREADABLE, repr(exc))
    if proc.returncode != 0:
        output = (proc.stderr or "") + (proc.stdout or "")
        return _refuse(plan, _limit_message(output) or REFUSE_UNREADABLE,
                       f"mas outdated exited {proc.returncode}: {(proc.stderr or '').strip()[-300:]}")
    try:
        entries = [o for o in inv.parse_outdated(proc.stdout or "") if o.adam_id == adam_id]
    except ValueError as exc:
        return _refuse(plan, REFUSE_UNREADABLE, repr(exc))
    if not entries:
        # An empty answer is "up to date" only if stderr names no limit. A warning alone is not one.
        limit = _limit_message(proc.stderr or "")
        if limit:
            return _refuse(plan, limit, f"mas outdated printed nothing: {(proc.stderr or '').strip()[-300:]}")
        return _refuse(plan, REFUSE_CURRENT.format(name=name, version=installed or "current"))
    entry = entries[0]
    plan.installed_version, plan.target_version = entry.version, entry.new_version
    if inv.version_key(entry.new_version) <= inv.version_key(entry.version):
        return _refuse(plan, REFUSE_CURRENT.format(name=name, version=entry.version))
    plan.major_change = is_major_change(entry.version, entry.new_version)
    return plan


def execute(plan: Plan, on_line: Callable[[str], None], runner: RunStreaming = run_streaming) -> int:
    on_line("$ " + plan.command_text)
    return runner(list(plan.command), {**os.environ}, on_line)


def read_installed(path: str | None, adam_id: str, mas: str, run: Callable = subprocess.run) -> str | None:
    """The installed version. Read the app's Info.plist first, then ask `mas list --json`."""
    if path:
        try:
            info = read_plist(Path(path) / "Contents" / "Info.plist")
            version = text(info.get("CFBundleShortVersionString")) or text(info.get("CFBundleVersion"))
            if version:
                return version
        except (OSError, ValueError):
            pass
    listing = inv.read_inventory(mas, run)
    app = next((a for a in listing.apps.values() if a.adam_id == adam_id), None)
    return app.version if app else None


def failure_message(output: str) -> str | None:
    """The explicit state for a failed `mas update`, if the output names one."""
    return _limit_message(output)
