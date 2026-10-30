"""The owner's settings (#17), in `settings.json` in the data folder (mode 0600).

One setting for now: `check_running_versions`. It is on by default (owner decision 2026-10-29). A missing
file, a file that is not valid and an unknown key all give the default. The refresh never fails because of this file.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .store import FILE_MODE, default_data_dir, ensure_private_dir

FILE_NAME = "settings.json"
FILE_VERSION = 1
DEFAULTS = {"check_running_versions": True}


def _path(data_dir) -> Path:
    return (Path(data_dir) if data_dir else default_data_dir()) / FILE_NAME


def load(data_dir=None) -> dict:
    """The settings with defaults. A value of the wrong type gives the default."""
    values = dict(DEFAULTS)
    try:
        data = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return values
    if isinstance(data, dict):
        for key, default in DEFAULTS.items():
            if isinstance(data.get(key), type(default)):
                values[key] = data[key]
    return values


def check_running_versions(data_dir=None) -> bool:
    return load(data_dir)["check_running_versions"]


def save(values: dict, data_dir=None) -> dict:
    """Write the settings with a private temp file and a replace. Returns what `load` returns after."""
    path = _path(data_dir)
    ensure_private_dir(path.parent)
    merged = {**load(data_dir), **{k: v for k, v in values.items() if k in DEFAULTS}}
    payload = json.dumps({"version": FILE_VERSION, **merged}, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=FILE_NAME, suffix=".tmp")
    try:
        os.fchmod(fd, FILE_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return load(data_dir)
