"""The engine lock (#111): one refresh or update at a time, for the app and for agents.

`refresh` and `update-run` take `<data dir>/engine.lock` with `flock` and do not wait.
The holder writes `{"held_by", "command", "since"}` into the file. A process that cannot take
the lock reads it and stops with `Locked`. The kernel drops the lock when the holder process ends,
so a crash never leaves a stale lock. The file stays (mode 0600). Only its content is cleared.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from .models import utc_now
from .store import FILE_MODE, default_data_dir, ensure_private_dir

LOCK_NAME = "engine.lock"
MESSAGE_AGENT = "An agent is running a refresh or update. Try again when it ends."
MESSAGE_APP = "A refresh or update is already running. Try again when it ends."


class Locked(Exception):
    """Another process holds the lock. `holder` is {"held_by", "command", "since"} (values can be None)."""

    def __init__(self, holder: dict):
        self.holder = holder
        super().__init__(self.message)

    @property
    def message(self) -> str:
        """The app shows this sentence. An agent holder gets its own text."""
        held_by = self.holder.get("held_by")
        return MESSAGE_AGENT if held_by and held_by != "app" else MESSAGE_APP


def _holder(fd: int) -> dict:
    """What the holder wrote. Empty or unreadable content gives None values."""
    try:
        data = json.loads(os.pread(fd, 4096, 0).decode() or "{}")
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {key: data.get(key) if isinstance(data.get(key), str) else None
            for key in ("held_by", "command", "since")}


@contextmanager
def engine_lock(data_dir, actor: str, command: str, clock: Callable[[], str] = utc_now) -> Iterator[None]:
    """Hold the lock for `command` run by `actor` (`app` or the agent name). Raises Locked at once if taken."""
    folder = ensure_private_dir(Path(data_dir) if data_dir else default_data_dir())
    fd = os.open(folder / LOCK_NAME, os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        os.fchmod(fd, FILE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Locked(_holder(fd)) from None
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, json.dumps({"held_by": actor, "command": command, "since": clock()}).encode(), 0)
            yield
        finally:
            try:
                os.ftruncate(fd, 0)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
