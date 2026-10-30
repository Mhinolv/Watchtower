"""Container image names of a project (#17), read from its Dockerfile and compose files.

Metadata only. The engine reads text files in the project folder. It starts no container, no Docker daemon and no
`docker` command, and it does not read the Docker config (`~/.docker`, which can hold credentials) or any image layer.
A file must be a regular file of 256 KB or less. A link, a larger file or a name that is not an image name is skipped.
"""
from __future__ import annotations

import os
import re
import stat

MAX_BYTES = 256 * 1024
MAX_IMAGES = 20
COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
# registry/name:tag or name@sha256:digest. No user info, no variable.
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[0-9a-f]{64})?$")
_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)
_COMPOSE_IMAGE = re.compile(r"^\s*image\s*:\s*(.+?)\s*(?:#.*)?$")


def _text(path: str) -> str | None:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(MAX_BYTES)
    except OSError:
        return None


def _valid(name: str) -> bool:
    return name.lower() != "scratch" and bool(_IMAGE.match(name))


def dockerfile_images(text: str) -> list[str]:
    """The base images of a Dockerfile, in order. A stage name (`FROM build`) is not an image."""
    stages: set[str] = set()
    images: list[str] = []
    for line in text.splitlines():
        found = _FROM.match(line)
        if not found:
            continue
        image, stage = found.group(1), found.group(2)
        if image.lower() not in stages and _valid(image):
            images.append(image)
        if stage:
            stages.add(stage.lower())
    return images


def compose_images(text: str) -> list[str]:
    """The `image:` values of a compose file."""
    images = []
    for line in text.splitlines():
        found = _COMPOSE_IMAGE.match(line)
        if found:
            name = found.group(1).strip("'\"")
            if _valid(name):
                images.append(name)
    return images


def project_images(folder: str) -> list[str]:
    """The image names in the top folder of a project, without duplicates, at most MAX_IMAGES."""
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    images: list[str] = []
    for name in names:
        lower = name.lower()
        if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
            reader = dockerfile_images
        elif lower in COMPOSE_FILES:
            reader = compose_images
        else:
            continue
        text = _text(os.path.join(folder, name))
        for image in reader(text) if text else []:
            if image not in images:
                images.append(image)
    return images[:MAX_IMAGES]
