#!/bin/zsh
# Full suite: Swift tests and engine tests. Run from the repo root.
set -e
cd "${0:A:h}/.."
swift test
[[ -x engine/.venv/bin/pytest ]] || { python3 -m venv engine/.venv && engine/.venv/bin/pip -q install pytest; }
cd engine && .venv/bin/pytest -q
