#!/bin/zsh
# Render the UI snapshot scenarios offscreen to PNG, light and dark. Run from the repo root.
# Usage: scripts/snapshot.sh <out-dir>
set -e
[[ -n "$1" ]] || { print -u2 "usage: scripts/snapshot.sh <out-dir>"; exit 2 }
out="${1:A}"
cd "${0:A:h}/.."
swift build --product WatchtowerSnapshots
"$(swift build --show-bin-path)/WatchtowerSnapshots" "$out"
