#!/bin/zsh
# Build the Swift app and check that the engine imports. Run from the repo root.
set -e
cd "${0:A:h}/.."
swift build
python3 -c "import sys; sys.path.insert(0, 'engine'); import watchtower_engine"
