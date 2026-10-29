#!/bin/zsh
# Render every mockup and state to PNG (light and dark). Run from anywhere.
cd "$(dirname "$0")"
./render.sh dashboard 1280 820
for s in stale partial running failed never; do ./render.sh dashboard 1280 820 state=$s -$s; done
./render.sh update-dialog 1700 780
./render.sh update-dialog-npm-uv 1700 1380
./render.sh menubar 1380 920
./render.sh findings 1400 860
for v in partial deferred resolved empty; do ./render.sh findings 1400 860 view=$v -$v; done
./render.sh update-log 1280 820
for v in notverified failed; do ./render.sh update-log 1280 820 view=$v -$v; done
./render.sh backlog 1280 820
./render.sh backlog 1280 820 view=empty -empty
./render.sh incidents 1280 820
for v in missed failed checking empty; do ./render.sh incidents 1280 820 view=$v -$v; done
./render.sh settings 780 380 tab=general -general
./render.sh settings 780 640 tab=projects -projects
./render.sh settings 780 380 tab=services -services
