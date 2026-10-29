#!/bin/zsh
# Render one mockup to light and dark PNGs. Usage: design/render.sh <name> [width height] [extra query like state=stale] [suffix]
# Example: design/render.sh dashboard 1280 820
set -e
cd "$(dirname "$0")/mockups"
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
name=$1; w=${2:-1280}; h=${3:-820}; extra=${4:-}; suffix=${5:-}
for theme in light dark; do
  q="theme=$theme${extra:+&$extra}"
  "$CH" --headless=new --disable-gpu --hide-scrollbars --window-size=$w,$h --virtual-time-budget=2000 \
    --screenshot="$PWD/${name}${suffix}-${theme}.png" "file://$PWD/${name}.html?$q" >/dev/null 2>&1
done
echo "rendered ${name}${suffix}"
