#!/bin/zsh
# Build Watchtower.app: the release binary, Info.plist, AppIcon.icns from design/logo/,
# the compiled asset catalog (AccentColor) and the SwiftPM resource bundles.
# Usage: scripts/bundle.sh [out-dir]   (default: build/)
set -e
cd "${0:A:h}/.."
out="${1:-build}"
out="${out:A}"
app="$out/Watchtower.app"
swift build -c release --product Watchtower
bin="$(swift build -c release --show-bin-path)"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin/Watchtower" "$app/Contents/MacOS/Watchtower"
cp Sources/WatchtowerApp/Info.plist "$app/Contents/Info.plist"
cp design/logo/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
for b in "$bin"/*.bundle(N); do cp -R "$b" "$app/Contents/Resources/"; done
xcrun actool Sources/WatchtowerApp/Assets.xcassets --compile "$app/Contents/Resources" \
    --platform macosx --minimum-deployment-target 15.0 \
    --output-partial-info-plist "$out/assetcatalog-info.plist" > /dev/null
rm -f "$out/assetcatalog-info.plist"
plutil -lint "$app/Contents/Info.plist" > /dev/null
print "$app"
