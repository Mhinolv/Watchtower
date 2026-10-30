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

# Sign with one stable identity, so macOS keeps permission grants across builds.
# Order: WATCHTOWER_SIGN_IDENTITY, then a Developer ID Application identity, then Apple Development.
# With no identity, the app stays ad-hoc signed and macOS can ask for permissions again after each build.
identities="$(security find-identity -v -p codesigning 2>/dev/null)"
identity="${WATCHTOWER_SIGN_IDENTITY:-}"
[[ -n "$identity" ]] || identity="$(print -r -- "$identities" | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)"
[[ -n "$identity" ]] || identity="$(print -r -- "$identities" | sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)"
if [[ -n "$identity" ]]; then
    codesign --force --options runtime --timestamp --sign "$identity" "$app" 2>/dev/null \
        || codesign --force --options runtime --timestamp=none --sign "$identity" "$app"
    codesign --verify --strict "$app"
    print -u2 "Signed with: $identity"
else
    codesign --force --sign - "$app"
    print -u2 "No signing identity found: the app is ad-hoc signed. macOS can ask for permissions again after each build."
fi
print "$app"
