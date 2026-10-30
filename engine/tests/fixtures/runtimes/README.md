# Runtime, SDK and extension fixtures (#16)

Real, taken from the build Mac and cut to their identity fields (no path, no project, no owner data):
- `package-*.json`: `name`, `displayName`, `version`, `publisher`, `engines` of three real VS Code and Cursor extension manifests.
- `xcode-version.plist`: the real `Xcode.app/Contents/version.plist` (Xcode 26.2).
- `sdksettings-*.plist`: `CanonicalName`, `DisplayName`, `Version` and the deployment targets of real `SDKSettings.plist` files (macOS 26.2 and iOS 26.2 of Xcode, macOS 15.5 and 15.2 of the Command Line Tools).
- `extension-folders.json`: the real folder names in `~/.vscode/extensions` and `~/.cursor/extensions` (public marketplace ids, with versions and `-darwin-arm64` or `-universal` suffixes).

SYNTHETIC, built by the tests in a temp folder: the version folders of nvm, fnm, Volta, pyenv, rbenv, rustup, SDKMAN!, asdf and mise, the Java virtual machine `Info.plist` files and the Go `VERSION` files. The build Mac has none of these installed. The folder names follow the layouts that each tool documents (`v22.9.0`, `3.12.4`, `go1.22.3`).
