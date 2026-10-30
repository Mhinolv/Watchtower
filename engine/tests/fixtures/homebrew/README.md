# Homebrew fixtures

`cask-catalog.json` holds 18 real entries from the public cask API (`https://formulae.brew.sh/api/cask/<token>.json`,
fetched 2026-10-29): t3-code, hopper-disassembler, zed, firefox, firefox@esr, firefox@beta, slack, slack@beta,
google-chrome, wondershare-uniconverter (lists `com.google.Chrome` in `uninstall quit`), visual-studio-code, tidgi
(lists `com.microsoft.VSCode` in a zap path), chatgpt, codex-app (both list `com.openai.codex`), iterm2, iterm2@beta,
zoom, zoom-for-it-admins (no app artifact, so only the bundle id matches). The shape is the
shape of `https://formulae.brew.sh/api/cask.json`: a list of these objects. Versions are as of that day.
`zoom` and `zoom-for-it-admins` share `us.zoom.xos` and no app name tells them apart: a real ambiguous match.
