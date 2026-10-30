# Homebrew fixtures

`cask-catalog.json` holds 6 real entries from the public cask API (`https://formulae.brew.sh/api/cask/<token>.json`,
fetched 2026-10-29): t3-code, hopper-disassembler, zed, firefox, firefox@esr, firefox@beta. The shape is the
shape of `https://formulae.brew.sh/api/cask.json`: a list of these objects. Versions are as of that day.
`firefox`, `firefox@esr` and `firefox@beta` all install `Firefox.app`, so they give a real ambiguous match.
