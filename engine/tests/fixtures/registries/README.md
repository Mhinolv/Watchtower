# Registry fixtures (#81)

Real answers, fetched 2026-10-30:
- `pypi-<name>.json`: the real `https://pypi.org/pypi/<name>/json` answer for requests, click, rich, PyYAML, pytest and urllib3, cut to `info.name` and `info.version`.
- `crates-<name>.ndjson`: the last lines (the newest versions) of the real sparse index file at `https://index.crates.io/<path>` for serde, itoa, smallvec and memchr. `crates-smallvec.ndjson` also holds the real pre-release lines `2.0.0-beta.x`: the newest version in the file is a pre-release and the engine must not take it as latest.
