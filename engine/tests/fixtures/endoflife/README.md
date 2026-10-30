# endoflife.date fixtures (#59)

Real answers of `https://endoflife.date/api/v1/products/<product>/`, fetched 2026-10-30:
- `nodejs.json`, `python.json`, `macos.json`, `ruby.json`, `go.json`: the whole answer, unchanged.
- `rust.json`, `gradle.json`, `kotlin.json`: the real answer, cut to the 8 newest `releases`.

The tests set the clock themselves, so the support states do not depend on the day that the tests run.
