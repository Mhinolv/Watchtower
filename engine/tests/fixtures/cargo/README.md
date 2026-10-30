# Cargo fixtures (#15)

Real output of cargo 1.98.0 (`cargo-version.txt`) on 2026-10-30, in temp projects. No owner project was used.

- `tool/`: a project with a range (`serde = "1.0.190"`), an exact pin (`itoa = "=1.0.9"`), `smallvec = "1.11"` and a dev dependency. `Cargo.lock` was made with `cargo generate-lockfile`, then `cargo update -p serde --precise 1.0.190` and `-p smallvec --precise 1.11.0`.
- `update-dry-run.stderr`: `cargo update --manifest-path tool/Cargo.toml -p serde@1.0.190 --precise 1.0.210 --dry-run`. Exit code 0, empty stdout. The lock did not change.
- `update-run.stderr` and `tool-Cargo.lock.after`: the same command without `--dry-run`. Only `Cargo.lock` changed. No `target/` folder was made.
- `update-exact-pin-error.stderr`: `-p itoa --precise 1.0.11 --dry-run` against the `=1.0.9` pin. Exit code 101. The temp path is in the text.
- `workspace/`: a workspace root with one member, and its `Cargo.lock`.
- `vuln/` and `osv-scan-output.json`: `smallvec = "1.6.0"` locked at 1.6.0, scanned by the pinned OSV-Scanner 2.7.0 with `--offline` against the crates.io `all.zip`. The lockfile path is replaced with `__CARGO_LOCK__`.
