# mas fixtures

`list.jsonl`, `outdated.jsonl` and `stderr.txt` are real output of mas 7.0.0 on the owner's Mac
(`mas list --json`, `mas outdated --json`, and the warning that mas wrote to stderr; exit code 0).
Real output has a first record `{"name":""}` with no `adamID`, and `outdated` adds `bundleID`.
`version.txt` is not captured. It follows the documented `mas version` output.
