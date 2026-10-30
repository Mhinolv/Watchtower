# requirements fixtures

- `simple.txt`, `with-*.txt`, `duplicate.txt`, `continued.txt`: real requirements.txt shapes (comments, exact pins, ranges,
  extras, markers, `-e` and URL lines, `-r` and `-c` includes, `--hash` pins, an index option). Package names are public
  packages. No project of the owner is named.
- `pip-report-requests-2.32.3.json`: the real output of `pip install --dry-run --report - requests==2.32.3` (pip 26.2.2)
  in an empty environment. The long package descriptions are cut. Every other field is as pip wrote it.
- `pypi-requests-2.32.3.json`, `pypi-pycrypto-2.6.1.json`: the `info.name`, `info.version` and `urls` of the real
  PyPI JSON pages. requests has a wheel. pycrypto 2.6.1 has only a source archive (the build case).

#80 fixtures:
- `requirements-pins-and-ranges.txt`: a requirements file in common shapes: comments, an inline comment, an extra with a marker, a range, a compatible-release range and an unpinned line.
- `osv-scan-output.json`: real output of the pinned OSV-Scanner 2.7.0 (`scan source --offline --format json`) on the pins-only file that the engine writes for that file (`requests==2.31.0`, `urllib3==1.26.18`, `Jinja2==3.1.2`), with the PyPI `all.zip` of 2026-10-30. Exit code 1. The scanner reports names in lower case (`jinja2`). The file path is replaced with `__REQUIREMENTS__`. The scanner gave the same packages for the full file: it reads exact pins only.

#96 fixtures (uv 0.8.8, the stderr of `uv pip install --dry-run --only-binary=:all: --python <.venv python> <name>==<target>`):
- `uv-dry-run-requests-2.32.3.txt`: an environment with requests 2.31.0 (an upgrade: one `-` and one `+` line). The environment folder name is replaced with `.venv`.
- `uv-dry-run-litellm-1.84.0.txt`: an environment with no litellm and no openai (new packages: `+` lines only).
