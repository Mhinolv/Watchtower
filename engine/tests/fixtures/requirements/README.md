# requirements fixtures

- `simple.txt`, `with-*.txt`, `duplicate.txt`, `continued.txt`: real requirements.txt shapes (comments, exact pins, ranges,
  extras, markers, `-e` and URL lines, `-r` and `-c` includes, `--hash` pins, an index option). Package names are public
  packages. No project of the owner is named.
- `pip-report-requests-2.32.3.json`: the real output of `pip install --dry-run --report - requests==2.32.3` (pip 26.2.2)
  in an empty environment. The long package descriptions are cut. Every other field is as pip wrote it.
- `pypi-requests-2.32.3.json`, `pypi-pycrypto-2.6.1.json`: the `info.name`, `info.version` and `urls` of the real
  PyPI JSON pages. requests has a wheel. pycrypto 2.6.1 has only a source archive (the build case).
