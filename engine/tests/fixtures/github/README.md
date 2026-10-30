# GitHub advisory fixtures

`reviewed-nltk-live.json` and `reviewed-nltk-withdrawn.json` are real answers of
`GET https://api.github.com/advisories?ghsa_id=<id>&type=reviewed&per_page=100` (fetched 2026-10-30) for the two
advisory ids of one nltk finding: `GHSA-5wp5-5229-5g6q` is live and `GHSA-gf32-cmjh-8m9v` is a withdrawn duplicate (#65).
`reviewed.json` and `malware.json` are made-up lodash and malware samples.
