# EPSS fixture

`epss_scores-excerpt.csv` has the first two lines of the real public file
`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (fetched 2026-10-30: the comment line with
`model_version` and `score_date`, and the header `cve,epss,percentile`) and 10 real rows of that file.
The real file is gzip with content type `binary/octet-stream` and no `content-encoding` header.
The URL answers 302 to `epss_scores-<date>.csv.gz`. Tests gzip the excerpt themselves.
