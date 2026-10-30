# Incident fixtures

- `github.rss`, `google.json`, `apple_security_releases.html`: samples of the vendor sources (#12).
- `hibp-breaches-excerpt.json`: real entries of `GET https://haveibeenpwned.com/api/v3/breaches` (fetched 2026-10-30), with the
  real field names: `000webhost`, `BTSec` (title `Bitcoin Security Forum Gmail Dump`, not a Google service), and others.
  The real list has 1048 breaches and none for GitHub or Google / Gmail today.
- `hibp-breaches-watched-synthetic.json`: SYNTHETIC records in the real shape (copies of the real `000webhost` entry with
  other names and domains) to test the watched-service rules. They are not real breaches.
No fixture holds an email address or an account name.
