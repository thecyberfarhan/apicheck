# apicheck

A small web and API misconfiguration checker. It sends a handful of safe, read-only requests and reports missing security headers, cookie flags, open CORS, leftover sensitive files (`.git`, `.env`, backups), directory listing, verbose error pages, and endpoints that answer without authentication. Standard library only.

> **This is a checker, not an exploit tool.** Every finding is an indicator to verify by hand — it tells you where to look, not that a vulnerability is proven. Only test systems you own or have written permission to test; a public target needs `--authorized`.

## Why

Most of the mistakes that turn into real incidents aren't exotic — they're a missing header, an exposed `.env`, or an endpoint nobody remembered to lock down. This checks for the common ones quickly, so the interesting manual work can start sooner.

## Install

```bash
git clone https://github.com/thecyberfarhan/apicheck
cd apicheck
python3 -m apicheck --help
```

## Usage

```bash
# basic scan of a lab target
python3 -m apicheck http://192.168.1.10:8080

# compare an authenticated vs anonymous response on specific endpoints
python3 -m apicheck http://192.168.1.10:8080 --token eyJhbGciOi... --endpoints paths.txt

# write a report
python3 -m apicheck http://192.168.1.10:8080 -o report.md
python3 -m apicheck http://192.168.1.10:8080 -o report.json
```

```
$ python3 -m apicheck http://192.168.1.10:4280
apicheck: only test systems you own or have written permission to test.
# apicheck report: http://192.168.1.10:4280

Requests sent: 28. Findings: 9.

## [MEDIUM] Content-Security-Policy missing
...
## [MEDIUM] Cookie 'PHPSESSID' lacks HttpOnly, SameSite
...
```

## What it checks

| Check | Looks for |
|---|---|
| `headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; version strings in `Server`/`X-Powered-By` |
| `cookies` | Session cookies missing `HttpOnly`, `Secure` or `SameSite` |
| `cors` | `Access-Control-Allow-Origin` reflecting an arbitrary origin, especially combined with credentials |
| `methods` | `TRACE` enabled; risky methods (`PUT`, `DELETE`, `PATCH`) advertised via `OPTIONS` |
| `exposure` | Leftover `.git/HEAD`, `.env`, backup files, `phpinfo.php`, `server-status`, published API docs |
| `listing` | Directory listing enabled on common paths |
| `errors` | Stack traces or SQL error text leaking from a malformed request |
| `auth` | Endpoints (from `--endpoints` or auto-discovered via an OpenAPI/Swagger document) that return the same data with and without a bearer token |

Pages that answer 200 to everything (soft-404 sites) are detected and excluded from the `exposure` check, to avoid false positives.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

Tests run two local servers — one deliberately misconfigured, one hardened — and assert the checker flags the first and stays quiet on the second.

## Project layout

```
apicheck/
  checks.py   each check, independent and testable
  cli.py      the python -m apicheck entry point
tests/
  test_checks.py
```

## License

MIT — see [LICENSE](LICENSE).
