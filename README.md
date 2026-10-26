# Security report 2026-10-26

Generated 2026-10-26 11:09 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (0)

Nothing flagged for the watchlist or the tracked runtimes.

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-116199** CVSS 9.2 CRITICAL - Snipe-IT before 8.6.3 contains an authentication bypass in GoogleAuthController::handleGoogleCallback, which logs in the user whose username matches the Google account email without enforcing the activated flag. Deactiv… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116199)
- **CVE-2026-116163** CVSS 9.1 CRITICAL - Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, validateLogin, and validateUpdate methods of custom adapters subclassing AuthAdapter are never cal… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116163)
- **CVE-2026-116070** CVSS 6.9 MEDIUM - Docker-Proxy through 5.1.9 contains a missing authentication vulnerability in the hubcmdui routes/config.js that allows unauthenticated attackers to read and overwrite configuration via /api/config. Attackers can retrie… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116070)

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

No matching advisories in the window.

## Node.js releases in window

No Node.js release in the window.

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |
|---|---|---|---|---|
| go | 1.26 | 1.26.10 | 1.26.10 | - |
| go | 1.27 | 1.27.3 | 1.27.3 | - |
| node | 22 | 22.23.4 | 22.23.4 | - |
| node | 24 | 24.22.1 | 24.22.1 | - |
| node | 26 | 26.12.1 | 26.12.1 | - |
| php | 8.2 | 8.2.35 | 8.2.35 | - |
| php | 8.3 | 8.3.36 | 8.3.36 | - |
| php | 8.4 | 8.4.27 | 8.4.27 | - |
| php | 8.5 | 8.5.12 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.10.23 |
| NVD \(new CVEs\) | OK | 3 | 194 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 5 more only mention one \(apps, plugins, libraries\) and are not l… |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 875 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
