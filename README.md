# Security report 2026-11-02

Generated 2026-11-02 13:32 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

> **INCOMPLETE REPORT.** 1 source(s) failed: nvd. Missing data is not the same as no incidents.

## Needs attention (3)

- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

> **Source unavailable.** This section is incomplete. Do not read it as "nothing happened".

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
| node | 24 | 24.22.2 | 24.22.1 | - |
| node | 26 | 26.13.0 | 26.12.1 | - |
| node | 27 | 27.0.0-alpha.0.0.0 | - | - |
| php | 8.2 | 8.2.35 | 8.2.35 | - |
| php | 8.3 | 8.3.36 | 8.3.36 | - |
| php | 8.4 | 8.4.27 | 8.4.27 | - |
| php | 8.5 | 8.5.12 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.10.30 |
| NVD \(new CVEs\) | **FAILED** | 0 | HTTP 503 for https:​//services.nvd.nist.gov/rest/json/cves/2.0 |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 878 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
