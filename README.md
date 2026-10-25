# Security report 2026-10-25

Generated 2026-10-25 09:50 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (2)

- **CVE-2026-115557** CVSS 9.4 CRITICAL - Python has added a denylist for known compromised certificates to the "ssl" module to ensure user safety even without certificate revocation configured. Known compromised certificates will automatically be rejected rega… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115557)
- **CVE-2026-114820** CVSS 9.1 CRITICAL - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE \(component: JSSE\). Supported versions that are affected are Oracle Java SE: 8u511-b32, 8u511-perf-… - **watching: java** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114820)

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-115557** CVSS 9.4 CRITICAL - Python has added a denylist for known compromised certificates to the "ssl" module to ensure user safety even without certificate revocation configured. Known compromised certificates will automatically be rejected rega… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115557)
- **CVE-2026-114820** CVSS 9.1 CRITICAL - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE \(component: JSSE\). Supported versions that are affected are Oracle Java SE: 8u511-b32, 8u511-perf-… - **watching: java** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114820)
- **CVE-2026-115933** CVSS 9.9 CRITICAL - Postiz signs its session, invitation and password reset tokens with one shared secret and without any marker of what a token is for. A route that refreshes the credentials of a browser-extension channel signed data take… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115933)
- **CVE-2026-115932** CVSS 9.6 CRITICAL - When a post is published, Postiz treats a media path that is not a web address as a file on the server's disk, but it does not check that the file lies inside the upload directory. A registered user can store a crafted… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115932)
- **CVE-2026-115995** CVSS 9.4 CRITICAL - A security vulnerability has been detected in Unitree Robotics Unitree Go2 up to 1.1.11.4. The impacted element is the function set\_volume of the file gpt\_thread.py of the component chat\_go. Such manipulation of the arg… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115995)
- **CVE-2026-116014** CVSS 9.2 CRITICAL - open62541 1.5.0 before 1.5.7 contains an integer overflow in UA\_DataType\_fromStructureDescription\(\) that wraps the 16-bit memSize field for large custom structure definitions. A malicious OPC UA server can supply DataTy… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116014)

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
| NVD \(new CVEs\) | OK | 6 | 66 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 3 more only mention one \(apps, plugins, libraries\) and are not li… |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 875 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
