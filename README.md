# Security report 2026-11-23

Generated 2026-11-23 16:01 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (10)

- **go 1.26** - REVIEW: upstream go 1.26 is 1.26.11, advisories.tsv is reviewed up to 1.26.10. Read the release notes for new security fixes and update the rules. - **watching: go**
- **go 1.27** - REVIEW: upstream go 1.27 is 1.27.4, advisories.tsv is reviewed up to 1.27.3. Read the release notes for new security fixes and update the rules. - **watching: go**
- **node 22** - REVIEW: upstream node 22 is 22.23.5, advisories.tsv is reviewed up to 22.23.4 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 24** - REVIEW: upstream node 24 is 24.22.3, advisories.tsv is reviewed up to 24.22.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.1, advisories.tsv is reviewed up to 26.12.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **php 8.2** - REVIEW: upstream php 8.2 is 8.2.36, advisories.tsv is reviewed up to 8.2.35. Read the release notes for new security fixes and update the rules. - **watching: php**
- **php 8.3** - REVIEW: upstream php 8.3 is 8.3.37, advisories.tsv is reviewed up to 8.3.36. Read the release notes for new security fixes and update the rules. - **watching: php**
- **php 8.4** - REVIEW: upstream php 8.4 is 8.4.28, advisories.tsv is reviewed up to 8.4.27. Read the release notes for new security fixes and update the rules. - **watching: php**
- **php 8.5** - REVIEW: upstream php 8.5 is 8.5.13, advisories.tsv is reviewed up to 8.5.12. Read the release notes for new security fixes and update the rules. - **watching: php**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-134882** CVSS 10.0 CRITICAL - A weakness has been identified in TOTOLINK A7100RU 7.4cu.2313\_B20191024. This issue affects the function exportOvpn of the file /cgi-bin/cstecgi.cgi of the component CGI Handler. This manipulation of the argument Userna… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134882)
- **CVE-2026-120382** CVSS 9.8 CRITICAL - An improper neutralization of argument delimiters in a command vulnerability in the OAuth API in Synology DiskStation Manager \(DSM\) before 7.1.1-42962-10, 7.2.1-69057-14, 7.2.2-72806-11, 7.3.2-86009-6, and 7.4.1-90080-2… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120382)
- **CVE-2026-115899** CVSS 9.3 CRITICAL - An attacker must control pagination data returned by an upstream API or service queried by an existing REST Collector. The Collector must use affected response-based pagination and process the crafted data during a job… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115899)
- **CVE-2026-121613** CVSS 9.3 CRITICAL - Missing authentication and authorization on an exposed interface allows an unauthenticated remote attacker to send arbitrary commands to the affected component, which can force a device reboot or let the attacker upload… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121613)
- **CVE-2026-134624** CVSS 9.3 CRITICAL - N-able MailAssure \(SpamExperts\) before 20261121.1943 does not restrict the destination of the LDAP synchronisation connection check performed when a relay is configured. An authenticated API user can cause the server to… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134624)
- **CVE-2026-134814** CVSS 9.2 CRITICAL - binary-parser before 2.3.1 contains a code injection vulnerability that allows attackers controlling parser definitions to inject JavaScript through string-typed options passed unvalidated by Context.generateOption\(\). A… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134814)
- **CVE-2026-134815** CVSS 9.2 CRITICAL - simple-git before 4.1.0 contains an argument injection vulnerability that allows attackers to bypass the allowUnsafePack guard by supplying the --exec option to non-push git operations. Attackers who influence arguments… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134815)
- **CVE-2026-135161** CVSS 9.2 CRITICAL - Interstellar before 6.3.0 contains a server-side request forgery vulnerability that allows unauthenticated attackers to reach internal services by enabling allow\_loopback\_ips and allow\_private\_ips in wisp-js at startup.… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135161)
- **CVE-2026-135171** CVSS 9.2 CRITICAL - Wing FTP Server before 8.2.8 contains a predictable session identifier vulnerability that allows unauthenticated attackers to hijack administrator sessions by deriving identifiers from process, time, ServerID, and clien… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135171)
- **CVE-2026-135174** CVSS 9.2 CRITICAL - Softaculous Virtualizor before 3.2.9 contains an SQL injection vulnerability in enduser/auth\_callback.php that allows unauthenticated attackers to bypass authentication via OAuth-returned email addresses. Attackers can… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135174)
- **CVE-2026-134838** CVSS 9.1 CRITICAL - Weblate before 2026.11 contains an account takeover vulnerability in the reset\_password view that allows unauthenticated attackers to reset victim passwords by abusing case-insensitive Unicode e-mail matching. Attackers… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134838)
- **CVE-2026-135163** CVSS 9.1 CRITICAL - Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated a… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135163)

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

No matching advisories in the window.

## Node.js releases in window

No Node.js release in the window.

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |
|---|---|---|---|---|
| go | 1.26 | 1.26.11 | 1.26.10 | - |
| go | 1.27 | 1.27.4 | 1.27.3 | - |
| node | 22 | 22.23.5 | 22.23.4 | - |
| node | 24 | 24.22.3 | 24.22.1 | - |
| node | 26 | 26.13.1 | 26.12.1 | - |
| node | 27 | 27.0.0-alpha.0.1.1 | - | - |
| php | 8.2 | 8.2.36 | 8.2.35 | - |
| php | 8.3 | 8.3.37 | 8.3.36 | - |
| php | 8.4 | 8.4.28 | 8.4.27 | - |
| php | 8.5 | 8.5.13 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.11.23 |
| NVD \(new CVEs\) | OK | 12 | 203 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 9 more only mention one \(apps, plugins, libraries\) and are not l… |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 883 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
