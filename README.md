# Security report 2026-11-12

Generated 2026-11-12 13:48 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (11)

- **CVE-2026-65982** CVSS 8.7 HIGH - nginx-http-flv-module is a media streaming server based on nginx-rtmp-module. Prior to version 1.2.14, if a server received an HTTP/1.0 request without a header Host, which was permitted by HTTP core of Nginx, then r-&gt;h… - **watching: nginx** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-65982)
- **CVE-2026-123866** CVSS 7.5 HIGH - A use-after-free in Node.js HTTP/2 stream teardown can leak response memory, including the contents of other connections' response buffers, to a peer. When a stream is torn down while a write is still backpressured, for… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123866)
- **CVE-2026-123874** CVSS 7.5 HIGH - A use-after-free in Node.js HTTP/2 lets an unauthenticated client corrupt server memory, over both TLS and cleartext, when the server serves files with respondWithFile\(\) or respondWithFD\(\). A client can make the server… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123874)
- **CVE-2026-106023** UNSCORED - NULL pointer dereference vulnerability in Apache HTTP Server's mod\_md during HTTP request processing. This issue affects Apache HTTP Server: from 2.4.30 through 2.4.69. - **watching: apache-httpd** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106023)
- **CVE-2026-109163** UNSCORED - Stack-based buffer overflow vulnerability in Apache HTTP Server's mod\_vhost\_alias \(after CVE-2026-63292\) This issue affects Apache HTTP Server: 2.4.69. - **watching: apache-httpd** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-109163)
- **go 1.26** - REVIEW: upstream go 1.26 is 1.26.11, advisories.tsv is reviewed up to 1.26.10. Read the release notes for new security fixes and update the rules. - **watching: go**
- **go 1.27** - REVIEW: upstream go 1.27 is 1.27.4, advisories.tsv is reviewed up to 1.27.3. Read the release notes for new security fixes and update the rules. - **watching: go**
- **node 22** - REVIEW: upstream node 22 is 22.23.5, advisories.tsv is reviewed up to 22.23.4 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 24** - REVIEW: upstream node 24 is 24.22.3, advisories.tsv is reviewed up to 24.22.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.1, advisories.tsv is reviewed up to 26.12.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-65982** CVSS 8.7 HIGH - nginx-http-flv-module is a media streaming server based on nginx-rtmp-module. Prior to version 1.2.14, if a server received an HTTP/1.0 request without a header Host, which was permitted by HTTP core of Nginx, then r-&gt;h… - **watching: nginx** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-65982)
- **CVE-2026-123866** CVSS 7.5 HIGH - A use-after-free in Node.js HTTP/2 stream teardown can leak response memory, including the contents of other connections' response buffers, to a peer. When a stream is torn down while a write is still backpressured, for… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123866)
- **CVE-2026-123874** CVSS 7.5 HIGH - A use-after-free in Node.js HTTP/2 lets an unauthenticated client corrupt server memory, over both TLS and cleartext, when the server serves files with respondWithFile\(\) or respondWithFD\(\). A client can make the server… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123874)
- **CVE-2026-106023** UNSCORED - NULL pointer dereference vulnerability in Apache HTTP Server's mod\_md during HTTP request processing. This issue affects Apache HTTP Server: from 2.4.30 through 2.4.69. - **watching: apache-httpd** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106023)
- **CVE-2026-109163** UNSCORED - Stack-based buffer overflow vulnerability in Apache HTTP Server's mod\_vhost\_alias \(after CVE-2026-63292\) This issue affects Apache HTTP Server: 2.4.69. - **watching: apache-httpd** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-109163)
- **CVE-2026-124815** CVSS 10.0 CRITICAL - The Clockinator Lite WordPress plugin before 1.1.0 does not restrict access to several of its record deletion actions, and uses a user-supplied table name in a SQL query without validating or escaping it, allowing unaut… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-124815)
- **CVE-2026-110697** CVSS 9.9 CRITICAL - A flaw was found in Quay where the robot account listing function constructs a SQL LIKE pattern from user-controlled namespace names without escaping wildcard metacharacters. An attacker who creates a namespace containi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110697)
- **CVE-2026-12591** CVSS 9.9 CRITICAL - Zohocorp ManageEngine M365 Manager Plus versions below 4818 is affected by an authenticated technician may exploit insufficient permission validation in the delegated administration interface to escalate privileges beyo… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-12591)
- **CVE-2026-110959** CVSS 9.8 CRITICAL - The Descope WordPress plugin before 1.2.0 does not validate the authentication token it receives before creating a WordPress session, accepting any non-empty token, so an unauthenticated attacker can obtain a session fo… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110959)
- **CVE-2026-123710** CVSS 9.8 CRITICAL - A flaw was found in Red Hat Quay. An unauthenticated client can obtain an anonymous registry token with an audience it controls, present that token to the service key rotation endpoint, and install its own approved sign… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123710)
- **CVE-2026-124814** CVSS 9.8 CRITICAL - The Ultimate Addons for Elementor Forms WordPress plugin before 1.0.8 does not properly validate the extension of uploaded files in its bundled file upload field, allowing unauthenticated users to upload arbitrary files… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-124814)
- **CVE-2026-126147** CVSS 9.8 CRITICAL - A improper limitation of a pathname to a restricted directory \('path traversal'\) vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2 all v… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126147)
- **CVE-2026-126148** CVSS 9.8 CRITICAL - A improper neutralization of special elements used in an os command \('os command injection'\) vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6 may allow an unauthenticated attacker t… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126148)
- **CVE-2026-126170** CVSS 9.8 CRITICAL - A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer Cloud 8.0.1 through 8.0.2, FortiAnalyzer Cloud 7.6.0 through 7.6.7,… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126170)
- **CVE-2026-126259** CVSS 9.8 CRITICAL - A missing authentication for critical function vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated attacker with… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126259)
- **CVE-2026-126262** CVSS 9.8 CRITICAL - A improper neutralization of special elements used in an sql command \('sql injection'\) vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer 7.4.0 through 7.4.11,… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126262)
- **CVE-2026-126263** CVSS 9.8 CRITICAL - A improper neutralization of special elements used in an sql command \('sql injection'\) vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.4, FortiMail 7.4.0 through 7.4.6 may allow an a… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126263)
- **CVE-2026-67449** CVSS 9.8 CRITICAL - Portabase is a database backup and restore tool for PostgreSQL, MySQL, MsSQL, MariaDB, Firebird SQL, SQLite, MongoDB, Redis, Files and Docker Volume. Prior to version 1.21.2, a path traversal in the TUS upload webhook h… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-67449)
- **CVE-2026-76954** CVSS 9.8 CRITICAL - An improper neutralization of special elements used in an SQL command vulnerability in the Auth API in Synology DiskStation Manager \(DSM\) before 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, and 7.4.1-90080-1 allows re… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-76954)
- **CVE-2026-126254** CVSS 9.6 CRITICAL - A numeric truncation error vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow a configured ibgp neighbor to send mali… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126254)
- **CVE-2026-65840** CVSS 9.6 CRITICAL - Fider is a feedback portal for feature requests and suggestions. Prior to version 0.36.0, in multi-tenant mode \(HOST\_MODE=multi\), an attacker can use an email verification key issued by Tenant A to authenticate as the s… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-65840)
- **CVE-2026-126164** CVSS 9.4 CRITICAL - A improper neutralization of special elements used in an sql command \('sql injection'\) vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126164)
- **CVE-2026-8333** CVSS 9.4 CRITICAL - A stored cross-site scripting vulnerability in Microchip the TimePictra platform could allow an authenticated, low-privileged attacker to store malicious script content that executes when another user views the affected… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-8333)
- **CVE-2026-110003** CVSS 9.3 CRITICAL - A vulnerability in the administration REST interface of Azul Payara allows a remote, unauthenticated attacker to bypass secure-admin remote-access restrictions by supplying an arbitrary value in the X-GlassFish-authToke… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110003)
- **CVE-2026-126253** CVSS 9.3 CRITICAL - A authentication bypass by primary weakness vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated att… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126253)
- ...and 23 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

No matching advisories in the window.

## Node.js releases in window

- **node 27.0.0-alpha.0.1.0** - Node.js 27.0.0-alpha.0.1.0 released - **watching: node.js** - [source](https://nodejs.org/en/blog/vulnerability)
- **node 22.23.5** - Node.js 22.23.5 released \(security release\) - **watching: node.js** - [source](https://nodejs.org/en/blog/vulnerability)

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |
|---|---|---|---|---|
| go | 1.26 | 1.26.11 | 1.26.10 | - |
| go | 1.27 | 1.27.4 | 1.27.3 | - |
| node | 22 | 22.23.5 | 22.23.4 | - |
| node | 24 | 24.22.3 | 24.22.1 | - |
| node | 26 | 26.13.1 | 26.12.1 | - |
| node | 27 | 27.0.0-alpha.0.1.0 | - | - |
| php | 8.2 | 8.2.35 | 8.2.35 | - |
| php | 8.3 | 8.3.36 | 8.3.36 | - |
| php | 8.4 | 8.4.27 | 8.4.27 | - |
| php | 8.5 | 8.5.12 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.11.10 |
| NVD \(new CVEs\) | OK | 48 | 550 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 25 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 2 | 882 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
