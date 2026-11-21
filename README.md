# Security report 2026-11-21

Generated 2026-11-21 13:29 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

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

- **CVE-2025-42884** - SAP NetWeaver - SAP NetWeaver Improper Neutralization of Special Elements in Data Query Logic Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2025-42884)
- **CVE-2026-123890** - Broadcom VMware vCenter - VMWare vCenter Authentication Bypass Using an Alternate Path or Channel Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123890)
- **CVE-2026-129448** - Apache Roller - Apache Roller Deserialization of Untrusted Data Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129448)
- **CVE-2026-76466** - Cisco Expressway Series - Cisco Expressway Series Use of Hard-coded Credentials Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-76466)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-14914** CVSS 10.0 CRITICAL - Unrestricted upload of file with dangerous type vulnerability in Tegsoft Yönetim ve Bilişim Hizmetleri Tic. Ltd. Şti. Tegsoft Contact Center allows Upload a Web Shell to a Web Server. This issue affects Tegsoft Contact… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-14914)
- **CVE-2026-120539** CVSS 9.8 CRITICAL - The Restrictions for BuddyPress plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.5.4 This is due to the plugin splicing the attacker-controlled request URI into a PHP e… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120539)
- **CVE-2026-129039** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data vulnerability in Tribulant Software Newsletters newsletters-lite allows Object Injection.This issue affects Newsletters: from n/a through 4.18.2. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129039)
- **CVE-2026-133968** CVSS 9.8 CRITICAL - monailabel \(aka MONAI Label\) through 0.8.5 allows directory traversal, with resultant remote code execution, via the image parameter to the PUT /datastore/image endpoint, as exploited in the wild starting in September 2… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133968)
- **CVE-2026-80188** CVSS 9.8 CRITICAL - The BuddyBoss Addons plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeover in versions up to, and including, 1.2.1. This is due to the Social Login REST endpoint trusting unverified App… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-80188)
- **CVE-2026-132658** CVSS 9.4 CRITICAL - In Postgres Enterprise Manager \(PEM\), the pem\_agent role, which every PEM agent login inherits, is a member of the PostgreSQL pg\_read\_server\_files and pg\_write\_server\_files roles on the PEM backend database. An attacker… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-132658)
- **CVE-2026-132659** CVSS 9.4 CRITICAL - In Postgres Enterprise Manager \(PEM\), the row-level security policies on pem.job and pem.jobstep that apply to PEM agents do not limit an agent to its own jobs. An attacker who controls one monitored host, and so its PE… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-132659)
- **CVE-2026-132660** CVSS 9.4 CRITICAL - In Postgres Enterprise Manager \(PEM\), several SECURITY DEFINER functions in the pem schema of the PEM backend database are owned by a superuser but do not set a safe search\_path. Any PEM user who can connect to the PEM… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-132660)
- **CVE-2026-126054** CVSS 9.3 CRITICAL - A Path Traversal vulnerability in workspace directory handling and Git integration in Google Cloud Dataform, BigQuery Studio and Colab Enterprise on Google Cloud Platform allows an authenticated remote attacker to read… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126054)
- **CVE-2026-129043** CVSS 9.3 CRITICAL - Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\) vulnerability in Tribulant Software Newsletters newsletters-lite allows SQL Injection.This issue affects Newsletters: from n/a through… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129043)
- **CVE-2026-129175** CVSS 9.3 CRITICAL - U.S Department of the Interior Unstable Slope Management Program allows an unauthenticated user to inject unauthorized SQL commands that allow the attacker to gain root access and complete control over the database. Fix… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129175)
- **CVE-2026-133949** CVSS 9.3 CRITICAL - pip prior to v26.2.2 the certifi bundled with pip contains the compromised eMudhra certificates. Upgrading to a secure version of pip should be done either by first upgrading Python to a version that rejects the comprom… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133949)
- **CVE-2026-62318** CVSS 9.3 CRITICAL - Netatalk is a Free and Open Source file server suite for Unix-like operating systems. From 2.0.0 until 4.5.1, the DHX2 and DHX2-PAM authentication state machine in etc/uams/uams\_dhx2\_pam.c permits logincont1 to be invok… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62318)
- **CVE-2026-94565** CVSS 9.3 CRITICAL - NukeViet CMS is a multi Content Management System. From the 3.x release line until 4.6.01, an unauthenticated visitor can submit a Contact module message containing an event-handler attribute prefixed by a slash. NukeVi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-94565)
- **CVE-2026-94567** CVSS 9.3 CRITICAL - NukeViet CMS is a multi Content Management System. Prior to 4.5.12 and 4.6.02, an attacker with access to an SVG upload flow can hide a script element in an internal DTD entity. NukeViet\\Files\\Upload::check\_svg\_tmpfile\(… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-94567)
- **CVE-2026-127027** CVSS 9.2 CRITICAL - Poste.io is vulnerable to remote code execution in DMARC report processing. Email sent to dmarc-reports@​&lt;domain&gt; is saved without sender verification. Script that runs as root unpacks the attachments using unsafe shell… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-127027)
- **CVE-2026-115407** CVSS 9.1 CRITICAL - In \`github.com/eclipse-keypont/crypto11/v2\` versions \`&lt;= 2.0.0-rc8\` \(and the deprecated v1 module paths \`github.com/eclipse-keypont/crypto11 &lt;= 1.6.8\`, \`github.com/ThalesGroup/crypto11 &lt;= 1.7.0-rc1\` and \`github.com/Thal… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115407)
- **CVE-2026-133872** CVSS 9.1 CRITICAL - LessPass self-hosted sync server backend before commit 9469b0c lacks rate limiting on the JWT login endpoints /tokens/auth/ and /auth/jwt/create/, allowing unlimited authentication attempts. Unauthenticated remote attac… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133872)
- **CVE-2026-133212** CVSS 9.0 CRITICAL - @​fastify/reply-from is a Fastify plugin that forwards an incoming HTTP request to an upstream server. In versions before 12.9.1, when the plugin forwards a request whose body is not written to the upstream connection, s… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133212)

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-4hrh-34w3-5ww8** CRITICAL - Fabio: Access-control bypass through unnormalized request paths (go:github.com/fabiolb/fabio \(fixed 1.7.3\)) - [source](https://github.com/advisories/GHSA-4hrh-34w3-5ww8)
- **GHSA-25qc-m4pw-2w8r** HIGH - Budibase: Unauthenticated global-admin &amp; database creation via tenant-confusion bypass of the one-time init guard \(\`POST /api/global/users/init\`\) (npm:@​budibase/server) - [source](https://github.com/advisories/GHSA-25qc-m4pw-2w8r)
- **GHSA-2hjf-7455-w946** HIGH - aMQTT: Inefficient Regular Expression Complexity and Uncontrolled Resource Consumption and Improper Input Validation (pip:amqtt \(fixed 0.11.4\)) - [source](https://github.com/advisories/GHSA-2hjf-7455-w946)
- **GHSA-555j-qj3j-c8jv** HIGH - svglib: Exponential resource consumption via nested &lt;use&gt; references in svg2rlg (pip:svglib \(fixed 2.3.1\)) - [source](https://github.com/advisories/GHSA-555j-qj3j-c8jv)
- **GHSA-66q9-mxf2-xqw6** HIGH - TeamPass folder re-parenting authorization bypass (composer:nilsteampassnet/TeamPass \(fixed 3.2.2.0\)) - [source](https://github.com/advisories/GHSA-66q9-mxf2-xqw6)
- **GHSA-9657-8vc2-7g2p** HIGH - Poweradmin: The email second factor is an mt\_rand\(\) six-digit code verified with no attempt limit or lockout, so an attacker holding the password can brute-force it within the validity window (composer:poweradmin/poweradmin \(fixed 4.2.6\), composer:poweradmin/poweradmin \(fixed 4.3.5\), composer:poweradmin/poweradmin \(fixed 4.4.1\)) - [source](https://github.com/advisories/GHSA-9657-8vc2-7g2p)
- **GHSA-hghq-53p7-c582** HIGH - go-guerrilla crashes on a bare XCLIENT command \(7-byte slice off-by-one panic\) (go:github.com/phires/go-guerrilla, go:github.com/phires/go-guerrilla \(fixed 1.6.7-1\)) - [source](https://github.com/advisories/GHSA-hghq-53p7-c582)
- **GHSA-jrjx-9jjw-747m** HIGH - AIT-GUI route chain allows unauthenticated Python execution in server process (pip:ait-gui \(fixed 2.5.1\)) - [source](https://github.com/advisories/GHSA-jrjx-9jjw-747m)
- **GHSA-jwgx-mp9m-jwcr** HIGH - appium allows unauthenticated arbitrary file/directory deletion in @​appium/storage-plugin (npm:@​appium/storage-plugin \(fixed 1.1.6\)) - [source](https://github.com/advisories/GHSA-jwgx-mp9m-jwcr)
- **GHSA-prhx-9q2h-ph2x** HIGH - Paymenter: Unauthenticated arbitrary method invocation in Livewire components (composer:paymenter/paymenter \(fixed 1.5.7\)) - [source](https://github.com/advisories/GHSA-prhx-9q2h-ph2x)
- **GHSA-r2q3-7m4h-63qg** HIGH - Budibase: Cross-privilege Stored XSS in the Budibase Builder via broken HTML-escaping in \`jsonFormatter.format\(\)\` rendered through \`{@​html}\` in the CSP-less Builder origin (npm:@​budibase/server) - [source](https://github.com/advisories/GHSA-r2q3-7m4h-63qg)
- **GHSA-r9qp-pqx5-8369** HIGH - contao/core-bundle: Non-admin users can self-grant permissions that implicitly make them administrators (composer:contao/core-bundle \(fixed 5.3.50\), composer:contao/core-bundle \(fixed 5.7.12\)) - [source](https://github.com/advisories/GHSA-r9qp-pqx5-8369)
- **GHSA-v9v2-98xq-627c** HIGH - pREST \_groupby function-expression SQL injection \(incomplete fix of CVE-2025-58450\) (go:github.com/prest/prest, go:github.com/prest/prest/v2 \(fixed 2.4.0\)) - [source](https://github.com/advisories/GHSA-v9v2-98xq-627c)
- **GHSA-w3f2-pr6x-wwjc** HIGH - Git LFS may attempt arbitrary remote commands via crafted SSH URLs (go:github.com/git-lfs/git-lfs, go:github.com/git-lfs/git-lfs/v3 \(fixed 3.8.1\)) - [source](https://github.com/advisories/GHSA-w3f2-pr6x-wwjc)
- **GHSA-wcqj-wx85-c75p** HIGH - aMQTT: Denial of Service \(DoS\) via Memory Leak in Unmanaged QoS 2 Session Handshakes (pip:amqtt \(fixed 0.12.1\)) - [source](https://github.com/advisories/GHSA-wcqj-wx85-c75p)
- **GHSA-x72p-hmqp-46hw** HIGH - Git LFS may execute arbitrary commands via crafted Git LFS configurations (go:github.com/git-lfs/git-lfs, go:github.com/git-lfs/git-lfs/v3 \(fixed 3.8.1\)) - [source](https://github.com/advisories/GHSA-x72p-hmqp-46hw)
- **GHSA-x7xj-4j4f-88xr** HIGH - Git LFS may leak HTTP headers after redirections (go:github.com/git-lfs/git-lfs, go:github.com/git-lfs/git-lfs/v3 \(fixed 3.8.1\)) - [source](https://github.com/advisories/GHSA-x7xj-4j4f-88xr)
- **GHSA-xrgv-7vx6-5vx6** HIGH - Git LFS may execute arbitrary commands via crafted Git configurations (go:github.com/git-lfs/git-lfs, go:github.com/git-lfs/git-lfs/v3 \(fixed 3.8.1\)) - [source](https://github.com/advisories/GHSA-xrgv-7vx6-5vx6)
- **GHSA-xxqp-5qx8-gj5q** HIGH - Aedes has Uncaught Exception and Uncontrolled Resource Consumption (npm:aedes \(fixed 1.1.1\)) - [source](https://github.com/advisories/GHSA-xxqp-5qx8-gj5q)

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
| CISA Known Exploited Vulnerabilities | OK | 4 | catalog 2026.11.20 |
| NVD \(new CVEs\) | OK | 19 | 379 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 25 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 19 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 883 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
