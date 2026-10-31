# Security report 2026-10-31

Generated 2026-10-31 10:57 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (4)

- **CVE-2026-119977** CVSS 8.1 HIGH - WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenti… - **watching: wordpress-core** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119977)
- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

- **CVE-2026-111357** - Ivanti Connect Secure - Ivanti Connect Secure Missing Authentication for Critical Function Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-111357)
- **CVE-2026-118527** - Ivanti Connect Secure - Ivanti Connect Secure Generation of Predictable Numbers or Identifiers Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118527)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-119977** CVSS 8.1 HIGH - WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenti… - **watching: wordpress-core** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119977)
- **CVE-2026-112816** CVSS 10.0 CRITICAL - Improper certificate validation in the HTTPS listener in Canonical LXD 4.0.14, 5.0.10, 5.21.8, 6.9 before 4.0.15, 5.0.11, 5.21.9, 6.10.1 allows an unauthenticated attacker to authenticate as any trusted client and gain… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-112816)
- **CVE-2026-61738** CVSS 10.0 CRITICAL - SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. Prior to 0.1.77, \`POST /api/scoutsuite/generate-gcp-report\` in \`backend/app/integrations/scoutsuite/routes/scoutsui… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61738)
- **CVE-2026-61826** CVSS 10.0 CRITICAL - Bazarr is a companion application to Sonarr and Radarr. Prior to 1.5.7-beta.14, the \`api\_ns\_plex\` namespace in \`bazarr/api/plex/oauth.py\` omits \`@​authenticate\` on its Resource handlers, while normal APIs require an API… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61826)
- **CVE-2026-61728** CVSS 9.9 CRITICAL - SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. In affected snapshots preceding the respective 0.1.70 and 0.1.76 sink repairs, portal users, including \`customer\_us… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61728)
- **CVE-2026-62853** CVSS 9.9 CRITICAL - ThingLinks is an enterprise IoT platform. Prior to 1.4.0, the \`/groovyScriptTest/registerScript\` endpoint accepts user-supplied Groovy script content and passes it to an unsandboxed \`Groovy compilation and loading\` flow… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62853)
- **CVE-2025-31704** CVSS 9.8 CRITICAL - A vulnerability has been found in the Dahua Intelligent Connection Center. A remote attacker could send a specially crafted request to the affected system, allowing the attacker to execute arbitrary commands, resulting… - [source](https://nvd.nist.gov/vuln/detail/CVE-2025-31704)
- **CVE-2026-109220** CVSS 9.8 CRITICAL - The PDF Invoice for WooCommerce + Drag and Drop Template Builder plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 7.1.1 via the 'customer\_note' parameter parameter. This i… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-109220)
- **CVE-2026-110799** CVSS 9.8 CRITICAL - Vvveb is a powerful and easy to use CMS with page builder to build websites, blogs or ecommerce stores. Prior to version 1.0.8.7, the password reset functionality is vulnerable to an Authentication Bypass due to insuffi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110799)
- **CVE-2026-116386** CVSS 9.8 CRITICAL - Unauthenticated Privilege Escalation in SMS Alert Order Notifications &lt;= 4.0.2 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116386)
- **CVE-2026-116512** CVSS 9.8 CRITICAL - The Project Manager – AI Powered Project Management, Task Management, Kanban Board &amp; Time Tracker plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.1.1 via the 'id' para… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116512)
- **CVE-2026-118235** CVSS 9.8 CRITICAL - The SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 3.10.2 via the handle\_upload functi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118235)
- **CVE-2026-119096** CVSS 9.8 CRITICAL - The Uncanny Toolkit for LearnDash plugin for WordPress is vulnerable to Authentication Bypass in versions up to, and including, 3.8.2 via the \`email\` parameter of the \`uo\_login\_action\(\)\` function. This is due to a parse… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119096)
- **CVE-2026-119526** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data vulnerability in ThemeREX Royal Event allows Object Injection. This issue affects Royal Event: from n/a through 2.0. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119526)
- **CVE-2026-39738** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in FunnelKit Automations &lt;= 3.8.6.1 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-39738)
- **CVE-2026-61620** CVSS 9.8 CRITICAL - HoneySQL turns Clojure data structures into SQL. From 2.0.0 until 2.7.1392, applications that pass user input or other arbitrary data into the HoneySQL \`DSL\` by calling \`keyword\` or \`symbol\` on that input can produce SQ… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61620)
- **CVE-2026-61737** CVSS 9.8 CRITICAL - ng-antd-admin is an Angular and NestJS administration system template. Prior to 22.0, a hardcoded default \`JWT\` secret permits token forgery when a deployment has not replaced the default secret, without a startup warni… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61737)
- **CVE-2026-63377** CVSS 9.8 CRITICAL - TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, \`POST /api/auth/setup\` in \`src/api/routers/auth.py\` allows an unauthenticate… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-63377)
- **CVE-2026-90888** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in LeadSnap &lt;= 1.25 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-90888)
- **CVE-2026-62863** CVSS 9.6 CRITICAL - MoLing is a computer-use and browser-use based MCP server. Prior to 0.5.0, when MoLing runs in SSE mode using \`-l\`, its \`/sse\` and \`/message\` HTTP endpoints do not authenticate requests and the \`mcp-go\` dependency sets… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62863)
- **CVE-2026-116366** CVSS 9.5 CRITICAL - An issue has been discovered in ClickHouse Server that, under certain conditions, could allow an unauthenticated user with network access to execute arbitrary code on the ClickHouse Server. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116366)
- **CVE-2026-116241** CVSS 9.4 CRITICAL - pgAdmin 4's Import/Export Data tool wraps a user's query export in a psql \\copy \(...\) TO command and checks that the query's parentheses are balanced so that nothing can escape the wrapper. The check rejected a backslas… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116241)
- **CVE-2026-61729** CVSS 9.4 CRITICAL - SOCFortress CoPilot focuses on providing a single pane of glass for all your security operations needs. Prior to 0.1.76, \`verify\_graylog\_header\` in \`backend/app/active\_response/routes/graylog.py\` and \`verify\_velocirapto… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61729)
- **CVE-2026-93327** CVSS 9.4 CRITICAL - A Deserialization of Untrusted Data vulnerability in the SubWorkflow task in Google Cloud Application Integration versions prior to 2026-09-11 on Google Cloud Platform allows an authenticated attacker to execute arbitra… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-93327)
- **CVE-2026-117656** CVSS 9.3 CRITICAL - Acceptance of Extraneous Untrusted Data With Trusted Data vulnerability in the Sign in with Apple strategy in pow-auth Assent allows an unauthenticated remote attacker to impersonate another user via the user parameter… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-117656)
- ...and 23 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-4xm8-rg9h-jhq2** CRITICAL - Signal K resources API path traversal can disclose the JWT signing secret and enable remote code execution (npm:signalk-server \(fixed 2.34.0\), npm:@​signalk/resources-provider \(fixed 1.5.3\)) - [source](https://github.com/advisories/GHSA-4xm8-rg9h-jhq2)
- **GHSA-5xjx-3w67-w9x9** CRITICAL - pypi-publish action revocation of CA in the chain that Sigstore uses in Trusted Publishing and Digital Attestations for PyPI (actions:pypa/gh-action-pypi-publish \(fixed 1.14.3\)) - [source](https://github.com/advisories/GHSA-5xjx-3w67-w9x9)
- **GHSA-hff9-5pqw-6w9f** CRITICAL - imgproxy has integer overflow in imgproxy ICO loader that causes denial of service and may permit remote code execution (go:github.com/imgproxy/imgproxy/v3 \(fixed 4.0.16\), go:github.com/imgproxy/imgproxy/v2 \(fixed 4.0.16\), go:github.com/imgproxy/imgproxy \(fixed 4.0.16\)) - [source](https://github.com/advisories/GHSA-hff9-5pqw-6w9f)
- **GHSA-2qm8-x737-gmw5** HIGH - pyasn1 has quadratic CPU consumption in constructed BIT STRING decoding (pip:pyasn1 \(fixed 0.6.5\)) - [source](https://github.com/advisories/GHSA-2qm8-x737-gmw5)
- **GHSA-42gh-23hr-vphw** HIGH - pypdf has possible long runtimes when retrieving page labels (pip:pypdf \(fixed 6.21.3\)) - [source](https://github.com/advisories/GHSA-42gh-23hr-vphw)
- **GHSA-4528-x5fx-h6hg** HIGH - joi: quadratic-time split in \`string\(\).email\({ multiple: true }\)\` allows denial of service (npm:joi \(fixed 17.13.9\), npm:@​hapi/joi, npm:joi \(fixed 18.3.1\)) - [source](https://github.com/advisories/GHSA-4528-x5fx-h6hg)
- **GHSA-494m-4556-wf5p** HIGH - imgproxy has out-of-bounds heap read/write in ICO loader BMP header reconstruction that allows unauthenticated remote worker crash (go:github.com/imgproxy/imgproxy/v3 \(fixed 4.0.17\)) - [source](https://github.com/advisories/GHSA-494m-4556-wf5p)
- **GHSA-4vqv-7265-gm2w** HIGH - pypdf has possible large memory usage for exceptions in strict mode (pip:pypdf \(fixed 6.21.3\)) - [source](https://github.com/advisories/GHSA-4vqv-7265-gm2w)
- **GHSA-5849-834g-hvw5** HIGH - pypdf has possible infinite loop when hitting EOF in standard xref table during trailer search (pip:pypdf \(fixed 6.21.4\)) - [source](https://github.com/advisories/GHSA-5849-834g-hvw5)
- **GHSA-5x38-2vff-x55p** HIGH - Forge: X.509 basicConstraints bypass in verifyCertificateChain\(\) via deprecated extension OIDs 2.5.29.10 and 2.5.29.13 (npm:node-forge \(fixed 1.4.1\)) - [source](https://github.com/advisories/GHSA-5x38-2vff-x55p)
- **GHSA-62m5-6wh8-28x7** HIGH - pypdf has possible long runtimes/large memory usage for encrypted PDF files (pip:pypdf \(fixed 6.21.3\)) - [source](https://github.com/advisories/GHSA-62m5-6wh8-28x7)
- **GHSA-6vfx-w7q3-42gq** HIGH - AdminNeo SQLite Database-List Drop Arbitrary File Deletion (composer:adminneo-org/adminneo \(fixed 5.5.1\)) - [source](https://github.com/advisories/GHSA-6vfx-w7q3-42gq)
- **GHSA-7984-qgvg-3j9c** HIGH - OAuthLib: Token grants can use attacker-supplied client\_id for authorization after authenticating a different client (pip:oauthlib \(fixed 4.0.0\)) - [source](https://github.com/advisories/GHSA-7984-qgvg-3j9c)
- **GHSA-79wv-8rh2-9vp2** HIGH - AdminNeo has Cookie Attribute Injection via Unsanitized X-Forwarded-Prefix in Set-Cookie Headers (composer:adminneo-org/adminneo \(fixed 5.5.1\)) - [source](https://github.com/advisories/GHSA-79wv-8rh2-9vp2)
- **GHSA-7wch-p9px-956x** HIGH - Forge: Regular expression denial of service in PEM decoding \(pem.decode\) (npm:node-forge \(fixed 1.4.1\)) - [source](https://github.com/advisories/GHSA-7wch-p9px-956x)
- **GHSA-8494-f6mr-cjpv** HIGH - @​hapi/content: quadratic-time parsing of Content-Disposition parameters allows denial of service (npm:@​hapi/content \(fixed 6.0.3\), npm:content) - [source](https://github.com/advisories/GHSA-8494-f6mr-cjpv)
- **GHSA-8fmv-6rg5-5924** HIGH - Kubeflow Pipelines: Pipeline archive upload allows decompression bomb to exhaust server memory (go:github.com/kubeflow/pipelines \(fixed 0.0.0-20260831164314-ba9ae72cc860\), go:github.com/kubeflow/pipelines) - [source](https://github.com/advisories/GHSA-8fmv-6rg5-5924)
- **GHSA-8hrf-8g6f-7xwp** HIGH - Forge: Denial of service in TLS record processing via a record interleaved with a fragmented handshake message (npm:node-forge \(fixed 1.4.1\)) - [source](https://github.com/advisories/GHSA-8hrf-8g6f-7xwp)
- **GHSA-9m75-vc3g-4x39** HIGH - pyasn1 has quadratic-time denial of service in constructed string and indefinite-length ANY decoding (pip:pyasn1 \(fixed 0.6.5\)) - [source](https://github.com/advisories/GHSA-9m75-vc3g-4x39)
- **GHSA-c73q-w75p-j82v** HIGH - Authlib RFC 7592 examples omit registration-access-token client binding (pip:Authlib \(fixed 1.9.1\)) - [source](https://github.com/advisories/GHSA-c73q-w75p-j82v)
- **GHSA-cggf-277g-3q54** HIGH - pypdf has possible large memory usage when parsing page tree (pip:pypdf \(fixed 6.21.4\)) - [source](https://github.com/advisories/GHSA-cggf-277g-3q54)
- **GHSA-fm9c-5rcf-2q5p** HIGH - pyasn1 has quadratic CPU use in schemaless BER/CER/DER container decoding (pip:pyasn1 \(fixed 0.6.5\)) - [source](https://github.com/advisories/GHSA-fm9c-5rcf-2q5p)
- **GHSA-hqq3-7jhf-c5jx** HIGH - Forge: Denial of service in TLS record processing via call stack exhaustion (npm:node-forge \(fixed 1.4.1\)) - [source](https://github.com/advisories/GHSA-hqq3-7jhf-c5jx)
- **GHSA-j63v-mwhm-56jx** HIGH - @​sigstore/oci sends the registry Authorization header to a cross-host blob-upload Location (npm:@​sigstore/oci \(fixed 0.7.2\)) - [source](https://github.com/advisories/GHSA-j63v-mwhm-56jx)
- **GHSA-jc66-7q78-782g** HIGH - Forge: PKCS#​12 MAC forgery and constant-key PBE via zero iteration count (npm:node-forge \(fixed 1.4.1\)) - [source](https://github.com/advisories/GHSA-jc66-7q78-782g)
- ...and 12 more (see the source).

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
| CISA Known Exploited Vulnerabilities | OK | 2 | catalog 2026.10.30 |
| NVD \(new CVEs\) | OK | 48 | 581 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 28 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 37 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 878 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
