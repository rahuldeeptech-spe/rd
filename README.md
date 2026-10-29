# Security report 2026-10-29

Generated 2026-10-29 11:33 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (4)

- **CVE-2026-118694** CVSS 8.7 HIGH - python-markdown2 through 2.5.5 contains a denial of service vulnerability that allows remote users to exhaust CPU by submitting Markdown with unclosed inline link destinations. Attackers can submit repeated '\[a\]\(' or '\!… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118694)
- **CVE-2026-116641** CVSS 7.6 HIGH - The DB Tools rely on the TLS implementation in Golang’s standard library, which generally uses the system CA store. However, the crypto/x509 package also has its own internal denylist of known-bad CA certificates. Golan… - **watching: go** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116641)
- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**

## Actively exploited (CISA KEV, added in window)

- **CVE-2026-41709** - Broadcom VMware ESX - Broadcom VMWare ESX Insufficient Logging Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-41709)
- **CVE-2026-46300** - Linux Kernel - Linux Kernel Missing Initialization of a Variable Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-46300)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-118694** CVSS 8.7 HIGH - python-markdown2 through 2.5.5 contains a denial of service vulnerability that allows remote users to exhaust CPU by submitting Markdown with unclosed inline link destinations. Attackers can submit repeated '\[a\]\(' or '\!… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118694)
- **CVE-2026-116641** CVSS 7.6 HIGH - The DB Tools rely on the TLS implementation in Golang’s standard library, which generally uses the system CA store. However, the crypto/x509 package also has its own internal denylist of known-bad CA certificates. Golan… - **watching: go** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116641)
- **CVE-2026-61564** CVSS 10.0 CRITICAL - AVideo is a video-sharing Platform. Prior to 8.1.0, the unauthenticated installer endpoint \`install/checkConfiguration.php\` assembles \`videos/configuration.php\` by interpolating request parameters, including \`webSiteRoo… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61564)
- **CVE-2026-61567** CVSS 10.0 CRITICAL - AVideo is a video-sharing Platform. Prior to 8.1.0, the live-streaming endpoint \`view/videosListToLive.php\` accepts an attacker-named streamer in \`webSiteRootURL\`, calls \`Login::run\` in \`objects/Login.php\`, and trusts t… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61567)
- **CVE-2026-113617** CVSS 9.9 CRITICAL - The Automated Import Products to Cart WordPress plugin before 1.0.4 does not sanitize a user-supplied file path before using it to read and delete files, allowing users with minimal permissions, such as subscribers, to… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-113617)
- **CVE-2026-44179** CVSS 9.9 CRITICAL - XWiki Remote Macros provides XWiki rendering macros that are useful when migrating content from Confluence. From 1.13 until 1.14.5, the \`excerpt-include\` macro does not properly escape the included page's title and exec… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-44179)
- **CVE-2026-103406** CVSS 9.8 CRITICAL - An Improper Neutralization of Special Elements used in an OS Command vulnerability in the AutomatedProvisioner in Juniper Networks Session Smart Conductor allows a remote attacker to execute arbitrary commands as root v… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103406)
- **CVE-2026-103409** CVSS 9.8 CRITICAL - A Missing authentication for critical function vulnerability in Juniper Networks Session Smart Router allows an unauthenticated network-based attacker to obtain administrative privileges by passing crafted URL parameter… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103409)
- **CVE-2026-109516** CVSS 9.8 CRITICAL - The Bot for Telegram on WooCommerce plugin for WordPress is vulnerable to Authentication Bypass leading to Account Takeover in all versions up to, and including, 1.3.0. The \`/wp-json/woo-telegram/v1/main/\` REST endpoint… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-109516)
- **CVE-2026-113616** CVSS 9.8 CRITICAL - The LogixFast Auth WordPress plugin before 1.0.4 does not deliver its password-reset one-time code to the resolved account's own email address, mailing it to the address supplied in the request instead, allowing unauthe… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-113616)
- **CVE-2026-114278** CVSS 9.8 CRITICAL - The che-machine-exec service constructs a shell command by concatenating user-controlled input \(the username and namespace fields from the /exec/init and /exec/config JSON endpoints\) into a double-quoted sh -c "echo "..… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114278)
- **CVE-2026-115245** CVSS 9.8 CRITICAL - The Chat AI with Dispatcher WordPress plugin before 2.4 does not properly validate uploaded files, relying only on a spoofable client-supplied content type, allowing unauthenticated attackers to upload arbitrary files,… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115245)
- **CVE-2026-115968** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data vulnerability in Ultimate Member Ultimate Member ultimate-member allows Object Injection.This issue affects Ultimate Member: from n/a through 2.13.1. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115968)
- **CVE-2026-42922** CVSS 9.8 CRITICAL - A authorization bypass vulnerability exists in the /nodered functionality of FUXA \(version\(s\): 1.3.2-2809\). A specially crafted HTTP request can lead to a arbitrary code execution. An attacker can make an unauthenticate… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-42922)
- **CVE-2026-115904** CVSS 9.6 CRITICAL - Topluyo is a social networking platform. A vulnerability exists in Topluyo Desktop for Linux prior to version 2026.9.2410 where user-controlled URLs are unsafely processed, leading to OS Command Injection via the \`openE… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115904)
- **CVE-2026-105420** CVSS 9.4 CRITICAL - Wing FTP Server does not verify user's base folder. An attacker with admin privileges can add user directories via scripts, allowing the added directories to escape the base folder. This allows the attacker to write fil… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-105420)
- **CVE-2026-63190** CVSS 9.4 CRITICAL - FearlessCMS is a flat-file \`content\` management system centered on simplicity and open source. Prior to version 0.1.4, five debug/test PHP scripts under \`admin/\` perform privileged operations without \`isLoggedIn\(\)\` auth… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-63190)
- **CVE-2026-66088** CVSS 9.4 CRITICAL - In openEQUELLA before 2026.1, the system.execute\(\) function available to the scripting engine runs supplied operating system commands without validation or an allow-list of permitted executables. A user able to create o… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-66088)
- **CVE-2026-111411** CVSS 9.3 CRITICAL - Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\) vulnerability in Aman FunnelKit Automations wp-marketing-automations allows Blind SQL Injection.This issue affects FunnelKit Automatio… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-111411)
- **CVE-2026-114358** CVSS 9.3 CRITICAL - This vulnerability exists in the Radius Xenia M2M Platform due to insufficient validation of user supplied input in the password recovery functionality in the web management interface. An unauthenticated remote attacker… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114358)
- **CVE-2026-115607** CVSS 9.3 CRITICAL - Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\) vulnerability in Crowd Favorite DXP ToolKit dxp-toolkit allows SQL Injection.This issue affects DXP ToolKit: from n/a through 2.0.1. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115607)
- **CVE-2026-115964** CVSS 9.3 CRITICAL - Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\) vulnerability in StylemixThemes Motors motors-car-dealership-classified-listings allows Blind SQL Injection.This issue affects Motors:… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115964)
- **CVE-2026-118690** CVSS 9.3 CRITICAL - Signal K Server before 2.33.0 contains a missing authentication vulnerability that allows unauthenticated remote attackers to download log archives via the /skServer/ziplogs endpoint. Attackers can extract the JWT secre… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118690)
- **CVE-2026-118633** CVSS 9.2 CRITICAL - A path traversal vulnerability allows a remote unauthenticated attacker to execute arbitrary code as root in Sophos UTM \(all versions\) after winning a race condition by sustaining repeated attacks for a few minutes when… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118633)
- **CVE-2026-117574** CVSS 9.1 CRITICAL - A flaw was found in ai-gateway-payload-processing. An authenticated remote attacker can exploit this vulnerability by submitting a request specifying another tenant's model identifier in the request body or header. Beca… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-117574)
- ...and 4 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-6jp4-8v48-cc5v** CRITICAL - Electrum: Malicious server can replace a just-broadcast tx and try to trick user into RBF-ing it (pip:electrum \(fixed 4.8.3\)) - [source](https://github.com/advisories/GHSA-6jp4-8v48-cc5v)
- **GHSA-m665-v7pm-7grj** CRITICAL - zip: Critical Parser Differential &amp; Security Control Bypass via Dual-Header Inconsistencies \(Zip Cloaking\) Leading to Arbitrary File Overwrite &amp; RCE (rust:zip \(fixed 9.0.5\)) - [source](https://github.com/advisories/GHSA-m665-v7pm-7grj)
- **GHSA-mghf-wjfp-p5xm** CRITICAL - Wasmtime: Cranelift backend on aarch64 can jump to incorrect target on large Wasm \`br\_table\` instruction (rust:wasmtime \(fixed 36.0.19\), rust:wasmtime \(fixed 48.0.7\), rust:wasmtime \(fixed 49.0.4\)) - [source](https://github.com/advisories/GHSA-mghf-wjfp-p5xm)
- **GHSA-35rr-xwfh-x789** HIGH - Highcharts Core: \`breadcrumbs.style\` keys become SVG event-handler attributes (npm:highcharts \(fixed 11.4.9\), npm:highcharts \(fixed 12.6.1\), npm:highcharts \(fixed 13.1.0\)) - [source](https://github.com/advisories/GHSA-35rr-xwfh-x789)
- **GHSA-375p-5qhx-8wq4** HIGH - Echo's middleware.Static: \`%2F\`-encoded path bypasses route/group middleware guarding a statically-served path (go:github.com/labstack/echo/v5 \(fixed 5.4.0\), go:github.com/labstack/echo/v4 \(fixed 4.16.0\)) - [source](https://github.com/advisories/GHSA-375p-5qhx-8wq4)
- **GHSA-3f7j-7jwc-fxfj** HIGH - systeminformation vulnerable to Windows command injection in services\(\) through Unicode quotation marks (npm:systeminformation \(fixed 5.33.16\)) - [source](https://github.com/advisories/GHSA-3f7j-7jwc-fxfj)
- **GHSA-434m-5hcj-pxf3** HIGH - GraphQL Tools: Per-request connection parameters persist into later users' WebSocket authentications (npm:@​graphql-tools/executor-legacy-ws \(fixed 1.1.36\)) - [source](https://github.com/advisories/GHSA-434m-5hcj-pxf3)
- **GHSA-4hm6-w6qq-w73v** HIGH - LangGraph JavaScript custom authentication may permit cross-user Store access (pip:langgraph-api \(fixed 0.15.0\)) - [source](https://github.com/advisories/GHSA-4hm6-w6qq-w73v)
- **GHSA-4mfg-r38w-w8fg** HIGH - mcp-sanitizer: URL sanitizer allows localhost/IPv6 loopback SSRF bypass via explicit port or bracketed IPv6 (npm:mcp-sanitizer \(fixed 1.4.0\)) - [source](https://github.com/advisories/GHSA-4mfg-r38w-w8fg)
- **GHSA-5793-x2q3-c3q7** HIGH - Highcharts: \`javascript:\` URL in credits.href runs script on click (npm:highcharts \(fixed 11.4.9\), npm:highcharts \(fixed 12.6.1\), npm:highcharts \(fixed 13.1.0\)) - [source](https://github.com/advisories/GHSA-5793-x2q3-c3q7)
- **GHSA-58g7-7f52-h92c** HIGH - Highcharts Dashboards parses fullscreen labels as HTML (npm:@​highcharts/dashboards \(fixed 4.2.3\)) - [source](https://github.com/advisories/GHSA-58g7-7f52-h92c)
- **GHSA-5ghw-9mgr-jvx2** HIGH - Highcharts Grid Pro: cell-renderer \`attributes\` map written with raw \`setAttribute\` (npm:@​highcharts/grid-pro \(fixed 3.2.0\), npm:@​highcharts/dashboards \(fixed 4.0.0\)) - [source](https://github.com/advisories/GHSA-5ghw-9mgr-jvx2)
- **GHSA-5j9r-fx4x-rpvg** HIGH - rucio has an Authorization Bypass on REST API endpoint for signing URLs (pip:rucio \(fixed 35.9.0\), pip:rucio \(fixed 38.6.0\), pip:rucio \(fixed 41.0.0rc1\)) - [source](https://github.com/advisories/GHSA-5j9r-fx4x-rpvg)
- **GHSA-65hg-cf3f-5m39** HIGH - Highcharts Core: HTML text parsing falls back to unfiltered \`innerHTML\` during printing (npm:highcharts \(fixed 12.6.1\), npm:highcharts \(fixed 13.1.0\)) - [source](https://github.com/advisories/GHSA-65hg-cf3f-5m39)
- **GHSA-6757-hggm-hp2w** HIGH - vLLM: Public multimodal SHM handle forgery reaches worker-side \`pickle.loads\(\)\` with insecure serialization disabled (pip:vllm \(fixed 0.32.0\)) - [source](https://github.com/advisories/GHSA-6757-hggm-hp2w)
- **GHSA-6g3c-p4fg-xv47** HIGH - Highcharts Grid: custom icon definition objects written with raw \`setAttribute\` on \`&lt;path&gt;\` (npm:@​highcharts/grid-lite \(fixed 3.2.0\), npm:@​highcharts/grid-pro \(fixed 3.2.0\)) - [source](https://github.com/advisories/GHSA-6g3c-p4fg-xv47)
- **GHSA-6hgp-fmhr-mrg4** HIGH - Highcharts Grid: \`javascript:\` URL in credits.href runs script on click (npm:@​highcharts/dashboards \(fixed 4.0.0\), npm:@​highcharts/grid-pro \(fixed 3.2.0\)) - [source](https://github.com/advisories/GHSA-6hgp-fmhr-mrg4)
- **GHSA-7rv5-mrxv-xcr9** HIGH - Seroval: Deserialization invokes attacker-chosen callables: AsyncIteratorFactoryInstance calls source.on\(listener\) without type check (npm:seroval \(fixed 1.6.8\)) - [source](https://github.com/advisories/GHSA-7rv5-mrxv-xcr9)
- **GHSA-7w82-6f9j-v9jp** HIGH - mcp-sanitizer: File Path Sanitizer Permits Arbitrary User-Home Absolute Paths (npm:mcp-sanitizer \(fixed 1.4.0\)) - [source](https://github.com/advisories/GHSA-7w82-6f9j-v9jp)
- **GHSA-83rm-6c8r-g728** HIGH - Vue I18n: escapeParameter does not prevent XSS through srcdoc in translation messages (npm:vue-i18n, npm:vue-i18n, npm:vue-i18n \(fixed 11.4.14\), npm:vue-i18n \(fixed 12.0.0-alpha.5\)) - [source](https://github.com/advisories/GHSA-83rm-6c8r-g728)
- **GHSA-97r2-qh9m-474h** HIGH - Seroval: fromJSON deserializer trusts node-supplied array length and sequence doneAt \(unauthenticated event-loop DoS\) (npm:seroval \(fixed 1.6.8\)) - [source](https://github.com/advisories/GHSA-97r2-qh9m-474h)
- **GHSA-c8p4-j97h-3vg8** HIGH - Happy DOM: SSRF via iframe and link stylesheet when parsing untrusted HTML (npm:happy-dom \(fixed 21.0.0\)) - [source](https://github.com/advisories/GHSA-c8p4-j97h-3vg8)
- **GHSA-gfvx-2c2g-38wq** HIGH - Highcharts: series column construction writes to Object.prototype (npm:highcharts \(fixed 13.1.0\)) - [source](https://github.com/advisories/GHSA-gfvx-2c2g-38wq)
- **GHSA-gg6h-894w-4m9c** HIGH - RE2JS: Quadratic-time denial of service in re2js lookbehind matching (npm:re2js \(fixed 2.8.7\)) - [source](https://github.com/advisories/GHSA-gg6h-894w-4m9c)
- **GHSA-grj7-r4jv-pw9j** HIGH - Highcharts Dashboards: \`chartConstructor\` is an unchecked lookup into the Highcharts namespace (npm:@​highcharts/dashboards \(fixed 4.2.2\)) - [source](https://github.com/advisories/GHSA-grj7-r4jv-pw9j)
- ...and 7 more (see the source).

## Node.js releases in window

- **node 26.13.0** - Node.js 26.13.0 released - **watching: node.js** - [source](https://nodejs.org/en/blog/vulnerability)

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |
|---|---|---|---|---|
| go | 1.26 | 1.26.10 | 1.26.10 | - |
| go | 1.27 | 1.27.3 | 1.27.3 | - |
| node | 22 | 22.23.4 | 22.23.4 | - |
| node | 24 | 24.22.2 | 24.22.1 | - |
| node | 26 | 26.13.0 | 26.12.1 | - |
| php | 8.2 | 8.2.35 | 8.2.35 | - |
| php | 8.3 | 8.3.36 | 8.3.36 | - |
| php | 8.4 | 8.4.27 | 8.4.27 | - |
| php | 8.5 | 8.5.12 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 2 | catalog 2026.10.28 |
| NVD \(new CVEs\) | OK | 29 | 421 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 20 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 32 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 1 | 877 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
