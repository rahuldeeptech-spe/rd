# Security report 2026-10-30

Generated 2026-10-30 11:25 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (5)

- **CVE-2026-59387** CVSS 8.8 HIGH - The Nginx routing configuration for Cloud Controller blocks unauthenticated access to /internal/v4/ and /internal/v5/ endpoints but omits an equivalent deny rule for /internal/v3/. As a result, the staging callback endp… - **watching: nginx** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-59387)
- **CVE-2019-25781** CVSS 8.7 HIGH - Python-Markdown 3.0 through 3.11.2 contains an algorithmic complexity vulnerability in inline link parsing that allows remote attackers to exhaust CPU through unmatched brackets. Attackers can submit short Markdown cont… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2019-25781)
- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

- **CVE-2026-76418** - Cisco Secure Firewall ASA Software and Cisco Secure FTD Software - Cisco Secure Firewall ASA Software and Cisco Secure FTD Software Unchecked Return Value to NULL Pointer Dereference Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-76418)
- **CVE-2026-97229** - GitLab Community Edition and Enterprise Edition - GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-97229)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-59387** CVSS 8.8 HIGH - The Nginx routing configuration for Cloud Controller blocks unauthenticated access to /internal/v4/ and /internal/v5/ endpoints but omits an equivalent deny rule for /internal/v3/. As a result, the staging callback endp… - **watching: nginx** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-59387)
- **CVE-2019-25781** CVSS 8.7 HIGH - Python-Markdown 3.0 through 3.11.2 contains an algorithmic complexity vulnerability in inline link parsing that allows remote attackers to exhaust CPU through unmatched brackets. Attackers can submit short Markdown cont… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2019-25781)
- **CVE-2026-61991** CVSS 10.0 CRITICAL - Unauthenticated Remote Code Execution \(RCE\) in AjaxLoadMore Cache &lt;= 3.1.1 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61991)
- **CVE-2026-84295** CVSS 10.0 CRITICAL - Improper authentication in Progress Software WS\_FTP Server versions prior to 2024.0.6 and 2025.0.3 on Windows could allow an unauthenticated remote attacker to access sensitive information, including administrative cred… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-84295)
- **CVE-2026-107327** CVSS 9.9 CRITICAL - IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to missing authorization. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-107327)
- **CVE-2026-107328** CVSS 9.9 CRITICAL - IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to improper neutralization of code in eval/exec. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-107328)
- **CVE-2026-107329** CVSS 9.9 CRITICAL - IBM Langflow OSS 1.0.0 through 1.12.4 could allow a remote authenticated attacker to execute arbitrary code due to improper control of code generation. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-107329)
- **CVE-2026-90868** CVSS 9.9 CRITICAL - An OS command injection vulnerability in Progress Software WS\_FTP Server versions prior to 2024.0.7 and 2025.0.4 on Windows could allow arbitrary command execution under certain configurations. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-90868)
- **CVE-2025-31704** CVSS 9.8 CRITICAL - A vulnerability has been found in the Dahua Intelligent Connection Center. A remote attacker could send a specially crafted request to the affected system, allowing the attacker to execute arbitrary commands, resulting… - [source](https://nvd.nist.gov/vuln/detail/CVE-2025-31704)
- **CVE-2026-103039** CVSS 9.8 CRITICAL - The Gravity Forms plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.1.2 via a Post Custom Field whose input type is List. This is due to GFFormsModel::create\_post\(\) passi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103039)
- **CVE-2026-104339** CVSS 9.8 CRITICAL - IBM Langflow OSS 1.0.0 through 1.12.3 could allow a remote attacker to execute arbitrary code due to improper neutralization of special elements used in an OS command. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-104339)
- **CVE-2026-107058** CVSS 9.8 CRITICAL - An issue in Shelter versionCode 445 allows attackers to register their own auth\_key and execute a takeover of another user's binder service API and preference state. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-107058)
- **CVE-2026-110186** CVSS 9.8 CRITICAL - IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to execute arbitrary code due to improper control of code generation. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110186)
- **CVE-2026-54856** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in RexCoin &lt;= 1.2.6 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54856)
- **CVE-2026-54857** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Quirky &lt;= 1.23 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54857)
- **CVE-2026-54858** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Printy &lt;= 1.13.0 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54858)
- **CVE-2026-54859** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Preservation &lt;= 1.15 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54859)
- **CVE-2026-54860** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Ozisti &lt;= 1.1.10 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54860)
- **CVE-2026-61992** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in GEO my WordPress &lt;= 4.5.5.3 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61992)
- **CVE-2026-61997** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Legal Stone &lt;= 1.2.11 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61997)
- **CVE-2026-61998** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Le Truffe &lt;= 1.1.7 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-61998)
- **CVE-2026-62001** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Marcell &lt;= 1.2.14 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62001)
- **CVE-2026-62002** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Meals &amp; Wheels &lt;= 1.1.13 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62002)
- **CVE-2026-62003** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Mission &lt;= 1.22 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62003)
- **CVE-2026-62004** CVSS 9.8 CRITICAL - Unauthenticated PHP Object Injection in Motorix &lt;= 1.11 versions. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62004)
- ...and 35 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-26mh-57q7-jfvr** HIGH - PraisonAI vulnerable to Remote Code Execution via Broken AST Sandbox (pip:praisonai \(fixed 4.6.78\)) - [source](https://github.com/advisories/GHSA-26mh-57q7-jfvr)
- **GHSA-8rvj-mm4h-c258** HIGH - cert-manager: Direct ACME Challenge resources can bypass Issuer DNS01 solver policy and use ClusterIssuer DNS credentials (go:github.com/cert-manager/cert-manager \(fixed 1.19.6\), go:github.com/cert-manager/cert-manager \(fixed 1.20.3\)) - [source](https://github.com/advisories/GHSA-8rvj-mm4h-c258)
- **GHSA-q344-5v34-gm84** HIGH - @​sylphx/pdf-reader-mcp: HTTP transport accepts unauthenticated requests despite a configured MCP\_API\_KEY (npm:@​sylphx/pdf-reader-mcp \(fixed 3.0.1\)) - [source](https://github.com/advisories/GHSA-q344-5v34-gm84)
- **GHSA-qr28-fpjm-wq7f** HIGH - decode-uri-component vulnerable to denial of service via quadratic replacement of percent-encoded runs (npm:decode-uri-component \(fixed 0.5.1\)) - [source](https://github.com/advisories/GHSA-qr28-fpjm-wq7f)
- **GHSA-rhj7-vh3v-mcq6** HIGH - Daptin: ParseAcceptLanguage \`\_\` separator bypass enables &gt;250x CPU amplification via Accept-Language header in LanguageMiddleware (go:github.com/daptin/daptin) - [source](https://github.com/advisories/GHSA-rhj7-vh3v-mcq6)
- **GHSA-vpp8-g58w-m8mp** HIGH - Twisted: Unauthenticated Remote Denial of Service in the Twisted HTTP/2 Server via Rapid Stream Reset (pip:Twisted \(fixed 26.10.0rc1\)) - [source](https://github.com/advisories/GHSA-vpp8-g58w-m8mp)
- **GHSA-w9x9-j56r-h98r** HIGH - @​eeacms/volto-chatbot has Unauthenticated Danswer API Confused Deputy Proxy (npm:@​eeacms/volto-chatbot \(fixed 2.0.4\)) - [source](https://github.com/advisories/GHSA-w9x9-j56r-h98r)

## Node.js releases in window

- **node 27.0.0-alpha.0.0.0** - Node.js 27.0.0-alpha.0.0.0 released - **watching: node.js** - [source](https://nodejs.org/en/blog/vulnerability)

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
| CISA Known Exploited Vulnerabilities | OK | 2 | catalog 2026.10.29 |
| NVD \(new CVEs\) | OK | 60 | 628 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 58 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 7 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 1 | 878 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
