# Security report 2026-11-24

Generated 2026-11-24 15:55 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

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

- **CVE-2026-133968** - Project MONAI MONAI Label - Project MONAI MONAI Label Path Traversal Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133968)
- **CVE-2026-134624** - N-able MailAssure - N-able MailAssure \(SpamExperts\) Server-Side Request Forgery \(SSRF\) Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134624)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-128791** CVSS 10.0 CRITICAL - Any WiFi client can send HTTP DELETE to /meeting-recording/delete to permanently delete files without authentication. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-128791)
- **CVE-2026-128797** CVSS 10.0 CRITICAL - Web administration panel \(port 8080\) binds to all network interfaces including public IPv6 addresses, making internal API endpoints reachable over WAN without firewall protection \(related to CVE-2026-50224\). - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-128797)
- **CVE-2026-128798** CVSS 10.0 CRITICAL - Any connected WiFi client can fetch device info and meeting recording metadata without credentials. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-128798)
- **CVE-2026-129514** CVSS 10.0 CRITICAL - Deserialization of Untrusted Data vulnerability in the application/vnd.hex+erlang request body parser in hexpm hexpm allows an unauthenticated remote attacker to execute operating system commands via a crafted Erlang ex… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129514)
- **CVE-2026-130169** CVSS 10.0 CRITICAL - AutoGPT is a workflow automation platform for creating, deploying, and managing continuous artificial intelligence agents. In versions 0.6.26 through 0.7.4, AutoGPT Platform ships a publicly known, hardcoded default JWT… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130169)
- **CVE-2026-59415** CVSS 10.0 CRITICAL - TypesenseVectorStore is vulnerable to a document ID injection in its delete operation that can cause unintended documents to be deleted. TypesenseVectorStore.doDelete\(List&lt;String&gt;\) builds a Typesense filter\_by expressio… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-59415)
- **CVE-2026-62841** CVSS 10.0 CRITICAL - Improper authentication in Azure Event Grid allows an unauthorized attacker to elevate privileges over a network. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-62841)
- **CVE-2026-9790** CVSS 10.0 CRITICAL - Endpoints accessible without authentication from any WiFi client \(e.g., /user/hasSimCard, /user/pooling, /api/device-info\). - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-9790)
- **CVE-2026-103782** CVSS 9.9 CRITICAL - Dell Enterprise Sonic Distribution, versions prior to 4.6.1, contains an Argument Injection vulnerability. A low privileged remote attacker could potentially exploit this vulnerability, leading to arbitrary command exec… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103782)
- **CVE-2026-18530** CVSS 9.9 CRITICAL - OS command injection in the a3cli restricted shell in Lantronix S2220 Series 2 allows an authenticated attacker to bypass shell restrictions and execute arbitrary operating system commands via unsanitized command substi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-18530)
- **CVE-2026-50691** CVSS 9.9 CRITICAL - Improper authorization in M365 Copilot allows an authorized attacker to elevate privileges over a network. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-50691)
- **CVE-2026-70193** CVSS 9.9 CRITICAL - Improper limitation of a pathname to a restricted directory \('path traversal'\) in Microsoft Office SharePoint allows an authorized attacker to execute code over a network. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-70193)
- **CVE-2026-119582** CVSS 9.8 CRITICAL - Improper neutralization of special elements used in an SQL command \('SQL injection'\) vulnerability in ITG Bilgisayar Teknoloji Grubu Tic. Ltd. Şti. VSRM allows SQL Injection. This issue affects vSRM: from v14.08.3 befor… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119582)
- **CVE-2026-133469** CVSS 9.8 CRITICAL - XO \(Xen Orchestra\) is a solution to visualize, manage, backup and delegate your XCP-ng \(or XenServer\) infrastructure. Prior to 6.9.2 and 6.10.1, REST cookie parsing turns authenticationToken=j:%7B%7D into {}. REST authe… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-133469)
- **CVE-2026-135202** CVSS 9.8 CRITICAL - Several plugins for WordPress published by WP connect \(Orders Sync to Airtable for WooCommerce, Add-On for Contact Form 7 to Notion, WP Sync for Notion – Notion to WordPress, Add-On for Contact Form 7 to Airtable, Add-o… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135202)
- **CVE-2026-65135** CVSS 9.8 CRITICAL - NVIDIA Video Codec SDK for Linux contains a vulnerability where a user may cause a heap-based buffer overflow issue. A successful exploit of this vulnerability may lead to code execution, data tampering, and denial of s… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-65135)
- **CVE-2026-65175** CVSS 9.8 CRITICAL - NVIDIA AIStore contains a vulnerability in storage-target node-control authorization where an unauthenticated attacker could access administrative functions through a target's public interface. A successful exploit migh… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-65175)
- **CVE-2026-103788** CVSS 9.6 CRITICAL - Dell Enterprise Sonic Distribution, versions prior to 4.6.1, contains an OS Command Injection vulnerability. An unauthenticated adjacent network attacker could potentially exploit this vulnerability, leading to arbitrar… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103788)
- **CVE-2026-109480** CVSS 9.6 CRITICAL - Server-side request forgery in Profile Data Roaming Service \(PDRS\) allows an authorized attacker to elevate privileges over a network. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-109480)
- **CVE-2026-118285** CVSS 9.6 CRITICAL - Server-side request forgery in Azure Machine Learning allows an authorized attacker to elevate privileges over a network. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118285)
- **CVE-2026-134401** CVSS 9.6 CRITICAL - Improper input validation in Variations in Google Chrome prior to 158.0.8127.88 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: C… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134401)
- **CVE-2026-135501** CVSS 9.6 CRITICAL - Sandbox escape due to use-after-free in the Audio/Video: cubeb component. This vulnerability was fixed in Firefox 161. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135501)
- **CVE-2026-135508** CVSS 9.6 CRITICAL - Sandbox escape due to use-after-free in the Graphics component. This vulnerability was fixed in Firefox 161, Firefox ESR 115.46, and Firefox ESR 153.8. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135508)
- **CVE-2026-135509** CVSS 9.6 CRITICAL - Sandbox escape due to use-after-free in the Graphics: WebRender component. This vulnerability was fixed in Firefox 161, Firefox ESR 115.46, and Firefox ESR 153.8. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135509)
- **CVE-2026-135513** CVSS 9.6 CRITICAL - Sandbox escape due to use-after-free in the Networking: HTTP component. This vulnerability was fixed in Firefox 161. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135513)
- ...and 28 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-2r3w-c2vx-fv5g** CRITICAL - Xen Orchestra: Empty-object login token (npm:xo-server) - [source](https://github.com/advisories/GHSA-2r3w-c2vx-fv5g)
- **GHSA-f9h7-4mmq-vgcq** HIGH - Klever Go counts bitmap padding bits toward BLS quorum, allowing blocks with insufficient signatures (go:github.com/klever-io/klever-go \(fixed 1.7.20\)) - [source](https://github.com/advisories/GHSA-f9h7-4mmq-vgcq)
- **GHSA-j44m-77cc-p3cc** HIGH - AVideo API vulnerable to OS command injection through an unescaped FFmpeg process keyword (composer:wwbn/avideo \(fixed 29.1.0\)) - [source](https://github.com/advisories/GHSA-j44m-77cc-p3cc)

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
| CISA Known Exploited Vulnerabilities | OK | 2 | catalog 2026.11.23 |
| NVD \(new CVEs\) | OK | 53 | 711 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 24 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 3 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 883 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
