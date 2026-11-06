# Security report 2026-11-06

Generated 2026-11-06 12:58 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (3)

- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-118423** CVSS 10.0 CRITICAL - The WP Libre Form WordPress plugin 1.5.0.1 does not validate the type of files uploaded through its form submissions, allowing unauthenticated attackers to upload PHP files to a web-accessible location and execute them,… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-118423)
- **CVE-2026-111489** CVSS 9.9 CRITICAL - A static credential embedded in the mobile app has been reported to return the 'autorizado' token on the MatchPoint platform. The report states that this token grants unauthenticated access to API services. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-111489)
- **CVE-2026-111490** CVSS 9.9 CRITICAL - Insecure direct object reference \(IDOR\) vulnerability in the MatchPoint API, which relies on the \`actingasuser\` HTTP header without verifying the requester's authorization for the specified user. Manipulation of sequent… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-111490)
- **CVE-2026-71550** CVSS 9.9 CRITICAL - SuiteCRM is an open-source, enterprise-ready Customer Relationship Management \(CRM\) software application. Prior to 7.15.2 and 8.10.2, the workflow controller uses a path-traversal-capable aow\_action value in require\_onc… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-71550)
- **CVE-2026-107622** CVSS 9.8 CRITICAL - The BuddyForms plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.10.5 via a form-type confusion attack through the \`bf\_post\_type\` parameter. This is due to the public fro… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-107622)
- **CVE-2026-116533** CVSS 9.8 CRITICAL - The Static Snapshot WordPress plugin through 0.2.1 does not sanitise shell metacharacters in a user-supplied value before concatenating it into operating-system commands run by the server, allowing unauthenticated attac… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116533)
- **CVE-2026-116779** CVSS 9.8 CRITICAL - FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia\_presence\_hand… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116779)
- **CVE-2026-119516** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data vulnerability in Mamunur Rashid Radius Booking — Booking Calendar for Appointments &amp;amp; Services radius-booking allows Object Injection.This issue affects Radius Booking — Booking Cale… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119516)
- **CVE-2026-120844** CVSS 9.8 CRITICAL - Incorrect Privilege Assignment vulnerability in miniOrange OAuth Single Sign On – SSO \(OAuth Client\) miniorange-login-with-eve-online-google-facebook allows Privilege Escalation.This issue affects OAuth Single Sign On –… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120844)
- **CVE-2026-54143** CVSS 9.8 CRITICAL - OpenHuman is an open-source agent harness available as a desktop application and Rust library. Before version 0.57.13, an attacker who can send messages to a configured external channel can cause the agent to create per… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-54143)
- **CVE-2026-82907** CVSS 9.8 CRITICAL - Authentication Bypass by Capture-replay in ExternalLoginKeysManager in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker who captures a live externalLoginKey value to obtain a… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-82907)
- **CVE-2026-83542** CVSS 9.8 CRITICAL - Improper Control of Generation of Code \('Code Injection'\) in Apache OFBiz 24.09 before 24.09.08 on all platforms allows a remote unauthenticated attacker to execute arbitrary code on the server by staging crafted widget… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-83542)
- **CVE-2026-102940** CVSS 9.6 CRITICAL - OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.4.0, controllers/C\_Document.class.php write actions, including move\_action\_process\(\), do not verify the… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-102940)
- **CVE-2026-123294** CVSS 9.6 CRITICAL - In JetBrains Hub before 2026.2.52556 privilege escalation was possible by changing email authentication details during the verification flow - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123294)
- **CVE-2026-77596** CVSS 9.6 CRITICAL - Kubeflow Pipelines enables users to build and deploy portable, scalable machine learning workflows. Prior to 2.18.0, the multi-user HTTP endpoints POST /apis/v2beta1/pipelines/upload and POST /apis/v2beta1/pipelines/upl… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-77596)
- **CVE-2026-100358** CVSS 9.4 CRITICAL - SuiteCRM is an open-source, enterprise-ready Customer Relationship Management \(CRM\) software application. Prior to 7.15.2 and 8.10.2, the Studio Dropdown Editor passes $dropdown\_name through html\_entity\_decode\(\) and wri… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-100358)
- **CVE-2026-63017** CVSS 9.4 CRITICAL - Incorrect authorization in PowerSYSTEM Center allows a low-privileged, authenticated user to access resources normally limited to administrators. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-63017)
- **CVE-2026-63774** CVSS 9.4 CRITICAL - Insufficient input validation in the PowerSYSTEM Center report designer allows an authenticated user to execute unauthorized SQL commands. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-63774)
- **CVE-2026-119757** CVSS 9.3 CRITICAL - BTCPay Server before 2.4.2, including 2.4.2 release candidates, contains an information disclosure vulnerability that allows unauthenticated remote attackers to retrieve .macaroon credential files for an LND \(Lightning… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119757)
- **CVE-2026-123198** CVSS 9.3 CRITICAL - LMFDB before commit 01829bd contains a server-side template injection vulnerability in the render\_knowl function that allows unauthenticated attackers to inject Jinja expressions via request parameters. Attackers can su… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-123198)
- **CVE-2026-48705** CVSS 9.3 CRITICAL - MONAI \(Medical Open Network for AI\) is an AI toolkit for health care imaging. Prior to 1.6.1, PydicomReader.\_get\_affine\(\) trusts non-finite values in the DICOM PixelSpacing, ImagePositionPatient, and ImageOrientationPat… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-48705)
- **CVE-2026-111494** CVSS 9.1 CRITICAL - Incorrect validation of TLS certificates in the MatchPoint Android app due to a TrustManager that accepts any certificate and a permissive hostname validator. Additionally, the app allows unencrypted HTTP traffic. An at… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-111494)
- **CVE-2026-114630** CVSS 9.1 CRITICAL - The ELEX WordPress HelpDesk &amp; Customer Ticketing System plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the factory\_reset function in all versions up to, and inc… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114630)
- **CVE-2026-116785** CVSS 9.1 CRITICAL - FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.2, ws\_read\_frame\(\) dec… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116785)
- **CVE-2026-116790** CVSS 9.1 CRITICAL - FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.2, FreeSWITCH's inboun… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-116790)
- ...and 7 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-5q7h-w9jf-cx97** CRITICAL - kaniko can send the build's Azure \(Entra ID\) access token to lookalike ACR registry hosts (go:github.com/chainguard-dev/kaniko \(fixed 1.25.20\)) - [source](https://github.com/advisories/GHSA-5q7h-w9jf-cx97)
- **GHSA-64vx-6h2c-rjh7** HIGH - Banks: Unsafe importlib.import\_module of attacker-controlled Tool.import\_path in CompletionExtension allows RCE (pip:banks \(fixed 2.4.3\)) - [source](https://github.com/advisories/GHSA-64vx-6h2c-rjh7)
- **GHSA-hhf9-qw4v-72xp** HIGH - lxd allows Cross-guest volume hijack via DevLXD device patch (go:github.com/canonical/lxd \(fixed 0.0.0-20260626085133-7cb96ac80a6d\)) - [source](https://github.com/advisories/GHSA-hhf9-qw4v-72xp)

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
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.11.04 |
| NVD \(new CVEs\) | OK | 32 | 735 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 45 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 3 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 878 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
