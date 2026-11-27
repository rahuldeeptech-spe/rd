# Security report 2026-11-27

Generated 2026-11-27 15:08 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

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

- **CVE-2026-126984** CVSS 10.0 CRITICAL - A \*\*server-side request forgery\*\* flaw has been found in the get\_remote\_artifact\_url\(\) function in pulp\_python/app/models.py of the pull-through caching feature in the \*\*pulp\_python\*\* package. The function uses the redi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-126984)
- **CVE-2026-137721** CVSS 10.0 CRITICAL - A vulnerability in the Platform component of Mitel OpenScape 4000 and OpenScape 4000 Manager could allow an attacker to conduct a command injection attack due to insufficient parameter sanitization. A successful exploit… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137721)
- **CVE-2026-137724** CVSS 10.0 CRITICAL - A vulnerability in the Platform component of Mitel OpenScape 4000, and OpenScape 4000 Manager could allow an unauthenticated attacker to conduct an unauthorized access attack due to improper authentication mechanisms. A… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137724)
- **CVE-2026-134963** CVSS 9.9 CRITICAL - Improper Control of Generation of Code \('Code Injection'\) vulnerability in Webdeclic WPMasterToolKit wpmastertoolkit allows Code Injection.This issue affects WPMasterToolKit: from n/a through 2.26.1. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134963)
- **CVE-2026-137498** CVSS 9.9 CRITICAL - Budibase Server from 3.39.18 before 4.0.0 contains a prototype pollution vulnerability that allows unauthenticated attackers to erase MongoDB query filters by supplying \_\_proto\_\_ as a dynamic JSON key in PUBLIC queries.… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137498)
- **CVE-2026-104998** CVSS 9.8 CRITICAL - The Product Input Fields for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.1.0 via the process\_file\_input\_field function. This is due to missing file typ… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-104998)
- **CVE-2026-106125** CVSS 9.8 CRITICAL - The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 8.7 via the 'callback' parameter of the sneeit\_compact\_menu\_mega\_content AJAX action. The handler sneeit… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106125)
- **CVE-2026-115867** CVSS 9.8 CRITICAL - The Database for Contact Form 7, WPforms, Elementor forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.5.5 via the copy\_files function. This is due to missing file… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115867)
- **CVE-2026-134994** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data vulnerability in Nitramix Revertix &amp;#​8211; Backup, Migration, Staging &amp;amp; Clone revertix allows Object Injection.This issue affects Revertix &amp;#​8211; Backup, Migration, Staging &amp;amp; C… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-134994)
- **CVE-2026-135933** CVSS 9.8 CRITICAL - Incorrect Privilege Assignment vulnerability in Tobias WebinarIgnition webinar-ignition allows Privilege Escalation.This issue affects WebinarIgnition: from n/a through 4.28.1. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135933)
- **CVE-2026-137738** CVSS 9.8 CRITICAL - In RealVNC Server before 7.19.1, UDP-based connections could potentially be exploited without authentication to execute code remotely or cause the software to crash. This could allow an attacker to remotely execute code… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137738)
- **CVE-2026-137723** CVSS 9.6 CRITICAL - A vulnerability in the Platform component of Mitel OpenScape 4000 and OpenScape 4000 Manager could allow an attacker to conduct a command injection attack due to insufficient parameter sanitization. A successful exploit… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137723)
- **CVE-2026-106169** CVSS 9.4 CRITICAL - A Deserialization of Untrusted Data vulnerability in the eventbus execution in Google Cloud Application Integration versions prior to 2026-09-22 on Google Cloud Platform allows an authenticated attacker to achieve remot… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106169)
- **CVE-2026-124981** CVSS 9.4 CRITICAL - A vulnerability has been identified in Mendix OIDC Provider \(Mendix 10 compatible\) \(All versions &lt; V6.0.0\), Mendix OIDC Provider \(Mendix 11 compatible\) \(All versions &lt; V6.0.0\), Mendix OIDC Provider \(Mendix 9 compatible\)… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-124981)
- **CVE-2026-137544** CVSS 9.4 CRITICAL - LaraDashboard before 1.5.0 contains a path traversal vulnerability in module.json providers and composer.json psr-4 namespace parsing that derives destination folder names without excluding traversal characters. Attacke… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137544)
- **CVE-2026-137706** CVSS 9.4 CRITICAL - Smart Portal developed by Direk Tech has a Missing Authorization vulnerability. Authenticated remote attackers can add a specified account to the Active Directory Domain Admins group, thereby obtaining domain administra… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137706)
- **CVE-2026-135009** CVSS 9.3 CRITICAL - Improper Neutralization of Special Elements used in an SQL Command \('SQL Injection'\) vulnerability in David Lingren Media LIbrary Assistant media-library-assistant allows Blind SQL Injection.This issue affects Media LIb… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135009)
- **CVE-2026-137499** CVSS 9.3 CRITICAL - Budibase from 3.41.0 before 4.0.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to take over password-less global Builder accounts via unverified-email OIDC/SSO account linking. A… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137499)
- **CVE-2026-137536** CVSS 9.3 CRITICAL - ToolJet before 3.21.94-beta contains an authentication bypass in its server OAuth SSO sign-in module, which resolves Google and Git SSO logins solely by the provider-asserted email without checking email\_verified or bin… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137536)
- **CVE-2026-137550** CVSS 9.3 CRITICAL - Frappe Framework before 15.122.0 and 16.x before 16.50.0 contains a missing authorization vulnerability in Document.update\(\) that fails to validate whether the caller is permitted to submit or modify the target document… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137550)
- **CVE-2026-59103** CVSS 9.3 CRITICAL - MONEO ERP exposes the Ping method of its \_slave JSON-RPC service over WebSocket as @​rpc.openpublic, so it can be called without a valid session. The method's only guard compares the calling application name with "\_login… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-59103)
- **CVE-2026-85258** CVSS 9.3 CRITICAL - A Missing Authorization vulnerability in the private console API in Google Cloud Vertex AI \(Vertex AI Assistant\) versions prior to 2026-04-13 on Google Cloud Platform allows an unauthenticated remote attacker to list, r… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-85258)
- **CVE-2026-135384** CVSS 9.2 CRITICAL - Improper authentication in OIDC bearer token verification in Canonical LXD before 5.0.12, 5.21.10, 6.10.2 allows a remote attacker holding a token signed by the configured identity provider to authenticate to the LXD AP… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-135384)
- **CVE-2026-137547** CVSS 9.2 CRITICAL - Coder before 2.29.27, 2.30.0 before 2.34.19, 2.35.0 before 2.37.11, 2.38.0 before 2.38.7, and 2.39.0 before 2.39.1 returns database connection errors containing a temporary AWS IAM database password in API key middlewar… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-137547)
- **CVE-2026-127163** CVSS 9.1 CRITICAL - Improper certificate validation in websocket connections in Canonical pylxd before 2.4.3 allows a network attacker to read command stdin and spoof command output via impersonating a remote LXD endpoint. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-127163)
- ...and 10 more (see the source).

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
| node | 27 | 27.0.0-alpha.0.2.0 | - | - |
| php | 8.2 | 8.2.36 | 8.2.35 | - |
| php | 8.3 | 8.3.37 | 8.3.36 | - |
| php | 8.4 | 8.4.28 | 8.4.27 | - |
| php | 8.5 | 8.5.13 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.11.25 |
| NVD \(new CVEs\) | OK | 35 | 476 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 22 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 0 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 884 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
