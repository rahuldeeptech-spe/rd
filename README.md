# Security report 2026-11-17

Generated 2026-11-17 14:28 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (7)

- **CVE-2026-95839** CVSS 7.1 HIGH - containerd is an open-source container runtime. From 2.2.0 until 2.2.10, 2.3.7, and 2.4.2, image manifest processing through the transfer service can encounter a child descriptor containing the io.containerd.manifest.su… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-95839)
- **go 1.26** - REVIEW: upstream go 1.26 is 1.26.11, advisories.tsv is reviewed up to 1.26.10. Read the release notes for new security fixes and update the rules. - **watching: go**
- **go 1.27** - REVIEW: upstream go 1.27 is 1.27.4, advisories.tsv is reviewed up to 1.27.3. Read the release notes for new security fixes and update the rules. - **watching: go**
- **node 22** - REVIEW: upstream node 22 is 22.23.5, advisories.tsv is reviewed up to 22.23.4 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 24** - REVIEW: upstream node 24 is 24.22.3, advisories.tsv is reviewed up to 24.22.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.1, advisories.tsv is reviewed up to 26.12.1 and upstream marks it a security release. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

No new entries in the window.

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-95839** CVSS 7.1 HIGH - containerd is an open-source container runtime. From 2.2.0 until 2.2.10, 2.3.7, and 2.4.2, image manifest processing through the transfer service can encounter a child descriptor containing the io.containerd.manifest.su… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-95839)
- **CVE-2026-120387** CVSS 10.0 CRITICAL - An improper JWT signature verification vulnerability in CIRCUTOR PowerStudio SCADA WAVE desktop version allows an unauthenticated remote attacker to bypass authentication by submitting an unsigned JWT with the algorithm… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120387)
- **CVE-2026-53998** CVSS 10.0 CRITICAL - Phoenix is an AI observability and evaluation platform. From 13.0.0 until 15.7.0, the applyChatTemplate GraphQL query passed attacker-controlled F-string templates to FStringTemplateFormatter.\_format, while DotDict.\_\_ge… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-53998)
- **CVE-2026-129448** CVSS 9.8 CRITICAL - Deserialization of Untrusted Data in Apache Roller versions 4.0.0 through 6.1.4 allows an unauthenticated remote attacker to execute arbitrary code. The XML-RPC endpoint accepts vendor extension types and deserializes t… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129448)
- **CVE-2026-79614** CVSS 9.8 CRITICAL - An out-of-bounds write vulnerability in “libclinkc.so” in Zyxel DX3301-T0/EX3301-T0 firmware versions through 5.50\(ABVY.8.3\)C0 could allow an unauthenticated attacker to elevate privileges and potentially execute arbitr… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-79614)
- **CVE-2026-119623** CVSS 9.4 CRITICAL - The installer \(first installation wizard\) could be re-enabled on an already configured instance by placing a file whose name starts with FIRST\_INSTALL in the public web root or the project root. The installer then becam… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119623)
- **CVE-2026-120699** CVSS 9.4 CRITICAL - CubeSandbox is an instant, concurrent, secure, and lightweight sandbox for AI agents. Prior to 0.5.1, any authenticated tenant permitted to call POST /sandboxes can supply metadata\["host-mount"\] with an arbitrary existi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120699)
- **CVE-2026-130587** CVSS 9.4 CRITICAL - OpenFunction through 1.2.0 contains a privilege escalation vulnerability that allows namespace tenants to create privileged host-access pods by supplying unrestricted PodSpec templates in Function and Serving resources.… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130587)
- **CVE-2026-129272** CVSS 9.3 CRITICAL - N-able N-central before 2026.4.1 HF3 uses a predictable credential to authenticate appliances to an agent-facing API. A remote, unauthenticated attacker who knows or guesses an appliance identifier can obtain a valid ap… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129272)
- **CVE-2026-129280** CVSS 9.3 CRITICAL - Multiple ServerUI and ServerUI2 SOAP operations in N-able N-central before 2026.4.1 HF3 do not verify the caller's session, permissions or customer scope. A remote attacker, in some cases without authentication, can rea… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129280)
- **CVE-2026-129941** CVSS 9.3 CRITICAL - Prime CMS \(@​primecms/core\) through 0.4.0-beta.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to register accounts via the createUser mutation on /prime/graphql. Because the isAut… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129941)
- **CVE-2026-129952** CVSS 9.3 CRITICAL - NodePress through 8.5.1 contains an authentication bypass vulnerability that allows unauthenticated remote attackers to gain administrator access by forging JWTs with the hardcoded 'nodepress-secret' fallback key. Attac… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129952)
- **CVE-2026-129955** CVSS 9.3 CRITICAL - NodePress through 8.5.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to gain administrator access by using the hardcoded default password 'root'. Attackers can send base64-encode… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129955)
- **CVE-2026-130070** CVSS 9.3 CRITICAL - Ghost by muneeb141 on the main branch from commit c731cdf through commit 672dfec contains an authentication bypass vulnerability in the whitelisted ghost.api.ghost.convert\_to\_real\_user method that allows unauthenticated… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130070)
- **CVE-2026-130071** CVSS 9.3 CRITICAL - TridotsTech go1cms master branch through commit 7f68d05 and version-3 branch before commit ead8da3 contains a missing authentication vulnerability in the guest-whitelisted update\_doc method that allows unauthenticated a… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130071)
- **CVE-2026-130320** CVSS 9.3 CRITICAL - In Open Object Rexx \(ooRexx\) before 5.2.0, RXAPI mishandles nameArg and userid bounds checking, possibly leading to arbitrary code execution via crafted messages. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130320)
- **CVE-2026-130327** CVSS 9.3 CRITICAL - In Open Object Rexx \(ooRexx\) before 5.2.0, RXAPI relies on a world-writable /tmp file unless XDG\_RUNTIME\_DIR is set, or localhost TCP port 10010, allowing RXAPI communication by any local user, e.g., for injection of a… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130327)
- **CVE-2026-130603** CVSS 9.3 CRITICAL - Eclipse Zenoh's zenoh-pico implementation, versions 0.7.2-rc up to but excluding 1.10.2, does not validate the Zenoh identifier \(ZID\) length when deserializing timestamps. An attacker-controlled length greater than 16 c… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130603)
- **CVE-2026-104840** CVSS 9.2 CRITICAL - OpenCTI is an open source platform for managing cyber threat intelligence knowledge and observables. Prior to 7.260428.0, the token GraphQL mutation used for primary login has no endpoint-specific rate limit, while the… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-104840)
- **CVE-2026-129286** CVSS 9.2 CRITICAL - N-able N-central before 2026.4.1 HF3 does not validate version values and download locations in software update metadata. An attacker able to supply or modify the update metadata received by the server can write files o… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-129286)
- **CVE-2026-130366** CVSS 9.2 CRITICAL - AdminNeo before 5.9.1 contains an authentication bypass vulnerability in the ClickHouse driver that allows remote attackers to log in to passwordless accounts without the configured defaultPasswordHash password. Attacke… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130366)
- **CVE-2026-130369** CVSS 9.2 CRITICAL - phpMyFAQ 4.1.9 before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2 contains an authorization bypass vulnerability in multisite deployments that allows attackers to overwrite passkeys of accounts on other tenants via a share… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130369)
- **CVE-2026-130371** CVSS 9.2 CRITICAL - phpMyFAQ before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2 contains an authentication bypass vulnerability because the web installer ignores the legacy config/database.php during 3.x upgrades. Unauthenticated attackers ca… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130371)
- **CVE-2026-130380** CVSS 9.2 CRITICAL - AdminNeo before 5.9.1 contains an authentication bypass vulnerability in the sqlsrv-based MS SQL driver that allows unauthenticated attackers to log in by submitting an empty username. Attackers can supply any non-empty… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130380)
- **CVE-2026-130583** CVSS 9.2 CRITICAL - Rootways Authorize.net CIM Pro extension for Magento 2 before 4.1.5 contains an unauthenticated server-side request forgery vulnerability in the Apple Pay merchant validation controller. Attackers can supply file://, go… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-130583)

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-24c4-3p7v-29cm** HIGH - AIOHTTP: Base64 multipart parts bypass client\_max\_size (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-24c4-3p7v-29cm)
- **GHSA-259w-wmqg-fp76** HIGH - termux-sync: Arbitrary file write during restore via attacker-controlled manifest source path (pip:termux-sync \(fixed 1.2.4\)) - [source](https://github.com/advisories/GHSA-259w-wmqg-fp76)
- **GHSA-28qf-cpwq-vmc2** HIGH - AIOHTTP: Pure-Python parser request replay and buffer growth behind a declined upgrade (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-28qf-cpwq-vmc2)
- **GHSA-3r8g-jcqq-3p5j** HIGH - SvelteKit: DoS while parsing form data from a remote functions \`form\` (npm:@​sveltejs/kit \(fixed 3.1.1\)) - [source](https://github.com/advisories/GHSA-3r8g-jcqq-3p5j)
- **GHSA-3rp8-rxj8-mvjw** HIGH - AIOHTTP: WebSocket max\_msg\_size bypass via integer overflow (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-3rp8-rxj8-mvjw)
- **GHSA-5rmc-48h2-hvcm** HIGH - AIOHTTP: WebSocket receive queue limits bypassed by small or compressed messages (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-5rmc-48h2-hvcm)
- **GHSA-72px-j8gh-p79x** HIGH - mail-parser: Sender IP address spoofing in get\_server\_ipaddress\(\) (pip:mail-parser \(fixed 4.6.2\)) - [source](https://github.com/advisories/GHSA-72px-j8gh-p79x)
- **GHSA-7mxv-7h3q-9324** HIGH - NLTK dot2img runs Graphviz 'dot' without the trusted-exec chokepoint, enabling local code execution via a writable PATH element (pip:nltk \(fixed 3.10.4\)) - [source](https://github.com/advisories/GHSA-7mxv-7h3q-9324)
- **GHSA-8vf2-hxg5-crqh** HIGH - Kubeshark: MCP \`start\_kubeshark\` argument injection via \`pod\_regex\` → image redirect → cluster takeover (go:github.com/kubeshark/kubeshark \(fixed 0.0.2-0.20260812200004-a76a1920dc75\)) - [source](https://github.com/advisories/GHSA-8vf2-hxg5-crqh)
- **GHSA-c94f-87xg-65wf** HIGH - Silverstripe Framework: RCE via i18nTextCollectorTask writer parameter (composer:silverstripe/framework \(fixed 6.2.13\)) - [source](https://github.com/advisories/GHSA-c94f-87xg-65wf)
- **GHSA-h4cc-hm5h-fmm9** HIGH - AIOHTTP: Concatenated compressed streams cause excessive CPU use (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-h4cc-hm5h-fmm9)
- **GHSA-jm3w-gw2p-xjfj** HIGH - AIOHTTP: Event loop stall in add\_domain\(\) wildcard matching (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-jm3w-gw2p-xjfj)
- **GHSA-jq3q-62jc-fqq9** HIGH - code-review-mcp-server: Command injection via unsanitized folderPath/baseBranch parameters (npm:code-review-mcp-server \(fixed 1.5.3\)) - [source](https://github.com/advisories/GHSA-jq3q-62jc-fqq9)
- **GHSA-m9j8-jcmv-hp69** HIGH - SvelteKit: Build-time server-only module import guard could fail, resulting in server secrets being statically replaced in client bundle (npm:@​sveltejs/kit \(fixed 3.1.1\)) - [source](https://github.com/advisories/GHSA-m9j8-jcmv-hp69)
- **GHSA-pw86-h8fm-j323** HIGH - AIOHTTP: Unbounded buffering of data received during an upgrade request (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-pw86-h8fm-j323)
- **GHSA-r7w7-vpq8-c5vv** HIGH - mail-parser is vulnerable to polynomial ReDoS in email header parsing (pip:mail-parser \(fixed 4.6.1\)) - [source](https://github.com/advisories/GHSA-r7w7-vpq8-c5vv)
- **GHSA-w553-pwx6-3mg9** HIGH - lightsaml allows Signature wrapping bypass (composer:litesaml/lightsaml \(fixed 5.0.1\), composer:litesaml/lightsaml \(fixed 4.7.1\)) - [source](https://github.com/advisories/GHSA-w553-pwx6-3mg9)
- **GHSA-xgw8-8ccx-rmqh** HIGH - AIOHTTP: Too many URL-encoded form fields block the event loop (pip:aiohttp \(fixed 3.14.4\)) - [source](https://github.com/advisories/GHSA-xgw8-8ccx-rmqh)

## Node.js releases in window

- **node 27.0.0-alpha.0.1.1** - Node.js 27.0.0-alpha.0.1.1 released - **watching: node.js** - [source](https://nodejs.org/en/blog/vulnerability)

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed | Reviewed up to |
|---|---|---|---|---|
| go | 1.26 | 1.26.11 | 1.26.10 | - |
| go | 1.27 | 1.27.4 | 1.27.3 | - |
| node | 22 | 22.23.5 | 22.23.4 | - |
| node | 24 | 24.22.3 | 24.22.1 | - |
| node | 26 | 26.13.1 | 26.12.1 | - |
| node | 27 | 27.0.0-alpha.0.1.1 | - | - |
| php | 8.2 | 8.2.35 | 8.2.35 | - |
| php | 8.3 | 8.3.36 | 8.3.36 | - |
| php | 8.4 | 8.4.27 | 8.4.27 | - |
| php | 8.5 | 8.5.12 | 8.5.12 | - |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 0 | catalog 2026.11.13 |
| NVD \(new CVEs\) | OK | 25 | 396 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 40 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 18 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 1 | 883 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
