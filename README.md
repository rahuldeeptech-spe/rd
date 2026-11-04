# Security report 2026-11-04

Generated 2026-11-04 13:01 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (7)

- **CVE-2026-119977** - WordPress WordPress Core - WordPress WordPress Core Time-of-check Time-of-use \(TOCTOU\) Race Condition Vulnerability - **watching: wordpress-core** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119977)
- **CVE-2026-112917** CVSS 9.2 CRITICAL - In Docker Desktop for Windows with the WSL2 backend, an unprivileged Linux container can use 32-bit socketcall to bypass the default seccomp restriction on AF\_VSOCK. This can expose host-facing services and Windows file… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-112917)
- **CVE-2026-103916** CVSS 8.4 HIGH - Docker Sandboxes sbx cp does not safely confine host-side paths to a shared workspace. A malicious sandbox can create or replace a workspace symlink so that a later user-initiated copy reads a host file outside the work… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103916)
- **CVE-2026-121614** CVSS 7.1 HIGH - Docker Sandboxes versions 0.31.0 before 0.50.0 do not neutralize repository-controlled Git configuration when running certain host-side Git commands. An attacker who can modify a host repository's Git configuration, for… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121614)
- **node 24** - REVIEW: upstream node 24 is 24.22.2, advisories.tsv is reviewed up to 24.22.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 26** - REVIEW: upstream node 26 is 26.13.0, advisories.tsv is reviewed up to 26.12.1. Read the release notes for new security fixes and update the rules. - **watching: node**
- **node 27** - REVIEW: new node branch 27 exists upstream but advisories.tsv has no rule for it \(it falls back to the 'newer' rule\). - **watching: node**

## Actively exploited (CISA KEV, added in window)

- **CVE-2026-119977** - WordPress WordPress Core - WordPress WordPress Core Time-of-check Time-of-use \(TOCTOU\) Race Condition Vulnerability - **watching: wordpress-core** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-119977)

## Critical new CVEs and CVEs about watched products (NVD)

- **CVE-2026-112917** CVSS 9.2 CRITICAL - In Docker Desktop for Windows with the WSL2 backend, an unprivileged Linux container can use 32-bit socketcall to bypass the default seccomp restriction on AF\_VSOCK. This can expose host-facing services and Windows file… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-112917)
- **CVE-2026-103916** CVSS 8.4 HIGH - Docker Sandboxes sbx cp does not safely confine host-side paths to a shared workspace. A malicious sandbox can create or replace a workspace symlink so that a later user-initiated copy reads a host file outside the work… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-103916)
- **CVE-2026-121614** CVSS 7.1 HIGH - Docker Sandboxes versions 0.31.0 before 0.50.0 do not neutralize repository-controlled Git configuration when running certain host-side Git commands. An attacker who can modify a host repository's Git configuration, for… - **watching: docker** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121614)
- **CVE-2026-28336** CVSS 9.9 CRITICAL - SolarWinds Dameware was found to be affected by a command injection vulnerability that could lead to the compromise of the remotely controlled host. Authentication is required. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-28336)
- **CVE-2026-114549** CVSS 9.8 CRITICAL - NoMachine nxwebrunner Heap-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of NoMachine. Authentication is not re… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114549)
- **CVE-2026-38600** CVSS 9.8 CRITICAL - A Zip Slip vulnerability in the /upload endpoint of codeskyblue gohttpserver through v1.3.0 allows attackers to write arbitrary files via uploading a crafted Zip archive. - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-38600)
- **CVE-2026-44266** CVSS 9.8 CRITICAL - Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, the Ruby backend in src/compilers/ruby.ts embeds attacker-controlled text in Ruby double-quoted strings without escaping #​, so Ruby inter… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-44266)
- **CVE-2026-44267** CVSS 9.8 CRITICAL - Elo is a purely functional expression language for no-code tools. Prior to 1.0.1, plain Elo strings supplied to defaultFormats.elo.parse\(\), bin/elo, or elo-lang.org/try can use .constructor.constructor to reach JavaScri… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-44267)
- **CVE-2026-92188** CVSS 9.8 CRITICAL - Quest Foglight for Databases ForgeMBeanServerSupport Missing Authentication Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Quest Fo… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-92188)
- **CVE-2026-92189** CVSS 9.8 CRITICAL - Quest Foglight for Databases writeTopologySectionToFile External Control of File Path Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations o… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-92189)
- **CVE-2026-92190** CVSS 9.8 CRITICAL - Quest Foglight for Databases baseRmiServiceExporter Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations o… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-92190)
- **CVE-2026-95731** CVSS 9.8 CRITICAL - Hardcoded password vulnerabilities in the command-line interface of HPE Networking Fabric Composer could allow an unauthenticated remote attacker to access the affected system using hardcoded credentials. Successful exp… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-95731)
- **CVE-2026-120931** CVSS 9.6 CRITICAL - Out of bounds write in WebGL in Google Chrome on on Android prior to 156.0.8078.47 allowed a remote attacker to execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: Critical\) - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-120931)
- **CVE-2026-121030** CVSS 9.6 CRITICAL - Incorrect authorization in DevTools in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chr… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121030)
- **CVE-2026-121034** CVSS 9.6 CRITICAL - Use after free in Views in Google Chrome on on Windows prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium secu… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121034)
- **CVE-2026-121035** CVSS 9.6 CRITICAL - Use after free in Prerender in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: Critical\) - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121035)
- **CVE-2026-121037** CVSS 9.6 CRITICAL - Out of bounds write in ANGLE in Google Chrome on on Windows prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121037)
- **CVE-2026-121060** CVSS 9.6 CRITICAL - Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(C… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121060)
- **CVE-2026-121071** CVSS 9.6 CRITICAL - Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(C… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121071)
- **CVE-2026-121074** CVSS 9.6 CRITICAL - Memory corruption in GPU in Google Chrome on on Android prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: Hi… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121074)
- **CVE-2026-121076** CVSS 9.6 CRITICAL - Use after free in WebXR in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity:… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121076)
- **CVE-2026-121077** CVSS 9.6 CRITICAL - Use after free in Mobile in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium secur… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121077)
- **CVE-2026-121086** CVSS 9.6 CRITICAL - Buffer overflow in Skia in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: High\) - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121086)
- **CVE-2026-121089** CVSS 9.6 CRITICAL - Use after free in WebGPU in Google Chrome prior to 157.0.8103.38 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(Chromium security severity: High\) - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121089)
- **CVE-2026-121104** CVSS 9.6 CRITICAL - Incorrect authorization in FileSystem in Google Chrome prior to 157.0.8103.38 allowed a remote attacker leveraging social engineering to potentially execute arbitrary code outside the sandbox via a crafted HTML page. \(C… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-121104)
- ...and 39 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-33r5-xmm8-v6x5** CRITICAL - Elo JavaScript emitter has sandbox escape to arbitrary Node.js / browser code execution via unfiltered \`.constructor\` member access (npm:@​enspirit/elo \(fixed 1.0.1\)) - [source](https://github.com/advisories/GHSA-33r5-xmm8-v6x5)
- **GHSA-7w38-ggh5-v542** CRITICAL - Elo Ruby backend has Remote Code Execution via unescaped \`#​{...}\` interpolation in emitted string literals and subtype-constraint labels (npm:@​enspirit/elo \(fixed 1.0.1\)) - [source](https://github.com/advisories/GHSA-7w38-ggh5-v542)
- **GHSA-48v2-6jcm-fc99** HIGH - praktor: Path traversal in Telegram file uploads allows writing outside the agent workspace uploads/ directory \(stored instruction injection\) (go:github.com/mtzanidakis/praktor \(fixed 0.9.1\)) - [source](https://github.com/advisories/GHSA-48v2-6jcm-fc99)
- **GHSA-gh9r-c94j-cmp5** HIGH - Stanza: RCE via pickle deserialization in the lemmatizer (pip:stanza \(fixed 1.15.0\)) - [source](https://github.com/advisories/GHSA-gh9r-c94j-cmp5)
- **GHSA-x9rp-7wh3-2rj5** HIGH - Elo backends have code injection via unvalidated emission of programmatic AST fields (npm:@​enspirit/elo \(fixed 1.0.1\)) - [source](https://github.com/advisories/GHSA-x9rp-7wh3-2rj5)

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
| CISA Known Exploited Vulnerabilities | OK | 1 | catalog 2026.11.03 |
| NVD \(new CVEs\) | OK | 64 | 816 CVEs published in window; showing CRITICAL \(9.0+\) and CVEs about a watched product itself; 26 more only mention one \(apps, plugins, libraries\) and are not… |
| GitHub Advisory Database | OK | 5 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 878 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
