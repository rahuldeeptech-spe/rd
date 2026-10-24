# Security report 2026-10-24

Generated 2026-10-24 08:43 UTC by an automated job. Window: last 24 hours. Not a substitute for the official vendor advisories.

## Needs attention (22)

- **CVE-2026-115806** CVSS 9.8 CRITICAL - The Prime Mover – Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.2.1 via deserialization of untrusted input in the migration search-and-replace ro… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115806)
- **CVE-2026-115727** CVSS 9.2 CRITICAL - AgenticSeek before commit 409840c contains a remote code execution vulnerability because llm\_server/app.py hardcodes Flask debug mode while binding to all interfaces. Attackers who reach the server port and obtain the d… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115727)
- **CVE-2026-115895** CVSS 8.8 HIGH - Happy DOM is a JavaScript implementation of a web browser without its graphical user interface. From 17.0.0 until 21.0.4, packages/happy-dom/src/module/ECMAScriptModuleCompiler.ts accepts a named ESM import alias withou… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115895)
- **CVE-2026-115775** CVSS 8.7 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, the twisted.words.xish.domish ExpatElementStream parser allows an unauthenticated remote peer to keep a contain… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115775)
- **CVE-2026-115938** CVSS 8.7 HIGH - Craft CMS allows any authenticated control panel user to submit an element-search condition whose element selector is evaluated as a sandboxed Twig object template. Craft’s allowed column filter delegates property looku… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115938)
- **CVE-2026-57845** CVSS 8.7 HIGH - Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code by crafting a malicious pickle file loaded through the deprecated pandas pack… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-57845)
- **CVE-2026-115481** CVSS 8.5 HIGH - baserCMS is a website development framework. Starting in version 5.0.0-beta1 and prior to versions 5.3.2 and 5.4.2, \`PermissionGroupsService::build\(\)\` reads a plugin's \`config/permission.php\` to decide what each user gr… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115481)
- **CVE-2026-112850** CVSS 8.1 HIGH - Improper Control of Filename for Include/Require Statement in PHP Program \('PHP Remote File Inclusion'\) vulnerability in AncoraThemes Your Dress your-dress allows PHP Local File Inclusion.This issue affects Your Dress:… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-112850)
- **CVE-2026-115776** CVSS 7.5 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.words.protocols.irc.IRC.dataReceived retains all bytes received without a line feed in its per-connecti… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115776)
- **CVE-2026-115778** CVSS 7.5 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.conch.telnet.Telnet.dataReceived appends every byte received after IAC SB to a persistent subnegotiatio… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115778)
- **CVE-2026-115887** CVSS 7.5 HIGH - GraphQL Scalars is a library of custom GraphQL scalars for creating precise type-safe GraphQL schemas. From 1.24.1 until 2.0.1, GraphQLPhoneNumber in src/scalars/PhoneNumber.ts uses ambiguous nested digit quantifiers th… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115887)
- **CVE-2026-105482** CVSS 7.4 HIGH - A flaw in Node.js DNS resolution allows hostnames containing a NUL byte to be silently truncated by the dns.resolve\*\(\) functions and dns.reverse\(\). This is an incomplete fix of CVE-2026-48930, which only covered dns.loo… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-105482)
- **CVE-2026-105483** CVSS 7.4 HIGH - A flaw in Node.js TLS hostname verification allows a certificate without a matching IP address SAN to authenticate a connection to an IPv4 address when the host is written with non-ASCII characters, such as fullwidth di… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-105483)
- **CVE-2026-106069** CVSS 7.4 HIGH - A flaw in Node.js TLS hostname verification can cause a server certificate to be validated against a different IP address than the one the client connected to, when the host is a non-canonical IPv4 literal with a leadin… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106069)
- **CVE-2026-115570** CVSS 7.4 HIGH - Electron is a framework for writing cross-platform desktop applications using JavaScript, HTML and CSS. Prior to 42.11.16, 43.8.1, 44.9.1, and 45.0.0-beta.6, Electron does not block compromised eMudhra intermediate cert… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115570)
- **CVE-2026-114622** CVSS 7.2 HIGH - baserCMS is a website development framework. In versions 5.2.3 before 5.3.2 and 5.4.0 before 5.4.2, the optional BcThemeFile plugin's Admin API validates a raw path in ThemeFilesService::update\(\) and getFullpath\(\), but… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114622)
- **CVE-2026-114624** CVSS 7.2 HIGH - baserCMS is a website development framework. In versions 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2, the widget-area entity serializes widgets only when the submitted value is an array, allowing a string submitted throug… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114624)
- **CVE-2026-115572** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF that repeatedly references the same nonexistent indirect object, causing relevant file parts such as pages to trigger… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115572)
- **CVE-2026-115580** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF with a standard cross-reference table whose declared entry count exceeds what the file can contain, causing excessive… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115580)
- **CVE-2026-115585** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an incomplete remediation for repeated malformed cross-reference entries in GHSA-55h5-xmcq-c37v could still trigger a complete PDF stream reload… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115585)
- **CVE-2026-115586** CVSS 7.1 HIGH - virtualenv is a tool for creating isolated virtual python environments. From 21.14.9 until 21.14.13, the bash bin/activate script can copy an attacker-controlled --prompt value into PS1 without escaping dollar signs or… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115586)
- **CVE-2026-113673** UNSCORED - The GeoDirectory WordPress plugin before 2.8.194 does not properly escape administrator-defined text before writing it into a generated PHP file in its own folder, allowing high privilege users such as a subsite adminis… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-113673)

## Actively exploited (CISA KEV, added in window)

- **CVE-2026-110447** - Collabora Collabora Online – Built-in CODE Server - Collabora Online – Built-in CODE Server OS Command Injection Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-110447)
- **CVE-2026-114625** - Arista VeloCloud Orchestrator - Arista VeloCloud Orchestrator SQL Injection Vulnerability - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114625)

## Critical new CVEs and watchlist matches (NVD)

- **CVE-2026-115806** CVSS 9.8 CRITICAL - The Prime Mover – Backup and Migration plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 2.2.1 via deserialization of untrusted input in the migration search-and-replace ro… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115806)
- **CVE-2026-115727** CVSS 9.2 CRITICAL - AgenticSeek before commit 409840c contains a remote code execution vulnerability because llm\_server/app.py hardcodes Flask debug mode while binding to all interfaces. Attackers who reach the server port and obtain the d… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115727)
- **CVE-2026-115895** CVSS 8.8 HIGH - Happy DOM is a JavaScript implementation of a web browser without its graphical user interface. From 17.0.0 until 21.0.4, packages/happy-dom/src/module/ECMAScriptModuleCompiler.ts accepts a named ESM import alias withou… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115895)
- **CVE-2026-115775** CVSS 8.7 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, the twisted.words.xish.domish ExpatElementStream parser allows an unauthenticated remote peer to keep a contain… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115775)
- **CVE-2026-115938** CVSS 8.7 HIGH - Craft CMS allows any authenticated control panel user to submit an element-search condition whose element selector is evaluated as a sandboxed Twig object template. Craft’s allowed column filter delegates property looku… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115938)
- **CVE-2026-57845** CVSS 8.7 HIGH - Hugging Face Datasets through 5.1.0 contains an insecure deserialization vulnerability that allows attackers to execute arbitrary Python code by crafting a malicious pickle file loaded through the deprecated pandas pack… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-57845)
- **CVE-2026-115481** CVSS 8.5 HIGH - baserCMS is a website development framework. Starting in version 5.0.0-beta1 and prior to versions 5.3.2 and 5.4.2, \`PermissionGroupsService::build\(\)\` reads a plugin's \`config/permission.php\` to decide what each user gr… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115481)
- **CVE-2026-112850** CVSS 8.1 HIGH - Improper Control of Filename for Include/Require Statement in PHP Program \('PHP Remote File Inclusion'\) vulnerability in AncoraThemes Your Dress your-dress allows PHP Local File Inclusion.This issue affects Your Dress:… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-112850)
- **CVE-2026-115776** CVSS 7.5 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.words.protocols.irc.IRC.dataReceived retains all bytes received without a line feed in its per-connecti… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115776)
- **CVE-2026-115778** CVSS 7.5 HIGH - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 26.10.0rc1, twisted.conch.telnet.Telnet.dataReceived appends every byte received after IAC SB to a persistent subnegotiatio… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115778)
- **CVE-2026-115887** CVSS 7.5 HIGH - GraphQL Scalars is a library of custom GraphQL scalars for creating precise type-safe GraphQL schemas. From 1.24.1 until 2.0.1, GraphQLPhoneNumber in src/scalars/PhoneNumber.ts uses ambiguous nested digit quantifiers th… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115887)
- **CVE-2026-105482** CVSS 7.4 HIGH - A flaw in Node.js DNS resolution allows hostnames containing a NUL byte to be silently truncated by the dns.resolve\*\(\) functions and dns.reverse\(\). This is an incomplete fix of CVE-2026-48930, which only covered dns.loo… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-105482)
- **CVE-2026-105483** CVSS 7.4 HIGH - A flaw in Node.js TLS hostname verification allows a certificate without a matching IP address SAN to authenticate a connection to an IPv4 address when the host is written with non-ASCII characters, such as fullwidth di… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-105483)
- **CVE-2026-106069** CVSS 7.4 HIGH - A flaw in Node.js TLS hostname verification can cause a server certificate to be validated against a different IP address than the one the client connected to, when the host is a non-canonical IPv4 literal with a leadin… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-106069)
- **CVE-2026-115570** CVSS 7.4 HIGH - Electron is a framework for writing cross-platform desktop applications using JavaScript, HTML and CSS. Prior to 42.11.16, 43.8.1, 44.9.1, and 45.0.0-beta.6, Electron does not block compromised eMudhra intermediate cert… - **watching: node.js** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115570)
- **CVE-2026-114622** CVSS 7.2 HIGH - baserCMS is a website development framework. In versions 5.2.3 before 5.3.2 and 5.4.0 before 5.4.2, the optional BcThemeFile plugin's Admin API validates a raw path in ThemeFilesService::update\(\) and getFullpath\(\), but… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114622)
- **CVE-2026-114624** CVSS 7.2 HIGH - baserCMS is a website development framework. In versions 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2, the widget-area entity serializes widgets only when the submitted value is an array, allowing a string submitted throug… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-114624)
- **CVE-2026-115572** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF that repeatedly references the same nonexistent indirect object, causing relevant file parts such as pages to trigger… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115572)
- **CVE-2026-115580** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an attacker can craft a PDF with a standard cross-reference table whose declared entry count exceeds what the file can contain, causing excessive… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115580)
- **CVE-2026-115585** CVSS 7.1 HIGH - pypdf is a free and open-source pure-python PDF library. Prior to 6.21.2, an incomplete remediation for repeated malformed cross-reference entries in GHSA-55h5-xmcq-c37v could still trigger a complete PDF stream reload… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115585)
- **CVE-2026-115586** CVSS 7.1 HIGH - virtualenv is a tool for creating isolated virtual python environments. From 21.14.9 until 21.14.13, the bash bin/activate script can copy an attacker-controlled --prompt value into PS1 without escaping dollar signs or… - **watching: python** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115586)
- **CVE-2026-113673** UNSCORED - The GeoDirectory WordPress plugin before 2.8.194 does not properly escape administrator-defined text before writing it into a generated PHP file in its own folder, allowing high privilege users such as a subsite adminis… - **watching: php** - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-113673)
- **CVE-2026-115889** CVSS 9.9 CRITICAL - Wasmtime is a runtime for WebAssembly. Prior to 36.0.19 and 43.0.0, the Cranelift compiler backend bit-packs SSA value indices in a way that can silently overflow in release builds when compiling a sufficiently large or… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115889)
- **CVE-2026-115893** CVSS 9.9 CRITICAL - Wasmtime is a runtime for WebAssembly. Prior to 36.0.19, 48.0.7, and 49.0.4, the Cranelift compiler backend on aarch64 can compile a Wasm br\_table instruction with more than approximately 256,000 targets so that it has… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115893)
- **CVE-2026-115931** CVSS 9.9 CRITICAL - Postiz lets a signed-in user ask the backend to run a function on one of their connected channels. The backend did not restrict which functions can be requested, so a user could call internal helper functions that were… - [source](https://nvd.nist.gov/vuln/detail/CVE-2026-115931)
- ...and 43 more (see the source).

## GitHub reviewed advisories (critical, plus high in watched ecosystems)

- **GHSA-5x8w-8jj5-q52h** CRITICAL - Pillow: Heap buffer overflow in FlashPix \(FPX\) JPEG decoding leads to code execution (pip:pillow \(fixed 13.0.0\)) - [source](https://github.com/advisories/GHSA-5x8w-8jj5-q52h)
- **GHSA-84c9-qqpq-2pq5** CRITICAL - obsidian-tc tokens can access arbitrary configured vaults (npm:obsidian-tc \(fixed 1.3.1\)) - [source](https://github.com/advisories/GHSA-84c9-qqpq-2pq5)
- **GHSA-897f-g5gm-fmxm** CRITICAL - Wasmtime: Bit-packing in Cranelift compiler causes silent overflow and miscompilation (rust:wasmtime \(fixed 36.0.19\), rust:wasmtime \(fixed 43.0.0\)) - [source](https://github.com/advisories/GHSA-897f-g5gm-fmxm)
- **GHSA-cxf3-9h37-7rr8** CRITICAL - Echo: Rejected WebSocket upgrades can bypass Echo route-level access controls (go:github.com/labstack/echo/v4 \(fixed 4.16.1\), go:github.com/labstack/echo/v5 \(fixed 5.4.1\)) - [source](https://github.com/advisories/GHSA-cxf3-9h37-7rr8)
- **GHSA-f9x3-7vq9-cph6** CRITICAL - Laravel TokenGuard authentication bypass through non-string API credentials (composer:laravel/framework \(fixed 13.29.0\), composer:laravel/framework \(fixed 12.68.0\)) - [source](https://github.com/advisories/GHSA-f9x3-7vq9-cph6)
- **GHSA-pqh8-4pj7-32xx** CRITICAL - obsidian-tc HTTP transport lacks Origin/DNS-rebinding protection, enabling drive-by vault access on loopback (npm:obsidian-tc \(fixed 1.3.1\)) - [source](https://github.com/advisories/GHSA-pqh8-4pj7-32xx)
- **GHSA-27r3-jxmh-p828** HIGH - body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body (npm:body-parser \(fixed 2.4.0\), npm:body-parser \(fixed 1.20.9\)) - [source](https://github.com/advisories/GHSA-27r3-jxmh-p828)
- **GHSA-3476-c5c2-fr73** HIGH - Twisted: Unauthenticated Remote Denial of Service in the Twisted words domish XML Element Stream via an Unbounded Element Tree (pip:Twisted \(fixed 26.10.0rc1\)) - [source](https://github.com/advisories/GHSA-3476-c5c2-fr73)
- **GHSA-394h-qwmc-48pf** HIGH - virtualenv: Xonsh activation literals depend on the script decoding codec (pip:virtualenv \(fixed 21.14.9\)) - [source](https://github.com/advisories/GHSA-394h-qwmc-48pf)
- **GHSA-4v6f-7vjh-6x4m** HIGH - Strands Agents SDK: Exposure of data element to wrong session in the A2A Server (pip:strands-agents \(fixed 1.43.0\), npm:@​strands-agents/sdk \(fixed 1.5.0\)) - [source](https://github.com/advisories/GHSA-4v6f-7vjh-6x4m)
- **GHSA-53xc-49m8-p798** HIGH - Twisted: Unauthenticated Remote Denial of Service in the Twisted IRC Server via an Unbounded Line Buffer (pip:Twisted \(fixed 26.10.0rc1\)) - [source](https://github.com/advisories/GHSA-53xc-49m8-p798)
- **GHSA-6c7f-9265-g8fw** HIGH - pypdf: Possible long runtimes for repeated references to the same missing object (pip:pypdf \(fixed 6.21.2\)) - [source](https://github.com/advisories/GHSA-6c7f-9265-g8fw)
- **GHSA-6w3r-xr62-4xcp** HIGH - virtualenv: Bash prompt values can change meaning under older compatibility modes (pip:virtualenv \(fixed 21.14.9\)) - [source](https://github.com/advisories/GHSA-6w3r-xr62-4xcp)
- **GHSA-737x-cwfr-5vvc** HIGH - obsidian-tc: Declined human-in-the-loop confirmations can permit destructive calls over HTTP (npm:obsidian-tc \(fixed 1.31.4\)) - [source](https://github.com/advisories/GHSA-737x-cwfr-5vvc)
- **GHSA-834v-8h66-3h79** HIGH - Happy DOM: Incomplete fix for CVE-2026-33943: unsanitized import alias leads to host code execution (npm:happy-dom \(fixed 21.0.4\)) - [source](https://github.com/advisories/GHSA-834v-8h66-3h79)
- **GHSA-9969-6676-49h5** HIGH - Echo: WebSocket proxy can retain connections and handlers after client disconnect (go:github.com/labstack/echo/v4 \(fixed 4.16.1\), go:github.com/labstack/echo/v5 \(fixed 5.4.1\)) - [source](https://github.com/advisories/GHSA-9969-6676-49h5)
- **GHSA-c8w8-3pqp-wr83** HIGH - SiYuan: A parser differential between the WebSocket keepalive exemption and the session quarantine allows unauthenticated access to the broadcast event stream (go:github.com/siyuan-note/siyuan/kernel \(fixed 0.0.0-20260731131820-67bc300b6ea6\)) - [source](https://github.com/advisories/GHSA-c8w8-3pqp-wr83)
- **GHSA-cwm5-jh59-mwxr** HIGH - Twisted: Unauthenticated Remote Denial of Service in the Twisted conch Telnet Transport via an Unbounded Subnegotiation Buffer (pip:Twisted \(fixed 26.10.0rc1\)) - [source](https://github.com/advisories/GHSA-cwm5-jh59-mwxr)
- **GHSA-cx6f-vjhg-g3cc** HIGH - virtualenv: Bash activator leaves the --prompt value unescaped in PS1 when promptvars is off, so prompt expansion later executes it \(regression in 21.14.9\) (pip:virtualenv \(fixed 21.14.13\)) - [source](https://github.com/advisories/GHSA-cx6f-vjhg-g3cc)
- **GHSA-f2hq-32vh-53cc** HIGH - postal-mime: Quadratic CPU consumption when decoding a header of many joinable RFC 2047 base64 encoded words (npm:postal-mime \(fixed 4.0.8\)) - [source](https://github.com/advisories/GHSA-f2hq-32vh-53cc)
- **GHSA-f48p-c9v4-h7xv** HIGH - Echo: BodyDump captures request and response bodies without size limits in v4 (go:github.com/labstack/echo/v4 \(fixed 4.16.1\)) - [source](https://github.com/advisories/GHSA-f48p-c9v4-h7xv)
- **GHSA-gmh7-3g9r-mjh5** HIGH - pypdf: Possible long runtimes for large xref table header limits (pip:pypdf \(fixed 6.21.2\)) - [source](https://github.com/advisories/GHSA-gmh7-3g9r-mjh5)
- **GHSA-gx7p-2j49-hfq4** HIGH - vLLM : DoS via unvalidated mm\_processor\_kwargs in multimodal image processors \(Isaac, InternVL, H2OVL, etc.\) (pip:vllm \(fixed 0.31.0\)) - [source](https://github.com/advisories/GHSA-gx7p-2j49-hfq4)
- **GHSA-h7wr-284f-5qvc** HIGH - Echo: Decompress permits unbounded gzip expansion in v4 (go:github.com/labstack/echo/v4 \(fixed 4.16.1\)) - [source](https://github.com/advisories/GHSA-h7wr-284f-5qvc)
- **GHSA-h7ww-273w-6cm8** HIGH - Mistune: Path Traversal and XSS in Include directive (pip:mistune \(fixed 3.3.0\)) - [source](https://github.com/advisories/GHSA-h7ww-273w-6cm8)
- ...and 7 more (see the source).

## Node.js releases in window

No Node.js release in the window.

## Tracked versions (upstream latest vs advisories.tsv)

| Runtime | Branch | Upstream latest | advisories.tsv fixed |
|---|---|---|---|
| go | 1.26 | 1.26.10 | 1.26.10 |
| go | 1.27 | 1.27.3 | 1.27.3 |
| node | 22 | 22.23.4 | 22.23.4 |
| node | 24 | 24.22.1 | 24.22.1 |
| node | 26 | 26.12.1 | 26.12.1 |
| php | 8.2 | 8.2.35 | 8.2.35 |
| php | 8.3 | 8.3.36 | 8.3.36 |
| php | 8.4 | 8.4.27 | 8.4.27 |
| php | 8.5 | 8.5.12 | 8.5.12 |

## Sources

| Source | Status | Items | Note |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | OK | 2 | catalog 2026.10.23 |
| NVD \(new CVEs\) | OK | 68 | 478 CVEs published in window; showing CRITICAL \(9.0+\) and watchlist matches |
| GitHub Advisory Database | OK | 32 | critical in all ecosystems; high only for composer, go, npm, pip |
| nodejs.org release index | OK | 0 | 875 versions in index |
| go.dev downloads | OK | 0 | branches: 1.26, 1.27 |
| php.net releases | OK | 0 | branches: 8.2, 8.3, 8.4, 8.5 |

## How to use this

- Run [`patchcheck`](https://github.com/rahuldeeptech-spe/rd) on your servers to see whether they are affected.
- Subscribe: Watch the repository (Custom > Issues) for alerts, or follow the branch feed `/commits/reports.atom`.
- Entries marked REVIEW mean the rules in `advisories.tsv` may be stale. A maintainer must confirm them against the official advisory.


Past reports: [archive/](archive/)
