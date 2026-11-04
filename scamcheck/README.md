# ScamCheck

Paste an SMS, WhatsApp message, email or link and get an instant answer: **is this a scam?**
English and हिन्दी. Free, private, works offline. No server, no tracking, no dependencies.

It targets the scams that hurt people in India right now:

- "Digital arrest" calls (fake CBI / police / customs / TRAI)
- Fake KYC, PAN, Aadhaar, bank-block messages and look-alike bank/government domains
- UPI traps ("enter PIN to receive", "scan QR to get refund") and OTP theft
- Fake APKs and remote-access apps (AnyDesk, TeamViewer ...)
- Task / part-time job scams, investment and stock-tip groups, lottery and advance-fee scams
- Fake courier, FASTag, challan, electricity-bill scares, "Hi Mum, new number"

## APK scanner (`apk.html`)

Drop in an `.apk` that someone sent you (WhatsApp, Telegram, a link) **before** installing it. Everything runs in the browser, the file is never uploaded.

It unzips the APK, decodes the binary `AndroidManifest.xml`, and looks for the traits of Indian SMS-stealer and banking-trojan apps:

- SMS read/receive/send, notification listener, Accessibility service, Device Admin, screen overlay, "install other apps"
- Combos: SMS + internet (OTP exfiltration), Accessibility + overlay (banking trojan), powerful permissions with no launcher icon (hidden app)
- Telegram-bot exfiltration strings, dynamic code loading, payloads hidden in `assets/`, suspicious server URLs in the DEX
- Missing signature or a generic "Android Debug" certificate, very old target SDK
- Lure names: `PM_Kisan`, `KYC`, `challan`, `SBI reward`, ...
- SHA-256 of the file, with a hash-only VirusTotal lookup link

Limits: static analysis only (no code is run), no signature database, and obfuscated or packed malware can hide behaviour. A legit-looking score never makes an unknown APK safe. Files over 150 MB are refused, and decompression is capped to defeat zip bombs.

## MCP auditor (`mcp.html`)

For people who connect AI assistants to MCP servers. Paste an MCP client config (`claude_desktop_config.json`, `.mcp.json`, Cursor, VS Code, Zed, Gemini CLI, Cline, Claude Code settings) and/or a server's `tools/list` response. Nothing leaves the browser, so secrets in the config stay local.

**Config checks**
- Real secrets written into the config (GitHub/Anthropic/OpenAI/AWS/Slack/Google tokens, JWTs, private keys, literal `*_TOKEN` values), shown masked
- `npx`/`uvx` packages without a pinned version, typosquatted look-alikes of official `@modelcontextprotocol/*` packages, git/URL packages
- `curl | sh`, encoded PowerShell, shell wrappers, scripts in temp folders
- Docker: `--privileged`, `docker.sock`, home mounts, host network, `:latest` images
- File servers given `/` or your whole home, servers bound to `0.0.0.0`, plain-`http` or tunnel endpoints, secrets in URLs
- Client settings: trust-all-project-servers, bypass-permissions mode, wildcard allow-lists, `trust: true`, auto-approved write/exec tools

**Tool-description checks (tool poisoning / prompt injection)**
- Fake `<IMPORTANT>`/`<system>` tags, "ignore previous instructions", "do not tell the user", confirmation bypass
- Instructions to read `~/.ssh`, MCP config or credentials, and to smuggle contents out through a parameter or URL
- Cross-tool shadowing (one tool giving orders about another)
- Invisible characters: zero-width, bidi controls and Unicode *tag* characters (the hidden message is decoded and shown)
- **Rug-pull detection**: save a SHA-256 fingerprint baseline of your tools, and any later change to a tool's text or schema is flagged

Limits: static and rule-based, JSON only (no TOML yet). It cannot see runtime behaviour. A clean result is not proof of safety.

## Package detector (`pkg.html`)

Check an npm or PyPI package **before** you install it. Everything is read, nothing is executed, and nothing is uploaded.

**Scan a package file** (`npm pack name --ignore-scripts` gives a `.tgz`, `pip download name --no-deps` a `.whl`/sdist; neither runs install scripts). The archive is opened and every script is analysed:
- Install-time execution: `postinstall` hooks, `setup.py`, `.pth` files, and whether suspicious code sits in a file that runs at install
- Decode-and-run (`eval(atob(...))`, `exec(base64...)`), `curl | sh`, reverse shells, miners
- Credential and wallet theft (SSH keys, `.npmrc`/`.pypirc`, cloud credentials, browser data), environment-variable dumps, exfiltration endpoints (Discord/Telegram webhooks, request catchers, tunnels)
- Persistence (shell rc files, cron, launch agents, `authorized_keys`), worm behaviour (publishing, CI workflow writes)
- Obfuscation, Trojan-Source bidi characters, hidden executables, `../` path traversal and escaping symlinks, commands that shadow system tools

**Check a dependency file** (`package.json`, `package-lock.json`, `requirements.txt`): typosquats of popular packages (transposition, dropped dash, homoglyphs), git/URL dependencies, wildcard versions, non-default or plain-http registries, missing lockfile integrity, and dependency-confusion setups (`--extra-index-url`).

Tuned against 41 real packages (28 npm, 13 Python: lodash, express, webpack, prettier, three, pip, setuptools, pandas, cryptography ...): none is flagged. That says nothing about recall on brand-new malware, so treat a clean result as "no known red flags".

## How it works

`engine.js` (messages and links, `apkscan.js` for APKs, `mcpaudit.js` for MCP, `pkgscan.js` for packages) is a rule engine (about 25 text rules plus URL analysis). Each finding has a severity,
a weight, an English and a Hindi explanation, and the exact text that triggered it. Scores add up
(0-100, capped); any *critical* finding forces at least 60. Genuine bank SMS that say
"Do not share OTP with anyone" are recognised and stay clean.

Everything runs in the browser. A strict Content-Security-Policy blocks all network access except same-origin files.

## Run it

```bash
cd scamcheck
python3 -m http.server 8000      # then open http://localhost:8000
```

Or just open `index.html` in a browser (the service worker only registers on https/localhost).

## Test

```bash
node --test scamcheck/*.test.js
```

`apkfixture.js` builds synthetic APKs (ZIP + binary AndroidManifest) for the tests, including fuzzing.
The parser was also checked against a real 105 MB APK (Termux) in Node and in Chromium.

## Deploy

Static files only. Easiest: enable GitHub Pages (Settings > Pages > Source: **GitHub Actions**) and run the
**ScamCheck deploy (GitHub Pages)** workflow. Cloudflare Pages / Netlify / any web server also work: serve the folder as-is.

## Accept donations

Edit [`config.js`](config.js). The "Keep ScamCheck free" card appears only when something is filled in:

```js
upiId: 'yourname@bank',                       // "Pay with UPI" + copy button
links: [{ label: 'GitHub Sponsors', url: 'https://github.com/sponsors/you' }],  // https:// only
```

## Add or tune a rule

Add an entry to `TEXT_RULES` in `engine.js` (`id`, `cat`, `sev`, `w`, `re`, `en`, `hi`) and a test in
`engine.test.js`. Keep regexes bounded (`.{0,60}`) and run the ReDoS test. Add a real brand to `BRANDS`
with every official domain to avoid false alarms.

## Limits

Rules and patterns, not an AI or a reputation database. It can miss new scams and can flag a genuine
message. Never treat "no red flags" as a guarantee. Report scams: **1930**, cybercrime.gov.in, sancharsaathi.gov.in.

MIT licensed (see repository root).
