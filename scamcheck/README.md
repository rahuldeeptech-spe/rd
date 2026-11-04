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

## How it works

`engine.js` is a rule engine (about 25 text rules plus URL analysis). Each finding has a severity,
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
node --test scamcheck/engine.test.js
```

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
