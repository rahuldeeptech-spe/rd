'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze, extractUrls, levelFor } = require('./engine.js');

const ids = (r) => r.findings.map((f) => f.id);

test('empty and whitespace input is clean', () => {
  for (const v of ['', '   ', null, undefined, '\n\n']) {
    const r = analyze(v);
    assert.equal(r.score, 0);
    assert.equal(r.level, 'clean');
    assert.equal(r.empty, true);
  }
});

test('ordinary chat is clean', () => {
  for (const t of [
    'Hi, are we meeting for lunch tomorrow at 1pm?',
    'Bhai abhi aa raha hu, 10 min mein pahunch jaunga',
    'Your Swiggy order #4821 is out for delivery. Total Rs 349.',
    'Meeting moved to 3pm, see you in the conference room.',
  ]) {
    const r = analyze(t);
    assert.ok(r.score < 20, `${t} => ${r.score} ${ids(r)}`);
  }
});

test('genuine bank OTP SMS with warning stays clean', () => {
  const r = analyze('123456 is your OTP for txn of Rs 500.00 at AMAZON. Do not share OTP with anyone. -HDFC Bank');
  assert.ok(!ids(r).includes('otp_request'), ids(r).join());
  assert.ok(r.score < 20, String(r.score));
  assert.equal(r.level, 'clean');
});

test('Hinglish OTP warning stays clean', () => {
  const r = analyze('Aapka OTP 482913 hai. Kisi ko na batayein. Bank kabhi OTP nahi maangta.');
  assert.ok(!ids(r).includes('otp_request'), ids(r).join());
});

test('digital arrest script is flagged as scam', () => {
  const r = analyze(
    'This is CBI officer. A parcel in your name has drugs and fake passports. You are under digital arrest. Do not disconnect the video call and do not tell your family.'
  );
  assert.ok(r.score >= 80, String(r.score));
  assert.equal(r.level, 'scam');
  for (const id of ['digital_arrest', 'authority_threat', 'stay_on_call', 'secrecy']) {
    assert.ok(ids(r).includes(id), `missing ${id}: ${ids(r)}`);
  }
});

test('Hindi digital arrest is flagged', () => {
  const r = analyze('आप डिजिटल अरेस्ट में हैं, आपको गिरफ्तार किया जाएगा। कॉल मत काटिए।');
  assert.ok(r.score >= 60, String(r.score));
  assert.ok(ids(r).includes('digital_arrest'));
});

test('KYC phishing with shortened link scores high', () => {
  const r = analyze('Dear customer your SBI account will be blocked today. Update KYC immediately: http://bit.ly/3xYz12');
  assert.ok(r.score >= 80, String(r.score));
  for (const id of ['kyc_block', 'account_block', 'urgency', 'link_shortener', 'combo_link_lure']) {
    assert.ok(ids(r).includes(id), `missing ${id}: ${ids(r)}`);
  }
});

test('look-alike bank domain is critical, real ones are not', () => {
  const bad = analyze('Login at https://sbi-kyc-update.xyz/login');
  assert.ok(ids(bad).includes('link_brand_lookalike'));
  assert.ok(bad.score >= 60);

  for (const good of [
    'https://www.onlinesbi.sbi/',
    'https://retail.onlinesbi.com/retail/login.htm',
    'https://www.hdfcbank.com/personal',
    'https://netbanking.hdfcbank.com',
    'https://www.incometax.gov.in/iec/foportal',
    'https://www.amazon.in/gp/help',
  ]) {
    const r = analyze(good);
    assert.ok(!ids(r).includes('link_brand_lookalike'), `${good}: ${ids(r)}`);
    assert.ok(!ids(r).includes('link_gov_lookalike'), `${good}: ${ids(r)}`);
    assert.ok(r.score < 20, `${good} => ${r.score}`);
  }
});

test('trick domains: suffix tricks are not treated as official', () => {
  const r = analyze('https://hdfcbank.com.verify-login.top/');
  assert.ok(ids(r).includes('link_brand_lookalike'));
  const r2 = analyze('https://nothdfcbank.com/');
  assert.ok(ids(r2).includes('link_brand_lookalike'));
});

test('fake government domain', () => {
  const r = analyze('Pay your fine at https://echallan-gov.online/pay');
  assert.ok(ids(r).includes('link_gov_lookalike'), ids(r).join());
  const ok = analyze('https://parivahan.gov.in/parivahan/');
  assert.ok(!ids(ok).includes('link_gov_lookalike'));
});

test('UPI "receive" tricks are critical', () => {
  for (const t of [
    'Enter your UPI PIN to receive Rs 5000 cashback',
    'Scan this QR code to receive your refund',
  ]) {
    const r = analyze(t);
    assert.ok(ids(r).includes('upi_pin_receive'), t);
    assert.ok(r.score >= 60, t);
  }
});

test('OTP request flagged', () => {
  const r = analyze('Sir please share the OTP you just received to complete verification');
  assert.ok(ids(r).includes('otp_request'));
  assert.ok(r.score >= 60);
});

test('task / job scam', () => {
  const r = analyze('Part time job! Like YouTube videos and earn Rs 5000 per day. Join our Telegram group for tasks. Daily payout.');
  assert.ok(ids(r).includes('task_job'));
  assert.ok(ids(r).includes('telegram_group'));
  assert.ok(r.score >= 60, String(r.score));
});

test('investment scam', () => {
  const r = analyze('Join our VIP stock tips group. Guaranteed returns, double your money in 30 days!');
  assert.ok(ids(r).includes('investment'));
  assert.ok(r.score >= 35);
});

test('prize + advance fee', () => {
  const r = analyze('Congratulations you have won a lottery of 25 lakh! Pay Rs 4999 registration fee to claim.');
  assert.ok(ids(r).includes('prize'));
  assert.ok(ids(r).includes('advance_fee'));
  assert.ok(r.score >= 60);
});

test('APK and remote-access apps are critical', () => {
  const r1 = analyze('Download PM_Kisan_Yojana.apk from this link to get your benefit');
  assert.ok(ids(r1).includes('apk_install'));
  const r2 = analyze('Please install AnyDesk so I can help you with the refund');
  assert.ok(ids(r2).includes('remote_access'));
  assert.ok(r2.score >= 60);
});

test('family impersonation', () => {
  const r = analyze('Hi Mum, I lost my phone, this is my new number. Please send money urgently, I am in hospital');
  assert.ok(ids(r).includes('family_impersonation'));
  assert.ok(r.score >= 60, String(r.score));
});

test('link-only checks', () => {
  assert.ok(ids(analyze('http://192.168.4.7/login')).includes('link_ip'));
  assert.ok(ids(analyze('http://paypal.com@evil.example.top/')).includes('link_userinfo'));
  assert.ok(ids(analyze('https://xn--pypal-4ve.com/')).includes('link_punycode'));
  assert.ok(ids(analyze('http://example.com/')).includes('link_http'));
  assert.ok(ids(analyze('https://rb.gy/abc')).includes('link_shortener'));
  assert.ok(ids(analyze('https://a.b.c.d.example.com/')).includes('link_subdomains'));
});

test('extractUrls handles punctuation, bare domains and email addresses', () => {
  const u = extractUrls('See (https://example.com/a?b=1), also www.test.in. and mail me at joe@example.com!');
  const hosts = u.map((x) => x.host);
  assert.deepEqual(hosts.sort(), ['example.com', 'www.test.in']);
});

test('score is bounded and findings sorted by severity', () => {
  const r = analyze(
    'CBI digital arrest warrant. Share OTP. Do not disconnect the video call. Install AnyDesk. Pay refundable deposit. https://hdfc-login.xyz/a.apk Lottery won immediately'
  );
  assert.equal(r.score, 100);
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  for (let i = 1; i < r.findings.length; i++) {
    assert.ok(order[r.findings[i - 1].sev] <= order[r.findings[i].sev]);
  }
});

test('every finding carries English and Hindi text', () => {
  const r = analyze(
    'CBI digital arrest. Share OTP now. KYC pending, account will be blocked. https://bit.ly/x http://sbi-kyc.xyz'
  );
  assert.ok(r.findings.length > 5);
  for (const f of r.findings) {
    assert.ok(f.en && f.en.length > 5, f.id);
    assert.ok(f.hi && f.hi.length > 5, f.id);
  }
});

test('levels', () => {
  assert.equal(levelFor(0), 'clean');
  assert.equal(levelFor(19), 'clean');
  assert.equal(levelFor(20), 'caution');
  assert.equal(levelFor(40), 'suspicious');
  assert.equal(levelFor(60), 'likely');
  assert.equal(levelFor(80), 'scam');
  assert.equal(levelFor(100), 'scam');
});

test('hostile input does not hang (ReDoS guard) and is truncated', () => {
  const nasty = [
    'a '.repeat(30000),
    'share '.repeat(5000) + 'otp',
    'http://' + 'a.'.repeat(5000) + 'com',
    'kyc ' + 'x'.repeat(50000),
    '(((('.repeat(5000),
    'account '.repeat(4000),
    'part time '.repeat(3000),
  ];
  for (const t of nasty) {
    const start = process.hrtime.bigint();
    analyze(t);
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    assert.ok(ms < 1500, `took ${ms}ms`);
  }
});

test('input types are coerced safely', () => {
  assert.doesNotThrow(() => analyze(12345));
  assert.doesNotThrow(() => analyze({}));
  assert.doesNotThrow(() => analyze(['a', 'b']));
});
