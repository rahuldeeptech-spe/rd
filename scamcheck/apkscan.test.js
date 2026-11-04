'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const ApkScan = require('./apkscan.js');
const { buildAxml, buildZip, makeApk, dex } = require('./apkfixture.js');

const P = (n) => 'android.permission.' + n;
const ids = (r) => r.findings.map((f) => f.id);
const LAUNCH = { kind: 'activity', name: '.Main', actions: ['android.intent.action.MAIN'], categories: ['android.intent.category.LAUNCHER'] };
const SIGN = { sigBlock: Buffer.from('legit-publisher-cert') };

test('manifest parsing: UTF-8 pool, UTF-16 pool and resource-id attribute names', () => {
  const spec = {
    pkg: 'com.example.demo', versionName: '2.1.0', versionCode: 21, minSdk: 24, targetSdk: 34, label: 'Demo',
    perms: [P('INTERNET'), P('CAMERA')], components: [LAUNCH],
  };
  for (const opts of [{}, { utf8: false }, { useResIds: true }, { useResIds: true, utf8: false }]) {
    const m = ApkScan.parseManifest(buildAxml(spec, opts));
    assert.equal(m.pkg, 'com.example.demo', JSON.stringify(opts));
    assert.equal(m.versionName, '2.1.0');
    assert.equal(m.versionCode, 21);
    assert.equal(m.minSdk, 24);
    assert.equal(m.targetSdk, 34);
    assert.equal(m.label, 'Demo');
    assert.deepEqual(m.permissions, [P('INTERNET'), P('CAMERA')]);
    assert.equal(m.components.length, 1);
    assert.deepEqual(m.components[0].actions, ['android.intent.action.MAIN']);
    assert.deepEqual(m.components[0].categories, ['android.intent.category.LAUNCHER']);
  }
});

test('benign app stays clean', async () => {
  const apk = makeApk({ pkg: 'com.example.notes', versionName: '1.0', targetSdk: 34, perms: [P('INTERNET'), P('CAMERA'), P('ACCESS_NETWORK_STATE')], components: [LAUNCH] }, SIGN);
  const r = await ApkScan.scanApk(apk, { fileName: 'notes.apk' });
  assert.equal(r.level, 'clean', JSON.stringify(ids(r)));
  assert.ok(r.score < 20);
  assert.equal(r.info.package, 'com.example.notes');
  assert.equal(r.info.signed, true);
  assert.equal(r.info.dexFiles, 1);
});

test('SMS stealer with Telegram exfiltration scores as scam', async () => {
  const apk = makeApk(
    {
      pkg: 'com.pmk.yojana', targetSdk: 22,
      perms: [P('INTERNET'), P('READ_SMS'), P('RECEIVE_SMS'), P('SEND_SMS'), P('RECEIVE_BOOT_COMPLETED')],
      components: [{ kind: 'receiver', name: '.SmsIn', actions: ['android.provider.Telephony.SMS_RECEIVED'] }],
    },
    { dexStrings: ['https://api.telegram.org/bot123456:ABC/sendMessage', 'Ldalvik/system/DexClassLoader;'] }
  );
  const r = await ApkScan.scanApk(apk, { fileName: 'PM_Kisan_Yojana.apk' });
  assert.equal(r.level, 'scam');
  for (const id of ['apk_sms_read', 'apk_sms_receiver', 'apk_sms_send', 'combo_sms_exfil', 'apk_telegram_c2', 'apk_dynamic_code', 'apk_hidden', 'apk_lure_name', 'apk_old_target', 'apk_unsigned']) {
    assert.ok(ids(r).includes(id), `missing ${id}: ${ids(r)}`);
  }
  assert.equal(r.score, 100);
});

test('banking trojan pattern: accessibility + overlay', async () => {
  const apk = makeApk(
    {
      pkg: 'com.secure.update', targetSdk: 33,
      perms: [P('INTERNET'), P('SYSTEM_ALERT_WINDOW')],
      components: [LAUNCH, { kind: 'service', name: '.Acc', permission: P('BIND_ACCESSIBILITY_SERVICE'), exported: true, actions: ['android.accessibilityservice.AccessibilityService'] }],
    },
    SIGN
  );
  const r = await ApkScan.scanApk(apk);
  assert.ok(ids(r).includes('apk_accessibility'));
  assert.ok(ids(r).includes('combo_bank_trojan'));
  assert.ok(r.score >= 80, String(r.score));
});

test('device admin and notification listener are flagged', async () => {
  const apk = makeApk(
    { pkg: 'com.x.y', targetSdk: 33, perms: [], components: [LAUNCH,
      { kind: 'receiver', name: '.Adm', permission: P('BIND_DEVICE_ADMIN') },
      { kind: 'service', name: '.Nl', permission: P('BIND_NOTIFICATION_LISTENER_SERVICE') }] },
    SIGN
  );
  const r = await ApkScan.scanApk(apk);
  assert.ok(ids(r).includes('apk_device_admin'));
  assert.ok(ids(r).includes('apk_notification_listener'));
});

test('signature checks', async () => {
  const spec = { pkg: 'com.sig.test', targetSdk: 33, perms: [], components: [LAUNCH] };
  const unsigned = await ApkScan.scanApk(makeApk(spec));
  assert.ok(ids(unsigned).includes('apk_unsigned'));

  const v2 = await ApkScan.scanApk(makeApk(spec, SIGN));
  assert.ok(!ids(v2).includes('apk_unsigned'));
  assert.ok(!ids(v2).includes('apk_debug_cert'));

  const debugV2 = await ApkScan.scanApk(makeApk(spec, { sigBlock: Buffer.from('CN=Android Debug,O=Android') }));
  assert.ok(ids(debugV2).includes('apk_debug_cert'));

  const v1 = await ApkScan.scanApk(makeApk(spec, { files: [{ name: 'META-INF/CERT.RSA', data: Buffer.from('xxCN=Android Debugxx') }] }));
  assert.ok(!ids(v1).includes('apk_unsigned'));
  assert.ok(ids(v1).includes('apk_debug_cert'));
});

test('embedded payload in assets and bad URLs in dex', async () => {
  const apk = makeApk(
    { pkg: 'com.drop.per', targetSdk: 33, perms: [P('INTERNET')], components: [LAUNCH] },
    {
      ...SIGN,
      files: [{ name: 'assets/update.apk', data: Buffer.from('PK-fake') }],
      dexStrings: ['http://192.168.7.7/gate.php', 'https://sbi-kyc-update.xyz/login', 'https://www.google.com/'],
    }
  );
  const r = await ApkScan.scanApk(apk);
  assert.ok(ids(r).includes('apk_embedded_payload'));
  const bad = r.findings.find((f) => f.id === 'apk_bad_url');
  assert.ok(bad, ids(r).join());
  assert.ok(bad.evidence.includes('192.168.7.7'));
  assert.ok(bad.evidence.includes('sbi-kyc-update.xyz'));
  assert.ok(!bad.evidence.includes('google.com'));
});

test('stored (uncompressed) manifest works', async () => {
  const spec = { pkg: 'com.stored.one', targetSdk: 33, perms: [], components: [LAUNCH] };
  const apk = buildZip([{ name: 'AndroidManifest.xml', data: buildAxml(spec), store: true }, { name: 'classes.dex', data: dex(['x']) }], { sigBlock: 'abc' });
  const r = await ApkScan.scanApk(apk);
  assert.equal(r.info.package, 'com.stored.one');
});

test('sha256 matches node crypto and every finding is bilingual', async () => {
  const apk = makeApk({ pkg: 'com.a.b', targetSdk: 22, perms: [P('READ_SMS'), P('INTERNET'), P('SYSTEM_ALERT_WINDOW'), P('REQUEST_INSTALL_PACKAGES'), P('READ_CALL_LOG'), P('READ_CONTACTS'), P('RECORD_AUDIO')], components: [] });
  const r = await ApkScan.scanApk(apk, { fileName: 'kyc.apk' });
  assert.equal(r.info.sha256, crypto.createHash('sha256').update(apk).digest('hex'));
  assert.ok(r.findings.length > 6);
  for (const f of r.findings) {
    assert.ok(f.en && f.en.length > 5, f.id);
    assert.ok(f.hi && f.hi.length > 5, f.id);
  }
});

test('invalid inputs fail with a clear error code', async () => {
  const codes = async (bytes) => { try { await ApkScan.scanApk(bytes); return 'ok'; } catch (e) { return e.code; } };
  assert.equal(await codes(new Uint8Array(0)), 'not_zip');
  assert.equal(await codes(new TextEncoder().encode('hello this is not an apk at all, just text')), 'not_zip');
  assert.equal(await codes(buildZip([{ name: 'readme.txt', data: Buffer.from('hi') }])), 'no_manifest');
  assert.equal(await codes(buildZip([{ name: 'AndroidManifest.xml', data: Buffer.from('<manifest/>') }])), 'bad_axml');
  const apk = makeApk({ pkg: 'a.b.c', perms: [], components: [] });
  assert.equal(await codes(apk.subarray(0, apk.length - 30)), 'bad_zip');
});

test('zip bomb: oversized entry is skipped quickly, manifest still read', async () => {
  const bomb = zlib.deflateRawSync(Buffer.alloc(60 * 1024 * 1024));
  const spec = { pkg: 'com.bomb.test', targetSdk: 33, perms: [], components: [LAUNCH] };
  const axml = Buffer.from(buildAxml(spec));
  // hand-built zip with a real manifest and a bomb "classes.dex"
  const zip = buildZip([{ name: 'AndroidManifest.xml', data: axml }]);
  const t0 = Date.now();
  const files = [{ name: 'AndroidManifest.xml', data: axml }, { name: 'classes.dex', data: Buffer.alloc(60 * 1024 * 1024) }];
  const bombZip = buildZip(files);
  const r = await ApkScan.scanApk(bombZip);
  assert.equal(r.info.package, 'com.bomb.test');
  assert.equal(r.info.dexFiles, 0);
  assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0}ms`);
  assert.ok(bomb.length < 200000 && zip.length > 0);
});

test('fuzz: corrupted APKs never hang or throw uncoded errors', async () => {
  const base = makeApk({ pkg: 'com.fuzz.me', targetSdk: 33, perms: [P('INTERNET'), P('READ_SMS')], components: [LAUNCH, { kind: 'service', name: '.S', permission: P('BIND_ACCESSIBILITY_SERVICE') }] }, SIGN);
  let seed = 1234567;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const t0 = Date.now();
  for (let i = 0; i < 300; i++) {
    const m = new Uint8Array(base);
    const flips = 1 + Math.floor(rnd() * 8);
    for (let k = 0; k < flips; k++) m[Math.floor(rnd() * m.length)] = Math.floor(rnd() * 256);
    const cut = rnd() < 0.2 ? m.subarray(0, Math.floor(rnd() * m.length)) : m;
    try {
      const r = await ApkScan.scanApk(cut, { skipHash: true });
      assert.ok(r.score >= 0 && r.score <= 100);
    } catch (e) {
      assert.ok(e.code, `uncoded error on iteration ${i}: ${e && e.stack}`);
    }
  }
  assert.ok(Date.now() - t0 < 20000);
});

test('manifest-level fuzz with valid zip wrapper', async () => {
  const spec = { pkg: 'com.fuzz.two', targetSdk: 33, perms: [P('INTERNET'), P('READ_SMS')], components: [LAUNCH] };
  const axml = buildAxml(spec);
  let seed = 99;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  for (let i = 0; i < 400; i++) {
    const m = new Uint8Array(axml);
    for (let k = 0; k < 1 + Math.floor(rnd() * 10); k++) m[Math.floor(rnd() * m.length)] = Math.floor(rnd() * 256);
    const zip = buildZip([{ name: 'AndroidManifest.xml', data: m }]);
    try { await ApkScan.scanApk(zip, { skipHash: true }); } catch (e) { assert.ok(e.code, `uncoded: ${e.stack}`); }
  }
});

test('powerful but ordinary developer-style app is only "caution" (no scam alarm)', async () => {
  // mirrors what a real terminal-emulator APK declares (validated against a real 105 MB APK)
  const apk = makeApk(
    { pkg: 'com.dev.terminal', versionName: '0.118.0', targetSdk: 28, debuggable: true,
      perms: [P('INTERNET'), P('WRITE_EXTERNAL_STORAGE'), P('SYSTEM_ALERT_WINDOW'), P('REQUEST_INSTALL_PACKAGES'), P('REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'), P('WAKE_LOCK')],
      components: [LAUNCH] },
    SIGN
  );
  const r = await ApkScan.scanApk(apk, { fileName: 'terminal-debug.apk' });
  assert.equal(r.level, 'caution', `${r.score} ${ids(r)}`);
  assert.ok(!ids(r).some((i) => i.startsWith('combo_')));
});
