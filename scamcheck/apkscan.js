/*
 * apkscan: offline static analysis of an Android APK, no network, no dependencies.
 * Works in the browser (window.ApkScan) and in Node (require('./apkscan.js')).
 *
 * It reads the ZIP container, decodes the binary AndroidManifest.xml, scans the DEX
 * files for a few telltale strings, checks the signature, and scores the result.
 * A low score does NOT prove an app is safe. A high score on a sideloaded APK is a
 * strong reason to delete it.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ApkScan = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_FILE = 150 * 1024 * 1024;     // refuse anything bigger
  var MAX_ENTRY = 40 * 1024 * 1024;     // per decompressed entry
  var MAX_TOTAL = 120 * 1024 * 1024;    // total decompressed bytes we are willing to read
  var MAX_ENTRIES = 20000;

  function fail(code, msg) { var e = new Error(msg); e.code = code; return e; }

  // ---- ZIP ----------------------------------------------------------------
  function readZip(buf) {
    var n = buf.length;
    if (n < 22 || buf[0] !== 0x50 || buf[1] !== 0x4b) throw fail('not_zip', 'Not a ZIP/APK file');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var eocd = -1;
    for (var i = n - 22; i >= Math.max(0, n - 22 - 65535); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw fail('bad_zip', 'ZIP end record not found');
    var count = dv.getUint16(eocd + 10, true);
    var cdSize = dv.getUint32(eocd + 12, true);
    var cdOff = dv.getUint32(eocd + 16, true);
    if (count > MAX_ENTRIES) throw fail('bad_zip', 'Too many entries');
    if (cdOff + cdSize > n) throw fail('bad_zip', 'Central directory out of range');
    var entries = [];
    var p = cdOff;
    for (var k = 0; k < count; k++) {
      if (p + 46 > n || dv.getUint32(p, true) !== 0x02014b50) break;
      var method = dv.getUint16(p + 10, true);
      var csize = dv.getUint32(p + 20, true);
      var usize = dv.getUint32(p + 24, true);
      var nl = dv.getUint16(p + 28, true);
      var el = dv.getUint16(p + 30, true);
      var cl = dv.getUint16(p + 32, true);
      var lho = dv.getUint32(p + 42, true);
      var name = '';
      for (var j = 0; j < nl && p + 46 + j < n; j++) name += String.fromCharCode(buf[p + 46 + j]);
      entries.push({ name: name, method: method, csize: csize, usize: usize, lho: lho });
      p += 46 + nl + el + cl;
    }
    return { entries: entries, cdOffset: cdOff };
  }

  async function inflateRaw(data, limit) {
    if (typeof module === 'object' && typeof require === 'function') {
      try {
        var z = require('zlib');
        return new Uint8Array(z.inflateRawSync(data, { maxOutputLength: limit }));
      } catch (e) { return null; }
    }
    if (typeof DecompressionStream === 'undefined') throw fail('unsupported', 'This browser cannot unzip files (DecompressionStream missing)');
    try {
      var stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      var reader = stream.getReader();
      var chunks = [];
      var total = 0;
      for (;;) {
        var r = await reader.read();
        if (r.done) break;
        total += r.value.length;
        if (total > limit) { await reader.cancel(); return null; }
        chunks.push(r.value);
      }
      var out = new Uint8Array(total);
      var o = 0;
      chunks.forEach(function (c) { out.set(c, o); o += c.length; });
      return out;
    } catch (e) { return null; }
  }

  async function entryData(buf, e, budget) {
    if (e.usize > MAX_ENTRY && e.method !== 0) return null;
    if (e.method === 0 && e.csize > MAX_ENTRY) return null;
    if (budget.left <= 0) return null;
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var o = e.lho;
    if (o + 30 > buf.length || dv.getUint32(o, true) !== 0x04034b50) return null;
    var start = o + 30 + dv.getUint16(o + 26, true) + dv.getUint16(o + 28, true);
    if (start + e.csize > buf.length) return null;
    var raw = buf.subarray(start, start + e.csize);
    var out;
    if (e.method === 0) out = raw;
    else if (e.method === 8) out = await inflateRaw(raw, Math.min(MAX_ENTRY, budget.left));
    else return null;
    if (out) budget.left -= out.length;
    return out;
  }

  // ---- Binary XML (AndroidManifest.xml) -----------------------------------
  var ATTR_BY_ID = {
    0x01010003: 'name', 0x01010001: 'label', 0x01010006: 'permission', 0x01010010: 'exported',
    0x0101000f: 'debuggable', 0x010104ec: 'usesCleartextTraffic', 0x0101021b: 'versionCode',
    0x0101021c: 'versionName', 0x0101020c: 'minSdkVersion', 0x01010270: 'targetSdkVersion',
  };

  function readPool(dv, buf, pos, size) {
    var hsz = dv.getUint16(pos + 2, true);
    var count = dv.getUint32(pos + 8, true);
    var flags = dv.getUint32(pos + 16, true);
    var sStart = dv.getUint32(pos + 20, true);
    if (count > 300000 || pos + hsz + count * 4 > pos + size) throw fail('bad_axml', 'String pool is malformed');
    var utf8 = (flags & 0x100) !== 0;
    var d8 = new TextDecoder('utf-8');
    var d16 = new TextDecoder('utf-16le');
    var out = new Array(count);
    var end = pos + size;
    for (var i = 0; i < count; i++) {
      var off = pos + sStart + dv.getUint32(pos + hsz + 4 * i, true);
      if (off + 2 > end) { out[i] = ''; continue; }
      if (utf8) {
        off += (buf[off] & 0x80) ? 2 : 1;
        var b = buf[off];
        var bl;
        if (b & 0x80) { bl = ((b & 0x7f) << 8) | buf[off + 1]; off += 2; } else { bl = b; off += 1; }
        out[i] = off + bl <= end ? d8.decode(buf.subarray(off, off + bl)) : '';
      } else {
        var l = dv.getUint16(off, true);
        if (l & 0x8000) { l = ((l & 0x7fff) << 16) | dv.getUint16(off + 2, true); off += 4; } else off += 2;
        out[i] = off + l * 2 <= end ? d16.decode(buf.subarray(off, off + l * 2)) : '';
      }
    }
    return out;
  }

  function parseManifest(buf) {
    try {
      return parseManifestUnsafe(buf);
    } catch (e) {
      if (e && e.code) throw e;
      throw fail('bad_axml', 'AndroidManifest.xml is corrupted');
    }
  }

  function parseManifestUnsafe(buf) {
    if (buf.length < 16) throw fail('bad_axml', 'Manifest too small');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    if (dv.getUint16(0, true) !== 0x0003) throw fail('bad_axml', 'AndroidManifest.xml is not binary XML');
    var pool = [];
    var resIds = [];
    var m = {
      pkg: '', versionName: '', versionCode: null, minSdk: null, targetSdk: null,
      debuggable: false, cleartext: false, label: null, permissions: [], components: [],
    };
    var cur = null;
    var pos = dv.getUint16(2, true);
    var guard = 0;
    while (pos + 8 <= buf.length && guard++ < 2000000) {
      var type = dv.getUint16(pos, true);
      var hsz = dv.getUint16(pos + 2, true);
      var size = dv.getUint32(pos + 4, true);
      if (size < 8 || pos + size > buf.length) break;
      if (type === 0x0001) pool = readPool(dv, buf, pos, size);
      else if (type === 0x0180) {
        for (var q = 0; q < (size - hsz) / 4; q++) resIds.push(dv.getUint32(pos + hsz + q * 4, true));
      } else if (type === 0x0102 && pos + 36 <= buf.length) {
        var nameIdx = dv.getUint32(pos + 20, true);
        var attrStart = dv.getUint16(pos + 24, true);
        var attrSize = dv.getUint16(pos + 26, true) || 20;
        var attrCount = dv.getUint16(pos + 28, true);
        if (attrCount > 2000) attrCount = 2000;
        var tag = pool[nameIdx] || '';
        var attrs = {};
        for (var a = 0; a < attrCount; a++) {
          var ap = pos + 16 + attrStart + a * attrSize;
          if (ap + 20 > pos + size) break;
          var an = dv.getUint32(ap + 4, true);
          var raw = dv.getUint32(ap + 8, true);
          var dt = buf[ap + 15];
          var data = dv.getUint32(ap + 16, true);
          var key = ATTR_BY_ID[resIds[an]] || pool[an] || '';
          var val;
          if (raw !== 0xffffffff) val = pool[raw];
          else if (dt === 0x03) val = pool[data];
          else if (dt === 0x10 || dt === 0x11) val = data | 0;
          else if (dt === 0x12) val = data !== 0;
          else if (dt === 0x01) val = '@0x' + data.toString(16);
          else val = data;
          if (key) attrs[key] = val;
        }
        if (tag === 'manifest') {
          m.pkg = String(attrs.package || '');
          m.versionName = attrs.versionName != null ? String(attrs.versionName) : '';
          m.versionCode = typeof attrs.versionCode === 'number' ? attrs.versionCode : null;
        } else if (tag === 'uses-permission' || tag === 'uses-permission-sdk-23') {
          if (attrs.name) m.permissions.push(String(attrs.name));
        } else if (tag === 'uses-sdk') {
          if (typeof attrs.minSdkVersion === 'number') m.minSdk = attrs.minSdkVersion;
          if (typeof attrs.targetSdkVersion === 'number') m.targetSdk = attrs.targetSdkVersion;
        } else if (tag === 'application') {
          m.debuggable = attrs.debuggable === true;
          m.cleartext = attrs.usesCleartextTraffic === true;
          if (typeof attrs.label === 'string' && attrs.label.charAt(0) !== '@') m.label = attrs.label;
        } else if (tag === 'activity' || tag === 'activity-alias' || tag === 'service' || tag === 'receiver' || tag === 'provider') {
          cur = {
            kind: tag, name: String(attrs.name || ''), permission: attrs.permission ? String(attrs.permission) : '',
            exported: attrs.exported === true, actions: [], categories: [],
          };
          if (m.components.length < 5000) m.components.push(cur);
        } else if (tag === 'action' && cur && attrs.name) {
          cur.actions.push(String(attrs.name));
        } else if (tag === 'category' && cur && attrs.name) {
          cur.categories.push(String(attrs.name));
        }
      } else if (type === 0x0103) {
        var endTag = pool[dv.getUint32(pos + 20, true)] || '';
        if (endTag === 'activity' || endTag === 'activity-alias' || endTag === 'service' || endTag === 'receiver' || endTag === 'provider') cur = null;
      }
      pos += size;
    }
    if (!m.pkg) throw fail('bad_axml', 'Could not read the package name from the manifest');
    return m;
  }

  // ---- Rules --------------------------------------------------------------
  var GROUPS = {
    sms_read: ['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.RECEIVE_MMS', 'android.permission.RECEIVE_WAP_PUSH'],
    sms_send: ['android.permission.SEND_SMS', 'android.permission.WRITE_SMS'],
    calls: ['android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG', 'android.permission.PROCESS_OUTGOING_CALLS', 'android.permission.ANSWER_PHONE_CALLS', 'android.permission.CALL_PHONE'],
    contacts: ['android.permission.READ_CONTACTS', 'android.permission.GET_ACCOUNTS'],
    overlay: ['android.permission.SYSTEM_ALERT_WINDOW'],
    installer: ['android.permission.REQUEST_INSTALL_PACKAGES'],
    storage: ['android.permission.MANAGE_EXTERNAL_STORAGE'],
    mic: ['android.permission.RECORD_AUDIO'],
    bglocation: ['android.permission.ACCESS_BACKGROUND_LOCATION'],
    boot: ['android.permission.RECEIVE_BOOT_COMPLETED'],
  };
  var DANGEROUS = [].concat(
    GROUPS.sms_read, GROUPS.sms_send, GROUPS.calls, GROUPS.contacts, GROUPS.overlay, GROUPS.installer,
    GROUPS.storage, GROUPS.mic, GROUPS.bglocation,
    ['android.permission.CAMERA', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_PHONE_STATE',
      'android.permission.READ_PHONE_NUMBERS', 'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.BIND_DEVICE_ADMIN', 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE']
  );

  var LURE_RE = /kyc|pm[-_. ]?kisan|kisan[-_. ]?(?:yojana|samman)|yojana|challan|parivahan|mparivahan|vahan|aadhaar|aadhar|voter[-_. ]?id|ration[-_. ]?card|reward[-_. ]?points?|wedding[-_. ]?invit|whatsapp[-_. ]?(?:gold|pink|plus)|electricity[-_. ]?bill|bijli|loan|income[-_. ]?tax|sbi|hdfc|icici|axis[-_. ]?bank|paytm|phonepe|gov[-_. ]?(?:scheme|app)|e[-_. ]?seva|cashback/i;

  function has(m, list) { return list.filter(function (p) { return m.permissions.indexOf(p) !== -1; }); }
  function short(p) { return p.replace(/^android\.permission\./, ''); }

  function assess(m, ctx) {
    ctx = ctx || {};
    var F = [];
    function add(id, sev, w, evidence, en, hi) { F.push({ id: id, cat: 'apk', sev: sev, w: w, evidence: evidence || '', en: en, hi: hi }); }
    var seen = {};

    var smsRead = has(m, GROUPS.sms_read);
    var smsRecv = m.components.filter(function (c) { return c.kind === 'receiver' && c.actions.indexOf('android.provider.Telephony.SMS_RECEIVED') !== -1; });
    var access = m.components.filter(function (c) { return c.permission === 'android.permission.BIND_ACCESSIBILITY_SERVICE'; });
    var admin = m.components.filter(function (c) { return c.permission === 'android.permission.BIND_DEVICE_ADMIN'; });
    var notif = m.components.filter(function (c) { return c.permission === 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE'; });
    var overlay = has(m, GROUPS.overlay);
    var hasInternet = m.permissions.indexOf('android.permission.INTERNET') !== -1;
    var launcher = m.components.some(function (c) {
      return c.actions.indexOf('android.intent.action.MAIN') !== -1 && c.categories.indexOf('android.intent.category.LAUNCHER') !== -1;
    });

    if (smsRead.length) {
      seen.sms = true;
      add('apk_sms_read', 'high', 35, smsRead.map(short).join(', '),
        'Can read or intercept your SMS. That is how OTP-stealing apps get into your bank account. Real apps from sideloaded APKs almost never need this.',
        'आपके SMS पढ़ या रोक सकता है। OTP चुराने वाले ऐप्स ऐसे ही बैंक खाते तक पहुँचते हैं। APK से इंस्टॉल हुए असली ऐप को इसकी ज़रूरत लगभग कभी नहीं होती।');
    }
    if (smsRecv.length) {
      add('apk_sms_receiver', 'high', 15, smsRecv[0].name,
        'Registers a receiver that fires on every incoming SMS.',
        'हर आने वाले SMS पर चलने वाला रिसीवर रजिस्टर करता है।');
    }
    var smsSend = has(m, GROUPS.sms_send);
    if (smsSend.length) {
      add('apk_sms_send', 'medium', 20, smsSend.map(short).join(', '),
        'Can send SMS from your number, used to spread the scam to your contacts or to subscribe you to premium services.',
        'आपके नंबर से SMS भेज सकता है, ठगी को आपके कॉन्टैक्ट्स तक फैलाने या प्रीमियम सर्विस सब्सक्राइब कराने के लिए।');
    }
    if (access.length) {
      seen.access = true;
      add('apk_accessibility', 'high', 40, access[0].name,
        'Declares an Accessibility service. Banking trojans use it to read your screen, tap buttons and approve payments for you.',
        'Accessibility सर्विस माँगता है। बैंकिंग ट्रोजन इसी से आपकी स्क्रीन पढ़ते, बटन दबाते और आपकी जगह पेमेंट मंज़ूर करते हैं।');
    }
    if (admin.length) {
      add('apk_device_admin', 'high', 30, admin[0].name,
        'Asks to become a Device Administrator, which makes it hard to uninstall and lets it lock or wipe the phone.',
        'डिवाइस एडमिन बनने को कहता है, जिससे अनइंस्टॉल करना मुश्किल होता है और फ़ोन लॉक/वाइप किया जा सकता है।');
    }
    if (notif.length) {
      add('apk_notification_listener', 'high', 30, notif[0].name,
        'Can read all your notifications, including OTPs shown there.',
        'आपके सारे नोटिफ़िकेशन पढ़ सकता है, जिनमें दिखने वाले OTP भी शामिल हैं।');
    }
    if (overlay.length) {
      seen.overlay = true;
      add('apk_overlay', 'medium', 15, 'SYSTEM_ALERT_WINDOW',
        'Can draw over other apps. Used for fake login screens on top of your real banking app.',
        'दूसरे ऐप्स के ऊपर स्क्रीन दिखा सकता है। असली बैंकिंग ऐप के ऊपर नकली लॉगिन स्क्रीन दिखाने में इस्तेमाल होता है।');
    }
    if (has(m, GROUPS.installer).length) {
      add('apk_installer', 'medium', 12, 'REQUEST_INSTALL_PACKAGES',
        'Can install other apps. Typical of a "dropper" that downloads the real malware later.',
        'दूसरे ऐप इंस्टॉल कर सकता है। यह "ड्रॉपर" की पहचान है, जो असली मैलवेयर बाद में डाउनलोड करता है।');
    }
    var calls = has(m, GROUPS.calls);
    if (calls.length) {
      add('apk_calls', 'medium', 15, calls.map(short).join(', '),
        'Can read your call log or control calls (for example forwarding calls to hide bank alerts).',
        'कॉल लॉग पढ़ सकता है या कॉल कंट्रोल कर सकता है (जैसे बैंक अलर्ट छुपाने के लिए कॉल फ़ॉरवर्ड करना)।');
    }
    if (has(m, GROUPS.contacts).length) {
      add('apk_contacts', 'low', 10, '', 'Reads your contacts and accounts.', 'आपके कॉन्टैक्ट्स और अकाउंट पढ़ता है।');
    }
    if (has(m, GROUPS.mic).length) {
      add('apk_mic', 'low', 10, 'RECORD_AUDIO', 'Can record audio.', 'ऑडियो रिकॉर्ड कर सकता है।');
    }
    if (has(m, GROUPS.bglocation).length) {
      add('apk_bg_location', 'low', 10, '', 'Can track your location in the background.', 'बैकग्राउंड में आपकी लोकेशन ट्रैक कर सकता है।');
    }
    if (has(m, GROUPS.storage).length) {
      add('apk_all_files', 'low', 10, 'MANAGE_EXTERNAL_STORAGE', 'Asks for access to all files on the phone.', 'फ़ोन की सारी फ़ाइलों तक पहुँच माँगता है।');
    }
    var dangerousCount = m.permissions.filter(function (p, i, arr) { return DANGEROUS.indexOf(p) !== -1 && arr.indexOf(p) === i; }).length;
    if (dangerousCount >= 10) {
      add('apk_many_perms', 'medium', 15, String(dangerousCount),
        'Asks for ' + dangerousCount + ' sensitive permissions, far more than most apps need.',
        dangerousCount + ' संवेदनशील परमिशन माँगता है, जो ज़्यादातर ऐप्स की ज़रूरत से कहीं ज़्यादा हैं।');
    }

    // combinations
    if (smsRead.length && hasInternet) {
      add('combo_sms_exfil', 'critical', 25, '',
        'SMS access plus internet access means your OTPs can be sent to the attacker.',
        'SMS एक्सेस के साथ इंटरनेट का मतलब है कि आपके OTP हमलावर तक भेजे जा सकते हैं।');
    }
    if (access.length && overlay.length) {
      add('combo_bank_trojan', 'critical', 30, '',
        'Accessibility plus screen overlay is the signature of an Android banking trojan.',
        'Accessibility के साथ स्क्रीन ओवरले एंड्रॉइड बैंकिंग ट्रोजन की पक्की पहचान है।');
    }

    // hidden app
    if (!launcher && (smsRead.length || access.length || admin.length || notif.length)) {
      add('apk_hidden', 'high', 20, '',
        'Has no launcher icon but asks for powerful permissions. It is built to hide from you.',
        'लॉन्चर आइकन नहीं है पर ताक़तवर परमिशन माँगता है। इसे आपसे छुपने के लिए बनाया गया है।');
    }

    // names that imitate banks / government / reward lures
    var nameText = [ctx.fileName || '', m.pkg || '', m.label || ''].join(' ');
    var lure = LURE_RE.exec(nameText);
    if (lure) {
      add('apk_lure_name', 'medium', 25, lure[0],
        'The name imitates a bank, KYC, government scheme, challan or reward. Real ones are installed only from Play Store / App Store, never from an APK sent to you.',
        'नाम किसी बैंक, KYC, सरकारी योजना, चालान या रिवॉर्ड की नकल करता है। असली ऐप सिर्फ़ Play Store / App Store से आते हैं, किसी भेजे गए APK से नहीं।');
    }

    // build quality / signing
    if (m.targetSdk != null && m.targetSdk < 23) {
      add('apk_old_target', 'medium', 15, 'targetSdk ' + m.targetSdk,
        'Built for a very old Android version (target SDK ' + m.targetSdk + '), which gets all permissions silently at install. Malware does this on purpose.',
        'बहुत पुराने Android (target SDK ' + m.targetSdk + ') के लिए बना है, जिसमें सारी परमिशन इंस्टॉल पर चुपचाप मिल जाती हैं। मैलवेयर यह जानबूझकर करता है।');
    }
    if (m.debuggable) add('apk_debuggable', 'low', 10, '', 'The app is marked debuggable, never shipped by real publishers.', 'ऐप debuggable है, असली प्रकाशक ऐसा रिलीज़ नहीं करते।');
    if (ctx.signature) {
      if (!ctx.signature.signed) {
        add('apk_unsigned', 'medium', 25, '',
          'The APK has no signature. Android should refuse it; it was tampered with or built carelessly.',
          'APK पर कोई सिग्नेचर नहीं है। Android को इसे मना करना चाहिए; यह बदला गया है या लापरवाही से बना है।');
      } else if (ctx.signature.debugCert) {
        add('apk_debug_cert', 'medium', 25, '',
          'Signed with a generic "Android Debug" test certificate, not a real publisher identity.',
          'असली प्रकाशक के बजाय सामान्य "Android Debug" टेस्ट सर्टिफ़िकेट से साइन किया गया है।');
      }
    }

    // payloads and strings
    if (ctx.embedded && ctx.embedded.length) {
      add('apk_embedded_payload', 'high', 30, ctx.embedded.slice(0, 3).join(', '),
        'Contains another app or code file hidden inside its assets, a common way to smuggle malware past scanners.',
        'अपने assets में कोई दूसरा ऐप या कोड फ़ाइल छुपाकर रखता है। मैलवेयर को स्कैनर से बचाने का आम तरीका।');
    }
    if (ctx.strings) {
      if (ctx.strings.telegramBot) {
        add('apk_telegram_c2', 'high', 40, 'api.telegram.org/bot…',
          'Contains a Telegram bot address. Many SMS-stealer apps send stolen data to the attacker through a Telegram bot.',
          'Telegram बॉट का पता मिला। कई SMS-स्टीलर ऐप चुराया डेटा Telegram बॉट के ज़रिये हमलावर को भेजते हैं।');
      }
      if (ctx.strings.dynamicLoad) {
        add('apk_dynamic_code', 'medium', 10, 'DexClassLoader',
          'Loads extra code at runtime, so what you scan is not everything it can do.',
          'चलते समय अतिरिक्त कोड लोड करता है, इसलिए जो आप स्कैन करते हैं वही सब कुछ नहीं है।');
      }
      if (ctx.strings.badUrls && ctx.strings.badUrls.length) {
        add('apk_bad_url', 'high', 25, ctx.strings.badUrls.slice(0, 3).join('  '),
          'Talks to a suspicious server address (raw IP, look-alike bank/government domain or similar).',
          'किसी संदिग्ध सर्वर पते (सीधा IP, नकली बैंक/सरकारी डोमेन आदि) से बात करता है।');
      }
    }

    var total = 0;
    var critical = false;
    F.forEach(function (f) { total += f.w; if (f.sev === 'critical') critical = true; });
    var score = Math.min(100, Math.round(total));
    if (critical && score < 60) score = 60;
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    F.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.w - a.w); });
    var level = score >= 80 ? 'scam' : score >= 60 ? 'likely' : score >= 40 ? 'suspicious' : score >= 20 ? 'caution' : 'clean';
    return { score: score, level: level, findings: F, dangerousCount: dangerousCount };
  }

  // ---- Scan ---------------------------------------------------------------
  function getEngine() {
    if (typeof self !== 'undefined' && self.ScamCheck) return self.ScamCheck;
    if (typeof module === 'object' && typeof require === 'function') { try { return require('./engine.js'); } catch (e) { return null; } }
    return null;
  }

  function scanDex(bytes, acc) {
    var s = new TextDecoder('latin1').decode(bytes);
    if (s.indexOf('api.telegram.org/bot') !== -1) acc.telegramBot = true;
    if (s.indexOf('Ldalvik/system/DexClassLoader;') !== -1 || s.indexOf('InMemoryDexClassLoader') !== -1) acc.dynamicLoad = true;
    var re = /https?:\/\/[\x21-\x7e]{4,200}/g;
    var m;
    var n = 0;
    while ((m = re.exec(s)) !== null && n < 400) { acc.urls[m[0]] = true; n++; }
  }

  function indexOfAscii(hay, needle, from, to) {
    var nl = needle.length;
    outer:
    for (var i = from; i <= to - nl; i++) {
      for (var j = 0; j < nl; j++) if (hay[i + j] !== needle.charCodeAt(j)) continue outer;
      return i;
    }
    return -1;
  }

  function checkSignature(buf, zip, entries, datas) {
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var cd = zip.cdOffset;
    var v1 = entries.filter(function (e) { return /^META-INF\/[^/]+\.(?:RSA|DSA|EC)$/i.test(e.name); });
    var hasBlock = false;
    var debug = false;
    if (cd >= 32) {
      var magic = 'APK Sig Block 42';
      var okMagic = true;
      for (var i = 0; i < 16; i++) if (buf[cd - 16 + i] !== magic.charCodeAt(i)) { okMagic = false; break; }
      if (okMagic) {
        hasBlock = true;
        var blockSize = dv.getUint32(cd - 24, true);
        var from = Math.max(0, cd - blockSize - 8);
        if (indexOfAscii(buf, 'Android Debug', from, cd) !== -1) debug = true;
      }
    }
    datas.forEach(function (d) { if (d && indexOfAscii(d, 'Android Debug', 0, d.length) !== -1) debug = true; });
    return { signed: hasBlock || v1.length > 0, debugCert: debug };
  }

  async function sha256Hex(buf) {
    var subtle = (typeof crypto !== 'undefined' && crypto.subtle) || (typeof require === 'function' ? require('crypto').webcrypto.subtle : null);
    if (!subtle) return '';
    var h = new Uint8Array(await subtle.digest('SHA-256', buf));
    return Array.prototype.map.call(h, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  async function scanApk(bytes, opts) {
    opts = opts || {};
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytes.length > MAX_FILE) throw fail('too_big', 'File is larger than ' + (MAX_FILE / 1048576) + ' MB');
    var zip = readZip(bytes);
    var entries = zip.entries;
    var budget = { left: MAX_TOTAL };

    var mEntry = entries.filter(function (e) { return e.name === 'AndroidManifest.xml'; })[0];
    if (!mEntry) throw fail('no_manifest', 'No AndroidManifest.xml: this is not an Android app');
    var mBytes = await entryData(bytes, mEntry, budget);
    if (!mBytes) throw fail('bad_axml', 'Could not read AndroidManifest.xml');
    var manifest = parseManifest(mBytes);

    var acc = { telegramBot: false, dynamicLoad: false, urls: {} };
    var dexCount = 0;
    var dexes = entries.filter(function (e) { return /^classes\d*\.dex$/.test(e.name); });
    for (var i = 0; i < dexes.length; i++) {
      var d = await entryData(bytes, dexes[i], budget);
      if (d) { dexCount++; scanDex(d, acc); }
    }

    var certDatas = [];
    var certEntries = entries.filter(function (e) { return /^META-INF\/[^/]+\.(?:RSA|DSA|EC)$/i.test(e.name); }).slice(0, 4);
    for (var c = 0; c < certEntries.length; c++) certDatas.push(await entryData(bytes, certEntries[c], budget));
    var signature = checkSignature(bytes, zip, entries, certDatas);

    var embedded = entries.filter(function (e) { return /^assets\/.+\.(?:dex|jar|apk|bin|dat|enc)$/i.test(e.name); }).map(function (e) { return e.name; });
    var natives = entries.filter(function (e) { return /^lib\/.+\.so$/.test(e.name); }).length;

    var badUrls = [];
    var engine = getEngine();
    if (engine) {
      Object.keys(acc.urls).slice(0, 80).forEach(function (u) {
        var r = engine.analyze(u);
        if (r.findings.some(function (f) { return f.cat === 'link' && (f.sev === 'critical' || f.sev === 'high'); })) badUrls.push(u);
      });
    }

    var res = assess(manifest, {
      fileName: opts.fileName, signature: signature, embedded: embedded,
      strings: { telegramBot: acc.telegramBot, dynamicLoad: acc.dynamicLoad, badUrls: badUrls },
    });
    var sha = opts.skipHash ? '' : await sha256Hex(bytes);
    res.info = {
      sha256: sha, size: bytes.length, package: manifest.pkg, versionName: manifest.versionName, versionCode: manifest.versionCode,
      label: manifest.label, minSdk: manifest.minSdk, targetSdk: manifest.targetSdk,
      permissions: manifest.permissions.slice(), dangerous: manifest.permissions.filter(function (p) { return DANGEROUS.indexOf(p) !== -1; }),
      dexFiles: dexCount, nativeLibs: natives, signed: signature.signed, debugCert: signature.debugCert,
      components: manifest.components.length,
    };
    res.version = VERSION;
    return res;
  }

  return { scanApk: scanApk, assess: assess, parseManifest: parseManifest, readZip: readZip, entryData: entryData, VERSION: VERSION, DANGEROUS: DANGEROUS, MAX_FILE: MAX_FILE };
});
