/*
 * wifiaudit: offline Wi-Fi and IoT security audit, no network, no dependencies.
 * Works in the browser (window.WifiAudit) and in Node (require('./wifiaudit.js')).
 *
 * A browser cannot scan a network, so this tool reads what YOU collected on your OWN network:
 *   - auditChecklist(answers): a guided router/home-network checklist
 *   - auditWifiScan(text, {ssid}): output of nmcli, netsh, iw or airport Wi-Fi scans
 *   - auditNmap(text): nmap output (-oX XML, -oG grepable or normal text) from your LAN
 *
 * Heuristics, not proof. Only audit networks you own or are allowed to test.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WifiAudit = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_INPUT = 3 * 1024 * 1024;
  var MAX_LINES = 60000;
  var MAX_HOSTS = 2000;
  var MAX_PORTS = 3000;
  var MAX_NETS = 2000;

  function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
  function str(x) { return typeof x === 'string' ? x : ''; }
  function fail(code, msg) { var e = new Error(msg); e.code = code; return e; }

  function Collector() { this.list = []; }
  Collector.prototype.add = function (id, sev, w, where, evidence, en, hi, fixEn, fixHi) {
    this.list.push({ id: id, sev: sev, w: w, where: where || '', evidence: evidence || '', en: en, hi: hi, fixEn: fixEn || '', fixHi: fixHi || '' });
  };
  Collector.prototype.merged = function () {
    var by = {};
    var order = [];
    this.list.forEach(function (f) {
      var m = by[f.id];
      if (!m) {
        m = by[f.id] = { id: f.id, cat: 'wifi', sev: f.sev, w: f.w, count: 0, where: [], evidence: f.evidence, en: f.en, hi: f.hi, fixEn: f.fixEn, fixHi: f.fixHi };
        order.push(f.id);
      }
      m.count++;
      if (f.w > m.w) { m.w = f.w; m.sev = f.sev; m.evidence = f.evidence; }
      if (f.where && m.where.indexOf(f.where) === -1 && m.where.length < 12) m.where.push(f.where);
    });
    return order.map(function (id) {
      var m = by[id];
      if (m.sev !== 'low') m.w = m.w + Math.min(15, 5 * (m.count - 1)); // weak hints never escalate by repetition
      return m;
    });
  };
  function finish(C, info, scale) {
    var findings = C.merged();
    if (scale && scale !== 1) findings.forEach(function (f) { f.w = Math.max(1, Math.round(f.w * scale)); });
    var total = 0;
    var critical = false;
    findings.forEach(function (f) { total += f.w; if (f.sev === 'critical') critical = true; });
    var score = Math.min(100, Math.round(total));
    if (critical && (!scale || scale === 1) && score < 60) score = 60;
    // A survey of the neighbourhood (we do not know which network is yours) can warn, but never sounds the alarm.
    if (scale && scale < 1 && score > 39) score = 39;
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.w - a.w); });
    var level = score >= 80 ? 'scam' : score >= 60 ? 'likely' : score >= 40 ? 'suspicious' : score >= 20 ? 'caution' : 'clean';
    return { score: score, level: level, findings: findings, info: info, version: VERSION };
  }

  // =========================================================================
  // 1. Router / home-network checklist
  // =========================================================================
  var QUESTIONS = [
    { id: 'security', options: ['open', 'wep', 'wpa', 'wpa2', 'wpa2wpa3', 'wpa3', 'unknown'], def: 'unknown' },
    { id: 'cipher', options: ['aes', 'tkip', 'unknown'], def: 'unknown' },
    { id: 'wps', options: ['off', 'on', 'unknown'], def: 'unknown' },
    { id: 'adminPassword', options: ['changed', 'default', 'unknown'], def: 'unknown' },
    { id: 'wifiPassword', options: ['strong', 'medium', 'weak', 'sticker', 'unknown'], def: 'unknown' },
    { id: 'passwordRotated', options: ['yes', 'no', 'unknown'], def: 'unknown' },
    { id: 'firmware', options: ['auto', 'recent', 'old', 'ancient', 'unknown'], def: 'unknown' },
    { id: 'routerAge', options: ['new', 'mid', 'old', 'unknown'], def: 'unknown' },
    { id: 'remoteAdmin', options: ['off', 'on', 'unknown'], def: 'unknown' },
    { id: 'upnp', options: ['off', 'on', 'unknown'], def: 'unknown' },
    { id: 'portForward', options: ['no', 'yes', 'unknown'], def: 'unknown' },
    { id: 'iot', options: ['none', 'some', 'many', 'unknown'], def: 'unknown' },
    { id: 'iotSeparate', options: ['yes', 'no', 'unknown'], def: 'unknown' },
    { id: 'hiddenReliance', options: ['no', 'yes'], def: 'no' },
  ];

  var CHECKS = [
    { id: 'cl_open', when: function (a) { return a.security === 'open'; }, sev: 'critical', w: 60,
      en: 'Your Wi-Fi has no password. Anyone nearby can join, watch unencrypted traffic and reach every device on your network.',
      hi: 'आपके Wi-Fi पर पासवर्ड नहीं है। आसपास का कोई भी जुड़ सकता है, बिना एन्क्रिप्शन वाला ट्रैफ़िक देख सकता है और आपके नेटवर्क के हर डिवाइस तक पहुँच सकता है।',
      fixEn: 'Turn on WPA2-AES or WPA3 and set a long password (router admin page > Wireless > Security).', fixHi: 'WPA2-AES या WPA3 चालू करें और लंबा पासवर्ड रखें (राउटर एडमिन पेज > Wireless > Security)।' },
    { id: 'cl_wep', when: function (a) { return a.security === 'wep'; }, sev: 'critical', w: 50,
      en: 'WEP encryption can be broken in minutes with free tools. It is as good as no password.',
      hi: 'WEP एन्क्रिप्शन फ़्री टूल से कुछ ही मिनटों में टूट जाता है। यह लगभग बिना पासवर्ड जैसा है।',
      fixEn: 'Switch to WPA2-AES or WPA3. If the router cannot, replace the router.', fixHi: 'WPA2-AES या WPA3 पर जाएँ। राउटर न कर सके तो राउटर बदलें।' },
    { id: 'cl_wpa1', when: function (a) { return a.security === 'wpa'; }, sev: 'high', w: 35,
      en: 'WPA (version 1) with TKIP is obsolete and has known attacks.', hi: 'WPA (वर्ज़न 1) और TKIP पुराने हैं और इन पर जाने-पहचाने हमले हैं।',
      fixEn: 'Use WPA2-AES (CCMP) or WPA3.', fixHi: 'WPA2-AES (CCMP) या WPA3 इस्तेमाल करें।' },
    { id: 'cl_tkip', when: function (a) { return (a.security === 'wpa2' || a.security === 'wpa2wpa3') && a.cipher === 'tkip'; }, sev: 'medium', w: 20,
      en: 'WPA2 is set to TKIP, the weak legacy cipher.', hi: 'WPA2 में TKIP चुना है, जो कमज़ोर पुराना सिफ़र है।',
      fixEn: 'Choose AES / CCMP only.', fixHi: 'सिर्फ़ AES / CCMP चुनें।' },
    { id: 'cl_security_unknown', when: function (a) { return a.security === 'unknown'; }, sev: 'medium', w: 10,
      en: 'You do not know which Wi-Fi security mode your router uses.', hi: 'आपको नहीं पता कि आपका राउटर कौन सा Wi-Fi सिक्योरिटी मोड इस्तेमाल करता है।',
      fixEn: 'Look it up in the router admin page (Wireless > Security). Aim for WPA2-AES or WPA3.', fixHi: 'राउटर एडमिन पेज में देखें (Wireless > Security)। WPA2-AES या WPA3 रखें।' },
    { id: 'cl_wps', when: function (a) { return a.wps === 'on'; }, sev: 'high', w: 30,
      en: 'WPS is on. The WPS PIN can be guessed offline or online (Pixie Dust, PIN brute force) to reveal your Wi-Fi password.',
      hi: 'WPS चालू है। WPS PIN का अंदाज़ा ऑफ़लाइन या ऑनलाइन (Pixie Dust, PIN brute force) लगाकर आपका Wi-Fi पासवर्ड निकाला जा सकता है।',
      fixEn: 'Turn WPS off completely in the router settings.', fixHi: 'राउटर सेटिंग में WPS पूरी तरह बंद करें।' },
    { id: 'cl_wps_unknown', when: function (a) { return a.wps === 'unknown'; }, sev: 'low', w: 8,
      en: 'You are not sure whether WPS is on.', hi: 'आपको पक्का नहीं पता कि WPS चालू है या नहीं।',
      fixEn: 'Check and disable WPS.', fixHi: 'जाँचें और WPS बंद करें।' },
    { id: 'cl_admin_default', when: function (a) { return a.adminPassword === 'default'; }, sev: 'critical', w: 50,
      en: 'The router admin password is still the default (admin/admin, or the one on the sticker). Anyone on your Wi-Fi, and malicious web pages, can take over the router and change its DNS.',
      hi: 'राउटर का एडमिन पासवर्ड अब भी डिफ़ॉल्ट है (admin/admin या स्टिकर वाला)। आपके Wi-Fi का कोई भी यूज़र, और ख़राब वेब पेज भी, राउटर पर क़ब्ज़ा करके उसका DNS बदल सकते हैं।',
      fixEn: 'Open the admin page (often 192.168.1.1 or 192.168.0.1) and set a unique, long admin password.', fixHi: 'एडमिन पेज खोलें (अक्सर 192.168.1.1 या 192.168.0.1) और अलग, लंबा एडमिन पासवर्ड रखें।' },
    { id: 'cl_admin_unknown', when: function (a) { return a.adminPassword === 'unknown'; }, sev: 'medium', w: 15,
      en: 'You do not know if the router admin password was changed.', hi: 'आपको नहीं पता कि राउटर का एडमिन पासवर्ड बदला गया या नहीं।',
      fixEn: 'Try logging in with the sticker/default password. If it works, change it now.', fixHi: 'स्टिकर/डिफ़ॉल्ट पासवर्ड से लॉगिन करके देखें। चल जाए तो तुरंत बदलें।' },
    { id: 'cl_wifi_weak', when: function (a) { return a.wifiPassword === 'weak'; }, sev: 'high', w: 30,
      en: 'Your Wi-Fi password is short or guessable (name, phone number, birthday, "12345678"). Attackers capture a handshake and guess it offline in minutes.',
      hi: 'आपका Wi-Fi पासवर्ड छोटा या अनुमान लगाने लायक है (नाम, फ़ोन नंबर, जन्मदिन, "12345678")। हमलावर हैंडशेक पकड़कर ऑफ़लाइन कुछ ही मिनटों में अंदाज़ा लगा लेते हैं।',
      fixEn: 'Use a random passphrase of 14 or more characters (for example four unrelated words).', fixHi: '14 या ज़्यादा अक्षरों का रैंडम पासफ़्रेज़ रखें (जैसे चार असंबंधित शब्द)।' },
    { id: 'cl_wifi_medium', when: function (a) { return a.wifiPassword === 'medium'; }, sev: 'medium', w: 15,
      en: 'Your Wi-Fi password is only 8 to 11 characters or follows a pattern.', hi: 'आपका Wi-Fi पासवर्ड सिर्फ़ 8 से 11 अक्षर का है या किसी पैटर्न पर है।',
      fixEn: 'Lengthen it to 14 or more characters.', fixHi: 'इसे 14 या ज़्यादा अक्षर का करें।' },
    { id: 'cl_wifi_sticker', when: function (a) { return a.wifiPassword === 'sticker'; }, sev: 'low', w: 10,
      en: 'You still use the Wi-Fi password printed on the router. On older routers it can be derived from the network name or MAC address.', hi: 'आप अब भी राउटर पर छपा Wi-Fi पासवर्ड इस्तेमाल करते हैं। पुराने राउटर में इसे नेटवर्क नाम या MAC पते से निकाला जा सकता है।',
      fixEn: 'Set your own long passphrase.', fixHi: 'अपना लंबा पासफ़्रेज़ रखें।' },
    { id: 'cl_not_rotated', when: function (a) { return a.passwordRotated === 'no'; }, sev: 'low', w: 10,
      en: 'You did not change the Wi-Fi password after tenants, guests, house-help or ex-staff left. They can still join.', hi: 'किरायेदार, मेहमान, घरेलू सहायक या पुराने स्टाफ़ के जाने के बाद आपने Wi-Fi पासवर्ड नहीं बदला। वे अब भी जुड़ सकते हैं।',
      fixEn: 'Change the password and give a separate guest network to visitors.', fixHi: 'पासवर्ड बदलें और मेहमानों को अलग गेस्ट नेटवर्क दें।' },
    { id: 'cl_fw_old', when: function (a) { return a.firmware === 'old'; }, sev: 'medium', w: 20,
      en: 'The router firmware was not updated for a year or more. Routers are attacked constantly through old bugs.', hi: 'राउटर का फ़र्मवेयर साल भर या उससे ज़्यादा से अपडेट नहीं हुआ। राउटर पर पुराने बग्स के ज़रिये लगातार हमले होते हैं।',
      fixEn: 'Check for a firmware update and turn on automatic updates if available.', fixHi: 'फ़र्मवेयर अपडेट देखें और ऑटो-अपडेट हो तो चालू करें।' },
    { id: 'cl_fw_ancient', when: function (a) { return a.firmware === 'ancient'; }, sev: 'high', w: 35,
      en: 'The router firmware is more than 3 years old or no longer supported.', hi: 'राउटर का फ़र्मवेयर 3 साल से ज़्यादा पुराना है या अब सपोर्ट में नहीं।',
      fixEn: 'Update it, or replace the router with a supported model.', fixHi: 'अपडेट करें, या सपोर्टेड मॉडल का राउटर लें।' },
    { id: 'cl_fw_unknown', when: function (a) { return a.firmware === 'unknown'; }, sev: 'low', w: 10,
      en: 'You do not know when the router firmware was last updated.', hi: 'आपको नहीं पता कि राउटर का फ़र्मवेयर आख़िरी बार कब अपडेट हुआ।',
      fixEn: 'Look at the firmware version/date in the admin page.', fixHi: 'एडमिन पेज में फ़र्मवेयर वर्ज़न/तारीख़ देखें।' },
    { id: 'cl_router_old', when: function (a) { return a.routerAge === 'old'; }, sev: 'medium', w: 15,
      en: 'The router is more than 5 years old, so it probably gets no more security fixes.', hi: 'राउटर 5 साल से ज़्यादा पुराना है, इसलिए शायद उसे अब सुरक्षा फ़िक्स नहीं मिलते।',
      fixEn: 'Plan a replacement with WPA3 and automatic updates.', fixHi: 'WPA3 और ऑटो-अपडेट वाला नया राउटर लेने की योजना बनाएँ।' },
    { id: 'cl_remote_admin', when: function (a) { return a.remoteAdmin === 'on'; }, sev: 'high', w: 40,
      en: 'Remote administration is on, so the router login page is reachable from the internet and is scanned by botnets all day.', hi: 'रिमोट एडमिनिस्ट्रेशन चालू है, यानी राउटर का लॉगिन पेज इंटरनेट से पहुँच में है और बॉटनेट पूरे दिन उसे स्कैन करते हैं।',
      fixEn: 'Turn off remote/WAN management and the telnet/SSH/TR-069 options you do not need.', fixHi: 'रिमोट/WAN मैनेजमेंट और जो telnet/SSH/TR-069 विकल्प ज़रूरी नहीं उन्हें बंद करें।' },
    { id: 'cl_remote_unknown', when: function (a) { return a.remoteAdmin === 'unknown'; }, sev: 'low', w: 8,
      en: 'You are not sure whether remote administration is on.', hi: 'आपको पक्का नहीं पता कि रिमोट एडमिनिस्ट्रेशन चालू है या नहीं।',
      fixEn: 'Check "Remote management" in the admin page.', fixHi: 'एडमिन पेज में "Remote management" देखें।' },
    { id: 'cl_upnp', when: function (a) { return a.upnp === 'on'; }, sev: 'medium', w: 15,
      en: 'UPnP is on. Any device or malware on your network can open ports to the internet without asking you.', hi: 'UPnP चालू है। आपके नेटवर्क का कोई भी डिवाइस या मैलवेयर आपसे पूछे बिना इंटरनेट के लिए पोर्ट खोल सकता है।',
      fixEn: 'Turn UPnP off unless you really need it (some games and cameras do).', fixHi: 'ज़रूरत न हो तो UPnP बंद करें (कुछ गेम और कैमरे माँगते हैं)।' },
    { id: 'cl_port_forward', when: function (a) { return a.portForward === 'yes'; }, sev: 'high', w: 35,
      en: 'You forward ports or use a DMZ to reach cameras, a DVR or a NAS from outside. Exposed IoT devices are found by internet-wide scanners within hours.', hi: 'बाहर से कैमरे, DVR या NAS तक पहुँचने के लिए आप पोर्ट फ़ॉरवर्ड या DMZ इस्तेमाल करते हैं। खुले IoT डिवाइस इंटरनेट-स्कैनर कुछ घंटों में खोज लेते हैं।',
      fixEn: 'Remove the forwards and use the vendor cloud app or a VPN (WireGuard/Tailscale) instead.', fixHi: 'फ़ॉरवर्ड हटाएँ और उसकी जगह वेंडर का क्लाउड ऐप या VPN (WireGuard/Tailscale) इस्तेमाल करें।' },
    { id: 'cl_iot_many', when: function (a) { return a.iot === 'many'; }, sev: 'high', w: 35,
      en: 'Several smart devices (cameras, plugs, TVs, set-top boxes) still use default or weak passwords. This is how Mirai-style botnets recruit devices.', hi: 'कई स्मार्ट डिवाइस (कैमरे, प्लग, TV, सेट-टॉप बॉक्स) अब भी डिफ़ॉल्ट या कमज़ोर पासवर्ड पर हैं। Mirai जैसे बॉटनेट इसी तरह डिवाइस भर्ती करते हैं।',
      fixEn: 'Change every device password and disable features you do not use (telnet, P2P, remote view).', fixHi: 'हर डिवाइस का पासवर्ड बदलें और जो फ़ीचर इस्तेमाल नहीं होते (telnet, P2P, रिमोट व्यू) उन्हें बंद करें।' },
    { id: 'cl_iot_some', when: function (a) { return a.iot === 'some'; }, sev: 'medium', w: 20,
      en: 'Some smart devices still use default or weak passwords.', hi: 'कुछ स्मार्ट डिवाइस अब भी डिफ़ॉल्ट या कमज़ोर पासवर्ड पर हैं।',
      fixEn: 'Change them now and keep their firmware updated.', fixHi: 'अभी बदलें और उनका फ़र्मवेयर अपडेट रखें।' },
    { id: 'cl_iot_unknown', when: function (a) { return a.iot === 'unknown'; }, sev: 'low', w: 8,
      en: 'You do not know whether your smart devices use default passwords.', hi: 'आपको नहीं पता कि आपके स्मार्ट डिवाइस डिफ़ॉल्ट पासवर्ड पर हैं या नहीं।',
      fixEn: 'List every connected device (router client list) and check each one.', fixHi: 'हर कनेक्टेड डिवाइस की सूची बनाएँ (राउटर की client list) और एक-एक जाँचें।' },
    { id: 'cl_iot_same_net', when: function (a) { return a.iot !== 'none' && a.iotSeparate === 'no'; }, sev: 'medium', w: 15,
      en: 'Smart devices share the network with your phones and laptops. One hacked camera or TV then has a path to everything else.', hi: 'स्मार्ट डिवाइस आपके फ़ोन और लैपटॉप के नेटवर्क पर ही हैं। एक हैक हुआ कैमरा या TV बाकी सबके लिए रास्ता बन जाता है।',
      fixEn: 'Put IoT devices on the guest network (with client isolation) or a separate VLAN.', fixHi: 'IoT डिवाइस गेस्ट नेटवर्क (client isolation के साथ) या अलग VLAN पर रखें।' },
    { id: 'cl_hidden', when: function (a) { return a.hiddenReliance === 'yes'; }, sev: 'low', w: 8,
      en: 'Hiding the network name or MAC filtering is not security. Both are bypassed in seconds.', hi: 'नेटवर्क का नाम छुपाना या MAC फ़िल्टरिंग सुरक्षा नहीं है। दोनों सेकंडों में बायपास हो जाते हैं।',
      fixEn: 'Rely on WPA2/WPA3 and a strong password instead.', fixHi: 'इनकी जगह WPA2/WPA3 और मज़बूत पासवर्ड पर भरोसा करें।' },
  ];

  function auditChecklist(answers) {
    var a = {};
    QUESTIONS.forEach(function (q) {
      var v = isObj(answers) ? str(answers[q.id]) : '';
      a[q.id] = q.options.indexOf(v) !== -1 ? v : q.def;
    });
    var C = new Collector();
    // "I don't know" answers are a nudge to go and look, not an emergency: together they are worth at most 25 points.
    var hit = CHECKS.filter(function (c) { return c.when(a); });
    var unkTotal = 0;
    hit.forEach(function (c) { if (/_unknown$/.test(c.id)) unkTotal += c.w; });
    var factor = unkTotal > 25 ? 25 / unkTotal : 1;
    hit.forEach(function (c) {
      var w = /_unknown$/.test(c.id) ? Math.max(1, Math.round(c.w * factor)) : c.w;
      C.add(c.id, c.sev, w, '', '', c.en, c.hi, c.fixEn, c.fixHi);
    });
    return finish(C, { kind: 'checklist', answers: a });
  }

  // =========================================================================
  // 2. Wi-Fi scan output (nmcli, netsh, iw, airport)
  // =========================================================================
  var MAC_RE = /[0-9a-f]{2}(?::[0-9a-f]{2}){5}/i;

  function classOf(sec) {
    if (sec === 'open') return 'open';
    if (sec === 'wep' || sec === 'wpa') return 'weak';
    if (sec === 'owe') return 'owe';
    return 'strong';
  }

  function secFromNmcli(s) {
    var t = String(s || '').trim();
    var up = t.toUpperCase();
    if (!t || t === '--') return { security: 'open' };
    if (/WEP/.test(up)) return { security: 'wep' };
    if (/802\.1X/.test(up)) return { security: 'enterprise' };
    if (/\bOWE\b/.test(up)) return { security: 'owe' };
    var has1 = /WPA1/.test(up);
    var has2 = /WPA2/.test(up);
    var has3 = /WPA3/.test(up);
    if (has3 && has2) return { security: 'wpa2wpa3', legacyWpa: has1 };
    if (has3) return { security: 'wpa3' };
    if (has2) return { security: 'wpa2', legacyWpa: has1 };
    if (has1 || /^WPA\b/.test(up)) return { security: 'wpa' };
    return { security: 'unknown' };
  }

  function parseNmcli(lines) {
    var hi = -1;
    for (var i = 0; i < lines.length; i++) if (/\bSSID\b/.test(lines[i]) && /\bSECURITY\b/.test(lines[i])) { hi = i; break; }
    if (hi < 0) return null;
    var h = lines[hi];
    var cols = [];
    var re = /\S+/g;
    var m;
    while ((m = re.exec(h)) !== null) cols.push({ name: m[0], start: m.index });
    function col(name) { for (var k = 0; k < cols.length; k++) if (cols[k].name === name) return k; return -1; }
    var iS = col('SSID');
    var iB = col('BSSID');
    var iC = col('CHAN');
    var iG = col('SIGNAL');
    var iSec = col('SECURITY');
    function cell(line, k) {
      if (k < 0) return '';
      var s = cols[k].start;
      var e = k + 1 < cols.length ? cols[k + 1].start : line.length;
      return line.slice(s, e).trim();
    }
    var out = [];
    for (var j = hi + 1; j < lines.length && out.length < MAX_NETS; j++) {
      var line = lines[j];
      if (!line.trim()) continue;
      var bssid = iB >= 0 ? cell(line, iB) : (MAC_RE.exec(line) || [''])[0];
      if (iB >= 0 && !MAC_RE.test(bssid)) continue;
      var sec = secFromNmcli(cell(line, iSec));
      var ssid = cell(line, iS);
      if (ssid === '--') ssid = ''; // nmcli prints "--" for a hidden network; every other parser yields ''
      out.push({ ssid: ssid, bssid: bssid.toLowerCase(), security: sec.security, legacyWpa: !!sec.legacyWpa, cipher: '', wps: false, channel: cell(line, iC), signal: cell(line, iG) });
    }
    return out;
  }

  function parseNetsh(lines) {
    var out = [];
    var cur = null;
    var bss = null;
    lines.forEach(function (raw) {
      var line = raw.replace(/\s+$/, '');
      var m = /^\s*SSID\s+\d+\s*:\s?(.*)$/.exec(line);
      if (m) { cur = { ssid: m[1].trim(), auth: '', enc: '' }; bss = null; return; }
      if (!cur) return;
      m = /^\s*Authentication\s*:\s*(.*)$/i.exec(line);
      if (m) { cur.auth = m[1].trim(); return; }
      m = /^\s*Encryption\s*:\s*(.*)$/i.exec(line);
      if (m) { cur.enc = m[1].trim(); return; }
      m = /^\s*BSSID\s+\d+\s*:\s*(\S+)/i.exec(line);
      if (m) {
        if (out.length >= MAX_NETS) return;
        bss = { ssid: cur.ssid, bssid: m[1].toLowerCase(), auth: cur.auth, enc: cur.enc, channel: '', signal: '' };
        out.push(bss);
        return;
      }
      m = /^\s*Signal\s*:\s*(\d+)/i.exec(line);
      if (m && bss) { bss.signal = m[1] + '%'; return; }
      m = /^\s*Channel\s*:\s*(\d+)/i.exec(line);
      if (m && bss) { bss.channel = m[1]; }
    });
    return out.map(function (n) {
      var a = n.auth.toLowerCase();
      var e = n.enc.toLowerCase();
      var sec = 'unknown';
      if (/enterprise/.test(a)) sec = 'enterprise';
      else if (/owe|enhanced open/.test(a)) sec = 'owe';
      else if (/wpa3/.test(a)) sec = 'wpa3';
      else if (/wpa2/.test(a)) sec = 'wpa2';
      else if (/wpa/.test(a)) sec = 'wpa';
      else if (/shared/.test(a) || /wep/.test(e)) sec = 'wep';
      else if (/open/.test(a)) sec = /none/.test(e) || !e ? 'open' : 'wep';
      return { ssid: n.ssid, bssid: n.bssid, security: sec, legacyWpa: false, cipher: /tkip/.test(e) ? 'tkip' : /ccmp|gcmp|aes/.test(e) ? 'aes' : '', wps: false, channel: n.channel, signal: n.signal };
    });
  }

  function parseIw(lines) {
    var out = [];
    var b = null;
    function push() {
      if (!b) return;
      var sec;
      if (b.rsn) {
        var s = b.rsnAuth;
        if (/802\.1X|IEEE 802\.1X/i.test(s) && !/PSK|SAE/i.test(s)) sec = 'enterprise';
        else if (/OWE/i.test(s)) sec = 'owe';
        else if (/SAE/i.test(s) && /PSK/i.test(s)) sec = 'wpa2wpa3';
        else if (/SAE/i.test(s)) sec = 'wpa3';
        else sec = 'wpa2';
      } else if (b.wpa) sec = 'wpa';
      else if (b.privacy) sec = 'wep';
      else sec = 'open';
      var ciphers = b.rsn ? b.rsnPair : b.wpaPair;
      var cipher = /CCMP|GCMP/i.test(ciphers) ? 'aes' : /TKIP/i.test(ciphers) ? 'tkip' : '';
      out.push({ ssid: b.ssid, bssid: b.bssid, security: sec, legacyWpa: !!(b.rsn && b.wpa), cipher: cipher, tkipAllowed: /TKIP/i.test(ciphers), wps: b.wps, channel: b.channel, signal: b.signal });
      b = null;
    }
    var section = '';
    lines.forEach(function (raw) {
      var m = /^BSS\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/i.exec(raw);
      if (m) {
        push();
        if (out.length >= MAX_NETS) return;
        b = { bssid: m[1].toLowerCase(), ssid: '', rsn: false, wpa: false, wps: false, privacy: false, rsnAuth: '', rsnPair: '', wpaPair: '', channel: '', signal: '' };
        section = '';
        return;
      }
      if (!b) return;
      var line = raw.replace(/^\s+/, '');
      if (/^SSID:/.test(line)) { b.ssid = line.replace(/^SSID:\s?/, '').replace(/\\x00/g, ''); section = ''; return; }
      if (/^capability:/i.test(line)) { b.privacy = /\bPrivacy\b/.test(line); return; }
      if (/^signal:/i.test(line)) { b.signal = (/(-?\d+(?:\.\d+)?)\s*dBm/.exec(line) || ['', ''])[1] + ' dBm'; return; }
      m = /^(?:DS Parameter set: channel|\* primary channel:)\s*(\d+)/i.exec(line);
      if (m) { b.channel = m[1]; return; }
      if (/^RSN:/.test(line)) { b.rsn = true; section = 'rsn'; return; }
      if (/^WPA:/.test(line)) { b.wpa = true; section = 'wpa'; return; }
      if (/^WPS:/.test(line)) { b.wps = true; section = 'wps'; return; }
      if (/^(?:Supported rates|Extended supported rates|HT capabilities|VHT capabilities|HE capabilities|Extended capabilities|BSS Load|Country|TSF|freq|beacon|last seen)/i.test(line)) { section = ''; return; }
      if (section === 'rsn' || section === 'wpa') {
        m = /^\*\s*Pairwise ciphers:\s*(.*)$/i.exec(line);
        if (m) { if (section === 'rsn') b.rsnPair = m[1]; else b.wpaPair = m[1]; return; }
        m = /^\*\s*Authentication suites:\s*(.*)$/i.exec(line);
        if (m && section === 'rsn') b.rsnAuth = m[1];
      }
    });
    push();
    return out;
  }

  function parseAirport(lines) {
    var hi = -1;
    for (var i = 0; i < lines.length; i++) if (/\bSSID\b/.test(lines[i]) && /\bBSSID\b/.test(lines[i]) && /\bSECURITY\b/.test(lines[i])) { hi = i; break; }
    if (hi < 0) return null;
    var out = [];
    var re = /^\s*(.*?)\s+((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\s+(-?\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$/i;
    for (var j = hi + 1; j < lines.length && out.length < MAX_NETS; j++) {
      var m = re.exec(lines[j]);
      if (!m) continue;
      var s = m[7];
      var up = s.toUpperCase();
      var sec = 'unknown';
      var legacy = false;
      if (/^NONE\b/.test(up)) sec = 'open';
      else if (/^WEP\b/.test(up)) sec = 'wep';
      else {
        var has3 = /WPA3|SAE/.test(up);
        var has2 = /WPA2|RSN/.test(up);
        var has1 = /(?:^|\s)WPA\(/.test(up) || /^WPA\b(?!2|3)/.test(up);
        if (/802\.1X/i.test(s) && !/PSK|SAE/.test(up)) sec = 'enterprise';
        else if (has3 && has2) sec = 'wpa2wpa3';
        else if (has3) sec = 'wpa3';
        else if (has2) { sec = 'wpa2'; legacy = has1; }
        else if (has1) sec = 'wpa';
      }
      out.push({ ssid: m[1].trim(), bssid: m[2].toLowerCase(), security: sec, legacyWpa: legacy, cipher: /AES|CCMP/.test(up) ? 'aes' : /TKIP/.test(up) ? 'tkip' : '', wps: false, channel: m[4], signal: m[3] + ' dBm' });
    }
    return out;
  }

  function parseWifiScan(input) {
    var text = String(input == null ? '' : input);
    if (text.length > MAX_INPUT) throw fail('too_big', 'Input is larger than 3 MB');
    var lines = text.split(/\r?\n/).slice(0, MAX_LINES);
    var nets = null;
    var format = '';
    if (/^BSS\s+(?:[0-9a-f]{2}:){5}/im.test(text)) { nets = parseIw(lines); format = 'iw'; }
    else if (/^\s*SSID\s+\d+\s*:/m.test(text)) { nets = parseNetsh(lines); format = 'netsh'; }
    else if (/\bSSID\b/.test(text) && /\bBSSID\b/.test(text) && /\bSECURITY\b/.test(text) && /\bRSSI\b/.test(text)) { nets = parseAirport(lines); format = 'airport'; }
    else if (/\bSSID\b/.test(text) && /\bSECURITY\b/.test(text)) { nets = parseNmcli(lines); format = 'nmcli'; }
    return { format: format, networks: nets || [] };
  }

  var BRAND_SSID_RE = /^(?:TP-?LINK|Tenda|D-?Link|NETGEAR|ASUS|Linksys|Jio(?:Fiber|Fi)?|Airtel|BSNL|ACT|Hathway|Excitel|Huawei|ZTE|Realme|Redmi|Xiaomi|Mercusys|Digisol|iBall|Alcatel|Syrotech|Netcore|Cambium)[-_ ]?[0-9A-Za-z]{2,}/i;
  var FREE_SSID_RE = /^(?:free|public|guest|open)[-_ ]?(?:wi-?fi|wifi|net|internet)|(?:airport|station|mall|hotel|cafe)[-_ ]?(?:free[-_ ]?)?wi-?fi/i;

  function auditWifiScan(input, opts) {
    opts = opts || {};
    var text = String(input == null ? '' : input);
    if (!text.trim()) throw fail('empty', 'Nothing to audit');
    var parsed = parseWifiScan(text);
    var nets = parsed.networks;
    if (!parsed.format) throw fail('unrecognised', 'Could not recognise this Wi-Fi scan format');
    if (!nets.length) throw fail('no_networks', 'No networks found in this output');
    var mine = str(opts.ssid).trim();
    var C = new Collector();
    var mineNets = mine ? nets.filter(function (n) { return n.ssid === mine; }) : [];
    if (mine && !mineNets.length) throw fail('ssid_not_found', 'Your network name was not in the scan');
    var targets = mine ? mineNets : nets;

    function nm(n) { return (n.ssid || '(hidden)') + ' [' + n.bssid + ']'; }
    targets.forEach(function (n) {
      var where = nm(n);
      if (n.security === 'open') {
        if (!mine && FREE_SSID_RE.test(n.ssid)) {
          C.add('wf_open_public', 'medium', 20, where, 'open, ' + n.ssid, 'A public/guest-style open hotspot. Anyone on it can sniff or tamper with traffic that is not end-to-end encrypted.', 'सार्वजनिक/गेस्ट जैसा ओपन हॉटस्पॉट। उस पर कोई भी, जो एंड-टू-एंड एन्क्रिप्टेड नहीं है ऐसा ट्रैफ़िक देख या बदल सकता है।',
            'Avoid logins and payments on it, or use a VPN.', 'उस पर लॉगिन और पेमेंट से बचें, या VPN इस्तेमाल करें।');
        } else {
          C.add('wf_open', mine ? 'critical' : 'high', mine ? 60 : 35, where, 'security: none',
            mine ? 'Your Wi-Fi is open: no password and no encryption. Anyone nearby can join and watch your traffic.' : 'This network is open (no encryption).',
            mine ? 'आपका Wi-Fi ओपन है: न पासवर्ड, न एन्क्रिप्शन। आसपास का कोई भी जुड़कर आपका ट्रैफ़िक देख सकता है।' : 'यह नेटवर्क ओपन है (कोई एन्क्रिप्शन नहीं)।',
            'Turn on WPA2-AES or WPA3 with a long password.', 'WPA2-AES या WPA3 और लंबा पासवर्ड चालू करें।');
        }
      } else if (n.security === 'wep') {
        C.add('wf_wep', 'critical', 50, where, 'security: WEP', 'WEP encryption is broken and can be cracked in minutes.', 'WEP एन्क्रिप्शन टूट चुका है और मिनटों में क्रैक हो जाता है।',
          'Switch to WPA2-AES or WPA3, or replace the router.', 'WPA2-AES या WPA3 पर जाएँ, या राउटर बदलें।');
      } else if (n.security === 'wpa') {
        C.add('wf_wpa1', 'high', 35, where, 'security: WPA (v1)' + (n.cipher === 'tkip' ? ' / TKIP' : ''), 'WPA version 1 (TKIP) is obsolete and has known attacks.', 'WPA वर्ज़न 1 (TKIP) पुराना है और उस पर जाने-पहचाने हमले हैं।',
          'Use WPA2-AES or WPA3.', 'WPA2-AES या WPA3 इस्तेमाल करें।');
      } else {
        if (n.legacyWpa) {
          C.add('wf_wpa1_fallback', 'medium', 15, where, 'WPA1 also allowed', 'Besides WPA2 the network still accepts legacy WPA1, so a device can be pushed down to the weak mode.', 'WPA2 के साथ नेटवर्क पुराना WPA1 भी स्वीकार करता है, इसलिए किसी डिवाइस को कमज़ोर मोड पर धकेला जा सकता है।',
            'Set the router to WPA2-only (AES) or WPA3.', 'राउटर को सिर्फ़ WPA2 (AES) या WPA3 पर रखें।');
        }
        if (n.cipher === 'tkip' || (n.tkipAllowed && n.security !== 'wpa3')) {
          C.add('wf_tkip', 'medium', 20, where, n.cipher === 'tkip' ? 'cipher: TKIP only' : 'TKIP also allowed', 'The weak legacy TKIP cipher is in use or allowed.', 'कमज़ोर पुराना TKIP सिफ़र इस्तेमाल या स्वीकार हो रहा है।',
            'Choose AES / CCMP only.', 'सिर्फ़ AES / CCMP चुनें।');
        }
      }
      if (n.wps && n.security !== 'open') {
        C.add('wf_wps', 'high', 30, where, 'WPS advertised', 'The access point advertises WPS. WPS PINs can be attacked (Pixie Dust, PIN brute force) to recover the Wi-Fi password.', 'एक्सेस पॉइंट WPS बताता है। WPS PIN पर हमला (Pixie Dust, PIN brute force) करके Wi-Fi पासवर्ड निकाला जा सकता है।',
          'Disable WPS in the router settings.', 'राउटर सेटिंग में WPS बंद करें।');
      }
      if (mine && n.ssid && BRAND_SSID_RE.test(n.ssid)) {
        C.add('wf_default_name', 'low', 6, where, n.ssid, 'The network name looks like a factory default. It reveals the router brand and often goes with the default password.', 'नेटवर्क का नाम फ़ैक्ट्री डिफ़ॉल्ट जैसा है। इससे राउटर का ब्रांड पता चलता है और अक्सर डिफ़ॉल्ट पासवर्ड भी वही रहता है।',
          'Rename it (without personal info) and change the password.', 'नाम बदलें (निजी जानकारी के बिना) और पासवर्ड बदलें।');
      }
    });

    // look-alike / evil twin: same name, different security class
    var bySsid = {};
    nets.forEach(function (n) { if (n.ssid) (bySsid[n.ssid] = bySsid[n.ssid] || []).push(n); });
    Object.keys(bySsid).forEach(function (ssid) {
      if (mine && ssid !== mine) return;
      var group = bySsid[ssid];
      var classes = {};
      group.forEach(function (n) { classes[classOf(n.security)] = true; });
      if (classes.owe) return; // OWE transition mode deliberately pairs an open and an OWE network
      if (classes.open && (classes.strong || classes.weak)) {
        C.add('wf_evil_twin', mine ? 'critical' : 'high', mine ? 50 : 35, ssid, group.map(function (n) { return n.bssid + ' ' + n.security; }).slice(0, 4).join(', '),
          'The same name "' + ssid + '" is broadcast both with and without encryption. An open copy is the classic "evil twin" that phones auto-join to intercept traffic.',
          'एक ही नाम "' + ssid + '" एन्क्रिप्शन के साथ भी और उसके बिना भी प्रसारित हो रहा है। ओपन कॉपी वही "evil twin" है जिससे फ़ोन अपने-आप जुड़कर ट्रैफ़िक कटवा देते हैं।',
          'If you did not set up the open copy, find that device. On your phones, forget the network and re-join manually.', 'ओपन कॉपी आपने नहीं बनाई तो उस डिवाइस को ढूँढें। फ़ोन में नेटवर्क "forget" करके हाथ से दोबारा जुड़ें।');
      } else if (classes.weak && classes.strong) {
        C.add('wf_security_mismatch', 'medium', 15, ssid, group.map(function (n) { return n.bssid + ' ' + n.security; }).slice(0, 4).join(', '),
          'The same name "' + ssid + '" appears with different security levels (some access points are on weak WEP/WPA). Either an old repeater or an impostor.', 'एक ही नाम "' + ssid + '" अलग सुरक्षा स्तरों के साथ दिखता है (कुछ एक्सेस पॉइंट कमज़ोर WEP/WPA पर हैं)। या तो पुराना रिपीटर है या नक़ली।',
          'Update or remove the old access point.', 'पुराना एक्सेस पॉइंट अपडेट करें या हटाएँ।');
      }
    });

    var counts = { open: 0, wep: 0, wpa: 0, wpa2: 0, wpa3: 0, wpa2wpa3: 0, enterprise: 0, owe: 0, unknown: 0 };
    nets.forEach(function (n) { counts[n.security] = (counts[n.security] || 0) + 1; });
    var info = {
      kind: 'wifi-scan', format: parsed.format, mySsid: mine, scope: mine ? 'mine' : 'survey', networks: nets.length, counts: counts,
      list: nets.slice(0, 200).map(function (n) { return { ssid: n.ssid, bssid: n.bssid, security: n.security, cipher: n.cipher, wps: n.wps, channel: n.channel, signal: n.signal, mine: !!mine && n.ssid === mine }; }),
    };
    // Without knowing which network is yours this is a survey of the neighbourhood: count it at half weight.
    return finish(C, info, mine ? 1 : 0.5);
  }

  // =========================================================================
  // 3. nmap output (-oX, -oG, normal)
  // =========================================================================
  function unent(s) {
    return String(s).replace(/&#(\d+);/g, function (_, d) { return String.fromCharCode(+d); }).replace(/&#x([0-9a-f]+);/gi, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  }

  function attrs(s) {
    var o = {};
    var re = /([\w:-]+)="([^"]*)"/g;
    var m;
    var n = 0;
    while ((m = re.exec(s)) !== null && n++ < 40) o[m[1]] = unent(m[2]);
    return o;
  }

  function mkPort(port, proto, state, service, banner, scripts) {
    return { port: port, proto: proto, state: state, service: service || '', banner: (banner || '').replace(/\s+/g, ' ').trim(), scripts: scripts || {} };
  }

  function parseNmapXml(text) {
    var hosts = [];
    var re = /<host\b[\s\S]*?<\/host>/g;
    var m;
    while ((m = re.exec(text)) !== null && hosts.length < MAX_HOSTS) {
      var hx = m[0];
      var st = /<status\s+state="(\w+)"/.exec(hx);
      if (st && st[1] !== 'up') continue;
      var host = { ip: '', hostname: '', mac: '', vendor: '', os: '', ports: [], scripts: {}, titles: [] };
      var ar = /<address\s+([^>]*?)\/?>/g;
      var a;
      while ((a = ar.exec(hx)) !== null) {
        var at = attrs(a[1]);
        if (at.addrtype === 'mac') { host.mac = at.addr || ''; host.vendor = at.vendor || ''; }
        else if (!host.ip) host.ip = at.addr || '';
      }
      var hn = /<hostname\s+([^>]*?)\/?>/.exec(hx);
      if (hn) host.hostname = attrs(hn[1]).name || '';
      var os = /<osmatch\s+([^>]*?)\/?>/.exec(hx);
      if (os) host.os = attrs(os[1]).name || '';
      else { var oc = /<osclass\s+([^>]*?)\/?>/.exec(hx); if (oc) { var oa = attrs(oc[1]); host.os = [oa.vendor, oa.osfamily, oa.osgen].filter(Boolean).join(' '); } }
      var hs = /<hostscript>([\s\S]*?)<\/hostscript>/.exec(hx);
      if (hs) {
        var sr = /<script\s+id="([^"]*)"\s+output="([^"]*)"/g;
        var s;
        while ((s = sr.exec(hs[1])) !== null) host.scripts[s[1]] = unent(s[2]);
      }
      var pr = /<port\s+protocol="(\w+)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
      var p;
      while ((p = pr.exec(hx)) !== null && host.ports.length < MAX_PORTS) {
        var body = p[3];
        var stt = /<state\s+state="([^"]+)"/.exec(body);
        var sv = /<service\s+([^>]*?)\/?>/.exec(body);
        var sa = sv ? attrs(sv[1]) : {};
        var scripts = {};
        var sc = /<script\s+id="([^"]*)"\s+output="([^"]*)"/g;
        var q;
        while ((q = sc.exec(body)) !== null) scripts[q[1]] = unent(q[2]);
        var banner = [sa.name, sa.product, sa.version, sa.extrainfo, sa.tunnel === 'ssl' ? '(ssl)' : ''].filter(Boolean).join(' ');
        var port = mkPort(+p[2], p[1], stt ? stt[1] : 'unknown', sa.name, banner, scripts);
        if (sa.tunnel === 'ssl') port.ssl = true;
        host.ports.push(port);
      }
      hosts.push(host);
    }
    return hosts;
  }

  function parseNmapGrep(text) {
    var hosts = [];
    var seen = {};
    text.split(/\r?\n/).slice(0, MAX_LINES).forEach(function (line) {
      var m = /^Host:\s+(\S+)\s+\(([^)]*)\)\s*(.*)$/.exec(line);
      if (!m) return;
      var h = seen[m[1]];
      if (!h) {
        if (hosts.length >= MAX_HOSTS) return;
        h = seen[m[1]] = { ip: m[1], hostname: m[2], mac: '', vendor: '', os: '', ports: [], scripts: {}, titles: [] };
        hosts.push(h);
      }
      var rest = m[3];
      var pm = /(?:^|\t)Ports:\s*(.*?)(?=\t[A-Z][\w ]*:|$)/.exec(rest);
      if (pm) {
        pm[1].split(/,\s+(?=\d+\/(?:open|closed|filtered|unfiltered)[^/]*\/)/).forEach(function (entry) {
          if (h.ports.length >= MAX_PORTS) return;
          var f = entry.split('/');
          if (f.length < 5) return;
          var version = (f[6] || '').replace(/\|/g, '/');
          h.ports.push(mkPort(+f[0], f[2], f[1], (f[4] || '').replace(/\?$/, ''), [f[4], version].filter(Boolean).join(' '), {}));
        });
      }
      var om = /(?:^|\t)OS:\s*([^\t]*)/.exec(rest);
      if (om) h.os = om[1].trim();
    });
    return hosts;
  }

  function parseNmapNormal(text) {
    var hosts = [];
    var cur = null;
    var lastScript = null;
    var lines = text.split(/\r?\n/).slice(0, MAX_LINES);
    lines.forEach(function (line) {
      var m = /^Nmap scan report for (.+)$/.exec(line);
      if (m) {
        if (hosts.length >= MAX_HOSTS) { cur = null; return; }
        var ip = '';
        var name = '';
        var mm = /^(.*?)\s+\(([^)]+)\)$/.exec(m[1].trim());
        if (mm) { name = mm[1]; ip = mm[2]; } else ip = m[1].trim();
        cur = { ip: ip, hostname: name, mac: '', vendor: '', os: '', ports: [], scripts: {}, titles: [] };
        hosts.push(cur);
        lastScript = null;
        return;
      }
      if (!cur) return;
      // Host-level scripts (smb-protocols, smb-vuln-*, ...) are listed after the port table under this heading.
      if (/^Host script results:/.test(line)) { lastScript = { port: { scripts: cur.scripts }, name: '' }; return; }
      m = /^MAC Address:\s*((?:[0-9A-F]{2}:){5}[0-9A-F]{2})(?:\s+\((.*)\))?/i.exec(line);
      if (m) { cur.mac = m[1]; cur.vendor = m[2] || ''; return; }
      m = /^(?:OS details|Running(?: \(JUST GUESSING\))?|Aggressive OS guesses):\s*(.+)$/.exec(line);
      if (m) { if (!cur.os) cur.os = m[1].replace(/\s*\(\d+%\).*$/, '').split(',')[0].trim(); return; }
      m = /^(\d+)\/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered|closed\|filtered)\s+(\S+)\s*(.*)$/.exec(line);
      if (m) {
        if (cur.ports.length < MAX_PORTS) {
          var port = mkPort(+m[1], m[2], m[3], m[4].replace(/\?$/, ''), (m[4].replace(/\?$/, '') + ' ' + m[5]).trim(), {});
          if (/ssl\//i.test(m[4])) port.ssl = true;
          cur.ports.push(port);
          lastScript = { port: port, name: '' };
        }
        return;
      }
      m = /^\|[_ ]\s?([\w.-]+):\s?(.*)$/.exec(line);
      if (m && lastScript) {
        lastScript.port.scripts[m[1]] = m[2];
        lastScript.name = m[1];
        return;
      }
      m = /^\|[_ ]?\s{2,}(.*)$/.exec(line);
      if (m && lastScript && lastScript.name) {
        lastScript.port.scripts[lastScript.name] += ' ' + m[1];
      }
    });
    return hosts;
  }

  function parseNmap(input) {
    var text = String(input == null ? '' : input);
    if (text.length > MAX_INPUT) throw fail('too_big', 'Input is larger than 3 MB');
    var hosts = [];
    var format = '';
    if (/<nmaprun\b|<host\b[\s\S]*<address\b/i.test(text)) { hosts = parseNmapXml(text); format = 'xml'; }
    else if (/^Host:\s+\S+\s+\([^)]*\)\s+(?:Ports|Status):/m.test(text)) { hosts = parseNmapGrep(text); format = 'grepable'; }
    else if (/^Nmap scan report for /m.test(text)) { hosts = parseNmapNormal(text); format = 'normal'; }
    return { format: format, hosts: hosts };
  }

  var DB_UNAUTH = [6379, 27017, 11211, 9200, 5984];
  var DB_SQL = [3306, 5432, 1433, 1521];
  var CAMERA_RE = /hikvision|dahua|ipcam|ip[ -]?camera|network camera|webcam|\bdvr\b|\bnvr\b|cctv|foscam|amcrest|reolink|\btapo\b|uniview|vivotek|\baxis\b|\bhi3510|\bxm(?:eye)?\b.*cam/i;

  function verBefore(banner, re, minMajor, minMinor) {
    var m = re.exec(banner);
    if (!m) return false;
    var maj = +m[1];
    var min = +m[2];
    return maj < minMajor || (maj === minMajor && min < minMinor);
  }

  function auditNmap(input) {
    var text = String(input == null ? '' : input);
    if (!text.trim()) throw fail('empty', 'Nothing to audit');
    var parsed = parseNmap(text);
    if (!parsed.format) throw fail('unrecognised', 'Could not recognise this as nmap output (-oX, -oG or normal text)');
    var hosts = parsed.hosts;
    if (!hosts.length) throw fail('no_hosts', 'No hosts found in this output');
    var C = new Collector();
    var openTotal = 0;
    var summary = [];

    hosts.forEach(function (h) {
      var open = h.ports.filter(function (p) { return p.state === 'open'; });
      openTotal += open.length;
      var label = h.ip + (h.hostname ? ' (' + h.hostname + ')' : '');
      open.forEach(function (p) {
        var where = h.ip + ':' + p.port + '/' + p.proto;
        var b = p.banner;
        var ev = (p.service ? p.service + ' ' : '') + (b && b !== p.service ? b.replace(new RegExp('^' + p.service.replace(/[^\w]/g, '\\$&') + '\\s*'), '') : '');
        ev = ev.trim().slice(0, 100);
        var tcp = p.proto === 'tcp';
        var svc = p.service.toLowerCase();
        var title = str(p.scripts['http-title']);
        var blob = b + ' ' + title + ' ' + str(p.scripts['http-server-header']) + ' ' + str(p.scripts.banner);

        if ((tcp && p.port === 23) || svc === 'telnet') {
          C.add('net_telnet', 'critical', 50, where, ev, 'Telnet is open. It sends passwords in clear text and is the main way Mirai-style botnets take over cameras and routers.', 'Telnet खुला है। यह पासवर्ड सादे टेक्स्ट में भेजता है और Mirai जैसे बॉटनेट इसी से कैमरे और राउटर पर क़ब्ज़ा करते हैं।',
            'Disable telnet on the device (use SSH or nothing) and change its password.', 'डिवाइस पर telnet बंद करें (SSH इस्तेमाल करें या कुछ नहीं) और पासवर्ड बदलें।');
        }
        if (tcp && p.port === 5555) {
          C.add('net_adb', 'critical', 50, where, ev || 'port 5555', 'Port 5555 is open. On Android TVs, boxes and phones this is the Android Debug Bridge, which gives full remote control with no password. (nmap often mislabels it as "freeciv".)', 'पोर्ट 5555 खुला है। Android TV, बॉक्स और फ़ोन पर यह Android Debug Bridge है, जो बिना पासवर्ड पूरा रिमोट कंट्रोल देता है। (nmap इसे अक्सर "freeciv" लिख देता है।)',
            'Turn off USB/Wi-Fi debugging in the developer options, or block the device from the network.', 'डेवलपर विकल्पों में USB/Wi-Fi debugging बंद करें, या डिवाइस को नेटवर्क से हटाएँ।');
        }
        if (/vsftpd 2\.3\.4/i.test(blob)) {
          C.add('net_vsftpd_backdoor', 'critical', 55, where, ev, 'vsftpd 2.3.4 is the version that shipped with a famous backdoor (CVE-2011-2523) giving a root shell.', 'vsftpd 2.3.4 वही वर्ज़न है जिसमें मशहूर बैकडोर (CVE-2011-2523) था और जो रूट शेल देता है।',
            'Remove or upgrade it immediately.', 'तुरंत हटाएँ या अपग्रेड करें।');
        }
        if (/Anonymous FTP login allowed/i.test(str(p.scripts['ftp-anon']))) {
          C.add('net_ftp_anon', 'high', 40, where, 'anonymous login allowed', 'The FTP server allows anonymous login, so anyone on the network can read (and maybe write) its files.', 'FTP सर्वर anonymous लॉगिन देता है, इसलिए नेटवर्क का कोई भी उसकी फ़ाइलें पढ़ (और शायद लिख) सकता है।',
            'Disable anonymous access.', 'Anonymous एक्सेस बंद करें।');
        } else if (tcp && (p.port === 21 || svc === 'ftp')) {
          C.add('net_ftp', 'medium', 20, where, ev, 'FTP is open. It is unencrypted and usually has weak or default accounts.', 'FTP खुला है। यह एन्क्रिप्टेड नहीं है और इसमें अक्सर कमज़ोर या डिफ़ॉल्ट अकाउंट होते हैं।',
            'Use SFTP or turn FTP off.', 'SFTP इस्तेमाल करें या FTP बंद करें।');
        }
        if (tcp && (p.port === 3389 || svc === 'ms-wbt-server')) {
          C.add('net_rdp', 'high', 35, where, ev, 'Remote Desktop (RDP) is open to the network. It is a top target for password guessing and ransomware.', 'Remote Desktop (RDP) नेटवर्क पर खुला है। पासवर्ड-अनुमान और रैनसमवेयर का यह मुख्य निशाना है।',
            'Turn RDP off, or allow it only through a VPN with strong passwords and network-level authentication.', 'RDP बंद करें, या सिर्फ़ VPN के ज़रिये मज़बूत पासवर्ड और NLA के साथ दें।');
        }
        if (tcp && (/^vnc/.test(svc) || (p.port >= 5900 && p.port <= 5903))) {
          C.add('net_vnc', 'high', 35, where, ev, 'VNC remote screen access is open. Many VNC servers have no or weak passwords.', 'VNC रिमोट स्क्रीन एक्सेस खुला है। कई VNC सर्वर में पासवर्ड नहीं या कमज़ोर होता है।',
            'Turn it off, or tunnel it through SSH/VPN with a strong password.', 'बंद करें, या SSH/VPN टनल और मज़बूत पासवर्ड से चलाएँ।');
        }
        if (tcp && (p.port === 554 || p.port === 8554 || svc === 'rtsp')) {
          C.add('net_camera_stream', 'high', 30, where, ev, 'An RTSP video stream is open. Cameras often serve it with no password or a default one, so anyone on the network can watch.', 'RTSP वीडियो स्ट्रीम खुली है। कैमरे अक्सर इसे बिना पासवर्ड या डिफ़ॉल्ट पासवर्ड से देते हैं, इसलिए नेटवर्क का कोई भी देख सकता है।',
            'Set a strong camera password and disable RTSP if you do not use it.', 'कैमरे का मज़बूत पासवर्ड रखें और RTSP इस्तेमाल न हो तो बंद करें।');
        }
        if (CAMERA_RE.test(blob)) {
          C.add('net_camera_device', 'medium', 15, where, (title || ev).slice(0, 100), 'This looks like a camera or DVR/NVR. These are the most abused IoT devices (default passwords, old firmware).', 'यह कैमरा या DVR/NVR जैसा दिखता है। ये सबसे ज़्यादा दुरुपयोग होने वाले IoT डिवाइस हैं (डिफ़ॉल्ट पासवर्ड, पुराना फ़र्मवेयर)।',
            'Change its password, update firmware, and keep it off the internet.', 'पासवर्ड बदलें, फ़र्मवेयर अपडेट करें और इंटरनेट से दूर रखें।');
        }
        if (tcp && p.port === 7547) {
          C.add('net_tr069', 'high', 30, where, ev || 'TR-069', 'TR-069 (ISP remote management) is reachable. It has been hit by large router-hijacking attacks.', 'TR-069 (ISP का रिमोट मैनेजमेंट) पहुँच में है। राउटर हाइजैक करने वाले बड़े हमले इस पर हो चुके हैं।',
            'Ask the ISP to restrict it to their network, or disable it if the router allows.', 'ISP से कहें कि इसे सिर्फ़ उनके नेटवर्क तक सीमित करें, या राउटर में बंद करें।');
        }
        if ((p.proto === 'udp' && p.port === 1900) || /upnp/i.test(svc) || /miniupnpd/i.test(blob)) {
          C.add('net_upnp', 'medium', 20, where, ev, 'UPnP is exposed. Any device or malware on the network can ask the router to open ports to the internet.', 'UPnP खुला है। नेटवर्क का कोई भी डिवाइस या मैलवेयर राउटर से इंटरनेट के लिए पोर्ट खुलवा सकता है।',
            'Disable UPnP on the router unless needed.', 'ज़रूरत न हो तो राउटर पर UPnP बंद करें।');
        }
        if (tcp && (DB_UNAUTH.indexOf(p.port) !== -1 || /^(?:redis|mongodb|memcached|elasticsearch|couchdb)/.test(svc))) {
          C.add('net_db_unauth', 'high', 30, where, ev || svc, 'A database or cache that often runs without a password (Redis, MongoDB, Memcached, Elasticsearch, CouchDB) is reachable on the network.', 'डेटाबेस या कैश जो अक्सर बिना पासवर्ड चलता है (Redis, MongoDB, Memcached, Elasticsearch, CouchDB) नेटवर्क पर पहुँच में है।',
            'Bind it to 127.0.0.1 or require authentication and a firewall.', '127.0.0.1 पर बाइंड करें या ऑथेंटिकेशन और फ़ायरवॉल लगाएँ।');
        } else if (tcp && (DB_SQL.indexOf(p.port) !== -1 || /^(?:mysql|postgresql|ms-sql|oracle)/.test(svc))) {
          C.add('net_db', 'medium', 20, where, ev || svc, 'A SQL database is reachable from the network.', 'SQL डेटाबेस नेटवर्क से पहुँच में है।',
            'Allow only the hosts that need it.', 'सिर्फ़ उन्हीं होस्ट को दें जिन्हें ज़रूरत है।');
        }
        if (tcp && (p.port === 1883 || svc === 'mqtt')) {
          C.add('net_mqtt', 'medium', 20, where, ev, 'An unencrypted MQTT broker is open. Smart-home brokers often allow anonymous publish/subscribe, which lets anyone control devices.', 'बिना एन्क्रिप्शन का MQTT ब्रोकर खुला है। स्मार्ट-होम ब्रोकर अक्सर anonymous publish/subscribe देते हैं, जिससे कोई भी डिवाइस चला सकता है।',
            'Require a username/password and use TLS (port 8883).', 'यूज़रनेम/पासवर्ड ज़रूरी करें और TLS (पोर्ट 8883) इस्तेमाल करें।');
        }
        if (tcp && (p.port === 445 || p.port === 139 || svc === 'microsoft-ds' || svc === 'netbios-ssn')) {
          C.add('net_smb', 'medium', 15, where, ev, 'Windows file sharing (SMB) is open. Keep it to trusted PCs only; it is the path worms and ransomware spread along.', 'Windows फ़ाइल शेयरिंग (SMB) खुली है। इसे सिर्फ़ भरोसेमंद PC तक रखें; वर्म और रैनसमवेयर इसी रास्ते फैलते हैं।',
            'Disable SMBv1 and share only what you need, with passwords.', 'SMBv1 बंद करें और सिर्फ़ ज़रूरी चीज़ें पासवर्ड के साथ शेयर करें।');
        }
        if (/\bBoa\b[^\n]{0,20}?\b0\.9\d/i.test(blob)) {
          C.add('net_boa', 'high', 30, where, ev, 'The device runs the Boa web server, abandoned since 2005 and full of unpatched bugs. It is common on old cameras and routers.', 'डिवाइस Boa वेब सर्वर चलाता है, जो 2005 से छोड़ दिया गया है और अनपैच बग्स से भरा है। पुराने कैमरों और राउटरों में आम है।',
            'Check for firmware updates; if none exist, replace the device or isolate it.', 'फ़र्मवेयर अपडेट देखें; न हो तो डिवाइस बदलें या अलग नेटवर्क पर रखें।');
        }
        var old = null;
        if (verBefore(b, /OpenSSH[ _](\d+)\.(\d+)/i, 7, 4)) old = 'OpenSSH older than 7.4 (2016)';
        else if (/Dropbear sshd (20\d\d)\./i.test(b) && +/Dropbear sshd (20\d\d)\./i.exec(b)[1] < 2019) old = 'Dropbear older than 2019';
        else if (/Apache httpd (?:1\.|2\.[0-2]\b)/i.test(b)) old = 'Apache httpd 2.2 or older (end of life)';
        else if (/IIS httpd (?:[2-7]\.|8\.0)/i.test(b)) old = 'old Microsoft IIS (end of life)';
        else if (/Samba smbd 3\./i.test(b)) old = 'Samba 3.x (end of life)';
        else if (/lighttpd[ /]1\.4\.(?:[0-9]|[12][0-9]|3[0-5])\b/i.test(blob)) old = 'lighttpd 1.4.35 or older (2014)';
        else if (/miniupnpd[ /]1\./i.test(blob)) old = 'miniupnpd 1.x';
        if (old) {
          C.add('net_old_software', 'medium', 20, where, old + ': ' + ev, 'Outdated server software with years of known vulnerabilities.', 'पुराना सर्वर सॉफ़्टवेयर जिसमें सालों की जानी-पहचानी कमज़ोरियाँ हैं।',
            'Update the device firmware or the service.', 'डिवाइस का फ़र्मवेयर या सर्विस अपडेट करें।');
        }
        Object.keys(p.scripts).forEach(function (sid) {
          var out = str(p.scripts[sid]);
          if (/VULNERABLE/i.test(out)) {
            C.add('net_vuln', 'critical', 50, where, sid + ': ' + out.replace(/\s+/g, ' ').slice(0, 90), 'An nmap vulnerability script reports this service as VULNERABLE.', 'nmap का vulnerability स्क्रिप्ट इस सर्विस को VULNERABLE बताता है।',
              'Patch or isolate it now.', 'तुरंत पैच करें या अलग करें।');
          } else if (sid === 'vulners' && /CVE-\d{4}-\d+/.test(out)) {
            C.add('net_known_cves', 'high', 35, where, 'vulners: ' + (/CVE-\d{4}-\d+/.exec(out) || [''])[0] + ' ...', 'The detected software version has published CVEs (nmap "vulners" script).', 'पहचाने गए सॉफ़्टवेयर वर्ज़न के प्रकाशित CVE हैं (nmap "vulners" स्क्रिप्ट)।',
              'Update the software, then re-scan.', 'सॉफ़्टवेयर अपडेट करें, फिर दोबारा स्कैन करें।');
          }
          if (/valid credentials|credentials found|default credentials|login: .*password:/i.test(out) && /brute|default|accounts/i.test(sid)) {
            C.add('net_default_creds', 'critical', 50, where, sid + ': ' + out.replace(/\s+/g, ' ').slice(0, 90), 'A login with default or guessed credentials worked on this service.', 'इस सर्विस पर डिफ़ॉल्ट या अनुमानित क्रेडेंशियल से लॉगिन हो गया।',
              'Change the password now.', 'पासवर्ड तुरंत बदलें।');
          }
          if (/ssl-enum-ciphers/.test(sid) && /SSLv[23]|TLSv1\.0/.test(out)) {
            C.add('net_ssl_old', 'medium', 15, where, 'old TLS/SSL versions enabled', 'The service still allows obsolete SSL/TLS versions.', 'सर्विस अब भी अप्रचलित SSL/TLS वर्ज़न की अनुमति देती है।',
              'Allow TLS 1.2 and 1.3 only.', 'सिर्फ़ TLS 1.2 और 1.3 रखें।');
          }
        });
        if (svc.indexOf('http') === 0 && !p.ssl && !/https/.test(svc) && p.port !== 443 && p.port !== 8443) {
          C.add('net_http_cleartext', 'low', 5, where, ev, 'A web interface is served over plain http. Admin passwords typed there are visible on the network.', 'वेब इंटरफ़ेस सादे http पर चलता है। वहाँ टाइप किए एडमिन पासवर्ड नेटवर्क पर दिखते हैं।',
            'Use https for admin pages where the device supports it.', 'जहाँ डिवाइस सपोर्ट करे वहाँ एडमिन पेज के लिए https इस्तेमाल करें।');
        }
      });
      Object.keys(h.scripts).forEach(function (sid) {
        var out = str(h.scripts[sid]);
        if (/VULNERABLE/i.test(out)) {
          C.add('net_vuln', 'critical', 50, h.ip, sid + ': ' + out.replace(/\s+/g, ' ').slice(0, 90), 'An nmap vulnerability script reports this host as VULNERABLE.', 'nmap का vulnerability स्क्रिप्ट इस होस्ट को VULNERABLE बताता है।', 'Patch or isolate it now.', 'तुरंत पैच करें या अलग करें।');
        }
        if (/smb-protocols/.test(sid) && /NT LM 0\.12/.test(out)) {
          C.add('net_smb1', 'high', 30, h.ip, 'SMBv1 enabled', 'The old SMBv1 protocol is enabled (the one WannaCry used).', 'पुराना SMBv1 प्रोटोकॉल चालू है (जिसका WannaCry ने इस्तेमाल किया था)।', 'Disable SMBv1.', 'SMBv1 बंद करें।');
        }
      });
      if (open.length > 15) {
        C.add('net_many_ports', 'medium', 15, h.ip, open.length + ' open ports', 'A single device exposes many open ports, a large attack surface.', 'एक ही डिवाइस कई पोर्ट खोले हुए है, यानी हमले की बड़ी सतह।', 'Turn off services you do not use.', 'जो सर्विस इस्तेमाल नहीं होतीं उन्हें बंद करें।');
      }
      if (/Windows (?:XP|Vista|7|2000|Server 2003|Server 2008)\b/i.test(h.os)) {
        C.add('net_eol_os', 'medium', 20, h.ip, h.os, 'This host runs an operating system that no longer gets security updates.', 'यह होस्ट ऐसा ऑपरेटिंग सिस्टम चला रहा है जिसे अब सुरक्षा अपडेट नहीं मिलते।', 'Upgrade or isolate it.', 'अपग्रेड करें या अलग रखें।');
      }
      summary.push({
        ip: h.ip, hostname: h.hostname, mac: h.mac, vendor: h.vendor, os: h.os, label: label,
        open: open.slice(0, 60).map(function (p) { return { port: p.port, proto: p.proto, service: p.service, banner: p.banner.slice(0, 80) }; }),
      });
    });

    return finish(C, { kind: 'nmap', format: parsed.format, hosts: hosts.length, openPorts: openTotal, list: summary.slice(0, 300) });
  }

  return {
    auditChecklist: auditChecklist, auditWifiScan: auditWifiScan, auditNmap: auditNmap,
    parseWifiScan: parseWifiScan, parseNmap: parseNmap, QUESTIONS: QUESTIONS, VERSION: VERSION, MAX_INPUT: MAX_INPUT,
  };
});
