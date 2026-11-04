/* ScamCheck APK scanner UI. The file never leaves the browser. */
(function () {
  'use strict';

  var CFG = window.SCAMCHECK_CONFIG || {};
  var $ = function (id) { return document.getElementById(id); };

  var T = {
    en: {
      navMsg: 'Message checker', navApk: 'APK scanner', navMcp: 'MCP auditor', navPkg: 'Package detector', navWifi: 'Wi-Fi & IoT',
      title: 'Is this APK safe to install?',
      subtitle: 'Got an app file on WhatsApp, Telegram or a link ("PM Kisan.apk", "SBI Reward.apk", "RTO Challan.apk")? Check it here before you tap Install.',
      privacy: '🔒 The file is analysed inside your browser. It is never uploaded.',
      scanHeading: 'Scanner', drop: 'Tap to choose an .apk file, or drop it here', dropSub: 'Up to 150 MB. Nothing is installed or run.',
      infoHeading: 'About this file', copyHash: 'Copy SHA-256', copied: 'Copied!', vtLookup: 'Look up hash on VirusTotal',
      vtNote: 'The lookup sends only the hash (a fingerprint), never the file. "Not found" does not mean safe.',
      whyHeading: 'Why we think so', permsHeading: 'Permissions requested',
      tipsHeading: 'Rules for APK files', reportHeading: 'Already installed it?',
      donateHeading: 'Keep ScamCheck free',
      donateBody: 'This tool has no ads and no tracking. If it saved you or your family from a scam, a small contribution pays for development and hosting.',
      disclaimer: "This is a static check of the app's declared permissions, signature and code strings. It cannot prove an app is safe, and some genuine apps ask for powerful permissions. If someone you do not know sent you the file, do not install it, whatever the score says.",
      source: 'Open source (MIT)', payUpi: 'Pay with UPI', copyUpi: 'Copy UPI ID', upiNote: 'UPI ID: ',
      reading: 'Analysing… this can take a few seconds for large files.',
      whatToDo: 'What to do now',
      sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
      k: { package: 'Package', version: 'Version', size: 'Size', sha: 'SHA-256', signed: 'Signature', target: 'Target Android', dex: 'Code files', yes: 'Present', no: 'MISSING', debug: 'Generic debug certificate', dangerous: 'Sensitive permissions' },
      levels: {
        clean: ['No known red flags', 'Nothing alarming in the manifest, signature or code strings. Still install only from a source you trust.'],
        caution: ['Be careful', 'Some powerful permissions or odd traits. Install only if you got it from the official developer and you know why it needs them.'],
        suspicious: ['Looks suspicious', 'Several risky traits. Do not install unless you can verify the publisher.'],
        likely: ['Likely malicious', 'Strong malware pattern. Do not install it.'],
        scam: ['Almost certainly malware', 'This matches known SMS-stealer / banking-trojan behaviour. Delete the file and do not install it.'],
      },
      adviceBad: [
        'Do not install it. Delete the file and the message it came from.',
        'Never turn on "Install unknown apps" for WhatsApp, Telegram or your browser.',
        'Real bank, government and utility apps are installed only from Play Store / App Store.',
        'If you already installed it: switch on airplane mode, uninstall it, run Play Protect, then change your banking passwords from another device and call your bank.',
        'Report it: call 1930 or use cybercrime.gov.in.',
      ],
      adviceOk: [
        'Install only from the official developer or Play Store.',
        'Compare the package name and publisher with the official app page.',
      ],
      tips: [
        'An APK that arrives by WhatsApp, SMS, Telegram or email is a scam far more often than not.',
        'No bank, government office or courier sends an app file. They point you to the Play Store.',
        'If an app asks for SMS, Accessibility, Device Admin or "draw over other apps", stop and think.',
        'Never grant Accessibility permission to a new app that you did not search for yourself.',
        'Keep Play Protect on, and keep "Install unknown apps" off for every app.',
      ],
      rep: [
        'Turn on airplane mode, then uninstall the app (Settings > Apps). If it will not uninstall, remove Device Admin first (Settings > Security).',
        'From another device, change your banking and email passwords and block your cards.',
        'Tell your bank immediately and ask them to freeze UPI.',
      ],
      errors: {
        not_zip: 'This does not look like an APK (it is not a ZIP-based file).',
        bad_zip: 'The file is damaged or cut off.',
        no_manifest: 'No AndroidManifest.xml inside. This is not an Android app.',
        bad_axml: 'The app manifest is unreadable or deliberately corrupted. Corrupted manifests are a trick used by malware: treat it as unsafe.',
        too_big: 'The file is larger than 150 MB.',
        unsupported: 'This browser cannot unzip files. Use a recent Chrome, Edge, Firefox or Safari.',
        other: 'Could not analyse this file.',
      },
      perm: 'Sensitive',
    },
    hi: {
      navMsg: 'मैसेज चेकर', navApk: 'APK स्कैनर', navMcp: 'MCP ऑडिटर', navPkg: 'पैकेज डिटेक्टर', navWifi: 'Wi-Fi और IoT',
      title: 'क्या यह APK इंस्टॉल करना सुरक्षित है?',
      subtitle: 'WhatsApp, Telegram या किसी लिंक से ऐप फ़ाइल मिली ("PM Kisan.apk", "SBI Reward.apk", "RTO Challan.apk")? Install दबाने से पहले यहाँ जाँच लें।',
      privacy: '🔒 फ़ाइल की जाँच आपके ब्राउज़र के अंदर ही होती है। कुछ भी अपलोड नहीं होता।',
      scanHeading: 'स्कैनर', drop: '.apk फ़ाइल चुनने के लिए टैप करें, या यहाँ डालें', dropSub: '150 MB तक। कुछ भी इंस्टॉल या रन नहीं होता।',
      infoHeading: 'इस फ़ाइल के बारे में', copyHash: 'SHA-256 कॉपी करें', copied: 'कॉपी हो गया!', vtLookup: 'VirusTotal पर हैश खोजें',
      vtNote: 'खोज में सिर्फ़ हैश (फ़िंगरप्रिंट) जाता है, फ़ाइल कभी नहीं। "नहीं मिला" का मतलब सुरक्षित नहीं है।',
      whyHeading: 'हमें ऐसा क्यों लगा', permsHeading: 'माँगी गई परमिशन',
      tipsHeading: 'APK फ़ाइलों के नियम', reportHeading: 'अगर इंस्टॉल कर लिया है?',
      donateHeading: 'ScamCheck को मुफ़्त रखने में मदद करें',
      donateBody: 'इसमें न विज्ञापन हैं न ट्रैकिंग। अगर इसने आपको या आपके परिवार को ठगी से बचाया, तो छोटा सा सहयोग डेवलपमेंट और होस्टिंग का खर्च उठाने में मदद करता है।',
      disclaimer: 'यह ऐप की घोषित परमिशन, सिग्नेचर और कोड स्ट्रिंग की स्टैटिक जाँच है। इससे पक्का नहीं होता कि ऐप सुरक्षित है, और कुछ असली ऐप भी ताक़तवर परमिशन माँगते हैं। अगर फ़ाइल किसी अनजान ने भेजी है, तो स्कोर जो भी हो, इंस्टॉल न करें।',
      source: 'ओपन सोर्स (MIT)', payUpi: 'UPI से दें', copyUpi: 'UPI ID कॉपी करें', upiNote: 'UPI ID: ',
      reading: 'जाँच हो रही है… बड़ी फ़ाइलों में कुछ सेकंड लग सकते हैं।',
      whatToDo: 'अब क्या करें',
      sev: { critical: 'गंभीर', high: 'ज़्यादा', medium: 'मध्यम', low: 'कम' },
      k: { package: 'पैकेज', version: 'वर्ज़न', size: 'साइज़', sha: 'SHA-256', signed: 'सिग्नेचर', target: 'टारगेट Android', dex: 'कोड फ़ाइलें', yes: 'मौजूद', no: 'गायब', debug: 'सामान्य डीबग सर्टिफ़िकेट', dangerous: 'संवेदनशील परमिशन' },
      levels: {
        clean: ['कोई जाने-पहचाने खतरे नहीं', 'मैनिफ़ेस्ट, सिग्नेचर या कोड में कुछ चिंताजनक नहीं मिला। फिर भी सिर्फ़ भरोसेमंद स्रोत से इंस्टॉल करें।'],
        caution: ['सावधान रहें', 'कुछ ताक़तवर परमिशन या अजीब लक्षण हैं। तभी इंस्टॉल करें जब यह आधिकारिक डेवलपर से मिला हो और आपको पता हो कि उसे ये क्यों चाहिए।'],
        suspicious: ['संदिग्ध लगता है', 'कई जोखिम भरे लक्षण हैं। प्रकाशक की पुष्टि हुए बिना इंस्टॉल न करें।'],
        likely: ['शायद मैलवेयर है', 'मैलवेयर का मज़बूत पैटर्न है। इंस्टॉल न करें।'],
        scam: ['लगभग पक्का मैलवेयर', 'यह जाने-पहचाने SMS-स्टीलर / बैंकिंग-ट्रोजन के व्यवहार से मेल खाता है। फ़ाइल डिलीट करें और इंस्टॉल न करें।'],
      },
      adviceBad: [
        'इंस्टॉल न करें। फ़ाइल और जिस मैसेज से आई उसे डिलीट कर दें।',
        'WhatsApp, Telegram या ब्राउज़र के लिए "अनजान ऐप इंस्टॉल करें" कभी चालू न करें।',
        'असली बैंक, सरकारी और बिजली-गैस के ऐप सिर्फ़ Play Store / App Store से आते हैं।',
        'अगर इंस्टॉल हो चुका है: एयरप्लेन मोड चालू करें, ऐप अनइंस्टॉल करें, Play Protect चलाएँ, फिर दूसरे डिवाइस से बैंकिंग पासवर्ड बदलें और बैंक को कॉल करें।',
        'रिपोर्ट करें: 1930 पर कॉल करें या cybercrime.gov.in पर जाएँ।',
      ],
      adviceOk: [
        'सिर्फ़ आधिकारिक डेवलपर या Play Store से इंस्टॉल करें।',
        'पैकेज नाम और प्रकाशक को आधिकारिक ऐप पेज से मिलाएँ।',
      ],
      tips: [
        'WhatsApp, SMS, Telegram या ईमेल से आई APK फ़ाइल अक्सर ठगी ही होती है।',
        'कोई बैंक, सरकारी दफ़्तर या कूरियर ऐप फ़ाइल नहीं भेजता। वे Play Store का रास्ता बताते हैं।',
        'अगर ऐप SMS, Accessibility, Device Admin या "दूसरे ऐप के ऊपर दिखाएँ" माँगे, तो रुकें और सोचें।',
        'जिस नए ऐप को आपने खुद सर्च करके नहीं डाला, उसे Accessibility परमिशन कभी न दें।',
        'Play Protect चालू रखें, और हर ऐप के लिए "अनजान ऐप इंस्टॉल करें" बंद रखें।',
      ],
      rep: [
        'एयरप्लेन मोड चालू करें, फिर ऐप अनइंस्टॉल करें (Settings > Apps)। न हटे तो पहले Device Admin हटाएँ (Settings > Security)।',
        'दूसरे डिवाइस से बैंकिंग और ईमेल पासवर्ड बदलें और कार्ड ब्लॉक करें।',
        'बैंक को तुरंत बताएँ और UPI फ़्रीज़ करने को कहें।',
      ],
      errors: {
        not_zip: 'यह APK जैसा नहीं दिखता (ZIP-आधारित फ़ाइल नहीं है)।',
        bad_zip: 'फ़ाइल ख़राब या अधूरी है।',
        no_manifest: 'अंदर AndroidManifest.xml नहीं है। यह Android ऐप नहीं है।',
        bad_axml: 'ऐप का मैनिफ़ेस्ट पढ़ा नहीं जा रहा या जानबूझकर बिगाड़ा गया है। बिगड़े मैनिफ़ेस्ट मैलवेयर की चाल होते हैं: इसे असुरक्षित मानें।',
        too_big: 'फ़ाइल 150 MB से बड़ी है।',
        unsupported: 'यह ब्राउज़र ZIP नहीं खोल सकता। नया Chrome, Edge, Firefox या Safari इस्तेमाल करें।',
        other: 'इस फ़ाइल की जाँच नहीं हो सकी।',
      },
      perm: 'संवेदनशील',
    },
  };

  var lang = 'en';
  var last = null;
  try {
    var saved = localStorage.getItem('scamcheck-lang');
    if (saved === 'hi' || saved === 'en') lang = saved;
    else if ((navigator.language || '').toLowerCase().indexOf('hi') === 0) lang = 'hi';
  } catch (e) { /* storage may be blocked */ }

  function t() { return T[lang]; }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; }

  function applyStatic() {
    var s = t();
    document.documentElement.lang = lang;
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n]'), function (n) {
      var v = s[n.getAttribute('data-i18n')];
      if (typeof v === 'string') n.textContent = v;
    });
    Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === lang));
    });
    var tips = $('tips'); tips.textContent = '';
    s.tips.forEach(function (x) { tips.appendChild(el('li', null, x)); });
    var rep = $('repList'); rep.textContent = '';
    s.rep.forEach(function (x) { rep.appendChild(el('li', null, x)); });
    renderDonate();
    if (last) render(last);
  }

  function row(dl, k, v, cls) {
    dl.appendChild(el('dt', null, k));
    var dd = el('dd', cls, v);
    dl.appendChild(dd);
    return dd;
  }

  function render(r) {
    var s = t();
    var box = $('result');
    box.hidden = false;
    $('errorBox').hidden = true;
    box.setAttribute('data-level', r.level);
    var lv = s.levels[r.level];
    $('verdict-title').textContent = lv[0];
    $('verdict-sub').textContent = lv[1];
    var num = $('scoreNum');
    num.textContent = '';
    num.appendChild(document.createTextNode(String(r.score)));
    num.appendChild(el('small', null, '/100'));
    $('meterFill').style.width = r.score + '%';

    var i = r.info;
    var dl = $('info');
    dl.textContent = '';
    row(dl, s.k.package, i.package, 'mono');
    row(dl, s.k.version, (i.versionName || '?') + (i.versionCode != null ? ' (' + i.versionCode + ')' : ''));
    row(dl, s.k.size, fmtSize(i.size));
    row(dl, s.k.signed, i.signed ? (i.debugCert ? s.k.debug : s.k.yes) : s.k.no, i.signed && !i.debugCert ? '' : 'bad');
    row(dl, s.k.target, i.targetSdk != null ? 'API ' + i.targetSdk : '?');
    row(dl, s.k.dex, String(i.dexFiles));
    row(dl, s.k.sha, i.sha256, 'mono');
    $('vtLink').href = /^[0-9a-f]{64}$/.test(i.sha256) ? 'https://www.virustotal.com/gui/file/' + i.sha256 : '#';
    $('vtLink').hidden = !/^[0-9a-f]{64}$/.test(i.sha256);
    $('copyHash').hidden = !i.sha256;

    var list = $('findings');
    list.textContent = '';
    $('whyH').hidden = r.findings.length === 0;
    r.findings.forEach(function (f) {
      var li = el('li');
      li.setAttribute('data-sev', f.sev);
      li.appendChild(el('span', 'sev', s.sev[f.sev] || f.sev));
      li.appendChild(el('p', null, f[lang] || f.en));
      if (f.evidence) li.appendChild(el('code', null, f.evidence));
      list.appendChild(li);
    });

    var pl = $('perms');
    pl.textContent = '';
    var dangerous = {};
    i.dangerous.forEach(function (p) { dangerous[p] = true; });
    i.permissions.forEach(function (p) {
      var li = el('li', dangerous[p] ? 'danger' : '', p.replace(/^android\.permission\./, ''));
      pl.appendChild(li);
    });
    $('permCount').textContent = '(' + i.permissions.length + ')';

    var act = $('actions');
    act.textContent = '';
    act.appendChild(el('h3', null, s.whatToDo));
    var ul = el('ul');
    (r.score >= 40 ? s.adviceBad : s.adviceOk).forEach(function (x) { ul.appendChild(el('li', null, x)); });
    act.appendChild(ul);
  }

  function showError(code) {
    var s = t();
    $('result').hidden = true;
    last = null;
    $('errorText').textContent = s.errors[code] || s.errors.other;
    $('errorBox').hidden = false;
    $('errorBox').scrollIntoView({ block: 'nearest' });
  }

  async function scan(file) {
    if (!file) return;
    $('errorBox').hidden = true;
    $('status').textContent = t().reading;
    try {
      if (file.size > window.ApkScan.MAX_FILE) { var e = new Error('big'); e.code = 'too_big'; throw e; }
      var buf = new Uint8Array(await file.arrayBuffer());
      last = await window.ApkScan.scanApk(buf, { fileName: file.name });
      $('status').textContent = file.name;
      render(last);
      var box = $('result');
      box.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
      box.focus({ preventScroll: true });
    } catch (err) {
      $('status').textContent = '';
      showError(err && err.code ? err.code : 'other');
    }
  }

  function safeHttps(u) {
    try { var p = new URL(u); return p.protocol === 'https:' ? p.href : null; } catch (e) { return null; }
  }

  function renderDonate() {
    var s = t();
    var box = $('donate');
    var btns = $('donateBtns');
    btns.textContent = '';
    var any = false;
    var upi = typeof CFG.upiId === 'string' ? CFG.upiId.trim() : '';
    if (/^[a-z0-9._-]{2,}@[a-z][a-z0-9]{1,}$/i.test(upi)) {
      any = true;
      var a = el('a', 'btn primary', s.payUpi);
      a.href = 'upi://pay?pa=' + encodeURIComponent(upi) + '&pn=' + encodeURIComponent(CFG.upiName || 'ScamCheck') + '&cu=INR&tn=' + encodeURIComponent('ScamCheck support');
      btns.appendChild(a);
      var c = el('button', 'btn', s.copyUpi);
      c.type = 'button';
      c.addEventListener('click', function () {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(upi).then(function () {
          c.textContent = t().copied; setTimeout(function () { c.textContent = t().copyUpi; }, 1800);
        }, function () {});
      });
      btns.appendChild(c);
      var note = $('upiNote');
      note.hidden = false;
      note.textContent = s.upiNote + upi;
    }
    (Array.isArray(CFG.links) ? CFG.links : []).forEach(function (l) {
      var href = l && safeHttps(l.url);
      if (!href || !l.label) return;
      any = true;
      var b = el('a', 'btn', String(l.label));
      b.href = href; b.target = '_blank'; b.rel = 'noopener noreferrer';
      btns.appendChild(b);
    });
    box.hidden = !any;
  }

  var input = $('file');
  input.addEventListener('change', function () { scan(input.files && input.files[0]); input.value = ''; });
  var drop = $('drop');
  ['dragenter', 'dragover'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (e) { scan(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]); });
  $('copyHash').addEventListener('click', function () {
    if (!last || !navigator.clipboard) return;
    var b = $('copyHash');
    navigator.clipboard.writeText(last.info.sha256).then(function () {
      b.textContent = t().copied; setTimeout(function () { b.textContent = t().copyHash; }, 1800);
    }, function () {});
  });
  Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
    b.addEventListener('click', function () {
      lang = b.getAttribute('data-lang');
      try { localStorage.setItem('scamcheck-lang', lang); } catch (e) { /* ignore */ }
      applyStatic();
    });
  });

  var repo = typeof CFG.repoUrl === 'string' && safeHttps(CFG.repoUrl);
  if (repo) $('repoLink').href = repo;
  $('ver').textContent = 'v' + window.ApkScan.VERSION;
  applyStatic();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
})();
