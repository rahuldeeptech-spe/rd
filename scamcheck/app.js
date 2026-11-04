/* ScamCheck UI. No network calls, no innerHTML with user data. */
(function () {
  'use strict';

  var CFG = window.SCAMCHECK_CONFIG || {};
  var $ = function (id) { return document.getElementById(id); };

  var T = {
    en: {
      navMsg: 'Message checker', navApk: 'APK scanner', navMcp: 'MCP auditor', navPkg: 'Package detector',
      title: 'Is this message a scam?',
      subtitle: 'Paste the SMS, WhatsApp text, email or link. You get an instant answer and what to do next.',
      privacy: '🔒 Everything is checked on your device. Nothing is uploaded or stored.',
      checkerHeading: 'Checker',
      inputLabel: 'Message or link to check',
      placeholder: 'Paste the message here…',
      check: 'Check now', clear: 'Clear', tryExamples: 'Try an example',
      whyHeading: 'Why we think so', share: 'Share this checker', shared: 'Link copied!',
      tipsHeading: '5 rules that stop most scams',
      reportHeading: 'Already lost money or shared an OTP?',
      reportBody: 'Act within the first hour. It matters a lot.',
      rep1930: 'National Cyber Crime Helpline (India). Call immediately.',
      repPortal: 'File a complaint online.',
      repChakshu: 'Report suspicious calls/SMS (Chakshu) and block stolen phones.',
      donateHeading: 'Keep ScamCheck free',
      donateBody: 'This tool has no ads and no tracking. If it saved you or your family from a scam, a small contribution pays for development and hosting.',
      disclaimer: 'ScamCheck uses rules and patterns. It can miss new scams and can occasionally flag a genuine message. A "no red flags" result is not a guarantee. When in doubt, hang up and contact the organisation using the number printed on your card or on their official website.',
      source: 'Open source (MIT)',
      enterSomething: 'Paste a message or link first.',
      payUpi: 'Pay with UPI', copyUpi: 'Copy UPI ID', copied: 'Copied!', upiNote: 'UPI ID: ',
      whatToDo: 'What to do now',
      sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
      levels: {
        clean: ['No known red flags', 'We found nothing suspicious, but new scams appear every day. Do not share OTPs or PINs, and verify through official channels if money is involved.'],
        caution: ['Be careful', 'A few warning signs. Do not click links or reply until you have verified the sender through an official channel.'],
        suspicious: ['Looks suspicious', 'Several scam signals. Treat this as unsafe until proven otherwise.'],
        likely: ['Likely a scam', 'Strong scam pattern. Do not respond, click or pay.'],
        scam: ['Almost certainly a scam', 'This matches known scam scripts. Stop all contact now.'],
      },
      adviceBad: [
        'Do not reply, click any link, install any app or send any money.',
        'Never share OTP, UPI PIN, CVV or passwords. Nobody legitimate needs them.',
        'Hang up on callers who claim to be police, CBI, customs, TRAI or RBI. Real agencies do not arrest people over video calls.',
        'Tell a family member now. Scammers depend on you staying isolated.',
        'Report it: call 1930 or use cybercrime.gov.in. Report the number on sancharsaathi.gov.in (Chakshu).',
      ],
      adviceOk: [
        'If money, KYC or an account is involved, open the official app or type the website yourself. Never use the link in the message.',
        'Call the organisation on the number printed on your card or on their official website.',
      ],
      tips: [
        'No real bank, police or government office asks for your OTP, PIN, CVV or password.',
        'You never need to enter a PIN or scan a QR code to receive money.',
        '"Digital arrest" does not exist. Hang up, then call 1930.',
        'Never install an app from a link or APK file. Use only the Play Store / App Store.',
        'If it is urgent, secret or too good to be true, pause and talk to someone you trust.',
      ],
      examples: [
        ['Digital arrest call', 'This is CBI officer Rakesh Sharma. A parcel in your name contains drugs and fake passports. An arrest warrant is issued. You are under digital arrest. Do not disconnect the video call and do not tell your family.'],
        ['Fake bank KYC', 'Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login'],
        ['Task job', 'Part time job! Like YouTube videos and earn Rs 5000 per day. Join our Telegram group for tasks. Daily payout.'],
        ['Real bank OTP', '482913 is your OTP for txn of Rs 500.00 at AMAZON. Do not share OTP with anyone. -HDFC Bank'],
      ],
    },
    hi: {
      navMsg: 'मैसेज चेकर', navApk: 'APK स्कैनर', navMcp: 'MCP ऑडिटर', navPkg: 'पैकेज डिटेक्टर',
      title: 'क्या यह संदेश ठगी है?',
      subtitle: 'SMS, WhatsApp, ईमेल या लिंक यहाँ पेस्ट करें। तुरंत जवाब और आगे क्या करना है, दोनों मिलेंगे।',
      privacy: '🔒 सारी जाँच आपके फ़ोन/कंप्यूटर पर ही होती है। कुछ भी अपलोड या सेव नहीं होता।',
      checkerHeading: 'जाँचकर्ता',
      inputLabel: 'जाँचने के लिए संदेश या लिंक',
      placeholder: 'संदेश यहाँ पेस्ट करें…',
      check: 'अभी जाँचें', clear: 'साफ़ करें', tryExamples: 'उदाहरण आज़माएँ',
      whyHeading: 'हमें ऐसा क्यों लगा', share: 'यह टूल शेयर करें', shared: 'लिंक कॉपी हो गया!',
      tipsHeading: '5 नियम जो ज़्यादातर ठगी रोकते हैं',
      reportHeading: 'पैसे कट गए या OTP बता दिया?',
      reportBody: 'पहले एक घंटे में कार्रवाई करें, इससे बहुत फ़र्क पड़ता है।',
      rep1930: 'राष्ट्रीय साइबर क्राइम हेल्पलाइन। तुरंत कॉल करें।',
      repPortal: 'ऑनलाइन शिकायत दर्ज करें।',
      repChakshu: 'संदिग्ध कॉल/SMS की रिपोर्ट (चक्षु) करें और खोया फ़ोन ब्लॉक कराएँ।',
      donateHeading: 'ScamCheck को मुफ़्त रखने में मदद करें',
      donateBody: 'इसमें न विज्ञापन हैं न ट्रैकिंग। अगर इसने आपको या आपके परिवार को ठगी से बचाया, तो छोटा सा सहयोग डेवलपमेंट और होस्टिंग का खर्च उठाने में मदद करता है।',
      disclaimer: 'ScamCheck नियमों और पैटर्न पर चलता है। यह नई ठगी चूक सकता है और कभी-कभी असली संदेश को भी संदिग्ध बता सकता है। "कोई खतरा नहीं" का मतलब गारंटी नहीं है। शक हो तो कॉल काटें और कार्ड या आधिकारिक वेबसाइट पर छपे नंबर से संस्था से संपर्क करें।',
      source: 'ओपन सोर्स (MIT)',
      enterSomething: 'पहले कोई संदेश या लिंक पेस्ट करें।',
      payUpi: 'UPI से दें', copyUpi: 'UPI ID कॉपी करें', copied: 'कॉपी हो गया!', upiNote: 'UPI ID: ',
      whatToDo: 'अब क्या करें',
      sev: { critical: 'गंभीर', high: 'ज़्यादा', medium: 'मध्यम', low: 'कम' },
      levels: {
        clean: ['कोई जाने-पहचाने खतरे नहीं', 'कुछ संदिग्ध नहीं मिला, लेकिन रोज़ नई ठगी आती है। OTP/PIN किसी को न दें, और पैसों का मामला हो तो आधिकारिक माध्यम से पुष्टि करें।'],
        caution: ['सावधान रहें', 'कुछ चेतावनी संकेत हैं। भेजने वाले की आधिकारिक माध्यम से पुष्टि होने तक लिंक न खोलें और जवाब न दें।'],
        suspicious: ['संदिग्ध लगता है', 'कई ठगी के संकेत हैं। इसे असुरक्षित मानें।'],
        likely: ['शायद ठगी है', 'ठगी का मज़बूत पैटर्न है। जवाब न दें, क्लिक न करें, पैसे न भेजें।'],
        scam: ['लगभग पक्की ठगी', 'यह जानी-पहचानी ठगी स्क्रिप्ट से मेल खाता है। तुरंत हर संपर्क बंद करें।'],
      },
      adviceBad: [
        'जवाब न दें, कोई लिंक न खोलें, कोई ऐप इंस्टॉल न करें और पैसे न भेजें।',
        'OTP, UPI PIN, CVV या पासवर्ड कभी न बताएँ। कोई असली संस्था इन्हें नहीं माँगती।',
        'पुलिस, CBI, कस्टम, TRAI या RBI बताने वाले कॉलर का फ़ोन काट दें। असली एजेंसियाँ वीडियो कॉल पर गिरफ्तार नहीं करतीं।',
        'अभी परिवार के किसी सदस्य को बताएँ। ठग चाहते हैं कि आप अकेले रहें।',
        'रिपोर्ट करें: 1930 पर कॉल करें या cybercrime.gov.in पर जाएँ। नंबर की रिपोर्ट sancharsaathi.gov.in (चक्षु) पर करें।',
      ],
      adviceOk: [
        'पैसे, KYC या खाते की बात हो तो आधिकारिक ऐप खोलें या वेबसाइट खुद टाइप करें। संदेश के लिंक का इस्तेमाल न करें।',
        'कार्ड या आधिकारिक वेबसाइट पर छपे नंबर पर संस्था को फ़ोन करें।',
      ],
      tips: [
        'कोई असली बैंक, पुलिस या सरकारी दफ़्तर आपका OTP, PIN, CVV या पासवर्ड नहीं माँगता।',
        'पैसे पाने के लिए PIN डालने या QR स्कैन करने की ज़रूरत कभी नहीं होती।',
        '"डिजिटल अरेस्ट" जैसा कुछ नहीं होता। फ़ोन काटें और 1930 पर कॉल करें।',
        'लिंक या APK फ़ाइल से ऐप कभी इंस्टॉल न करें। सिर्फ़ Play Store / App Store इस्तेमाल करें।',
        'जो बात ज़रूरी, गुप्त या बहुत अच्छी लगे, रुकें और किसी भरोसेमंद से बात करें।',
      ],
      examples: [
        ['डिजिटल अरेस्ट कॉल', 'मैं CBI अधिकारी राकेश शर्मा बोल रहा हूँ। आपके नाम के पार्सल में ड्रग्स और नकली पासपोर्ट मिले हैं। गिरफ्तारी वारंट जारी है। आप डिजिटल अरेस्ट में हैं। वीडियो कॉल मत काटिए और परिवार को मत बताइए।'],
        ['नकली बैंक KYC', 'Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login'],
        ['टास्क जॉब', 'Part time job! Like YouTube videos and earn Rs 5000 per day. Join our Telegram group for tasks. Daily payout.'],
        ['असली बैंक OTP', '482913 is your OTP for txn of Rs 500.00 at AMAZON. Do not share OTP with anyone. -HDFC Bank'],
      ],
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

  function applyStatic() {
    var s = t();
    document.documentElement.lang = lang;
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n]'), function (n) {
      var v = s[n.getAttribute('data-i18n')];
      if (typeof v === 'string') n.textContent = v;
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n-ph]'), function (n) {
      n.setAttribute('placeholder', s[n.getAttribute('data-i18n-ph')]);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === lang));
    });
    var tips = $('tips');
    tips.textContent = '';
    s.tips.forEach(function (x) { tips.appendChild(el('li', null, x)); });
    var chips = $('chips');
    chips.textContent = '';
    s.examples.forEach(function (ex) {
      var b = el('button', 'chip', ex[0]);
      b.type = 'button';
      b.addEventListener('click', function () { $('input').value = ex[1]; run(); });
      chips.appendChild(b);
    });
    renderDonate();
    if (last) render(last);
  }

  function render(r) {
    var s = t();
    var box = $('result');
    box.hidden = false;
    box.setAttribute('data-level', r.level);
    var lv = s.levels[r.level];
    $('verdict-title').textContent = lv[0];
    $('verdict-sub').textContent = lv[1];
    var num = $('scoreNum');
    num.textContent = '';
    num.appendChild(document.createTextNode(String(r.score)));
    num.appendChild(el('small', null, '/100'));
    $('meterFill').style.width = r.score + '%';

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

    var act = $('actions');
    act.textContent = '';
    act.appendChild(el('h3', null, s.whatToDo));
    var ul = el('ul');
    (r.score >= 40 ? s.adviceBad : s.adviceOk).forEach(function (x) { ul.appendChild(el('li', null, x)); });
    act.appendChild(ul);
  }

  function run() {
    var v = $('input').value;
    if (!v.trim()) {
      $('input').focus();
      $('input').setAttribute('placeholder', t().enterSomething);
      return;
    }
    last = window.ScamCheck.analyze(v);
    render(last);
    var box = $('result');
    box.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    box.focus({ preventScroll: true });
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
        var done = function () { c.textContent = s.copied; setTimeout(function () { c.textContent = t().copyUpi; }, 1800); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(upi).then(done, function () {});
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
      b.href = href;
      b.target = '_blank';
      b.rel = 'noopener noreferrer';
      btns.appendChild(b);
    });
    box.hidden = !any;
  }

  function share() {
    var url = location.href.split('#')[0];
    var text = t().title + ' ' + url;
    if (navigator.share) {
      navigator.share({ title: 'ScamCheck', text: t().title, url: url }).catch(function () {});
    } else if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        var b = $('share'); var old = b.textContent; b.textContent = t().shared;
        setTimeout(function () { b.textContent = old; }, 1800);
      }, function () {});
    }
  }

  $('check').addEventListener('click', run);
  $('clear').addEventListener('click', function () {
    $('input').value = '';
    last = null;
    $('result').hidden = true;
    $('input').setAttribute('placeholder', t().placeholder);
    $('input').focus();
  });
  $('input').addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run();
  });
  $('share').addEventListener('click', share);
  Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
    b.addEventListener('click', function () {
      lang = b.getAttribute('data-lang');
      try { localStorage.setItem('scamcheck-lang', lang); } catch (e) { /* ignore */ }
      applyStatic();
    });
  });

  var repo = typeof CFG.repoUrl === 'string' && safeHttps(CFG.repoUrl);
  if (repo) $('repoLink').href = repo;
  $('ver').textContent = 'v' + window.ScamCheck.VERSION;
  applyStatic();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
})();
