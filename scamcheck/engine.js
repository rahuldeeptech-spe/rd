/*
 * scamcheck engine: offline, rule-based scam-message and link analysis.
 * No network calls, no dependencies. Works in the browser (window.ScamCheck)
 * and in Node (require('./engine.js')).
 *
 * This is a heuristic. A low score does NOT prove a message is safe.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ScamCheck = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_INPUT = 20000;

  // ---- Levels -------------------------------------------------------------
  var LEVELS = [
    { id: 'clean', min: 0 },
    { id: 'caution', min: 20 },
    { id: 'suspicious', min: 40 },
    { id: 'likely', min: 60 },
    { id: 'scam', min: 80 },
  ];

  function levelFor(score) {
    var out = LEVELS[0];
    for (var i = 0; i < LEVELS.length; i++) if (score >= LEVELS[i].min) out = LEVELS[i];
    return out.id;
  }

  // ---- Text rules ---------------------------------------------------------
  // sev: critical rules floor the score at 60 (a single one is enough to warn).
  // neg: test against text with "do not share ..." style warnings removed,
  //      so genuine bank OTP SMS ("Do not share OTP with anyone") stay clean.
  var TEXT_RULES = [
    {
      id: 'digital_arrest', cat: 'impersonation', sev: 'critical', w: 60,
      re: /digital[\s-]*arrest|डिजिटल\s*अरेस्ट|डिजिटल\s*गिरफ्तार/i,
      en: '"Digital arrest" does not exist in Indian law. No agency arrests anyone over a call or video call.',
      hi: '"डिजिटल अरेस्ट" जैसी कोई चीज़ कानून में नहीं है। कोई एजेंसी कॉल या वीडियो कॉल पर गिरफ्तारी नहीं करती।',
    },
    {
      id: 'authority_threat', cat: 'impersonation', sev: 'high', w: 35,
      re: /(?:\bcbi\b|enforcement directorate|\bncb\b|narcotics|customs|\btrai\b|cyber\s*crime|supreme court|(?:mumbai|delhi|cyber)\s*police|\bpolice\b|\brbi\b|income\s*tax)\b.{0,80}?(?:arrest|warrant|\bfir\b|illegal|money laundering|parcel|seiz|freez|block|case registered|legal action)/i,
      en: 'Claims to be from police / CBI / customs / TRAI / RBI and threatens you. Real agencies send written notices, not threatening calls.',
      hi: 'पुलिस / CBI / कस्टम / TRAI / RBI होने का दावा करके धमकी दी जा रही है। असली एजेंसियाँ लिखित नोटिस भेजती हैं, धमकी भरे कॉल नहीं।',
    },
    {
      id: 'arrest_words', cat: 'impersonation', sev: 'high', w: 35,
      re: /arrest warrant|गिरफ्तार|मनी\s*लॉन्ड्रिंग|money laundering|drugs?\b.{0,40}(?:found|parcel|package)|parcel\b.{0,50}(?:drugs?|illegal|fake passport|contraband)/i,
      en: 'Mentions arrest, warrant, money laundering or drugs in a parcel, a classic pressure script.',
      hi: 'गिरफ्तारी, वारंट, मनी लॉन्ड्रिंग या पार्सल में ड्रग्स की बात, यह डराने वाली आम स्क्रिप्ट है।',
    },
    {
      id: 'stay_on_call', cat: 'pressure', sev: 'critical', w: 45,
      re: /(?:do not|don't|dont|never)\s+(?:disconnect|cut|hang\s*up|end)\b.{0,20}(?:call|video)|stay on (?:the )?(?:call|video)|keep (?:your )?camera on|video call.{0,20}(?:mat|na)\s+(?:katna|hatna)|कॉल\s*(?:मत|न)\s*काट/i,
      en: 'Tells you not to hang up or to stay on a video call. Scammers isolate victims this way.',
      hi: 'कॉल न काटने या वीडियो कॉल पर बने रहने को कहा जा रहा है। ठग इसी तरह शिकार को अलग-थलग करते हैं।',
    },
    {
      id: 'secrecy', cat: 'pressure', sev: 'high', w: 30,
      re: /(?:do not|don't|dont|never)\s+(?:tell|inform|discuss|talk)\b.{0,25}(?:family|police|bank|friends|about (?:this|the|case|call|matter|investigation))|keep (?:this|it) (?:secret|confidential)|किसी\s*को\s*(?:न|नहीं)\s*बता/i,
      en: 'Asks you to keep this secret from family, bank or police. Genuine officials never do that.',
      hi: 'परिवार, बैंक या पुलिस से बात छुपाने को कहा जा रहा है। असली अधिकारी ऐसा कभी नहीं कहते।',
    },
    {
      id: 'otp_request', cat: 'credentials', sev: 'critical', w: 50, neg: true,
      re: /(?:share|send|tell|give|forward|read out|batao|bata do|bhejo|bhej do|बताएं|बताओ|भेजें|दें)\b.{0,30}?\b(?:otp|cvv|upi\s*pin|atm\s*pin|mpin|password|ओटीपी)|\b(?:otp|cvv|upi\s*pin|atm\s*pin|mpin|ओटीपी)\b.{0,25}?(?:share|send|batao|bhejo|बताएं|भेजें)/i,
      en: 'Asks for your OTP, PIN, CVV or password. No bank, agency or company ever needs these.',
      hi: 'OTP, PIN, CVV या पासवर्ड माँगा जा रहा है। कोई बैंक या कंपनी ये कभी नहीं माँगती।',
    },
    {
      id: 'upi_pin_receive', cat: 'credentials', sev: 'critical', w: 55,
      re: /upi\s*pin\b.{0,60}(?:receive|credit|refund|prize|cashback|पैसे)|(?:receive|get|refund|cashback).{0,40}upi\s*pin|scan\b.{0,25}\bqr\b.{0,50}(?:receive|get paid|refund|credit)/i,
      en: 'You NEVER enter a UPI PIN or scan a QR code to RECEIVE money. That only sends money out.',
      hi: 'पैसे पाने के लिए UPI PIN डालना या QR स्कैन करना कभी ज़रूरी नहीं। इससे सिर्फ़ पैसे कटते हैं।',
    },
    {
      id: 'remote_access', cat: 'malware', sev: 'critical', w: 45,
      re: /anydesk|teamviewer|quick\s*support|rustdesk|airdroid|screen\s*shar(?:e|ing)\s*(?:app|apk)?/i,
      en: 'Asks you to install a remote-access / screen-share app. That gives the scammer full control of your phone and banking apps.',
      hi: 'रिमोट-एक्सेस / स्क्रीन-शेयर ऐप इंस्टॉल करने को कहा जा रहा है। इससे ठग आपके फ़ोन और बैंकिंग ऐप पर पूरा कंट्रोल पा लेता है।',
    },
    {
      id: 'apk_install', cat: 'malware', sev: 'critical', w: 45,
      re: /\.apk\b|install\b.{0,30}\b(?:apk|app)\b.{0,40}(?:link|below|attached)|एपीके/i,
      en: 'Pushes an .apk file or app outside the Play Store. Fake APKs steal SMS, OTPs and bank logins.',
      hi: 'Play Store के बाहर .apk फ़ाइल या ऐप इंस्टॉल करने को कहा जा रहा है। नकली APK आपके SMS, OTP और बैंक लॉगिन चुरा लेते हैं।',
    },
    {
      id: 'kyc_block', cat: 'phishing', sev: 'high', w: 25,
      re: /(?:\bkyc\b|केवाईसी|pan\s*card|\bpan\b|aadhaar|aadhar|आधार).{0,60}?(?:expire|update|pending|verify|verification|suspend|block|band|बंद|अपडेट|सत्यापित)|(?:update|complete|verify|renew|अपडेट)\s+(?:your\s+)?(?:\bkyc\b|केवाईसी|pan\b|aadhaar|aadhar|आधार)/i,
      en: 'KYC / PAN / Aadhaar "update or your account is blocked" is a very common phishing lure. Banks do this only in branch or the official app.',
      hi: 'KYC / PAN / आधार "अपडेट करो वरना खाता बंद" एक आम फ़िशिंग चाल है। बैंक यह केवल ब्रांच या आधिकारिक ऐप में करते हैं।',
    },
    {
      id: 'account_block', cat: 'phishing', sev: 'medium', w: 25,
      re: /(?:account|a\/c|खाता|card|\bsim\b|mobile number|number).{0,40}?(?:will be )?(?:block|suspend|deactivat|clos|disconnect|band ho|बंद|ब्लॉक)/i,
      en: 'Threatens to block or close your account, card or SIM.',
      hi: 'आपका खाता, कार्ड या SIM बंद/ब्लॉक करने की धमकी।',
    },
    {
      id: 'urgency', cat: 'pressure', sev: 'low', w: 12,
      re: /(?:within|in|next)\s*\d+\s*(?:hours?|hrs?|minutes?|mins?)|immediately|right now|urgent(?:ly)?|last (?:warning|chance|notice)|today only|turant|abhi turant|तुरंत|जल्द से जल्द|आज ही/i,
      en: 'Creates artificial urgency so you act before thinking.',
      hi: 'जल्दबाज़ी का दबाव बनाया जा रहा है ताकि आप सोचे बिना कदम उठाएँ।',
    },
    {
      id: 'prize', cat: 'lure', sev: 'high', w: 30,
      re: /you (?:have )?won\b|congratulations.{0,40}(?:won|prize|winner|selected|reward)|lucky (?:draw|winner)|lottery|\bkbc\b|jackpot|inaam|इनाम|लॉटरी|जैकपॉट/i,
      en: 'Prize / lottery / lucky-draw message. You cannot win a contest you never entered.',
      hi: 'इनाम / लॉटरी / लकी ड्रॉ का संदेश। जिस प्रतियोगिता में हिस्सा ही नहीं लिया, उसे जीता नहीं जा सकता।',
    },
    {
      id: 'advance_fee', cat: 'lure', sev: 'high', w: 35,
      re: /(?:registration|processing|clearance|release|insurance|customs|delivery|gst|activation)\s*(?:fee|fees|charge|charges|amount|deposit)|refundable\s*(?:deposit|fee|amount)|pay\b.{0,30}to (?:release|claim|receive|unlock)|security deposit/i,
      en: 'Asks for an upfront fee to release money, a parcel or a job. Real prizes and jobs never charge you first.',
      hi: 'पैसे, पार्सल या नौकरी "छुड़ाने" के लिए पहले फ़ीस माँगी जा रही है। असली इनाम या नौकरी में पहले पैसे नहीं लगते।',
    },
    {
      id: 'task_job', cat: 'lure', sev: 'high', w: 40,
      re: /(?:part[\s-]*time|work from home|\bwfh\b|ghar baithe).{0,60}?(?:earn|income|salary|₹|rs\.?|inr|कमाएं|कमाई)|earn\b.{0,25}?(?:₹|rs\.?|inr)\s*\d[\d,]*\s*(?:per|a|\/)?\s*(?:day|daily|hour)|(?:like|subscribe|rate|review|follow)\b.{0,35}(?:youtube|videos?|products?|hotel|google maps|instagram).{0,50}(?:earn|pay|₹|rs|income)|daily (?:payout|payment|income)|(?:घर बैठे).{0,30}(?:कमाएं|कमाई)/i,
      en: 'Part-time / "like videos and earn" task job. Classic task scam: small early payouts, then you are asked to deposit big amounts.',
      hi: 'पार्ट-टाइम / "वीडियो लाइक करो और कमाओ" वाला टास्क जॉब। शुरू में छोटा भुगतान, फिर बड़ी रकम जमा कराई जाती है।',
    },
    {
      id: 'telegram_group', cat: 'lure', sev: 'medium', w: 20,
      re: /telegram.{0,40}(?:task|group|channel|join)|join.{0,30}(?:telegram|whatsapp)\s*(?:group|channel)/i,
      en: 'Moves you to a Telegram/WhatsApp group. Common in job, task and stock-tip scams.',
      hi: 'आपको Telegram/WhatsApp ग्रुप में बुलाया जा रहा है। जॉब, टास्क और स्टॉक-टिप ठगी में यह आम है।',
    },
    {
      id: 'investment', cat: 'lure', sev: 'high', w: 35,
      re: /(?:guaranteed|assured|fixed|daily)\s*(?:returns?|profit|income)|double your money|\d{2,3}\s*%\s*(?:profit|returns?)\s*(?:daily|weekly|monthly|guaranteed)|(?:vip|premium)\s*(?:stock|trading|signal|group)|ipo allotment|insider (?:tip|info)|(?:stock|trading|crypto|forex)\s*(?:tips?|signals?)\b|crypto.{0,30}(?:profit|returns|invest)/i,
      en: 'Guaranteed returns / VIP stock-tip / crypto profit pitch. Guaranteed returns do not exist in real investing.',
      hi: '"पक्का मुनाफ़ा" / VIP स्टॉक-टिप / क्रिप्टो कमाई का दावा। असली निवेश में गारंटीड रिटर्न नहीं होता।',
    },
    {
      id: 'utility_scare', cat: 'phishing', sev: 'medium', w: 25,
      re: /(?:electricity|power|bijli|बिजली).{0,50}?(?:disconnect|cut|tonight|काट|कनेक्शन)|fastag.{0,30}(?:block|suspend|deactivat)|(?:e-?challan|traffic fine).{0,40}(?:pay|due|unpaid|pending)|(?:gas|lpg).{0,30}(?:connection|subsidy).{0,30}(?:block|kyc|cancel)/i,
      en: 'Bill / FASTag / challan / gas scare. These "pay now or be cut off" messages are usually fake.',
      hi: 'बिजली / FASTag / चालान / गैस कनेक्शन कटने का डर। ऐसे "अभी भरो वरना कनेक्शन कटेगा" संदेश अक्सर फ़र्ज़ी होते हैं।',
    },
    {
      id: 'delivery_scam', cat: 'phishing', sev: 'medium', w: 25,
      re: /(?:package|parcel|courier|delivery|india post).{0,50}?(?:held|on hold|pending|failed|address|incomplete|undelivered).{0,70}?(?:click|link|update|pay|reschedule)|india post.{0,40}(?:address|link)/i,
      en: 'Fake courier / India Post "address incomplete, click to fix" message.',
      hi: 'नकली कूरियर / इंडिया पोस्ट का "पता अधूरा है, लिंक पर क्लिक करें" संदेश।',
    },
    {
      id: 'refund_bait', cat: 'lure', sev: 'medium', w: 20,
      re: /(?:refund|cashback|reward points?|rewards?)\b.{0,40}?(?:claim|click|expire|redeem|credited soon)/i,
      en: 'Refund / cashback / reward "claim now" bait.',
      hi: 'रिफ़ंड / कैशबैक / रिवॉर्ड "अभी क्लेम करें" का लालच।',
    },
    {
      id: 'loan_bait', cat: 'lure', sev: 'medium', w: 25,
      re: /(?:instant|pre[\s-]?approved|easy) loan.{0,50}?(?:no (?:cibil|documents?|collateral)|apply now|click|link)|loan.{0,30}(?:processing fee|advance fee)/i,
      en: 'Instant / pre-approved loan bait, often a way to harvest documents or take a processing fee.',
      hi: 'इंस्टेंट / प्री-अप्रूव्ड लोन का लालच, आमतौर पर दस्तावेज़ या प्रोसेसिंग फ़ीस हड़पने के लिए।',
    },
    {
      id: 'family_impersonation', cat: 'impersonation', sev: 'high', w: 50,
      re: /(?:hi|hello|hey)\s+(?:mum|mom|dad|papa|mummy|beta|bhai)\b.{0,60}?(?:new number|lost my phone|phone (?:broke|is broken|fell)|changed my number)/i,
      en: '"Hi Mum/Dad, this is my new number" is a well-known family-impersonation scam. Call the person on their old number.',
      hi: '"मम्मी/पापा, यह मेरा नया नंबर है" एक जानी-पहचानी ठगी है। पुराने नंबर पर फ़ोन करके पुष्टि करें।',
    },
    {
      id: 'emergency_money', cat: 'impersonation', sev: 'high', w: 30,
      re: /(?:urgent|emergency|accident|hospital|arrested).{0,60}?(?:send|transfer|pay)\b.{0,25}(?:money|₹|rs\.?|amount|paise|पैसे)/i,
      en: 'Emergency + "send money now" pattern. Verify by calling the person directly.',
      hi: 'इमरजेंसी + "अभी पैसे भेजो" वाला पैटर्न। सीधे उस व्यक्ति को फ़ोन करके पुष्टि करें।',
    },
  ];

  var RULE_BY_ID = {};
  TEXT_RULES.forEach(function (r) { RULE_BY_ID[r.id] = r; });

  // ---- Link analysis ------------------------------------------------------
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd', 'shorturl.at', 'tiny.cc', 'goo.gl',
    'ow.ly', 'buff.ly', 'rebrand.ly', 'bl.ink', 'v.gd', 'x.co', 'shorte.st', 'qr.ae', 'lnkd.in',
  ];
  var CHAT_INVITES = ['t.me', 'telegram.me', 'chat.whatsapp.com', 'wa.me', 'discord.gg'];
  var RISKY_TLDS = [
    'xyz', 'top', 'click', 'icu', 'cfd', 'sbs', 'vip', 'live', 'shop', 'site', 'online', 'buzz', 'work',
    'rest', 'monster', 'cyou', 'fun', 'life', 'link', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'bond',
  ];
  var COMMON_TLDS = [
    'com', 'in', 'co.in', 'net', 'org', 'gov.in', 'nic.in', 'info', 'app', 'me', 'io', 'co', 'ly', 'sbi',
  ].concat(RISKY_TLDS);

  // keyword -> official registrable domains. A hostname that contains the keyword
  // but is not one of these (or a subdomain of one) is treated as a look-alike.
  var BRANDS = [
    { kw: 'sbi', strict: true, name: 'SBI', ok: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbi.bank.in', 'sbicard.com', 'sbilife.co.in', 'sbimf.com'] },
    { kw: 'hdfc', name: 'HDFC', ok: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net', 'hdfclife.com', 'hdfcergo.com', 'hdfcsec.com', 'hdfcfund.com', 'hdfcbank.bank.in'] },
    { kw: 'icici', name: 'ICICI', ok: ['icicibank.com', 'icicidirect.com', 'iciciprulife.com', 'icicilombard.com', 'icici.bank.in'] },
    { kw: 'axisbank', name: 'Axis Bank', ok: ['axisbank.com', 'axis.bank.in', 'axismaxlife.com'] },
    { kw: 'kotak', name: 'Kotak', ok: ['kotak.com', 'kotak.bank.in'] },
    { kw: 'paytm', name: 'Paytm', ok: ['paytm.com', 'paytmbank.com', 'paytm.in'] },
    { kw: 'phonepe', name: 'PhonePe', ok: ['phonepe.com'] },
    { kw: 'gpay', strict: true, name: 'Google Pay', ok: ['pay.google.com', 'gpay.app.goo.gl'] },
    { kw: 'irctc', name: 'IRCTC', ok: ['irctc.co.in', 'irctc.com'] },
    { kw: 'incometax', name: 'Income Tax Dept', ok: ['incometax.gov.in', 'incometaxindia.gov.in'] },
    { kw: 'uidai', name: 'UIDAI / Aadhaar', ok: ['uidai.gov.in'] },
    { kw: 'epfo', name: 'EPFO', ok: ['epfindia.gov.in', 'epfindia.com'] },
    { kw: 'npci', name: 'NPCI', ok: ['npci.org.in'] },
    { kw: 'amazon', name: 'Amazon', ok: ['amazon.in', 'amazon.com', 'amazon.co.uk', 'amazonaws.com', 'amzn.in', 'amzn.to', 'amazon.jobs'] },
    { kw: 'flipkart', name: 'Flipkart', ok: ['flipkart.com', 'fkrt.it'] },
    { kw: 'indiapost', name: 'India Post', ok: ['indiapost.gov.in'] },
    { kw: 'fastag', name: 'FASTag', ok: ['netc.org.in', 'npci.org.in'] },
    { kw: 'whatsapp', name: 'WhatsApp', ok: ['whatsapp.com', 'wa.me', 'whatsapp.net'] },
    { kw: 'telegram', name: 'Telegram', ok: ['telegram.org', 't.me', 'telegram.me'] },
  ];

  function isUnder(host, domain) {
    return host === domain || host.slice(-(domain.length + 1)) === '.' + domain;
  }

  function endsWithTld(host, tld) {
    return host.slice(-(tld.length + 1)) === '.' + tld;
  }

  var TLD_ALT = COMMON_TLDS.slice().sort(function (a, b) { return b.length - a.length; })
    .map(function (t) { return t.replace(/\./g, '\\.'); }).join('|');
  var URL_RE = new RegExp(
    '(?:https?:\\/\\/[^\\s<>"\'`]+)|(?:www\\.[^\\s<>"\'`]+)|(?:\\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,5}\\.(?:' +
      TLD_ALT + ')(?![a-z0-9-])(?:[\\/?#][^\\s<>"\'`]*)?)',
    'gi'
  );

  function extractUrls(text) {
    var found = [];
    var seen = {};
    var m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text)) !== null) {
      var raw = m[0].replace(/[)\].,;:!?'"]+$/, '');
      if (!raw) continue;
      // skip e-mail addresses like name@example.com (the host part)
      var before = text.charAt(m.index - 1);
      if (before === '@') continue;
      var withScheme = /^https?:\/\//i.test(raw) ? raw : 'http://' + raw;
      var u;
      try { u = new URL(withScheme); } catch (e) { continue; }
      var key = u.hostname + u.pathname;
      if (seen[key]) continue;
      seen[key] = true;
      found.push({
        raw: raw,
        host: u.hostname.toLowerCase().replace(/\.$/, ''),
        path: u.pathname + u.search,
        protocol: /^https:\/\//i.test(raw) ? 'https:' : (/^http:\/\//i.test(raw) ? 'http:' : 'none'),
        hasUserinfo: !!(u.username || u.password),
      });
    }
    return found;
  }

  function analyseUrl(u) {
    var out = [];
    var host = u.host;
    var labels = host.split('.');
    var tokens = host.split(/[.\-]/);

    function add(id, sev, w, en, hi) { out.push({ id: id, cat: 'link', sev: sev, w: w, evidence: u.raw, en: en, hi: hi }); }

    if (u.hasUserinfo || /@/.test(u.raw.replace(/^https?:\/\//i, '').split('/')[0])) {
      add('link_userinfo', 'high', 40,
        'The link hides its real destination behind an "@" sign.',
        'लिंक में "@" लगाकर असली गंतव्य छुपाया गया है।');
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[.*\]$/.test(host)) {
      add('link_ip', 'high', 35,
        'The link points to a raw IP address instead of a normal website name.',
        'लिंक किसी वेबसाइट नाम की जगह सीधे IP पते पर जाता है।');
    }
    if (labels.some(function (l) { return l.indexOf('xn--') === 0; })) {
      add('link_punycode', 'high', 35,
        'The domain uses look-alike (international) characters to imitate a real site.',
        'डोमेन में मिलते-जुलते (अंतरराष्ट्रीय) अक्षरों से असली साइट की नकल की गई है।');
    }
    var shortener = SHORTENERS.some(function (s) { return isUnder(host, s); });
    if (shortener) {
      add('link_shortener', 'medium', 20,
        'Shortened link: you cannot see where it really goes.',
        'छोटा किया हुआ लिंक: आप देख नहीं सकते कि यह असल में कहाँ जाता है।');
    }
    if (CHAT_INVITES.some(function (s) { return isUnder(host, s); })) {
      add('link_chat_invite', 'low', 15,
        'Chat-group invite link. Be careful if someone you do not know asks you to join.',
        'चैट ग्रुप का इनवाइट लिंक। अनजान व्यक्ति के कहने पर जुड़ने से बचें।');
    }
    var tld = labels[labels.length - 1];
    if (RISKY_TLDS.indexOf(tld) !== -1 && !shortener) {
      add('link_tld', 'medium', 20,
        'The link ends in ".' + tld + '", a cheap domain ending heavily abused for scams. Banks and government sites do not use it.',
        'लिंक ".' + tld + '" पर ख़त्म होता है, यह सस्ता डोमेन है जो ठगी में बहुत इस्तेमाल होता है। बैंक और सरकारी साइटें इसे नहीं अपनातीं।');
    }

    var brandHit = false;
    BRANDS.forEach(function (b) {
      if (brandHit) return;
      var has = b.strict ? tokens.indexOf(b.kw) !== -1 : host.indexOf(b.kw) !== -1;
      if (!has) return;
      var official = b.ok.some(function (d) { return isUnder(host, d); });
      if (!official) {
        brandHit = true;
        add('link_brand_lookalike', 'critical', 55,
          'The link mentions "' + b.name + '" but is NOT an official ' + b.name + ' address (' + b.ok[0] + ').',
          'लिंक में "' + b.name + '" का नाम है लेकिन यह ' + b.name + ' का आधिकारिक पता (' + b.ok[0] + ') नहीं है।');
      }
    });

    var govLike = tokens.indexOf('gov') !== -1 || tokens.indexOf('govt') !== -1 || tokens.indexOf('government') !== -1;
    if (!brandHit && govLike && !endsWithTld(host, 'gov.in') && !endsWithTld(host, 'nic.in')) {
      add('link_gov_lookalike', 'critical', 50,
        'Looks like a government site but does not end in .gov.in or .nic.in.',
        'सरकारी साइट जैसा दिखता है लेकिन .gov.in या .nic.in पर ख़त्म नहीं होता।');
    }

    if (u.protocol === 'http:') {
      add('link_http', 'low', 10,
        'The link uses plain http:// with no encryption.',
        'लिंक बिना एन्क्रिप्शन के सादे http:// पर है।');
    }
    if (labels.length >= 5) {
      add('link_subdomains', 'medium', 15,
        'The link has an unusually long chain of sub-domains, a trick to bury the real domain.',
        'लिंक में बहुत लंबी सब-डोमेन श्रृंखला है, असली डोमेन छुपाने की चाल।');
    }
    if ((host.match(/-/g) || []).length >= 3) {
      add('link_hyphens', 'low', 15,
        'The domain name is stuffed with hyphens, typical of throw-away scam sites.',
        'डोमेन नाम में बहुत सारे हाइफ़न हैं, जो फ़र्ज़ी साइटों की पहचान है।');
    }
    if (/\.apk(?:$|[?#])/i.test(u.path)) {
      add('link_apk', 'critical', 45,
        'The link downloads an .apk file directly.',
        'लिंक सीधे .apk फ़ाइल डाउनलोड कराता है।');
    }
    return out;
  }

  // ---- Helpers ------------------------------------------------------------
  function normalise(input) {
    var s = String(input == null ? '' : input);
    if (s.length > MAX_INPUT) s = s.slice(0, MAX_INPUT);
    try { s = s.normalize('NFKC'); } catch (e) { /* very old engines */ }
    return s.replace(/[​-‍⁠﻿]/g, '').replace(/\s+/g, ' ').trim();
  }

  var NEGATED = [
    /(?:please |kindly )?(?:do not|don't|dont|never)\s+(?:share|disclose|reveal|give|tell|send|forward)\b.{0,60}?(?:anyone|anybody|any one|others|third part\w+|\.|$)/gi,
    /(?:kisi\s*(?:ko|se)\s*)?(?:na|mat)\s+(?:batay\w*|bataiye|share|bhej\w*|dijiye)\b.{0,40}/gi,
    /किसी\s*(?:को|से)\s*(?:न|मत)\s*(?:बताएं|बताओ|दें|शेयर)[^.]{0,40}/g,
    /(?:never|not)\s+(?:ask|asks|asked)\s+(?:you\s+)?for\b.{0,40}/gi,
  ];

  function stripNegated(text) {
    var out = text;
    NEGATED.forEach(function (re) { out = out.replace(re, ' '); });
    return out;
  }

  function snippet(text, m) {
    var start = Math.max(0, m.index - 20);
    var end = Math.min(text.length, m.index + m[0].length + 20);
    var s = text.slice(start, end);
    return (start > 0 ? '…' : '') + s + (end < text.length ? '…' : '');
  }

  // ---- Public: analyze ----------------------------------------------------
  function analyze(input) {
    var text = normalise(input);
    var findings = [];
    var seen = {};

    if (!text) {
      return { score: 0, level: 'clean', findings: [], urls: [], empty: true, version: VERSION };
    }

    var negText = null;
    TEXT_RULES.forEach(function (r) {
      var hay = text;
      if (r.neg) { negText = negText === null ? stripNegated(text) : negText; hay = negText; }
      var m = r.re.exec(hay);
      if (m && !seen[r.id]) {
        seen[r.id] = true;
        findings.push({ id: r.id, cat: r.cat, sev: r.sev, w: r.w, evidence: snippet(hay, m), en: r.en, hi: r.hi });
      }
    });

    var urls = extractUrls(text);
    urls.slice(0, 10).forEach(function (u) {
      analyseUrl(u).forEach(function (f) {
        if (seen[f.id]) return;
        seen[f.id] = true;
        findings.push(f);
      });
    });

    // Combination bonuses: signals that are weak alone but strong together.
    var has = function (id) { return !!seen[id]; };
    var bonus = 0;
    var bonusFindings = [];
    function addBonus(id, w, en, hi) {
      bonus += w;
      bonusFindings.push({ id: id, cat: 'combo', sev: 'medium', w: w, evidence: '', en: en, hi: hi });
    }
    var lure = has('kyc_block') || has('account_block') || has('prize') || has('refund_bait') || has('delivery_scam') || has('utility_scare') || has('loan_bait');
    if (urls.length && lure) {
      addBonus('combo_link_lure', 15,
        'A link combined with a scare or reward is the standard phishing recipe.',
        'लिंक के साथ डर या इनाम का लालच, यही फ़िशिंग का मानक तरीका है।');
    }
    if (has('urgency') && (lure || has('otp_request') || has('authority_threat'))) {
      addBonus('combo_urgent_threat', 10,
        'Urgency plus a threat or credential request.',
        'जल्दबाज़ी के साथ धमकी या गोपनीय जानकारी की माँग।');
    }
    if (has('authority_threat') && (has('stay_on_call') || has('secrecy') || has('arrest_words'))) {
      addBonus('combo_authority_isolation', 15,
        'Fake-authority plus isolation tactics: the digital-arrest playbook.',
        'नकली अधिकारी + अलग-थलग करने की चाल: "डिजिटल अरेस्ट" की पूरी स्क्रिप्ट।');
    }
    findings = findings.concat(bonusFindings);

    var total = 0;
    var critical = false;
    findings.forEach(function (f) {
      total += f.w;
      if (f.sev === 'critical') critical = true;
    });
    var score = Math.min(100, Math.round(total));
    if (critical && score < 60) score = 60;

    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.w - a.w); });

    return { score: score, level: levelFor(score), findings: findings, urls: urls, empty: false, version: VERSION };
  }

  return { analyze: analyze, extractUrls: extractUrls, normalise: normalise, levelFor: levelFor, LEVELS: LEVELS, RULES: TEXT_RULES, VERSION: VERSION };
});
