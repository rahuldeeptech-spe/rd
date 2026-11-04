/* ScamCheck Wi-Fi & IoT auditor UI. Everything you paste stays in the browser. */
(function () {
  'use strict';

  var CFG = window.SCAMCHECK_CONFIG || {};
  var $ = function (id) { return document.getElementById(id); };

  var EXAMPLES = {"wifi": [{"label": ["Linux (nmcli): evil twin + WEP", "Linux (nmcli): evil twin + WEP"], "ssid": "HomeNet", "text": "IN-USE  BSSID              SSID          MODE   CHAN  RATE        SIGNAL  BARS  SECURITY\n*       AA:BB:CC:00:11:22  HomeNet       Infra  6     270 Mbit/s  82      ▂▄▆█  WPA2\n        AA:BB:CC:00:11:23  HomeNet       Infra  36    540 Mbit/s  70      ▂▄▆_  WPA2\n        DE:AD:BE:EF:00:01  HomeNet       Infra  6     54 Mbit/s   64      ▂▄▆_  --\n        11:22:33:44:55:66  CafeFreeWiFi  Infra  1     54 Mbit/s   55      ▂▄__  --\n        66:55:44:33:22:11  OldRouter     Infra  11    54 Mbit/s   40      ▂▄__  WEP\n        77:88:99:AA:BB:CC  Tenda_4F2A10  Infra  3     130 Mbit/s  35      ▂▄__  WPA1 WPA2\n        01:02:03:04:05:06  OfficeCorp    Infra  44    540 Mbit/s  30      ▂___  WPA2 802.1X\n        0A:0B:0C:0D:0E:0F  Modern        Infra  149   866 Mbit/s  28      ▂___  WPA3\n"}, {"label": ["Windows (netsh): old WEP router", "Windows (netsh): पुराना WEP राउटर"], "ssid": "OldRouter", "text": "Interface name : Wi-Fi\nThere are 4 networks currently visible.\n\nSSID 1 : HomeNet\n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP\n    BSSID 1                 : aa:bb:cc:00:11:22\n         Signal             : 88%\n         Radio type         : 802.11n\n         Channel            : 6\n    BSSID 2                 : aa:bb:cc:00:11:23\n         Signal             : 61%\n         Radio type         : 802.11ac\n         Channel            : 36\n\nSSID 2 : CafeFreeWiFi\n    Network type            : Infrastructure\n    Authentication          : Open\n    Encryption              : None\n    BSSID 1                 : 11:22:33:44:55:66\n         Signal             : 55%\n         Channel            : 1\n\nSSID 3 : OldRouter\n    Network type            : Infrastructure\n    Authentication          : Open\n    Encryption              : WEP\n    BSSID 1                 : 66:55:44:33:22:11\n         Signal             : 40%\n         Channel            : 11\n\nSSID 4 : Legacy\n    Network type            : Infrastructure\n    Authentication          : WPA-Personal\n    Encryption              : TKIP\n    BSSID 1                 : 77:88:99:aa:bb:cc\n         Signal             : 33%\n         Channel            : 3\n"}, {"label": ["Linux (iw): WPS on", "Linux (iw): WPS चालू"], "ssid": "HomeNet", "text": "BSS aa:bb:cc:00:11:22(on wlan0)\n\tlast seen: 1000.1s [boottime]\n\tTSF: 123 usec (0d, 00:00:00)\n\tfreq: 2437\n\tbeacon interval: 100 TUs\n\tcapability: ESS Privacy ShortSlotTime (0x0411)\n\tsignal: -45.00 dBm\n\tSSID: HomeNet\n\tSupported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0\n\tDS Parameter set: channel 6\n\tRSN:\t * Version: 1\n\t\t * Group cipher: CCMP\n\t\t * Pairwise ciphers: CCMP\n\t\t * Authentication suites: PSK\n\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)\n\tWPS:\t * Version: 1.0\n\t\t * Wi-Fi Protected Setup State: 2 (Configured)\n\t\t * Response Type: 3 (AP)\n\t\t * Config methods: Label, Display, Keypad\nBSS 66:55:44:33:22:11(on wlan0)\n\tcapability: ESS Privacy ShortSlotTime (0x0411)\n\tsignal: -70.00 dBm\n\tSSID: OldRouter\n\tDS Parameter set: channel 11\nBSS 11:22:33:44:55:66(on wlan0)\n\tcapability: ESS ShortSlotTime (0x0401)\n\tsignal: -60.00 dBm\n\tSSID: CafeFreeWiFi\n\tDS Parameter set: channel 1\nBSS 77:88:99:aa:bb:cc(on wlan0)\n\tcapability: ESS Privacy (0x0411)\n\tsignal: -80.00 dBm\n\tSSID: Mixed\n\tRSN:\t * Version: 1\n\t\t * Group cipher: TKIP\n\t\t * Pairwise ciphers: CCMP TKIP\n\t\t * Authentication suites: PSK\n\tWPA:\t * Version: 1\n\t\t * Group cipher: TKIP\n\t\t * Pairwise ciphers: TKIP CCMP\n\t\t * Authentication suites: PSK\nBSS 0a:0b:0c:0d:0e:0f(on wlan0)\n\tcapability: ESS Privacy (0x0411)\n\tsignal: -50.00 dBm\n\tSSID: Modern\n\tRSN:\t * Version: 1\n\t\t * Group cipher: CCMP\n\t\t * Pairwise ciphers: CCMP\n\t\t * Authentication suites: SAE\n"}], "nmap": [{"label": ["Smart-home LAN (real nmap output)", "स्मार्ट-होम LAN (असली nmap आउटपुट)"], "text": "# nmap -sV --script http-title,banner 192.168.1.0/24\nNmap scan report for 192.168.1.12\nHost is up (0.000018s latency).\n\nPORT     STATE  SERVICE    VERSION\n21/tcp   open   ftp        vsftpd 2.3.4\n|_banner: 220 (vsFTPd 2.3.4)\n\nNmap scan report for 192.168.1.13\nHost is up (0.0000030s latency).\n\nPORT     STATE  SERVICE    VERSION\n23/tcp   open   telnet     Linux telnetd\n| fingerprint-strings: \n|_banner: \\xFF\\xFD\\x18\\xFF\\xFD \\xFF\\xFD#\\xFF\\xFD'\\x0D\\x0Alogin:\n\nNmap scan report for 192.168.1.14\nHost is up (0.0000020s latency).\n\nPORT     STATE  SERVICE    VERSION\n22/tcp   open   ssh        Dropbear sshd 2014.65 (protocol 2.0)\n|_banner: SSH-2.0-dropbear_2014.65\n80/tcp   open   http       Boa/0.94.14rc21\n|_http-server-header: Boa/0.94.14rc21\n|_http-title: Network Camera Login\n| fingerprint-strings: \n554/tcp  open   rtsp\n| fingerprint-strings: \n2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :\n==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============\n\nNmap scan report for 192.168.1.15\nHost is up (0.0000020s latency).\n\nPORT     STATE  SERVICE    VERSION\n6379/tcp open   redis?\n| fingerprint-strings:\n\nNmap scan report for 192.168.1.16\nHost is up (0.000063s latency).\n\nBug in mqtt-subscribe: no string output.\nPORT     STATE  SERVICE    VERSION\n1883/tcp open   mqtt?\n5555/tcp open   freeciv?\n\nNmap scan report for 192.168.1.17\nHost is up (0.000011s latency).\n\nPORT     STATE  SERVICE    VERSION\n22/tcp   open   ssh        OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)\n|_banner: SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8\n80/tcp   open   http       lighttpd 1.4.35\n|_http-server-header: lighttpd/1.4.35\n|_http-title: Home Router Admin\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n# Nmap done at Wed Nov  4 13:38:59 2026 -- 7 IP addresses (7 hosts up) scanned in 15.36 seconds\n"}]};

  // questions: id -> [label EN, label HI, {option: [EN, HI]}]
  var Q = {
    security: ['Wi-Fi security type', 'Wi-Fi सिक्योरिटी का प्रकार', { open: ['No password (open)', 'पासवर्ड नहीं (ओपन)'], wep: ['WEP', 'WEP'], wpa: ['WPA / TKIP (version 1)', 'WPA / TKIP (वर्ज़न 1)'], wpa2: ['WPA2', 'WPA2'], wpa2wpa3: ['WPA2 + WPA3 (mixed)', 'WPA2 + WPA3 (मिक्स्ड)'], wpa3: ['WPA3', 'WPA3'], unknown: ["I don't know", 'पता नहीं'] }],
    cipher: ['WPA2 encryption cipher', 'WPA2 एन्क्रिप्शन सिफ़र', { aes: ['AES / CCMP', 'AES / CCMP'], tkip: ['TKIP', 'TKIP'], unknown: ["I don't know", 'पता नहीं'] }],
    wps: ['WPS (push-button / PIN setup)', 'WPS (पुश-बटन / PIN सेटअप)', { off: ['Off', 'बंद'], on: ['On', 'चालू'], unknown: ["I don't know", 'पता नहीं'] }],
    adminPassword: ['Router admin (login page) password', 'राउटर एडमिन (लॉगिन पेज) पासवर्ड', { changed: ['I changed it to a strong one', 'मैंने मज़बूत वाला रखा है'], default: ['Still the default (admin/admin or sticker)', 'अब भी डिफ़ॉल्ट (admin/admin या स्टिकर)'], unknown: ["I don't know", 'पता नहीं'] }],
    wifiPassword: ['Wi-Fi password', 'Wi-Fi पासवर्ड', { strong: ['14+ random characters or a passphrase', '14+ रैंडम अक्षर या पासफ़्रेज़'], medium: ['8 to 11 characters or a pattern', '8 से 11 अक्षर या कोई पैटर्न'], weak: ['Short or guessable (name, phone, 12345678)', 'छोटा या अनुमान लायक (नाम, फ़ोन, 12345678)'], sticker: ['Still the one printed on the router', 'अब भी राउटर पर छपा वाला'], unknown: ["I don't know", 'पता नहीं'] }],
    passwordRotated: ['Changed the Wi-Fi password after tenants, guests or staff left?', 'किरायेदार, मेहमान या स्टाफ़ जाने के बाद Wi-Fi पासवर्ड बदला?', { yes: ['Yes', 'हाँ'], no: ['No', 'नहीं'], unknown: ["I don't know", 'पता नहीं'] }],
    firmware: ['Router firmware updates', 'राउटर फ़र्मवेयर अपडेट', { auto: ['Automatic updates on', 'ऑटो-अपडेट चालू'], recent: ['Updated in the last year', 'पिछले साल में अपडेट हुआ'], old: ['1 to 3 years ago, or never checked', '1 से 3 साल पहले, या कभी नहीं देखा'], ancient: ['More than 3 years, or unsupported', '3 साल से ज़्यादा, या सपोर्ट बंद'], unknown: ["I don't know", 'पता नहीं'] }],
    routerAge: ['Router age', 'राउटर की उम्र', { new: ['Under 3 years', '3 साल से कम'], mid: ['3 to 5 years', '3 से 5 साल'], old: ['Over 5 years', '5 साल से ज़्यादा'], unknown: ["I don't know", 'पता नहीं'] }],
    remoteAdmin: ['Remote management from the internet', 'इंटरनेट से रिमोट मैनेजमेंट', { off: ['Off', 'बंद'], on: ['On', 'चालू'], unknown: ["I don't know", 'पता नहीं'] }],
    upnp: ['UPnP', 'UPnP', { off: ['Off', 'बंद'], on: ['On', 'चालू'], unknown: ["I don't know", 'पता नहीं'] }],
    portForward: ['Port forwarding / DMZ (cameras, DVR or NAS reachable from outside)', 'पोर्ट फ़ॉरवर्डिंग / DMZ (बाहर से कैमरा, DVR या NAS)', { no: ['No', 'नहीं'], yes: ['Yes', 'हाँ'], unknown: ["I don't know", 'पता नहीं'] }],
    iot: ['Smart devices still on default or weak passwords', 'स्मार्ट डिवाइस जो अब भी डिफ़ॉल्ट/कमज़ोर पासवर्ड पर हैं', { none: ['None, or no smart devices', 'कोई नहीं, या कोई स्मार्ट डिवाइस नहीं'], some: ['A few', 'कुछ'], many: ['Many', 'कई'], unknown: ["I don't know", 'पता नहीं'] }],
    iotSeparate: ['Smart devices on a separate guest / IoT network', 'स्मार्ट डिवाइस अलग गेस्ट / IoT नेटवर्क पर', { yes: ['Yes', 'हाँ'], no: ['No', 'नहीं'], unknown: ["I don't know", 'पता नहीं'] }],
    hiddenReliance: ['I rely on a hidden network name or MAC filtering', 'मैं छुपे नेटवर्क नाम या MAC फ़िल्टरिंग पर भरोसा करता हूँ', { no: ['No', 'नहीं'], yes: ['Yes', 'हाँ'] }],
  };

  var T = {
    en: {
      navMsg: 'Message checker', navApk: 'APK scanner', navMcp: 'MCP auditor', navPkg: 'Package detector', navWifi: 'Wi-Fi & IoT',
      title: 'Is your Wi-Fi and smart home safe?',
      subtitle: 'Three ways to audit your own network: a router checklist, the output of a Wi-Fi scan, or the output of an nmap scan of your devices.',
      privacy: '🔒 Everything is analysed in your browser. Nothing you paste is uploaded.',
      notice: 'Only audit networks and devices you own or have written permission to test.',
      aHeading: '1. Router checklist', aHelp: 'Answer what you know. "I don\'t know" is fine, but it counts as a small risk because you cannot fix what you have not checked.', auditRouter: 'Audit my router',
      bHeading: '2. Wi-Fi scan', bHelp: 'Run one of these on your laptop, paste the output, and enter your own Wi-Fi name to audit it. Supports nmcli, netsh, iw and airport.',
      wifiLabel: 'Wi-Fi scan output', ssidLabel: 'Your Wi-Fi name (SSID), optional but recommended', auditWifi: 'Audit Wi-Fi scan', clear: 'Clear', tryExamples: 'Try an example',
      cHeading: '3. Network scan (nmap)', cHelp: 'Scan only your own network, then paste the result. XML, grepable and normal output all work. Add --script http-title for device names.', nmapLabel: 'nmap output', auditNmap: 'Audit nmap output',
      whyHeading: 'Findings', whatToDo: 'What to do now', where: 'Where', fix: 'Fix',
      tipsHeading: 'Home network basics',
      donateHeading: 'Keep ScamCheck free',
      donateBody: 'This tool has no ads and no tracking. If it saved you or your family from a scam, a small contribution pays for development and hosting.',
      disclaimer: 'This tool reads what you paste. It does not scan anything itself. Results are rule-based and can miss problems or flag harmless setups. A clean result means "no known red flags", never proof of safety.',
      source: 'Open source (MIT)', payUpi: 'Pay with UPI', copyUpi: 'Copy UPI ID', copied: 'Copied!', upiNote: 'UPI ID: ',
      sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }, x: 'times',
      levels: {
        clean: ['No known red flags', 'Nothing alarming found. Keep firmware updated and re-check after changes.'],
        caution: ['A few things to tighten', 'No emergency, but there are weaknesses worth fixing.'],
        suspicious: ['Weak setup', 'Several weaknesses an attacker could use. Fix the top ones this week.'],
        likely: ['Dangerous setup', 'Serious problems. Fix these before anything else.'],
        scam: ['Critical: very exposed', 'Your network or devices are wide open. Fix the critical items now.'],
      },
      advice: [
        'Fix the Critical and High findings first. Each one has a "Fix" line.',
        'Change default passwords on the router and every smart device.',
        'Update router and device firmware, and replace anything the vendor no longer supports.',
        'Put smart devices on a guest/IoT network. Do not forward ports to cameras or NAS: use a VPN.',
        'Re-run the audit after you change settings.',
      ],
      adviceOk: ['Keep firmware updated.', 'Re-run this audit after any big change (new router, new camera).'],
      tips: [
        'Use WPA2-AES or WPA3 with a random passphrase of 14+ characters.',
        'Turn off WPS, UPnP and remote management unless you really need them.',
        'Change the router admin password. It is not the same as the Wi-Fi password.',
        'Keep cameras, TVs and plugs on a separate guest network, and never expose them with port forwarding.',
        'Update the router. If the maker stopped updates, replace it.',
      ],
      table: { wifi: 'Networks in the scan', nmap: 'Devices found', ssid: 'Name', sec: 'Security', ch: 'Channel', sig: 'Signal', host: 'Device', ports: 'Open ports', mine: 'yours', hidden: '(hidden)', wps: 'WPS' },
      secNames: { open: 'Open', wep: 'WEP', wpa: 'WPA', wpa2: 'WPA2', wpa3: 'WPA3', wpa2wpa3: 'WPA2/WPA3', enterprise: 'Enterprise', owe: 'OWE', unknown: '?' },
      summaryWifi: function (i) { return i.networks + ' network(s), format: ' + i.format + (i.scope === 'survey' ? '. Enter your own Wi-Fi name for a real audit; this is only a survey of the area.' : '. Auditing: ' + i.mySsid); },
      summaryNmap: function (i) { return i.hosts + ' device(s), ' + i.openPorts + ' open port(s), format: ' + i.format; },
      summaryChecklist: function () { return 'Based on your answers.'; },
      errors: {
        empty: 'Paste something first.', unrecognised: 'Could not recognise this output. Check the format against the commands shown above.',
        no_networks: 'No Wi-Fi networks were found in this output.', no_hosts: 'No hosts were found in this nmap output.',
        ssid_not_found: 'That Wi-Fi name was not found in the scan. Check the spelling (it is case-sensitive) or clear the box for a survey.',
        too_big: 'Input is larger than 3 MB.', other: 'Could not analyse this input.',
      },
    },
    hi: {
      navMsg: 'मैसेज चेकर', navApk: 'APK स्कैनर', navMcp: 'MCP ऑडिटर', navPkg: 'पैकेज डिटेक्टर', navWifi: 'Wi-Fi और IoT',
      title: 'क्या आपका Wi-Fi और स्मार्ट होम सुरक्षित है?',
      subtitle: 'अपने नेटवर्क को जाँचने के तीन तरीके: राउटर चेकलिस्ट, Wi-Fi स्कैन का आउटपुट, या अपने डिवाइस के nmap स्कैन का आउटपुट।',
      privacy: '🔒 सब कुछ आपके ब्राउज़र में ही जाँचा जाता है। आप जो पेस्ट करते हैं वह अपलोड नहीं होता।',
      notice: 'सिर्फ़ वही नेटवर्क और डिवाइस जाँचें जो आपके हैं या जिन्हें जाँचने की आपके पास लिखित अनुमति है।',
      aHeading: '1. राउटर चेकलिस्ट', aHelp: 'जो पता है वही बताएँ। "पता नहीं" चलेगा, पर उसे छोटा जोखिम गिना जाता है क्योंकि जो जाँचा नहीं उसे ठीक नहीं कर सकते।', auditRouter: 'मेरा राउटर जाँचें',
      bHeading: '2. Wi-Fi स्कैन', bHelp: 'इनमें से कोई एक अपने लैपटॉप पर चलाएँ, आउटपुट पेस्ट करें और अपने Wi-Fi का नाम लिखें। nmcli, netsh, iw और airport चलते हैं।',
      wifiLabel: 'Wi-Fi स्कैन आउटपुट', ssidLabel: 'आपके Wi-Fi का नाम (SSID), वैकल्पिक पर बेहतर', auditWifi: 'Wi-Fi स्कैन जाँचें', clear: 'साफ़ करें', tryExamples: 'उदाहरण आज़माएँ',
      cHeading: '3. नेटवर्क स्कैन (nmap)', cHelp: 'सिर्फ़ अपना नेटवर्क स्कैन करें, फिर नतीजा पेस्ट करें। XML, grepable और normal आउटपुट सब चलते हैं। डिवाइस के नाम के लिए --script http-title जोड़ें।', nmapLabel: 'nmap आउटपुट', auditNmap: 'nmap आउटपुट जाँचें',
      whyHeading: 'निष्कर्ष', whatToDo: 'अब क्या करें', where: 'कहाँ', fix: 'समाधान',
      tipsHeading: 'होम नेटवर्क की बुनियादी बातें',
      donateHeading: 'ScamCheck को मुफ़्त रखने में मदद करें',
      donateBody: 'इसमें न विज्ञापन हैं न ट्रैकिंग। अगर इसने आपको या आपके परिवार को ठगी से बचाया, तो छोटा सा सहयोग डेवलपमेंट और होस्टिंग का खर्च उठाने में मदद करता है।',
      disclaimer: 'यह टूल सिर्फ़ वही पढ़ता है जो आप पेस्ट करते हैं। यह खुद कुछ स्कैन नहीं करता। नतीजे नियम-आधारित हैं और समस्या चूक सकते हैं या बेज़रर सेटअप को भी चिह्नित कर सकते हैं। साफ़ नतीजे का मतलब "कोई जाना-पहचाना खतरा नहीं" है, सुरक्षा का सबूत नहीं।',
      source: 'ओपन सोर्स (MIT)', payUpi: 'UPI से दें', copyUpi: 'UPI ID कॉपी करें', copied: 'कॉपी हो गया!', upiNote: 'UPI ID: ',
      sev: { critical: 'गंभीर', high: 'ज़्यादा', medium: 'मध्यम', low: 'कम' }, x: 'बार',
      levels: {
        clean: ['कोई जाने-पहचाने खतरे नहीं', 'कुछ चिंताजनक नहीं मिला। फ़र्मवेयर अपडेट रखें और बदलाव के बाद दोबारा जाँचें।'],
        caution: ['कुछ चीज़ें कसनी हैं', 'कोई आपात स्थिति नहीं, पर कुछ कमज़ोरियाँ ठीक करने लायक हैं।'],
        suspicious: ['कमज़ोर सेटअप', 'कई कमज़ोरियाँ जिनका हमलावर फ़ायदा उठा सकता है। इसी हफ़्ते ऊपर वाली ठीक करें।'],
        likely: ['ख़तरनाक सेटअप', 'गंभीर समस्याएँ। सबसे पहले इन्हें ठीक करें।'],
        scam: ['गंभीर: बहुत खुला हुआ', 'आपका नेटवर्क या डिवाइस पूरी तरह खुले हैं। गंभीर मदें अभी ठीक करें।'],
      },
      advice: [
        'पहले Critical और High निष्कर्ष ठीक करें। हर एक में "समाधान" की लाइन है।',
        'राउटर और हर स्मार्ट डिवाइस के डिफ़ॉल्ट पासवर्ड बदलें।',
        'राउटर और डिवाइस का फ़र्मवेयर अपडेट करें, और जिसे वेंडर ने सपोर्ट देना बंद कर दिया उसे बदलें।',
        'स्मार्ट डिवाइस गेस्ट/IoT नेटवर्क पर रखें। कैमरे या NAS पर पोर्ट फ़ॉरवर्ड न करें: VPN इस्तेमाल करें।',
        'सेटिंग बदलने के बाद ऑडिट दोबारा चलाएँ।',
      ],
      adviceOk: ['फ़र्मवेयर अपडेट रखें।', 'कोई बड़ा बदलाव (नया राउटर, नया कैमरा) हो तो ऑडिट दोबारा चलाएँ।'],
      tips: [
        '14+ अक्षर के रैंडम पासफ़्रेज़ के साथ WPA2-AES या WPA3 इस्तेमाल करें।',
        'ज़रूरत न हो तो WPS, UPnP और रिमोट मैनेजमेंट बंद रखें।',
        'राउटर का एडमिन पासवर्ड बदलें। यह Wi-Fi पासवर्ड से अलग होता है।',
        'कैमरे, TV और प्लग अलग गेस्ट नेटवर्क पर रखें, और उन्हें पोर्ट फ़ॉरवर्ड से कभी खुला न छोड़ें।',
        'राउटर अपडेट करें। निर्माता ने अपडेट बंद कर दिए हों तो उसे बदलें।',
      ],
      table: { wifi: 'स्कैन में मिले नेटवर्क', nmap: 'मिले डिवाइस', ssid: 'नाम', sec: 'सिक्योरिटी', ch: 'चैनल', sig: 'सिग्नल', host: 'डिवाइस', ports: 'खुले पोर्ट', mine: 'आपका', hidden: '(छुपा)', wps: 'WPS' },
      secNames: { open: 'ओपन', wep: 'WEP', wpa: 'WPA', wpa2: 'WPA2', wpa3: 'WPA3', wpa2wpa3: 'WPA2/WPA3', enterprise: 'Enterprise', owe: 'OWE', unknown: '?' },
      summaryWifi: function (i) { return i.networks + ' नेटवर्क, फ़ॉर्मेट: ' + i.format + (i.scope === 'survey' ? '। असली ऑडिट के लिए अपने Wi-Fi का नाम लिखें; यह सिर्फ़ इलाके का सर्वे है।' : '। जाँच: ' + i.mySsid); },
      summaryNmap: function (i) { return i.hosts + ' डिवाइस, ' + i.openPorts + ' खुले पोर्ट, फ़ॉर्मेट: ' + i.format; },
      summaryChecklist: function () { return 'आपके जवाबों के आधार पर।'; },
      errors: {
        empty: 'पहले कुछ पेस्ट करें।', unrecognised: 'यह आउटपुट पहचाना नहीं गया। ऊपर दिखाई कमांड से फ़ॉर्मेट मिलाएँ।',
        no_networks: 'इस आउटपुट में कोई Wi-Fi नेटवर्क नहीं मिला।', no_hosts: 'इस nmap आउटपुट में कोई होस्ट नहीं मिला।',
        ssid_not_found: 'यह Wi-Fi नाम स्कैन में नहीं मिला। स्पेलिंग जाँचें (अक्षर बड़े-छोटे मायने रखते हैं) या सर्वे के लिए बॉक्स खाली करें।',
        too_big: 'इनपुट 3 MB से बड़ा है।', other: 'इस इनपुट की जाँच नहीं हो सकी।',
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
  function li() { return lang === 'hi' ? 1 : 0; }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function buildForm() {
    var form = $('checklist');
    var keep = {};
    Array.prototype.forEach.call(form.querySelectorAll('select'), function (s) { keep[s.name] = s.value; });
    form.textContent = '';
    window.WifiAudit.QUESTIONS.forEach(function (q) {
      var def = Q[q.id];
      if (!def) return;
      var row = el('div', 'qrow');
      var lab = el('label', 'qlabel', def[li()]);
      lab.setAttribute('for', 'q_' + q.id);
      var sel = el('select', 'qsel');
      sel.id = 'q_' + q.id;
      sel.name = q.id;
      q.options.forEach(function (o) {
        var op = el('option', null, def[2][o] ? def[2][o][li()] : o);
        op.value = o;
        sel.appendChild(op);
      });
      sel.value = keep[q.id] || q.def;
      row.appendChild(lab);
      row.appendChild(sel);
      form.appendChild(row);
    });
  }

  function applyStatic() {
    var s = t();
    document.documentElement.lang = lang;
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n]'), function (n) {
      var v = s[n.getAttribute('data-i18n')];
      if (typeof v === 'string') n.textContent = v;
    });
    Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === lang)); });
    var tips = $('tips'); tips.textContent = '';
    s.tips.forEach(function (x) { tips.appendChild(el('li', null, x)); });
    buildForm();
    var wc = $('wifiChips'); wc.textContent = '';
    EXAMPLES.wifi.forEach(function (ex) {
      var b = el('button', 'chip', ex.label[li()]);
      b.type = 'button';
      b.addEventListener('click', function () { $('wifiInput').value = ex.text; $('ssid').value = ex.ssid; runWifi(); });
      wc.appendChild(b);
    });
    var nc = $('nmapChips'); nc.textContent = '';
    EXAMPLES.nmap.forEach(function (ex) {
      var b = el('button', 'chip', ex.label[li()]);
      b.type = 'button';
      b.addEventListener('click', function () { $('nmapInput').value = ex.text; runNmap(); });
      nc.appendChild(b);
    });
    renderDonate();
    if (last) render(last);
  }

  function addCell(tr, text, cls) { tr.appendChild(el('td', cls || null, text)); }

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
    $('summary').textContent = i.kind === 'wifi-scan' ? s.summaryWifi(i) : i.kind === 'nmap' ? s.summaryNmap(i) : s.summaryChecklist();

    var list = $('findings');
    list.textContent = '';
    $('whyH').hidden = r.findings.length === 0;
    r.findings.forEach(function (f) {
      var item = el('li');
      item.setAttribute('data-sev', f.sev);
      item.appendChild(el('span', 'sev', (s.sev[f.sev] || f.sev) + (f.count > 1 ? ' · ' + f.count + ' ' + s.x : '')));
      item.appendChild(el('p', null, f[lang] || f.en));
      if (f.where && f.where.length) item.appendChild(el('p', 'small', s.where + ': ' + f.where.join(', ')));
      if (f.evidence) item.appendChild(el('code', null, f.evidence));
      var fix = lang === 'hi' ? f.fixHi : f.fixEn;
      if (fix) { var p = el('p', 'fixline'); p.appendChild(el('strong', null, s.fix + ': ')); p.appendChild(document.createTextNode(fix)); item.appendChild(p); }
      list.appendChild(item);
    });

    var tb = $('tableBox');
    var tbl = $('tbl');
    tbl.textContent = '';
    if (i.kind === 'wifi-scan') {
      tb.hidden = false;
      $('tableH').textContent = s.table.wifi;
      var head = el('tr');
      [s.table.ssid, s.table.sec, s.table.ch, s.table.sig, s.table.wps].forEach(function (h) { head.appendChild(el('th', null, h)); });
      tbl.appendChild(head);
      i.list.slice(0, 60).forEach(function (n) {
        var tr = el('tr', n.mine ? 'mine' : null);
        addCell(tr, (n.ssid || s.table.hidden) + (n.mine ? ' · ' + s.table.mine : ''));
        addCell(tr, s.secNames[n.security] || n.security, n.security === 'open' || n.security === 'wep' || n.security === 'wpa' ? 'bad' : '');
        addCell(tr, n.channel || '');
        addCell(tr, n.signal || '');
        addCell(tr, n.wps ? 'WPS' : '', n.wps ? 'bad' : '');
        tbl.appendChild(tr);
      });
    } else if (i.kind === 'nmap') {
      tb.hidden = false;
      $('tableH').textContent = s.table.nmap;
      var head2 = el('tr');
      [s.table.host, s.table.ports].forEach(function (h) { head2.appendChild(el('th', null, h)); });
      tbl.appendChild(head2);
      i.list.slice(0, 80).forEach(function (h) {
        var tr = el('tr');
        addCell(tr, h.ip + (h.hostname ? ' (' + h.hostname + ')' : '') + (h.vendor ? ' · ' + h.vendor : ''), 'mono');
        addCell(tr, h.open.map(function (p) { return p.port + '/' + p.service; }).join('  ') || '-', 'mono');
        tbl.appendChild(tr);
      });
    } else tb.hidden = true;

    var act = $('actions');
    act.textContent = '';
    act.appendChild(el('h3', null, s.whatToDo));
    var ul = el('ul');
    (r.score >= 20 ? s.advice : s.adviceOk).forEach(function (x) { ul.appendChild(el('li', null, x)); });
    act.appendChild(ul);
  }

  function show(r) {
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

  function runChecklist() {
    var ans = {};
    Array.prototype.forEach.call($('checklist').querySelectorAll('select'), function (s) { ans[s.name] = s.value; });
    try { show(window.WifiAudit.auditChecklist(ans)); } catch (e) { showError(e && e.code ? e.code : 'other'); }
  }
  function runWifi() {
    try { show(window.WifiAudit.auditWifiScan($('wifiInput').value, { ssid: $('ssid').value })); } catch (e) { showError(e && e.code ? e.code : 'other'); }
  }
  function runNmap() {
    try { show(window.WifiAudit.auditNmap($('nmapInput').value)); } catch (e) { showError(e && e.code ? e.code : 'other'); }
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

  $('runChecklist').addEventListener('click', runChecklist);
  $('runWifi').addEventListener('click', runWifi);
  $('runNmap').addEventListener('click', runNmap);
  $('clearWifi').addEventListener('click', function () { $('wifiInput').value = ''; $('ssid').value = ''; last = null; $('result').hidden = true; $('errorBox').hidden = true; });
  $('clearNmap').addEventListener('click', function () { $('nmapInput').value = ''; last = null; $('result').hidden = true; $('errorBox').hidden = true; });
  Array.prototype.forEach.call(document.querySelectorAll('.lang button'), function (b) {
    b.addEventListener('click', function () {
      lang = b.getAttribute('data-lang');
      try { localStorage.setItem('scamcheck-lang', lang); } catch (e) { /* ignore */ }
      applyStatic();
    });
  });

  var repo = typeof CFG.repoUrl === 'string' && safeHttps(CFG.repoUrl);
  if (repo) $('repoLink').href = repo;
  $('ver').textContent = 'v' + window.WifiAudit.VERSION;
  applyStatic();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('sw.js').catch(function () {});
  }
})();
