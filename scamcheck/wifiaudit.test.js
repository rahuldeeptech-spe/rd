'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const W = require('./wifiaudit.js');

const ids = (r) => r.findings.map((f) => f.id);
const code = (fn) => { try { fn(); return 'ok'; } catch (e) { return e.code || 'UNCODED:' + e.message; } };
const data = (f) => fs.readFileSync(path.join(__dirname, 'testdata', f), 'utf8');

// ---- hand-written samples that follow the documented output of each tool ----------------------
const NMCLI = `IN-USE  BSSID              SSID          MODE   CHAN  RATE        SIGNAL  BARS  SECURITY
*       AA:BB:CC:00:11:22  HomeNet       Infra  6     270 Mbit/s  82      ▂▄▆█  WPA2
        AA:BB:CC:00:11:23  HomeNet       Infra  36    540 Mbit/s  70      ▂▄▆_  WPA2
        DE:AD:BE:EF:00:01  HomeNet       Infra  6     54 Mbit/s   64      ▂▄▆_  --
        11:22:33:44:55:66  CafeFreeWiFi  Infra  1     54 Mbit/s   55      ▂▄__  --
        66:55:44:33:22:11  OldRouter     Infra  11    54 Mbit/s   40      ▂▄__  WEP
        77:88:99:AA:BB:CC  Tenda_4F2A10  Infra  3     130 Mbit/s  35      ▂▄__  WPA1 WPA2
        01:02:03:04:05:06  OfficeCorp    Infra  44    540 Mbit/s  30      ▂___  WPA2 802.1X
        0A:0B:0C:0D:0E:0F  Modern        Infra  149   866 Mbit/s  28      ▂___  WPA3
`;

const NETSH = `Interface name : Wi-Fi
There are 4 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:11:22
         Signal             : 88%
         Radio type         : 802.11n
         Channel            : 6
    BSSID 2                 : aa:bb:cc:00:11:23
         Signal             : 61%
         Radio type         : 802.11ac
         Channel            : 36

SSID 2 : CafeFreeWiFi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 55%
         Channel            : 1

SSID 3 : OldRouter
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : WEP
    BSSID 1                 : 66:55:44:33:22:11
         Signal             : 40%
         Channel            : 11

SSID 4 : Legacy
    Network type            : Infrastructure
    Authentication          : WPA-Personal
    Encryption              : TKIP
    BSSID 1                 : 77:88:99:aa:bb:cc
         Signal             : 33%
         Channel            : 3
`;

const IW = `BSS aa:bb:cc:00:11:22(on wlan0)
\tlast seen: 1000.1s [boottime]
\tTSF: 123 usec (0d, 00:00:00)
\tfreq: 2437
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -45.00 dBm
\tSSID: HomeNet
\tSupported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)
\t\t * Response Type: 3 (AP)
\t\t * Config methods: Label, Display, Keypad
BSS 66:55:44:33:22:11(on wlan0)
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -70.00 dBm
\tSSID: OldRouter
\tDS Parameter set: channel 11
BSS 11:22:33:44:55:66(on wlan0)
\tcapability: ESS ShortSlotTime (0x0401)
\tsignal: -60.00 dBm
\tSSID: CafeFreeWiFi
\tDS Parameter set: channel 1
BSS 77:88:99:aa:bb:cc(on wlan0)
\tcapability: ESS Privacy (0x0411)
\tsignal: -80.00 dBm
\tSSID: Mixed
\tRSN:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: CCMP TKIP
\t\t * Authentication suites: PSK
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP CCMP
\t\t * Authentication suites: PSK
BSS 0a:0b:0c:0d:0e:0f(on wlan0)
\tcapability: ESS Privacy (0x0411)
\tsignal: -50.00 dBm
\tSSID: Modern
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
`;

const AIRPORT = `                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                         HomeNet aa:bb:cc:00:11:22 -45  6       Y  -- WPA2(PSK/AES/AES)
                    CafeFreeWiFi 11:22:33:44:55:66 -60  1       Y  -- NONE
                       OldRouter 66:55:44:33:22:11 -70  11      N  -- WEP
                          Legacy 77:88:99:aa:bb:cc -80  3       Y  -- WPA(PSK/TKIP/TKIP)
                          Modern 0a:0b:0c:0d:0e:0f -50  149     Y  -- WPA3(SAE/AES/AES)
                           Mixed 01:02:03:04:05:06 -55  11      Y  -- WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/AES)
`;

// ------------------------------------------------------------------------------------------------
test('checklist: a hardened setup is clean', () => {
  const r = W.auditChecklist({ security: 'wpa3', cipher: 'aes', wps: 'off', adminPassword: 'changed', wifiPassword: 'strong', passwordRotated: 'yes', firmware: 'auto', routerAge: 'new', remoteAdmin: 'off', upnp: 'off', portForward: 'no', iot: 'none', iotSeparate: 'yes', hiddenReliance: 'no' });
  assert.equal(r.level, 'clean');
  assert.equal(r.score, 0);
  assert.deepEqual(ids(r), []);
});

test('checklist: every risky answer triggers its own finding, and the worst setup is a 100', () => {
  const worst = { security: 'wep', wps: 'on', adminPassword: 'default', wifiPassword: 'weak', passwordRotated: 'no', firmware: 'ancient', routerAge: 'old', remoteAdmin: 'on', upnp: 'on', portForward: 'yes', iot: 'many', iotSeparate: 'no', hiddenReliance: 'yes' };
  const r = W.auditChecklist(worst);
  for (const id of ['cl_wep', 'cl_wps', 'cl_admin_default', 'cl_wifi_weak', 'cl_not_rotated', 'cl_fw_ancient', 'cl_router_old', 'cl_remote_admin', 'cl_upnp', 'cl_port_forward', 'cl_iot_many', 'cl_iot_same_net', 'cl_hidden']) assert.ok(ids(r).includes(id), id);
  assert.equal(r.score, 100);
  assert.equal(r.level, 'scam');
  assert.equal(W.auditChecklist({ security: 'open' }).findings[0].id, 'cl_open');
  assert.ok(W.auditChecklist({ security: 'open' }).score >= 60);
  assert.ok(ids(W.auditChecklist({ security: 'wpa' })).includes('cl_wpa1'));
  assert.ok(ids(W.auditChecklist({ security: 'wpa2', cipher: 'tkip' })).includes('cl_tkip'));
  assert.ok(!ids(W.auditChecklist({ security: 'wpa3', cipher: 'tkip' })).includes('cl_tkip'));
  assert.ok(ids(W.auditChecklist({ iot: 'none', iotSeparate: 'no' })).every((i) => i !== 'cl_iot_same_net'));
});

test('checklist: unknown and garbage input is coerced safely; "do not know" is not free', () => {
  for (const bad of [undefined, null, 'x', 5, [], { security: 'nope', wps: 42 }]) {
    const r = W.auditChecklist(bad);
    assert.ok(r.score >= 0 && r.score <= 100);
  }
  const r = W.auditChecklist({});
  assert.ok(r.score > 0 && ids(r).includes('cl_admin_unknown'));
  assert.ok(r.score <= 40 && ['caution', 'suspicious'].includes(r.level), 'knowing nothing is a nudge, not an alarm: ' + r.score);
  assert.ok(W.auditChecklist({}).score < W.auditChecklist({ adminPassword: 'default' }).score);
  assert.equal(r.info.answers.security, 'unknown');
  assert.ok(Array.isArray(W.QUESTIONS) && W.QUESTIONS.length >= 12);
});

test('Wi-Fi scan: all four formats are recognised and normalised the same way', () => {
  const nm = W.parseWifiScan(NMCLI);
  assert.equal(nm.format, 'nmcli');
  assert.equal(nm.networks.length, 8);
  const sec = (res, ssid) => res.networks.filter((n) => n.ssid === ssid).map((n) => n.security);
  assert.deepEqual(sec(nm, 'HomeNet'), ['wpa2', 'wpa2', 'open']);
  assert.deepEqual(sec(nm, 'OldRouter'), ['wep']);
  assert.deepEqual(sec(nm, 'Modern'), ['wpa3']);
  assert.deepEqual(sec(nm, 'OfficeCorp'), ['enterprise']);
  assert.equal(nm.networks.find((n) => n.ssid === 'Tenda_4F2A10').legacyWpa, true);
  assert.equal(nm.networks[0].channel, '6');

  const ns = W.parseWifiScan(NETSH);
  assert.equal(ns.format, 'netsh');
  assert.equal(ns.networks.length, 5);
  assert.deepEqual(sec(ns, 'HomeNet'), ['wpa2', 'wpa2']);
  assert.deepEqual(sec(ns, 'CafeFreeWiFi'), ['open']);
  assert.deepEqual(sec(ns, 'OldRouter'), ['wep']);
  assert.deepEqual(sec(ns, 'Legacy'), ['wpa']);
  assert.equal(ns.networks.find((n) => n.ssid === 'Legacy').cipher, 'tkip');

  const iw = W.parseWifiScan(IW);
  assert.equal(iw.format, 'iw');
  assert.equal(iw.networks.length, 5);
  assert.deepEqual(sec(iw, 'HomeNet'), ['wpa2']);
  assert.equal(iw.networks[0].wps, true);
  assert.deepEqual(sec(iw, 'OldRouter'), ['wep']);
  assert.deepEqual(sec(iw, 'CafeFreeWiFi'), ['open']);
  const mixed = iw.networks.find((n) => n.ssid === 'Mixed');
  assert.equal(mixed.security, 'wpa2');
  assert.equal(mixed.legacyWpa, true);
  assert.equal(mixed.tkipAllowed, true);
  assert.deepEqual(sec(iw, 'Modern'), ['wpa3']);
  assert.equal(iw.networks[0].channel, '6');

  const ap = W.parseWifiScan(AIRPORT);
  assert.equal(ap.format, 'airport');
  assert.equal(ap.networks.length, 6);
  assert.deepEqual(sec(ap, 'HomeNet'), ['wpa2']);
  assert.deepEqual(sec(ap, 'CafeFreeWiFi'), ['open']);
  assert.deepEqual(sec(ap, 'OldRouter'), ['wep']);
  assert.deepEqual(sec(ap, 'Legacy'), ['wpa']);
  assert.deepEqual(sec(ap, 'Modern'), ['wpa3']);
  assert.equal(ap.networks.find((n) => n.ssid === 'Mixed').legacyWpa, true);
});

test('Wi-Fi scan: auditing "my network" finds its real problems', () => {
  const open = W.auditWifiScan(NMCLI, { ssid: 'CafeFreeWiFi' });
  assert.ok(ids(open).includes('wf_open'));
  assert.ok(open.score >= 60);
  assert.equal(open.info.scope, 'mine');

  const wep = W.auditWifiScan(NETSH, { ssid: 'OldRouter' });
  assert.ok(ids(wep).includes('wf_wep') && wep.score >= 60);

  const wpa1 = W.auditWifiScan(NETSH, { ssid: 'Legacy' });
  assert.ok(ids(wpa1).includes('wf_wpa1'));

  const wps = W.auditWifiScan(IW, { ssid: 'HomeNet' });
  assert.ok(ids(wps).includes('wf_wps'));

  const mixed = W.auditWifiScan(IW, { ssid: 'Mixed' });
  assert.ok(ids(mixed).includes('wf_wpa1_fallback') && ids(mixed).includes('wf_tkip'));

  const good = W.auditWifiScan(IW, { ssid: 'Modern' });
  assert.deepEqual(ids(good), []);
  assert.equal(good.level, 'clean');
  const brand = W.auditWifiScan(NMCLI, { ssid: 'Tenda_4F2A10' });
  assert.ok(ids(brand).includes('wf_default_name'));
});

test('Wi-Fi scan: evil twin, mesh and OWE-transition cases', () => {
  // HomeNet is broadcast with WPA2 and also as an open copy
  const twin = W.auditWifiScan(NMCLI, { ssid: 'HomeNet' });
  assert.ok(ids(twin).includes('wf_evil_twin'));
  assert.equal(twin.findings.find((f) => f.id === 'wf_evil_twin').sev, 'critical');
  assert.ok(twin.score >= 60);
  // a normal dual-band mesh with WPA2 + WPA2/WPA3 is not a twin
  const mesh = `IN-USE  BSSID              SSID    MODE   CHAN  RATE        SIGNAL  BARS  SECURITY
*       AA:BB:CC:00:11:22  Mesh    Infra  6     270 Mbit/s  82      ▂▄▆█  WPA2
        AA:BB:CC:00:11:23  Mesh    Infra  36    540 Mbit/s  70      ▂▄▆_  WPA2 WPA3
        AA:BB:CC:00:11:24  Mesh    Infra  149   866 Mbit/s  60      ▂▄▆_  WPA3
`;
  assert.deepEqual(ids(W.auditWifiScan(mesh, { ssid: 'Mesh' })), []);
  const owe = `IN-USE  BSSID              SSID    MODE   CHAN  RATE        SIGNAL  BARS  SECURITY
        AA:BB:CC:00:11:22  Guest   Infra  6     270 Mbit/s  82      ▂▄▆█  --
        AA:BB:CC:00:11:23  Guest   Infra  6     270 Mbit/s  82      ▂▄▆█  OWE
`;
  assert.ok(!ids(W.auditWifiScan(owe, { ssid: 'Guest' })).includes('wf_evil_twin'));
  // old repeater on WEP next to a strong AP of the same name
  const rep = `IN-USE  BSSID              SSID    MODE   CHAN  RATE        SIGNAL  BARS  SECURITY
        AA:BB:CC:00:11:22  Home    Infra  6     270 Mbit/s  82      ▂▄▆█  WPA2
        AA:BB:CC:00:11:23  Home    Infra  6     54 Mbit/s   50      ▂▄▆_  WEP
`;
  assert.ok(ids(W.auditWifiScan(rep, { ssid: 'Home' })).includes('wf_security_mismatch'));
});

test('Wi-Fi scan: without a network name it is a half-weight survey, and cannot be a "critical 60"', () => {
  const r = W.auditWifiScan(NMCLI);
  assert.equal(r.info.scope, 'survey');
  assert.ok(r.score <= 39 && r.level === 'caution', String(r.score) + ' ' + r.level);
  assert.ok(ids(r).includes('wf_wep') && ids(r).includes('wf_open_public'));
  assert.equal(r.info.networks, 8);
  assert.equal(r.info.counts.wep, 1);
  assert.equal(r.info.list.length, 8);
});

test('nmap: the three real output formats give the same findings', () => {
  const xml = W.auditNmap(data('nmap-lan.xml'));
  const gnmap = W.auditNmap(data('nmap-lan.gnmap'));
  const normal = W.auditNmap(data('nmap-lan.nmap'));
  assert.equal(xml.info.format, 'xml');
  assert.equal(gnmap.info.format, 'grepable');
  assert.equal(normal.info.format, 'normal');
  for (const r of [xml, gnmap, normal]) {
    assert.equal(r.info.hosts, 7);
    assert.equal(r.info.openPorts, 11);
    for (const id of ['net_vsftpd_backdoor', 'net_telnet', 'net_adb', 'net_boa', 'net_camera_stream', 'net_db_unauth', 'net_old_software', 'net_ftp', 'net_mqtt']) assert.ok(ids(r).includes(id), `${r.info.format} missing ${id}`);
    assert.equal(r.level, 'scam');
  }
  // closed ports are listed by nmap but must never be reported
  assert.ok(!xml.findings.some((f) => f.where.some((w) => w.startsWith('127.0.0.1:21'))));
  assert.deepEqual(xml.findings.find((f) => f.id === 'net_telnet').where, ['127.0.0.3:23/tcp']);
  assert.deepEqual(xml.findings.find((f) => f.id === 'net_adb').where, ['127.0.0.6:5555/tcp']);
  // grepable output has no http-title script, XML and normal do
  assert.ok(ids(xml).includes('net_camera_device') && ids(normal).includes('net_camera_device') && !ids(gnmap).includes('net_camera_device'));
  const host4 = xml.info.list.find((h) => h.ip === '127.0.0.4');
  assert.deepEqual(host4.open.map((p) => p.port), [22, 80, 554]);
});

test('nmap: parsing details (entities, grepable "|" in versions, down hosts, MAC vendor, OS)', () => {
  const xml = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TP-Link &amp; Co"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Boa httpd" version="0.94.14rc21"/><script id="http-title" output="IP Camera &quot;Login&quot;"/></port>
<port protocol="udp" portid="1900"><state state="open"/><service name="upnp" product="MiniUPnP" version="1.6"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="6.6.1p1"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port></ports>
<os><osmatch name="Microsoft Windows XP SP3" accuracy="95"/></os>
<hostscript><script id="smb-protocols" output="dialects: NT LM 0.12 (SMBv1)"/></hostscript></host>
<host><status state="down"/><address addr="192.168.1.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host></nmaprun>`;
  const r = W.auditNmap(xml);
  assert.equal(r.info.hosts, 1, 'a host that is down must be ignored');
  assert.ok(!ids(r).includes('net_telnet'));
  for (const id of ['net_boa', 'net_upnp', 'net_old_software', 'net_camera_device', 'net_smb1', 'net_eol_os']) assert.ok(ids(r).includes(id), id);
  assert.equal(r.info.list[0].mac, 'AA:BB:CC:DD:EE:FF');
  assert.equal(r.info.list[0].vendor, 'TP-Link & Co');
  assert.equal(r.info.list[0].hostname, 'router.lan');

  const g = `# Nmap 7.94 scan initiated
Host: 10.0.0.5 (cam.lan)\tStatus: Up
Host: 10.0.0.5 (cam.lan)\tPorts: 80/open/tcp//http//Boa|0.94.14rc21/, 554/open/tcp//rtsp///, 23/closed/tcp//telnet///, 5555/open/tcp//freeciv?///\tIgnored State: filtered (990)
# Nmap done`;
  const gr = W.auditNmap(g);
  assert.equal(gr.info.format, 'grepable');
  assert.deepEqual(gr.info.list[0].open.map((p) => p.port), [80, 554, 5555]);
  assert.ok(ids(gr).includes('net_boa') && ids(gr).includes('net_adb') && !ids(gr).includes('net_telnet'));
});

test('nmap: script-based findings (vulners, VULNERABLE, anonymous FTP, default credentials, old TLS)', () => {
  const n = `Nmap scan report for nas.lan (192.168.1.20)
Host is up.
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     ProFTPD 1.3.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 ftp ftp 12 backup.txt
80/tcp   open  http    Apache httpd 2.2.22
| vulners:
|   cpe:/a:apache:http_server:2.2.22:
|     CVE-2017-7679  7.5  https://vulners.com/cve/CVE-2017-7679
|_http-title: NAS Login
443/tcp  open  ssl/https nginx
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|_      TLS_RSA_WITH_RC4_128_SHA - broken
2222/tcp open  ssh     OpenSSH 5.3 (protocol 2.0)
| ssh-brute:
|   Accounts:
|     admin:admin - Valid credentials
|_  Statistics: Performed 5 guesses
MAC Address: 00:11:22:33:44:55 (Synology)
`;
  const r = W.auditNmap(n);
  assert.equal(r.info.format, 'normal');
  for (const id of ['net_ftp_anon', 'net_known_cves', 'net_old_software', 'net_ssl_old', 'net_default_creds']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  assert.equal(r.info.list[0].mac, '00:11:22:33:44:55');
  assert.ok(r.score >= 80);
  const v = W.auditNmap('Nmap scan report for 10.0.0.2\nPORT STATE SERVICE\n445/tcp open microsoft-ds\n| smb-vuln-ms17-010:\n|   VULNERABLE:\n|_    Remote Code Execution vulnerability in Microsoft SMBv1');
  assert.ok(ids(v).includes('net_vuln') && ids(v).includes('net_smb'));
});

test('nmap: databases, RDP, VNC, TR-069 and many ports', () => {
  const ports = (list) => 'Nmap scan report for 10.0.0.9\nPORT STATE SERVICE\n' + list.map(([p, s]) => `${p}/tcp open ${s}`).join('\n');
  const r = W.auditNmap(ports([[3389, 'ms-wbt-server'], [5900, 'vnc'], [7547, 'unknown'], [27017, 'mongodb'], [3306, 'mysql'], [445, 'microsoft-ds']]));
  for (const id of ['net_rdp', 'net_vnc', 'net_tr069', 'net_db_unauth', 'net_db', 'net_smb']) assert.ok(ids(r).includes(id), id);
  const many = W.auditNmap(ports(Array.from({ length: 20 }, (_, i) => [1000 + i, 'unknown'])));
  assert.ok(ids(many).includes('net_many_ports'));
  const clean = W.auditNmap(ports([[22, 'ssh'], [443, 'https']]));
  assert.ok(clean.score < 20);
});

test('every finding has English, Hindi and a fix; ids are unique', () => {
  const results = [
    W.auditChecklist({ security: 'wep', wps: 'on', adminPassword: 'default', wifiPassword: 'weak', firmware: 'ancient', remoteAdmin: 'on', upnp: 'on', portForward: 'yes', iot: 'many', iotSeparate: 'no', hiddenReliance: 'yes', passwordRotated: 'no', routerAge: 'old' }),
    W.auditWifiScan(NMCLI, { ssid: 'HomeNet' }), W.auditWifiScan(IW, { ssid: 'Mixed' }), W.auditWifiScan(NETSH), W.auditNmap(data('nmap-lan.xml')),
  ];
  for (const r of results) {
    const seen = new Set();
    assert.ok(r.findings.length > 0);
    for (const f of r.findings) {
      assert.ok(f.en.length > 10 && f.hi.length > 10 && f.fixEn.length > 5 && f.fixHi.length > 5, f.id);
      assert.ok(['critical', 'high', 'medium', 'low'].includes(f.sev), f.id);
      assert.ok(!seen.has(f.id), 'duplicate ' + f.id);
      seen.add(f.id);
    }
    assert.ok(r.score >= 0 && r.score <= 100);
  }
});

test('error codes for bad input', () => {
  assert.equal(code(() => W.auditWifiScan('')), 'empty');
  assert.equal(code(() => W.auditNmap('   ')), 'empty');
  assert.equal(code(() => W.auditWifiScan('hello world, not a scan')), 'unrecognised');
  assert.equal(code(() => W.auditNmap('hello world, not nmap')), 'unrecognised');
  assert.equal(code(() => W.auditWifiScan(NMCLI, { ssid: 'DoesNotExist' })), 'ssid_not_found');
  assert.equal(code(() => W.auditNmap('<nmaprun></nmaprun>')), 'no_hosts');
  assert.equal(code(() => W.auditNmap('Nmap scan report for x\n')), 'ok');
  assert.equal(code(() => W.auditWifiScan('x'.repeat(W.MAX_INPUT + 1))), 'too_big');
  assert.equal(code(() => W.auditNmap('x'.repeat(W.MAX_INPUT + 1))), 'too_big');
});

test('fuzz: corrupted real outputs and random text never throw uncoded errors', () => {
  const sources = [NMCLI, NETSH, IW, AIRPORT, data('nmap-lan.xml'), data('nmap-lan.gnmap'), data('nmap-lan.nmap')];
  let seed = 777;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const junk = ['\u0000', '<', '>', '"', '&', '/', '|', '\t', '\n', '::', '%', '‮', '\ud83d'];
  for (let i = 0; i < 1500; i++) {
    let s = sources[i % sources.length];
    for (let k = 0, n = 1 + Math.floor(rnd() * 12); k < n; k++) {
      const pos = Math.floor(rnd() * s.length);
      const op = rnd();
      if (op < 0.4) s = s.slice(0, pos) + junk[Math.floor(rnd() * junk.length)] + s.slice(pos + 1);
      else if (op < 0.7) s = s.slice(0, pos) + s.slice(pos + 1 + Math.floor(rnd() * 30));
      else s = s.slice(0, pos) + s.slice(Math.floor(rnd() * s.length));
    }
    for (const fn of [() => W.auditWifiScan(s), () => W.auditWifiScan(s, { ssid: 'HomeNet' }), () => W.auditNmap(s)]) {
      const c = code(fn);
      assert.ok(!c.startsWith('UNCODED'), c + ' on iteration ' + i);
    }
  }
});

test('hostile inputs finish quickly (ReDoS and size guards)', () => {
  const nasty = [
    'Nmap scan report for ' + 'a'.repeat(300000), '<host><address ' + 'a="b" '.repeat(80000), '<host>' + '<port protocol="tcp" portid="1">'.repeat(50000),
    'Host: 1.2.3.4 ()\tPorts: ' + '1/open/tcp//x///, '.repeat(100000), 'BSS 00:11:22:33:44:55 ' + '\n\tRSN:'.repeat(100000),
    'SSID 1 : x\n' + 'BSSID 1 : y\n'.repeat(100000), 'IN-USE BSSID SSID SECURITY\n' + ' '.repeat(500000),
    '1/tcp open ' + 'x '.repeat(200000), '|'.repeat(300000), '&#'.repeat(100000),
  ];
  for (const t of nasty) {
    const t0 = Date.now();
    for (const fn of [() => W.auditNmap(t), () => W.auditWifiScan(t)]) {
      const c = code(fn);
      assert.ok(!c.startsWith('UNCODED'), c);
    }
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0}ms for ${t.slice(0, 25)}`);
  }
});
