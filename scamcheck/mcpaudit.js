/*
 * mcpaudit: offline security audit of MCP (Model Context Protocol) configs and tool definitions.
 * No network, no dependencies. Works in the browser (window.McpAudit) and in Node.
 *
 * Input is JSON (comments and trailing commas allowed): an MCP client config
 * (claude_desktop_config.json, .mcp.json, Cursor / VS Code / Zed / Gemini / Cline style) and/or
 * a tools/list response with tool definitions. Findings are heuristics, not proof.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.McpAudit = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_INPUT = 1000000;
  var MAX_NODES = 20000;

  // ---- helpers ------------------------------------------------------------
  function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
  function arr(x) { return Array.isArray(x) ? x : []; }
  function str(x) { return typeof x === 'string' ? x : (typeof x === 'number' || typeof x === 'boolean' ? String(x) : ''); }
  function fail(code, msg, extra) { var e = new Error(msg); e.code = code; if (extra) e.detail = extra; return e; }

  // JSON with comments and trailing commas (VS Code / Zed style).
  function parseJsonc(text) {
    var out = '';
    var i = 0;
    var n = text.length;
    var inStr = false;
    while (i < n) {
      var c = text[i];
      if (inStr) {
        out += c;
        if (c === '\\' && i + 1 < n) { out += text[i + 1]; i += 2; continue; }
        if (c === '"') inStr = false;
        i++;
      } else if (c === '"') { inStr = true; out += c; i++; }
      else if (c === '/' && text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; }
      else if (c === '/' && text[i + 1] === '*') { i += 2; while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; }
      else { out += c; i++; }
    }
    // trailing commas outside strings
    var res = '';
    inStr = false;
    for (var k = 0; k < out.length; k++) {
      var ch = out[k];
      if (inStr) {
        res += ch;
        if (ch === '\\' && k + 1 < out.length) { res += out[k + 1]; k++; continue; }
        if (ch === '"') inStr = false;
      } else if (ch === '"') { inStr = true; res += ch; }
      else if (ch === ',') {
        var j = k + 1;
        while (j < out.length && /\s/.test(out[j])) j++;
        if (out[j] === '}' || out[j] === ']') continue;
        res += ch;
      } else res += ch;
    }
    return JSON.parse(res);
  }

  function lev(a, b) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > 3) return 4;
    var prev = [];
    var i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function mask(s) {
    s = String(s);
    if (s.length <= 8) return s.slice(0, 2) + '…';
    return s.slice(0, 4) + '…' + s.slice(-2) + ' (' + s.length + ' chars)';
  }

  // ---- finding collection -------------------------------------------------
  function Collector() {
    this.list = [];
  }
  Collector.prototype.add = function (id, sev, w, where, evidence, en, hi, fixEn, fixHi) {
    this.list.push({ id: id, sev: sev, w: w, where: where || '', evidence: evidence || '', en: en, hi: hi, fixEn: fixEn || '', fixHi: fixHi || '' });
  };
  Collector.prototype.merged = function () {
    var by = {};
    var order = [];
    this.list.forEach(function (f) {
      var m = by[f.id];
      if (!m) {
        m = by[f.id] = { id: f.id, cat: 'mcp', sev: f.sev, w: f.w, count: 0, where: [], evidence: f.evidence, en: f.en, hi: f.hi, fixEn: f.fixEn, fixHi: f.fixHi };
        order.push(f.id);
      }
      m.count++;
      if (f.where && m.where.indexOf(f.where) === -1 && m.where.length < 12) m.where.push(f.where);
    });
    return order.map(function (id) {
      var m = by[id];
      m.w = m.w + Math.min(15, 5 * (m.count - 1));
      return m;
    });
  };

  // ---- config analysis ----------------------------------------------------
  var OFFICIAL = [
    'server-filesystem', 'server-github', 'server-gitlab', 'server-postgres', 'server-sqlite', 'server-puppeteer',
    'server-brave-search', 'server-google-maps', 'server-memory', 'server-slack', 'server-sequential-thinking',
    'server-everything', 'server-fetch', 'server-redis', 'server-sentry', 'server-gdrive', 'server-everart',
    'server-aws-kb-retrieval', 'server-time', 'server-git',
  ].map(function (n) { return '@modelcontextprotocol/' + n; }).concat(['mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite']);
  var OFFICIAL_SCOPES = ['@modelcontextprotocol', '@anthropic-ai'];

  var SECRET_PATTERNS = [
    [/sk-ant-[A-Za-z0-9_-]{20,}/, 'Anthropic API key'],
    [/sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/, 'OpenAI-style API key'],
    [/github_pat_[A-Za-z0-9_]{40,}/, 'GitHub token'],
    [/gh[pousr]_[A-Za-z0-9]{30,}/, 'GitHub token'],
    [/glpat-[A-Za-z0-9_-]{20,}/, 'GitLab token'],
    [/\bA(?:KIA|SIA)[0-9A-Z]{16}\b/, 'AWS access key'],
    [/xox[abprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
    [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
    [/sbp_[a-f0-9]{40}/, 'Supabase token'],
    [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, 'JWT'],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  ];
  var SECRET_KEY_RE = /token|secret|passw(?:or)?d|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key/i;
  var PLACEHOLDER_RE = /^\$\{?[A-Za-z_]|^\$\{(?:env|input|secret|vault):|^<.*>$|^\{\{.*\}\}$|^%[A-Za-z_]+%$|^(?:your|my)[-_ ]|^x{3,}$|^\*+$|example|placeholder|replace|changeme|^todo$/i;

  function secretIn(value) {
    var v = str(value);
    if (!v) return null;
    for (var i = 0; i < SECRET_PATTERNS.length; i++) {
      var m = SECRET_PATTERNS[i][0].exec(v);
      if (m) return { kind: SECRET_PATTERNS[i][1], value: m[0] };
    }
    return null;
  }

  function isLiteralSecret(key, value) {
    var v = str(value).trim();
    if (v.length < 12 || PLACEHOLDER_RE.test(v)) return false;
    return SECRET_KEY_RE.test(key);
  }

  function pkgName(spec) {
    // strip version: "@scope/name@1.2.3" or "name@1.2.3"
    var s = str(spec);
    var at = s.indexOf('@', 1);
    var name = at === -1 ? s : s.slice(0, at);
    var version = at === -1 ? '' : s.slice(at + 1);
    return { name: name, version: version };
  }

  function firstPositional(args, skipWithValue) {
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (typeof a !== 'string') continue;
      if (a.charAt(0) === '-') { if (skipWithValue && skipWithValue.indexOf(a) !== -1) i++; continue; }
      return { value: a, index: i };
    }
    return null;
  }

  var SHELLS = ['sh', 'bash', 'zsh', 'dash', 'fish', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'];
  var WRAP_OK = ['npx', 'uvx', 'uv', 'node', 'python', 'python3', 'bunx', 'bun', 'pnpm', 'deno', 'docker', 'npx.cmd'];

  function analyseServer(name, cfg, C) {
    if (!isObj(cfg)) return;
    var where = 'server:' + name;
    var cmdRaw = cfg.command;
    var args = arr(cfg.args);
    var env = isObj(cfg.env) ? cfg.env : {};
    if (isObj(cmdRaw)) { // Zed style {path, args, env}
      args = arr(cmdRaw.args).length ? arr(cmdRaw.args) : args;
      if (isObj(cmdRaw.env)) env = cmdRaw.env;
      cmdRaw = cmdRaw.path;
    }
    var cmd = str(cmdRaw);
    var base = cmd.split(/[\\/]/).pop().toLowerCase();
    var argv = args.slice(0, 200).map(function (a) { return str(a).slice(0, 1000); });
    cmd = cmd.slice(0, 1000);
    var joined = argv.join(' ').slice(0, 6000);
    var full = (cmd + ' ' + joined).trim().slice(0, 6000);

    // 1. remote script execution / encoded commands
    if (/(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&]*(?:\||;|&&)\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i.test(full) ||
        /\|\s*(?:iex|invoke-expression)\b/i.test(full) || /(?:^|\s)-(?:enc|encodedcommand)\b/i.test(full)) {
      C.add('mcp_remote_exec', 'critical', 45, where, full.slice(0, 120),
        'Downloads and runs code in one step (curl | sh, iex, or an encoded command). Whoever controls that URL controls your machine.',
        'कोड डाउनलोड करके सीधे चलाता है (curl | sh, iex या encoded कमांड)। उस URL का मालिक आपकी मशीन का मालिक बन जाता है।',
        'Install a pinned version first, review it, then point "command" at the installed binary.',
        'पहले पिन किया हुआ वर्ज़न इंस्टॉल करें, जाँचें, फिर "command" को इंस्टॉल हुए बाइनरी पर सेट करें।');
    }

    // 2. shell wrappers
    if (SHELLS.indexOf(base) !== -1 && argv.some(function (a) { return /^(?:-c|\/c|\/k|-command|-lc)$/i.test(a); })) {
      var innerIdx = -1;
      argv.forEach(function (a, i) { if (innerIdx === -1 && /^(?:-c|\/c|\/k|-command|-lc)$/i.test(a)) innerIdx = i; });
      var inner = str(argv[innerIdx + 1]).trim().split(/\s+/)[0].toLowerCase().split(/[\\/]/).pop();
      if (WRAP_OK.indexOf(inner) !== -1 && argv.length <= innerIdx + 12 && !/[;&|`$()<>]/.test(argv.slice(innerIdx + 1).join(' '))) {
        // plain "cmd /c npx ..." wrapper, common on Windows
      } else {
        C.add('mcp_shell_wrapper', 'medium', 20, where, (cmd + ' ' + joined).slice(0, 120),
          'Runs through a shell with a command string. Shell strings are hard to audit and easy to inject into.',
          'शेल के ज़रिए कमांड स्ट्रिंग चलाता है। शेल स्ट्रिंग की जाँच कठिन है और उसमें इंजेक्शन आसान।',
          'Call the program directly: set "command" to the executable and put each argument in "args".',
          '"command" में सीधे प्रोग्राम रखें और हर आर्ग्युमेंट "args" में अलग से दें।');
      }
    }

    // 3. package execution without a pinned version
    var runner = base.replace(/\.cmd$|\.exe$/, '');
    var pkgSpec = null;
    if (runner === 'npx' || runner === 'bunx') pkgSpec = firstPositional(argv, ['-p', '--package', '--registry', '-c']);
    else if (runner === 'uvx') pkgSpec = firstPositional(argv, ['--from', '--python', '-p', '--with', '--index', '--index-url']);
    else if (runner === 'pnpm' && argv[0] === 'dlx') pkgSpec = firstPositional(argv.slice(1));
    else if (runner === 'pipx' && argv[0] === 'run') pkgSpec = firstPositional(argv.slice(1), ['--spec', '--python']);
    else if (runner === 'bun' && argv[0] === 'x') pkgSpec = firstPositional(argv.slice(1));
    else if (runner === 'deno' && argv[0] === 'run') pkgSpec = firstPositional(argv.slice(1), ['--allow-net', '--allow-read']);

    if (pkgSpec) {
      var spec = pkgSpec.value;
      var isGit = /^(?:git\+|github:|gitlab:|bitbucket:|https?:\/\/|git@|file:|\.{0,2}\/|~\/)/.test(spec) || /\bgit\+https?:\/\//.test(joined);
      if (/^(?:git\+|github:|gitlab:|bitbucket:|https?:\/\/|git@)/.test(spec) || /(?:^|\s)--from(?:=|\s)(?:git\+|https?:\/\/)/.test(joined)) {
        C.add('mcp_git_package', 'high', 30, where, spec.slice(0, 100),
          'Runs code straight from a git repository or URL. There is no registry review, and the branch can change under you.',
          'सीधे git रिपॉज़िटरी या URL से कोड चलाता है। कोई रजिस्ट्री रिव्यू नहीं, और ब्रांच कभी भी बदल सकती है।',
          'Pin to a full commit hash, or publish/consume a versioned package from a registry you trust.',
          'पूरे commit hash पर पिन करें, या भरोसेमंद रजिस्ट्री का वर्ज़न वाला पैकेज इस्तेमाल करें।');
      } else if (!isGit) {
        var p = pkgName(spec);
        var pinned = p.version && !/^(?:latest|next|beta|canary|\*|x)$/i.test(p.version);
        if (runner === 'uvx' || runner === 'pipx') pinned = /==|@\d/.test(spec);
        var official = OFFICIAL.indexOf(p.name) !== -1;
        if (!pinned) {
          C.add('mcp_unpinned', 'medium', official ? 15 : 25, where, spec,
            'Runs "' + p.name + '" without a pinned version. Every launch fetches whatever is newest, so a compromised release runs on your machine automatically.',
            '"' + p.name + '" बिना पिन किए वर्ज़न के चलता है। हर बार सबसे नया वर्ज़न आता है, इसलिए कोई ख़राब रिलीज़ अपने-आप आपकी मशीन पर चल जाती है।',
            'Pin an exact version (e.g. ' + p.name + '@1.2.3) and update it deliberately.',
            'सटीक वर्ज़न पिन करें (जैसे ' + p.name + '@1.2.3) और अपडेट सोच-समझकर करें।');
        }
        // typosquatting
        if (!official && p.name.length > 8) {
          var near = null;
          OFFICIAL.forEach(function (o) { var d = lev(p.name.toLowerCase(), o); if (d > 0 && d <= 2 && !near) near = o; });
          var scope = p.name.charAt(0) === '@' ? p.name.split('/')[0].toLowerCase() : '';
          var scopeNear = null;
          if (scope) OFFICIAL_SCOPES.forEach(function (s) { if (scope !== s && lev(scope, s) <= 2) scopeNear = s; });
          if (scope === '@anthropic' || scope === '@modelcontextprotocols' || scope === '@model-context-protocol') scopeNear = scopeNear || (scope === '@anthropic' ? '@anthropic-ai' : '@modelcontextprotocol');
          if (near || scopeNear) {
            C.add('mcp_typosquat', 'critical', 50, where, p.name,
              'The package name looks like an official one (' + (near || scopeNear) + ') but is not. Typosquatted MCP packages are used to steal tokens and files.',
              'पैकेज का नाम आधिकारिक (' + (near || scopeNear) + ') जैसा दिखता है पर है नहीं। नकली नाम वाले MCP पैकेज टोकन और फ़ाइलें चुराने के लिए इस्तेमाल होते हैं।',
              'Check the exact spelling and publisher on the registry page before running it. Remove it if unsure.',
              'चलाने से पहले रजिस्ट्री पेज पर सही स्पेलिंग और प्रकाशक जाँचें। शक हो तो हटा दें।');
          }
        }
      }
    }

    // 4. docker
    if (runner === 'docker' || runner === 'podman') {
      var di = argv.indexOf('run');
      if (di !== -1) {
        var dargs = argv.slice(di + 1);
        var VALUE_FLAGS = ['-e', '--env', '-v', '--volume', '-p', '--publish', '--name', '-w', '--workdir', '--network', '--net', '-u', '--user',
          '--entrypoint', '--env-file', '-l', '--label', '--cap-add', '--cap-drop', '--mount', '--memory', '-m', '--cpus', '--platform', '--add-host', '--security-opt', '--pid', '--device'];
        var img = firstPositional(dargs, VALUE_FLAGS);
        if (img) {
          var ref = img.value;
          var hasDigest = ref.indexOf('@sha256:') !== -1;
          var tag = ref.indexOf(':', ref.lastIndexOf('/') + 1) !== -1 ? ref.slice(ref.lastIndexOf(':') + 1) : '';
          if (!hasDigest && (!tag || tag === 'latest')) {
            C.add('mcp_docker_unpinned', 'medium', 20, where, ref,
              'Docker image has no version tag or digest, so it silently follows "latest".',
              'Docker इमेज पर कोई वर्ज़न टैग या digest नहीं है, इसलिए वह चुपचाप "latest" को फ़ॉलो करती है।',
              'Pin a version tag, ideally an @sha256 digest.', 'वर्ज़न टैग, बेहतर हो तो @sha256 digest, पिन करें।');
          }
        }
        var dj = dargs.join(' ');
        if (/--privileged\b/.test(dj) || /docker\.sock/.test(dj) || /(?:^|\s)(?:-v|--volume)(?:=|\s)\/(?::|\s|$)/.test(dj) || /--pid[= ]host\b/.test(dj)) {
          C.add('mcp_docker_escape', 'critical', 45, where, dj.slice(0, 120),
            'The container is privileged, mounts the Docker socket, shares the host PID namespace or mounts "/". A compromised server can take over the host.',
            'कंटेनर privileged है, Docker socket माउंट करता है, होस्ट PID शेयर करता है या "/" माउंट करता है। ख़राब सर्वर पूरे होस्ट पर क़ब्ज़ा कर सकता है।',
            'Drop --privileged, never mount docker.sock, and mount only the one project folder (read-only if possible).',
            '--privileged हटाएँ, docker.sock कभी माउंट न करें, और सिर्फ़ एक प्रोजेक्ट फ़ोल्डर (हो सके तो read-only) माउंट करें।');
        } else if (/(?:-v|--volume|--mount)(?:=|\s)(?:\$HOME|~|\/Users\/[^/:\s]+|\/home\/[^/:\s]+|C:\\Users\\[^\\:\s]+)(?::|\s|,|$)/i.test(dj)) {
          C.add('mcp_docker_home', 'high', 25, where, dj.slice(0, 120),
            'Mounts your whole home folder into the container, including SSH keys and cloud credentials.',
            'पूरा होम फ़ोल्डर कंटेनर में माउंट करता है, जिसमें SSH कुंजियाँ और क्लाउड क्रेडेंशियल भी हैं।',
            'Mount only the specific project folder.', 'सिर्फ़ ज़रूरी प्रोजेक्ट फ़ोल्डर माउंट करें।');
        }
        if (/--(?:network|net)(?:=|\s)host\b/.test(dj)) {
          C.add('mcp_docker_hostnet', 'medium', 15, where, '--network host',
            'Host networking lets the container reach every local service (databases, admin panels).',
            'Host नेटवर्किंग से कंटेनर हर लोकल सर्विस (डेटाबेस, एडमिन पैनल) तक पहुँच सकता है।',
            'Use the default bridge network and publish only the ports you need.', 'डिफ़ॉल्ट bridge नेटवर्क रखें और सिर्फ़ ज़रूरी पोर्ट खोलें।');
        }
      }
    }

    // 5. dangerous flags
    var flag = /(?:^|\s)(--[a-z-]*(?:dangerously|skip-permissions|disable-auth|no-auth|insecure|allow-all|unsafe|no-sandbox|disable-web-security)[a-z-]*)/i.exec(' ' + joined);
    if (flag) {
      C.add('mcp_danger_flag', 'high', 30, where, flag[1],
        'A flag that disables a safety check (' + flag[1] + ').',
        'ऐसा फ़्लैग जो सुरक्षा जाँच बंद करता है (' + flag[1] + ')।',
        'Remove the flag, or limit it to a throw-away sandbox.', 'फ़्लैग हटाएँ, या उसे सिर्फ़ फेंक देने लायक सैंडबॉक्स तक सीमित रखें।');
    }

    // 6. binding to all interfaces
    if (/(?:--host|--bind|--listen|-h)(?:=|\s)(?:0\.0\.0\.0|::)(?:\s|$|:)/.test(' ' + joined + ' ') || /\b0\.0\.0\.0:\d+/.test(joined)) {
      C.add('mcp_bind_all', 'high', 35, where, joined.slice(0, 100),
        'Listens on 0.0.0.0, so anyone on your network (cafe Wi-Fi, office LAN) can call the server and its tools.',
        '0.0.0.0 पर सुनता है, इसलिए आपके नेटवर्क (कैफ़े Wi-Fi, ऑफ़िस LAN) का कोई भी इसके टूल कॉल कर सकता है।',
        'Bind to 127.0.0.1 and add authentication if remote access is truly needed.',
        '127.0.0.1 पर बाइंड करें, और रिमोट एक्सेस सच में ज़रूरी हो तो ऑथेंटिकेशन जोड़ें।');
    }

    // 7. over-broad filesystem access
    var looksFs = /filesystem|file-?system|\bfs\b/i.test(full);
    var broad = argv.filter(function (a) {
      return /^(?:\/|~|\$HOME|%USERPROFILE%|[A-Za-z]:[\\/]?|\/(?:Users|home)\/[^/\\]+\/?|\/etc\/?|\/root\/?|\/var\/?|C:\\Users\\[^\\]+\\?)$/.test(a);
    });
    if (looksFs && broad.length) {
      C.add('mcp_fs_broad', 'high', 35, where, broad.join(' '),
        'The file server is given a root or your whole home folder. The model (and any prompt injection) can read SSH keys, browser data and .env files.',
        'फ़ाइल सर्वर को रूट या पूरा होम फ़ोल्डर दिया गया है। मॉडल (और कोई भी प्रॉम्प्ट इंजेक्शन) SSH कुंजियाँ, ब्राउज़र डेटा और .env फ़ाइलें पढ़ सकता है।',
        'Allow only the specific project folders you want the assistant to touch.', 'सिर्फ़ वही प्रोजेक्ट फ़ोल्डर दें जिन्हें असिस्टेंट को छूने देना है।');
    }

    // 8. suspicious script locations
    if (argv.concat([cmd]).some(function (a) { return /^(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|%TEMP%|C:\\Windows\\Temp|.*[\\/]Downloads[\\/]).+/i.test(a) && /\.(?:js|mjs|py|sh|exe|bat|ps1|jar)$/i.test(a); })) {
      C.add('mcp_temp_path', 'medium', 25, where, joined.slice(0, 100),
        'Runs a script from a temp or Downloads folder, which anyone or anything can overwrite.',
        'temp या Downloads फ़ोल्डर की स्क्रिप्ट चलाता है, जिसे कोई भी बदल सकता है।',
        'Move the server to a protected folder you control.', 'सर्वर को अपने नियंत्रण वाले सुरक्षित फ़ोल्डर में रखें।');
    }

    // 9. secrets in env / args / headers / url
    var secretHits = [];
    Object.keys(env).forEach(function (k) {
      var v = str(env[k]);
      var s = secretIn(v);
      if (s) secretHits.push(k + '=' + mask(s.value) + ' [' + s.kind + ']');
      else if (isLiteralSecret(k, v)) secretHits.push(k + '=' + mask(v));
    });
    var hdrs = isObj(cfg.headers) ? cfg.headers : {};
    Object.keys(hdrs).forEach(function (k) {
      var v = str(hdrs[k]).replace(/^(?:Bearer|Basic|Token)\s+/i, '');
      var s = secretIn(v);
      if (s) secretHits.push('header ' + k + ': ' + mask(s.value) + ' [' + s.kind + ']');
      else if (/authorization|api[-_]?key|token|secret/i.test(k) && v.length >= 12 && !PLACEHOLDER_RE.test(v)) secretHits.push('header ' + k + ': ' + mask(v));
    });
    argv.forEach(function (a, i) {
      var s = secretIn(a);
      if (s) { secretHits.push('arg: ' + mask(s.value) + ' [' + s.kind + ']'); return; }
      var m = /^--?(?:token|api[-_]?key|password|secret|auth[-_]?token|access[-_]?token)(?:=(.+))?$/i.exec(a);
      if (m) {
        var val = m[1] != null ? m[1] : str(argv[i + 1]);
        if (val.length >= 8 && !PLACEHOLDER_RE.test(val)) secretHits.push('arg ' + a.split('=')[0] + ': ' + mask(val));
      }
    });
    if (secretHits.length) {
      C.add('mcp_secret', 'critical', 40, where, secretHits.slice(0, 3).join('; '),
        'A real-looking secret is written directly in the config. These files get synced, committed, screenshotted and backed up.',
        'कॉन्फ़िग में सीधे असली जैसा सीक्रेट लिखा है। ऐसी फ़ाइलें सिंक, commit, स्क्रीनशॉट और बैकअप हो जाती हैं।',
        'Rotate the secret now, then reference an environment variable or the client\'s secret/input mechanism instead.',
        'सीक्रेट अभी रोटेट करें, फिर उसकी जगह environment variable या क्लाइंट का secret/input तरीका इस्तेमाल करें।');
    }

    // 10. remote servers
    var urlRaw = str(cfg.url || cfg.serverUrl || cfg.httpUrl || cfg.endpoint);
    if (urlRaw) {
      var u = null;
      try { u = new URL(urlRaw); } catch (e) { u = null; }
      if (u) {
        var host = u.hostname.toLowerCase();
        var local = host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1' || /\.localhost$/.test(host);
        if (u.protocol === 'http:' && !local) {
          C.add('mcp_http', 'high', 30, where, urlRaw.slice(0, 100),
            'Connects to a remote server over plain http. Tool calls, data and tokens travel unencrypted and can be read or changed on the way.',
            'रिमोट सर्वर से सादे http पर जुड़ता है। टूल कॉल, डेटा और टोकन बिना एन्क्रिप्शन के जाते हैं और रास्ते में पढ़े या बदले जा सकते हैं।',
            'Use https:// only.', 'सिर्फ़ https:// इस्तेमाल करें।');
        }
        if (host === '0.0.0.0') {
          C.add('mcp_bind_all', 'high', 35, where, urlRaw.slice(0, 100),
            'Points at 0.0.0.0, a server exposed on all network interfaces.', '0.0.0.0 की ओर इशारा करता है, यानी सर्वर सभी नेटवर्क इंटरफ़ेस पर खुला है।',
            'Use 127.0.0.1 for local servers.', 'लोकल सर्वर के लिए 127.0.0.1 इस्तेमाल करें।');
        }
        if (/(?:ngrok|trycloudflare\.com|loca\.lt|serveo\.net|localtunnel|ngrok-free\.app|lhr\.life)/.test(host)) {
          C.add('mcp_tunnel', 'medium', 20, where, host,
            'Points at a temporary public tunnel. You cannot tell who runs the other end, and the address can be reassigned to someone else.',
            'अस्थायी पब्लिक टनल की ओर इशारा करता है। दूसरी तरफ़ कौन है पता नहीं, और पता किसी और को भी मिल सकता है।',
            'Use a stable, authenticated endpoint you control or trust.', 'अपना या भरोसेमंद, स्थिर और ऑथेंटिकेटेड endpoint इस्तेमाल करें।');
        }
        if (u.username || u.password || /[?&](?:token|api[_-]?key|apikey|access_token|key|secret|auth)=[^&]{8,}/i.test(u.search)) {
          C.add('mcp_url_secret', 'high', 35, where, mask(urlRaw),
            'A credential is embedded in the URL. URLs end up in logs, proxies and history.',
            'URL में क्रेडेंशियल जुड़ा है। URL लॉग, प्रॉक्सी और हिस्ट्री में रह जाते हैं।',
            'Send credentials in an Authorization header taken from an environment variable.',
            'क्रेडेंशियल environment variable से लिए गए Authorization header में भेजें।');
        }
      }
    }

    // 11. per-server auto-approval
    var aa = cfg.alwaysAllow || cfg.autoApprove || cfg.auto_approve;
    if (cfg.trust === true) {
      C.add('mcp_trust', 'high', 30, where, 'trust: true',
        'Marks the server as fully trusted, so its tool calls run without any confirmation prompt.',
        'सर्वर को पूरी तरह भरोसेमंद मार्क करता है, इसलिए उसके टूल कॉल बिना किसी पुष्टि के चलते हैं।',
        'Remove "trust" and approve sensitive tools one by one.', '"trust" हटाएँ और संवेदनशील टूल एक-एक करके मंज़ूर करें।');
    } else if (aa === true || (Array.isArray(aa) && aa.some(function (t) { return str(t) === '*' || /write|delete|remove|exec|run|shell|command|bash|send|post|deploy|install|drop|update|push/i.test(str(t)); }))) {
      C.add('mcp_auto_approve', 'medium', 25, where, Array.isArray(aa) ? aa.map(str).slice(0, 6).join(', ') : 'all tools',
        'Auto-approves tools that can change or send things. A prompt injection can then act without you seeing it.',
        'ऐसे टूल ऑटो-अप्रूव करता है जो कुछ बदल या भेज सकते हैं। प्रॉम्प्ट इंजेक्शन तब आपको दिखे बिना काम कर सकता है।',
        'Auto-approve only read-only tools.', 'सिर्फ़ read-only टूल ही ऑटो-अप्रूव करें।');
    }
  }

  function looksLikeServer(x) {
    return isObj(x) && (typeof x.command === 'string' || isObj(x.command) || typeof x.url === 'string' || typeof x.serverUrl === 'string' || typeof x.httpUrl === 'string');
  }

  function collectServers(rootObj) {
    var out = [];
    var seen = 0;
    function addMap(m, prefix) {
      Object.keys(m).forEach(function (k) {
        if (out.length < 200 && isObj(m[k])) out.push({ name: (prefix ? prefix + ' > ' : '') + k, cfg: m[k] });
      });
    }
    function walk(node, depth, parentKey) {
      if (!isObj(node) || depth > 6 || seen++ > MAX_NODES) return;
      Object.keys(node).forEach(function (k) {
        var v = node[k];
        if (!isObj(v)) return;
        if (k === 'mcpServers' || k === 'mcp_servers' || k === 'context_servers') addMap(v, '');
        else if (k === 'servers' && (depth === 0 || parentKey === 'mcp') && Object.keys(v).some(function (x) { return looksLikeServer(v[x]); })) addMap(v, '');
        else walk(v, depth + 1, k);
      });
    }
    if (looksLikeServer(rootObj)) { out.push({ name: 'server', cfg: rootObj }); return out; }
    walk(rootObj, 0, '');
    if (!out.length && isObj(rootObj)) {
      var keys = Object.keys(rootObj);
      if (keys.length && keys.every(function (k) { return looksLikeServer(rootObj[k]); })) addMap(rootObj, '');
    }
    return out;
  }

  function analyseSettings(rootObj, C) {
    var seen = 0;
    (function walk(node, depth) {
      if (!isObj(node) || depth > 6 || seen++ > MAX_NODES) return;
      Object.keys(node).forEach(function (k) {
        var v = node[k];
        if (k === 'enableAllProjectMcpServers' && v === true) {
          C.add('mcp_trust_project', 'high', 35, 'settings', 'enableAllProjectMcpServers: true',
            'Automatically trusts every MCP server declared by a project. A cloned repository can then start programs on your machine the moment you open it.',
            'हर प्रोजेक्ट में घोषित MCP सर्वर पर अपने-आप भरोसा करता है। क्लोन की हुई रिपॉज़िटरी खोलते ही आपकी मशीन पर प्रोग्राम शुरू कर सकती है।',
            'Turn it off and approve each project server after reading its command.', 'इसे बंद करें और हर प्रोजेक्ट सर्वर की कमांड पढ़कर ही मंज़ूर करें।');
        } else if (k === 'defaultMode' && v === 'bypassPermissions') {
          C.add('mcp_bypass', 'critical', 45, 'settings', 'defaultMode: bypassPermissions',
            'All permission prompts are switched off. Any prompt injection can run commands and edit files unseen.',
            'सारे परमिशन प्रॉम्प्ट बंद हैं। कोई भी प्रॉम्प्ट इंजेक्शन बिना दिखे कमांड चला और फ़ाइलें बदल सकता है।',
            'Use the default mode, and use bypass only inside a disposable container.', 'डिफ़ॉल्ट मोड रखें; bypass सिर्फ़ फेंक देने लायक कंटेनर में इस्तेमाल करें।');
        } else if ((k === 'dangerouslySkipPermissions' || k === 'skipPermissions' || k === 'yolo' || k === 'yoloMode') && v === true) {
          C.add('mcp_bypass', 'critical', 45, 'settings', k + ': true',
            'All permission prompts are switched off.', 'सारे परमिशन प्रॉम्प्ट बंद हैं।', 'Turn it off.', 'इसे बंद करें।');
        } else if (k === 'allow' && Array.isArray(v) && v.some(function (x) { var s = str(x).trim(); return s === '*' || s === 'Bash' || /^Bash\(\*\)$/.test(s) || /^mcp__\*$/.test(s) || /^Bash\((?:\*|:\*)\)$/.test(s); })) {
          C.add('mcp_allow_all', 'high', 30, 'settings', v.map(str).slice(0, 5).join(', '),
            'The allow-list contains a wildcard (all shell commands or all MCP tools). The assistant can run anything without asking.',
            'allow-list में वाइल्डकार्ड है (सारे शेल कमांड या सारे MCP टूल)। असिस्टेंट बिना पूछे कुछ भी चला सकता है।',
            'List specific, narrow commands instead of a wildcard.', 'वाइल्डकार्ड की जगह ख़ास और सीमित कमांड लिखें।');
        } else if (isObj(v)) walk(v, depth + 1);
      });
    })(rootObj, 0);
  }

  // ---- tool description analysis -----------------------------------------
  // Strong: files whose contents are almost never a legitimate tool input. Weak: common but worth a look.
  var SENSITIVE_STRONG = '(?:~\\/|\\$HOME\\/|%USERPROFILE%\\\\|\\/home\\/\\w+\\/|\\/Users\\/\\w+\\/)?\\.(?:ssh|aws|gnupg|kube|config\\/gcloud)\\b|id_rsa|id_ed25519|\\/etc\\/(?:passwd|shadow)|mcp\\.json|claude_desktop_config|credentials\\.json|\\.netrc|wallet\\.dat|cookies?\\.sqlite|login data|\\.git-credentials';
  var SENSITIVE_WEAK = '\\.env\\b|\\.npmrc|\\.docker\\b|keychain';
  var RE = {
    hiddenTag: /<\s*(?:important|system|instructions?|secret|hidden|admin|override|sidenote|assistant)\s*>|\[\s*(?:system|important|hidden)\s*\]|###\s*(?:system|instruction)/i,
    ignorePrior: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|safety|system|user'?s?)\s*(?:instructions?|rules|prompts?|messages?|guidelines|restrictions)/i,
    conceal: /(?:do\s*n[o']?t|never|without)\s+(?:tell|inform|mention|notify|show|reveal|let|alert|warn)\b[^.]{0,50}\b(?:user|human|anyone|them)\b|(?:keep|stay)\s+(?:this\s+|it\s+)?(?:secret|hidden|quiet|confidential)|\bsilently\b|\bcovertly\b|(?:do\s*n[o']?t|never)\s+(?:mention|reveal|disclose|say|talk\s+about)\s+(?:that|this|these|it|anything|the\s+fact)\b/i,
    readSensitive: new RegExp('(?:read|cat|open|load|include|attach|send|pass|append|upload|exfiltrat\\w*|copy|access|fetch|get)\\b[^.]{0,70}(?:' + SENSITIVE_STRONG + ')', 'i'),
    sensitiveOnly: new RegExp('(?:' + SENSITIVE_STRONG + '|' + SENSITIVE_WEAK + ')', 'i'),
    exfil: /(?:send|post|upload|forward|transmit|exfiltrat\w*|email|leak|copy|submit)\b[^.]{0,90}\b(?:to|at|via|into)\b[^.]{0,50}(?:https?:\/\/|\bwebhook\b|\bpastebin\b|\bngrok\b|\bdiscord\.com\/api\b|\btelegram\b)|\b(?:curl|wget)\s+(?:-\S+\s+)*https?:\/\//i,
    paramSmuggle: /(?:in|as|into|via|through|inside)\s+(?:the\s+)?(?:`?'?"?\w+"?'?`?\s+)?(?:parameter|argument|field|param)\b[^.]{0,90}(?:contents?|file|key|token|history|conversation|system\s+prompt|secrets?|credentials?)|(?:contents?\s+of|full\s+(?:conversation|chat|history)|system\s+prompt|chat\s+history)[^.]{0,60}(?:parameter|argument|field|param)\b|\b(?:contents?|keys?|tokens?|secrets?|credentials?|history|conversation)\b[^.]{0,40}\b(?:as|in|into|via|to)\b[^.]{0,40}\b(?:parameter|argument|field|param)\b|\b(?:pass|send|include|put|provide|supply|add|set|fill)\b[^.]{0,50}\b(?:contents?|keys?|tokens?|secrets?|credentials?|history|conversation)\b[^.]{0,40}\b(?:as|in|into|to)\s+['"`]\w+['"`]/i,
    confirmBypass: /(?:without|no\s+need\s+(?:for|to)|do\s*n[o']?t)\s+(?:ask(?:ing)?|requir\w+|request\w*|seek\w*|wait\w*)\s+(?:for\s+)?(?:the\s+)?(?:user\s+)?(?:confirm\w+|permission|approval|consent)|auto[-\s]?approve|skip\s+(?:the\s+)?(?:confirmation|approval|permission)|already\s+(?:been\s+)?(?:approved|authorized|authorised)/i,
    override: /\byou\s+(?:are\s+now|must\s+now|will\s+now)\b|\bnew\s+(?:system\s+)?instructions?\b|\bfrom\s+now\s+on\b|\bact\s+as\s+(?:the\s+)?(?:system|admin|root|developer)\b|\byour\s+(?:real|true|actual)\s+(?:task|goal|purpose)\b/i,
    directive: /\b(?:instead|override|redirect|replace|always\s+(?:use|call|send|route)|must\s+(?:be\s+)?(?:use|used|call|called|send|sent|route|routed)|before\s+(?:using|calling|running)|whenever|every\s+time|all\s+\w+\s+(?:to|must)|rather\s+than)\b/i,
    b64: /[A-Za-z0-9+\/]{120,}={0,2}/,
  };

  // Every string value in a tool definition (description, parameter descriptions, enums, defaults...)
  // is text the model reads, so all of it is checked.
  function collectStrings(node, out, depth) {
    if (out.total > 60000 || depth > 8) return;
    if (typeof node === 'string') { out.parts.push(node); out.total += node.length; return; }
    if (Array.isArray(node)) { node.slice(0, 200).forEach(function (x) { collectStrings(x, out, depth + 1); }); return; }
    if (isObj(node)) Object.keys(node).slice(0, 200).forEach(function (k) {
      if (k !== 'type') collectStrings(node[k], out, depth + 1);
    });
  }

  function hiddenChars(s) {
    var zw = 0;
    var bidi = 0;
    var tag = 0;
    var tagText = '';
    for (var i = 0; i < s.length; i++) {
      var cp = s.codePointAt(i);
      if (cp > 0xffff) i++;
      if (cp === 0x200b || (cp >= 0x2060 && cp <= 0x2064) || cp === 0x180e || (cp === 0xfeff && i > 0)) zw++;
      else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
      else if (cp >= 0xe0000 && cp <= 0xe007f) { tag++; if (cp >= 0xe0020 && cp <= 0xe007e) tagText += String.fromCharCode(cp - 0xe0000); }
      else if (cp >= 0xe0100 && cp <= 0xe01ef) tag++;
    }
    return { zw: zw, bidi: bidi, tag: tag, tagText: tagText };
  }

  function getEngine() {
    if (typeof self !== 'undefined' && self.ScamCheck) return self.ScamCheck;
    if (typeof module === 'object' && typeof require === 'function') { try { return require('./engine.js'); } catch (e) { return null; } }
    return null;
  }

  function evid(text, re) {
    var m = re.exec(text);
    if (!m) return '';
    var s = Math.max(0, m.index - 25);
    var e = Math.min(text.length, m.index + m[0].length + 25);
    return (s > 0 ? '…' : '') + text.slice(s, e).replace(/\s+/g, ' ') + (e < text.length ? '…' : '');
  }

  function analyseText(label, rawText, C, siblingNames) {
    var where = label;
    var original = String(rawText || '');
    if (!original) return;
    var hc = hiddenChars(original);
    if (hc.tag) {
      C.add('mcp_hidden_tag', 'critical', 50, where, hc.tagText ? 'hidden text: "' + hc.tagText.slice(0, 100) + '"' : hc.tag + ' invisible tag characters',
        'Contains invisible Unicode "tag" characters that carry a hidden message. You cannot see it, but the model can read it.',
        'अदृश्य Unicode "tag" अक्षर हैं जिनमें छुपा संदेश है। आप उसे नहीं देख सकते, पर मॉडल पढ़ सकता है।',
        'Do not use this server. Report it to its publisher.', 'यह सर्वर इस्तेमाल न करें। इसके प्रकाशक को रिपोर्ट करें।');
    }
    if (hc.zw || hc.bidi) {
      C.add('mcp_hidden_chars', 'high', 40, where, (hc.zw ? hc.zw + ' zero-width' : '') + (hc.zw && hc.bidi ? ', ' : '') + (hc.bidi ? hc.bidi + ' bidi-control' : '') + ' characters',
        'Contains zero-width or text-direction control characters, used to hide or reorder text so a human reviewer sees something different from the model.',
        'zero-width या टेक्स्ट-डायरेक्शन कंट्रोल अक्षर हैं, जो टेक्स्ट छुपाने या उलटने के काम आते हैं ताकि इंसान को मॉडल से अलग कुछ दिखे।',
        'Strip these characters and re-read the description.', 'इन अक्षरों को हटाकर विवरण फिर से पढ़ें।');
    }
    var text = original;
    try { text = original.normalize('NFKC'); } catch (e) { /* ignore */ }
    text = text.replace(/[\u200b-\u200d\u2060-\u2064\ufeff\u00ad]/g, '');
    if (text.length > 20000) text = text.slice(0, 20000);

    if (RE.hiddenTag.test(text)) {
      C.add('mcp_inject_tag', 'critical', 45, where, evid(text, RE.hiddenTag),
        'Uses a fake <IMPORTANT>/<system> style tag to give the model instructions the user never sees. This is the signature of tool poisoning.',
        'नकली <IMPORTANT>/<system> जैसे टैग से मॉडल को ऐसे निर्देश देता है जो यूज़र कभी नहीं देखता। यह tool poisoning की पहचान है।',
        'Do not connect this server. Real tool descriptions only describe what the tool does.', 'यह सर्वर कनेक्ट न करें। असली टूल विवरण सिर्फ़ यह बताता है कि टूल क्या करता है।');
    }
    if (RE.ignorePrior.test(text)) {
      C.add('mcp_inject_ignore', 'critical', 45, where, evid(text, RE.ignorePrior),
        'Tells the model to ignore its previous instructions or safety rules.', 'मॉडल को पिछले निर्देश या सुरक्षा नियम अनदेखा करने को कहता है।',
        'Do not connect this server.', 'यह सर्वर कनेक्ट न करें।');
    }
    if (RE.readSensitive.test(text)) {
      C.add('mcp_read_secrets', 'critical', 45, where, evid(text, RE.readSensitive),
        'Instructs the model to read or pass along sensitive files (SSH keys, .env, cloud credentials, MCP config). A tool description has no reason to do that.',
        'मॉडल को संवेदनशील फ़ाइलें (SSH कुंजी, .env, क्लाउड क्रेडेंशियल, MCP कॉन्फ़िग) पढ़ने या आगे भेजने को कहता है। किसी टूल विवरण को इसकी कोई ज़रूरत नहीं।',
        'Remove the server and rotate any credential that may have been exposed.', 'सर्वर हटाएँ और जो भी क्रेडेंशियल उजागर हुआ हो उसे रोटेट करें।');
    } else if (RE.sensitiveOnly.test(text)) {
      C.add('mcp_mentions_secrets', 'low', 10, where, evid(text, RE.sensitiveOnly),
        'The description mentions a sensitive file or path. Check that the tool really needs it.', 'विवरण में किसी संवेदनशील फ़ाइल/पाथ का ज़िक्र है। जाँचें कि टूल को सच में उसकी ज़रूरत है।',
        'Read the whole description and the tool\'s source.', 'पूरा विवरण और टूल का सोर्स पढ़ें।');
    }
    if (RE.exfil.test(text)) {
      C.add('mcp_exfil', 'high', 40, where, evid(text, RE.exfil),
        'Tells the model to send data to an outside address. That is a data-exfiltration channel.', 'मॉडल को डेटा किसी बाहरी पते पर भेजने को कहता है। यह डेटा चोरी का रास्ता है।',
        'Block the server, and check what data it already received.', 'सर्वर ब्लॉक करें और जाँचें कि उसे अब तक कौन सा डेटा मिल चुका है।');
    }
    if (RE.paramSmuggle.test(text)) {
      C.add('mcp_param_smuggle', 'high', 35, where, evid(text, RE.paramSmuggle),
        'Asks the model to put file contents, keys or the conversation into a tool parameter. Data is smuggled out through an ordinary-looking argument.',
        'मॉडल से फ़ाइल सामग्री, कुंजियाँ या पूरी बातचीत किसी टूल पैरामीटर में डालने को कहता है। सामान्य दिखने वाले आर्ग्युमेंट से डेटा बाहर जाता है।',
        'Review the parameter descriptions and reject tools whose parameters ask for unrelated data.', 'पैरामीटर विवरण जाँचें और जिन टूल के पैरामीटर बेमतलब डेटा माँगें उन्हें अस्वीकार करें।');
    }
    if (RE.conceal.test(text)) {
      C.add('mcp_conceal', 'high', 40, where, evid(text, RE.conceal),
        'Tells the model to hide what it is doing from the user.', 'मॉडल से कहता है कि वह जो कर रहा है उसे यूज़र से छुपाए।',
        'Legitimate tools never need secrecy. Do not use this server.', 'असली टूल को कभी गोपनीयता की ज़रूरत नहीं होती। यह सर्वर इस्तेमाल न करें।');
    }
    if (RE.confirmBypass.test(text)) {
      C.add('mcp_confirm_bypass', 'high', 30, where, evid(text, RE.confirmBypass),
        'Tells the model to skip asking you for confirmation.', 'मॉडल से कहता है कि आपसे पुष्टि पूछना छोड़ दे।',
        'Keep confirmations on for tools like this.', 'ऐसे टूल के लिए पुष्टि चालू रखें।');
    }
    if (RE.override.test(text)) {
      C.add('mcp_role_override', 'medium', 25, where, evid(text, RE.override),
        'Tries to redefine the model\'s role or goal ("from now on", "new instructions").', 'मॉडल की भूमिका या लक्ष्य बदलने की कोशिश ("from now on", "new instructions")।',
        'Tool text should describe the tool, not instruct the assistant.', 'टूल का टेक्स्ट टूल के बारे में होना चाहिए, असिस्टेंट को निर्देश देने के लिए नहीं।');
    }
    if (RE.b64.test(text)) {
      C.add('mcp_blob', 'medium', 20, where, 'long encoded blob',
        'Contains a long base64-like blob, which can hide instructions or data.', 'लंबा base64 जैसा ब्लॉब है, जिसमें निर्देश या डेटा छुपा हो सकता है।',
        'Decode and inspect it, or reject the tool.', 'डिकोड करके जाँचें, या टूल अस्वीकार करें।');
    }
    if (text.length > 2000) {
      C.add('mcp_long_desc', 'low', 10, where, text.length + ' characters',
        'Unusually long description. Long text is where instructions get buried.', 'असामान्य रूप से लंबा विवरण। निर्देश अक्सर लंबे टेक्स्ट में दबा दिए जाते हैं।',
        'Read the whole thing, not just the first lines.', 'सिर्फ़ शुरुआती पंक्तियाँ नहीं, पूरा पढ़ें।');
    }
    // shadowing: this tool's text issues directives about another tool
    if (siblingNames && siblingNames.length) {
      var lower = text.toLowerCase();
      for (var i = 0; i < siblingNames.length; i++) {
        var other = siblingNames[i];
        if (other.length < 4 || label === 'tool:' + other) continue;
        var idx = lower.indexOf(other.toLowerCase());
        if (idx === -1) continue;
        var win = text.slice(Math.max(0, idx - 90), idx + other.length + 90);
        if (RE.directive.test(win)) {
          C.add('mcp_shadow', 'high', 35, where, evid(win, RE.directive),
            'This tool\'s text gives orders about another tool ("' + other + '"), so one server can quietly change how a different, trusted server behaves.',
            'इस टूल का टेक्स्ट दूसरे टूल ("' + other + '") के बारे में आदेश देता है, यानी एक सर्वर चुपचाप दूसरे भरोसेमंद सर्वर का व्यवहार बदल सकता है।',
            'Do not let one server\'s text reference another server\'s tools. Remove the server.', 'एक सर्वर के टेक्स्ट को दूसरे सर्वर के टूल का हवाला न देने दें। सर्वर हटाएँ।');
          break;
        }
      }
    }
    var eng = getEngine();
    if (eng) {
      var urls = eng.extractUrls(text).slice(0, 15);
      var bad = urls.filter(function (u) {
        var r = eng.analyze(u.raw);
        return r.findings.some(function (f) { return f.cat === 'link' && (f.sev === 'critical' || f.sev === 'high'); });
      });
      if (bad.length) {
        C.add('mcp_bad_link', 'high', 25, where, bad.map(function (u) { return u.raw; }).slice(0, 3).join(' '),
          'The text links to a suspicious address (raw IP, look-alike domain, hidden redirect).', 'टेक्स्ट में संदिग्ध पते (सीधा IP, नकली डोमेन, छुपा रीडायरेक्ट) का लिंक है।',
          'Do not follow or allow requests to it.', 'उस पर न जाएँ और उसके अनुरोध अनुमति न दें।');
      }
    }
  }

  function findTools(rootObj) {
    var tools = [];
    var instructions = [];
    function pick(list) {
      list.forEach(function (t) { if (isObj(t) && (typeof t.name === 'string') && tools.length < 2000) tools.push(t); });
    }
    if (Array.isArray(rootObj)) pick(rootObj);
    else if (isObj(rootObj)) {
      if (Array.isArray(rootObj.tools)) pick(rootObj.tools);
      if (isObj(rootObj.result)) {
        if (Array.isArray(rootObj.result.tools)) pick(rootObj.result.tools);
        if (typeof rootObj.result.instructions === 'string') instructions.push(rootObj.result.instructions);
      }
      if (typeof rootObj.instructions === 'string') instructions.push(rootObj.instructions);
      if (Array.isArray(rootObj.servers) === false && isObj(rootObj.mcpServers) === false) {
        // a single tool object pasted on its own
        if (typeof rootObj.name === 'string' && (rootObj.description || rootObj.inputSchema) && !looksLikeServer(rootObj)) pick([rootObj]);
      }
    }
    return { tools: tools, instructions: instructions };
  }

  // ---- fingerprints (rug-pull detection) ----------------------------------
  function canonical(x) {
    if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
    if (isObj(x)) return '{' + Object.keys(x).sort().map(function (k) { return JSON.stringify(k) + ':' + canonical(x[k]); }).join(',') + '}';
    return JSON.stringify(x === undefined ? null : x);
  }

  async function sha256Hex(s) {
    var subtle = (typeof crypto !== 'undefined' && crypto.subtle) || (typeof require === 'function' ? require('crypto').webcrypto.subtle : null);
    if (!subtle) return '';
    var h = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(s)));
    return Array.prototype.map.call(h, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  async function fingerprint(tools) {
    var out = { version: 1, tools: {} };
    for (var i = 0; i < tools.length; i++) {
      var t = tools[i];
      out.tools[t.name] = await sha256Hex(canonical({ d: t.description || '', s: t.inputSchema || t.input_schema || null }));
    }
    return out;
  }

  function diffBaseline(fp, baseline, C) {
    if (!isObj(baseline) || !isObj(baseline.tools)) throw fail('bad_baseline', 'Baseline must look like {"version":1,"tools":{"name":"sha256"}}');
    var changed = [];
    var added = [];
    var removed = [];
    Object.keys(fp.tools).forEach(function (n) {
      if (!(n in baseline.tools)) added.push(n);
      else if (baseline.tools[n] !== fp.tools[n]) changed.push(n);
    });
    Object.keys(baseline.tools).forEach(function (n) { if (!(n in fp.tools)) removed.push(n); });
    changed.forEach(function (n) {
      C.add('mcp_tool_changed', 'high', 45, 'tool:' + n, 'definition differs from baseline',
        'This tool\'s description or schema changed since you saved the baseline. A "rug pull" is when a server turns malicious after you approved it.',
        'आपके baseline सेव करने के बाद इस टूल का विवरण या स्कीमा बदल गया। "Rug pull" वह है जब सर्वर आपकी मंज़ूरी के बाद ख़राब हो जाता है।',
        'Diff the old and new text before approving again.', 'दोबारा मंज़ूर करने से पहले पुराने और नए टेक्स्ट का फ़र्क़ देखें।');
    });
    added.forEach(function (n) {
      C.add('mcp_tool_added', 'medium', 15, 'tool:' + n, 'not in baseline', 'A new tool appeared that was not in your baseline.', 'एक नया टूल दिखा जो आपके baseline में नहीं था।',
        'Review it like a new server.', 'इसे नए सर्वर की तरह जाँचें।');
    });
    removed.forEach(function (n) {
      C.add('mcp_tool_removed', 'low', 5, 'tool:' + n, 'missing now', 'A tool from your baseline is gone.', 'आपके baseline का एक टूल अब नहीं है।', 'Check whether that was expected.', 'जाँचें कि यह अपेक्षित था या नहीं।');
    });
    return { changed: changed, added: added, removed: removed };
  }

  // ---- public: audit ------------------------------------------------------
  async function audit(input, opts) {
    opts = opts || {};
    var text = String(input == null ? '' : input);
    if (!text.trim()) throw fail('empty', 'Nothing to audit');
    if (text.length > MAX_INPUT) throw fail('too_big', 'Input is larger than 1 MB');
    var data;
    try { data = parseJsonc(text); } catch (e) { throw fail('bad_json', 'Input is not valid JSON', e && e.message); }
    if (!isObj(data) && !Array.isArray(data)) throw fail('bad_shape', 'Expected a JSON object or array');

    var C = new Collector();
    var servers = isObj(data) ? collectServers(data) : [];
    servers.forEach(function (s) { analyseServer(s.name, s.cfg, C); });
    if (isObj(data)) analyseSettings(data, C);

    var found = findTools(data);
    var names = found.tools.map(function (t) { return str(t.name); });
    found.tools.forEach(function (t) {
      var out = { parts: [], total: 0 };
      collectStrings({ d: t.description, s: t.inputSchema || t.input_schema, t: t.title, a: t.annotations }, out, 0);
      analyseText('tool:' + str(t.name), str(t.name) + '\n' + out.parts.join('\n'), C, names);
    });
    found.instructions.forEach(function (s) { analyseText('server instructions', s, C, names); });

    var fp = null;
    var diff = null;
    if (found.tools.length) {
      fp = await fingerprint(found.tools);
      if (opts.baseline) {
        var base = opts.baseline;
        if (typeof base === 'string') { try { base = parseJsonc(base); } catch (e) { throw fail('bad_baseline', 'Baseline is not valid JSON'); } }
        diff = diffBaseline(fp, base, C);
      }
    }

    var findings = C.merged();
    var total = 0;
    var critical = false;
    findings.forEach(function (f) { total += f.w; if (f.sev === 'critical') critical = true; });
    var score = Math.min(100, Math.round(total));
    if (critical && score < 60) score = 60;
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.w - a.w); });
    var level = score >= 80 ? 'scam' : score >= 60 ? 'likely' : score >= 40 ? 'suspicious' : score >= 20 ? 'caution' : 'clean';

    return {
      score: score, level: level, findings: findings, fingerprint: fp, diff: diff, version: VERSION,
      info: { servers: servers.map(function (s) { return s.name; }), tools: found.tools.length },
    };
  }

  return { audit: audit, parseJsonc: parseJsonc, fingerprint: fingerprint, canonical: canonical, VERSION: VERSION, MAX_INPUT: MAX_INPUT };
});
