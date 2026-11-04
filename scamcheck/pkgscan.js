/*
 * pkgscan: offline static analysis of npm / PyPI packages, no network, no dependencies.
 * Works in the browser (window.PkgScan) and in Node (require('./pkgscan.js')).
 *
 *  - scanManifest(text): package.json, package-lock.json or requirements.txt. Typosquats, risky
 *    install hooks, git/URL dependencies, non-default registries, dependency-confusion setups.
 *  - scanArchive(bytes): an npm tarball (.tgz from `npm pack`), a wheel/zip (.whl), or an sdist
 *    (.tar.gz). The files are read, never executed. Looks for install-time execution, obfuscation,
 *    credential theft, exfiltration, persistence, miners, reverse shells and hidden Unicode.
 *
 * Heuristics, not proof. A clean result never means "safe".
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PkgScan = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var MAX_FILE = 150 * 1024 * 1024;
  var MAX_TOTAL = 150 * 1024 * 1024;
  var MAX_ENTRIES = 20000;
  var MAX_TEXT_FILE = 2 * 1024 * 1024;
  var MAX_TEXT_BUDGET = 40 * 1024 * 1024;
  var MAX_MANIFEST = 5 * 1024 * 1024;

  function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
  function str(x) { return typeof x === 'string' ? x : ''; }
  function fail(code, msg) { var e = new Error(msg); e.code = code; return e; }

  function getApkScan() {
    if (typeof self !== 'undefined' && self.ApkScan) return self.ApkScan;
    if (typeof module === 'object' && typeof require === 'function') { try { return require('./apkscan.js'); } catch (e) { return null; } }
    return null;
  }

  // ---- popular package names (for typosquat detection) --------------------
  var NPM_POPULAR = ('react react-dom react-router react-router-dom redux react-redux lodash underscore express axios chalk commander debug moment request async bluebird uuid typescript ' +
    'webpack webpack-cli webpack-dev-server babel-core babel-loader eslint prettier jest mocha chai sinon vue vuex vue-router next nuxt jquery dotenv cors body-parser cookie-parser ' +
    'mongoose mongodb mysql mysql2 pg redis ioredis socket.io socket.io-client ws yargs minimist glob rimraf mkdirp fs-extra semver inquirer ora colors node-fetch cross-env nodemon ' +
    'tailwindcss postcss autoprefixer rxjs zod vite rollup esbuild gulp grunt browserify handlebars ejs pug jade mustache marked cheerio puppeteer playwright selenium-webdriver sharp jimp ' +
    'multer passport jsonwebtoken bcrypt bcryptjs helmet morgan winston pino bunyan joi yup ajv validator date-fns dayjs luxon ramda immutable immer classnames prop-types ' +
    'styled-components emotion antd bootstrap tslib core-js regenerator-runtime whatwg-fetch isomorphic-fetch superagent got node-sass sass less stylus uglify-js terser ts-node tsup nx lerna ' +
    'husky lint-staged chokidar fsevents readable-stream through2 event-stream left-pad is-promise is-number kind-of ms qs url-parse form-data mime mime-types iconv-lite safe-buffer buffer ' +
    'inherits util process path-to-regexp express-session serve-static http-proxy http-proxy-middleware compression ts-loader css-loader style-loader file-loader html-webpack-plugin ' +
    'mini-css-extract-plugin copy-webpack-plugin clean-webpack-plugin eslint-plugin-react eslint-config-airbnb babel-eslint stylelint npm yarn pnpm electron cypress storybook graphql ' +
    'apollo-server firebase firebase-admin aws-sdk stripe twilio nodemailer sequelize typeorm prisma knex lodash-es lodash.merge lodash.get big.js bignumber.js decimal.js crypto-js nanoid ' +
    'shortid picocolors kleur ansi-styles strip-ansi wrap-ansi string-width escape-string-regexp supports-color has-flag color-convert color-name js-yaml yaml toml xml2js fast-xml-parser ' +
    'csv-parse papaparse xlsx exceljs pdfkit moment-timezone i18next react-i18next formik react-hook-form swr react-query zustand mobx recoil three d3 chart.js echarts leaflet ' +
    'lodash.debounce debounce throttle-debounce concurrently npm-run-all cross-spawn execa shelljs which open opn cli-table cli-table3 boxen figlet gradient-string listr listr2 prompts ' +
    'enquirer meow cac oclif zone.js svelte solid-js preact lit alpinejs htmx.org hono fastify koa koa-router hapi restify express-validator swagger-ui-express openai langchain ethers web3 ' +
    'bitcoinjs-lib tailwind-merge clsx cssnesting sqlite3 better-sqlite3 pm2 forever supertest nock jsdom enzyme ' +
    'react-native expo vue-cli webpack-merge babel-preset-env core-js-pure rimraf-cli http-server live-server browser-sync').split(/\s+/).filter(Boolean);

  var PYPI_POPULAR = ('requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch torchvision keras transformers openai anthropic langchain boto3 botocore awscli s3transfer ' +
    'setuptools pip wheel virtualenv six certifi idna charset-normalizer chardet python-dateutil pytz tzdata pyyaml jinja2 markupsafe click flask django fastapi uvicorn gunicorn starlette ' +
    'pydantic sqlalchemy alembic psycopg2 psycopg2-binary pymysql mysqlclient redis celery kombu pymongo motor pytest pytest-cov pytest-mock tox nose coverage mock attrs cryptography ' +
    'pycryptodome pyopenssl paramiko bcrypt pynacl cffi pycparser pillow opencv-python beautifulsoup4 lxml html5lib selenium scrapy aiohttp httpx httplib2 websockets websocket-client tqdm ' +
    'rich colorama termcolor tabulate prettytable black flake8 pylint mypy isort autopep8 yapf ruff poetry pipenv docker kubernetes ansible fabric invoke jsonschema simplejson ujson orjson ' +
    'toml tomli typing-extensions packaging pyparsing decorator wrapt regex protobuf grpcio google-api-python-client google-auth google-cloud-storage oauthlib requests-oauthlib python-dotenv ' +
    'pyjwt cachetools joblib networkx sympy statsmodels xgboost lightgbm nltk spacy gensim jupyter notebook ipython ipykernel jedi pexpect psutil pyserial pywin32 pyinstaller cython numba ' +
    'h5py pyarrow openpyxl xlrd xlsxwriter python-docx reportlab pypdf2 pypdf markdown docutils sphinx mkdocs babel emoji faker python-slugify unidecode validators email-validator dnspython ' +
    'netaddr pycurl tzlocal humanize arrow pendulum dateparser croniter schedule apscheduler watchdog filelock platformdirs distlib zipp importlib-metadata importlib-resources more-itertools ' +
    'toolz sortedcontainers bidict cachecontrol msgpack zstandard lz4 brotli pluggy iniconfig exceptiongroup anyio sniffio h11 httpcore uvloop tenacity retry backoff ratelimit ruamel-yaml ' +
    'python-multipart itsdangerous werkzeug flask-cors flask-sqlalchemy djangorestframework django-cors-headers whitenoise mcp pyautogui pyperclip keyboard pynput discord-py tweepy ' +
    'python-telegram-bot pytest-asyncio freezegun responses moto factory-boy hypothesis').split(/\s+/).filter(Boolean);

  var NPM_SET = {};
  NPM_POPULAR.forEach(function (n) { NPM_SET[n] = true; });
  var PYPI_SET = {};
  PYPI_POPULAR.forEach(function (n) { PYPI_SET[n] = true; });
  var TRUSTED_SCOPES = ['@types', '@babel', '@angular', '@aws-sdk', '@azure', '@google-cloud', '@nestjs', '@mui', '@emotion', '@testing-library', '@vue', '@typescript-eslint', '@eslint', '@rollup', '@tanstack', '@prisma', '@apollo', '@anthropic-ai', '@modelcontextprotocol', '@sentry', '@octokit', '@aws-cdk', '@stripe', '@vitejs', '@svgr', '@swc', '@nx'];

  // Optimal string alignment distance: insert, delete, substitute and adjacent transposition each cost 1.
  function osa(a, b) {
    var al = a.length;
    var bl = b.length;
    if (!al) return bl;
    if (!bl) return al;
    var d = [];
    var i, j;
    for (i = 0; i <= al; i++) { d[i] = [i]; }
    for (j = 0; j <= bl; j++) d[0][j] = j;
    for (i = 1; i <= al; i++) {
      for (j = 1; j <= bl; j++) {
        var cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a.charCodeAt(i - 1) === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[al][bl];
  }

  function normName(name, eco) {
    var n = String(name).trim().toLowerCase();
    if (eco === 'pypi') n = n.replace(/[-_.]+/g, '-');
    return n;
  }

  // Returns {near, dist} if the name looks like a popular package without being one.
  function lookalike(name, eco) {
    var n = normName(name, eco);
    if (n.length < 5 || n.length > 60) return null;
    if (eco === 'npm' && n.charAt(0) === '@') return null;
    var set = eco === 'pypi' ? PYPI_SET : NPM_SET;
    if (set[n]) return null;
    var list = eco === 'pypi' ? PYPI_POPULAR : NPM_POPULAR;
    var glyph = n.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/rn/g, 'm');
    if (glyph !== n && set[glyph]) return { near: glyph, dist: 1 };
    var best = null;
    for (var i = 0; i < list.length; i++) {
      var p = list[i];
      if (p.length < 5) continue;
      var diff = Math.abs(p.length - n.length);
      if (diff > 2) continue;
      if (osa(n, p) !== 1) continue;
      // "color" vs "colors", "typescript" vs "typescript3": legitimate sibling names, not squats.
      // (An extra "s" on a name that already ends in "s", like "expresss", is still suspicious.)
      var shorter = n.length < p.length ? n : p;
      var longer = n.length < p.length ? p : n;
      var tail = longer.charAt(longer.length - 1);
      if (longer.length === shorter.length + 1 && longer.indexOf(shorter) === 0 && (/[0-9]/.test(tail) || (tail === 's' && shorter.charAt(shorter.length - 1) !== 's'))) continue;
      best = { near: p, dist: 1 };
      break;
    }
    return best;
  }

  var BAD_NAME_RE = /(?:stealer|grabber|token-?logger|keylogger|ransom|cryptojack|crypto-?miner|backdoor|reverse-?shell|password-?stealer|cookie-?stealer|discord-?token|nitro-?gen)/i;

  // ---- findings collector -------------------------------------------------
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
        m = by[f.id] = { id: f.id, cat: 'pkg', sev: f.sev, w: f.w, count: 0, where: [], evidence: f.evidence, en: f.en, hi: f.hi, fixEn: f.fixEn, fixHi: f.fixHi };
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
  function finish(C, info) {
    var findings = C.merged();
    var total = 0;
    var critical = false;
    findings.forEach(function (f) { total += f.w; if (f.sev === 'critical') critical = true; });
    var score = Math.min(100, Math.round(total));
    if (critical && score < 60) score = 60;
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort(function (a, b) { return (order[a.sev] - order[b.sev]) || (b.w - a.w); });
    var level = score >= 80 ? 'scam' : score >= 60 ? 'likely' : score >= 40 ? 'suspicious' : score >= 20 ? 'caution' : 'clean';
    return { score: score, level: level, findings: findings, info: info, version: VERSION };
  }

  // ---- messages used in more than one place --------------------------------
  function addTyposquat(C, where, name, hit, eco) {
    C.add('pkg_typosquat', 'high', hit.dist === 1 ? 40 : 30, where, name + ' ≈ ' + hit.near,
      '"' + name + '" is one or two characters away from the popular ' + (eco === 'pypi' ? 'PyPI' : 'npm') + ' package "' + hit.near + '". Typosquatting is the most common way malicious packages get installed by accident.',
      '"' + name + '", लोकप्रिय ' + (eco === 'pypi' ? 'PyPI' : 'npm') + ' पैकेज "' + hit.near + '" से एक-दो अक्षर दूर है। टाइपो-स्क्वैटिंग वह सबसे आम तरीका है जिससे ख़राब पैकेज ग़लती से इंस्टॉल हो जाते हैं।',
      'Check the spelling against the registry page (publisher, downloads, repository) before installing.',
      'इंस्टॉल से पहले रजिस्ट्री पेज (प्रकाशक, डाउनलोड, रिपॉज़िटरी) पर स्पेलिंग मिलाएँ।');
  }

  function checkName(C, where, name, eco) {
    var n = str(name);
    if (!n) return;
    var hit = lookalike(n, eco);
    if (hit) addTyposquat(C, where, n, hit, eco);
    if (BAD_NAME_RE.test(n)) {
      C.add('pkg_bad_name', 'medium', 25, where, n,
        'The name advertises a malicious purpose (stealer, grabber, keylogger, backdoor ...). It may be security research, but it is also exactly how malware is labelled.',
        'नाम किसी दुर्भावनापूर्ण उद्देश्य (stealer, grabber, keylogger, backdoor ...) का संकेत देता है। यह सिक्योरिटी रिसर्च हो सकता है, पर मैलवेयर भी ऐसे ही नाम से आता है।',
        'Only use it if you know the author and have read the source.', 'लेखक को जानते हों और सोर्स पढ़ चुके हों तभी इस्तेमाल करें।');
    }
  }

  var INSTALL_BAD_RE = /\b(?:curl|wget|powershell|pwsh|certutil|bitsadmin|nc\s+-|bash\s+-c|sh\s+-c|python3?\s+-c|base64|eval|iex|Invoke-WebRequest|mshta|rundll32)\b|\|\s*(?:ba)?sh\b|https?:\/\//i;
  var INLINE_NODE_RE = /\bnode\s+(?:-\w+\s+)*-[ep]\b/;
  var INLINE_SUSPICIOUS_RE = /child_process|\bexec|spawn|\bhttps?\b|fetch|Buffer|process\.env|atob|btoa|fromCharCode|\bfs\.|writeFile|readFile/i;
  function installIsBad(cmd) {
    if (INSTALL_BAD_RE.test(cmd)) return true;
    // a short `node -e "require('./postinstall')"` is a common, harmless wrapper; long or suspicious inline code is not
    return INLINE_NODE_RE.test(cmd) && (cmd.length > 160 || INLINE_SUSPICIOUS_RE.test(cmd));
  }
  var HOOKS = ['preinstall', 'install', 'postinstall'];

  function checkInstallScripts(C, where, scripts, collectFiles) {
    if (!isObj(scripts)) return [];
    var seen = [];
    HOOKS.forEach(function (h) {
      var cmd = str(scripts[h]);
      if (!cmd) return;
      seen.push(h + ': ' + cmd.slice(0, 120));
      if (installIsBad(cmd)) {
        C.add('pkg_install_bad', 'critical', 45, where, h + ': ' + cmd.slice(0, 140),
          'An install hook downloads, decodes or runs inline code (' + h + '). Install hooks run automatically with your permissions the moment you install, with no chance to review.',
          'इंस्टॉल हुक (' + h + ') कोड डाउनलोड, डिकोड या इनलाइन चलाता है। इंस्टॉल हुक इंस्टॉल होते ही आपकी अनुमतियों के साथ अपने-आप चलते हैं, समीक्षा का मौका नहीं मिलता।',
          'Do not install. Install with scripts disabled (npm install --ignore-scripts) and read the hook first.',
          'इंस्टॉल न करें। scripts बंद करके इंस्टॉल करें (npm install --ignore-scripts) और पहले हुक पढ़ें।');
      } else {
        C.add('pkg_install_script', 'low', 8, where, h + ': ' + cmd.slice(0, 100),
          'Has an install hook (' + h + ') that runs automatically at install time. Many legitimate packages do (native builds), but it is the first place to look.',
          'इंस्टॉल हुक (' + h + ') है जो इंस्टॉल के समय अपने-आप चलता है। कई असली पैकेज में भी होता है (native build), पर सबसे पहले यहीं देखना चाहिए।',
          'Read what it runs. Use --ignore-scripts when you only need the files.', 'देखें कि क्या चलाता है। सिर्फ़ फ़ाइलें चाहिए तो --ignore-scripts इस्तेमाल करें।');
      }
      if (collectFiles) {
        var m = /(?:node|python3?|sh|bash)\s+(?:-\S+\s+)*([\w./\\@-]+\.(?:js|cjs|mjs|py|sh))/.exec(cmd);
        if (m) collectFiles.push(m[1].replace(/^\.\//, '').replace(/\\/g, '/'));
        var rq = /require\(\s*['"]\.\/([\w./-]+?)(?:\.js)?['"]\s*\)/.exec(cmd);
        if (rq) { collectFiles.push(rq[1] + '.js'); collectFiles.push(rq[1] + '/index.js'); collectFiles.push(rq[1]); }
      }
    });
    return seen;
  }

  // ---- manifests ----------------------------------------------------------
  function specRisk(C, where, name, spec) {
    var s = str(spec).trim();
    if (!s) return;
    if (/^(?:file:|link:|workspace:|npm:|\.{1,2}\/)/i.test(s)) return;
    if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|git@|ssh:)/i.test(s) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s)) {
      var ref = /#([^#]+)$/.exec(s);
      var sevW = !ref ? ['high', 30] : /^[0-9a-f]{40}$/i.test(ref[1]) ? ['low', 8] : /^v?\d+\.\d+/.test(ref[1]) ? ['medium', 18] : ['high', 30];
      C.add('pkg_url_dep', sevW[0], sevW[1], where, name + ' → ' + s.slice(0, 90),
        'Depends on code fetched from a git repository or URL instead of the registry. There is no registry review, and the branch or file can change under you.',
        'रजिस्ट्री की जगह git रिपॉज़िटरी या URL से कोड लेने पर निर्भर है। कोई रजिस्ट्री समीक्षा नहीं, और ब्रांच या फ़ाइल कभी भी बदल सकती है।',
        'Pin to a full commit hash, or publish a versioned package to a registry you trust.', 'पूरे commit hash पर पिन करें, या भरोसेमंद रजिस्ट्री पर वर्ज़न वाला पैकेज प्रकाशित करें।');
    } else if (/^(?:\*|latest|x|next)$/i.test(s)) {
      C.add('pkg_wildcard', 'medium', 15, where, name + ': ' + s,
        'Accepts any version ("' + s + '"), so a malicious new release is installed automatically.', 'कोई भी वर्ज़न ("' + s + '") स्वीकार करता है, इसलिए नया ख़राब रिलीज़ अपने-आप इंस्टॉल हो जाएगा।',
        'Pin a version range you have reviewed and commit a lockfile.', 'समीक्षा किया हुआ वर्ज़न रेंज पिन करें और lockfile commit करें।');
    }
  }

  // includeDev is true when scanning a project's own package.json, false for a package you are about to
  // install: its devDependencies are never installed, and peerDependencies are ranges, not downloads.
  function scanPackageJson(obj, C, label, includeDev) {
    var where = label || 'package.json';
    checkName(C, where, obj.name, 'npm');
    var count = 0;
    (includeDev ? ['dependencies', 'devDependencies', 'optionalDependencies'] : ['dependencies', 'optionalDependencies']).forEach(function (k) {
      if (!isObj(obj[k])) return;
      Object.keys(obj[k]).slice(0, 5000).forEach(function (dep) {
        count++;
        if (TRUSTED_SCOPES.indexOf(dep.split('/')[0]) === -1) checkName(C, k + ': ' + dep, dep, 'npm');
        specRisk(C, k + ': ' + dep, dep, obj[k][dep]);
      });
    });
    var hooks = checkInstallScripts(C, where, obj.scripts, null);
    return { name: str(obj.name), version: str(obj.version), deps: count, hooks: hooks };
  }

  function scanLock(obj, C) {
    var pk = isObj(obj.packages) ? obj.packages : null;
    var total = 0;
    var installScripts = [];
    function visit(name, ent) {
      if (!isObj(ent) || total++ > 20000) return;
      var resolved = str(ent.resolved);
      var where = name;
      if (TRUSTED_SCOPES.indexOf(name.split('/')[0]) === -1) checkName(C, where, name, 'npm');
      if (resolved) {
        if (/^http:\/\//i.test(resolved)) {
          C.add('pkg_lock_http', 'high', 30, where, resolved.slice(0, 100), 'Resolved over plain http, so the download can be swapped in transit.', 'सादे http से रिज़ॉल्व होता है, इसलिए डाउनलोड रास्ते में बदला जा सकता है।',
            'Use https registries only.', 'सिर्फ़ https रजिस्ट्री इस्तेमाल करें।');
        } else if (/^(?:git\+|git:|github:)/i.test(resolved) || /codeload\.github\.com|\.git(?:#|$)/.test(resolved)) {
          C.add('pkg_url_dep', 'high', 30, where, resolved.slice(0, 100), 'Locked to a git source instead of the registry.', 'रजिस्ट्री की जगह git सोर्स पर लॉक है।',
            'Pin to a full commit hash.', 'पूरे commit hash पर पिन करें।');
        } else {
          var m = /^https:\/\/([^/]+)/i.exec(resolved);
          if (m && !/^(?:registry\.npmjs\.org|registry\.yarnpkg\.com)$/i.test(m[1])) {
            C.add('pkg_lock_registry', 'medium', 20, where, m[1],
              'Resolved from a registry other than the default npm one. Fine for a private registry you run, dangerous if it is not yours (dependency-confusion and mirror attacks).',
              'डिफ़ॉल्ट npm के अलावा किसी और रजिस्ट्री से रिज़ॉल्व होता है। अपनी प्राइवेट रजिस्ट्री हो तो ठीक, वरना खतरनाक (dependency-confusion और mirror हमले)।',
              'Confirm you own that registry.', 'पक्का करें कि वह रजिस्ट्री आपकी है।');
          }
          if (m && !str(ent.integrity)) {
            C.add('pkg_lock_no_integrity', 'medium', 15, where, 'no integrity hash', 'No integrity hash recorded, so a tampered tarball would not be detected.', 'कोई integrity hash दर्ज नहीं, इसलिए छेड़छाड़ किया हुआ tarball पकड़ा नहीं जाएगा।',
              'Regenerate the lockfile with npm install.', 'npm install से lockfile दोबारा बनाएँ।');
          }
        }
      }
      if (ent.hasInstallScript) installScripts.push(name);
    }
    if (pk) {
      Object.keys(pk).slice(0, 20001).forEach(function (path) {
        if (path === '') return;
        var name = path.replace(/^.*node_modules\//, '');
        visit(name, pk[path]);
      });
    } else if (isObj(obj.dependencies)) {
      (function walk(deps, depth) {
        Object.keys(deps).slice(0, 5000).forEach(function (n) {
          visit(n, deps[n]);
          if (depth < 6 && isObj(deps[n]) && isObj(deps[n].dependencies)) walk(deps[n].dependencies, depth + 1);
        });
      })(obj.dependencies, 0);
    }
    if (installScripts.length) {
      installScripts.slice(0, 30).forEach(function (n) {
        C.add('pkg_lock_install_script', 'low', 3, n, 'hasInstallScript', 'This dependency runs an install script when installed.', 'यह निर्भरता इंस्टॉल के समय इंस्टॉल स्क्रिप्ट चलाती है।',
          'Review it, or install with --ignore-scripts.', 'इसकी समीक्षा करें, या --ignore-scripts से इंस्टॉल करें।');
      });
    }
    return { name: str(obj.name), version: str(obj.version), deps: total, hooks: installScripts.slice(0, 30).map(function (n) { return 'install script: ' + n; }) };
  }

  function scanRequirements(text, C) {
    var lines = text.split(/\r?\n/).slice(0, 20000);
    var deps = 0;
    var unpinned = [];
    lines.forEach(function (raw) {
      var line = raw.replace(/\s+#.*$/, '').trim();
      if (!line || line.charAt(0) === '#') return;
      var where = line.slice(0, 80);
      if (/^--?extra-index-url\b/i.test(line)) {
        C.add('pkg_extra_index', 'high', 35, where, line.slice(0, 100),
          '--extra-index-url adds a second package index. pip picks the highest version across all indexes, so an attacker can publish a higher-numbered package with your private name to PyPI (dependency confusion).',
          '--extra-index-url दूसरा पैकेज इंडेक्स जोड़ता है। pip सभी इंडेक्स में सबसे ऊँचा वर्ज़न चुनता है, इसलिए हमलावर आपके प्राइवेट नाम का ऊँचे नंबर वाला पैकेज PyPI पर डाल सकता है (dependency confusion)।',
          'Use a single --index-url that proxies PyPI, or pin hashes (--require-hashes).', 'PyPI को प्रॉक्सी करने वाला एक --index-url इस्तेमाल करें, या hash पिन करें (--require-hashes)।');
        return;
      }
      if (/^(?:-i|--index-url)\b/i.test(line)) {
        if (/http:\/\//i.test(line)) C.add('pkg_index_http', 'high', 30, where, line.slice(0, 100), 'The package index uses plain http.', 'पैकेज इंडेक्स सादे http का इस्तेमाल करता है।', 'Use an https index.', 'https इंडेक्स इस्तेमाल करें।');
        return;
      }
      if (/^--trusted-host\b/i.test(line)) {
        C.add('pkg_trusted_host', 'medium', 20, where, line.slice(0, 100), 'Disables TLS verification for a host, so downloads from it can be tampered with.', 'किसी होस्ट के लिए TLS सत्यापन बंद करता है, इसलिए उससे डाउनलोड में छेड़छाड़ हो सकती है।', 'Remove it and fix the certificate instead.', 'इसे हटाएँ और सर्टिफ़िकेट ठीक करें।');
        return;
      }
      if (/^-/.test(line) && !/^-e\b/.test(line)) return;
      var spec = line.replace(/^-e\s+/, '');
      if (/^(?:git\+|hg\+|svn\+|bzr\+|https?:\/\/|file:|\.{0,2}\/)/i.test(spec) || /\s@\s*(?:git\+|https?:\/\/)/.test(spec)) {
        C.add('pkg_url_dep', 'high', 30, where, spec.slice(0, 100), 'Installs code from a git repository or URL instead of PyPI. Nothing reviews it, and the branch can change.', 'PyPI की जगह git रिपॉज़िटरी या URL से कोड इंस्टॉल करता है। कोई समीक्षा नहीं, और ब्रांच बदल सकती है।', 'Pin a full commit hash.', 'पूरा commit hash पिन करें।');
        return;
      }
      var m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$/.exec(spec);
      if (!m) return;
      deps++;
      var name = m[1];
      var rest = m[2];
      checkName(C, name, name, 'pypi');
      if (!/==|===|@/.test(rest)) unpinned.push(name);
    });
    if (unpinned.length) {
      C.add('pkg_unpinned_py', 'low', 5, unpinned.slice(0, 8).join(', '), unpinned.length + ' requirement(s) without ==',
        'Requirements are not pinned to exact versions, so a malicious new release can be pulled in.', 'आवश्यकताएँ सटीक वर्ज़न पर पिन नहीं हैं, इसलिए नया ख़राब रिलीज़ खिंच सकता है।',
        'Pin with == (pip-compile --generate-hashes is ideal).', '== से पिन करें (pip-compile --generate-hashes सबसे अच्छा)।');
    }
    return { name: '', version: '', deps: deps, hooks: [] };
  }

  function scanManifest(input) {
    var text = String(input == null ? '' : input);
    if (!text.trim()) throw fail('empty', 'Nothing to scan');
    if (text.length > MAX_MANIFEST) throw fail('too_big', 'Input is larger than 5 MB');
    var C = new Collector();
    var kind;
    var meta;
    var obj = null;
    if (/^\s*[{[]/.test(text)) {
      try { obj = JSON.parse(text); } catch (e) { throw fail('bad_json', 'Looks like JSON but is not valid'); }
    }
    if (isObj(obj) && (obj.lockfileVersion != null || (isObj(obj.packages) && Object.keys(obj.packages)[0] === ''))) {
      kind = 'package-lock.json';
      meta = scanLock(obj, C);
      if (isObj(obj.packages) && isObj(obj.packages[''])) {
        var rootEnt = obj.packages[''];
        ['dependencies', 'devDependencies'].forEach(function (k) {
          if (isObj(rootEnt[k])) Object.keys(rootEnt[k]).slice(0, 2000).forEach(function (d) { specRisk(C, k + ': ' + d, d, rootEnt[k][d]); });
        });
      }
    } else if (isObj(obj)) {
      if (!(isObj(obj.dependencies) || isObj(obj.devDependencies) || isObj(obj.scripts) || obj.name != null || isObj(obj.optionalDependencies) || isObj(obj.peerDependencies))) throw fail('unrecognised', 'This JSON is not a package.json or package-lock.json');
      kind = 'package.json';
      meta = scanPackageJson(obj, C, 'package.json', true);
    } else if (Array.isArray(obj)) {
      throw fail('unrecognised', 'Expected package.json, package-lock.json or requirements.txt');
    } else {
      kind = 'requirements.txt';
      if (!/^[\s\S]*[A-Za-z0-9]/.test(text)) throw fail('unrecognised', 'Nothing recognisable');
      meta = scanRequirements(text, C);
    }
    var info = { kind: kind, ecosystem: kind === 'requirements.txt' ? 'pypi' : 'npm', name: meta.name, version: meta.version, dependencies: meta.deps, hooks: meta.hooks };
    return finish(C, info);
  }

  // ---- archive reading ----------------------------------------------------
  function cstr(buf, off, len) {
    var s = '';
    for (var i = 0; i < len; i++) {
      var c = buf[off + i];
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  function octal(buf, off, len) {
    if (buf[off] & 0x80) { // base-256 size (files > 8 GiB), not expected here
      var v = 0;
      for (var i = 1; i < len; i++) v = v * 256 + buf[off + i];
      return v;
    }
    var s = cstr(buf, off, len).trim();
    if (!s) return 0;
    var n = parseInt(s, 8);
    return isNaN(n) ? -1 : n;
  }

  function utf8(buf) { return new TextDecoder('utf-8').decode(buf); }

  function readTar(buf) {
    var entries = [];
    var pos = 0;
    var n = buf.length;
    var longName = null;
    var paxPath = null;
    var paxLink = null;
    while (pos + 512 <= n && entries.length < MAX_ENTRIES) {
      var zero = true;
      for (var z = 0; z < 512; z++) if (buf[pos + z] !== 0) { zero = false; break; }
      if (zero) break;
      var size = octal(buf, pos + 124, 12);
      if (size < 0 || pos + 512 + size > n) throw fail('bad_archive', 'Archive is truncated or corrupted');
      var typeflag = String.fromCharCode(buf[pos + 156] || 48);
      var name = cstr(buf, pos, 100);
      var link = cstr(buf, pos + 157, 100);
      if (cstr(buf, pos + 257, 5) === 'ustar') {
        var prefix = cstr(buf, pos + 345, 155);
        if (prefix) name = prefix + '/' + name;
      }
      var data = buf.subarray(pos + 512, pos + 512 + size);
      var next = pos + 512 + Math.ceil(size / 512) * 512;
      if (typeflag === 'L') { longName = utf8(data).replace(/\0+$/, ''); }
      else if (typeflag === 'K') { /* GNU long link name, ignored */ }
      else if (typeflag === 'x' || typeflag === 'g') {
        var txt = utf8(data);
        var re = /(\d+) ([^=]+)=([^\n]*)\n/g;
        var m;
        var guard = 0;
        while ((m = re.exec(txt)) !== null && guard++ < 200) {
          if (m[2] === 'path') paxPath = m[3];
          else if (m[2] === 'linkpath') paxLink = m[3];
        }
      } else {
        if (longName != null) { name = longName; longName = null; }
        if (paxPath != null) { name = paxPath; paxPath = null; }
        if (paxLink != null) { link = paxLink; paxLink = null; }
        entries.push({ name: name, size: size, type: typeflag, link: link, data: data });
      }
      pos = next;
    }
    return entries;
  }

  async function gunzip(bytes, limit) {
    if (typeof module === 'object' && typeof require === 'function') {
      try { return new Uint8Array(require('zlib').gunzipSync(bytes, { maxOutputLength: limit })); }
      catch (e) {
        if (e && (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError)) throw fail('too_big', 'Archive expands to more than ' + (limit / 1048576) + ' MB');
        throw fail('bad_archive', 'Could not decompress the archive');
      }
    }
    if (typeof DecompressionStream === 'undefined') throw fail('unsupported', 'This browser cannot decompress .tgz files');
    try {
      var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
      var reader = stream.getReader();
      var chunks = [];
      var total = 0;
      for (;;) {
        var r = await reader.read();
        if (r.done) break;
        total += r.value.length;
        if (total > limit) { await reader.cancel(); throw fail('too_big', 'Archive expands to more than ' + (limit / 1048576) + ' MB'); }
        chunks.push(r.value);
      }
      var out = new Uint8Array(total);
      var o = 0;
      chunks.forEach(function (c) { out.set(c, o); o += c.length; });
      return out;
    } catch (e) {
      if (e && e.code) throw e;
      throw fail('bad_archive', 'Could not decompress the archive');
    }
  }

  // ---- content rules ------------------------------------------------------
  var TEXT_EXT = /\.(?:js|cjs|mjs|jsx|ts|sh|bash|zsh|bat|cmd|ps1|vbs|py|pth|rb|pl|php|cfg|toml|ini|yml|yaml)$/i;
  var SPECIAL_NAMES = /(?:^|\/)(?:package\.json|setup\.py|setup\.cfg|pyproject\.toml|PKG-INFO|METADATA|entry_points\.txt|install|configure|Makefile)$/;
  var BENIGN_PTH = /(?:distutils-precedence|__editable__|-nspkg|easy-install|matplotlib-.*nspkg|a1_coverage)\.pth$|(?:^|\/)(?:distutils-precedence|easy-install)\.pth$/i;

  function snippet(text, m) {
    var s = Math.max(0, m.index - 30);
    var e = Math.min(text.length, m.index + m[0].length + 40);
    return ((s > 0 ? '…' : '') + text.slice(s, e).replace(/\s+/g, ' ') + (e < text.length ? '…' : '')).slice(0, 180);
  }

  var R = {
    decodeExec: [
      /\beval\s*\(\s*(?:atob|Buffer\.from|unescape|String\.fromCharCode)\b/,
      /\bnew\s+Function\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode)\b/,
      /\beval\s*\(\s*(?:[\w$]+\.)*(?:decode|decrypt|decompress|inflate|unzip|b64decode)\w*\s*\(/,
      /\b(?:exec|eval)\s*\(\s*(?:__import__\(\s*['"]base64['"]\)|base64\.|zlib\.|marshal\.|codecs\.|bytes\.fromhex|binascii\.)/,
      /\b(?:exec|eval)\s*\(\s*compile\s*\(\s*(?:base64|zlib|marshal|codecs|bytes\.fromhex|binascii|requests|urllib|__import__)/,
      /\bexec\s*\(\s*(?:requests\.(?:get|post)|urllib\.request\.urlopen|urlopen)\b/,
      /\bexec\s*\(\s*['"]{2}\s*\.\s*join\s*\(\s*(?:chr|map)\b/,
    ],
    shellDownload: [
      /(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|system|popen|Popen|call|run|check_output)\s*\(\s*[`'"][^`'"\n]{0,200}?\b(?:curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin|mshta|nc\s+-e)\b/i,
      /(?:os\.system|subprocess\.\w+|os\.popen)\s*\(\s*[^)\n]{0,200}?\b(?:curl|wget|certutil)\b/i,
      /\bpowershell(?:\.exe)?\b[^\n]{0,200}?(?:DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bIEX\b|-enc(?:odedcommand)?\b|https?:\/\/)/i,
    ],
    remoteExec: /\b(?:curl|wget)\b[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*iex\b|(?:^|\s)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}|Invoke-Expression\s*\(?\s*(?:New-Object|iwr|Invoke-WebRequest)/i,
    reverseShell: /\/dev\/tcp\/|bash\s+-i\s*>&|\bnc\s+(?:-\w+\s+)*-e\s|\bsocat\b[^\n]{0,60}exec:|['"`]\/bin\/(?:ba)?sh['"`]\s*,\s*\[?\s*['"`]-i['"`]|pty\.spawn\s*\(\s*['"`]\/bin\/(?:ba)?sh|os\.dup2\s*\([^)]*\)\s*;?[\s\S]{0,80}os\.dup2/,
    miner: /stratum\+(?:tcp|ssl):\/\/|\bxmrig\b|coinhive|cryptonight|minexmr|supportxmr|nanopool\.org|monerohash|c3pool\.com/i,
    exfil: /discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|\boast\.(?:pro|live|site|me|fun)\b|burpcollaborator|transfer\.sh|pastebin\.com\/raw|\.trycloudflare\.com|canarytokens|oastify\.com/i,
    envDumpJs: /JSON\.stringify\(\s*process\.env|Object\.(?:entries|keys|values)\(\s*process\.env|JSON\.stringify\(\s*\{[^}]{0,80}\.\.\.\s*process\.env/,
    envDumpPy: /json\.dumps\(\s*(?:dict\()?os\.environ|os\.environ\.(?:items|copy|keys|values)\(\)|\bdict\(\s*os\.environ\s*\)|str\(\s*os\.environ\s*\)/,
    netJs: /\b(?:https?\.(?:request|get)|fetch\s*\(|axios|XMLHttpRequest|dns\.(?:lookup|resolve\w*)|net\.connect|new\s+WebSocket|\bgot\s*\(|node-fetch|\brequest\s*\()/,
    netPy: /\b(?:requests\.(?:post|get|put)|urllib\.request|http\.client|socket\.socket|httpx\.|aiohttp|smtplib|ftplib|dns\.resolver|socket\.gethostbyname)/,
    credStrong: /(?:readFile(?:Sync)?|createReadStream|readdir(?:Sync)?|copyFile(?:Sync)?|\bcat\s|\bopen\s*\(|read_text|read_bytes|shutil\.copy\w*|glob\.glob|os\.walk|expanduser)\s*\(?[^\n]{0,140}?(?:\.ssh\b|id_rsa|id_ed25519|\.aws[\\/]credentials|\.aws\b|\.config[\\/]gcloud|\.kube[\\/]config|\.git-credentials|Login Data|Local Extension Settings|wallet\.dat|\.gnupg|nkbihfbeogaeaoehlefnkodbefgpgknn|Exodus|Electrum)/i,
    credWeak: /(?:readFile(?:Sync)?|createReadStream|copyFile(?:Sync)?|\bcat\s|\bopen\s*\(|read_text|read_bytes|shutil\.copy\w*|expanduser)\s*\(?[^\n]{0,140}?(?:\.npmrc|\.pypirc|\.netrc|\.docker[\\/]config)/i,
    persistence: /(?:appendFile(?:Sync)?|writeFile(?:Sync)?|createWriteStream|>>|\btee\s|\.write\s*\()[^\n]{0,150}?(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys|LaunchAgents|\/etc\/cron|systemd[\\/]system|CurrentVersion[\\/]+Run|Startup[\\/])|\b(?:crontab\s+-|schtasks\s+\/create|launchctl\s+load|systemctl\s+enable)\b/i,
    worm: [/(?:exec|execSync|spawn|spawnSync|system|execFile)\s*\(\s*[`'"][^`'"\n]{0,40}\bnpm\s+(?:publish|token\s+create)\b|-\/npm\/v1\/tokens|-\/user\/org\.couchdb\.user/, /(?:writeFile\w*|appendFile\w*|mkdir\w*)\s*\([^\n]{0,100}\.github[\\/]workflows/],
    obfuscJs: [/\b_0x[0-9a-f]{4,6}\b/g, /\[\]\[\(!\[\]\+\[\]\)/],
    obfuscPy: [/(?:\\x[0-9a-fA-F]{2}){40,}/, /(?:chr\(\s*\d+\s*\)\s*\+\s*){20,}/, /__pyarmor__|pytransform/],
    blob: /[A-Za-z0-9+/]{2000,}={0,2}/,
    evade: /VBoxService|vmtoolsd|wireshark|procmon|sandboxie|vboxguest|\bvmware\b[^\n]{0,60}\b(?:exit|return|abort)\b/i,
    cmdclass: /\bcmdclass\s*=|class\s+\w+\(\s*(?:install|develop|egg_info|build_py|build_ext)\s*\)/,
    webhookRecon: /(?:ipinfo\.io|api\.ipify\.org|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com)/i,
    npmCmd: /process\.binding\(|process\.dlopen\(/,
  };

  function scanText(path, text, C, flags) {
    var m;
    var isPy = /\.(?:py|pth)$/i.test(path) || /(?:^|\/)(?:setup\.py)$/.test(path);
    var isJs = /\.(?:js|cjs|mjs|jsx|ts)$/i.test(path);

    // hidden Unicode (Trojan Source and tag-character smuggling)
    var hidden = 0;
    var bidi = 0;
    for (var i = 0; i < text.length && i < 400000; i++) {
      var cp = text.charCodeAt(i);
      if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
      else if (cp === 0x200b || (cp >= 0x2060 && cp <= 0x2064) || (cp === 0xfeff && i > 0)) hidden++;
      else if (cp === 0xdb40) hidden++;
    }
    if (bidi || hidden) {
      C.add('pkg_hidden_chars', bidi ? 'high' : 'medium', bidi ? 40 : 15, path, (bidi ? bidi + ' bidi-control' : '') + (bidi && hidden ? ', ' : '') + (hidden ? hidden + ' invisible' : '') + ' characters',
        'Source contains invisible or text-direction control characters ("Trojan Source"), which make code look different to a reviewer than to the machine.',
        'सोर्स में अदृश्य या टेक्स्ट-डायरेक्शन कंट्रोल अक्षर हैं ("Trojan Source"), जो समीक्षक को मशीन से अलग कोड दिखाते हैं।',
        'Strip them and re-read the code.', 'इन्हें हटाकर कोड दोबारा पढ़ें।');
    }

    R.decodeExec.some(function (re) { m = re.exec(text); return !!m; });
    if (m) {
      C.add('pkg_decode_exec', 'critical', 45, path, snippet(text, m),
        'Decodes hidden data and runs it (eval/exec of base64, zlib or downloaded text). Legitimate libraries do not need to hide the code they run.',
        'छुपे डेटा को डिकोड करके चलाता है (base64, zlib या डाउनलोड किए टेक्स्ट पर eval/exec)। असली लाइब्रेरी को अपना चलने वाला कोड छुपाने की ज़रूरत नहीं।',
        'Do not use the package. Report it to the registry.', 'पैकेज इस्तेमाल न करें। रजिस्ट्री को रिपोर्ट करें।');
      flags.bad = true;
    }
    m = R.remoteExec.exec(text);
    if (m) {
      C.add('pkg_remote_exec', 'critical', 45, path, snippet(text, m),
        'Downloads code and pipes it straight into a shell (curl | sh, iex, encoded PowerShell).', 'कोड डाउनलोड करके सीधे शेल में पाइप करता है (curl | sh, iex, encoded PowerShell)।',
        'Do not use the package.', 'पैकेज इस्तेमाल न करें।');
      flags.bad = true;
    } else {
      R.shellDownload.some(function (re) { m = re.exec(text); return !!m; });
      if (m) {
        C.add('pkg_shell_download', 'high', 35, path, snippet(text, m),
          'Spawns a shell that downloads or runs something with curl/wget/PowerShell.', 'ऐसा शेल चलाता है जो curl/wget/PowerShell से कुछ डाउनलोड या चलाता है।',
          'Read what it fetches. Prefer packages that bundle their binaries and verify checksums.', 'देखें कि क्या लाता है। जो पैकेज बाइनरी साथ रखते और checksum जाँचते हैं उन्हें चुनें।');
        flags.bad = true;
      }
    }
    m = R.reverseShell.exec(text);
    if (m) {
      C.add('pkg_reverse_shell', 'critical', 50, path, snippet(text, m), 'Contains a reverse-shell pattern that gives a remote attacker a command line on your machine.', 'रिवर्स-शेल पैटर्न है जो दूर बैठे हमलावर को आपकी मशीन पर कमांड लाइन देता है।',
        'Do not use the package. Treat the machine as compromised if it already ran.', 'पैकेज इस्तेमाल न करें। पहले चल चुका हो तो मशीन को compromised मानें।');
      flags.bad = true;
    }
    m = R.miner.exec(text);
    if (m) {
      C.add('pkg_miner', 'critical', 45, path, snippet(text, m), 'References a cryptocurrency miner or mining pool.', 'क्रिप्टोकरेंसी माइनर या माइनिंग पूल का संदर्भ है।', 'Do not use the package.', 'पैकेज इस्तेमाल न करें।');
      flags.bad = true;
    }
    m = R.exfil.exec(text);
    if (m) {
      C.add('pkg_exfil_endpoint', 'high', 35, path, snippet(text, m),
        'Talks to a typical data-exfiltration endpoint (Discord/Telegram webhook, request catcher, tunnel, out-of-band test server).',
        'डेटा चोरी के आम endpoint (Discord/Telegram webhook, request catcher, tunnel, out-of-band टेस्ट सर्वर) से बात करता है।',
        'Block the domain and check what the package could have sent.', 'डोमेन ब्लॉक करें और जाँचें कि पैकेज क्या भेज सकता था।');
      flags.bad = true;
    }
    var envDump = isPy ? R.envDumpPy.test(text) : R.envDumpJs.test(text);
    if (envDump && (isPy ? R.netPy.test(text) : R.netJs.test(text))) {
      C.add('pkg_env_exfil', 'high', 40, path, 'dumps environment variables and has network code',
        'Collects all environment variables (API keys, cloud and CI tokens) and also contains network code.', 'सभी environment variables (API keys, क्लाउड और CI टोकन) इकट्ठा करता है और नेटवर्क कोड भी है।',
        'Do not use the package. Rotate secrets that were in the environment where it ran.', 'पैकेज इस्तेमाल न करें। जहाँ चला वहाँ के environment के सीक्रेट रोटेट करें।');
      flags.bad = true;
    }
    var hasNet = (isPy ? R.netPy : R.netJs).test(text) || R.exfil.test(text);
    m = R.credStrong.exec(text);
    var weak = m ? null : R.credWeak.exec(text);
    if (m || (weak && (hasNet || flags.installTime))) {
      var hit = m || weak;
      if (hasNet || flags.installTime) {
        C.add('pkg_cred_read', m ? 'critical' : 'high', m ? 45 : 30, path, snippet(text, hit),
          'Reads credential or wallet locations (SSH keys, .npmrc/.pypirc, cloud credentials, browser data, crypto wallets) in code that also talks to the network or runs at install time.', 'ऐसे कोड में क्रेडेंशियल या वॉलेट की जगहें (SSH कुंजी, .npmrc/.pypirc, क्लाउड क्रेडेंशियल, ब्राउज़र डेटा, क्रिप्टो वॉलेट) पढ़ता है जो नेटवर्क से भी बात करता है या इंस्टॉल के समय चलता है।',
          'Do not use the package. Rotate those credentials.', 'पैकेज इस्तेमाल न करें। वे क्रेडेंशियल रोटेट करें।');
        flags.bad = true;
      } else {
        C.add('pkg_cred_access', 'medium', 12, path, snippet(text, hit),
          'Reads credential locations such as SSH keys or cloud credentials. Tools like SSH clients and package managers do this legitimately, so check that this package has a reason to.', 'SSH कुंजी या क्लाउड क्रेडेंशियल जैसी जगहें पढ़ता है। SSH क्लाइंट और पैकेज मैनेजर जैसे टूल यह वैध रूप से करते हैं, इसलिए जाँचें कि इस पैकेज को इसकी वजह है।',
          'Make sure the package has a reason to read these.', 'पक्का करें कि पैकेज के पास इन्हें पढ़ने की वजह है।');
      }
    }
    m = R.persistence.exec(text);
    if (m) {
      C.add('pkg_persistence', 'critical', 45, path, snippet(text, m),
        'Writes to shell start-up files, cron, launch agents, services or SSH authorized_keys so it keeps running or keeps access after install.', 'शेल स्टार्टअप फ़ाइलों, cron, launch agents, services या SSH authorized_keys में लिखता है ताकि इंस्टॉल के बाद भी चलता या पहुँच बनाए रखता रहे।',
        'Do not use the package. Check those files for added entries.', 'पैकेज इस्तेमाल न करें। उन फ़ाइलों में जुड़ी एंट्री जाँचें।');
      flags.bad = true;
    }
    R.worm.some(function (re) { m = re.exec(text); return !!m; });
    if (m) {
      C.add('pkg_worm', 'high', 40, path, snippet(text, m),
        'Code that publishes packages, creates npm tokens or writes CI workflows. A dependency has no reason to do this; it is how supply-chain worms spread.', 'पैकेज प्रकाशित करने, npm टोकन बनाने या CI workflow लिखने वाला कोड। किसी निर्भरता को इसकी कोई ज़रूरत नहीं; supply-chain worm ऐसे ही फैलते हैं।',
        'Do not use the package. Rotate npm and CI tokens.', 'पैकेज इस्तेमाल न करें। npm और CI टोकन रोटेट करें।');
      flags.bad = true;
    }
    var obf = isPy ? R.obfuscPy : R.obfuscJs;
    var obfHit = null;
    var cnt = (text.match(obf[0]) || []).length;
    if (!isPy && cnt >= 30) obfHit = cnt + ' obfuscator-style identifiers';
    else {
      for (var k = isPy ? 0 : 1; k < obf.length; k++) {
        m = obf[k].exec(text);
        if (!m) continue;
        if (isPy && /^(?:\\x[0-9a-fA-F]{2})+$/.test(m[0]) && new Set(m[0].match(/\\x[0-9a-fA-F]{2}/g)).size < 12) continue; // repeated bytes = a table, not a payload
        obfHit = snippet(text, m).slice(0, 80);
        break;
      }
    }
    if (obfHit) {
      C.add('pkg_obfuscated', 'high', 30, path, obfHit, 'Heavily obfuscated code (hex-named identifiers, escaped strings, JSFuck or packers). Open-source libraries ship readable code.', 'भारी obfuscated कोड (hex नाम वाले identifier, escaped स्ट्रिंग, JSFuck या packer)। ओपन-सोर्स लाइब्रेरी पढ़ने लायक कोड भेजती हैं।',
        'Treat as untrusted. Ask the maintainer for readable source.', 'अविश्वसनीय मानें। मेंटेनर से पढ़ने लायक सोर्स माँगें।');
      flags.obf = true;
    }
    if ((isJs || isPy) && R.blob.test(text)) {
      C.add('pkg_blob', 'low', 5, path, 'long base64-like blob', 'Contains a very long base64-like blob, a common place to hide a payload.', 'बहुत लंबा base64 जैसा ब्लॉब है, पेलोड छुपाने की आम जगह।',
        'Decode and inspect it.', 'डिकोड करके जाँचें।');
    }
    m = R.evade.exec(text);
    if (m) {
      C.add('pkg_sandbox_evasion', 'medium', 20, path, snippet(text, m), 'Looks for virtual machines or analysis tools, which malware does to avoid being studied.', 'वर्चुअल मशीन या विश्लेषण टूल खोजता है, जो मैलवेयर अपनी जाँच से बचने के लिए करता है।',
        'Be suspicious of the whole package.', 'पूरे पैकेज पर शक करें।');
    }
    if (isPy && /(?:^|\/)setup\.py$/.test(path) && R.cmdclass.test(text)) {
      C.add('pkg_py_cmdclass', 'medium', 20, path, 'custom install command class', 'setup.py overrides the install/develop command, so extra code runs on `pip install`.', 'setup.py install/develop कमांड बदलता है, इसलिए `pip install` पर अतिरिक्त कोड चलता है।',
        'Read that code. Prefer wheels, which cannot run setup code.', 'वह कोड पढ़ें। wheel को प्राथमिकता दें, उनमें setup कोड नहीं चलता।');
    }
    if (flags.bad && R.webhookRecon.test(text)) {
      C.add('pkg_ip_recon', 'medium', 15, path, 'looks up the machine\'s public IP', 'Looks up the machine\'s public IP, usually to tag stolen data with its victim.', 'मशीन का पब्लिक IP खोजता है, आमतौर पर चुराए डेटा पर पीड़ित का टैग लगाने के लिए।',
        'Treat as part of the other findings.', 'इसे बाक़ी निष्कर्षों का हिस्सा मानें।');
    }
  }

  var EXEC_EXT = /\.(?:exe|dll|scr|bat|cmd|ps1|vbs|msi|com|jar)$/i;
  var SHADOW = ['pip', 'pip3', 'python', 'python3', 'sudo', 'ssh', 'git', 'npm', 'node', 'curl', 'bash', 'sh', 'ls', 'cat', 'su'];

  function badPath(name) {
    return /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(name) || /^[\\/]/.test(name) || /^[A-Za-z]:[\\/]/.test(name);
  }

  // ---- archive scanning ---------------------------------------------------
  async function scanArchive(input, opts) {
    opts = opts || {};
    var bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (bytes.length > MAX_FILE) throw fail('too_big', 'File is larger than ' + (MAX_FILE / 1048576) + ' MB');
    if (bytes.length < 20) throw fail('not_archive', 'Not a package archive');

    var files = []; // {path, size, type, link, get: async () => Uint8Array|null}
    var format;
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      var tar = await gunzip(bytes, MAX_TOTAL);
      format = 'tar.gz';
      readTar(tar).forEach(function (e) {
        files.push({ path: e.name, size: e.size, type: e.type, link: e.link, get: async function () { return e.data; } });
      });
    } else if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
      var A = getApkScan();
      if (!A) throw fail('unsupported', 'ZIP support is not loaded');
      var zip;
      try { zip = A.readZip(bytes); } catch (e) { throw fail('bad_archive', 'The ZIP file is damaged'); }
      format = 'zip';
      var budget = { left: MAX_TOTAL };
      zip.entries.forEach(function (e) {
        if (/\/$/.test(e.name)) return;
        files.push({ path: e.name, size: e.usize, type: '0', link: '', get: async function () { return await A.entryData(bytes, e, budget); } });
      });
    } else if (bytes.length > 512 && cstr(bytes, 257, 5) === 'ustar') {
      format = 'tar';
      readTar(bytes).forEach(function (e) {
        files.push({ path: e.name, size: e.size, type: e.type, link: e.link, get: async function () { return e.data; } });
      });
    } else {
      throw fail('not_archive', 'Not a .tgz, .tar, .whl or .zip file');
    }
    if (!files.length) throw fail('empty_archive', 'The archive has no files');
    if (files.length > MAX_ENTRIES) throw fail('bad_archive', 'Too many files');

    var C = new Collector();
    var meta = { ecosystem: 'unknown', name: '', version: '', hooks: [] };
    var installFiles = [];
    var rootPrefix = '';

    // npm tarballs wrap everything in one folder (usually "package/")
    var tops = {};
    files.forEach(function (f) { var t = f.path.split('/')[0]; tops[t] = true; });
    var topKeys = Object.keys(tops);
    if (topKeys.length === 1 && files.some(function (f) { return f.path.split('/').length > 1; })) rootPrefix = topKeys[0] + '/';
    function rel(p) { return rootPrefix && p.indexOf(rootPrefix) === 0 ? p.slice(rootPrefix.length) : p; }

    // structure checks
    files.forEach(function (f) {
      if (badPath(f.path)) {
        C.add('pkg_path_traversal', 'high', 35, f.path.slice(0, 80), f.path.slice(0, 100),
          'An entry path escapes the package folder ("../" or absolute). Extractors that do not guard against this can overwrite files anywhere on your disk.',
          'किसी एंट्री का पाथ पैकेज फ़ोल्डर से बाहर निकलता है ("../" या absolute)। जो एक्सट्रैक्टर इससे नहीं बचते वे आपकी डिस्क पर कहीं भी फ़ाइल बदल सकते हैं।',
          'Do not extract it with an unguarded tool.', 'इसे बिना सुरक्षा वाले टूल से एक्सट्रैक्ट न करें।');
      }
      if ((f.type === '2' || f.type === '1') && f.link && (/^[\\/]/.test(f.link) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(f.link))) {
        C.add('pkg_symlink', 'high', 30, f.path.slice(0, 80), f.path + ' → ' + f.link,
          'A symlink points outside the package (absolute path or "../"). Later writes through it can land in files you did not expect.', 'एक symlink पैकेज के बाहर इशारा करता है (absolute पाथ या "../")। उसके ज़रिये बाद में की गई लिखाई अनपेक्षित फ़ाइलों में जा सकती है।',
          'Do not extract it with an unguarded tool.', 'इसे बिना सुरक्षा वाले टूल से एक्सट्रैक्ट न करें।');
      }
    });

    var fileMap = {};
    files.forEach(function (f) { fileMap[rel(f.path)] = f; });

    // metadata
    var pj = fileMap['package.json'];
    var txtBudget = MAX_TEXT_BUDGET;
    if (pj) {
      var pd = await pj.get();
      if (pd && pd.length < MAX_TEXT_FILE) {
        try {
          var obj = JSON.parse(utf8(pd));
          if (isObj(obj)) {
            meta.ecosystem = 'npm';
            var sm = scanPackageJson(obj, C, 'package.json', false);
            meta.name = sm.name; meta.version = sm.version; meta.hooks = sm.hooks; meta.deps = sm.deps;
            checkInstallScripts(new Collector(), '', obj.scripts, installFiles);
          }
        } catch (e) { /* unreadable package.json, ignore */ }
      }
    }
    var distMeta = files.filter(function (f) { return /\.dist-info\/METADATA$/.test(f.path) || /(?:^|\/)PKG-INFO$/.test(f.path); })[0];
    if (distMeta) {
      var md = await distMeta.get();
      if (md && md.length < MAX_TEXT_FILE) {
        var mt = utf8(md);
        var nm = /^Name:\s*(.+)$/m.exec(mt);
        var vm = /^Version:\s*(.+)$/m.exec(mt);
        meta.ecosystem = 'pypi';
        if (nm) { meta.name = nm[1].trim(); checkName(C, 'METADATA', meta.name, 'pypi'); }
        if (vm) meta.version = vm[1].trim();
        var req = mt.match(/^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)/gm) || [];
        req.slice(0, 500).forEach(function (r) { var dn = r.replace(/^Requires-Dist:\s*/, ''); checkName(C, 'Requires-Dist: ' + dn, dn, 'pypi'); });
      }
    } else if (!pj && files.some(function (f) { return /(?:^|\/)setup\.py$/.test(f.path); })) meta.ecosystem = 'pypi';

    // entry points that shadow system commands
    var ep = files.filter(function (f) { return /\.dist-info\/entry_points\.txt$/.test(f.path) || /\.egg-info\/entry_points\.txt$/.test(f.path); })[0];
    if (ep) {
      var ed = await ep.get();
      if (ed && ed.length < MAX_TEXT_FILE) {
        var sec = /\[console_scripts\]([\s\S]*?)(?:\n\[|$)/.exec(utf8(ed));
        if (sec) sec[1].split('\n').forEach(function (l) {
          var nme = l.split('=')[0].trim();
          var own = String(meta.name || '').toLowerCase().replace(/[-_.]+/g, '-');
          var ownCmd = own && new RegExp('^' + own.replace(/[^a-z0-9-]/g, '\\$&') + '[0-9.]*$').test(nme.toLowerCase());
          if (nme && SHADOW.indexOf(nme.toLowerCase().replace(/[0-9.]+$/, '')) !== -1 && !ownCmd) {
            C.add('pkg_shadow_command', 'high', 35, 'entry_points.txt', nme, 'Installs a command named "' + nme + '", shadowing a real system tool so it runs instead of the genuine one.', '"' + nme + '" नाम का कमांड इंस्टॉल करता है, जो असली सिस्टम टूल की जगह चलने लगता है।',
              'Do not install. Check what that command does.', 'इंस्टॉल न करें। देखें कि वह कमांड क्या करता है।');
          }
        });
      }
    }

    // order: install-time files first so the budget is spent where it matters
    var paths = Object.keys(fileMap);
    function priority(p) {
      if (installFiles.indexOf(p) !== -1 || /(?:^|\/)setup\.py$/.test(p) || /\.pth$/.test(p)) return 0;
      if (SPECIAL_NAMES.test(p)) return 1;
      return 2;
    }
    paths.sort(function (a, b) { return priority(a) - priority(b); });

    var installHit = false;
    var skipped = 0;
    var binaries = [];
    var executables = [];
    for (var i = 0; i < paths.length; i++) {
      var p = paths[i];
      var f = fileMap[p];
      if (f.type !== '0' && f.type !== '\0' && f.type !== '7') continue;
      var isText = TEXT_EXT.test(p) || SPECIAL_NAMES.test(p) || /(?:^|\/)bin\/[^/.]+$/.test(p);
      var head = null;
      if (EXEC_EXT.test(p) && !/\.jar$/i.test(p) && !/(?:^|\/)(?:cli|gui|t|w)(?:-?(?:32|64(?:-arm)?|arm64))\.exe$/i.test(p) && !(/\.(?:bat|cmd|ps1|vbs)$/i.test(p) && /(?:^|\/)(?:docs?|tests?|testing|examples?|samples?|benchmarks?|scripts?|tools?|\.github)\//i.test(p)) && !/(?:^|\/)make\.bat$/i.test(p)) executables.push(p);
      if (!isText) {
        if (f.size >= 4 && !/\.(?:exe|node|so|dylib|dll|wasm|png|jpg|jpeg|gif|ico|woff2?|ttf|otf|eot|map|json|md|txt|svg|d\.ts|lock|zip|gz|tgz|br)$/i.test(p) && !/\.so\.\d/.test(p)) {
          var d0 = await f.get();
          if (d0 && d0.length >= 4) {
            head = d0;
            if ((d0[0] === 0x7f && d0[1] === 0x45 && d0[2] === 0x4c && d0[3] === 0x46) || (d0[0] === 0x4d && d0[1] === 0x5a) || (d0[0] === 0xcf && d0[1] === 0xfa && d0[2] === 0xed && d0[3] === 0xfe)) binaries.push(p);
          }
        }
        continue;
      }
      if (f.size > MAX_TEXT_FILE || txtBudget <= 0) { skipped++; continue; }
      var data = await f.get();
      if (!data) { skipped++; continue; }
      if (data.length >= 4 && ((data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) || (data[0] === 0x4d && data[1] === 0x5a) || (data[0] === 0xcf && data[1] === 0xfa && data[2] === 0xed && data[3] === 0xfe))) {
        binaries.push(p); // an executable hiding behind a script-like name
        continue;
      }
      txtBudget -= data.length;
      var text = utf8(data);
      var flags = { bad: false, obf: false };
      var before = C.list.length;
      if (/\.pth$/i.test(p)) {
        var lines = text.split('\n').filter(function (l) { return /^\s*import\s/.test(l) || /\bexec\s*\(/.test(l); });
        if (lines.length && !BENIGN_PTH.test(p)) {
          C.add('pkg_pth', 'high', 40, p, lines[0].slice(0, 140), 'A .pth file with executable code runs every time Python starts, in every program, with no import needed. Attackers use it for stealthy persistence.', '.pth फ़ाइल में चलने वाला कोड हर बार Python शुरू होने पर, हर प्रोग्राम में, बिना import के चलता है। हमलावर इसे छुपी हुई persistence के लिए इस्तेमाल करते हैं।',
            'Do not install. Inspect the .pth line.', 'इंस्टॉल न करें। .pth की लाइन जाँचें।');
          flags.bad = /exec|base64|b64|__import__/.test(lines.join(' '));
        }
      }
      if (/(?:^|\/)package\.json$/.test(p) && p !== 'package.json') continue; // nested manifests are data
      flags.installTime = installFiles.indexOf(p) !== -1 || /(?:^|\/)setup\.py$/.test(p) || /\.pth$/i.test(p);
      scanText(p, text, C, flags);
      if (C.list.length > before && (installFiles.indexOf(p) !== -1 || /(?:^|\/)setup\.py$/.test(p) || /\.pth$/i.test(p)) && (flags.bad || flags.obf)) installHit = true;
    }

    if (executables.length) {
      C.add('pkg_executable', 'medium', 15, executables[0], executables.slice(0, 3).join(', '), 'Ships Windows executables or scripts (.exe, .dll, .bat, .ps1 ...). Some packages bundle tools, but this is also how malware is delivered.', 'Windows executables या scripts (.exe, .dll, .bat, .ps1 ...) साथ भेजता है। कुछ पैकेज टूल बंडल करते हैं, पर मैलवेयर भी ऐसे ही पहुँचाया जाता है।',
        'Check that the binaries match the project\'s official releases.', 'जाँचें कि बाइनरी प्रोजेक्ट की आधिकारिक रिलीज़ से मेल खाती हैं।');
    }
    if (binaries.length) {
      C.add('pkg_binary', 'medium', 20, binaries[0], binaries.slice(0, 3).join(', '), 'Contains native executable files that are not normal addons (.node/.so). Hard to audit and can run when launched.', 'ऐसी native executable फ़ाइलें हैं जो सामान्य addon (.node/.so) नहीं हैं। जाँचना कठिन है और चलाने पर चल सकती हैं।',
        'Compare hashes with the official release.', 'आधिकारिक रिलीज़ से hash मिलाएँ।');
    }
    if (installHit) {
      C.add('pkg_install_exec', 'critical', 30, 'install-time', 'suspicious code runs automatically at install', 'Suspicious code sits in a file that runs automatically at install time (install hook, setup.py or .pth). You would be infected by simply installing it.', 'संदिग्ध कोड ऐसी फ़ाइल में है जो इंस्टॉल के समय अपने-आप चलती है (install hook, setup.py या .pth)। सिर्फ़ इंस्टॉल करने से ही संक्रमण हो जाएगा।',
        'Do not install. If you already did, treat the machine and its secrets as exposed.', 'इंस्टॉल न करें। कर चुके हों तो मशीन और उसके सीक्रेट उजागर मानें।');
    }
    if (skipped) {
      C.add('pkg_scan_partial', 'low', 3, '', skipped + ' file(s) too large or over the scan budget', 'Some large files were not read, so the result may miss things in them.', 'कुछ बड़ी फ़ाइलें पढ़ी नहीं गईं, इसलिए उनमें की चीज़ें छूट सकती हैं।',
        'Review those files manually.', 'उन फ़ाइलों को हाथ से जाँचें।');
    }

    var res = finish(C, {
      format: format, ecosystem: meta.ecosystem, name: meta.name, version: meta.version, files: files.length, size: bytes.length,
      hooks: meta.hooks, installFiles: installFiles.slice(0, 10), fileName: opts.fileName || '', sha256: '',
    });
    if (!opts.skipHash) res.info.sha256 = await sha256Hex(bytes);
    return res;
  }

  async function sha256Hex(buf) {
    var subtle = (typeof crypto !== 'undefined' && crypto.subtle) || (typeof require === 'function' ? require('crypto').webcrypto.subtle : null);
    if (!subtle) return '';
    var h = new Uint8Array(await subtle.digest('SHA-256', buf));
    return Array.prototype.map.call(h, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  return { scanManifest: scanManifest, scanArchive: scanArchive, lookalike: lookalike, readTar: readTar, osa: osa, VERSION: VERSION, MAX_FILE: MAX_FILE };
});
