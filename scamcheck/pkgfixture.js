'use strict';
// Test helper: builds small npm tarballs, sdists and wheels in memory.
const zlib = require('node:zlib');
const { buildZip } = require('./apkfixture.js');

function field(buf, off, len, s) { Buffer.from(s, 'latin1').copy(buf, off, 0, len); }

function header(name, size, type, link, opts = {}) {
  const h = Buffer.alloc(512);
  field(h, 0, 100, name);
  field(h, 100, 8, '0000644\0');
  field(h, 108, 8, '0000000\0');
  field(h, 116, 8, '0000000\0');
  field(h, 124, 12, size.toString(8).padStart(11, '0') + '\0');
  field(h, 136, 12, '00000000000\0');
  h.fill(0x20, 148, 156);
  h[156] = (type || '0').charCodeAt(0);
  if (link) field(h, 157, 100, link);
  field(h, 257, 6, 'ustar\0');
  field(h, 263, 2, '00');
  if (opts.prefix) field(h, 345, 155, opts.prefix);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += h[i];
  field(h, 148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
  return h;
}

function pad(b) { const r = (512 - (b.length % 512)) % 512; return Buffer.concat([b, Buffer.alloc(r)]); }

// files: [{name, data, type?, link?, pax?: true, prefix?}]
function buildTar(files) {
  const parts = [];
  for (const f of files) {
    const data = Buffer.from(f.data || '');
    let name = f.name;
    if (f.pax) {
      const rec = ' path=' + f.name + '\n';
      let len = rec.length + String(rec.length).length;
      if (String(len).length !== String(rec.length).length) len++;
      const body = Buffer.from(len + rec);
      parts.push(header('PaxHeader/x', body.length, 'x'), pad(body));
      name = f.name.slice(0, 50);
    }
    parts.push(header(name, data.length, f.type || '0', f.link || '', { prefix: f.prefix }), pad(data));
  }
  parts.push(Buffer.alloc(1024));
  return new Uint8Array(Buffer.concat(parts));
}

const tgz = (files) => new Uint8Array(zlib.gzipSync(buildTar(files)));

function npmPkg(pkgJson, extra = []) {
  return tgz([{ name: 'package/package.json', data: JSON.stringify(pkgJson) }, ...extra.map((f) => ({ ...f, name: 'package/' + f.name }))]);
}

function wheel(name, version, files = [], entryPoints) {
  const base = name.replace(/-/g, '_') + '-' + version;
  const list = [
    { name: base + '.dist-info/METADATA', data: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n` },
    { name: base + '.dist-info/WHEEL', data: 'Wheel-Version: 1.0\n' },
    ...files,
  ];
  if (entryPoints) list.push({ name: base + '.dist-info/entry_points.txt', data: entryPoints });
  return buildZip(list);
}

module.exports = { buildTar, tgz, npmPkg, wheel };
