'use strict';
// Test helper: builds small synthetic APKs (ZIP + binary AndroidManifest.xml) in memory.
const zlib = require('node:zlib');

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }

// ---- Binary XML -----------------------------------------------------------
const RES = { name: 0x01010003, label: 0x01010001, permission: 0x01010006, exported: 0x01010010, debuggable: 0x0101000f,
  versionCode: 0x0101021b, versionName: 0x0101021c, minSdkVersion: 0x0101020c, targetSdkVersion: 0x01010270 };

function buildAxml(spec, opts = {}) {
  const utf8 = opts.utf8 !== false;
  const useIds = !!opts.useResIds;
  const attrNames = Object.keys(RES);
  const strings = [];
  const idx = (s) => { let i = strings.indexOf(s); if (i < 0) { strings.push(s); i = strings.length - 1; } return i; };

  // With resource ids the first pool entries are the attribute names (junk text, real meaning from ids).
  const attrIdx = {};
  if (useIds) attrNames.forEach((n, i) => { strings.push('x' + i); attrIdx[n] = i; });
  const attrName = (n) => (useIds ? attrIdx[n] : idx(n));

  const events = [];
  const A = (name, value) => ({ name, value });
  const start = (tag, attrs) => events.push({ t: 'start', tag, attrs });
  const end = (tag) => events.push({ t: 'end', tag });

  const manifestAttrs = [{ raw: 'package', ns: false, value: spec.pkg }];
  if (spec.versionName) manifestAttrs.push(A('versionName', spec.versionName));
  if (spec.versionCode != null) manifestAttrs.push(A('versionCode', spec.versionCode));
  start('manifest', manifestAttrs);
  if (spec.minSdk != null || spec.targetSdk != null) {
    const a = [];
    if (spec.minSdk != null) a.push(A('minSdkVersion', spec.minSdk));
    if (spec.targetSdk != null) a.push(A('targetSdkVersion', spec.targetSdk));
    start('uses-sdk', a); end('uses-sdk');
  }
  for (const p of spec.perms || []) { start('uses-permission', [A('name', p)]); end('uses-permission'); }
  const appAttrs = [];
  if (spec.debuggable) appAttrs.push(A('debuggable', true));
  if (spec.label) appAttrs.push(A('label', spec.label));
  start('application', appAttrs);
  for (const c of spec.components || []) {
    const a = [A('name', c.name)];
    if (c.permission) a.push(A('permission', c.permission));
    if (c.exported) a.push(A('exported', true));
    start(c.kind, a);
    if ((c.actions && c.actions.length) || (c.categories && c.categories.length)) {
      start('intent-filter', []);
      for (const x of c.actions || []) { start('action', [A('name', x)]); end('action'); }
      for (const x of c.categories || []) { start('category', [A('name', x)]); end('category'); }
      end('intent-filter');
    }
    end(c.kind);
  }
  end('application');
  end('manifest');

  // Intern names and values now so the pool is complete before encoding.
  for (const ev of events) {
    idx(ev.tag);
    for (const at of ev.attrs || []) {
      if (at.raw) idx(at.raw); else attrName(at.name);
      if (typeof at.value === 'string') idx(at.value);
    }
  }

  idx('http://schemas.android.com/apk/res/android');
  const poolStrings = strings.map((s) => {
    if (utf8) {
      const b = Buffer.from(s, 'utf8');
      if (s.length > 127 || b.length > 127) throw new Error('fixture string too long');
      return Buffer.concat([Buffer.from([s.length, b.length]), b, Buffer.from([0])]);
    }
    const b = Buffer.from(s, 'utf16le');
    return Buffer.concat([u16(s.length), b, u16(0)]);
  });
  let off = 0;
  const offsets = poolStrings.map((b) => { const o = off; off += b.length; return o; });
  let data = Buffer.concat(poolStrings);
  while (data.length % 4) data = Buffer.concat([data, Buffer.from([0])]);
  const hdr = 28;
  const stringsStart = hdr + strings.length * 4;
  const pool = Buffer.concat([
    u16(0x0001), u16(hdr), u32(stringsStart + data.length), u32(strings.length), u32(0), u32(utf8 ? 0x100 : 0), u32(stringsStart), u32(0),
    ...offsets.map(u32), data,
  ]);

  const parts = [pool];
  if (useIds) {
    const ids = attrNames.map((n) => RES[n]);
    parts.push(Buffer.concat([u16(0x0180), u16(8), u32(8 + ids.length * 4), ...ids.map(u32)]));
  }
  const NONE = 0xffffffff;
  for (const ev of events) {
    if (ev.t === 'start') {
      const attrs = ev.attrs.map((at) => {
        const nameIdx = at.raw ? idx(at.raw) : attrName(at.name);
        const ns = at.raw ? NONE : idx('http://schemas.android.com/apk/res/android');
        let rawV = NONE, dt = 0, d = 0;
        if (typeof at.value === 'string') { rawV = idx(at.value); dt = 3; d = rawV; }
        else if (typeof at.value === 'boolean') { dt = 0x12; d = at.value ? 0xffffffff : 0; }
        else { dt = 0x10; d = at.value; }
        return Buffer.concat([u32(ns), u32(nameIdx), u32(rawV), u16(8), Buffer.from([0, dt]), u32(d)]);
      });
      parts.push(Buffer.concat([
        u16(0x0102), u16(16), u32(36 + attrs.length * 20), u32(1), u32(NONE),
        u32(NONE), u32(idx(ev.tag)), u16(20), u16(20), u16(attrs.length), u16(0), u16(0), u16(0), ...attrs,
      ]));
    } else {
      parts.push(Buffer.concat([u16(0x0103), u16(16), u32(24), u32(1), u32(NONE), u32(NONE), u32(idx(ev.tag))]));
    }
  }
  const body = Buffer.concat(parts);
  return new Uint8Array(Buffer.concat([u16(0x0003), u16(8), u32(8 + body.length), body]));
}

// ---- ZIP ------------------------------------------------------------------
function buildZip(files, opts = {}) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const nameB = Buffer.from(f.name, 'latin1');
    const raw = Buffer.from(f.data);
    const store = f.store === true;
    const comp = store ? raw : zlib.deflateRawSync(raw);
    const crc = crc32(raw);
    const lh = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(store ? 0 : 8), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(raw.length), u16(nameB.length), u16(0), nameB]);
    locals.push(lh, comp);
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(store ? 0 : 8), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(raw.length), u16(nameB.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), nameB]));
    offset += lh.length + comp.length;
  }
  let block = Buffer.alloc(0);
  if (opts.sigBlock) {
    const payload = Buffer.from(opts.sigBlock);
    const pair = Buffer.concat([Buffer.from(u32(payload.length + 4)), Buffer.alloc(4), u32(0x7109871a), payload]);
    const size = pair.length + 8 + 16;
    const sz = Buffer.alloc(8); sz.writeUInt32LE(size);
    block = Buffer.concat([sz, pair, sz, Buffer.from('APK Sig Block 42')]);
  }
  const cd = Buffer.concat(central);
  const cdOff = offset + block.length;
  const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length), u32(cd.length), u32(cdOff), u16(0)]);
  return new Uint8Array(Buffer.concat([...locals, block, cd, eocd]));
}

function dex(strs) {
  return Buffer.concat([Buffer.from('dex\n035\0'), Buffer.alloc(32), ...strs.map((s) => Buffer.from('\0' + s + '\0'))]);
}

function makeApk(spec, extra = {}) {
  const files = [{ name: 'AndroidManifest.xml', data: buildAxml(spec, extra.axml) }];
  files.push({ name: 'classes.dex', data: dex(extra.dexStrings || ['Lcom/example/Main;']) });
  for (const f of extra.files || []) files.push(f);
  return buildZip(files, { sigBlock: extra.sigBlock });
}

module.exports = { buildAxml, buildZip, makeApk, dex, crc32 };
