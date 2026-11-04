'use strict';
// Network-first for pages, cache fallback so the checker works offline.
const CACHE = 'scamcheck-v5';
const FILES = ['./', 'index.html', 'apk.html', 'mcp.html', 'pkg.html', 'wifi.html', 'style.css', 'engine.js', 'apkscan.js', 'mcpaudit.js', 'pkgscan.js', 'wifiaudit.js', 'app.js', 'apk.js', 'mcp.js', 'pkg.js', 'wifi.js', 'config.js', 'icon.svg', 'manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
      })
      .catch(() => caches.match(req).then((hit) => hit || caches.match('index.html')))
  );
});
