// ============================================================================
// HL AI Trader v1 — Service Worker (docs/sw.js)
// - public_snapshot.json & /api/* : Always Network-First (cache: 'no-store')
// - Static App Shell (./index.html, ./app.js, ./manifest.json, icons): Network-First with Cache Fallback
// ============================================================================
const CACHE_NAME = 'hl-ai-trader-v1-shell-v3';
const SHELL_ASSETS = [
  './',
  './index.html',
  './app.js',
  './static/app.js',
  './manifest.json',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(SHELL_ASSETS).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // 1. public_snapshot.json および API リクエストは常に最新を Network-First (キャッシュバスター付き) で取得
  if (url.pathname.endsWith('public_snapshot.json') || url.pathname.includes('/api/')) {
    event.respondWith(
      fetch(req, { cache: 'no-store' }).catch(() => caches.match(req))
    );
    return;
  }

  // 2. 静的シェル資産も Network-First で最新を優先し、オフライン時のみキャッシュへフォールバック
  event.respondWith(
    fetch(req)
      .then(res => {
        if (res && res.status === 200 && url.origin === self.location.origin) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});
