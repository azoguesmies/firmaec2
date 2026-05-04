/* FirmaEC PWA — Service Worker v1.1 */

const CACHE_NAME  = 'firmaec-v1.1';
const ASSETS_CORE = [
  '/',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

/* ── Instalación: precachear assets core ─────────────────────── */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS_CORE))
      .then(() => self.skipWaiting())
  );
});

/* ── Activación: limpiar caches anteriores ───────────────────── */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key  => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

/* ── Fetch: cache-first para assets, network-only para API ───── */
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Las llamadas a la API nunca se cachean (datos sensibles)
  if (url.pathname.startsWith('/api/')) return;

  // Solo manejar GET
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;

      return fetch(event.request).then(response => {
        // Solo cachear respuestas válidas del mismo origen
        if (
          response &&
          response.status === 200 &&
          (response.type === 'basic' || response.type === 'cors')
        ) {
          const toCache = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, toCache);
          });
        }
        return response;
      }).catch(() => {
        // Offline fallback: devolver la raíz cacheada
        if (event.request.mode === 'navigate') {
          return caches.match('/');
        }
      });
    })
  );
});
