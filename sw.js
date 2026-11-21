/**
 * Service worker: кэш оболочки приложения (HTML, CSS, JS), чтобы страница
 * могла загрузиться без сети. API запросы НЕ кэшируются — при отсутствии
 * сети fetch бросает ошибку, и приложение переходит на чтение из IndexedDB.
 *
 * Схема cache-first + фоновое обновление:
 *   - файл из кэша отдаётся сразу, свежая версия скачивается фоном и кладётся в кэш;
 *   - при ошибке сети кэш не меняется и не очищается;
 *   - если файла в кэше нет и сети нет — отдаётся честный 503.
 *
 * Важно: вместо CSS/JS HTML не отдаётся никогда — раньше фолбэк возвращал index.htm
 * на запрос app.css/app.js, и браузер получал «Unexpected token '<'.
 * Имя кэша стабильное ('pm-shell'); старые кэши 'pm-shell-*' сначала переносятся
 * в основной кэш, потом удаляются.
 */
const CACHE_NAME = 'pm-shell';
/* Оболочка + иконки FontAwesome (локальный subset: стили и один solid-шрифт).
   Subset ~2 КБ + woff2 ~158 КБ вместо полного набора ~1.4 МБ — кэш лёгкий. */
const SHELL = [
  './',
  './index.htm',
  './assets/app.css',
  './assets/app.js',
  './assets/fontawesome/css/fa-solid.min.css',
  './assets/fontawesome/webfonts/fa-solid-900.woff2'
];

function cachedResponse(message, status) {
  return new Response(message, {
    status: status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8' }
  });
}

function isPage(pathname) {
  return pathname === '/' || pathname.endsWith('/index.htm');
}

/** Кэшируем каждый файл отдельно: cache.addAll атомарен, и один неудачный запрос очищал весь кэш. */
async function fillCache(cache) {
  for (const req of SHELL) {
    try {
      const res = await fetch(req);
      if (res.ok) await cache.put(req, res.clone());
    } catch (e) { /* сети нет — оставляем то, что уже в кэше */ }
  }
}

/** Переносим записи из старых кэшей pm-shell-* в основной кэш, затем удаляем старые. */
async function migrateLegacyCaches() {
  const keys = await caches.keys();
  const legacy = keys.filter(k => k.startsWith('pm-shell-') && k !== CACHE_NAME);
  if (!legacy.length) return;

  const target = await caches.open(CACHE_NAME);
  for (const name of legacy) {
    const old = await caches.open(name);
    const entries = await old.keys();
    for (const entry of entries) {
      const request = entry.request || entry;
      const response = await old.match(request);
      if (!response) continue;
      if (await target.match(request)) continue;   // основной кэш приоритетнее
      await target.put(request, response.clone());
    }
  }
  await Promise.all(legacy.map(k => caches.delete(k)));
}

self.addEventListener('install', (e) => {
  e.waitUntil(
    migrateLegacyCaches()
      .then(() => caches.open(CACHE_NAME))
      .then(cache => fillCache(cache))
      .then(() => self.skipWaiting())
  );
});

/** Удаляем из кэша файлы, которых больше нет в SHELL (например, полный FontAwesome после subset). */
async function pruneCache(cache) {
  const wanted = new Set(SHELL.map(p => new URL(p, self.location).pathname));
  for (const req of await cache.keys()) {
    if (!wanted.has(new URL(req.url).pathname)) await cache.delete(req);
  }
}

self.addEventListener('activate', (e) => {
  e.waitUntil(
    migrateLegacyCaches()
      .then(() => caches.open(CACHE_NAME))
      .then(cache => pruneCache(cache))
      .then(() => self.clients.claim())
  );
});

/** Приложение сообщает, что сеть есть — SW обновляет кэш оболочки (при ошибке кэш остаётся). */
self.addEventListener('message', (e) => {
  if (e.data && e.data.action === 'sync-shell') {
    e.waitUntil(caches.open(CACHE_NAME).then(cache => fillCache(cache)));
  }
});

/** Фонтовое обновление кэша: успешный ответ кладём в кэш, ошибка сети ничего не меняет. */
function revalidate(request) {
  fetch(request)
    .then(res => {
      if (!res.ok) return null;
      const copy = res.clone();
      return caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
    })
    .catch(() => null);
}

/** Поиск в кэше с variants: без query-параметров и по относительному пути. */
async function matchCached(request) {
  const hit = await caches.match(request);
  if (hit) return hit;

  const url = new URL(request.url);
  const variants = [url.origin + url.pathname, './' + url.pathname.replace(/^\//, '')];
  for (const v of variants) {
    const found = await caches.match(v);
    if (found) return found;
  }
  return null;
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API не кэшируем: при отсутствии сети fetch падает, и приложение читает данные из IndexedDB.
  if (url.pathname.endsWith('/api.php')) return;

  if (e.request.method !== 'GET') return;

  e.respondWith(
    matchCached(e.request).then(hit => {
      if (hit) {
        revalidate(e.request);      // отдаём кэш, свежую версию скачиваем фоном
        return hit;
      }

      return fetch(e.request)
        .then(res => {
          if (res.ok && url.origin === self.location.origin) {
            const copy = res.clone();   // клонируем до того, как body прочитает страница
            caches.open(CACHE_NAME).then(cache => cache.put(e.request, copy));
          }
          return res;
        })
        .catch(() => {
          // Только для запросов страницы допускается отдать кэш index.htm; для CSS/JS — честный 503.
          if (isPage(url.pathname)) {
            return caches.match('./index.htm').then(
              fallback => fallback || cachedResponse('Нет сети и страница не в кэше', 503)
            );
          }
          return cachedResponse('Нет сети и файла нет в кэше: ' + url.pathname, 503);
        });
    })
  );
});
