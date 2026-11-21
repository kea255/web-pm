'use strict';

/* ============================== конфигурация ============================== */
const API = 'api.php';
const ITERATIONS = 100000;      // должно совпадать с const kdf_iterations в config/config.php
const IV_LEN = 12;              // AES-GCM: 12 байт IV + ciphertext + 16 байт tag
const PROBE = 'pass-manager-probe';   // известный текст: по нему проверяем мастер-пароль офлайн
const REQUEST_TIMEOUT = 8000;         // мс: если сервер не отвечает, обрываем запрос по таймауту

/* ============================== состояние ============================== */
const state = {
  csrf: '',
  kdfSalt: '',
  key: null,          // CryptoKey, только в памяти; при блокировке теряется
  offline: false,
  hasCache: false,      // в IndexedDB есть данные за последний вход
  setupNeeded: false, // база пуста: первый запуск — задаём единственный мастер-пароль
  categories: [],
  categoryId: null,
  entries: [],        // [{id,title,url,login,password,comment,updated_at,decryptError}]
  revealed: new Set() // id записей с показанным паролем
};

/* ============================== вспомогательные функции ============================== */
const el = id => document.getElementById(id);

function toast(message, isError = false) {
  const t = el('toast');
  t.textContent = message;
  t.classList.toggle('error', isError);
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 4000);
}

/**
 * Кнопка с иконкой FontAwesome вместо текственной надписи:
 * смысл действия остаётся в title (всплывающая подсказка) и aria-label.
 */
function setIcon(button, iconName, label) {
  button.innerHTML = '<i class="fa-solid ' + iconName + '" aria-hidden="true"></i>';
  button.title = label;
  button.setAttribute('aria-label', label);
  return button;
}

/* ============================== утилиты: bytes / base64 / hex ============================== */
function bytesToB64(bytes) {
  let s = '';
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function b64ToBytes(b64) {
  const raw = atob(b64);
  const u = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) u[i] = raw.charCodeAt(i);
  return u;
}
function hexToBytes(hex) {
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.substr(i * 2, 2), 16);
  return u;
}

/* ============================== криптография ============================== */
/** Ключ AES-GCM выводится из мастер-пароля. Пароль = ключ авторизации = ключ расшифровки. */
async function deriveKey(password, saltHex) {
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,               // ключ не извлекаемый
    ['encrypt', 'decrypt']
  );
}

async function encrypt(key, text) {
  if (text === null || text === undefined || text === '') return null;
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text)));
  const buf = new Uint8Array(iv.length + ct.length);
  buf.set(iv, 0);
  buf.set(ct, iv.length);
  return bytesToB64(buf);
}

async function decrypt(key, cipher) {
  if (!cipher) return '';
  try {
    const bytes = b64ToBytes(cipher);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, IV_LEN) }, key, bytes.subarray(IV_LEN));
    return new TextDecoder().decode(plain);
  } catch (e) {
    return null; // ключ не тот или данные повреждены
  }
}

/* ============================== кэш (IndexedDB) ============================== */
const DB_NAME = 'passmanager_cache';
const STORE = 'kv';
let idb = null;

function openIdb() {
  return new Promise((resolve, reject) => {
    const rq = indexedDB.open(DB_NAME, 1);
    rq.onupgradeneeded = () => { rq.result.createObjectStore(STORE); };
    rq.onsuccess = () => { idb = rq.result; resolve(idb); };
    rq.onerror = () => reject(rq.error);
  });
}
function idbPut(key, value) {
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}
function idbGet(key) {
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(STORE);
    const rq = tx.objectStore(STORE).get(key);
    rq.onsuccess = () => resolve(rq.result);
    rq.onerror = () => reject(rq.error);
  });
}
function idbDel(key) {
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

/* ============================== AJAX ============================== */
/** Режим Offline в DevTools и потеря связи: navigator.onLine = false — запрос не делаем. */
function offlineNow() {
  return navigator.onLine === false;
}

function offlineError(message) {
  return Object.assign(new Error(message), { network: true, offline: true });
}

/** Когда сеть есть — просим service worker обновить кэш оболочки, чтобы офлайн гарантированно открыл страницу. */
async function syncShell() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return;
    const sw = reg.active || reg.installing || reg.waiting;   // активный, устанавливающий или ожидающий
    if (sw) sw.postMessage({ action: 'sync-shell' });
  } catch (e) { /* не критично */ }
}

async function api(action, params = {}, method = 'POST') {
  if (offlineNow()) throw offlineError('Нет сети (режим офлайн)');

  let url = API + '?action=' + encodeURIComponent(action);
  const opt = { credentials: 'same-origin', method, headers: {} };

  if (method === 'GET') {
    url += '&' + new URLSearchParams(params).toString();
  } else {
    opt.headers['Content-Type'] = 'application/json';
    opt.headers['X-CSRF'] = state.csrf;
    opt.body = JSON.stringify(params);
  }

  // Сервер может не отвечать (нет сети) — обрываем запрос по таймауту и считаем это офлайном.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT);
  opt.signal = ctrl.signal;

  const res = await fetch(url, opt);           // без сети бросает TypeError
  clearTimeout(timer);
  let json;
  try {
    json = await res.json();
  } catch (e) {
    throw Object.assign(new Error('Сервер вернул не JSON (HTTP ' + res.status + ')'),
      { network: res.status === 0 || res.status >= 500, offline: res.status === 0 || res.status >= 500, status: res.status });
  }
  if (!json.ok) {
    throw Object.assign(new Error(json.error || ('HTTP ' + res.status)),
      { network: res.status >= 500, offline: res.status >= 500, status: res.status });
  }
  return json.data;
}

function isNetworkError(err) {
  if (!err) return false;
  if (err.offline === true || err.network === true) return true;
  if (err instanceof TypeError) return true;      // Failed to fetch — сети нет
  if (err.name === 'AbortError') return true;     // запрос сорван по таймауту
  return /fetch|network|offline|abort|timeout/i.test(String(err.message || ''));
}

function setOffline(on, note) {
  state.offline = on;
  const st = el('status');
  st.textContent = on
    ? 'Оффлайн' + (note ? ': ' + note : ': данные из кэша за последний вход')
    : 'Соединение с сервером';
  st.classList.toggle('offline', on);
  el('addEntry').disabled = on;
  el('addCat').disabled = on;
}

/* ============================== экран авторизации ============================== */
function authError(msg) { el('authMsg').textContent = msg; }

/**
 * Подсказка, подпись кнопки и текст экрана входа — по актуальной связи и кэшу.
 * checkServer = true: если режим «оффлайн' остался, а navigator.onLine снова true —
 * проверяем сервер и сбрасываем режим.
 */
async function refreshAuthScreen(checkServer = false) {
  const meta = await idbGet('meta');
  state.hasCache = !!meta;

  if (checkServer && !offlineNow() && state.offline) {
    try {
      const data = await api('ping', {}, 'GET');
      setOffline(false);
      state.setupNeeded = !!data.setup_needed;
    } catch (err) {
      setOffline(true, 'сервер недоступен');
    }
  }

  const offline = offlineNow() || state.offline;

  el('offlineHint').hidden = !(offline && meta);
  el('offlineHint').textContent = meta
    ? 'Сети нет. В кэше есть данные за последний вход — введите мастер-пароль, чтобы открыть их офлайн.'
    : 'Сети нет и в кэше нет данных за последний вход.';
  el('authSubmit').title = offline
    ? 'Разблокировать офлайн'
    : (state.setupNeeded ? 'Создать мастер-пароль' : 'Разблокировать');
  el('authIntro').textContent = offline
    ? (meta
        ? 'Сети нет: ввод мастер-пароля откроет данные из кэша за последний вход.'
        : 'Сети нет и в кэше нет данных за последний вход — без сервера приложение не работает.')
    : (state.setupNeeded
        ? 'Первый запуск: придумайте мастер-пароль. Он одновременно становится ключом авторизации и ключом шифрования.'
        : '');
}

function showAuth() {
  el('workspace').hidden = true;
  el('auth').hidden = false;
  el('masterPass').value = '';
  el('masterPass').focus();
}
function showWorkspace() {
  el('auth').hidden = true;
  el('workspace').hidden = false;
  el('lockState').textContent = 'ключ активен';
}

async function afterAuth(data, password) {
  state.csrf = data.csrf;
  state.kdfSalt = data.kdf_salt;
  state.key = await deriveKey(password, data.kdf_salt);

  // Для офлайн-входа: соль KDF + «проба», зашифрованная этим ключом. Ключ и пароль не сохраняются.
  await idbPut('meta', {
    kdfSalt: data.kdf_salt,
    probeCipher: await encrypt(state.key, PROBE),
    updatedAt: new Date().toISOString()
  });

  showWorkspace();
  setOffline(false);
  el('offlineHint').hidden = true;
  await loadCategories();
}

/** Один экран авторизации: поле только мастер-пароль (он же ключ шифрования), логина нет. */
async function doUnlock() {
  const password = el('masterPass').value;
  if (!password) return authError('Введите мастер-пароль');
  if (password.length < 8 && state.setupNeeded) return authError('Мастер-пароль длиной не менее 8 символов');
  authError('');
  await refreshAuthScreen(true);   // сеть могла вернуться — перепроверяем режим перед входом

  try {
    const data = state.setupNeeded
      ? await api('setup', { password })     // первый запуск: создаём единственный мастер-пароль
      : await api('unlock', { password });
    await afterAuth(data, password);
  } catch (err) {
    if (isNetworkError(err)) return offlineUnlock(password);
    authError(err.message);
  }
}

/** Офлайн-вход: проверяем мастер-пароль по «пробе» и расшифровываем кэш последнего входа. */
async function offlineUnlock(password) {
  const meta = await idbGet('meta');
  if (!meta) return authError('Сети нет, а в кэше нет данных за последний вход.');
  if (!meta.kdfSalt || !meta.probeCipher) return authError('Кэш от предыдущей версии приложения — войдите с сетью, затем повторите офлайн-вход.');

  state.csrf = '';
  state.kdfSalt = meta.kdfSalt;
  state.key = await deriveKey(password, meta.kdfSalt);   // тот же мастер-пароль = тот же ключ

  // AES-GCM: неверный ключ → ошибка тега, проба не расшифровывается.
  if (await decrypt(state.key, meta.probeCipher) === null) {
    state.key = null;
    return authError('Неверный мастер-пароль.');
  }

  showWorkspace();
  setOffline(true, 'данные за вход ' + new Date(meta.updatedAt).toLocaleString());
  await loadCategoriesFromCache();
}

async function lock() {
  if (!state.offline && state.csrf) {
    try { await api('logout', {}); } catch (err) { /* сервер мог быть недоступен */ }
  }
  state.key = null;
  state.csrf = '';
  state.entries = [];
  state.categories = [];
  state.categoryId = null;
  state.revealed.clear();
  el('rows').innerHTML = '';
  el('catList').innerHTML = '';
  el('lockState').textContent = 'ключ не активен';
  state.offline = offlineNow();
  setOffline(state.offline, state.offline ? 'режим офлайн (нет сети)' : undefined);
  await refreshAuthScreen();
  showAuth();
}

/* ============================== категории ============================== */
async function loadCategories() {
  const data = await api('categories', {}, 'GET');
  setOffline(false);            // сервер ответил — мы не в офлайн-режиме
  state.categories = data.categories;
  await idbPut('categories', data.categories);
  renderCategories();
  await pickCategory(state.categoryId);
}

async function loadCategoriesFromCache() {
  state.categories = (await idbGet('categories')) || [];
  renderCategories();
  await pickCategory(state.categoryId);
}

/** Выбрать категорию: если её id нет в списке — берём первую. */
async function pickCategory(id) {
  if (!state.categories.length) {
    state.categoryId = null;
    el('catTitle').textContent = 'нет категорий';
    el('rows').innerHTML = '';
    el('rowsEmpty').hidden = false;
    return;
  }
  const target = state.categories.find(c => c.id === id) || state.categories[0];
  await selectCategory(target.id);
}

function renderCategories() {
  const list = el('catList');
  list.innerHTML = '';
  el('catsEmpty').hidden = state.categories.length > 0;

  for (const c of state.categories) {
    const li = document.createElement('li');
    li.dataset.id = String(c.id);
    li.draggable = true;
    li.className = c.id === state.categoryId ? 'active' : '';
    li.addEventListener('click', () => selectCategory(c.id));

    const name = document.createElement('span');
    name.className = 'cname';
    name.textContent = c.name;
    li.appendChild(name);

    const cnt = document.createElement('span');
    cnt.className = 'ccount';
    cnt.textContent = c.count;
    li.appendChild(cnt);

    const ops = document.createElement('span');
    ops.className = 'catops';

    const ren = document.createElement('button');
    ren.className = 'btn ghost icon';
    setIcon(ren, 'fa-pen-to-square', 'Переименовать категорию');
    ren.addEventListener('click', e => { e.stopPropagation(); openCatModal('rename', c); });
    ops.appendChild(ren);

    const del = document.createElement('button');
    del.className = 'btn ghost danger icon';
    setIcon(del, 'fa-trash', 'Удалить категорию со всеми записями');
    del.addEventListener('click', e => { e.stopPropagation(); deleteCategory(c); });
    ops.appendChild(del);

    li.appendChild(ops);
    list.appendChild(li);
  }
}

async function selectCategory(id) {
  state.categoryId = id;
  renderCategories();
  const cat = state.categories.find(c => c.id === id);
  el('catTitle').textContent = cat ? cat.name : '—';

  if (offlineNow()) return loadEntriesFromCache(id);

  try {
    const data = await api('entries', { category_id: id }, 'GET');
    const rows = data.entries;
    await idbPut('entries:' + id, { rows, syncedAt: new Date().toISOString() });
    setOffline(false);            // связь вернулась — выходим из офлайн-режима
    await renderRows(rows, 'синхронизировано ' + new Date().toLocaleTimeString());
  } catch (err) {
    if (isNetworkError(err)) {
      setOffline(true, 'данные из кэша');
      await loadEntriesFromCache(id);
    } else {
      toast(err.message, true);
    }
  }
}

async function loadEntriesFromCache(id) {
  const cache = await idbGet('entries:' + id);
  const rows = cache ? cache.rows : [];
  const note = cache ? 'из кэша за ' + new Date(cache.syncedAt).toLocaleString() : 'кэш пуст для этой категории';
  await renderRows(rows, note);
}

/* ============================== таблица записей ============================== */
async function renderRows(rows, note) {
  if (!state.key) {
    el('rows').innerHTML = '';
    el('rowsEmpty').hidden = false;
    el('rowsEmpty').textContent = 'Ключ расшифровки не активен.';
    return;
  }

  const decrypted = [];
  for (const r of rows) {
    const login = await decrypt(state.key, r.login_cipher);
    const pass = await decrypt(state.key, r.pass_cipher);
    const comment = await decrypt(state.key, r.comment_cipher);
    decrypted.push({
      id: r.id,
      title: r.title || '(без заголовка)',
      url: r.url || '',
      login,
      password: pass,
      comment,
      updated_at: r.updated_at,
      deleted_at: r.deleted_at || null,
      decryptError: login === null || pass === null
    });
  }
  state.entries = decrypted;
  drawTable(note);
}

function drawTable(note) {
  const tbody = el('rows');
  tbody.innerHTML = '';

  const q = el('search').value.trim().toLowerCase();
  const visible = state.entries.filter(e => {
    if (!q) return true;
    return [e.title, e.url, e.login, e.comment, e.password].some(v => String(v || '').toLowerCase().includes(q));
  });

  el('status').textContent = (state.offline ? 'Оффлайн: ' + (note || '') : 'Соединение с сервером' + (note ? ': ' + note : ''));
  el('status').classList.toggle('offline', state.offline);
  el('addEntry').disabled = state.offline;
  el('addCat').disabled = state.offline;

  el('rowsEmpty').hidden = visible.length > 0;
  el('rowsEmpty').textContent = q ? 'Ничего не найдено по запросу "' + q + '"' : 'В этой категории нет записей.';

  for (const e of visible) {
    const tr = document.createElement('tr');
    tr.dataset.id = String(e.id);
    if (e.deleted_at) tr.classList.add('deleted');
    // Перетаскивание возможно только когда поиск не активен: при фильтре часть записей скрыта,
    // и сохранённый порядок потерял бы невидимые строки. Помеченные тоже тащим — их можно
    // перенести в другую категорию; внутри таблицы они всегда ниже остальных.
    tr.draggable = !q;

    // Заголовок
    const tdTitle = document.createElement('td');
    tdTitle.textContent = e.title;
    tr.appendChild(tdTitle);

    // Логин
    const tdLogin = document.createElement('td');
    if (e.decryptError) {
      const fail = document.createElement('span');
      fail.className = 'decryptfail';
      fail.textContent = 'не расшифровано';
      tdLogin.appendChild(fail);
    } else {
      const code = document.createElement('code');
      code.textContent = e.login || '';
      tdLogin.appendChild(code);
    }
    tr.appendChild(tdLogin);

    // Пароль (закрыт по умолчанию)
    const tdPass = document.createElement('td');
    const pw = document.createElement('div');
    pw.className = 'pw';
    if (e.decryptError) {
      const fail = document.createElement('span');
      fail.className = 'decryptfail';
      fail.textContent = 'не расшифровано';
      pw.appendChild(fail);
    } else {
      const val = document.createElement('code');
      val.className = state.revealed.has(e.id) ? '' : 'masked';
      val.textContent = state.revealed.has(e.id) ? (e.password || '') : '••••••';
      pw.appendChild(val);

      // Кнопки закреплены у правого края ячейки, ширина поля не меняется
      const ops = document.createElement('div');
      ops.className = 'ops';
      pw.appendChild(ops);

      const toggle = document.createElement('button');
      toggle.className = 'btn ghost icon';
      const shown = state.revealed.has(e.id);
      setIcon(toggle, shown ? 'fa-eye-slash' : 'fa-eye', shown ? 'Скрыть пароль' : 'Показать пароль');
      toggle.addEventListener('click', () => {
        if (state.revealed.has(e.id)) state.revealed.delete(e.id); else state.revealed.add(e.id);
        drawTable();
      });
      ops.appendChild(toggle);

      const copy = document.createElement('button');
      copy.className = 'btn ghost icon';
      setIcon(copy, 'fa-copy', 'Копировать пароль');
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(e.password || ''); toast('Пароль скопирован'); }
        catch (err) { toast('Буфер обмена недоступен', true); }
      });
      ops.appendChild(copy);
    }
    tdPass.appendChild(pw);
    tr.appendChild(tdPass);

    // Комментарий
    const tdComment = document.createElement('td');
    tdComment.className = 'comment';
    tdComment.textContent = e.decryptError ? '…' : (e.comment || '');
    tr.appendChild(tdComment);

    // URL
    const tdUrl = document.createElement('td');
    tdUrl.className = 'url';
    if (e.url && /^https?:\/\//i.test(e.url)) {
      const a = document.createElement('a');
      a.href = e.url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = e.url;
      tdUrl.appendChild(a);
    } else {
      tdUrl.textContent = e.url || '';
    }
    tr.appendChild(tdUrl);

    // Действия
    const tdActions = document.createElement('td');
    const box = document.createElement('div');
    box.className = 'cell-actions';

    const edit = document.createElement('button');
    edit.className = 'btn ghost icon';
    if (e.deleted_at) {
      setIcon(edit, 'fa-rotate-left', 'Восстановить помеченную запись');
      edit.addEventListener('click', () => restoreEntry(e));
    } else {
      setIcon(edit, 'fa-pen', 'Изменить запись');
      edit.addEventListener('click', () => openEntryModal(e));
    }
    box.appendChild(edit);

    const del = document.createElement('button');
    del.className = 'btn ghost danger icon';
    setIcon(del, 'fa-trash', e.deleted_at ? 'Удалить помеченную запись из базы' : 'Пометить запись как удалённую');
    del.addEventListener('click', () => deleteEntry(e));
    box.appendChild(del);

    tdActions.appendChild(box);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  }
}

/* ============================== перетаскивание ============================== */
/* Что именно тащим мышью: строку таблицы (запись) или элемент списка (категорию). */
let draggedEl = null;
let draggedEntryId = null;
let draggedCatId = null;
let dragMoved = false;   // запись уже перенесена на категорию — порядок таблицы сохранять не нужно

function clearCatHighlight() {
  el('catList').querySelectorAll('.droptarget').forEach(li => li.classList.remove('droptarget'));
}

function clearDragState() {
  if (draggedEl) draggedEl.classList.remove('dragging');
  const wasEntry = draggedEntryId;
  const wasCat = draggedCatId;
  const moved = dragMoved;
  draggedEl = null;
  draggedEntryId = null;
  draggedCatId = null;
  dragMoved = false;
  clearCatHighlight();
  return { wasEntry, wasCat, moved };
}

function beginDrag(item, e) {
  dragMoved = false;
  item.classList.add('dragging');
  draggedEl = item;
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', item.dataset.id || '');
  }
}

/** Переставляет перетаскиваемый элемент внутри контейнера: выше/ниже цели по высоте курсора. */
function reorderInside(container, dragging, target, clientY) {
  const rect = target.getBoundingClientRect();
  const after = clientY > rect.top + rect.height / 2;
  container.insertBefore(dragging, after ? target.nextSibling : target);
}

function setupDrag() {
  const tbody = el('rows');
  const cats = el('catList');

  // --- таблица: перестановка записей внутри и перенос на категорию в боковой колонке ---
  tbody.addEventListener('dragstart', e => {
    const tr = e.target.closest('tr');
    if (!tr || tr.draggable === false) return;
    beginDrag(tr, e);
    draggedEntryId = Number(tr.dataset.id) || null;
  });

  tbody.addEventListener('dragover', e => {
    if (!draggedEl || !draggedEntryId) return;
    e.preventDefault();
    const tr = e.target.closest('tr');
    if (!tr || tr === draggedEl) return;
    reorderInside(tbody, draggedEl, tr, e.clientY);
  });

  tbody.addEventListener('drop', e => e.preventDefault());

  tbody.addEventListener('dragend', () => {
    const { wasEntry, moved } = clearDragState();
    if (wasEntry && !moved) persistRowOrder();
  });

  // --- список категорий: перестановка категорий и приём записей, перетащенных из таблицы ---
  cats.addEventListener('dragstart', e => {
    const li = e.target.closest('li');
    if (!li) return;
    beginDrag(li, e);
    draggedCatId = Number(li.dataset.id) || null;
  });

  cats.addEventListener('dragover', e => {
    e.preventDefault();
    clearCatHighlight();
    const li = e.target.closest('li');

    if (draggedEntryId) {          // тащим запись: подсвечаем категорию, куда она попадёт
      if (li) li.classList.add('droptarget');
      return;
    }
    if (!draggedEl || !draggedCatId) return;
    if (!li || li === draggedEl) return;
    reorderInside(cats, draggedEl, li, e.clientY);
  });

  cats.addEventListener('drop', e => {
    e.preventDefault();
    const li = e.target.closest('li');
    clearCatHighlight();
    if (draggedEntryId && li) {
      dragMoved = true;
      moveEntryToCategory(draggedEntryId, Number(li.dataset.id));
    }
  });

  cats.addEventListener('dragend', () => {
    const { wasCat } = clearDragState();
    if (wasCat) persistCatOrder();
  });
}

/** Финальный порядок записей в таблице → сохраняем (или только в кэше, если офлайн). */
async function persistRowOrder() {
  const tbody = el('rows');
  const ids = Array.from(tbody.children).map(tr => Number(tr.dataset.id)).filter(id => id > 0);
  if (!ids.length) return;

  const byId = new Map(state.entries.map(e => [e.id, e]));
  state.entries = ids.map(id => byId.get(id)).filter(Boolean);

  if (state.offline) {
    const cache = await idbGet('entries:' + state.categoryId);
    if (cache && Array.isArray(cache.rows)) {
      const rowsById = new Map(cache.rows.map(r => [Number(r.id), r]));
      cache.rows = ids.map(id => rowsById.get(id)).filter(Boolean);
      await idbPut('entries:' + state.categoryId, cache);
    }
    return toast('Порядок записей сохранён в локальном кэше');
  }

  try {
    await api('entries_reorder', { category_id: state.categoryId, ids });
    toast('Порядок записей сохранён');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); }
    toast(err.message, true);
  }
}

/** Финальный порядок категорий → сохраняем (или только в кэше, если офлайн). */
async function persistCatOrder() {
  const ids = Array.from(el('catList').children).map(li => Number(li.dataset.id)).filter(id => id > 0);
  if (!ids.length) return;

  const byId = new Map(state.categories.map(c => [c.id, c]));
  state.categories = ids.map(id => byId.get(id)).filter(Boolean);
  renderCategories();

  if (state.offline) {
    await idbPut('categories', state.categories);
    return toast('Порядок категорий сохранён в локальном кэше');
  }

  try {
    await api('categories_reorder', { ids });
    toast('Порядок категорий сохранён');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadCategoriesFromCache(); }
    toast(err.message, true);
  }
}

/**
 * Перенос записи в другую категорию: сервер ставит её в конец новой категории
 * (position), состояние «помечена» сохраняется.
 */
async function moveEntryToCategory(entryId, catId) {
  if (!entryId || !catId) return;
  const cat = state.categories.find(c => c.id === catId);
  if (!cat) return toast('Категория не найдена', true);
  if (state.categoryId === catId) return;   // перенос в текущую категорию — ничего не меняем

  if (state.offline) return toast('Оффлайн-режим: перенос записей недоступен.', true);

  try {
    await api('entry_move', { id: entryId, category_id: catId });
    await loadCategories();   // обновляет счётчики категорий и перезагружает текущую таблицу
    toast('Запись перенесена в категорию «' + cat.name + '»');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadCategoriesFromCache(); }
    toast(err.message, true);
  }
}

/* ============================== модалка категории ============================== */
let catModalMode = 'add';
let catModalTarget = null;

function openCatModal(mode, category) {
  if (state.offline) return toast('Оффлайн-режим: добавление и изменение категорий недоступно.', true);
  catModalMode = mode;
  catModalTarget = category || null;
  el('catModalTitle').textContent = mode === 'rename' ? 'Переименовать категорию' : 'Новая категория';
  el('catName').value = mode === 'rename' ? (category ? category.name : '') : '';
  el('catModal').hidden = false;
  el('catName').focus();
}

async function saveCatModal() {
  const name = el('catName').value.trim();
  if (!name) return toast('Имя категории не может быть пустым', true);
  try {
    if (catModalMode === 'rename') {
      await api('category_rename', { id: catModalTarget.id, name });
      const c = state.categories.find(x => x.id === catModalTarget.id);
      if (c) c.name = name;
      await loadCategories();
      toast('Категория переименована');
    } else {
      const data = await api('category_add', { name });
      state.categoryId = data.id;
      await loadCategories();
      toast('Категория добавлена');
    }
    el('catModal').hidden = true;
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadCategoriesFromCache(); }
    toast(err.message, true);
  }
}

async function deleteCategory(cat) {
  if (state.offline) return toast('Оффлайн-режим: удаление недоступно.', true);
  if (!confirm('Удалить категорию «' + cat.name + '» вместе со всеми её записями?')) return;
  try {
    await api('category_delete', { id: cat.id });
    if (state.categoryId === cat.id) state.categoryId = null;
    await idbDel('entries:' + cat.id);
    await loadCategories();
    toast('Категория удалена');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadCategoriesFromCache(); }
    toast(err.message, true);
  }
}

/* ============================== модалка записи ============================== */
let entryModalId = null;

function openEntryModal(entry) {
  if (state.offline) return toast('Оффлайн-режим: добавление и изменение записей недоступно.', true);
  entryModalId = entry ? entry.id : null;
  el('entryModalTitle').textContent = entry ? 'Изменить запись' : 'Новая запись';
  el('fTitle').value = entry ? (entry.title || '') : '';
  el('fUrl').value = entry ? (entry.url || '') : '';
  el('fLogin').value = entry ? (entry.login || '') : '';
  el('fPass').value = entry ? (entry.password || '') : '';
  el('fComment').value = entry ? (entry.comment || '') : '';
  el('entryModal').hidden = false;
  el('fTitle').focus();
}

async function saveEntryModal() {
  const login = el('fLogin').value;
  const pass = el('fPass').value;
  if (!login || !pass) return toast('Логин и пароль обязательны', true);

  try {
    const payload = {
      category_id: state.categoryId,
      title: el('fTitle').value.trim(),
      url: el('fUrl').value.trim(),
      login_cipher: await encrypt(state.key, login),
      pass_cipher: await encrypt(state.key, pass),
      comment_cipher: await encrypt(state.key, el('fComment').value.trim())
    };
    if (entryModalId) payload.id = entryModalId;

    await api('entry_save', payload);
    el('entryModal').hidden = true;
    await loadCategories();          // обновляет счётчики категорий и перезагружает таблицу
    toast(entryModalId ? 'Запись обновлена' : 'Запись добавлена');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadEntriesFromCache(state.categoryId); }
    toast(err.message, true);
  }
}

async function deleteEntry(entry) {
  if (state.offline) return toast('Оффлайн-режим: удаление недоступно.', true);
  const text = entry.deleted_at
    ? 'Удалить помеченную запись «' + entry.title + '" из базы (без возможности восстановления)?'
    : 'Пометить запись «' + entry.title + '" как удалённую? Она останется в таблице ниже остальных записей.';
  if (!confirm(text)) return;
  try {
    const data = await api('entry_delete', { id: entry.id });
    await loadCategories();   // обновляет счётчики категорий и перезагружает таблицу
    toast(data.soft_deleted ? 'Запись помечена как удалённая' : 'Запись удалена из базы');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadEntriesFromCache(state.categoryId); }
    toast(err.message, true);
  }
}

/** Восстановить помеченную запись: deleted_at сбрасывается, запись возвращается в список. */
async function restoreEntry(entry) {
  if (state.offline) return toast('Оффлайн-режим: восстановление недоступно.', true);
  try {
    await api('entry_restore', { id: entry.id });
    await loadCategories();   // обновляет счётчики категорий и перезагружает таблицу
    toast('Запись восстановлена');
  } catch (err) {
    if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadEntriesFromCache(state.categoryId); }
    toast(err.message, true);
  }
}

/* ============================== запуск ============================== */
async function init() {
  await openIdb();

  el('authForm').addEventListener('submit', async e => { e.preventDefault(); await doUnlock(); });
  el('logout').addEventListener('click', lock);
  el('addCat').addEventListener('click', () => openCatModal('add'));
  el('catSave').addEventListener('click', saveCatModal);
  el('catCancel').addEventListener('click', () => { el('catModal').hidden = true; });
  el('addEntry').addEventListener('click', () => openEntryModal(null));
  el('entrySave').addEventListener('click', saveEntryModal);
  el('entryCancel').addEventListener('click', () => { el('entryModal').hidden = true; });
  el('search').addEventListener('input', () => drawTable());
  el('bPassGen').addEventListener('click', () => { el('fPass').value = omgopass({syllables:2, numbers:true, titlecase:false}); });

  // Сортировка перетаскиванием (записи и категории) + перенос записи на категорию в боковой колонке.
  setupDrag();

  // проверка доступности сервера: если мастер-пароль ещё не задан — первый запуск
  try {
    const data = await api('ping', {}, 'GET');
    setOffline(false);
    state.setupNeeded = !!data.setup_needed;
  } catch (err) {
    setOffline(true, offlineNow() ? 'режим офлайн (нет сети)' : 'сервер недоступен');
    state.setupNeeded = false;
  }
  await refreshAuthScreen();

  // сеть включилась/выключилась (например Offline в DevTools) — пересчитываем режим и экран входа
  window.addEventListener('online', async () => {
    try {
      const data = await api('ping', {}, 'GET');
      setOffline(false);
      state.setupNeeded = !!data.setup_needed;
      syncShell();                 // сеть есть — обновляем кэш оболочки
    } catch (err) {
      setOffline(true, 'сервер всё ещё недоступен');
    }
    await refreshAuthScreen();
    if (!el('workspace').hidden && state.key) {
      try { await loadCategories(); }
      catch (err) {
        if (isNetworkError(err)) { setOffline(true, 'данные из кэша'); await loadCategoriesFromCache(); }
        else toast(err.message, true);
      }
    }
  });

  window.addEventListener('offline', async () => {
    setOffline(true, 'режим офлайн (нет сети)');
    await refreshAuthScreen();
  });

  // service worker: кэш HTML/CSS/JS для офлайн-загрузки страницы
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
    try { await navigator.serviceWorker.register('sw.js'); } catch (e) { /* не важно для работы приложения */ }
  }
  if (!state.offline) syncShell();   // сеть есть — обновляем кэш оболочки для офлайн-режима

  el('lockState').textContent = 'ключ не активен';
  showAuth();
}

init().catch(err => {
  authError('Ошибка запуска приложения: ' + err.message);
  console.error(err);
});
