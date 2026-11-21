<?php
/**
 * API «Менеджер паролей». Все ответы — JSON, фронт работает только через AJAX (fetch).
 *
 * Безопасность:
 *   - логина нет: единственный вход — мастер-пароль, он же ключ шифрования;
 *   - в БД хранится только bcrypt-верификатор предварительно хешированного пароля (sha256(password));
 *   - логин, пароль и комментарий каждой записи — AES-256-GCM, base64(iv + ciphertext + tag),
 *     ключ выводится из мастер-пароля на клиенте (WebCrypto PBKDF2) и на сервере не хранится;
 *   - сервер не имеет ключа и не может ничего расшифровать.
 */
declare(strict_types=1);

require __DIR__ . '/config.php';
require __DIR__ . '/lib/dbi.class.php';

DBi::$skip_error = true;
DBi::$query_log_file = db_log;

const MAX_CIPHER = 32768; // base64(iv+ct+tag) — ограничение по длине

/* ---------------- вывод JSON ---------------- */
function out(bool $ok, array $data = [], ?string $error = null, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => $ok, 'data' => $data, 'error' => $error]);
    exit;
}

/* ---------------- соединение с базой ---------------- */
try {
    DBi::init();
} catch (Throwable $t) {
    out(false, [], 'База данных недоступна: ' . $t->getMessage(), 503);
}
if (!empty(DBi::$mysqli->connect_error)) {
    out(false, [], 'Ошибка MySQL: ' . DBi::$mysqli->connect_error, 503);
}
DBi::$mysqli->set_charset(db_charset);

/* ---------------- сессия ---------------- */
session_name('PMSESS');
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure'   => !empty($_SERVER['HTTPS']),
]);

/* ---------------- helpers ---------------- */
function input(): array
{
    $raw = file_get_contents('php://input');
    $json = json_decode((string)$raw, true);
    return is_array($json) ? $json : [];
}

function field(array $in, string $key, int $max = 200, string $default = ''): string
{
    $v = $in[$key] ?? null;
    if (!is_string($v)) return $default;
    $v = trim(preg_replace('/[\x00-\x1f\x7f]/u', '', $v));
    return mb_substr($v, 0, $max);
}

function int_field(array $in, string $key, int $default = 0): int
{
    $v = $in[$key] ?? null;
    if (is_numeric($v)) return (int)$v;
    return $default;
}

/** Проверяет, что значение — base64 из IV + ciphertext + tag, сервер не расшифровывает его. */
function is_cipher($v, int $max = MAX_CIPHER): bool
{
    return is_string($v) && strlen($v) <= $max && preg_match('#^[A-Za-z0-9+/=]{12,}$#', $v) === 1;
}

function uid(): int { return (int)($_SESSION['uid'] ?? 0); }

function auth(): int
{
    if (!uid()) out(false, [], 'Требуется авторизация', 401);
    return uid();
}

function check_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_SESSION['csrf'] ?? '') !== ($_SERVER['HTTP_X_CSRF'] ?? '')) {
        out(false, [], 'Некорректный CSRF-токен', 403);
    }
}

/** bcrypt не принимает пароли длиннее 72 байт, поэтому сначала хешируем пароль SHA-256. */
function make_verifier(string $password): string
{
    return password_hash(hash('sha256', $password), PASSWORD_BCRYPT, ['cost' => 12]);
}

function check_verifier(string $password, string $verifier): bool
{
    return password_verify(hash('sha256', $password), $verifier);
}

function sql_error(): string
{
    return DBi::$mysqli->error ?: 'SQL error';
}

/* ---------------- маршруты API ---------------- */
$action = $_GET['action'] ?? '';

switch ($action) {

    /* --- доступен ли сервер + создан ли мастер-пароль (первый запуск) --- */
    case 'ping':
        $keys = (int)(DBi::selectCell('SELECT COUNT(*) FROM users') ?? 0);
        out(true, ['online' => true, 'server_time' => date('c'), 'setup_needed' => $keys === 0, 'keys' => $keys]);

    /* --- первый запуск: задаём единственный мастер-пароль (он же ключ шифрования) --- */
    case 'setup':
        $in = input();
        $password = (string)($in['password'] ?? '');
        if (mb_strlen($password) < 8) out(false, [], 'Мастер-пароль должен быть не короче 8 символов', 422);
        if (mb_strlen($password) > 512) out(false, [], 'Мастер-пароль слишком длинный', 422);
        if (DBi::selectCell('SELECT COUNT(*) FROM users')) out(false, [], 'Мастер-пароль уже создан — просто введите его', 409);

        $kdf_salt = bin2hex(random_bytes(16));
        $data = [
            'pass_salt'  => bin2hex(random_bytes(16)),
            'verifier'   => make_verifier($password),
            'kdf_salt'   => $kdf_salt,
            'created_at' => date('Y-m-d H:i:s'),
        ];
        DBi::query('INSERT INTO users(?#) VALUES(?a)', array_keys($data), array_values($data));
        if (DBi::$mysqli->insert_id <= 0) out(false, [], 'Ошибка создания мастер-пароля: ' . sql_error(), 500);

        session_regenerate_id(true);
        $_SESSION['uid'] = DBi::$mysqli->insert_id;
        $_SESSION['fail'] = 0;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));

        out(true, ['created' => true, 'kdf_salt' => $kdf_salt, 'csrf' => $_SESSION['csrf'], 'iterations' => kdf_iterations]);

    /* --- разблокировка: только мастер-пароль, поля «логин» нет --- */
    case 'unlock':
        $in = input();
        $password = (string)($in['password'] ?? '');
        if ($password === '') out(false, [], 'Введите мастер-пароль', 422);
        if ((int)($_SESSION['fail'] ?? 0) >= 8) out(false, [], 'Слишком много неудачных попыток — закройте вкладку и подождите', 429);

        $rows = DBi::select('SELECT id, verifier, kdf_salt FROM users');
        if (!$rows) out(false, [], 'Мастер-пароль ещё не создан — задайте его на этой странице', 409);

        $uid = 0;
        $kdf_salt = '';
        foreach ($rows as $r) {
            if (check_verifier($password, $r['verifier'])) {
                $uid = (int)$r['id'];
                $kdf_salt = $r['kdf_salt'];
                break;
            }
        }
        if (!$uid) {
            $_SESSION['fail'] = (int)($_SESSION['fail'] ?? 0) + 1;
            usleep(200000);                    // замедляем перебор мастер-пароля
            out(false, [], 'Неверный мастер-пароль', 401);
        }

        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        $_SESSION['fail'] = 0;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        out(true, ['kdf_salt' => $kdf_salt, 'csrf' => $_SESSION['csrf'], 'iterations' => kdf_iterations]);

    /* --- выход --- */
    case 'logout':
        check_csrf();
        $_SESSION = [];
        session_destroy();
        out(true, ['logged_out' => true]);

    /* --- активна ли сессия --- */
    case 'whoami':
        auth();
        out(true, ['authorized' => true, 'csrf' => $_SESSION['csrf'] ?? '']);

    /* --- список категорий + число записей --- */
    case 'categories':
        $uid = auth();
        $rows = DBi::select('SELECT id, name, position FROM categories WHERE user_id=? ORDER BY position, name', $uid);
        $counts = DBi::select('SELECT category_id, COUNT(*) AS cnt FROM entries WHERE user_id=? AND deleted_at IS NULL GROUP BY category_id', $uid);
        $cnt = [];
        foreach ($counts as $c) $cnt[(int)$c['category_id']] = (int)$c['cnt'];
        $out = [];
        foreach ($rows as $r) {
            $out[] = ['id' => (int)$r['id'], 'name' => $r['name'], 'position' => (int)$r['position'], 'count' => $cnt[(int)$r['id']] ?? 0];
        }
        out(true, ['categories' => $out]);

    /* --- добавить категорию --- */
    case 'category_add':
        check_csrf();
        $uid = auth();
        $name = field(input(), 'name', 100);
        if ($name === '') out(false, [], 'Имя категории не может быть пустым', 422);
        if (DBi::selectCell('SELECT id FROM categories WHERE user_id=? AND name=?', $uid, $name)) out(false, [], 'Категория с таким именем уже есть', 409);
        $pos = (int)(DBi::selectCell('SELECT MAX(position) FROM categories WHERE user_id=?', $uid) ?? 0) + 1;
        $data = ['user_id' => $uid, 'name' => $name, 'position' => $pos];
        DBi::query('INSERT INTO categories(?#) VALUES(?a)', array_keys($data), array_values($data));
        if (DBi::$mysqli->insert_id <= 0) out(false, [], 'Ошибка создания категории: ' . sql_error(), 500);
        out(true, ['id' => DBi::$mysqli->insert_id, 'name' => $name, 'position' => $pos, 'count' => 0]);

    /* --- переименовать категорию --- */
    case 'category_rename':
        check_csrf();
        $uid = auth();
        $in = input();
        $id = int_field($in, 'id');
        $name = field($in, 'name', 100);
        if (!$id || $name === '') out(false, [], 'Нужны id категории и имя', 422);
        if (DBi::selectCell('SELECT id FROM categories WHERE user_id=? AND name=? AND id<>?', $uid, $name, $id)) out(false, [], 'Категория с таким именем уже есть', 409);
        DBi::query('UPDATE categories SET ?a WHERE id=? AND user_id=?', ['name' => $name], $id, $uid);
        if (DBi::$mysqli->affected_rows === 0) out(false, [], 'Категория не найдена', 404);
        out(true, ['id' => $id, 'name' => $name]);

    /* --- удалить категорию вместе с записями --- */
    case 'category_delete':
        check_csrf();
        $uid = auth();
        $id = int_field(input(), 'id');
        if (!$id) out(false, [], 'Не указан id категории', 422);
        DBi::query('DELETE FROM entries WHERE user_id=? AND category_id=?', $uid, $id);
        DBi::query('DELETE FROM categories WHERE id=? AND user_id=?', $id, $uid);
        if (DBi::$mysqli->affected_rows === 0) out(false, [], 'Категория не найдена', 404);
        out(true, ['id' => $id, 'deleted' => true]);

    /* --- записи категории: сервер отдаёт только шифроттекты --- */
    case 'entries':
        $uid = auth();
        $cat = int_field($_GET + input(), 'category_id');
        if (!$cat) out(false, [], 'Не указан category_id', 422);
        if (!DBi::selectCell('SELECT id FROM categories WHERE id=? AND user_id=?', $cat, $uid)) out(false, [], 'Категория не найдена', 404);
        $rows = DBi::select(
            'SELECT id, title, url, login_cipher, pass_cipher, comment_cipher, updated_at, deleted_at
             FROM entries WHERE user_id=? AND category_id=?
             ORDER BY deleted_at IS NULL DESC, position, id',
            $uid, $cat
        );
        $out = [];
        foreach ($rows as $r) {
            $out[] = [
                'id' => (int)$r['id'],
                'title' => $r['title'],
                'url' => $r['url'],
                'login_cipher' => $r['login_cipher'],
                'pass_cipher' => $r['pass_cipher'],
                'comment_cipher' => $r['comment_cipher'],
                'updated_at' => $r['updated_at'],
                'deleted_at' => $r['deleted_at'],
            ];
        }
        out(true, ['category_id' => $cat, 'entries' => $out]);

    /* --- создать/изменить запись (шифроттекты присылает клиент) --- */
    case 'entry_save':
        check_csrf();
        $uid = auth();
        $in = input();
        $cat = int_field($in, 'category_id');
        $id = int_field($in, 'id');
        $title = field($in, 'title', 200);
        $url = field($in, 'url', 250);
        $login = $in['login_cipher'] ?? null;
        $pass = $in['pass_cipher'] ?? null;
        $comment = $in['comment_cipher'] ?? null;

        if (!$cat || !DBi::selectCell('SELECT id FROM categories WHERE id=? AND user_id=?', $cat, $uid)) out(false, [], 'Категория не найдена', 404);
        if (!is_cipher($login)) out(false, [], 'Логин должен быть зашифрован (base64 AES-GCM)', 422);
        if (!is_cipher($pass)) out(false, [], 'Пароль должен быть зашифрован (base64 AES-GCM)', 422);
        if ($comment !== null && $comment !== '' && !is_cipher($comment)) out(false, [], 'Комментарий должен быть зашифрован (base64 AES-GCM)', 422);

        $data = [
            'user_id'        => $uid,
            'category_id'    => $cat,
            'title'          => $title,
            'url'            => $url,
            'login_cipher'   => $login,
            'pass_cipher'    => $pass,
            'comment_cipher' => ($comment === '' || $comment === null ? '' : $comment),
            'updated_at'     => date('Y-m-d H:i:s'),
        ];

        if ($id > 0) {
            $row = DBi::select('SELECT id, deleted_at FROM entries WHERE id=? AND user_id=?', $id, $uid);
            if (!$row) out(false, [], 'Запись не найдена', 404);
            if (!empty($row[0]['deleted_at'])) out(false, [], 'Запись помечена как удалённая — сначала восстановите её', 409);
            unset($data['user_id']);
            DBi::query('UPDATE entries SET ?a WHERE id=? AND user_id=?', $data, $id, $uid);
            out(true, ['id' => $id]);
        } else {
            // Новая запись — в конец списка категории (низ таблицы).
            $data['position'] = (int)(DBi::selectCell('SELECT MAX(position) FROM entries WHERE user_id=? AND category_id=?', $uid, $cat) ?? 0) + 1;
            DBi::query('INSERT INTO entries(?#) VALUES(?a)', array_keys($data), array_values($data));
            if (DBi::$mysqli->insert_id <= 0) out(false, [], 'Ошибка создания записи: ' . sql_error(), 500);
            out(true, ['id' => DBi::$mysqli->insert_id, 'position' => $data['position']]);
        }

    /* --- удаление: активная запись помечается удалённой, удалённая — удаляется из базы --- */
    case 'entry_delete':
        check_csrf();
        $uid = auth();
        $id = int_field(input(), 'id');
        if (!$id) out(false, [], 'Не указан id записи', 422);
        $row = DBi::select('SELECT id, deleted_at FROM entries WHERE id=? AND user_id=?', $id, $uid);
        if (!$row) out(false, [], 'Запись не найдена', 404);

        if (empty($row[0]['deleted_at'])) {
            DBi::query('UPDATE entries SET ?a WHERE id=? AND user_id=?',
                ['deleted_at' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s')], $id, $uid);
            out(true, ['id' => $id, 'soft_deleted' => true, 'deleted_at' => date('Y-m-d H:i:s')]);
        } else {
            DBi::query('DELETE FROM entries WHERE id=? AND user_id=?', $id, $uid);
            if (DBi::$mysqli->affected_rows === 0) out(false, [], 'Запись не найдена', 404);
            out(true, ['id' => $id, 'deleted' => true]);
        }

    /* --- восстановить помеченную запись --- */
    case 'entry_restore':
        check_csrf();
        $uid = auth();
        $id = int_field(input(), 'id');
        if (!$id) out(false, [], 'Не указан id записи', 422);
        DBi::query('UPDATE entries SET deleted_at=NULL, updated_at=? WHERE id=? AND user_id=?',
            date('Y-m-d H:i:s'), $id, $uid);
        if (DBi::$mysqli->affected_rows === 0) out(false, [], 'Запись не найдена', 404);
        out(true, ['id' => $id, 'restored' => true]);

    /* --- перенести запись в другую категорию (перетаскивание на категорию) --- */
    case 'entry_move':
        check_csrf();
        $uid = auth();
        $in = input();
        $id = int_field($in, 'id');
        $cat = int_field($in, 'category_id');
        if (!$id || !$cat) out(false, [], 'Нужны id записи и category_id', 422);
        if (!DBi::selectCell('SELECT id FROM entries WHERE id=? AND user_id=?', $id, $uid)) out(false, [], 'Запись не найдена', 404);
        if (!DBi::selectCell('SELECT id FROM categories WHERE id=? AND user_id=?', $cat, $uid)) out(false, [], 'Категория не найдена', 404);

        // В новую категорию — в конец списка (position после последней записи этой категории).
        $pos = (int)(DBi::selectCell('SELECT MAX(position) FROM entries WHERE user_id=? AND category_id=?', $uid, $cat) ?? 0) + 1;
        DBi::query('UPDATE entries SET ?a WHERE id=? AND user_id=?',
            ['category_id' => $cat, 'position' => $pos, 'updated_at' => date('Y-m-d H:i:s')], $id, $uid);
        out(true, ['id' => $id, 'category_id' => $cat, 'position' => $pos]);

    /* --- произвольный порядок записей внутри категории (перетаскивание) --- */
    case 'entries_reorder':
        check_csrf();
        $uid = auth();
        $in = input();
        $cat = int_field($in, 'category_id');
        $ids = $in['ids'] ?? [];
        if (!$cat || !is_array($ids)) out(false, [], 'Нужны category_id и список ids', 422);
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if (!$ids) out(false, [], 'Список записей пуст', 422);
        if (!DBi::selectCell('SELECT id FROM categories WHERE id=? AND user_id=?', $cat, $uid)) out(false, [], 'Категория не найдена', 404);

        $owned = array_map('intval', DBi::selectCol('SELECT id FROM entries WHERE user_id=? AND category_id=?', $uid, $cat));
        if (count($ids) !== count($owned) || array_diff($ids, $owned) || array_diff($owned, $ids)) {
            out(false, [], 'Список записей не совпадает с содержимым категории', 422);
        }

        $pos = 0;
        foreach ($ids as $id) {
            DBi::query('UPDATE entries SET ?a WHERE id=? AND user_id=?', ['position' => $pos++], $id, $uid);
        }
        out(true, ['category_id' => $cat, 'count' => $pos]);

    /* --- произвольный порядок категорий (перетаскивание) --- */
    case 'categories_reorder':
        check_csrf();
        $uid = auth();
        $ids = input()['ids'] ?? [];
        if (!is_array($ids)) out(false, [], 'Нужен список ids категорий', 422);
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if (!$ids) out(false, [], 'Список категорий пуст', 422);

        $owned = array_map('intval', DBi::selectCol('SELECT id FROM categories WHERE user_id=?', $uid));
        if (count($ids) !== count($owned) || array_diff($ids, $owned) || array_diff($owned, $ids)) {
            out(false, [], 'Список категорий не совпадает с их содержимым', 422);
        }

        $pos = 0;
        foreach ($ids as $id) {
            DBi::query('UPDATE categories SET ?a WHERE id=? AND user_id=?', ['position' => $pos++], $id, $uid);
        }
        out(true, ['count' => $pos]);

    default:
        out(false, [], 'Неизвестное действие: ' . $action, 404);
}
