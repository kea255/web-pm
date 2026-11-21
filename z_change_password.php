<?php
/**
 * Смена мастер-пароля web-pm.
 * Расшифровывает все записи старым паролем, шифрует новым, обновляет verifier и kdf_salt.
 * Всё в одной транзакции: при любой ошибке БД не меняется.
 *
 * Запуск (рядом с config.php):  php change_master.php [--dry-run]
 * Перед запуском: mysqldump <db> > backup.sql
 *
 * Формат совпадает с assets/app.js / api.php:
 *   key    = PBKDF2-SHA256(password, hex2bin(kdf_salt), kdf_iterations) -> 32 байта
 *   cipher = base64(iv[12] . ciphertext . tag[16]), AES-256-GCM, без AAD
 *   verifier = password_hash(sha256_hex(password), BCRYPT, cost 12)
 */
declare(strict_types=1);

const IV_LEN  = 12;
const TAG_LEN = 16;

function derive_key(string $password, string $saltHex, int $iterations): string
{
    return hash_pbkdf2('sha256', $password, hex2bin($saltHex), $iterations, 32, true);
}

/** @return string|null  null = неверный ключ / повреждённые данные */
function dec_field(string $key, ?string $cipher): ?string
{
    if ($cipher === null || $cipher === '') return '';
    $raw = base64_decode($cipher, true);
    if ($raw === false || strlen($raw) < IV_LEN + TAG_LEN) return null;
    $iv  = substr($raw, 0, IV_LEN);
    $tag = substr($raw, -TAG_LEN);
    $ct  = substr($raw, IV_LEN, -TAG_LEN);
    $plain = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $plain === false ? null : $plain;
}

/** Пустое значение -> '' (как в api.php для пустого комментария). */
function enc_field(string $key, string $plain): string
{
    if ($plain === '') return '';
    $iv  = random_bytes(IV_LEN);
    $tag = '';
    $ct  = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', TAG_LEN);
    if ($ct === false) throw new RuntimeException('openssl_encrypt failed');
    return base64_encode($iv . $ct . $tag);
}

function check_verifier(string $password, string $verifier): bool
{
    return password_verify(hash('sha256', $password), $verifier);
}

function make_verifier(string $password): string
{
    return password_hash(hash('sha256', $password), PASSWORD_BCRYPT, ['cost' => 12]);
}

function ask_hidden(string $prompt): string
{
    fwrite(STDERR, $prompt);
    $tty = function_exists('posix_isatty') ? posix_isatty(STDIN) : true;
    if ($tty) shell_exec('stty -echo 2>/dev/null');
    $line = fgets(STDIN);
    if ($tty) shell_exec('stty echo 2>/dev/null');
    fwrite(STDERR, "\n");
    if ($line === false) die("Ввод прерван\n");
    return rtrim($line, "\r\n");
}

function main(array $argv): void
{
    if (php_sapi_name() !== 'cli') { http_response_code(403); exit("Только CLI\n"); }
    $dry = in_array('--dry-run', $argv, true);

    require __DIR__ . '/config.php';
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = new mysqli(dbhost, dbuser, dbpass, dbname);
    $db->set_charset(defined('db_charset') ? db_charset : 'utf8mb4');
    $iter = defined('kdf_iterations') ? (int)kdf_iterations : 100000;

    $old = ask_hidden('Текущий мастер-пароль: ');
    $new = ask_hidden('Новый мастер-пароль: ');
    $new2 = ask_hidden('Повторите новый: ');
    if ($new !== $new2)            die("Новые пароли не совпадают\n");
    if (mb_strlen($new) < 8)       die("Новый пароль короче 8 символов\n");
    if (mb_strlen($new) > 512)     die("Новый пароль длиннее 512 символов\n");
    if ($new === $old)             die("Новый пароль совпадает со старым\n");

    $db->begin_transaction();
    try {
        // Блокируем users на время операции, находим пользователя по старому паролю.
        $uid = 0; $oldSalt = '';
        $res = $db->query('SELECT id, verifier, kdf_salt FROM users FOR UPDATE');
        while ($r = $res->fetch_assoc()) {
            if (check_verifier($old, $r['verifier'])) { $uid = (int)$r['id']; $oldSalt = $r['kdf_salt']; break; }
        }
        $res->free();
        if (!$uid) throw new RuntimeException('Неверный текущий мастер-пароль');

        $oldKey  = derive_key($old, $oldSalt, $iter);
        $newSalt = bin2hex(random_bytes(16));
        $newKey  = derive_key($new, $newSalt, $iter);

        // Все записи пользователя, включая помеченные удалёнными.
        $res = $db->query('SELECT id, login_cipher, pass_cipher, comment_cipher FROM entries WHERE user_id=' . $uid . ' FOR UPDATE');
        $rows = $res->fetch_all(MYSQLI_ASSOC);
        $res->free();

        $out = [];
        $bad = [];
        foreach ($rows as $r) {
            $f = [];
            foreach (['login_cipher', 'pass_cipher', 'comment_cipher'] as $col) {
                $p = dec_field($oldKey, $r[$col]);
                if ($p === null) { $bad[] = $r['id'] . ':' . $col; continue; }
                $n = enc_field($newKey, $p);
                if (dec_field($newKey, $n) !== $p) throw new RuntimeException("Ошибка проверки round-trip: id={$r['id']} $col");
                $f[$col] = $n;
            }
            $out[(int)$r['id']] = $f;
        }
        if ($bad) throw new RuntimeException('Не расшифровались поля (' . count($bad) . '): ' . implode(', ', $bad));

        if ($dry) {
            $db->rollback();
            echo 'dry-run: ок, записей к перешифровке: ' . count($out) . ", БД не изменена\n";
            return;
        }

        $st = $db->prepare('UPDATE entries SET login_cipher=?, pass_cipher=?, comment_cipher=? WHERE id=? AND user_id=?');
        foreach ($out as $id => $f) {
            $st->bind_param('sssii', $f['login_cipher'], $f['pass_cipher'], $f['comment_cipher'], $id, $uid);
            $st->execute();
        }
        $st->close();

        $ver = make_verifier($new);
        $st = $db->prepare('UPDATE users SET verifier=?, kdf_salt=? WHERE id=?');
        $st->bind_param('ssi', $ver, $newSalt, $uid);
        $st->execute();
        $st->close();

        $db->commit();
        echo 'Готово. Перешифровано записей: ' . count($out) . "\n";
        echo "Клиентам: войти онлайн с новым паролем (офлайн-кэш в IndexedDB обновится при входе).\n";
    } catch (Throwable $e) {
        $db->rollback();
        fwrite(STDERR, 'ОШИБКА: ' . $e->getMessage() . "\nБД не изменена.\n");
        exit(1);
    }
}

if (isset($argv[0]) && realpath($argv[0]) === __FILE__) main($argv);
