<?php
/**
 * Установщик: создаёт базу (если её нет) и таблицы из schema.sql.
 * Запуск: php install.php  —  или открыть в браузере /install.php (нужны права на DDL).
 */
declare(strict_types=1);

require __DIR__ . '/config.php';
require __DIR__ . '/lib/dbi.class.php';

$cli = php_sapi_name() === 'cli';

function line(string $text): void
{
    global $cli;
    if ($cli) {
        echo $text . "\n";
    } else {
        echo htmlspecialchars($text) . "<br>\n";
    }
}

if (!$cli) {
    header('Content-Type: text/plain; charset=utf-8');
    echo "<pre>\n";
}

/* 1. Подключение без БД — создаём БД, если её нет. */
$root = @new mysqli(dbhost, dbuser, dbpass);
if ($root->connect_error) {
    line('Не удалось подключиться к MySQL: ' . $root->connect_error);
    line('Проверьте константы dbhost / dbuser / dbpass в config/config.php');
    exit;
}
if ($root->query('CREATE DATABASE IF NOT EXISTS `' . dbname . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')) {
    line('База "' . dbname . '" готова (создана, если её не было).');
} else {
    line('Не удалось создать базу "' . dbname . '": ' . $root->error . ' (продолжаем, таблицы создадим в существующей)');
}
$root->close();

/* 2. Таблицы из schema.sql — через DBi. */
DBi::init();
DBi::$mysqli->set_charset(db_charset);
DBi::$skip_error = true;

$schema = (string)file_get_contents(__DIR__ . '/schema.sql');
$schema = preg_replace('/^\s*--.*$/m', '', $schema);
$statements = array_filter(array_map('trim', explode(';', $schema)));

$ok = true;
foreach ($statements as $stmt) {
    $name = '';
    if (preg_match('/CREATE TABLE IF NOT EXISTS\s+`?(\w+)`?/i', $stmt, $m)) $name = $m[1];
    $res = DBi::query($stmt);
    if ($res === false) {
        $ok = false;
        line('Ошибка в таблице ' . ($name ?: '?') . ': ' . (DBi::$mysqli->error ?: 'SQL error'));
    } else {
        line('Таблица ' . ($name ?: '?') . ' — ок');
    }
}

/* 3. Миграция: поля position (порядок задаётся перетаскиванием) и deleted_at (мягкое удаление). */
if (in_array('entries', DBi::selectCol('SHOW TABLES'))) {
    $cols = (int)(DBi::selectCell(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'entries' AND COLUMN_NAME = 'position'
    ") ?? 0);
    if ($cols === 0) {
        DBi::query('ALTER TABLE entries ADD COLUMN position INT NOT NULL DEFAULT 0 AFTER updated_at');
        line('entries.position — добавлено');
        // Заполняем порядок по id (записи вставляются в конце, поэтому id растёт снизу).
        $rows = DBi::select('SELECT id, category_id FROM entries ORDER BY category_id, id');
        $seq = [];
        foreach ($rows as $r) {
            $cat = (int)$r['category_id'];
            $seq[$cat] = ($seq[$cat] ?? -1) + 1;
            DBi::query('UPDATE entries SET ?a WHERE id=?', ['position' => $seq[$cat]], (int)$r['id']);
        }
        line('entries.position — заполнено по id (' . count($rows) . ' записей)');
    } else {
        line('entries.position — уже есть');
    }

    $del = (int)(DBi::selectCell(
        "SELECT COUNT(*) FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'entries' AND COLUMN_NAME = 'deleted_at'
    ") ?? 0);
    if ($del === 0) {
        DBi::query('ALTER TABLE entries ADD COLUMN deleted_at DATETIME DEFAULT NULL AFTER position');
        line('entries.deleted_at — добавлено (записи помечаются, а не удаляются)');
    } else {
        line('entries.deleted_at — уже есть');
    }
}

/* 4. Проверка: все ли три таблицы присутствуют. */
$existing = DBi::selectCol('SHOW TABLES');
line('Таблицы в базе: ' . implode(', ', $existing));

if ($ok && in_array('users', $existing) && in_array('categories', $existing) && in_array('entries', $existing)) {
    line('');
    line('Установка завершена. Откройте index.php: на странице авторизации задайте мастер-пароль (первый запуск).');
} else {
    line('');
    line('Установка завершилась с ошибками — проверьте schema.sql и права пользователя MySQL.');
}

if (!$cli) echo "</pre>\n";
