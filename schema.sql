-- Схема базы "Менеджер паролей".
-- Логина нет: единственный вход в приложение — мастер-пароль, он же ключ шифрования.
-- Таблица users хранит только bcrypt-верификатор (password_verify) мастер-пароля, сам пароль не хранится.
-- Логины, пароли и комментарии записей хранятся в БД зашифрованными (AES-256-GCM, base64: iv + ciphertext + tag).
-- Ключ шифрования выводится из мастер-пароля на клиенте (PBKDF2-SHA256), сервер ключ не хранит.

CREATE TABLE IF NOT EXISTS users (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  pass_salt  VARCHAR(32) NOT NULL,
  verifier   VARCHAR(255) NOT NULL,
  kdf_salt   VARCHAR(32) NOT NULL,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS categories (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  user_id  INT NOT NULL,
  name     VARCHAR(100) NOT NULL,
  position INT NOT NULL DEFAULT 0,
  UNIQUE KEY uq_user_name (user_id, name),
  CONSTRAINT fk_cat_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS entries (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT NOT NULL,
  category_id    INT NOT NULL,
  title          VARCHAR(200) NOT NULL DEFAULT '',
  url            VARCHAR(250) NOT NULL DEFAULT '',
  login_cipher   TEXT NOT NULL,
  pass_cipher    TEXT NOT NULL,
  comment_cipher TEXT,
  updated_at     DATETIME NOT NULL,
  position       INT NOT NULL DEFAULT 0,
  deleted_at     DATETIME DEFAULT NULL,
  KEY idx_cat (user_id, category_id),
  KEY idx_cat_pos (user_id, category_id, position),
  CONSTRAINT fk_entry_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_entry_cat  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
