"""
Banco SQLite: usuários, organizações (equipes), papéis, aplicações e linhas de log.

O esquema evolui por migrações numeradas (PRAGMA user_version), então um banco
criado numa versão antiga é atualizado sozinho, sem perder dados.
"""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, current_app, g

# Versão 1: o esquema original, de quando cada aplicação pertencia a uma pessoa.
SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    totp_secret    TEXT,                       -- NULL até a pessoa configurar o 2FA
    totp_pending   TEXT,                       -- segredo mostrado no QR, antes de ser confirmado
    totp_last_step INTEGER NOT NULL DEFAULT 0, -- impede reusar o mesmo código de 6 dígitos
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT
);

-- Tentativas erradas de login e de 2FA, para bloquear brute force no próprio sistema.
CREATE TABLE IF NOT EXISTS auth_failures (
    id  INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_failures_key ON auth_failures(key, at);

CREATE TABLE IF NOT EXISTS apps (
    id               INTEGER PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- quem criou
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('ssh', 'web')),
    threshold        INTEGER NOT NULL DEFAULT 5,
    api_key_hash     TEXT NOT NULL UNIQUE,     -- só o hash: a chave aparece uma vez para a pessoa
    api_key_hint     TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_received_at TEXT,
    version          INTEGER NOT NULL DEFAULT 0,   -- muda a cada envio de linhas
    summary_json     TEXT,                         -- resumo da última análise
    summary_version  INTEGER NOT NULL DEFAULT -1
);

CREATE TABLE IF NOT EXISTS log_lines (
    id          INTEGER PRIMARY KEY,
    app_id      INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    line        TEXT NOT NULL,
    source      TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_log_lines_app ON log_lines(app_id, id);
"""

MIGRATIONS = {
    # Versão 2: aplicações passam a pertencer a organizações, com papéis por membro;
    # sessões ficam no servidor (podem ser revogadas); registro de atividade.
    2: """
    CREATE TABLE orgs (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE memberships (
        org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role       TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (org_id, user_id)
    );
    CREATE INDEX idx_memberships_user ON memberships(user_id);

    CREATE TABLE invitations (
        id          INTEGER PRIMARY KEY,
        org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        email       TEXT NOT NULL COLLATE NOCASE,
        role        TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
        token_hash  TEXT NOT NULL UNIQUE,
        invited_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at  REAL NOT NULL,
        accepted_at TEXT
    );

    CREATE TABLE user_sessions (
        id         INTEGER PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        created_at REAL NOT NULL,
        last_seen  REAL NOT NULL,
        ip         TEXT,
        user_agent TEXT
    );
    CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);

    CREATE TABLE audit_events (
        id      INTEGER PRIMARY KEY,
        org_id  INTEGER REFERENCES orgs(id) ON DELETE CASCADE,   -- NULL: evento só da conta
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action  TEXT NOT NULL,
        detail  TEXT NOT NULL DEFAULT '',
        ip      TEXT,
        at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX idx_audit_org ON audit_events(org_id, id);

    ALTER TABLE apps ADD COLUMN org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE;
    CREATE INDEX idx_apps_org ON apps(org_id);

    -- Códigos antigos usavam SHA-256 puro; os novos usam HMAC com a chave do servidor.
    ALTER TABLE recovery_codes ADD COLUMN scheme TEXT NOT NULL DEFAULT 'sha256';

    -- Cada pessoa que já existia ganha uma organização própria, como administradora,
    -- e as aplicações dela vão para essa organização.
    INSERT INTO orgs (id, name)
        SELECT id, 'Organização de ' || substr(email, 1, instr(email, '@') - 1) FROM users;
    INSERT INTO memberships (org_id, user_id, role) SELECT id, id, 'admin' FROM users;
    UPDATE apps SET org_id = user_id;
    """,
}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def migrate(db: sqlite3.Connection) -> int:
    db.executescript(SCHEMA_V1)
    version = db.execute("PRAGMA user_version").fetchone()[0]
    for number in sorted(MIGRATIONS):
        if number > version:
            # Tudo numa transação: ou a migração inteira entra, ou nada muda.
            db.executescript(f"BEGIN;\n{MIGRATIONS[number]}\nPRAGMA user_version = {number};\nCOMMIT;")
            version = number
    return version


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.execute("PRAGMA journal_mode = WAL")   # o agente grava enquanto alguém lê o painel
        migrate(db)
        db.commit()
    # Senhas (em hash), segredos do 2FA e logs: só o dono do processo lê o arquivo.
    # O SQLite cria os arquivos -wal e -shm novos com a mesma permissão do banco.
    for suffix in ("", "-wal", "-shm"):
        path = app.config["DATABASE"] + suffix
        if os.path.exists(path):
            os.chmod(path, 0o600)
