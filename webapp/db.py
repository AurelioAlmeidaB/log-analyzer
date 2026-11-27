"""Banco SQLite: usuários, códigos de recuperação, aplicações e linhas de log."""

from __future__ import annotations

import sqlite3

from flask import Flask, current_app, g

SCHEMA = """
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
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.execute("PRAGMA journal_mode = WAL")   # o agente grava enquanto alguém lê o painel
        db.executescript(SCHEMA)
        db.commit()
