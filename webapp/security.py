"""
Proteções comuns a todas as páginas:
  - token CSRF em todo formulário POST
  - cabeçalhos de segurança (CSP com nonce, anti-clickjacking, HSTS com HTTPS)
  - limite de tentativas erradas (o próprio login não pode sofrer brute force)
  - sessões guardadas no servidor: sair, trocar a senha ou encerrar sessões revoga de verdade
  - organizações e papéis: quem pode ver e quem pode mudar cada coisa
  - registro de atividade das ações administrativas
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, abort, current_app, flash, g, redirect, request, session, url_for

from .db import get_db

CSRF_EXEMPT = {"monitor.ingest"}   # a API usa chave no cabeçalho, não cookie de sessão

SESSION_IDLE = 2 * 3600            # sem uso por 2 h: precisa entrar de novo
SESSION_MAX = 12 * 3600            # no máximo 12 h, mesmo usando

# Papéis, do que pode menos para o que pode mais.
ROLE_RANK = {"analyst": 1, "admin": 2}
ROLE_LABELS = {"admin": "Administrador", "analyst": "Analista SOC"}

# Papel mínimo para cada ação. O servidor confere sempre; a interface só esconde
# os botões que a pessoa não pode usar.
PERMISSIONS = {
    "view": "analyst",          # ver aplicações, painéis e linhas de log
    "export": "analyst",        # baixar o relatório em JSON
    "upload": "admin",          # enviar arquivo de log
    "manage_apps": "admin",     # criar e excluir aplicações, trocar chave, apagar logs
    "manage_team": "admin",     # convidar, mudar papéis, remover membros, renomear a organização
    "view_audit": "admin",      # ver o registro de atividade
}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csp_nonce() -> str:
    if "csp_nonce" not in g:
        g.csp_nonce = secrets.token_urlsafe(16)
    return g.csp_nonce


def _check_csrf() -> None:
    if request.method != "POST" or request.endpoint in CSRF_EXEMPT:
        return
    expected = session.get("csrf")
    sent = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "O formulário expirou. Recarregue a página e tente de novo.")


def _security_headers(response):
    nonce = csp_nonce()
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if current_app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if response.mimetype in ("text/html", "application/json"):
        response.headers["Cache-Control"] = "no-store"   # dados não ficam em cache
    return response


def init_app(app: Flask) -> None:
    app.before_request(_check_csrf)
    app.after_request(_security_headers)
    app.jinja_env.globals.update(csrf_token=csrf_token, csp_nonce=csp_nonce, can=can, ROLE_LABELS=ROLE_LABELS)


# --- Limite de tentativas -------------------------------------------------------------


def retry_after(key: str, limit: int, window: int) -> int:
    """Segundos até poder tentar de novo, ou 0 se ainda não passou do limite."""
    since = time.time() - window
    rows = get_db().execute(
        "SELECT at FROM auth_failures WHERE key = ? AND at > ? ORDER BY at", (key, since)
    ).fetchall()
    if len(rows) < limit:
        return 0
    return max(1, int(rows[-limit]["at"] + window - time.time()))


def record_failure(*keys: str) -> None:
    db = get_db()
    now = time.time()
    db.executemany("INSERT INTO auth_failures (key, at) VALUES (?, ?)", [(k, now) for k in keys])
    db.execute("DELETE FROM auth_failures WHERE at < ?", (now - 86400,))
    db.commit()


def clear_failures(key: str) -> None:
    db = get_db()
    db.execute("DELETE FROM auth_failures WHERE key = ?", (key,))
    db.commit()


def client_ip() -> str:
    return request.remote_addr or "?"


def safe_next(target: str | None) -> str | None:
    """Só aceita voltar para um caminho deste site (evita redirecionamento aberto).

    "/\\\\site.com" também é recusado: os navegadores tratam a barra invertida
    como "/" e iriam para outro site.
    """
    if not target or not target.startswith("/") or target[1:2] in ("/", "\\"):
        return None
    if "\\" in target or any(ord(c) < 32 for c in target):
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    return target


# --- Sessões no servidor ----------------------------------------------------------------


def start_session(user_id: int, next_org: int | None = None) -> None:
    """Login completo. Sessão nova (contra fixação de sessão) registrada no banco."""
    session.clear()
    token = secrets.token_urlsafe(32)
    now = time.time()
    db = get_db()
    db.execute(
        "INSERT INTO user_sessions (user_id, token_hash, created_at, last_seen, ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, token_hash(token), now, now, client_ip(), request.headers.get("User-Agent", "")[:200]))
    db.commit()
    session["uid"] = user_id
    session["sid"] = token
    if next_org:
        session["org_id"] = next_org
    session.permanent = True


def end_session() -> None:
    token = session.get("sid")
    if token:
        db = get_db()
        db.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash(token),))
        db.commit()
    session.clear()


def end_other_sessions(user_id: int) -> int:
    """Encerra as sessões da pessoa em outros navegadores; devolve quantas."""
    current = token_hash(session.get("sid", ""))
    db = get_db()
    cur = db.execute("DELETE FROM user_sessions WHERE user_id = ? AND token_hash != ?", (user_id, current))
    db.commit()
    return cur.rowcount


def current_user():
    """(usuário, sessão) válidos, ou (None, motivo)."""
    uid, token = session.get("uid"), session.get("sid")
    if uid is None or not token:
        return None, "anon"
    db = get_db()
    row = db.execute("SELECT * FROM user_sessions WHERE token_hash = ? AND user_id = ?",
                     (token_hash(token), uid)).fetchone()
    if row is None:
        return None, "revoked"
    now = time.time()
    if now - row["created_at"] > SESSION_MAX or now - row["last_seen"] > SESSION_IDLE:
        db.execute("DELETE FROM user_sessions WHERE id = ?", (row["id"],))
        db.commit()
        return None, "expired"
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None or user["totp_secret"] is None:
        return None, "revoked"
    if now - row["last_seen"] > 60:
        db.execute("UPDATE user_sessions SET last_seen = ? WHERE id = ?", (now, row["id"]))
        db.commit()
    return user, row


# --- Organizações e papéis -------------------------------------------------------------


def create_personal_org(db, user_id: int, email: str) -> int:
    cur = db.execute("INSERT INTO orgs (name) VALUES (?)", (f"Organização de {email.split('@')[0]}",))
    db.execute("INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, 'admin')", (cur.lastrowid, user_id))
    return cur.lastrowid


def load_memberships() -> None:
    """Define g.orgs (todas as organizações da pessoa), g.org (a atual) e g.role."""
    db = get_db()
    query = ("SELECT orgs.id, orgs.name, m.role FROM memberships m JOIN orgs ON orgs.id = m.org_id "
             "WHERE m.user_id = ? ORDER BY orgs.name COLLATE NOCASE")
    orgs = db.execute(query, (g.user["id"],)).fetchall()
    if not orgs:                       # removida de todas: ganha uma organização própria
        create_personal_org(db, g.user["id"], g.user["email"])
        db.commit()
        orgs = db.execute(query, (g.user["id"],)).fetchall()
    current = next((o for o in orgs if o["id"] == session.get("org_id")), orgs[0])
    session["org_id"] = current["id"]
    g.orgs, g.org, g.role = orgs, current, current["role"]


def switch_org(org_id: int) -> bool:
    if not any(o["id"] == org_id for o in g.orgs):
        return False
    session["org_id"] = org_id
    load_memberships()
    return True


def can(action: str, role: str | None = None) -> bool:
    role = role or g.get("role")
    return role is not None and ROLE_RANK[role] >= ROLE_RANK[PERMISSIONS[action]]


def require(action: str, role: str | None = None) -> None:
    if not can(action, role):
        abort(403)


def audit(action: str, detail: str = "", org_id: int | None = -1) -> None:
    """Registra uma ação. org_id=-1 usa a organização atual; None é evento só da conta."""
    if org_id == -1:
        org_id = g.org["id"] if g.get("org") else None
    user = g.get("user")
    get_db().execute("INSERT INTO audit_events (org_id, user_id, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
                     (org_id, user["id"] if user else None, action, detail[:300], client_ip()))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user, reason = current_user()
        if user is None:
            if reason in ("expired", "revoked"):
                session.clear()
                flash("Sua sessão terminou. Entre de novo para continuar.", "warn")
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        g.user = user
        load_memberships()
        return view(*args, **kwargs)

    return wrapped
