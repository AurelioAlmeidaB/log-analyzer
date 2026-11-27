"""
Proteções comuns a todas as páginas:
  - token CSRF em todo formulário POST
  - cabeçalhos de segurança (CSP com nonce, anti-clickjacking, HSTS com HTTPS)
  - limite de tentativas erradas (o próprio login não pode sofrer brute force)
  - exigência de login completo (senha + 2FA) nas páginas internas
"""

from __future__ import annotations

import hmac
import secrets
import time
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, abort, current_app, g, redirect, request, session, url_for

from .db import get_db

CSRF_EXEMPT = {"monitor.ingest"}   # a API usa chave no cabeçalho, não cookie de sessão


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
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store"   # páginas com dados não ficam em cache
    return response


def init_app(app: Flask) -> None:
    app.before_request(_check_csrf)
    app.after_request(_security_headers)
    app.jinja_env.globals.update(csrf_token=csrf_token, csp_nonce=csp_nonce)


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


# --- Sessão ---------------------------------------------------------------------------


def safe_next(target: str | None) -> str | None:
    """Só aceita voltar para um caminho deste site (evita redirecionamento aberto)."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


def start_session(user_id: int) -> None:
    """Login completo. Limpa a sessão antiga para evitar fixação de sessão."""
    session.clear()
    session["uid"] = user_id
    session.permanent = True


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        uid = session.get("uid")
        login_url = url_for("auth.login", next=request.full_path.rstrip("?"))
        if uid is None:
            return redirect(login_url)      # não apaga um login que está na etapa do código
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user is None or user["totp_secret"] is None:
            session.clear()                 # conta apagada ou sessão inválida
            return redirect(login_url)
        g.user = user
        return view(*args, **kwargs)

    return wrapped
