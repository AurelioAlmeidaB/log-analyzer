"""
Contas: cadastro, login em duas etapas (senha + código do app autenticador),
códigos de recuperação, troca de senha e saída.

Fluxo:
  cadastro -> configurar 2FA (QR code) -> códigos de recuperação -> dentro
  entrar (e-mail e senha) -> código de 6 dígitos (ou de recuperação) -> dentro
"""

from __future__ import annotations

import math
import re
import sqlite3
import time

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import totp
from .db import get_db
from .security import (clear_failures, client_ip, login_required, record_failure, retry_after, safe_next,
                       start_session)

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOGIN_LIMIT = 5        # senhas erradas por e-mail em 15 min
IP_LIMIT = 20          # senhas erradas por IP em 15 min
CODE_LIMIT = 5         # códigos errados por conta em 15 min
SIGNUP_LIMIT = 5       # cadastros por IP em 1 h
WINDOW = 15 * 60
PENDING_TTL = 5 * 60   # tempo para digitar o código depois da senha
SETUP_TTL = 15 * 60    # tempo para configurar o 2FA depois do cadastro

COMMON_PASSWORDS = {
    "1234567890", "12345678910", "0123456789", "1q2w3e4r5t", "qwertyuiop", "abcdefghij",
    "senha12345", "senhasenha", "password123", "password1234", "administrador", "iloveyou12",
}

_dummy_hash = None


def _hash(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def _check_password(stored: str | None, password: str) -> bool:
    """Compara sempre um hash, mesmo sem usuário, para o tempo de resposta não revelar quem existe."""
    global _dummy_hash
    if stored is None:
        _dummy_hash = _dummy_hash or _hash("conta-que-nao-existe")
        check_password_hash(_dummy_hash, password)
        return False
    return check_password_hash(stored, password)


def password_problem(password: str, email: str) -> str | None:
    lowered = password.lower()
    if len(password) < 10:
        return "Use pelo menos 10 caracteres. Uma frase com espaços é fácil de lembrar e forte."
    if len(password) > 128:
        return "Use no máximo 128 caracteres."
    if lowered in COMMON_PASSWORDS or lowered in (email.lower(), email.split("@")[0].lower()) or len(set(password)) < 4:
        return "Essa senha é fácil de adivinhar. Escolha outra."
    return None


def wait_text(seconds: int) -> str:
    minutes = math.ceil(seconds / 60)
    return f"{minutes} minuto" if minutes == 1 else f"{minutes} minutos"


def _begin_setup(user_id: int) -> None:
    session.clear()
    session["setup_uid"] = user_id
    session["setup_at"] = time.time()


def _store_recovery_codes(db, user_id: int) -> list[str]:
    codes = totp.new_recovery_codes()
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    db.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                   [(user_id, totp.hash_recovery_code(c)) for c in codes])
    return codes


@bp.route("/cadastro", methods=["GET", "POST"])
def register():
    if not current_app.config["ALLOW_SIGNUP"]:
        abort(404)
    if session.get("uid"):
        return redirect(url_for("monitor.index"))
    error, email = None, ""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        ip_key = f"signup:{client_ip()}"
        wait = retry_after(ip_key, SIGNUP_LIMIT, 3600)
        if wait:
            error = f"Muitos cadastros feitos daqui. Tente de novo em {wait_text(wait)}."
        elif len(email) > 254 or not EMAIL_RE.match(email):
            error = "Digite um e-mail válido."
        elif password != request.form.get("confirm", ""):
            error = "As duas senhas não são iguais."
        else:
            error = password_problem(password, email)
        if not error:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, _hash(password)))
                db.commit()
            except sqlite3.IntegrityError:
                error = "Já existe uma conta com esse e-mail. Entre com ela ou use outro e-mail."
            else:
                record_failure(ip_key)      # conta cadastros por IP
                _begin_setup(cur.lastrowid)
                return redirect(url_for("auth.setup_2fa"))
    return render_template("auth/register.html", error=error, email=email)


@bp.route("/2fa/configurar", methods=["GET", "POST"])
def setup_2fa():
    uid = session.get("setup_uid")
    if not uid or time.time() - session.get("setup_at", 0) > SETUP_TTL:
        session.clear()
        return redirect(url_for("auth.login"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None or user["totp_secret"]:
        session.clear()
        return redirect(url_for("auth.login"))

    secret = user["totp_pending"]
    if not secret:
        secret = totp.new_secret()
        db.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (secret, uid))
        db.commit()

    error = None
    if request.method == "POST":
        key = f"2fa:{uid}"
        wait = retry_after(key, CODE_LIMIT, WINDOW)
        step = None if wait else totp.verify(secret, request.form.get("code", ""), last_step=0)
        if wait:
            error = f"Muitos códigos errados. Tente de novo em {wait_text(wait)}."
        elif step is None:
            record_failure(key)
            error = "Código incorreto. Digite o código que aparece agora no app (ele muda a cada 30 segundos)."
        else:
            db.execute("UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_last_step = ? WHERE id = ?",
                       (secret, step, uid))
            codes = _store_recovery_codes(db, uid)
            db.commit()
            clear_failures(key)
            start_session(uid)
            return render_template("auth/recovery_codes.html", codes=codes, first_time=True)

    uri = totp.provisioning_uri(secret, user["email"])
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("auth/setup_2fa.html", qr=totp.qr_svg(uri), secret=grouped, uri=uri, error=error)


@bp.route("/entrar", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("monitor.index"))
    next_url = safe_next(request.values.get("next"))
    error, email, status = None, "", 200
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        email_key, ip_key = f"login:{email.lower()}", f"login-ip:{client_ip()}"
        wait = max(retry_after(email_key, LOGIN_LIMIT, WINDOW), retry_after(ip_key, IP_LIMIT, WINDOW))
        if wait:
            error, status = f"Muitas tentativas erradas. Tente de novo em {wait_text(wait)}.", 429
        else:
            user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not _check_password(user["password_hash"] if user else None, password):
                record_failure(email_key, ip_key)
                error = "E-mail ou senha incorretos."
            else:
                clear_failures(email_key)
                if user["totp_secret"] is None:          # cadastrou mas não terminou o 2FA
                    _begin_setup(user["id"])
                    return redirect(url_for("auth.setup_2fa"))
                session.clear()
                session["pending_uid"] = user["id"]
                session["pending_at"] = time.time()
                if next_url:
                    session["next"] = next_url
                return redirect(url_for("auth.verify_2fa"))
    return render_template("auth/login.html", error=error, email=email, next=next_url,
                           allow_signup=current_app.config["ALLOW_SIGNUP"]), status


@bp.route("/entrar/codigo", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_uid")
    if not uid or time.time() - session.get("pending_at", 0) > PENDING_TTL:
        session.clear()
        return redirect(url_for("auth.login"))
    error, status = None, 200
    if request.method == "POST":
        key = f"2fa:{uid}"
        wait = retry_after(key, CODE_LIMIT, WINDOW)
        if wait:
            error, status = f"Muitos códigos errados. Tente de novo em {wait_text(wait)}.", 429
        else:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            code = request.form.get("code", "")
            ok, used_recovery = False, False
            if totp.looks_like_recovery_code(code):
                # UPDATE condicional: dois pedidos ao mesmo tempo não usam o mesmo código.
                cur = db.execute(
                    "UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP "
                    "WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                    (uid, totp.hash_recovery_code(code)))
                ok = used_recovery = cur.rowcount == 1
            else:
                step = totp.verify(user["totp_secret"], code, user["totp_last_step"])
                if step is not None:
                    cur = db.execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                                     (step, uid, step))
                    ok = cur.rowcount == 1
            if ok:
                db.commit()
                clear_failures(key)
                next_url = session.get("next")
                start_session(uid)
                if used_recovery:
                    left = db.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                                      (uid,)).fetchone()[0]
                    flash(f"Você entrou com um código de recuperação. Restam {left}. "
                          "Se perdeu o celular, gere novos códigos em Conta.")
                return redirect(next_url or url_for("monitor.index"))
            record_failure(key)
            error = "Código incorreto ou já usado."
    return render_template("auth/verify_2fa.html", error=error), status


@bp.route("/sair", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/conta")
@login_required
def account():
    left = get_db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                            (g.user["id"],)).fetchone()[0]
    return render_template("auth/account.html", recovery_left=left)


@bp.route("/conta/senha", methods=["POST"])
@login_required
def change_password():
    uid = g.user["id"]
    key = f"password:{uid}"
    wait = retry_after(key, LOGIN_LIMIT, WINDOW)
    new = request.form.get("new", "")
    if wait:
        flash(f"Muitas tentativas erradas. Tente de novo em {wait_text(wait)}.", "error")
    elif not _check_password(g.user["password_hash"], request.form.get("current", "")):
        record_failure(key)
        flash("A senha atual está incorreta.", "error")
    elif new != request.form.get("confirm", ""):
        flash("As duas senhas novas não são iguais.", "error")
    elif problem := password_problem(new, g.user["email"]):
        flash(problem, "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_hash(new), uid))
        db.commit()
        clear_failures(key)
        start_session(uid)          # novo cookie de sessão
        flash("Senha alterada.")
    return redirect(url_for("auth.account"))


@bp.route("/conta/codigos", methods=["POST"])
@login_required
def new_recovery_codes():
    uid = g.user["id"]
    key = f"2fa:{uid}"
    wait = retry_after(key, CODE_LIMIT, WINDOW)
    step = None if wait else totp.verify(g.user["totp_secret"], request.form.get("code", ""), g.user["totp_last_step"])
    if wait:
        flash(f"Muitos códigos errados. Tente de novo em {wait_text(wait)}.", "error")
        return redirect(url_for("auth.account"))
    if step is None:
        record_failure(key)
        flash("Código do app autenticador incorreto.", "error")
        return redirect(url_for("auth.account"))
    db = get_db()
    db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, uid))
    codes = _store_recovery_codes(db, uid)
    db.commit()
    clear_failures(key)
    return render_template("auth/recovery_codes.html", codes=codes, first_time=False)
