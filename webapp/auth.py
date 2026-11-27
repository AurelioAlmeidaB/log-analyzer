"""
Contas: cadastro, login em duas etapas (senha + código do app autenticador),
códigos de recuperação, sessões ativas, troca de senha e de app autenticador.

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
from .security import (audit, clear_failures, client_ip, create_personal_org, end_other_sessions, end_session,
                       login_required, record_failure, retry_after, safe_next, start_session, token_hash)

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOGIN_LIMIT = 5        # senhas erradas por e-mail em 15 min
IP_LIMIT = 20          # senhas erradas por IP em 15 min
CODE_LIMIT = 5         # códigos errados por conta em 15 min
SIGNUP_LIMIT = 10      # tentativas de cadastro por IP em 1 h (contam todas, não só as que deram certo)
WINDOW = 15 * 60
PENDING_TTL = 5 * 60   # tempo para digitar o código depois da senha
SETUP_TTL = 15 * 60    # tempo para configurar o 2FA depois do cadastro
MAX_PASSWORD = 128

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
    if len(password) > MAX_PASSWORD:
        password = password[:MAX_PASSWORD + 1]          # nunca bate e não custa caro
    if stored is None:
        _dummy_hash = _dummy_hash or _hash("conta-que-nao-existe")
        check_password_hash(_dummy_hash, password)
        return False
    return check_password_hash(stored, password)


def password_problem(password: str, email: str) -> str | None:
    lowered = password.lower()
    if len(password) < 10:
        return "Use pelo menos 10 caracteres. Uma frase com espaços é fácil de lembrar e forte."
    if len(password) > MAX_PASSWORD:
        return f"Use no máximo {MAX_PASSWORD} caracteres."
    if lowered in COMMON_PASSWORDS or lowered in (email.lower(), email.split("@")[0].lower()) or len(set(password)) < 4:
        return "Essa senha é fácil de adivinhar. Escolha outra."
    return None


def wait_text(seconds: int) -> str:
    minutes = math.ceil(seconds / 60)
    return f"{minutes} minuto" if minutes == 1 else f"{minutes} minutos"


def _pepper() -> str:
    return current_app.config["SECRET_KEY"]


def _begin_setup(user_id: int, next_url: str | None = None) -> None:
    session.clear()
    session["setup_uid"] = user_id
    session["setup_at"] = time.time()
    if next_url:
        session["next"] = next_url


def _store_recovery_codes(db, user_id: int) -> list[str]:
    codes = totp.new_recovery_codes()
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    db.executemany("INSERT INTO recovery_codes (user_id, code_hash, scheme) VALUES (?, ?, 'hmac')",
                   [(user_id, totp.hash_recovery_code(c, _pepper())) for c in codes])
    return codes


def _use_recovery_code(db, user_id: int, code: str) -> bool:
    # UPDATE condicional: dois pedidos ao mesmo tempo não usam o mesmo código.
    cur = db.execute(
        "UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL "
        "AND ((scheme = 'hmac' AND code_hash = ?) OR (scheme = 'sha256' AND code_hash = ?))",
        (user_id, totp.hash_recovery_code(code, _pepper()), totp.legacy_hash_recovery_code(code)))
    return cur.rowcount == 1


def _recovery_left(user_id: int) -> int:
    return get_db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                            (user_id,)).fetchone()[0]


@bp.route("/cadastro", methods=["GET", "POST"])
def register():
    if not current_app.config["ALLOW_SIGNUP"]:
        abort(404)
    if session.get("uid"):
        return redirect(url_for("monitor.index"))
    next_url = safe_next(request.values.get("next"))
    error, email, status = None, "", 200
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        ip_key = f"signup:{client_ip()}"
        wait = retry_after(ip_key, SIGNUP_LIMIT, 3600)
        if wait:
            error, status = f"Muitas tentativas de cadastro daqui. Tente de novo em {wait_text(wait)}.", 429
        else:
            record_failure(ip_key)      # conta toda tentativa: impede testar e-mails em massa
            if len(email) > 254 or not EMAIL_RE.match(email):
                error = "Digite um e-mail válido."
            elif password != request.form.get("confirm", ""):
                error = "As duas senhas não são iguais."
            else:
                error = password_problem(password, email)
        if not error:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, _hash(password)))
                create_personal_org(db, cur.lastrowid, email)
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                error = "Já existe uma conta com esse e-mail. Entre com ela ou use outro e-mail."
            else:
                _begin_setup(cur.lastrowid, next_url)
                return redirect(url_for("auth.setup_2fa"))
    return render_template("auth/register.html", error=error, email=email, next=next_url), status


def _setup_page(user, secret: str, action: str, error: str | None, reset: bool):
    uri = totp.provisioning_uri(secret, user["email"])
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("auth/setup_2fa.html", qr=totp.qr_svg(uri), secret=grouped, error=error,
                           action=action, reset=reset)


def _pending_secret(db, user) -> str:
    secret = user["totp_pending"]
    if not secret:
        secret = totp.new_secret()
        db.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (secret, user["id"]))
        db.commit()
    return secret


def _confirm_code(db, user, secret: str):
    """(passo, erro). Confere o código digitado para o segredo novo, com limite de tentativas."""
    key = f"2fa:{user['id']}"
    wait = retry_after(key, CODE_LIMIT, WINDOW)
    if wait:
        return None, f"Muitos códigos errados. Tente de novo em {wait_text(wait)}."
    step = totp.verify(secret, request.form.get("code", ""), last_step=0)
    if step is None:
        record_failure(key)
        return None, "Código incorreto. Digite o código que aparece agora no app (ele muda a cada 30 segundos)."
    clear_failures(key)
    return step, None


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
    secret = _pending_secret(db, user)

    error = None
    if request.method == "POST":
        step, error = _confirm_code(db, user, secret)
        if step is not None:
            db.execute("UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_last_step = ? WHERE id = ?",
                       (secret, step, uid))
            codes = _store_recovery_codes(db, uid)
            db.commit()
            next_url = session.get("next")
            start_session(uid)
            return render_template("auth/recovery_codes.html", codes=codes, first_time=True,
                                   next=next_url or url_for("monitor.index"))
    return _setup_page(user, secret, url_for("auth.setup_2fa"), error, reset=False)


@bp.route("/entrar", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("monitor.index"))
    next_url = safe_next(request.values.get("next"))
    error, email, status = None, "", 200
    if request.method == "POST":
        email = request.form.get("email", "").strip()[:254]
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
                    _begin_setup(user["id"], next_url)
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
        flash("O tempo para digitar o código acabou. Entre de novo.", "warn")
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
            ok = used_recovery = False
            if totp.looks_like_recovery_code(code):
                ok = used_recovery = _use_recovery_code(db, uid, code)
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
                    flash(f"Você entrou com um código de recuperação. Restam {_recovery_left(uid)}. "
                          "Se perdeu o celular, troque o app autenticador em Conta.", "warn")
                return redirect(next_url or url_for("monitor.index"))
            record_failure(key)
            error = "Código incorreto ou já usado."
    return render_template("auth/verify_2fa.html", error=error), status


@bp.route("/sair", methods=["POST"])
def logout():
    end_session()
    flash("Você saiu da conta.")
    return redirect(url_for("auth.login"))


@bp.route("/conta")
@login_required
def account():
    sessions = get_db().execute(
        "SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_seen DESC", (g.user["id"],)).fetchall()
    current = token_hash(session.get("sid", ""))
    return render_template("auth/account.html", recovery_left=_recovery_left(g.user["id"]),
                           sessions=sessions, current_session=current)


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
        db.execute("DELETE FROM user_sessions WHERE user_id = ?", (uid,))   # derruba todos os navegadores
        audit("senha_alterada", org_id=None)
        db.commit()
        clear_failures(key)
        start_session(uid, session.get("org_id"))
        flash("Senha alterada. As outras sessões foram encerradas.")
    return redirect(url_for("auth.account"))


@bp.route("/conta/sessoes/encerrar", methods=["POST"])
@login_required
def end_sessions():
    count = end_other_sessions(g.user["id"])
    flash("Nenhuma outra sessão aberta." if not count else
          f"{count} {'sessão encerrada' if count == 1 else 'sessões encerradas'}.")
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
    audit("codigos_recuperacao_gerados", org_id=None)
    db.commit()
    clear_failures(key)
    return render_template("auth/recovery_codes.html", codes=codes, first_time=False, next=url_for("auth.account"))


@bp.route("/conta/2fa", methods=["POST"])
@login_required
def reset_2fa_start():
    """Trocar o app autenticador (celular novo ou perdido). Pede a senha de novo."""
    uid = g.user["id"]
    key = f"password:{uid}"
    wait = retry_after(key, LOGIN_LIMIT, WINDOW)
    if wait:
        flash(f"Muitas tentativas erradas. Tente de novo em {wait_text(wait)}.", "error")
        return redirect(url_for("auth.account"))
    if not _check_password(g.user["password_hash"], request.form.get("password", "")):
        record_failure(key)
        flash("Senha incorreta.", "error")
        return redirect(url_for("auth.account"))
    clear_failures(key)
    db = get_db()
    db.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (totp.new_secret(), uid))
    db.commit()
    session["reset_2fa_at"] = time.time()
    return redirect(url_for("auth.reset_2fa"))


@bp.route("/conta/2fa/configurar", methods=["GET", "POST"])
@login_required
def reset_2fa():
    if time.time() - session.get("reset_2fa_at", 0) > SETUP_TTL or not g.user["totp_pending"]:
        return redirect(url_for("auth.account"))
    db = get_db()
    secret = g.user["totp_pending"]
    error = None
    if request.method == "POST":
        step, error = _confirm_code(db, g.user, secret)
        if step is not None:
            uid = g.user["id"]
            db.execute("UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_last_step = ? WHERE id = ?",
                       (secret, step, uid))
            codes = _store_recovery_codes(db, uid)
            db.execute("DELETE FROM user_sessions WHERE user_id = ? AND token_hash != ?",
                       (uid, token_hash(session.get("sid", ""))))
            audit("app_autenticador_trocado", org_id=None)
            db.commit()
            session.pop("reset_2fa_at", None)
            flash("App autenticador trocado. Os códigos antigos e as outras sessões deixaram de valer.")
            return render_template("auth/recovery_codes.html", codes=codes, first_time=False,
                                   next=url_for("auth.account"))
    return _setup_page(g.user, secret, url_for("auth.reset_2fa"), error, reset=True)
