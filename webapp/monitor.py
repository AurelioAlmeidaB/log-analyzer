"""
Aplicações monitoradas: cadastro, chave de API, envio de logs (upload ou agente)
e o painel de ataques de cada uma.

Cada aplicação pertence a uma conta. Toda consulta filtra por user_id, então
ninguém vê aplicação de outra pessoa trocando o número na URL.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

from flask import (Blueprint, abort, flash, g, jsonify, redirect, render_template, request, send_file, url_for)

from .db import get_db
from .security import csp_nonce, login_required

# O analisador fica na raiz do projeto, um nível acima deste pacote.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from dashboard import analyze_lines, render_html  # noqa: E402

bp = Blueprint("monitor", __name__)

KINDS = {"ssh": "Servidor (SSH / auth.log)", "web": "Site ou API (nginx / Apache)"}
LOG_HINT = {"ssh": "/var/log/auth.log", "web": "/var/log/nginx/access.log"}
MAX_LINES_PER_APP = 200_000      # guarda só as mais recentes
MAX_LINE_LENGTH = 8_192
MAX_INGEST_LINES = 10_000        # por requisição do agente


def _new_api_key() -> tuple[str, str, str]:
    """(chave, hash para o banco, dica para mostrar). Só o hash é guardado."""
    key = "la_" + secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest(), key[:7] + "…" + key[-4:]


def _get_app(app_id: int):
    row = get_db().execute("SELECT * FROM apps WHERE id = ? AND user_id = ?", (app_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return row


def _store_lines(app_id: int, lines: list[str], source: str) -> int:
    db = get_db()
    clean = [line[:MAX_LINE_LENGTH] for line in lines if line.strip()]
    if not clean:
        return 0
    db.executemany("INSERT INTO log_lines (app_id, line, source) VALUES (?, ?, ?)",
                   [(app_id, line, source) for line in clean])
    db.execute(
        "DELETE FROM log_lines WHERE app_id = ? AND id <= ("
        "  SELECT id FROM log_lines WHERE app_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?)",
        (app_id, app_id, MAX_LINES_PER_APP))
    db.execute("UPDATE apps SET version = version + 1, last_received_at = CURRENT_TIMESTAMP WHERE id = ?", (app_id,))
    db.commit()
    return len(clean)


def _lines(app_id: int) -> list[str]:
    rows = get_db().execute("SELECT line FROM log_lines WHERE app_id = ? ORDER BY id", (app_id,))
    return [r["line"] for r in rows]


def _analysis(app) -> dict:
    return analyze_lines(_lines(app["id"]), kind=app["kind"], threshold=app["threshold"], source=app["name"])


def _summary(app) -> dict:
    """Resumo para a lista de aplicações, refeito só quando chegam linhas novas."""
    if app["summary_version"] == app["version"] and app["summary_json"]:
        return json.loads(app["summary_json"])
    data = _analysis(app)
    summary = {
        "level": data["verdict"]["level"],
        "title": data["verdict"]["title"],
        "lines": data["totals"]["lines"],
        "ips": data["totals"]["ips"],
        "findings": [f["title"] for f in data["findings"][:3]],
    }
    db = get_db()
    db.execute("UPDATE apps SET summary_json = ?, summary_version = ? WHERE id = ?",
               (json.dumps(summary, ensure_ascii=False), app["version"], app["id"]))
    db.commit()
    return summary


def _detail(app, new_key: str | None = None):
    count = get_db().execute("SELECT COUNT(*) FROM log_lines WHERE app_id = ?", (app["id"],)).fetchone()[0]
    server = request.host_url.rstrip("/")
    return render_template("apps/detail.html", app=app, kinds=KINDS, line_count=count, new_key=new_key,
                           server=server, log_hint=LOG_HINT[app["kind"]],
                           summary=_summary(app) if count else None)


@bp.route("/")
@login_required
def index():
    apps = get_db().execute("SELECT * FROM apps WHERE user_id = ? ORDER BY created_at DESC, id DESC",
                            (g.user["id"],)).fetchall()
    return render_template("apps/index.html", apps=[(a, _summary(a)) for a in apps], kinds=KINDS)


@bp.route("/apps/nova", methods=["GET", "POST"])
@login_required
def new_app():
    error = None
    form = {"name": "", "kind": "ssh", "threshold": "5"}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        try:
            threshold = int(form["threshold"])
        except ValueError:
            threshold = 0
        if not 1 <= len(form["name"]) <= 80:
            error = "Dê um nome de 1 a 80 caracteres."
        elif form["kind"] not in KINDS:
            error = "Escolha o tipo de log."
        elif not 1 <= threshold <= 100:
            error = "O limite precisa ser um número de 1 a 100."
        else:
            key, key_hash, hint = _new_api_key()
            db = get_db()
            cur = db.execute(
                "INSERT INTO apps (user_id, name, kind, threshold, api_key_hash, api_key_hint) VALUES (?, ?, ?, ?, ?, ?)",
                (g.user["id"], form["name"], form["kind"], threshold, key_hash, hint))
            db.commit()
            return _detail(_get_app(cur.lastrowid), new_key=key)
    return render_template("apps/new.html", kinds=KINDS, form=form, error=error)


@bp.route("/apps/<int:app_id>")
@login_required
def detail(app_id: int):
    return _detail(_get_app(app_id))


@bp.route("/apps/<int:app_id>/painel")
@login_required
def dashboard(app_id: int):
    app = _get_app(app_id)
    nav = {"href": url_for("monitor.detail", app_id=app_id), "label": "Voltar para " + app["name"],
           "title": app["name"]}
    return render_html(_analysis(app), nonce=csp_nonce(), nav=nav)


@bp.route("/apps/<int:app_id>/upload", methods=["POST"])
@login_required
def upload(app_id: int):
    app = _get_app(app_id)
    file = request.files.get("logfile")
    if not file or not file.filename:
        flash("Escolha um arquivo de log.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    text = file.read().decode("utf-8", errors="replace")
    count = _store_lines(app["id"], text.splitlines(), "upload")
    if not count:
        flash("O arquivo estava vazio.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    return redirect(url_for("monitor.dashboard", app_id=app_id))


@bp.route("/apps/<int:app_id>/chave", methods=["POST"])
@login_required
def rotate_key(app_id: int):
    app = _get_app(app_id)
    key, key_hash, hint = _new_api_key()
    db = get_db()
    db.execute("UPDATE apps SET api_key_hash = ?, api_key_hint = ? WHERE id = ?", (key_hash, hint, app["id"]))
    db.commit()
    return _detail(_get_app(app_id), new_key=key)


@bp.route("/apps/<int:app_id>/limpar", methods=["POST"])
@login_required
def clear_lines(app_id: int):
    app = _get_app(app_id)
    db = get_db()
    db.execute("DELETE FROM log_lines WHERE app_id = ?", (app["id"],))
    db.execute("UPDATE apps SET version = version + 1 WHERE id = ?", (app["id"],))
    db.commit()
    flash("Linhas apagadas.")
    return redirect(url_for("monitor.detail", app_id=app_id))


@bp.route("/apps/<int:app_id>/excluir", methods=["POST"])
@login_required
def delete_app(app_id: int):
    app = _get_app(app_id)
    if request.form.get("confirm_name", "").strip() != app["name"]:
        flash("Digite o nome da aplicação exatamente como está para excluir.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    db = get_db()
    db.execute("DELETE FROM apps WHERE id = ?", (app["id"],))
    db.commit()
    flash(f"Aplicação {app['name']} excluída.")
    return redirect(url_for("monitor.index"))


@bp.route("/agent.py")
def agent_script():
    """O agente é código aberto; servir daqui facilita instalar com um curl."""
    return send_file(PROJECT_ROOT / "agent.py", mimetype="text/x-python", as_attachment=True,
                     download_name="agent.py")


@bp.route("/api/ingest", methods=["POST"])
def ingest():
    """Recebe linhas do agente. Autenticação: Authorization: Bearer <chave da aplicação>."""
    auth = request.headers.get("Authorization", "")
    key = auth[7:].strip() if auth.startswith("Bearer ") else ""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    app = get_db().execute("SELECT * FROM apps WHERE api_key_hash = ?", (key_hash,)).fetchone() if key else None
    if app is None or not hmac.compare_digest(app["api_key_hash"], key_hash):
        return jsonify(erro="chave inválida"), 401
    lines = request.get_data(cache=False).decode("utf-8", errors="replace").splitlines()
    if len(lines) > MAX_INGEST_LINES:
        return jsonify(erro=f"no máximo {MAX_INGEST_LINES} linhas por envio"), 413
    return jsonify(recebidas=_store_lines(app["id"], lines, "agente"))
