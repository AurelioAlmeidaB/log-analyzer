"""
Aplicações monitoradas: cadastro, chave de API, envio de logs (upload ou agente),
o painel de ataques e o relatório em JSON.

Cada aplicação pertence a uma organização. Toda consulta junta a aplicação com
a participação da pessoa naquela organização: quem não é membro recebe 404
(nem descobre que a aplicação existe) e quem não tem o papel exigido recebe 403.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import (Blueprint, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   url_for)

from .db import get_db
from .security import audit, can, csp_nonce, login_required, require, switch_org

# O analisador fica na raiz do projeto, um nível acima deste pacote.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from dashboard import analyze_lines, render_html  # noqa: E402

bp = Blueprint("monitor", __name__)

KINDS = {"ssh": "Servidor Linux (SSH / auth.log)", "web": "Site ou API (nginx / Apache)"}
LOG_HINT = {"ssh": "/var/log/auth.log", "web": "/var/log/nginx/access.log"}
MAX_LINES_PER_APP = 200_000      # guarda só as mais recentes
MAX_LINE_LENGTH = 8_192
MAX_INGEST_LINES = 10_000        # por requisição do agente
AGENT_ONLINE_SECONDS = 120       # recebeu algo nos últimos 2 min: agente ativo


def _new_api_key() -> tuple[str, str, str]:
    """(chave, hash para o banco, dica para mostrar). Só o hash é guardado."""
    key = "la_" + secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest(), key[:7] + "…" + key[-4:]


def _get_app(app_id: int, action: str = "view"):
    """A aplicação, se a pessoa for membro da organização dela e o papel permitir `action`."""
    row = get_db().execute(
        "SELECT apps.*, m.role AS my_role FROM apps "
        "JOIN memberships m ON m.org_id = apps.org_id AND m.user_id = ? WHERE apps.id = ?",
        (g.user["id"], app_id)).fetchone()
    if row is None:
        abort(404)
    if row["org_id"] != g.org["id"]:       # link de outra organização da pessoa: troca para ela
        switch_org(row["org_id"])
    require(action, row["my_role"])
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


def seconds_since(utc_text: str | None) -> float | None:
    if not utc_text:
        return None
    then = datetime.strptime(utc_text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds()


def time_ago(utc_text: str | None) -> str:
    """"há 3 min": funciona em qualquer fuso, ao contrário de mostrar a hora UTC."""
    return _ago(seconds_since(utc_text))


def epoch_ago(epoch: float | None) -> str:
    return _ago(None if epoch is None else datetime.now(timezone.utc).timestamp() - epoch)


def _ago(seconds: float | None) -> str:
    if seconds is None:
        return "nunca"
    if seconds < 60:
        return "agora há pouco"
    for size, one, many in ((86400, "dia", "dias"), (3600, "hora", "horas"), (60, "min", "min")):
        if seconds >= size:
            n = int(seconds // size)
            return f"há {n} {one if n == 1 else many}"
    return "agora há pouco"


def agent_status(app) -> tuple[str, str]:
    """(nível do badge, texto) sobre o último envio de linhas."""
    seconds = seconds_since(app["last_received_at"])
    if seconds is None:
        return "medio", "Nenhum log recebido ainda"
    if seconds <= AGENT_ONLINE_SECONDS:
        return "baixo", "Recebendo logs"
    return "medio", f"Último log {time_ago(app['last_received_at'])}"


def _detail(app, new_key: str | None = None):
    count = get_db().execute("SELECT COUNT(*) FROM log_lines WHERE app_id = ?", (app["id"],)).fetchone()[0]
    return render_template("apps/detail.html", app=app, kinds=KINDS, line_count=count, new_key=new_key,
                           server=request.host_url.rstrip("/"), log_hint=LOG_HINT[app["kind"]],
                           summary=_summary(app) if count else None, status=agent_status(app))


@bp.route("/")
@login_required
def index():
    apps = get_db().execute("SELECT * FROM apps WHERE org_id = ? ORDER BY created_at DESC, id DESC",
                            (g.org["id"],)).fetchall()
    return render_template("apps/index.html", apps=[(a, _summary(a), agent_status(a)) for a in apps], kinds=KINDS)


@bp.route("/apps/nova", methods=["GET", "POST"])
@login_required
def new_app():
    require("manage_apps")
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
                "INSERT INTO apps (user_id, org_id, name, kind, threshold, api_key_hash, api_key_hint) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (g.user["id"], g.org["id"], form["name"], form["kind"], threshold, key_hash, hint))
            audit("app_criada", form["name"])
            db.commit()
            return _detail(_get_app(cur.lastrowid, "manage_apps"), new_key=key)
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
           "title": f"{g.org['name']} · {app['name']}", "refresh": True}
    return render_html(_analysis(app), nonce=csp_nonce(), nav=nav)


@bp.route("/apps/<int:app_id>/relatorio.json")
@login_required
def report(app_id: int):
    app = _get_app(app_id, "export")
    data = _analysis(app)
    data.pop("lines", None)                  # o relatório leva a análise, não o log cru
    filename = f"relatorio-{app['id']}-{datetime.now():%Y%m%d-%H%M}.json"
    return Response(json.dumps(data, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.route("/apps/<int:app_id>/upload", methods=["POST"])
@login_required
def upload(app_id: int):
    app = _get_app(app_id, "upload")
    file = request.files.get("logfile")
    if not file or not file.filename:
        flash("Escolha um arquivo de log.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    text = file.read().decode("utf-8", errors="replace")
    count = _store_lines(app["id"], text.splitlines(), "upload")
    if not count:
        flash("O arquivo estava vazio.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    audit("logs_enviados", f"{app['name']} ({count} linhas)")
    get_db().commit()
    return redirect(url_for("monitor.dashboard", app_id=app_id))


@bp.route("/apps/<int:app_id>/chave", methods=["POST"])
@login_required
def rotate_key(app_id: int):
    app = _get_app(app_id, "manage_apps")
    key, key_hash, hint = _new_api_key()
    db = get_db()
    db.execute("UPDATE apps SET api_key_hash = ?, api_key_hint = ? WHERE id = ?", (key_hash, hint, app["id"]))
    audit("chave_trocada", app["name"])
    db.commit()
    return _detail(_get_app(app_id), new_key=key)


@bp.route("/apps/<int:app_id>/limpar", methods=["POST"])
@login_required
def clear_lines(app_id: int):
    app = _get_app(app_id, "manage_apps")
    db = get_db()
    db.execute("DELETE FROM log_lines WHERE app_id = ?", (app["id"],))
    db.execute("UPDATE apps SET version = version + 1 WHERE id = ?", (app["id"],))
    audit("logs_apagados", app["name"])
    db.commit()
    flash("Linhas apagadas.")
    return redirect(url_for("monitor.detail", app_id=app_id))


@bp.route("/apps/<int:app_id>/excluir", methods=["POST"])
@login_required
def delete_app(app_id: int):
    app = _get_app(app_id, "manage_apps")
    if request.form.get("confirm_name", "").strip() != app["name"]:
        flash("Digite o nome da aplicação exatamente como está para excluir.", "error")
        return redirect(url_for("monitor.detail", app_id=app_id))
    db = get_db()
    db.execute("DELETE FROM apps WHERE id = ?", (app["id"],))
    audit("app_excluida", app["name"])
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
