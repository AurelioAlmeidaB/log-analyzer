"""
Triagem de alertas: o trabalho do analista SOC.

Um alerta é um tipo de ataque vindo de um IP numa aplicação (ex.: "Brute force
no SSH" de 203.0.113.5). Ciclo de vida:

    novo -> em análise (alguém assume) -> resolvido ou falso positivo

- resolver ou marcar falso positivo exige uma nota explicando o porquê
- um alerta resolvido volta para "novo" se o ataque acontecer de novo
- cada mudança fica no histórico do alerta e no registro de atividade

Administradores e analistas SOC fazem a triagem; ninguém vê alertas de outra organização.
"""

from __future__ import annotations

import json

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from remediation import REMEDIATION

from . import analysis
from .db import get_db
from .monitor import SEVERITY_SQL, STATUS_LABELS
from .security import audit, can, login_required, require, switch_org

bp = Blueprint("alerts", __name__)

MAX_NOTE = 2000
NOTE_REQUIRED = {"resolvido", "falso_positivo"}
QUEUES = {   # aba -> status incluídos
    "abertos": ("novo", "em_analise"),
    "novo": ("novo",),
    "em_analise": ("em_analise",),
    "resolvido": ("resolvido",),
    "falso_positivo": ("falso_positivo",),
    "todos": tuple(STATUS_LABELS),
}
QUEUE_LABELS = {"abertos": "Abertos", "novo": "Novos", "em_analise": "Em análise", "resolvido": "Resolvidos",
                "falso_positivo": "Falsos positivos", "todos": "Todos"}
SEVERITY_LABELS = {"critico": "Crítico", "alto": "Alto", "medio": "Médio", "baixo": "Baixo"}


@bp.app_context_processor
def new_alerts_badge():
    """Quantidade de alertas novos da organização atual, para o menu."""
    if not g.get("org"):
        return {}
    count = get_db().execute(
        "SELECT COUNT(*) FROM alerts JOIN apps ON apps.id = alerts.app_id WHERE apps.org_id = ? AND status = 'novo'",
        (g.org["id"],)).fetchone()[0]
    return {"new_alerts": count}


@bp.route("/alertas")
@login_required
def index():
    require("view")
    analysis.refresh_org(g.org["id"])
    queue = request.args.get("fila", "abertos")
    if queue not in QUEUES:
        queue = "abertos"
    severity = request.args.get("gravidade", "")
    app_id = request.args.get("app", type=int)
    mine = request.args.get("meus") == "1"

    where = ["apps.org_id = ?"]
    params: list = [g.org["id"]]
    if severity in SEVERITY_LABELS:
        where.append("alerts.severity = ?")
        params.append(severity)
    if app_id:
        where.append("alerts.app_id = ?")
        params.append(app_id)
    if mine:
        where.append("alerts.assignee_id = ?")
        params.append(g.user["id"])

    db = get_db()
    counts = dict(db.execute(
        f"SELECT status, COUNT(*) FROM alerts JOIN apps ON apps.id = alerts.app_id WHERE {' AND '.join(where)} "
        "GROUP BY status", params).fetchall())
    statuses = QUEUES[queue]
    rows = db.execute(
        "SELECT alerts.*, apps.name AS app_name, users.email AS assignee_email FROM alerts "
        "JOIN apps ON apps.id = alerts.app_id LEFT JOIN users ON users.id = alerts.assignee_id "
        f"WHERE {' AND '.join(where)} AND alerts.status IN ({','.join('?' * len(statuses))}) "
        f"ORDER BY {SEVERITY_SQL}, alerts.updated_at DESC LIMIT 500", params + list(statuses)).fetchall()
    apps = db.execute("SELECT id, name FROM apps WHERE org_id = ? ORDER BY name COLLATE NOCASE",
                      (g.org["id"],)).fetchall()
    tab_counts = {q: sum(counts.get(s, 0) for s in st) for q, st in QUEUES.items()}
    return render_template("alerts/index.html", alerts=rows, queue=queue, queues=QUEUE_LABELS, tab_counts=tab_counts,
                           severity=severity, severities=SEVERITY_LABELS, app_id=app_id, apps=apps, mine=mine,
                           status_labels=STATUS_LABELS)


def _get_alert(alert_id: int, action: str = "view"):
    """O alerta, se a pessoa for membro da organização da aplicação dele."""
    row = get_db().execute(
        "SELECT alerts.*, apps.name AS app_name, apps.org_id, apps.kind AS app_kind, m.role AS my_role, "
        "users.email AS assignee_email FROM alerts JOIN apps ON apps.id = alerts.app_id "
        "JOIN memberships m ON m.org_id = apps.org_id AND m.user_id = ? "
        "LEFT JOIN users ON users.id = alerts.assignee_id WHERE alerts.id = ?",
        (g.user["id"], alert_id)).fetchone()
    if row is None:
        abort(404)
    if row["org_id"] != g.org["id"]:
        switch_org(row["org_id"])
    require(action, row["my_role"])
    return row


@bp.route("/alertas/<int:alert_id>")
@login_required
def detail(alert_id: int):
    alert = _get_alert(alert_id)
    db = get_db()
    evidence = []
    for line_id in json.loads(alert["evidence_ids"]):
        row = db.execute("SELECT line, (SELECT COUNT(*) FROM log_lines WHERE app_id = ? AND id <= ?) AS n "
                         "FROM log_lines WHERE id = ? AND app_id = ?",
                         (alert["app_id"], line_id, line_id, alert["app_id"])).fetchone()
        evidence.append({"text": row["line"], "n": row["n"]} if row else None)
    history = db.execute(
        "SELECT alert_events.*, users.email FROM alert_events LEFT JOIN users ON users.id = alert_events.user_id "
        "WHERE alert_id = ? ORDER BY alert_events.id DESC", (alert_id,)).fetchall()
    return render_template("alerts/detail.html", alert=alert, evidence=evidence, history=history,
                           status_labels=STATUS_LABELS, severities=SEVERITY_LABELS,
                           fix=REMEDIATION.get(alert["type"]), can_triage=can("triage", alert["my_role"]),
                           note_required=NOTE_REQUIRED)


def _event(alert_id: int, kind: str, note: str = "", from_status: str | None = None, to_status: str | None = None):
    get_db().execute("INSERT INTO alert_events (alert_id, user_id, kind, from_status, to_status, note) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (alert_id, g.user["id"], kind, from_status, to_status, note))


@bp.route("/alertas/<int:alert_id>", methods=["POST"])
@login_required
def update(alert_id: int):
    alert = _get_alert(alert_id, "triage")
    db = get_db()
    action = request.form.get("action", "")
    note = request.form.get("note", "").strip()
    label = f"#{alert['id']} {alert['title']} ({alert['ip']})"
    back = redirect(url_for("alerts.detail", alert_id=alert_id))

    if len(note) > MAX_NOTE:
        flash(f"A nota pode ter no máximo {MAX_NOTE} caracteres.", "error")
        return back

    if action == "assumir":
        new_status = "em_analise" if alert["status"] == "novo" else alert["status"]
        db.execute("UPDATE alerts SET assignee_id = ?, status = ? WHERE id = ?", (g.user["id"], new_status, alert_id))
        previous = f"Antes estava com {alert['assignee_email']}." if alert["assignee_email"] else ""
        _event(alert_id, "atribuido", previous, alert["status"], new_status)
        audit("alerta_assumido", label)
        db.commit()
        flash("Alerta com você." + (" Status: Em análise." if new_status != alert["status"] else ""))
        return back

    if action == "liberar":
        if alert["assignee_id"] != g.user["id"] and not can("manage_team", alert["my_role"]):
            abort(403)
        db.execute("UPDATE alerts SET assignee_id = NULL WHERE id = ?", (alert_id,))
        _event(alert_id, "liberado")
        audit("alerta_liberado", label)
        db.commit()
        flash("Alerta sem responsável.")
        return back

    if action != "atualizar":
        abort(400)
    status = request.form.get("status", alert["status"])
    if status not in STATUS_LABELS:
        abort(400)
    if status == alert["status"]:
        if not note:
            flash("Nada mudou. Escolha outro status ou escreva uma nota.", "warn")
            return back
        _event(alert_id, "nota", note)
        audit("alerta_nota", label)
        db.commit()
        flash("Nota adicionada.")
        return back
    if status in NOTE_REQUIRED and not note:
        flash(f"Explique na nota por que o alerta é \"{STATUS_LABELS[status]}\": isso fica para quem investigar depois.",
              "error")
        return back

    assignee = alert["assignee_id"]
    if status == "em_analise" and assignee is None:
        assignee = g.user["id"]                      # quem começa a analisar fica responsável
    # status_line_id: a decisão vale até a última ocorrência vista agora; outra depois disso reabre.
    db.execute("UPDATE alerts SET status = ?, assignee_id = ?, status_line_id = last_line_id WHERE id = ?",
               (status, assignee, alert_id))
    _event(alert_id, "status", note, alert["status"], status)
    audit("alerta_status", f"{label}: {STATUS_LABELS[alert['status']]} → {STATUS_LABELS[status]}")
    db.commit()
    flash(f"Alerta marcado como {STATUS_LABELS[status]}.")
    if status in NOTE_REQUIRED:
        return redirect(url_for("alerts.index"))      # fechou: volta para a fila
    return back
