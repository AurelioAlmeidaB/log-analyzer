"""
Equipe: cada organização tem membros com papéis.

  Administrador  tudo: aplicações, chaves, upload, membros, registro de atividade
  Analista SOC   vê aplicações, painéis e logs e baixa relatórios; não muda nada

Convites são links de uso único, válidos por 7 dias e só para o e-mail convidado.
"""

from __future__ import annotations

import secrets
import time

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for

from .db import get_db
from .security import (ROLE_LABELS, ROLE_RANK, audit, login_required, require, switch_org, token_hash,
                       current_user, load_memberships)

bp = Blueprint("team", __name__)

INVITE_TTL = 7 * 24 * 3600

AUDIT_LABELS = {
    "app_criada": "criou a aplicação",
    "app_excluida": "excluiu a aplicação",
    "chave_trocada": "gerou nova chave para",
    "logs_enviados": "enviou um arquivo de log para",
    "logs_apagados": "apagou as linhas de",
    "convite_criado": "convidou",
    "convite_revogado": "cancelou o convite de",
    "membro_entrou": "entrou na organização como",
    "papel_alterado": "mudou o papel de",
    "membro_removido": "removeu",
    "membro_saiu": "saiu da organização",
    "organizacao_renomeada": "renomeou a organização para",
}


def _members():
    return get_db().execute(
        "SELECT users.id, users.email, m.role, m.created_at FROM memberships m JOIN users ON users.id = m.user_id "
        "WHERE m.org_id = ? ORDER BY m.role, users.email COLLATE NOCASE", (g.org["id"],)).fetchall()


def _admin_count(org_id: int) -> int:
    return get_db().execute("SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = 'admin'",
                            (org_id,)).fetchone()[0]


def _team_page(invite_link: str | None = None, invite_email: str | None = None, error: str | None = None):
    invitations = get_db().execute(
        "SELECT * FROM invitations WHERE org_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY id DESC",
        (g.org["id"], time.time())).fetchall()
    return render_template("team/index.html", members=_members(), invitations=invitations, roles=ROLE_LABELS,
                           invite_link=invite_link, invite_email=invite_email, error=error,
                           admin_count=_admin_count(g.org["id"]))


@bp.route("/equipe")
@login_required
def index():
    require("manage_team")
    return _team_page()


@bp.route("/equipe/nome", methods=["POST"])
@login_required
def rename():
    require("manage_team")
    name = request.form.get("name", "").strip()
    if not 1 <= len(name) <= 80:
        flash("O nome precisa ter de 1 a 80 caracteres.", "error")
    else:
        db = get_db()
        db.execute("UPDATE orgs SET name = ? WHERE id = ?", (name, g.org["id"]))
        audit("organizacao_renomeada", name)
        db.commit()
        flash("Nome atualizado.")
    return redirect(url_for("team.index"))


@bp.route("/equipe/convites", methods=["POST"])
@login_required
def invite():
    require("manage_team")
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "")
    db = get_db()
    if len(email) > 254 or "@" not in email:
        return _team_page(error="Digite um e-mail válido.")
    if role not in ROLE_LABELS:
        return _team_page(error="Escolha um papel.")
    member = db.execute("SELECT 1 FROM memberships m JOIN users ON users.id = m.user_id "
                        "WHERE m.org_id = ? AND users.email = ?", (g.org["id"], email)).fetchone()
    if member:
        return _team_page(error=f"{email} já faz parte da equipe.")
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM invitations WHERE org_id = ? AND email = ? AND accepted_at IS NULL", (g.org["id"], email))
    db.execute("INSERT INTO invitations (org_id, email, role, token_hash, invited_by, expires_at) "
               "VALUES (?, ?, ?, ?, ?, ?)",
               (g.org["id"], email, role, token_hash(token), g.user["id"], time.time() + INVITE_TTL))
    audit("convite_criado", f"{email} ({ROLE_LABELS[role]})")
    db.commit()
    return _team_page(invite_link=url_for("team.accept", token=token, _external=True), invite_email=email)


@bp.route("/equipe/convites/<int:invite_id>/cancelar", methods=["POST"])
@login_required
def revoke_invite(invite_id: int):
    require("manage_team")
    db = get_db()
    row = db.execute("SELECT * FROM invitations WHERE id = ? AND org_id = ?", (invite_id, g.org["id"])).fetchone()
    if row is None:
        abort(404)
    db.execute("DELETE FROM invitations WHERE id = ?", (invite_id,))
    audit("convite_revogado", row["email"])
    db.commit()
    flash(f"Convite de {row['email']} cancelado.")
    return redirect(url_for("team.index"))


def _member_or_404(user_id: int):
    row = get_db().execute(
        "SELECT users.id, users.email, m.role FROM memberships m JOIN users ON users.id = m.user_id "
        "WHERE m.org_id = ? AND m.user_id = ?", (g.org["id"], user_id)).fetchone()
    if row is None:
        abort(404)
    return row


@bp.route("/equipe/membros/<int:user_id>/papel", methods=["POST"])
@login_required
def change_role(user_id: int):
    require("manage_team")
    member = _member_or_404(user_id)
    role = request.form.get("role", "")
    if role not in ROLE_LABELS:
        abort(400)
    if member["role"] == "admin" and role != "admin" and _admin_count(g.org["id"]) == 1:
        flash("A organização precisa de pelo menos um administrador.", "error")
        return redirect(url_for("team.index"))
    if role != member["role"]:
        db = get_db()
        db.execute("UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?", (role, g.org["id"], user_id))
        audit("papel_alterado", f"{member['email']}: {ROLE_LABELS[member['role']]} → {ROLE_LABELS[role]}")
        db.commit()
        flash(f"{member['email']} agora é {ROLE_LABELS[role]}.")
    if user_id == g.user["id"] and ROLE_RANK[role] < ROLE_RANK["admin"]:
        return redirect(url_for("monitor.index"))
    return redirect(url_for("team.index"))


@bp.route("/equipe/membros/<int:user_id>/remover", methods=["POST"])
@login_required
def remove_member(user_id: int):
    require("manage_team")
    member = _member_or_404(user_id)
    if member["role"] == "admin" and _admin_count(g.org["id"]) == 1:
        flash("Não dá para remover o único administrador.", "error")
        return redirect(url_for("team.index"))
    db = get_db()
    db.execute("DELETE FROM memberships WHERE org_id = ? AND user_id = ?", (g.org["id"], user_id))
    audit("membro_removido", member["email"])
    db.commit()
    flash(f"{member['email']} foi removido e perdeu o acesso na hora.")
    if user_id == g.user["id"]:
        return redirect(url_for("monitor.index"))
    return redirect(url_for("team.index"))


@bp.route("/organizacoes/<int:org_id>/sair", methods=["POST"])
@login_required
def leave(org_id: int):
    membership = next((o for o in g.orgs if o["id"] == org_id), None)
    if membership is None:
        abort(404)
    if membership["role"] == "admin" and _admin_count(org_id) == 1:
        flash("Você é o único administrador. Promova outra pessoa antes de sair.", "error")
        return redirect(url_for("auth.account"))
    db = get_db()
    db.execute("DELETE FROM memberships WHERE org_id = ? AND user_id = ?", (org_id, g.user["id"]))
    audit("membro_saiu", g.user["email"], org_id=org_id)
    db.commit()
    flash(f"Você saiu de {membership['name']}.")
    return redirect(url_for("monitor.index"))


@bp.route("/organizacoes/trocar", methods=["POST"])
@login_required
def switch():
    try:
        org_id = int(request.form.get("org_id", ""))
    except ValueError:
        abort(400)
    if not switch_org(org_id):
        abort(404)
    return redirect(url_for("monitor.index"))


@bp.route("/atividade")
@login_required
def activity():
    require("view_audit")
    events = get_db().execute(
        "SELECT audit_events.*, users.email FROM audit_events LEFT JOIN users ON users.id = audit_events.user_id "
        "WHERE org_id = ? ORDER BY audit_events.id DESC LIMIT 300", (g.org["id"],)).fetchall()
    return render_template("team/activity.html", events=events, labels=AUDIT_LABELS)


# --- Aceitar convite ----------------------------------------------------------------


def _find_invite(token: str):
    return get_db().execute(
        "SELECT invitations.*, orgs.name AS org_name FROM invitations JOIN orgs ON orgs.id = invitations.org_id "
        "WHERE token_hash = ?", (token_hash(token),)).fetchone()


@bp.route("/convite/<token>", methods=["GET", "POST"])
def accept(token: str):
    user, _ = current_user()
    if user is None:
        flash("Entre (ou crie uma conta) com o e-mail que recebeu o convite para aceitar.", "warn")
        return redirect(url_for("auth.login", next=url_for("team.accept", token=token)))
    g.user = user
    load_memberships()

    invite = _find_invite(token)
    problem = None
    if invite is None or invite["accepted_at"]:
        problem = "Este convite não existe ou já foi usado. Peça um novo ao administrador."
    elif invite["expires_at"] < time.time():
        problem = "Este convite expirou. Peça um novo ao administrador."
    elif invite["email"].lower() != user["email"].lower():
        problem = (f"Este convite é para outro e-mail. Você entrou como {user['email']}; "
                   "saia e entre com a conta convidada.")
    if problem:
        return render_template("team/invite.html", problem=problem), 400 if invite else 404

    if request.method == "POST":
        db = get_db()
        cur = db.execute("UPDATE invitations SET accepted_at = CURRENT_TIMESTAMP WHERE id = ? AND accepted_at IS NULL",
                         (invite["id"],))
        if cur.rowcount == 1:
            db.execute("INSERT OR IGNORE INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)",
                       (invite["org_id"], user["id"], invite["role"]))
            audit("membro_entrou", ROLE_LABELS[invite["role"]], org_id=invite["org_id"])
            db.commit()
            session["org_id"] = invite["org_id"]
            flash(f"Você entrou em {invite['org_name']} como {ROLE_LABELS[invite['role']]}.")
        return redirect(url_for("monitor.index"))
    return render_template("team/invite.html", invite=invite, role_label=ROLE_LABELS[invite["role"]])
