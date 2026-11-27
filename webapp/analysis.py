"""
Análise das linhas guardadas de cada aplicação.

Sempre que chegam linhas novas (apps.version muda), a próxima leitura refaz a
análise uma vez, guarda o resumo para a lista de aplicações e atualiza os
alertas de triagem. Assim a fila de alertas nunca diverge do painel.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .db import get_db

# O analisador fica na raiz do projeto, um nível acima deste pacote.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from dashboard import analyze_lines  # noqa: E402

REOPEN_NOTE = "O ataque voltou a acontecer depois da resolução."


def load_lines(app_id: int) -> tuple[list[str], list[int]]:
    """Linhas na ordem em que chegaram e o id de cada uma (a linha N do painel é ids[N-1])."""
    rows = get_db().execute("SELECT id, line FROM log_lines WHERE app_id = ? ORDER BY id", (app_id,)).fetchall()
    return [r["line"] for r in rows], [r["id"] for r in rows]


def analyze_app(app) -> dict:
    lines, ids = load_lines(app["id"])
    data = analyze_lines(lines, kind=app["kind"], threshold=app["threshold"], source=app["name"])
    if app["alerts_version"] != app["version"]:
        sync_alerts(app, data, ids)
    return data


def summary(app) -> dict:
    """Resumo para a lista de aplicações; só refaz a análise quando chegam linhas novas."""
    if app["summary_version"] == app["version"] and app["alerts_version"] == app["version"] and app["summary_json"]:
        return json.loads(app["summary_json"])
    data = analyze_app(app)
    result = {
        "level": data["verdict"]["level"],
        "title": data["verdict"]["title"],
        "lines": data["totals"]["lines"],
        "ips": data["totals"]["ips"],
        "findings": [f["title"] for f in data["findings"][:3]],
    }
    db = get_db()
    db.execute("UPDATE apps SET summary_json = ?, summary_version = ? WHERE id = ?",
               (json.dumps(result, ensure_ascii=False), app["version"], app["id"]))
    db.commit()
    return result


def refresh_org(org_id: int) -> None:
    """Garante que os alertas de todas as aplicações da organização estão em dia."""
    for app in get_db().execute("SELECT * FROM apps WHERE org_id = ?", (org_id,)).fetchall():
        summary(app)


def sync_alerts(app, data: dict, ids: list[int]) -> None:
    """Cria ou atualiza um alerta por (tipo de ataque, IP).

    Um alerta resolvido volta para "novo" se o ataque acontecer de novo depois
    da decisão. Um falso positivo continua fechado: só os números são atualizados.
    """
    db = get_db()
    existing = {(r["type"], r["ip"]): r for r in db.execute("SELECT * FROM alerts WHERE app_id = ?", (app["id"],))}

    def line_id(n: int) -> int | None:
        return ids[n - 1] if 0 < n <= len(ids) else None

    for f in data["findings"]:
        for ip, info in f["per_ip"].items():
            last_id = line_id(info["last_line"])
            evidence = json.dumps([i for i in map(line_id, info["lines"]) if i])
            row = existing.get((f["type"], ip))
            if row is None:
                cur = db.execute(
                    "INSERT INTO alerts (app_id, type, ip, severity, title, occurrences, first_time, last_time, "
                    "last_line_id, evidence_ids, status_line_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (app["id"], f["type"], ip, f["severity"], f["title"], info["count"], info["first_time"],
                     info["last_time"], last_id, evidence, last_id))
                db.execute("INSERT INTO alert_events (alert_id, kind, to_status, note) VALUES (?, 'criado', 'novo', ?)",
                           (cur.lastrowid, f"{info['count']} ocorrência(s) no log."))
                continue
            new_activity = last_id is not None and last_id > (row["last_line_id"] or 0)
            db.execute(
                "UPDATE alerts SET severity = ?, title = ?, occurrences = ?, first_time = ?, last_time = ?, "
                "last_line_id = ?, evidence_ids = ?, "
                "updated_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE updated_at END WHERE id = ?",
                (f["severity"], f["title"], info["count"], info["first_time"], info["last_time"], last_id,
                 evidence, new_activity, row["id"]))
            if row["status"] == "resolvido" and last_id and last_id > (row["status_line_id"] or 0):
                db.execute("UPDATE alerts SET status = 'novo', status_line_id = ? WHERE id = ?", (last_id, row["id"]))
                db.execute("INSERT INTO alert_events (alert_id, kind, from_status, to_status, note) "
                           "VALUES (?, 'reaberto', 'resolvido', 'novo', ?)", (row["id"], REOPEN_NOTE))
    db.execute("UPDATE apps SET alerts_version = ? WHERE id = ?", (app["version"], app["id"]))
    db.commit()
