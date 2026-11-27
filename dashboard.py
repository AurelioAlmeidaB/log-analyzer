#!/usr/bin/env python3
"""
dashboard.py - gera o dashboard HTML (arquivo único, abre offline) a partir de um log.

Funciona com auth.log (SSH) e access.log (nginx/Apache). O dashboard mostra:
  - o veredito: algum atacante entrou?
  - pontos de ataque: de onde vêm (IPs) e o que miram
  - ferramentas prováveis e técnicas MITRE ATT&CK, com as linhas que servem de evidência
  - como corrigir cada tipo de ataque encontrado
  - a sequência de eventos de cada IP (por que a ordem do log importa)
  - o log, com filtros e busca

Uso:
    python log_analyzer.py sample_auth.log --html dashboard.html
    python dashboard.py sample_access.log -o dashboard_web.html

A análise vira um dicionário já pronto para exibir (textos, cartões, linhas);
o template só desenha. A aplicação web usa o mesmo template.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime

import web_log_analyzer as web
from log_analyzer import (
    DEFAULT_THRESHOLD,
    LOGIN_RE,
    TIMESTAMP,
    count_failures_by_ip,
    detect_bruteforce,
    detect_kind,
    detect_success_after_failures,
    group_alerts_by_ip,
)
from remediation import finding, sort_findings

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_template.html")

# Acima disso o painel guarda só as linhas ligadas a ataques, e as mais recentes,
# para o HTML não passar de alguns MB.
MAX_EMBEDDED_LINES = 20_000

# Qualquer linha de syslog: "<data> <host> <processo>[<pid>]: <mensagem>"
SYSLOG_RE = re.compile(
    TIMESTAMP + r"\s+(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# Mensagens do sshd que dão contexto ao ataque.
# "Connection from" aparece com LogLevel VERBOSE; o banner do cliente, com LogLevel DEBUG1.
CONNECTION_RE = re.compile(r"Connection from (?P<ip>\S+) port \d+ on (?P<dst>\S+) port (?P<dport>\d+)")
SOFTWARE_RE = re.compile(r"remote software version (?P<software>\S.*)")   # sem ".+?\s*$": quadrático
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
SESSION_RE = re.compile(r"session opened for user (?P<user>[^\s(]+)")
# IP remoto em mensagens como "Connection closed by invalid user admin 1.2.3.4 port 5555".
# Exige "from"/"by" antes, para não confundir com "Server listening on 0.0.0.0 port 22".
REMOTE_IP_RE = re.compile(
    r"(?:from|by)\s+(?:(?:invalid|authenticating)\s+user\s+\S+\s+|user\s+\S+\s+)?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+)\s+port\b"
)

# Sinais de varredura: alguém abriu a porta 22 mas não fez um handshake SSH normal.
RECON_PATTERNS = [
    (re.compile(r"Did not receive identification string from (?P<ip>\S+)"), "conectou sem enviar banner SSH"),
    (re.compile(r"kex_exchange_identification: "), "abandonou o handshake SSH"),
    (re.compile(r"banner exchange: Connection from (?P<ip>\S+) port \d+: invalid format"), "enviou banner inválido"),
    (re.compile(r"Bad protocol version identification .*? from (?P<ip>\S+)"), "protocolo inválido"),
    (re.compile(r"Unable to negotiate with (?P<ip>\S+) port \d+"), "ofereceu só algoritmos antigos"),
]

# Banner do cliente SSH -> ferramenta provável. A ordem importa (libssh2 antes de libssh).
TOOL_SIGNATURES = [
    (re.compile(r"^libssh2", re.I), "Medusa / Nmap ssh-brute", "usam a biblioteca libssh2"),
    (re.compile(r"^libssh[_-]", re.I), "Hydra (THC-Hydra)", "o módulo SSH do Hydra usa a libssh"),
    (re.compile(r"paramiko", re.I), "Script Python (Paramiko)", "biblioteca comum em scripts de ataque"),
    (re.compile(r"asyncssh", re.I), "Script Python (AsyncSSH)", "biblioteca comum em scripts de ataque"),
    (re.compile(r"^Nmap", re.I), "Nmap (scripts NSE)", "banner padrão dos scripts SSH do Nmap"),
    (re.compile(r"^Go$"), "Bot/scanner escrito em Go", "banner padrão da biblioteca SSH do Go, comum em botnets"),
    (re.compile(r"PuTTY", re.I), "PuTTY", "cliente interativo"),
    (re.compile(r"^OpenSSH", re.I), "Cliente OpenSSH", "cliente padrão de Linux, macOS e Windows"),
]

TECHNIQUES = {
    "T1046": ("Varredura de serviço", "Conexões que abrem a porta 22 e saem sem handshake: mapeamento do serviço."),
    "T1595.002": ("Varredura de vulnerabilidades", "Ferramenta automática procurando falhas conhecidas."),
    "T1595.003": ("Varredura por lista de palavras", "Muitos caminhos testados a partir de uma lista pronta."),
    "T1190": ("Exploração de aplicação pública", "Payloads de SQL injection, XSS, path traversal ou execução de comando."),
    "T1110.001": ("Adivinhação de senha", "Muitas senhas contra a mesma conta."),
    "T1110.003": ("Password spraying", "Poucas tentativas em muitas contas, geralmente de uma lista pronta."),
    "T1078": ("Uso de conta válida", "Login aceito depois de várias senhas erradas: senha descoberta."),
    "T1552.001": ("Credenciais em arquivos", "Um arquivo com segredos (.env, backup) foi baixado."),
}

RISK_ORDER = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
MACHINE_PACE_SECONDS = 3  # mediana <= 3 s entre tentativas: ninguém digita senha tão rápido

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


# --- Utilidades -------------------------------------------------------------------


def to_datetime(ts: str) -> datetime | None:
    """Converte as datas dos logs. O formato clássico do syslog não tem ano; só as diferenças importam."""
    try:
        if ts[:2].isdigit() and ts[2:3] == "/":            # 27/Nov/2026:03:10:01 -0300 (nginx)
            day, month, rest = ts.split("/", 2)
            year, hms = rest.split(":", 1)
            hour, minute, second = map(int, hms.split()[0].split(":"))
            return datetime(int(year), MONTHS[month], int(day), hour, minute, second)
        if ts[0].isdigit():                                 # 2026-11-22T02:47:03.123-03:00
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        month, day, hms = ts.split()                        # Nov 22 02:47:03
        hour, minute, second = map(int, hms.split(":"))
        return datetime(2000, MONTHS[month], int(day), hour, minute, second)
    except (ValueError, KeyError, IndexError):
        return None


def pretty_time(ts: str | None) -> str:
    """Data curta para ler: datas com ano viram 27/11/2026 03:10:01."""
    if not ts:
        return "—"
    if ts[0].isdigit():
        dt = to_datetime(ts)
        if dt:
            return dt.strftime("%d/%m/%Y %H:%M:%S")
    return ts


def clock(ts: str | None) -> str:
    """Só a hora (HH:MM:SS), em qualquer um dos formatos de data."""
    dt = to_datetime(ts) if ts else None
    return dt.strftime("%H:%M:%S") if dt else "—"


def host_port(host: str, port: str) -> str:
    """IPv6 vai entre colchetes, senão não dá para saber onde começa a porta."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def pace(timestamps: list[str], min_events: int = 3, machine_seconds: float = MACHINE_PACE_SECONDS):
    """Mediana dos segundos entre eventos e se o ritmo é de máquina."""
    times = [to_datetime(t) for t in timestamps]
    gaps = []
    for a, b in zip(times, times[1:]):
        if a and b:
            try:
                delta = (b - a).total_seconds()
            except TypeError:                      # data com e sem fuso misturadas
                continue
            if delta >= 0:
                gaps.append(delta)
    median_gap = statistics.median(gaps) if gaps else None
    machine = len(timestamps) >= min_events and median_gap is not None and median_gap <= machine_seconds
    return median_gap, machine


def shorten(text: str, size: int = 60) -> str:
    return text if len(text) <= size else text[: size - 1] + "…"


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def embed_lines(records: list[dict], critical_lines: set[int], is_relevant) -> tuple[list[list], str | None]:
    """Linhas que vão dentro do HTML, como [n, tipo, texto, ip]."""
    total = len(records)
    keep = records if total <= MAX_EMBEDDED_LINES else [r for r in records if is_relevant(r)]
    if len(keep) > MAX_EMBEDDED_LINES:
        tail = keep[-MAX_EMBEDDED_LINES:]
        older_critical = [r for r in keep[:-MAX_EMBEDDED_LINES] if r["n"] in critical_lines]
        keep = older_critical + tail
    note = None
    if len(keep) < total:
        note = (f"O painel mostra {len(keep):,} de {total:,} linhas: ficaram de fora as que não têm relação "
                f"com ataques e as mais antigas, para o arquivo não ficar pesado.").replace(",", ".")
    return [[r["n"], r["k"], r["t"], r["ip"]] for r in keep], note


def aggregate_techniques(attackers: list[dict]) -> list[dict]:
    techniques = []
    for tid, (name, description) in TECHNIQUES.items():
        found = [(a["ip"], t["evidence"]) for a in attackers for t in a["techniques"] if t["id"] == tid]
        if found:
            techniques.append({
                "id": tid, "name": name, "description": description,
                "ips": [ip for ip, _ in found],
                "evidence": sorted({n for _, ev in found for n in ev})[:8],
            })
    return techniques


# --- SSH --------------------------------------------------------------------------


def classify_sshd_message(msg: str) -> tuple[str, str | None, dict]:
    """Diz o que uma mensagem do sshd (que não é Failed/Accepted) significa."""
    m = CONNECTION_RE.search(msg)
    if m:
        return "connection", m["ip"], {"dst": m["dst"], "dport": m["dport"]}
    m = SOFTWARE_RE.search(msg)
    if m:
        return "client", None, {"software": m["software"].strip()}
    m = INVALID_USER_RE.search(msg)
    if m:
        return "invalid_user", m["ip"], {"user": m["user"]}
    for pattern, label in RECON_PATTERNS:
        m = pattern.search(msg)
        if m:
            return "recon", m.groupdict().get("ip"), {"label": label}
    m = SESSION_RE.search(msg)
    if m:
        return "session", None, {"user": m["user"]}
    m = REMOTE_IP_RE.search(msg)
    return "other", (m["ip"] if m else None), {}


def guess_tool(software: str | None, machine_pace: bool, recon: list, attempts: int) -> tuple[str, str]:
    """Ferramenta provável e o motivo. É heurística: um atacante pode trocar o banner."""
    if software:
        for pattern, tool, why in TOOL_SIGNATURES:
            if pattern.search(software):
                return tool, f'banner do cliente "{software}": {why}'
        return f'Cliente "{software}"', "banner do cliente não reconhecido"
    if machine_pace:
        return "Ferramenta automatizada", "ritmo de máquina entre as tentativas"
    if recon and not attempts:
        return "Scanner de portas", "conexões sem handshake SSH (ex.: Nmap, Masscan)"
    if attempts:
        return "Cliente interativo", "ritmo compatível com alguém digitando"
    return "Desconhecida", "sem informação suficiente no log"


def _new_ip_info() -> dict:
    return {"software": [], "recon": [], "sessions": [], "connections": 0, "first": None, "last": None}


def analyze_ssh_lines(lines: list[str], threshold: int = DEFAULT_THRESHOLD) -> dict:
    records = []
    events = []                    # mesmo formato do log_analyzer, mais "line" e "invalid"
    pid_ip = {}                    # sshd[pid] -> IP: liga linhas sem IP à conexão certa
    hosts = Counter()
    targets = Counter()
    first_time = last_time = None
    per_ip = defaultdict(_new_ip_info)

    for n, raw in enumerate(lines, 1):
        text = raw.rstrip("\r\n")
        rec = {"n": n, "k": "other", "t": text, "ip": None}
        records.append(rec)

        m = SYSLOG_RE.match(text)
        if not m:
            continue
        first_time = first_time or m["time"]
        last_time = m["time"]
        hosts[m["host"]] += 1
        if not m["proc"].startswith("sshd"):
            continue

        pid = m["pid"]
        login = LOGIN_RE.search(text)
        if login:
            kind, ip, info = login["status"].lower(), login["ip"], {}
            for _ in range(int(login["repeat"] or 1)):
                events.append({
                    "time": login["time"], "user": login["user"], "ip": ip,
                    "status": kind, "invalid": bool(login["invalid"]), "line": n,
                })
        else:
            kind, ip, info = classify_sshd_message(m["msg"])

        if kind == "connection":
            pid_ip[pid] = ip                       # nova conexão neste pid
            targets[(info["dst"], info["dport"])] += 1
        elif ip:
            pid_ip[pid] = ip
        else:
            ip = pid_ip.get(pid)

        rec["k"] = kind
        rec["ip"] = ip
        if not ip:
            continue

        p = per_ip[ip]
        p["first"] = p["first"] or m["time"]
        p["last"] = m["time"]
        if kind == "connection":
            p["connections"] += 1
        elif kind == "client":
            p["software"].append({"software": info["software"], "n": n})
        elif kind == "recon":
            p["recon"].append({"label": info["label"], "n": n, "time": m["time"]})
        elif kind == "session":
            p["sessions"].append({"user": info["user"], "n": n, "time": m["time"]})

    # As detecções são as do log_analyzer, para o dashboard nunca discordar do terminal.
    failures_by_ip = count_failures_by_ip(events)
    bruteforce = detect_bruteforce(failures_by_ip, threshold)
    alerts = detect_success_after_failures(events, threshold)
    accepted = iter(e for e in events if e["status"] == "accepted")
    for a in alerts:                               # os alertas saem na ordem do log
        for e in accepted:
            if (e["ip"], e["user"], e["time"]) == (a["ip"], a["user"], a["time"]):
                a["line"] = e["line"]
                break

    events_by_ip = defaultdict(list)
    for e in events:
        events_by_ip[e["ip"]].append(e)
    alerts_by_ip = defaultdict(list)
    for a in alerts:
        alerts_by_ip[a["ip"]].append(a)
    brute_ips = {ip for ip, _ in bruteforce}

    attackers = [
        profile_ssh_ip(ip, events_by_ip.get(ip, []), per_ip[ip], threshold, ip in brute_ips, alerts_by_ip.get(ip, []))
        for ip in dict.fromkeys([*events_by_ip, *per_ip])
    ]
    attackers.sort(key=lambda a: (RISK_ORDER[a["risk"]], -a["failed"]))
    by_ip = {a["ip"]: a for a in attackers}

    failed = [e for e in events if e["status"] == "failed"]
    compromised_users = {a["user"] for a in alerts}
    users = defaultdict(list)
    for e in failed:
        users[e["user"]].append(e)
    accounts = []
    existing, missing = [], []
    for user, evs in sorted(users.items(), key=lambda kv: -len(kv[1])):
        exists = not any(e["invalid"] for e in evs)
        (existing if exists else missing).append(user)
        flags = []
        if user in compromised_users:
            flags.append({"text": "comprometida", "critical": True})
        if not exists:
            flags.append({"text": "não existe"})
        ips = sorted({e["ip"] for e in evs})
        accounts.append({
            "name": user, "count": len(evs), "flags": flags,
            "tip": f"{user}: {plural(len(evs), 'falha', 'falhas')}\nde {', '.join(ips)}"
                   + ("" if exists else "\nconta não existe no servidor"),
        })

    # Como corrigir
    findings = []
    occurrence = lambda e: (e["ip"], e["line"], e["time"])  # noqa: E731
    if alerts:
        sessions = [(ip, s["n"]) for ip in alerts_by_ip for s in per_ip[ip]["sessions"]]
        findings.append(finding("ssh_compromise", [(a["ip"], a["line"], a["time"]) for a in alerts], sessions))
    if bruteforce:
        findings.append(finding("ssh_bruteforce", [occurrence(e) for e in failed if e["ip"] in brute_ips]))
    spray = {a["ip"] for a in attackers if len(a["users"]) >= 3}
    if spray:
        first_try = {}                      # uma ocorrência por conta testada
        for e in failed:
            if e["ip"] in spray:
                first_try.setdefault((e["ip"], e["user"]), e)
        findings.append(finding("ssh_spraying", [occurrence(e) for e in first_try.values()]))
    recon = [a["ip"] for a in attackers if per_ip[a["ip"]]["recon"]]
    if recon:
        findings.append(finding("ssh_scan", [(ip, r["n"], r["time"]) for ip in recon for r in per_ip[ip]["recon"]]))

    # Veredito
    groups = group_alerts_by_ip(alerts)
    if groups:
        g = groups[0]
        a0 = alerts_by_ip[g["ip"]][0]
        users_text = ", ".join(g["users"])
        text = (f"{g['ip']} errou a senha {g['max_failures']} vezes seguidas e depois entrou como "
                f"{users_text} em {pretty_time(g['last'])}.")
        if g["count"] > 1:
            text += f" Isso aconteceu {g['count']} vezes."
        text += f" Ferramenta provável: {by_ip[g['ip']]['tool']}."
        if len(groups) > 1:
            text += " Outros IPs que também entraram: " + ", ".join(x["ip"] for x in groups[1:]) + "."
        verdict = {
            "level": "critico",
            "title": "Um atacante conseguiu entrar" if len(alerts) == 1 else f"{len(alerts)} logins aceitos após brute force",
            "text": text,
            "actions": [{"label": f"Ver o login no log (L{a0['line']})", "line": a0["line"]},
                        {"label": f"Todas as linhas de {g['ip']}", "ip": g["ip"]}],
        }
    else:
        verdict = {
            "level": "baixo",
            "title": "Nenhum atacante conseguiu entrar",
            "text": (f"{plural(len(bruteforce), 'IP passou', 'IPs passaram')} do limite de {threshold} falhas, "
                     "mas nenhum teve login aceito logo depois." if bruteforce
                     else f"Nenhum IP passou do limite de {threshold} falhas."),
            "actions": [],
        }

    suspects = sum(1 for a in attackers if a["risk"] != "baixo")
    kpis = [
        {"label": "Eventos de login", "value": len(events), "note": plural(len(records), "linha lida", "linhas lidas")},
        {"label": "Falhas", "value": len(failed),
         "note": f"{100 * len(failed) / len(events):.1f}% das tentativas".replace(".", ",") if events else ""},
        {"label": "Logins aceitos", "value": len(events) - len(failed), "note": f"{len(alerts)} após brute force"},
        {"label": "IPs de origem", "value": len(attackers), "note": plural(suspects, "suspeito", "suspeitos")},
        {"label": "Brute force", "value": len(bruteforce), "note": f"IPs com ≥ {threshold} falhas"},
    ]

    t0 = targets.most_common(1)[0][0] if targets else None
    sessions = [dict(s, ip=a["ip"]) for a in attackers if a["risk"] == "critico" for s in a["sessions"]]
    target = {
        "title": host_port(*t0) if t0 else (hosts.most_common(1)[0][0] if hosts else "—"),
        "tag": "SSH",
        "sub": "host " + (", ".join(h for h, _ in hosts.most_common()) or "—"),
        "rows": [
            {"label": "Conexões",
             "text": ", ".join(f"{c} na porta {p}" for (_, p), c in targets.most_common())
             or "porta não registrada (ative LogLevel VERBOSE)", "muted": not targets},
            {"label": "Contas que existem", "chips": existing},
            {"label": "Contas inexistentes", "chips": missing,
             "note": "Nomes tirados de listas prontas (wordlists)." if missing else None},
            {"label": "Sessões do atacante",
             "items": [{"text": f"{s['user']} aberta às {pretty_time(s['time'])} por {s['ip']}", "line": s["n"]}
                       for s in sessions]},
        ],
    }

    critical_lines = {a["line"] for a in alerts}
    embedded, note = embed_lines(records, critical_lines, lambda r: r["ip"] or r["k"] != "other")
    return {
        "kind": "ssh",
        "hosts": [h for h, _ in hosts.most_common()],
        "targets": [{"dst": d, "port": p, "connections": c} for (d, p), c in targets.most_common()],
        "period": {"start": first_time, "end": last_time},
        "totals": {"lines": len(records), "events": len(events), "failed": len(failed),
                   "accepted": len(events) - len(failed), "ips": len(attackers),
                   "bruteforce": len(bruteforce), "critical": len(alerts)},
        "verdict": verdict,
        "kpis": kpis,
        "alerts": alerts,
        "bruteforce": bruteforce,
        "attackers": attackers,
        "accounts": accounts,
        "target": target,
        "techniques": aggregate_techniques(attackers),
        "findings": sort_findings(findings),
        "critical_lines": sorted(critical_lines),
        "labels": {
            "failed": "Falhas", "accepted": "Aceitos", "users": "Contas",
            "failed_unit": ["falha", "falhas"], "accepted_unit": ["aceito", "aceitos"],
            "target_sub": "O que foi atacado neste servidor.",
            "accounts_title": "Contas mais atacadas", "accounts_sub": "Falhas de login por conta.",
            "accounts_empty": "Nenhuma falha de login.",
            "seq_intro": "O log é lido na ordem. Contar falhas mostra o brute force; só a ordem mostra "
                         "que o login aceito veio depois delas. O contador zera a cada login aceito.",
            "legend": [["failed", "Falha"], ["accepted", "Login aceito"],
                       ["crit", "Aceito após o limite (crítico)"], ["recon", "Varredura"]],
            "limit": f"Limite de {threshold} falhas seguidas",
        },
        "log_filters": [["all", "Todas", []], ["failed", "Falhas", ["failed", "invalid_user"]],
                        ["accepted", "Aceitos e sessões", ["accepted", "session"]],
                        ["recon", "Varreduras", ["recon"]], ["client", "Banner do cliente", ["client"]]],
        "kind_labels": {"failed": "FALHA", "invalid_user": "USUÁRIO INVÁLIDO", "accepted": "ACEITO",
                        "session": "SESSÃO", "recon": "VARREDURA", "client": "CLIENTE", "connection": "CONEXÃO"},
        "lines": embedded,
        "lines_note": note,
    }


def profile_ssh_ip(ip: str, evs: list, extra: dict, threshold: int, is_brute: bool, alerts: list) -> dict:
    """Ficha de um IP: risco, ritmo, ferramenta provável, técnicas e sequência de eventos."""
    failed = [e for e in evs if e["status"] == "failed"]
    accepted = [e for e in evs if e["status"] == "accepted"]
    users = Counter(e["user"] for e in failed)

    median_gap, machine_pace = pace([e["time"] for e in evs])
    software = extra["software"][0] if extra["software"] else None
    tool, tool_basis = guess_tool(software and software["software"], machine_pace, extra["recon"], len(evs))

    techniques = []
    if extra["recon"]:
        techniques.append({"id": "T1046", "evidence": [r["n"] for r in extra["recon"]]})
    if users and users.most_common(1)[0][1] >= 3:
        top_user = users.most_common(1)[0][0]
        techniques.append({"id": "T1110.001", "evidence": [e["line"] for e in failed if e["user"] == top_user]})
    if len(users) >= 3:
        first_per_user = {}
        for e in failed:
            first_per_user.setdefault(e["user"], e["line"])
        techniques.append({"id": "T1110.003", "evidence": list(first_per_user.values())})
    if alerts:
        evidence = [a["line"] for a in alerts]
        evidence += [s["n"] for s in extra["sessions"] if s["n"] > evidence[0]]
        techniques.append({"id": "T1078", "evidence": evidence})

    if alerts:
        risk = "critico"
    elif is_brute:
        risk = "alto"
    elif extra["recon"] or (failed and (machine_pace or any(e["invalid"] for e in failed))):
        risk = "medio"
    else:
        risk = "baixo"

    # Sequência na ordem do log. O contador de falhas zera a cada login aceito,
    # igual à regra de detecção.
    sequence = []
    since_success = 0
    items = [(e["line"], "ev", e) for e in evs] + [(r["n"], "recon", r) for r in extra["recon"]]
    for n, kind, item in sorted(items, key=lambda x: x[0]):
        if kind == "recon":
            sequence.append({"k": "recon", "n": n, "time": item["time"], "label": "Varredura: " + item["label"]})
        elif item["status"] == "failed":
            since_success += 1
            sequence.append({"k": "failed", "n": n, "time": item["time"], "count": since_success,
                             "label": f"Falha nº {since_success} seguida · {item['user']}"})
        else:
            crit = since_success >= threshold
            sequence.append({"k": "accepted", "n": n, "time": item["time"], "crit": crit,
                             "label": ("ACEITO APÓS O LIMITE · " if crit else "Aceito · ") + item["user"]})
            since_success = 0

    return {
        "ip": ip,
        "risk": risk,
        "failed": len(failed),
        "accepted": len(accepted),
        "users": [u for u, _ in users.most_common()] or sorted({e["user"] for e in accepted}),
        "first": extra["first"],
        "last": extra["last"],
        "period": f"{clock(extra['first'])} → {clock(extra['last'])}",
        "median_gap": median_gap,
        "machine_pace": machine_pace,
        "software": software,
        "tool": tool,
        "tool_basis": tool_basis,
        "sessions": extra["sessions"],
        "techniques": techniques,
        "sequence": sequence,
    }


# --- Web (nginx/Apache) -------------------------------------------------------------


def analyze_web_lines(lines: list[str], threshold: int = DEFAULT_THRESHOLD) -> dict:
    events = web.web_events_from_lines(lines)
    by_line = {e["n"]: e for e in events}
    login_alerts = web.detect_login_compromise(events, threshold)
    exposed = [e for e in events if web.is_exposed(e)]

    records = []
    for n, raw in enumerate(lines, 1):
        e = by_line.get(n)
        kind = "other"
        if e:
            if e["attack"]:
                kind = "attack_ok" if 200 <= e["status"] < 300 else "attack"
            elif e["login"]:
                kind = "login_ok" if e["login"] == "success" else "login_fail"
            else:
                kind = "recon" if e["status"] == 404 else "normal"
        records.append({"n": n, "k": kind, "t": raw.rstrip("\r\n"), "ip": e["ip"] if e else None})

    events_by_ip = defaultdict(list)
    for e in events:
        events_by_ip[e["ip"]].append(e)
    alerts_by_ip = defaultdict(list)
    for a in login_alerts:
        alerts_by_ip[a["ip"]].append(a)

    attackers = [profile_web_ip(ip, evs, threshold, alerts_by_ip.get(ip, [])) for ip, evs in events_by_ip.items()]
    attackers.sort(key=lambda a: (RISK_ORDER[a["risk"]], -a["failed"]))
    by_ip = {a["ip"]: a for a in attackers}

    malicious = [e for e in events if e["attack"] or e["login"] == "fail"]
    attack_ok = [e for e in events if e["attack"] and 200 <= e["status"] < 300]

    # Caminhos mais atacados
    paths = defaultdict(list)
    for e in malicious:
        paths[shorten(e["path"].split("?", 1)[0], 48)].append(e)
    exposed_paths = {shorten(e["path"].split("?", 1)[0], 48) for e in exposed}
    compromised_paths = {shorten(a["path"].split("?", 1)[0], 48) for a in login_alerts}
    accounts = []
    for path, evs in sorted(paths.items(), key=lambda kv: -len(kv[1]))[:15]:
        kinds = Counter(web.ATTACK_LABELS.get(e["attack"], "Senha errada") for e in evs)
        flags = []
        if path in exposed_paths:
            flags.append({"text": "exposto", "critical": True})
        if path in compromised_paths:
            flags.append({"text": "invadido", "critical": True})
        flags += [{"text": k} for k, _ in kinds.most_common(2)]
        ips = sorted({e["ip"] for e in evs})
        accounts.append({"name": path, "count": len(evs), "flags": flags,
                         "tip": f"{path}: {plural(len(evs), 'requisição maliciosa', 'requisições maliciosas')}\n"
                                f"de {', '.join(ips[:5])}{' …' if len(ips) > 5 else ''}"})

    # Como corrigir
    findings = []
    occurrence = lambda e: (e["ip"], e["n"], e["time"])  # noqa: E731
    if exposed:
        findings.append(finding("web_sensitive_exposed", [occurrence(e) for e in exposed]))
    if login_alerts:
        findings.append(finding("web_login_compromise", [(a["ip"], a["n"], a["time"]) for a in login_alerts]))
    for kind, key in (("rce", "web_rce"), ("sqli", "web_sqli"), ("traversal", "web_traversal"), ("xss", "web_xss")):
        hits = [occurrence(e) for e in events if e["attack"] == kind]
        if hits:
            findings.append(finding(key, hits))
    login_fail = Counter(e["ip"] for e in events if e["login"] == "fail")
    brute = [ip for ip, n in login_fail.items() if n >= threshold]
    if brute:
        findings.append(finding("web_login_bruteforce",
                                [occurrence(e) for e in events if e["login"] == "fail" and e["ip"] in brute]))
    probes = [occurrence(e) for e in events if e["attack"] == "sensitive" and not web.is_exposed(e)]
    if probes and not exposed:
        findings.append(finding("web_sensitive_probe", probes))
    scanners = {a["ip"] for a in attackers if any(t["id"] in ("T1595.002", "T1595.003") for t in a["techniques"])}
    if scanners:
        findings.append(finding("web_scanning", [occurrence(e) for e in events if e["ip"] in scanners]))

    # Veredito
    critical_lines = {e["n"] for e in exposed} | {a["n"] for a in login_alerts}
    if critical_lines:
        parts = [f"{e['ip']} baixou {shorten(e['path'], 50)} (resposta {e['status']}, {e['size']} bytes)."
                 for e in exposed[:2]]
        parts += [f"{a['ip']} errou a senha {a['failures']} vezes em {a['path']} e depois entrou "
                  f"({by_ip[a['ip']]['tool']})." for a in login_alerts[:2]]
        first = min(critical_lines)
        first_ip = by_line[first]["ip"]
        title = ("Ataques com sucesso" if exposed and login_alerts
                 else "Arquivo sensível exposto" if exposed else "Um atacante entrou no site")
        verdict = {"level": "critico", "title": title, "text": " ".join(parts),
                   "actions": [{"label": f"Ver no log (L{first})", "line": first},
                               {"label": f"Todas as linhas de {first_ip}", "ip": first_ip}]}
    elif malicious:
        level = "alto" if any(a["risk"] == "alto" for a in attackers) else "medio"
        verdict = {"level": level, "title": "Ataques detectados, nenhum com sucesso confirmado",
                   "text": f"{plural(len(malicious), 'requisição maliciosa', 'requisições maliciosas')} de "
                           f"{plural(len({e['ip'] for e in malicious}), 'IP', 'IPs')}. Veja abaixo como corrigir.",
                   "actions": []}
    else:
        verdict = {"level": "baixo", "title": "Nenhum ataque detectado",
                   "text": f"{plural(len(events), 'requisição analisada', 'requisições analisadas')}.", "actions": []}

    offensive = sum(1 for a in attackers if a["offensive_tool"])
    suspects = sum(1 for a in attackers if a["risk"] != "baixo")
    kpis = [
        {"label": "Requisições", "value": len(events), "note": plural(len(records), "linha lida", "linhas lidas")},
        {"label": "Ataques", "value": len(malicious),
         "note": f"{100 * len(malicious) / len(events):.1f}% das requisições".replace(".", ",") if events else ""},
        {"label": "Ataques com 2xx", "value": len(attack_ok), "note": plural(len(critical_lines), "crítico", "críticos")},
        {"label": "IPs de origem", "value": len(attackers), "note": plural(suspects, "suspeito", "suspeitos")},
        {"label": "Ferramentas de ataque", "value": offensive, "note": "identificadas pelo user-agent"},
    ]

    statuses = Counter(e["status"] for e in events)
    target = {
        "title": "Site / API",
        "tag": "HTTP",
        "sub": plural(len(events), "requisição", "requisições"),
        "rows": [
            {"label": "Respostas", "chips": [f"{s} × {n}" for s, n in statuses.most_common(6)]},
            {"label": "Arquivos expostos",
             "items": [{"text": f"{shorten(e['path'], 40)} para {e['ip']}", "line": e["n"]} for e in exposed[:5]]},
            {"label": "Logins após brute force",
             "items": [{"text": f"{a['path']} por {a['ip']}", "line": a["n"]} for a in login_alerts[:5]]},
            {"label": "Mais procurados (404)",
             "chips": [shorten(p, 24) for p, _ in Counter(
                 e["path"].split("?", 1)[0] for e in events if e["status"] == 404).most_common(8)]},
        ],
    }

    times = [e["time"] for e in events]
    embedded, note = embed_lines(records, critical_lines, lambda r: r["k"] not in ("normal", "other"))
    return {
        "kind": "web",
        "hosts": [],
        "targets": [],
        "period": {"start": times[0] if times else None, "end": times[-1] if times else None},
        "totals": {"lines": len(records), "events": len(events), "failed": len(malicious),
                   "accepted": len(attack_ok), "ips": len(attackers),
                   "bruteforce": len(brute), "critical": len(critical_lines)},
        "verdict": verdict,
        "kpis": kpis,
        "alerts": [{"ip": by_line[n]["ip"], "line": n} for n in sorted(critical_lines)],
        "attackers": attackers,
        "accounts": accounts,
        "target": target,
        "techniques": aggregate_techniques(attackers),
        "findings": sort_findings(findings),
        "critical_lines": sorted(critical_lines),
        "labels": {
            "failed": "Ataques", "accepted": "Com 2xx", "users": "Caminhos",
            "failed_unit": ["ataque", "ataques"], "accepted_unit": ["com 2xx", "com 2xx"],
            "target_sub": "O que foi atacado neste site.",
            "accounts_title": "Caminhos mais atacados", "accounts_sub": "Requisições maliciosas por caminho.",
            "accounts_empty": "Nenhuma requisição maliciosa.",
            "seq_intro": "Cada quadrado é uma requisição suspeita, na ordem do log. Resposta 2xx a um ataque "
                         "merece atenção; um arquivo sensível baixado ou um login depois de brute force é crítico.",
            "legend": [["failed", "Ataque bloqueado ou senha errada"], ["warn", "Ataque com resposta 2xx"],
                       ["crit", "Ataque com sucesso (crítico)"], ["accepted", "Login aceito"],
                       ["recon", "404 (sondagem)"]],
            "limit": f"Limite de {threshold} senhas erradas seguidas",
        },
        "log_filters": [["all", "Todas", []], ["attack", "Ataques", ["attack", "attack_ok"]],
                        ["login", "Logins", ["login_fail", "login_ok"]], ["recon", "404", ["recon"]]],
        "kind_labels": {"attack": "ATAQUE", "attack_ok": "ATAQUE 2XX", "login_fail": "LOGIN ✕",
                        "login_ok": "LOGIN ✓", "recon": "404"},
        "lines": embedded,
        "lines_note": note,
    }


def profile_web_ip(ip: str, evs: list, threshold: int, alerts: list) -> dict:
    attacks = [e for e in evs if e["attack"]]
    login_fail = [e for e in evs if e["login"] == "fail"]
    exposed = [e for e in evs if web.is_exposed(e)]
    not_found = [e for e in evs if e["status"] == 404 and not e["attack"]]
    attack_ok = [e for e in attacks if 200 <= e["status"] < 300]
    types = Counter(e["attack"] for e in attacks)

    median_gap, machine_pace = pace([e["time"] for e in evs], min_events=5, machine_seconds=1)
    ua_event = next((e for e in evs if e["ua"] and e["ua"] != "-"), None)
    found = web.detect_tool(ua_event["ua"]) if ua_event else None
    offensive = bool(found and found[2])
    if found:
        tool, why, _ = found
        basis = f'user-agent "{shorten(ua_event["ua"], 40)}": {why}'
        if tool == "Navegador" and machine_pace and (attacks or login_fail):
            tool, basis = "Ferramenta automatizada", basis + "; o ritmo de máquina sugere user-agent falso"
    elif machine_pace:
        tool, basis = "Ferramenta automatizada", "ritmo de máquina entre as requisições"
    else:
        tool, basis = "Desconhecida", "requisições sem user-agent reconhecido"
    if ua_event and types.get("rce") and web.ATTACK_PATTERNS[0][1].search(ua_event["ua"]):
        tool, basis = "Exploit no user-agent", "payload de Log4Shell/Shellshock enviado no cabeçalho User-Agent"

    techniques = []
    exploit = [e["n"] for e in attacks if e["attack"] in ("rce", "sqli", "traversal", "xss")]
    if exploit:
        techniques.append({"id": "T1190", "evidence": exploit})
    if offensive:
        techniques.append({"id": "T1595.002", "evidence": [e["n"] for e in evs[:3]]})
    if len(not_found) >= web.SCAN_404_THRESHOLD or types.get("sensitive", 0) >= 3:
        techniques.append({"id": "T1595.003",
                           "evidence": [e["n"] for e in (not_found or attacks)][:5]})
    if len(login_fail) >= threshold:
        techniques.append({"id": "T1110.001", "evidence": [e["n"] for e in login_fail]})
    if alerts:
        techniques.append({"id": "T1078", "evidence": [a["n"] for a in alerts]})
    if exposed:
        techniques.append({"id": "T1552.001", "evidence": [e["n"] for e in exposed]})

    if exposed or alerts:
        risk = "critico"
    elif types.keys() & {"rce", "sqli", "traversal"} or len(login_fail) >= threshold:
        risk = "alto"
    elif types or login_fail or len(not_found) >= web.SCAN_404_THRESHOLD or offensive:
        risk = "medio"
    else:
        risk = "baixo"

    sequence = []
    since_success = 0
    for e in evs:
        target = f"{e['method']} {shorten(e['path'], 50)} → {e['status']}"
        if e["attack"]:
            ok = 200 <= e["status"] < 300
            crit = web.is_exposed(e) or (e["attack"] == "traversal" and ok)
            sequence.append({"k": "warn" if ok else "failed", "crit": crit, "n": e["n"], "time": e["time"],
                             "label": f"{web.ATTACK_LABELS[e['attack']]} · {target}"})
        elif e["login"] == "fail":
            since_success += 1
            sequence.append({"k": "failed", "n": e["n"], "time": e["time"], "count": since_success,
                             "label": f"Senha errada nº {since_success} · {target}"})
        elif e["login"] == "success":
            crit = since_success >= threshold
            sequence.append({"k": "accepted", "crit": crit, "n": e["n"], "time": e["time"],
                             "label": ("LOGIN APÓS BRUTE FORCE · " if crit else "Login aceito · ") + target})
            since_success = 0
        elif e["status"] == 404:
            sequence.append({"k": "recon", "n": e["n"], "time": e["time"], "label": f"404 · {target}"})

    paths = Counter(e["path"].split("?", 1)[0] for e in attacks + login_fail)
    return {
        "ip": ip,
        "risk": risk,
        "failed": len(attacks) + len(login_fail),
        "accepted": len(attack_ok) + len(alerts),
        "users": [shorten(p, 40) for p, _ in paths.most_common()],
        "first": evs[0]["time"],
        "last": evs[-1]["time"],
        "period": f"{clock(evs[0]['time'])} → {clock(evs[-1]['time'])}",
        "median_gap": median_gap,
        "machine_pace": machine_pace,
        "software": {"software": ua_event["ua"], "n": ua_event["n"]} if ua_event else None,
        "tool": tool,
        "tool_basis": basis,
        "offensive_tool": offensive,
        "sessions": [],
        "techniques": techniques,
        "sequence": sequence,
    }


# --- Entrada e saída ------------------------------------------------------------------


def analyze_lines(lines: list[str], kind: str = "auto", threshold: int = DEFAULT_THRESHOLD,
                  source: str = "log") -> dict:
    lines = list(lines)
    if kind == "auto":
        kind = detect_kind(lines)
    data = analyze_web_lines(lines, threshold) if kind == "web" else analyze_ssh_lines(lines, threshold)
    data["source"] = os.path.basename(source)
    data["generated"] = datetime.now().strftime("%d/%m/%Y %H:%M")
    data["threshold"] = threshold
    data["meta"] = [
        data["source"],
        *(["host " + ", ".join(data["hosts"])] if data["hosts"] else []),
        f"{pretty_time(data['period']['start'])} → {pretty_time(data['period']['end'])}",
        f"gerado em {data['generated']}",
    ]
    return data


def analyze(path: str, threshold: int = DEFAULT_THRESHOLD, kind: str = "auto") -> dict:
    """Lê o log e monta tudo que o dashboard precisa."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return analyze_lines(f.read().splitlines(), kind=kind, threshold=threshold, source=path)


def render_html(data: dict, nonce: str | None = None, nav: dict | None = None) -> str:
    """HTML final. `nonce` e `nav` são usados pela aplicação web (CSP e link de volta)."""
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        template = f.read()
    if nav:
        data = {**data, "nav": nav}
    # Usuários, caminhos e linhas do log vêm do atacante: "<" escapado impede que
    # um texto como "</script><script>..." execute código no dashboard.
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    nonce_attr = f' nonce="{nonce}"' if nonce else ""
    return template.replace("__NONCE_ATTR__", nonce_attr).replace("__DATA__", payload)


def write_dashboard(log_path: str, out_path: str, threshold: int = DEFAULT_THRESHOLD, kind: str = "auto") -> None:
    html = render_html(analyze(log_path, threshold, kind))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera um dashboard HTML a partir de um log SSH ou web.")
    parser.add_argument("logfile")
    parser.add_argument("-o", "--output", default="dashboard.html")
    parser.add_argument("--tipo", choices=["auto", "ssh", "web"], default="auto")
    parser.add_argument("--limite", type=int, default=DEFAULT_THRESHOLD)
    args = parser.parse_args(argv)
    try:
        write_dashboard(args.logfile, args.output, args.limite, args.tipo)
    except OSError as err:
        print(f"Erro: {err}", file=sys.stderr)
        return 1
    print(f"Dashboard salvo em {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
