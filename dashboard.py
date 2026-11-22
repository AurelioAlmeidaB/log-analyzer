#!/usr/bin/env python3
"""
dashboard.py - gera um dashboard HTML (arquivo único, abre offline) a partir do log.

O dashboard mostra:
  - o veredito: algum atacante entrou?
  - pontos de ataque: de onde vêm (IPs) e o que miram (host, porta, contas)
  - ferramentas prováveis e técnicas MITRE ATT&CK, com as linhas que servem de evidência
  - a sequência de eventos de cada IP (por que a ordem do log importa)
  - o log completo, com filtros e busca

Uso:
    python log_analyzer.py sample_auth.log --html dashboard.html
    python dashboard.py sample_auth.log -o dashboard.html

As regras de detecção são as mesmas do log_analyzer.py; este módulo só
acrescenta contexto (conexões, banner do cliente, varreduras) lendo as
outras linhas do sshd.
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

from log_analyzer import (
    DEFAULT_THRESHOLD,
    LOGIN_RE,
    TIMESTAMP,
    count_failures_by_ip,
    detect_bruteforce,
    detect_success_after_failures,
)

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_template.html")

# Qualquer linha de syslog: "<data> <host> <processo>[<pid>]: <mensagem>"
SYSLOG_RE = re.compile(
    TIMESTAMP + r"\s+(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# Mensagens do sshd que dão contexto ao ataque.
# "Connection from" aparece com LogLevel VERBOSE; o banner do cliente, com LogLevel DEBUG1.
CONNECTION_RE = re.compile(r"Connection from (?P<ip>\S+) port \d+ on (?P<dst>\S+) port (?P<dport>\d+)")
SOFTWARE_RE = re.compile(r"remote software version (?P<software>.+?)\s*$")
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
    "T1110.001": ("Adivinhação de senha", "Muitas senhas contra a mesma conta."),
    "T1110.003": ("Password spraying", "Poucas tentativas em muitas contas, geralmente de uma lista pronta."),
    "T1078": ("Uso de conta válida", "Login aceito depois de passar do limite de falhas: senha descoberta."),
}

RISK_ORDER = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
MACHINE_PACE_SECONDS = 3  # mediana <= 3 s entre tentativas: ninguém digita senha tão rápido

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def to_datetime(ts: str) -> datetime | None:
    """Converte a data do log. O formato clássico não tem ano; só as diferenças importam."""
    try:
        if ts[0].isdigit():
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        month, day, clock = ts.split()
        hour, minute, second = map(int, clock.split(":"))
        return datetime(2000, MONTHS[month], int(day), hour, minute, second)
    except (ValueError, KeyError):
        return None


def classify_sshd_message(msg: str) -> tuple[str, str | None, dict]:
    """Diz o que uma mensagem do sshd (que não é Failed/Accepted) significa."""
    m = CONNECTION_RE.search(msg)
    if m:
        return "connection", m["ip"], {"dst": m["dst"], "dport": m["dport"]}
    m = SOFTWARE_RE.search(msg)
    if m:
        return "client", None, {"software": m["software"]}
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


def analyze(path: str, threshold: int = DEFAULT_THRESHOLD) -> dict:
    """Lê o log uma vez e monta tudo que o dashboard precisa."""
    lines = []
    events = []                    # mesmo formato do log_analyzer, mais "line" e "invalid"
    pid_ip = {}                    # sshd[pid] -> IP: liga linhas sem IP à conexão certa
    hosts = Counter()
    targets = Counter()
    first_time = last_time = None
    per_ip = defaultdict(lambda: {
        "software": [], "recon": [], "sessions": [], "connections": 0,
        "first": None, "last": None, "lines": 0,
    })

    with open(path, encoding="utf-8", errors="replace") as f:
        for n, raw in enumerate(f, 1):
            text = raw.rstrip("\r\n")
            rec = {"n": n, "k": "other", "t": text, "ip": None}
            lines.append(rec)

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
            p["lines"] += 1
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
    for a in alerts:
        a["line"] = next(
            e["line"] for e in events
            if e["status"] == "accepted" and e["ip"] == a["ip"]
            and e["user"] == a["user"] and e["time"] == a["time"]
        )

    events_by_ip = defaultdict(list)
    for e in events:
        events_by_ip[e["ip"]].append(e)

    brute_ips = {ip for ip, _ in bruteforce}
    alerts_by_ip = defaultdict(list)
    for a in alerts:
        alerts_by_ip[a["ip"]].append(a)

    attackers = [
        profile_ip(ip, events_by_ip.get(ip, []), per_ip[ip], threshold, ip in brute_ips, alerts_by_ip.get(ip, []))
        for ip in dict.fromkeys([*events_by_ip, *per_ip])
    ]
    attackers.sort(key=lambda a: (RISK_ORDER[a["risk"]], -a["failed"]))

    failed = [e for e in events if e["status"] == "failed"]
    compromised_users = {a["user"] for a in alerts}
    accounts = []
    for user, count in Counter(e["user"] for e in failed).most_common():
        mine = [e for e in failed if e["user"] == user]
        accounts.append({
            "user": user,
            "failed": count,
            "ips": sorted({e["ip"] for e in mine}),
            "exists": not any(e["invalid"] for e in mine),
            "compromised": user in compromised_users,
        })

    techniques = []
    for tid, (name, description) in TECHNIQUES.items():
        found = [(a["ip"], t["evidence"]) for a in attackers for t in a["techniques"] if t["id"] == tid]
        if found:
            techniques.append({
                "id": tid, "name": name, "description": description,
                "ips": [ip for ip, _ in found],
                "evidence": sorted({n for _, ev in found for n in ev})[:8],
            })

    return {
        "file": os.path.basename(path),
        "generated": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "threshold": threshold,
        "hosts": [h for h, _ in hosts.most_common()],
        "targets": [{"dst": d, "port": p, "connections": c} for (d, p), c in targets.most_common()],
        "period": {"start": first_time, "end": last_time},
        "totals": {
            "lines": len(lines),
            "events": len(events),
            "failed": len(failed),
            "accepted": len(events) - len(failed),
            "ips": len(attackers),
            "bruteforce": len(bruteforce),
            "critical": len(alerts),
        },
        "alerts": alerts,
        "bruteforce": bruteforce,
        "attackers": attackers,
        "accounts": accounts,
        "techniques": techniques,
        "lines": lines,
    }


def profile_ip(ip: str, evs: list, extra: dict, threshold: int, is_brute: bool, alerts: list) -> dict:
    """Ficha de um IP: risco, ritmo, ferramenta provável, técnicas e sequência de eventos."""
    failed = [e for e in evs if e["status"] == "failed"]
    accepted = [e for e in evs if e["status"] == "accepted"]
    users = Counter(e["user"] for e in failed)

    times = [to_datetime(e["time"]) for e in evs]
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
    machine_pace = len(evs) >= 3 and median_gap is not None and median_gap <= MACHINE_PACE_SECONDS

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

    # Sequência na ordem do log: falhas, sucessos e varreduras deste IP.
    sequence = []
    seen_failures = 0
    items = [(e["line"], "ev", e) for e in evs] + [(r["n"], "recon", r) for r in extra["recon"]]
    for n, kind, item in sorted(items, key=lambda x: x[0]):
        if kind == "recon":
            sequence.append({"k": "recon", "n": n, "time": item["time"], "label": item["label"]})
        elif item["status"] == "failed":
            seen_failures += 1
            sequence.append({"k": "failed", "n": n, "time": item["time"], "user": item["user"], "count": seen_failures})
        else:
            sequence.append({
                "k": "accepted", "n": n, "time": item["time"], "user": item["user"],
                "after_limit": seen_failures >= threshold,
            })

    return {
        "ip": ip,
        "risk": risk,
        "failed": len(failed),
        "accepted": len(accepted),
        "users": [u for u, _ in users.most_common()],
        "accepted_users": sorted({e["user"] for e in accepted}),
        "invalid_users": sorted({e["user"] for e in failed if e["invalid"]}),
        "first": extra["first"],
        "last": extra["last"],
        "connections": extra["connections"],
        "median_gap": median_gap,
        "machine_pace": machine_pace,
        "software": software,
        "tool": tool,
        "tool_basis": tool_basis,
        "sessions": extra["sessions"],
        "techniques": techniques,
        "sequence": sequence,
    }


def render_html(data: dict) -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        template = f.read()
    # Usuários e linhas do log vêm do atacante: "<" escapado impede que um
    # usuário chamado "</script><script>..." execute código no dashboard.
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("__DATA__", payload)


def write_dashboard(log_path: str, out_path: str, threshold: int = DEFAULT_THRESHOLD) -> None:
    html = render_html(analyze(log_path, threshold))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera um dashboard HTML a partir de um log SSH.")
    parser.add_argument("logfile")
    parser.add_argument("-o", "--output", default="dashboard.html")
    args = parser.parse_args(argv)
    try:
        write_dashboard(args.logfile, args.output)
    except OSError as err:
        print(f"Erro: {err}", file=sys.stderr)
        return 1
    print(f"Dashboard salvo em {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
