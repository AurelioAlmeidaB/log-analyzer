#!/usr/bin/env python3
"""
log_analyzer.py - analisador de logs de autenticação SSH (auth.log).

Responde três perguntas:
  1. Alguém está tentando adivinhar senhas? (brute force)
  2. Quais contas estão sendo atacadas?
  3. Algum atacante conseguiu entrar?  <- a mais importante

Uso:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --html dashboard.html

Python puro (só biblioteca padrão). Use apenas em logs seus ou de laboratório.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter

DEFAULT_THRESHOLD = 5

# --- Passo 1: regex -----------------------------------------------------------

# Data no começo da linha, nos dois formatos que o syslog usa:
#   clássico:  "Nov 22 02:47:03"
#   RFC 3339:  "2026-11-22T02:47:03.123456-03:00"   (Ubuntu 24.04 em diante)
TIMESTAMP = (
    r"(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# "<data> <host> sshd[<pid>]: "  (no OpenSSH 9.8+ o processo é "sshd-session")
SSHD_PREFIX = TIMESTAMP + r"\s+(?P<host>\S+)\s+sshd(?:-session)?\[(?P<pid>\d+)\]:\s+"

# Linha de tentativa de login, por exemplo:
#   Failed password for invalid user admin from 203.0.113.5 port 40110 ssh2
#   Accepted password for root from 203.0.113.5 port 40128 ssh2
# O rsyslog junta linhas iguais seguidas em
#   message repeated 3 times: [ Failed password for root from ... ]
# por isso o trecho opcional "message repeated".
LOGIN_RE = re.compile(
    SSHD_PREFIX
    + r"(?:message repeated (?P<repeat>\d+) times: \[\s*)?"
    + r"(?P<status>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive/pam)"
    + r" for (?P<invalid>invalid user )?(?P<user>\S+)"
    + r" from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)


def parse_line(line: str) -> dict | None:
    """Transforma uma linha do log em evento, ou None se não for tentativa de login.

    Evento: {"time", "user", "ip", "status"}, com status "failed" ou "accepted".
    """
    match = LOGIN_RE.search(line)
    if not match:
        return None
    return {
        "time": match["time"],
        "user": match["user"],
        "ip": match["ip"],
        "status": match["status"].lower(),
    }


def repeat_count(line: str) -> int:
    """Quantas tentativas a linha representa (>1 em "message repeated N times")."""
    match = LOGIN_RE.search(line)
    return int(match["repeat"]) if match and match["repeat"] else 1


# --- Passo 2: carregar eventos ------------------------------------------------


def load_events(path: str) -> list[dict]:
    """Lê o arquivo NA ORDEM e devolve a lista de eventos de login."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event is None:
                continue
            for _ in range(repeat_count(line)):
                events.append(dict(event))
    return events


# --- Passo 3: contagens -------------------------------------------------------


def count_failures_by_ip(events: list[dict]) -> Counter:
    return Counter(e["ip"] for e in events if e["status"] == "failed")


def count_failures_by_user(events: list[dict]) -> Counter:
    return Counter(e["user"] for e in events if e["status"] == "failed")


# --- Passo 4: detecções -------------------------------------------------------


def detect_bruteforce(failures_by_ip: Counter, threshold: int = DEFAULT_THRESHOLD) -> list[tuple[str, int]]:
    """IPs com falhas >= limite, do mais ativo para o menos ativo. Severidade: média."""
    return [(ip, n) for ip, n in failures_by_ip.most_common() if n >= threshold]


def detect_success_after_failures(events: list[dict], threshold: int = DEFAULT_THRESHOLD) -> list[dict]:
    """IPs que atingiram o limite de falhas e DEPOIS tiveram login aceito. Severidade: crítica.

    Os eventos precisam estar na ordem do log: só a contagem total não diz se
    o sucesso veio antes ou depois das falhas.
    """
    failures_so_far = Counter()
    alerts = []
    for event in events:
        ip = event["ip"]
        if event["status"] == "failed":
            failures_so_far[ip] += 1
        elif failures_so_far[ip] >= threshold:
            alerts.append({
                "ip": ip,
                "user": event["user"],
                "failures": failures_so_far[ip],
                "time": event["time"],
            })
    return alerts


# --- Passo 5: relatório -------------------------------------------------------


def build_report(events: list[dict], threshold: int = DEFAULT_THRESHOLD, top: int = 5) -> str:
    failures_by_ip = count_failures_by_ip(events)
    failures_by_user = count_failures_by_user(events)
    total_failures = sum(failures_by_ip.values())

    lines = [
        "=== RELATÓRIO DE ANÁLISE DE LOG ===",
        f"Eventos de login: {len(events)}  |  Falhas: {total_failures}",
        "",
    ]

    alerts = detect_success_after_failures(events, threshold)
    if alerts:
        lines.append("🚨 ALERTA: login aceito após falhas")
        for a in alerts:
            lines.append(
                f'   {a["ip"]}  ({a["failures"]} falhas, depois sucesso como "{a["user"]}" em {a["time"]})'
            )
    else:
        lines.append("✅ Nenhum login aceito após falhas")
    lines.append("")

    lines.append(f"⚠️  Possível brute force (>= {threshold} falhas)")
    suspects = detect_bruteforce(failures_by_ip, threshold)
    for ip, n in suspects:
        lines.append(f"   {ip:<15} {n:>3} falhas")
    if not suspects:
        lines.append("   nenhum IP atingiu o limite")
    lines.append("")

    lines.append("🎯 Contas mais atacadas")
    for user, n in failures_by_user.most_common(top):
        lines.append(f"   {user:<10} {n:>3}")
    if len(failures_by_user) > top:
        lines.append(f"   ... (+{len(failures_by_user) - top} contas)")
    if not failures_by_user:
        lines.append("   nenhuma falha de login")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analisa logs de autenticação SSH (auth.log).")
    parser.add_argument("logfile", help="arquivo de log, ex.: /var/log/auth.log")
    parser.add_argument("--html", metavar="ARQUIVO", help="gera também um dashboard HTML")
    args = parser.parse_args(argv)

    # Evita erro de encoding com os emojis quando a saída vai para um arquivo no Windows.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    try:
        events = load_events(args.logfile)
    except OSError as err:
        print(f"Erro ao ler {args.logfile}: {err}", file=sys.stderr)
        return 1

    print(build_report(events))

    if args.html:
        from dashboard import write_dashboard

        write_dashboard(args.logfile, args.html)
        print(f"\n📊 Dashboard salvo em {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
