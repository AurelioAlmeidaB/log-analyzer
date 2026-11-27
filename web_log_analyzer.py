"""
web_log_analyzer.py - analisador de access.log do nginx/Apache (formato "combined").

Detecta por requisição:
  - SQL injection, XSS, path traversal e execução de comandos (inclui Log4Shell e Shellshock)
  - procura por arquivos sensíveis (.env, .git, backups) e se algum respondeu 200
  - brute force no formulário de login e login aceito depois dele
  - varredura (muitos 404) e a ferramenta usada, pelo user-agent

Python puro. Use apenas em logs seus ou de laboratório.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Iterable
from urllib.parse import unquote_plus

# 203.0.113.9 - - [27/Nov/2026:03:10:01 -0300] "GET /p.php?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.8"
ACCESS_RE = re.compile(
    r'^(?P<ip>[0-9A-Fa-f:.]+) \S+ (?P<authuser>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)

# Assinaturas de ataque, da mais grave para a menos grave. Testadas no caminho
# decodificado (%27 -> '), e a de RCE também no user-agent (Log4Shell, Shellshock).
ATTACK_PATTERNS = [
    ("rce", re.compile(
        r"\$\{jndi:|\(\)\s*\{\s*:;\s*\};|[;|`]\s*(?:cat|id|whoami|uname|wget|curl|nc|bash|sh)\b"
        r"|\$\((?:id|whoami|curl|wget|cat)\b|/bin/(?:ba)?sh\b|cmd\.exe|powershell", re.I)),
    ("sqli", re.compile(
        r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select|'\s*or\s+'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1"
        r"|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|waitfor\s+delay|;\s*drop\s+table|'\s*--"
        r"|\band\s+\d+\s*=\s*\d+|=\d+'(?:&|$)", re.I)),
    ("traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|/proc/self/", re.I)),
    ("xss", re.compile(
        r"<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|alert\(|document\.cookie", re.I)),
]
# Arquivos que nunca deveriam estar públicos (testado só no caminho, sem a query).
SENSITIVE_RE = re.compile(
    r"/\.env(?:\.\w+)?$|/\.git(?:/|$)|/\.svn/|/\.aws/|/\.ssh/|id_rsa|/\.ht(?:access|passwd)$|wp-config\.php"
    r"|/config\.(?:json|ya?ml|php)$|\.(?:bak|old|swp|sql|tar\.gz|zip)$|/phpinfo\.php$|/server-status$",
    re.I,
)
ATTACK_LABELS = {
    "rce": "Execução de comando",
    "sqli": "SQL injection",
    "traversal": "Path traversal",
    "xss": "XSS",
    "sensitive": "Arquivo sensível",
}

# Formulários de login comuns. POST com redirecionamento (3xx) = entrou; 200/4xx = errou.
# Em APIs (/api/...) é o contrário: 2xx = entrou, 4xx = errou.
LOGIN_PATH_RE = re.compile(
    r"^/(?:wp-login\.php|xmlrpc\.php|login|signin|sign-in|entrar|user/login|admin/login|accounts/login"
    r"|api/(?:v\d+/)?(?:auth|login|token))(?:/|$)",
    re.I,
)

SCAN_404_THRESHOLD = 20  # 404s do mesmo IP para chamar de varredura

# user-agent -> (ferramenta, explicação, é ferramenta de ataque/varredura?)
UA_TOOLS = [
    (re.compile(r"sqlmap", re.I), "sqlmap", "ferramenta automática de SQL injection", True),
    (re.compile(r"nikto", re.I), "Nikto", "scanner de vulnerabilidades web", True),
    (re.compile(r"nuclei", re.I), "Nuclei", "scanner de vulnerabilidades por templates", True),
    (re.compile(r"wpscan", re.I), "WPScan", "scanner de WordPress", True),
    (re.compile(r"gobuster", re.I), "Gobuster", "descobre pastas testando uma lista de nomes", True),
    (re.compile(r"dirbuster", re.I), "DirBuster", "descobre pastas testando uma lista de nomes", True),
    (re.compile(r"\bffuf\b|Fuzz Faster U Fool", re.I), "ffuf", "fuzzer de URLs", True),
    (re.compile(r"wfuzz", re.I), "Wfuzz", "fuzzer de URLs", True),
    (re.compile(r"Nmap Scripting Engine", re.I), "Nmap (NSE)", "scripts HTTP do Nmap", True),
    (re.compile(r"masscan", re.I), "Masscan", "scanner de portas em massa", True),
    (re.compile(r"zgrab", re.I), "ZGrab", "scanner de internet", True),
    (re.compile(r"\bhydra\b", re.I), "Hydra", "brute force de formulários de login", True),
    (re.compile(r"python-requests|python-urllib|aiohttp|httpx", re.I), "Script Python",
     "biblioteca HTTP do Python", False),
    (re.compile(r"Go-http-client", re.I), "Programa em Go", "cliente HTTP padrão do Go, comum em bots", False),
    (re.compile(r"^(?:curl|Wget)/", re.I), "curl / Wget", "ferramenta de linha de comando", False),
    (re.compile(r"Mozilla/5\.0", re.I), "Navegador", "user-agent de navegador (pode ser falsificado)", False),
]

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")


def _decode(text: str) -> str:
    """Desfaz \\x22 do nginx e a codificação de URL (duas vezes, para pegar %2527)."""
    text = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m[1], 16)), text)
    return unquote_plus(unquote_plus(text))


def parse_request_line(line: str) -> dict | None:
    """Transforma uma linha do access.log em requisição, ou None se não for desse formato."""
    m = ACCESS_RE.match(line)
    if not m:
        return None
    parts = m["request"].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", m["request"])
    return {
        "time": m["time"],
        "ip": m["ip"],
        "method": method,
        "path": path,
        "status": int(m["status"]),
        "size": 0 if m["size"] == "-" else int(m["size"]),
        "ua": _decode(m["ua"] or ""),
    }


def classify_request(req: dict) -> str | None:
    """Tipo de ataque da requisição ("sqli", "xss", ...) ou None."""
    decoded = _decode(req["path"])
    for kind, pattern in ATTACK_PATTERNS:
        if pattern.search(decoded) or (kind == "rce" and pattern.search(req["ua"])):
            return kind
    if SENSITIVE_RE.search(decoded.split("?", 1)[0]):
        return "sensitive"
    return None


def login_result(req: dict) -> str | None:
    """"fail", "success" ou None (não é tentativa de login)."""
    path = req["path"].split("?", 1)[0]
    if req["method"] != "POST" or not LOGIN_PATH_RE.match(path):
        return None
    status = req["status"]
    if path.lower().startswith("/api/"):
        return "success" if 200 <= status < 300 else "fail"
    return "success" if 300 <= status < 400 else "fail"


def detect_tool(ua: str) -> tuple[str, str, bool] | None:
    for pattern, tool, why, offensive in UA_TOOLS:
        if pattern.search(ua):
            return tool, why, offensive
    return None


def web_events_from_lines(lines: Iterable[str]) -> list[dict]:
    """Requisições na ordem do log, com o tipo de ataque e o resultado de login já marcados."""
    events = []
    for n, line in enumerate(lines, 1):
        req = parse_request_line(line)
        if req is None:
            continue
        req["n"] = n
        req["attack"] = classify_request(req)
        req["login"] = login_result(req)
        events.append(req)
    return events


def is_exposed(req: dict) -> bool:
    """Arquivo sensível que respondeu 2xx com conteúdo: vazou."""
    return req["attack"] == "sensitive" and 200 <= req["status"] < 300 and req["size"] > 0


def detect_login_compromise(events: list[dict], threshold: int) -> list[dict]:
    """Login aceito depois de >= limite falhas seguidas do mesmo IP (mesma regra do SSH)."""
    since_success = Counter()
    alerts = []
    for e in events:
        if e["login"] == "fail":
            since_success[e["ip"]] += 1
        elif e["login"] == "success":
            if since_success[e["ip"]] >= threshold:
                alerts.append({"ip": e["ip"], "path": e["path"], "failures": since_success[e["ip"]],
                               "time": e["time"], "n": e["n"]})
            since_success[e["ip"]] = 0
    return alerts


def build_web_report(lines: list[str], threshold: int = 5, top: int = 5) -> str:
    events = web_events_from_lines(lines)
    attacks = [e for e in events if e["attack"] or e["login"] == "fail"]
    out = [
        "=== RELATÓRIO DE ANÁLISE DE LOG (WEB) ===",
        f"Requisições: {len(events)}  |  Ataques: {len(attacks)}  |  IPs: {len({e['ip'] for e in events})}",
        "",
    ]

    critical = [f'   {e["ip"]:<15} {e["method"]} {e["path"]} respondeu {e["status"]} (arquivo sensível exposto)'
                for e in events if is_exposed(e)]
    critical += [f'   {a["ip"]:<15} login aceito em {a["path"]} depois de {a["failures"]} falhas ({a["time"]})'
                 for a in detect_login_compromise(events, threshold)]
    if critical:
        out.append("🚨 ALERTA: ataque com sucesso")
        out += critical
    else:
        out.append("✅ Nenhum ataque com sucesso confirmado")
    out.append("")

    by_type = defaultdict(set)
    count_type = Counter()
    for e in events:
        kind = e["attack"] or ("login" if e["login"] == "fail" else None)
        if kind:
            count_type[kind] += 1
            by_type[kind].add(e["ip"])
    out.append("⚠️  Ataques por tipo")
    labels = {**ATTACK_LABELS, "login": "Senha errada no login"}
    for kind, n in count_type.most_common():
        out.append(f"   {labels[kind]:<22} {n:>4}   ({', '.join(sorted(by_type[kind]))})")
    if not count_type:
        out.append("   nenhum")
    out.append("")

    not_found = Counter(e["ip"] for e in events if e["status"] == 404)
    scanners = [(ip, n) for ip, n in not_found.most_common() if n >= SCAN_404_THRESHOLD]
    if scanners:
        out.append(f"🔎 Varredura (>= {SCAN_404_THRESHOLD} respostas 404)")
        out += [f"   {ip:<15} {n:>4} x 404" for ip, n in scanners]
        out.append("")

    tools = {}
    for e in events:
        found = detect_tool(e["ua"])
        if found and found[2]:
            tools.setdefault(e["ip"], found[0])
    if tools:
        out.append("🛠️  Ferramentas de ataque (pelo user-agent)")
        out += [f"   {ip:<15} {tool}" for ip, tool in tools.items()]
        out.append("")

    paths = Counter(e["path"].split("?", 1)[0] for e in attacks)
    out.append("🎯 Caminhos mais atacados")
    for path, n in paths.most_common(top):
        out.append(f"   {path[:40]:<40} {n:>4}")
    if not paths:
        out.append("   nenhum")
    return "\n".join(out)
