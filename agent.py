#!/usr/bin/env python3
"""
agent.py - envia as linhas novas de um log para o Log Analyzer.

Roda no servidor que você quer monitorar. Só biblioteca padrão (Python 3.8+).

    export LA_CHAVE="la_..."    # chave da aplicação, mostrada uma vez no painel
    python3 agent.py --servidor https://seu-log-analyzer --arquivo /var/log/auth.log

- Guarda até onde já enviou (em ~/.local/state/log-analyzer-agent/), então pode
  parar e iniciar de novo sem duplicar nem perder linhas.
- Percebe rotação do log (logrotate) e recomeça do início do arquivo novo.
- Se o servidor cair, tenta de novo com espera crescente, sem perder linhas.

Prefira passar a chave pela variável LA_CHAVE: um argumento na linha de comando
aparece para outros usuários em `ps`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

BATCH_BYTES = 512 * 1024        # até ~512 KB por envio
MAX_LINES_PER_BATCH = 5_000     # o servidor aceita até 10 mil
USER_AGENT = "log-analyzer-agent/1.0"


class InvalidKey(Exception):
    pass


class RedirectRefused(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Não segue redirecionamentos: o urllib repassaria o cabeçalho Authorization,
    com a chave, para o endereço novo, mesmo que seja outro servidor."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def state_file(server: str, path: str) -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    ident = hashlib.sha256(f"{server}|{os.path.abspath(path)}".encode()).hexdigest()[:16]
    return os.path.join(base, "log-analyzer-agent", f"{ident}.json")


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, path)       # troca atômica: nunca fica meio escrito


def read_new_lines(log_path: str, state: dict) -> tuple[list[str], dict]:
    """Linhas completas depois do ponto salvo, e o novo ponto. Não avança em linha pela metade."""
    st = os.stat(log_path)
    offset = state.get("offset", 0)
    if state.get("inode") != st.st_ino or st.st_size < offset:
        offset = 0              # arquivo novo (rotação) ou truncado
    with open(log_path, "rb") as f:
        f.seek(offset)
        data = f.read(BATCH_BYTES)
    end = data.rfind(b"\n")
    if end == -1:
        return [], {"inode": st.st_ino, "offset": offset}
    raw = data[:end].split(b"\n")[:MAX_LINES_PER_BATCH]
    consumed = sum(len(line) + 1 for line in raw)
    lines = [line.decode("utf-8", errors="replace").rstrip("\r") for line in raw]
    return lines, {"inode": st.st_ino, "offset": offset + consumed}


def send(server: str, key: str, lines: list[str], timeout: float = 20) -> int:
    request = urllib.request.Request(
        server.rstrip("/") + "/api/ingest",
        data="\n".join(lines).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "text/plain; charset=utf-8",
                 "User-Agent": USER_AGENT},
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return json.load(response).get("recebidas", 0)
    except urllib.error.HTTPError as err:
        if err.code == 401:
            raise InvalidKey from err
        if 300 <= err.code < 400:
            raise RedirectRefused(err.headers.get("Location", "?")) from err
        raise


def run(server: str, key: str, log_path: str, interval: float, once: bool, from_end: bool) -> int:
    state_path = state_file(server, log_path)
    state = load_state(state_path)
    if not state and from_end:
        st = os.stat(log_path)
        state = {"inode": st.st_ino, "offset": st.st_size}
        save_state(state_path, state)
    backoff = interval
    while True:
        try:
            lines, new_state = read_new_lines(log_path, state)
            if lines:
                received = send(server, key, lines)
                noun = "linha enviada" if received == 1 else "linhas enviadas"
                print(f"{time.strftime('%H:%M:%S')}  {received} {noun}", flush=True)
            state = new_state
            save_state(state_path, state)
            backoff = interval
            if lines and not once:
                continue        # ainda pode ter mais: envia logo
            if once and not lines:
                return 0
            if once:
                continue
        except InvalidKey:
            print("Chave inválida. Confira LA_CHAVE ou gere uma nova chave no painel.", file=sys.stderr)
            return 2
        except RedirectRefused as err:
            print(f"O servidor pediu redirecionamento para {err}. Por segurança o agente não segue: "
                  "use o endereço final (com https://) em --servidor.", file=sys.stderr)
            return 2
        except FileNotFoundError:
            print(f"{log_path} não existe (rotação em andamento?). Tentando de novo.", file=sys.stderr)
        except PermissionError:
            print(f"Sem permissão para ler {log_path}. Para o auth.log: sudo usermod -aG adm $USER",
                  file=sys.stderr)
            return 1
        except (urllib.error.URLError, OSError, ValueError) as err:
            print(f"Falha ao enviar ({err}). Tentando de novo em {backoff:.0f} s.", file=sys.stderr)
            if once:
                return 1
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
            continue
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Envia as linhas novas de um log para o Log Analyzer.")
    parser.add_argument("--servidor", required=True, help="endereço do Log Analyzer, ex.: https://logs.exemplo.com")
    parser.add_argument("--arquivo", required=True, help="log a monitorar, ex.: /var/log/auth.log")
    parser.add_argument("--chave", help="chave da aplicação (prefira a variável LA_CHAVE)")
    parser.add_argument("--intervalo", type=float, default=5, help="segundos entre verificações (padrão: 5)")
    parser.add_argument("--uma-vez", action="store_true", help="envia o que houver de novo e sai")
    parser.add_argument("--do-fim", action="store_true",
                        help="na primeira execução, ignora o que já está no arquivo e envia só o que chegar depois")
    args = parser.parse_args(argv)

    key = args.chave or os.environ.get("LA_CHAVE", "")
    if not key:
        parser.error("informe a chave em LA_CHAVE (ou --chave)")
    parsed = urlparse(args.servidor)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        parser.error("--servidor precisa começar com http:// ou https://")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        print("Aviso: sem HTTPS, a chave e os logs viajam sem criptografia.", file=sys.stderr)

    try:
        return run(args.servidor, key, args.arquivo, args.intervalo, args.uma_vez, args.do_fim)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
