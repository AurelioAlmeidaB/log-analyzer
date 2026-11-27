"""
remediation.py - o que fazer para corrigir cada tipo de ataque detectado.

Cada entrada tem: título, severidade, por que importa, passos e, quando
ajuda, comandos/configuração prontos para copiar. O dashboard mostra só as
entradas dos ataques que aparecem no log analisado.
"""

SEVERITY_ORDER = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}

REMEDIATION = {
    # --- SSH ---------------------------------------------------------------------
    "ssh_compromise": {
        "title": "Login aceito depois de brute force",
        "severity": "critico",
        "why": "A senha foi descoberta: trate como invasão até provar o contrário.",
        "steps": [
            "Isole o servidor da rede (ou bloqueie o IP no firewall) antes de investigar.",
            "Troque a senha da conta atacada e remova chaves desconhecidas de ~/.ssh/authorized_keys.",
            "Veja o que foi feito: comandos, usuários novos, cron, processos e conexões abertas.",
            "Se não der para confiar no que encontrou, reinstale a partir de um backup limpo.",
            "Depois aplique as correções de brute force abaixo para não acontecer de novo.",
        ],
        "commands": [
            "last -i | head -20                # quem entrou e de onde",
            "sudo cat /root/.bash_history     # comandos do root",
            "sudo crontab -l; ls /etc/cron.*  # tarefas agendadas novas",
            "sudo ss -tunap                   # conexões abertas agora",
            "awk -F: '$3 >= 1000' /etc/passwd # contas de usuário",
        ],
    },
    "ssh_bruteforce": {
        "title": "Brute force no SSH",
        "severity": "alto",
        "why": "Alguém está tentando adivinhar senhas; basta uma senha fraca para entrar.",
        "steps": [
            "Use só chaves SSH e desative o login por senha.",
            "Proíba o login direto como root.",
            "Instale o fail2ban para bloquear IPs depois de algumas falhas.",
            "Se possível, libere a porta 22 só para a sua rede ou VPN.",
        ],
        "commands": [
            "# /etc/ssh/sshd_config",
            "PasswordAuthentication no",
            "PermitRootLogin no",
            "MaxAuthTries 3",
            "sudo systemctl reload ssh",
            "sudo apt install fail2ban         # a jail do sshd já vem ativa no Ubuntu",
            "sudo ufw allow from 192.168.0.0/24 to any port 22",
        ],
    },
    "ssh_spraying": {
        "title": "Várias contas testadas (lista de usuários)",
        "severity": "medio",
        "why": "Contas que nem existem mostram uma lista pronta: o atacante procura qualquer conta fraca.",
        "steps": [
            "Restrinja quem pode entrar por SSH com AllowUsers ou AllowGroups.",
            "Não use nomes óbvios (admin, test, guest, oracle) para contas reais.",
            "O fail2ban também bloqueia esse padrão.",
        ],
        "commands": [
            "# /etc/ssh/sshd_config",
            "AllowUsers maria deploy",
        ],
    },
    "ssh_scan": {
        "title": "Varredura da porta SSH",
        "severity": "baixo",
        "why": "Robôs varrem a internet o tempo todo; é reconhecimento, não invasão.",
        "steps": [
            "Mantenha o OpenSSH atualizado.",
            "Esconda o SSH atrás de uma VPN ou libere só IPs conhecidos.",
            "Trocar a porta 22 reduz o ruído no log, mas não é proteção de verdade.",
        ],
        "commands": [
            "sudo apt update && sudo apt upgrade openssh-server",
        ],
    },
    # --- Web ---------------------------------------------------------------------
    "web_sensitive_exposed": {
        "title": "Arquivo sensível exposto",
        "severity": "critico",
        "why": "O servidor respondeu 200 para um arquivo como .env ou .git: segredos podem ter vazado.",
        "steps": [
            "Tire o arquivo da pasta pública agora.",
            "Considere vazados todos os segredos dele: troque senhas do banco, chaves de API e tokens.",
            "Bloqueie arquivos ocultos e de backup no servidor web.",
            "Confira no log quem mais baixou o arquivo.",
        ],
        "commands": [
            "# nginx: dentro do bloco server",
            "location ~ /\\.(?!well-known) { deny all; }",
            "location ~* \\.(bak|old|sql|swp|zip|tar\\.gz)$ { deny all; }",
            "curl -I https://seu-site/.env     # precisa responder 403 ou 404",
        ],
    },
    "web_login_compromise": {
        "title": "Login aceito depois de brute force no site",
        "severity": "critico",
        "why": "A conta foi acessada depois de várias senhas erradas: provável senha descoberta.",
        "steps": [
            "Troque a senha da conta e encerre todas as sessões abertas.",
            "Ative 2FA para os usuários, começando pelos administradores.",
            "Revise o que a conta fez depois do login.",
        ],
        "commands": [],
    },
    "web_rce": {
        "title": "Tentativa de execução de comandos (RCE)",
        "severity": "alto",
        "why": "O atacante tenta rodar comandos no servidor (injeção de comando, Log4Shell, Shellshock).",
        "steps": [
            "Nunca passe entrada do usuário para o shell; use listas de argumentos sem shell=True.",
            "Atualize bibliotecas e o servidor (Log4j 2.17.1+, bash corrigido).",
            "Rode a aplicação com um usuário sem privilégios e sem saída livre para a internet.",
            "Se alguma dessas requisições teve resposta 200, investigue o servidor.",
        ],
        "commands": [
            "subprocess.run([\"ping\", \"-c\", \"1\", host])   # e não os.system(f\"ping {host}\")",
        ],
    },
    "web_sqli": {
        "title": "Tentativa de SQL injection",
        "severity": "alto",
        "why": "Se a consulta for montada com texto do usuário, o atacante lê ou apaga o banco.",
        "steps": [
            "Use consultas parametrizadas (ou um ORM) em todo acesso ao banco.",
            "Dê ao usuário do banco só as permissões que a aplicação precisa.",
            "Um WAF (ModSecurity + OWASP CRS) ajuda como camada extra, não como correção.",
            "Respostas 200 com tamanho fora do normal podem indicar vazamento: confira.",
        ],
        "commands": [
            "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))   # certo",
            "cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")       # vulnerável",
        ],
    },
    "web_traversal": {
        "title": "Tentativa de path traversal (../)",
        "severity": "alto",
        "why": "O atacante tenta ler arquivos fora da pasta do site, como /etc/passwd.",
        "steps": [
            "Não monte caminhos de arquivo com texto do usuário; use uma lista de arquivos permitidos.",
            "Se precisar, normalize o caminho e confira que ele continua dentro da pasta permitida.",
            "Rode a aplicação com um usuário que não consegue ler arquivos do sistema.",
        ],
        "commands": [
            "path = (BASE / nome).resolve()",
            "if not path.is_relative_to(BASE): abort(404)",
        ],
    },
    "web_xss": {
        "title": "Tentativa de XSS",
        "severity": "medio",
        "why": "Se a página devolver o texto sem escapar, o script roda no navegador das vítimas.",
        "steps": [
            "Escape toda saída (templates com autoescape, como Jinja2 e React, já fazem isso).",
            "Adicione um Content-Security-Policy que bloqueie scripts inline.",
            "Marque os cookies de sessão como HttpOnly.",
        ],
        "commands": [
            "Content-Security-Policy: default-src 'self'; script-src 'self'",
        ],
    },
    "web_login_bruteforce": {
        "title": "Brute force no login do site",
        "severity": "alto",
        "why": "Muitas senhas erradas seguidas no formulário de login.",
        "steps": [
            "Limite tentativas por conta e por IP, com bloqueio temporário.",
            "Ofereça 2FA e incentive senhas longas.",
            "No WordPress, desative o xmlrpc.php se não usa.",
            "fail2ban também funciona com o log do nginx.",
        ],
        "commands": [
            "# nginx: até 5 tentativas por minuto por IP no login",
            "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;",
            "location = /wp-login.php { limit_req zone=login burst=5; ... }",
        ],
    },
    "web_sensitive_probe": {
        "title": "Procura por arquivos sensíveis",
        "severity": "medio",
        "why": "Robôs testam .env, .git e backups em todo site; nenhum respondeu 200 aqui.",
        "steps": [
            "Garanta que .env, .git e backups nunca fiquem na pasta pública.",
            "Bloqueie arquivos ocultos no servidor web (veja o bloco de nginx acima).",
        ],
        "commands": [
            "location ~ /\\.(?!well-known) { deny all; }",
        ],
    },
    "web_scanning": {
        "title": "Varredura do site",
        "severity": "baixo",
        "why": "Muitos 404 seguidos ou ferramenta de varredura: o atacante mapeia o site.",
        "steps": [
            "Mantenha o site, plugins e o servidor web atualizados.",
            "Remova páginas de exemplo, painéis e instaladores que não usa.",
            "O filtro nginx-botsearch do fail2ban bloqueia quem gera muitos 404.",
        ],
        "commands": [],
    },
}


def finding(kind: str, ips: list[str], count: int, evidence: list[int]) -> dict:
    """Junta a recomendação com o que foi encontrado no log."""
    info = REMEDIATION[kind]
    return {
        "type": kind,
        "title": info["title"],
        "severity": info["severity"],
        "why": info["why"],
        "steps": info["steps"],
        "commands": info["commands"],
        "ips": ips,
        "count": count,
        "evidence": sorted(set(evidence))[:8],
    }


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["count"]))
