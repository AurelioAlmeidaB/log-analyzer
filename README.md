# Log Analyzer: detector de ataques em logs SSH e web

Lê logs de servidores Linux e de sites e responde:

1. Alguém está tentando invadir? (brute force, SQL injection, varreduras...)
2. O que está sendo atacado? (contas, páginas, arquivos)
3. **Algum atacante conseguiu entrar?** (a pergunta mais importante)
4. Como corrigir cada problema encontrado.

Funciona de dois jeitos:

- **Linha de comando**, em Python puro: relatório no terminal e um dashboard HTML que abre offline.
- **Aplicação web**, com login seguro (senha + 2FA): cada pessoa cadastra suas aplicações, um agente envia os logs e o painel mostra os ataques em tempo quase real.

**Dashboards de exemplo:** [▶ servidor SSH](https://aurelioalmeidab.github.io/log-analyzer/dashboard.html) · [▶ site com nginx](https://aurelioalmeidab.github.io/log-analyzer/dashboard_web.html)

## O que detecta

**SSH (`/var/log/auth.log`)**

| Ataque | Como reconhece | Severidade |
|---|---|---|
| Login aceito depois de brute force | login aceito depois de ≥ 5 falhas **seguidas** do mesmo IP | crítica |
| Brute force | IP com ≥ 5 falhas | alta |
| Várias contas testadas | ≥ 3 usuários diferentes, inclusive inexistentes | média |
| Varredura da porta 22 | conexões que fecham sem handshake SSH | baixa |

**Web (`access.log` do nginx ou Apache)**

| Ataque | Como reconhece | Severidade |
|---|---|---|
| Arquivo sensível exposto | `.env`, `.git`, backups etc. com resposta 200 | crítica |
| Login aceito depois de brute force | POST no login com sucesso depois de ≥ 5 falhas seguidas | crítica |
| Execução de comando (RCE) | `;cat`, `$(id)`, Log4Shell (`${jndi:`), Shellshock | alta |
| SQL injection | `' OR 1=1`, `UNION SELECT`, `SLEEP(5)`... | alta |
| Path traversal | `../`, `/etc/passwd` | alta |
| XSS | `<script`, `onerror=`, `javascript:` | média |
| Varredura | ≥ 20 respostas 404 ou ferramenta de varredura | baixa |

Para cada ataque encontrado, o painel mostra **como corrigir**: passos em ordem e configurações prontas para copiar (sshd, fail2ban, nginx, código seguro).

### Ferramenta usada pelo atacante

| Sinal | Ferramenta provável |
|---|---|
| Banner SSH `libssh_*` | Hydra |
| Banner SSH `libssh2_*` | Medusa ou Nmap `ssh-brute` |
| Banner SSH `Go` | bot ou scanner escrito em Go |
| Banner SSH `Nmap-SSH2-*` | Nmap |
| User-agent `sqlmap`, `Nikto`, `gobuster`, `WPScan`, `Nuclei`, `(Hydra)`... | a própria ferramenta |
| Intervalo mediano ≤ 3 s entre tentativas | ferramenta automática |

É uma **heurística**: banner e user-agent podem ser falsificados. No SSH, o banner só aparece com `LogLevel DEBUG1` e a porta de destino com `LogLevel VERBOSE` no `sshd_config`.

Cada IP também recebe as técnicas do **MITRE ATT&CK** correspondentes (T1110 brute force, T1190 exploração de aplicação, T1595 varredura, T1078 conta válida, T1552 credenciais em arquivos), com as linhas do log que servem de evidência.

## Por que "login depois de falhas" é o alerta que importa

Falhas de login acontecem o tempo todo: robôs varrem a internet testando `root/123456`. Elas mostram que você **está sendo atacado**. Um login **aceito** vindo do mesmo IP *logo depois* de várias falhas mostra que o ataque **deu certo**.

Por isso o log é lido **na ordem**, e o contador de falhas **zera a cada login aceito**. Sem isso, uma pessoa que erra a senha duas vezes por dia viraria "atacante" no terceiro dia de um log longo.

## Linha de comando

Só precisa de Python 3.8 ou mais novo; nada para instalar.

```
python log_analyzer.py sample_auth.log                     # SSH
python log_analyzer.py sample_access.log                   # web: o formato é detectado sozinho
python log_analyzer.py sample_auth.log --html dashboard.html
python log_analyzer.py /var/log/auth.log --limite 10 --json
```

```
=== RELATÓRIO DE ANÁLISE DE LOG ===
Eventos de login: 23  |  Falhas: 21

🚨 ALERTA: login aceito após falhas
   203.0.113.5  (12 falhas, depois sucesso como "root" em Nov 22 02:47:16)

⚠️  Possível brute force (>= 5 falhas)
   203.0.113.5      12 falhas
   198.51.100.7      7 falhas

🎯 Contas mais atacadas
   root         5
   admin        2
   maria        2
   test         1
   oracle       1
   ... (+10 contas)
```

Aceita data clássica do syslog e RFC 3339 (Ubuntu 24.04), `sshd` e `sshd-session` (OpenSSH 9.8+), IPv4 e IPv6, linhas agrupadas pelo rsyslog (`message repeated N times`) e o formato *combined* do nginx/Apache.

## Aplicação web

### Rodar na sua máquina

```
python3 -m venv .venv                 # no Ubuntu: sudo apt install python3-venv
.venv/bin/pip install -r requirements.txt
.venv/bin/flask --app webapp run
```

Abra http://127.0.0.1:5000, crie a conta e siga os passos.

### Login

1. **Cadastro** com e-mail e senha (mínimo de 10 caracteres; senhas óbvias são recusadas).
2. **2FA obrigatório**: escaneie o QR code com Google Authenticator, Microsoft Authenticator, Authy, 1Password ou Bitwarden e digite o código.
3. **8 códigos de recuperação** para quem perder o celular, cada um vale uma vez.
4. Nos próximos acessos: e-mail e senha, depois o código de 6 dígitos.

### Equipes e papéis

Cada conta nasce com a sua organização. As aplicações pertencem à organização, e quem é de outra organização não vê nem descobre que elas existem (a resposta é 404).

| Ação | Administrador | Analista SOC |
|---|:---:|:---:|
| Ver aplicações, painéis e logs | ✓ | ✓ |
| Baixar o relatório em JSON | ✓ | ✓ |
| Triar alertas: assumir, mudar status, escrever notas | ✓ | ✓ |
| Enviar arquivo de log | ✓ | |
| Criar e excluir aplicações, ver e trocar chaves, apagar logs | ✓ | |
| Convidar pessoas, mudar papéis, remover membros | ✓ | |
| Ver o registro de atividade (quem fez o quê) | ✓ | |

- O administrador convida pelo e-mail e recebe um **link de uso único**, válido por 7 dias e só para aquele e-mail.
- Mudar o papel ou remover alguém vale **na hora**, sem esperar a pessoa sair.
- A organização sempre tem pelo menos um administrador.
- Quem participa de mais de uma organização troca entre elas no topo da página.

### Triagem de alertas (o trabalho do analista SOC)

Cada tipo de ataque vindo de um IP vira um **alerta**, como "Brute force no SSH, 203.0.113.5". A página **Alertas** é a fila de trabalho:

1. **Novo**: o alerta acabou de aparecer; o menu mostra quantos há.
2. **Em análise**: alguém clicou em *Assumir* e virou o responsável.
3. **Resolvido** ou **Falso positivo**: fechar exige uma nota dizendo o que foi visto e feito.

- Cada alerta mostra as linhas do log que servem de evidência (com link para a linha no painel), o passo a passo de como corrigir e o histórico completo: quem assumiu, quem mudou o status e as notas.
- **Reabre sozinho:** um alerta resolvido volta para *Novo* se o ataque acontecer de novo depois da decisão. Um falso positivo continua fechado.
- Filas por status, filtros por gravidade e aplicação, e "só os meus".
- No painel de ataques, cada IP mostra o status da triagem e leva ao alerta.
- Reenviar o mesmo arquivo de log não duplica linhas nem reabre alertas.

### Monitorar uma aplicação

1. Em **Nova aplicação**, escolha *Servidor Linux (SSH)* ou *Site ou API (nginx/Apache)*.
2. Copie a chave (ela aparece uma vez).
3. **Para testar:** envie um arquivo de log pela página.
4. **Para monitorar sempre:** rode o agente no servidor:

```
curl -fsSO https://seu-log-analyzer/agent.py
export LA_CHAVE="la_..."
python3 agent.py --servidor https://seu-log-analyzer --arquivo /var/log/auth.log
```

O agente usa só a biblioteca padrão, envia as linhas novas a cada 5 segundos, continua de onde parou depois de reiniciar, percebe rotação de log e tenta de novo se o servidor cair.

### Segurança implementada

| Proteção | Como |
|---|---|
| Senhas | hash scrypt (Werkzeug); nunca guardadas em texto |
| 2FA | TOTP (RFC 6238) com janela de ±30 s; o mesmo código não serve duas vezes; trocar de celular pede a senha |
| Códigos de recuperação | uso único, guardados com HMAC e a chave do servidor: quem copia só o banco não consegue testá-los |
| Brute force no próprio login | 5 senhas erradas por conta ou 20 por IP em 15 min bloqueiam; o mesmo para o código 2FA |
| Enumeração de contas | mesma mensagem e mesmo tempo de resposta no login; o cadastro tem limite de tentativas por IP |
| Sessões | guardadas no servidor: sair, trocar a senha ou "encerrar as outras" revoga de verdade; terminam após 2 h sem uso ou 12 h no total; lista de sessões abertas na conta |
| Cookie | HttpOnly, SameSite=Lax, Secure com HTTPS; sessão nova a cada login |
| CSRF | token em todo formulário |
| XSS | escape automático nos templates; CSP com nonce, sem `unsafe-inline`; o texto do log nunca vira HTML |
| Clickjacking e outros | `frame-ancestors 'none'`, `X-Frame-Options`, `nosniff`, HSTS com HTTPS |
| Isolamento entre organizações | toda consulta junta a aplicação com a participação da pessoa; papel conferido no servidor em cada ação |
| Chaves de API e convites | gerados com `secrets`, guardados só como hash, mostrados uma vez |
| Redirecionamento aberto | `?next=` só aceita caminhos do próprio site, inclusive contra `/\site.com` |
| Arquivo do banco | permissão 600: outros usuários da máquina não leem |
| ReDoS | nenhuma regex tem repetição ambígua; linhas de 64 KB são analisadas em milissegundos |
| Agente | não segue redirecionamentos, para não entregar a chave a outro servidor |

### Revisão de segurança

Falhas encontradas testando a própria aplicação, todas corrigidas e com teste em `tests/test_security.py`:

| Gravidade | Falha | Correção |
|---|---|---|
| Alta | ReDoS: uma requisição com `union/**/ /**/ ...` no endereço travava a análise por mais de 10 s | padrão de comentário SQL sem ambiguidade |
| Alta | o agente repassava a chave de API ao seguir um redirecionamento 301/302/303 para outro servidor | o agente recusa redirecionamentos |
| Média | sair da conta não invalidava o cookie: uma cópia dele continuava valendo por 8 h | sessões guardadas e revogadas no servidor |
| Média | trocar a senha não derrubava sessões abertas em outros navegadores | troca de senha encerra todas as outras |
| Média | `?next=/\site.com` redirecionava para outro site depois do login | validação recusa barra invertida |
| Média | o limite do cadastro só contava cadastros que deram certo, permitindo testar e-mails sem limite | toda tentativa conta |
| Média | códigos de recuperação com SHA-256 puro (~49 bits) podiam ser quebrados a partir de uma cópia do banco | HMAC com a chave do servidor |
| Baixa | banco criado com permissão 644 (legível por outros usuários da máquina) | permissão 600 |
| Baixa | regex do banner SSH com custo quadrático | padrão linear |

### Colocar no ar

`flask run` é só para desenvolvimento. Em produção use HTTPS e um servidor WSGI:

```
pip install gunicorn
LA_HTTPS=1 LA_BEHIND_PROXY=1 LA_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  gunicorn -w 2 -b 127.0.0.1:8000 "webapp:create_app()"
```

Com o nginx na frente fazendo o HTTPS (Let's Encrypt). `LA_ALLOW_SIGNUP=0` fecha o cadastro depois de criar sua conta. O GitHub Pages só hospeda os dashboards estáticos; a aplicação precisa de um servidor (uma VPS, Render, Railway, Fly.io...).

## Como testar

```
python -m unittest -v                  # analisador, agente e 2FA (sem dependências)
.venv/bin/python -m unittest -v        # inclui os testes da aplicação web
```

158 testes, entre eles:

- `test_order_matters` e `test_counter_resets_after_success`: a ordem do log e o contador que zera
- `test_legit_user_is_not_flagged_after_many_days`: a usuária que erra a senha não vira atacante num log longo
- `test_rfc6238_vectors`: o 2FA bate com os vetores oficiais do RFC 6238
- `TestTenantIsolation`: alguém de outra organização recebe 404 em todas as páginas e ações
- `TestRoles`: o analista SOC vê e exporta, mas recebe 403 em tudo que muda algo; mudança de papel vale na hora
- `TestSessions`: cookie copiado não vale depois de sair; trocar a senha derruba os outros navegadores
- `test_resolved_alert_reopens_when_attack_returns` e `test_false_positive_stays_closed`: o ciclo de vida da triagem
- `test_regexes_resist_redos`: linhas hostis de 64 KB são analisadas em menos de 0,5 s
- `test_html_escapes_attacker_controlled_text`: um usuário chamado `</script><script>...` no log não executa código no painel

## Logs de exemplo

Todos com IPs de documentação (RFC 5737), que não pertencem a ninguém.

`sample_auth.log` (SSH):

| IP | Cenário | Resultado |
|---|---|---|
| 203.0.113.5 | Hydra: 12 falhas e entra como `root` | **crítico** |
| 198.51.100.7 | bot em Go: varre a porta e tenta 7 contas | alto |
| 203.0.113.88 | Nmap: só varredura | médio |
| 192.0.2.10 | `maria` erra a senha duas vezes e entra | baixo |

`sample_access.log` (nginx):

| IP | Cenário | Resultado |
|---|---|---|
| 198.51.100.23 | Nikto acha o `.env` exposto | **crítico** |
| 203.0.113.50 | Hydra no `/wp-login.php`: 8 erros e entra | **crítico** |
| 203.0.113.9 | sqlmap com 10 payloads de SQL injection | alto |
| 203.0.113.200 | Log4Shell e Shellshock no user-agent | alto |
| 198.51.100.77 | Gobuster: 24 páginas inexistentes | médio |
| 192.0.2.44 | visitante normal | baixo |

## Estrutura

```
log_analyzer.py          CLI e regras do SSH: parse_line → eventos → contagens → detecções → relatório
web_log_analyzer.py      regras do nginx/Apache: assinaturas de ataque, login, ferramenta pelo user-agent
remediation.py           como corrigir cada tipo de ataque
dashboard.py             monta os dados do painel (SSH e web) e gera o HTML
dashboard_template.html  o painel: HTML/CSS/JS sem dependências
agent.py                 agente que envia o log para a aplicação web
webapp/                  aplicação web (Flask + SQLite)
  auth.py                contas, 2FA, códigos de recuperação, sessões
  team.py                organizações, convites, papéis, registro de atividade
  alerts.py              triagem: fila de alertas, status, responsável, notas e histórico
  analysis.py            análise das linhas guardadas, resumo e sincronização dos alertas
  monitor.py             aplicações, upload, API do agente, painel e relatório
  security.py            CSRF, CSP, limites de tentativa, sessões, permissões
  db.py                  esquema e migrações
tests/                   testes (unittest)
```

## Próximos passos

- Falhas em janela de tempo (5 falhas em 1 minuto é mais grave que 5 em um dia)
- Alertas por e-mail ou Telegram quando aparecer um ataque crítico
- Recuperação de senha por e-mail, verificação do e-mail no cadastro e convite enviado por e-mail
- Comentários com menção (@pessoa) e prazo (SLA) por gravidade na triagem
- Análise em segundo plano para logs grandes (hoje o painel refaz a análise a cada abertura)
- Passkeys (WebAuthn) como alternativa ao código de 6 dígitos
- Mandar só o resumo agregado (não o log cru) para um LLM explicar o incidente em português

## Aviso

Use apenas em logs seus ou de laboratório.
