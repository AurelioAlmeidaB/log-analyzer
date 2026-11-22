# Log Analyzer: detector de brute force em logs SSH

Lê um `auth.log` de servidor Linux e responde três perguntas:

1. Alguém está tentando adivinhar senhas? (brute force)
2. Quais contas estão sendo atacadas?
3. **Algum atacante conseguiu entrar?** (a pergunta mais importante)

Python puro, sem bibliotecas externas. Gera um relatório no terminal e, se você quiser, um dashboard HTML que abre offline.

**[▶ Ver o dashboard ao vivo](https://aurelioalmeidab.github.io/log-analyzer/dashboard.html)** (gerado a partir do `sample_auth.log`)

## O que é brute force

É tentar senhas em sequência, geralmente com uma ferramenta automática, até acertar uma.

## Por que "sucesso após falhas" é o alerta que importa

Falhas de login acontecem o tempo todo: bots varrem a internet inteira testando `root/123456`. Elas mostram que você **está sendo atacado**. Um login **aceito** vindo do mesmo IP *depois* de dezenas de falhas mostra que o ataque **deu certo**: a senha foi descoberta e alguém está dentro do servidor.

Para isso o log é lido **na ordem**. Uma contagem simples não diz se o sucesso veio antes das falhas (usuário legítimo) ou depois (invasão).

## Relatório no terminal

```
$ python log_analyzer.py sample_auth.log
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

## Dashboard

```
python log_analyzer.py sample_auth.log --html dashboard.html
```

Abra o `dashboard.html` no navegador, ou veja a [versão publicada](https://aurelioalmeidab.github.io/log-analyzer/dashboard.html) do log de exemplo. Ele mostra:

| Seção | O que mostra |
|---|---|
| Veredito | Se algum atacante entrou, como e quando |
| Origem dos ataques | Cada IP com risco, falhas, contas tentadas, ferramenta provável e ritmo das tentativas |
| Alvo | Host e porta atacados, contas que existem e contas inexistentes (vindas de wordlists), sessões abertas pelo atacante |
| Contas mais atacadas | Falhas por conta, marcando as comprometidas e as que nem existem |
| Ferramentas e técnicas | Ferramenta provável (Hydra, Nmap, bot em Go...) e técnicas MITRE ATT&CK, cada uma com as linhas do log que servem de evidência |
| Sequência por IP | Os eventos de cada IP em ordem, com o limite de falhas marcado: mostra visualmente por que a ordem importa |
| Log completo | Todas as linhas, com filtro por tipo e por IP e busca; clicar em qualquer evidência leva à linha |

<!-- Coloque aqui um print do dashboard: docs/dashboard.png -->

### Como a ferramenta é identificada

| Sinal no log | Conclusão |
|---|---|
| Banner `libssh_*` | Hydra (o módulo SSH do Hydra usa a libssh) |
| Banner `libssh2_*` | Medusa ou Nmap `ssh-brute` |
| Banner `Go` | Bot ou scanner escrito em Go (comum em botnets) |
| Banner `Nmap-SSH2-*` | Scripts NSE do Nmap |
| Banner `paramiko` / `AsyncSSH` | Script em Python |
| Intervalo mediano ≤ 3 s entre tentativas | Ferramenta automática (ninguém digita tão rápido) |
| Conexão que sai sem handshake (`kex_exchange_identification`, `banner exchange`) | Varredura de portas |

É uma **heurística**: o atacante pode trocar o banner. O banner só aparece com `LogLevel DEBUG1` no `/etc/ssh/sshd_config`, e a porta de destino com `LogLevel VERBOSE`. Sem isso, o dashboard funciona com o que tiver (ritmo e contagens).

### Técnicas MITRE ATT&CK

| ID | Técnica | Quando é marcada |
|---|---|---|
| T1046 | Varredura de serviço | Conexões sem handshake SSH |
| T1110.001 | Adivinhação de senha | ≥ 3 falhas na mesma conta |
| T1110.003 | Password spraying | ≥ 3 contas diferentes tentadas |
| T1078 | Uso de conta válida | Login aceito depois do limite de falhas |

## Regras de detecção

| Regra | Lógica | Severidade |
|---|---|---|
| Brute force | IP com falhas ≥ limite (padrão 5) | média |
| Sucesso após falhas | IP que atingiu o limite e **depois** teve login aceito | crítica |
| Contas visadas | contagem de falhas por usuário | informativa |

## Como rodar

Requer Python 3.8 ou mais novo.

```
python log_analyzer.py sample_auth.log
python log_analyzer.py sample_auth.log --html dashboard.html
python log_analyzer.py /var/log/auth.log          # no seu servidor (precisa de sudo)
```

Formatos aceitos: data clássica do syslog (`Nov 22 02:47:03`) e RFC 3339 (`2026-11-22T02:47:03.123456-03:00`, padrão do Ubuntu 24.04), processo `sshd` ou `sshd-session` (OpenSSH 9.8+), IPv4 e IPv6, e as linhas agrupadas pelo rsyslog (`message repeated N times`).

## Como testar

```
python -m unittest -v
```

28 testes cobrindo regex, leitura, contagens, detecções, relatório e dashboard, incluindo:

- `test_order_matters`: sucesso **antes** das falhas não gera alerta
- `test_legit_user_with_typos_is_not_flagged`: usuário que errou a senha duas vezes não é suspeito
- `test_html_escapes_attacker_controlled_text`: o nome de usuário vem do atacante, então um usuário chamado `</script><script>...` não pode executar código no dashboard

## O log de exemplo

`sample_auth.log` tem quatro cenários, todos com IPs de documentação (RFC 5737), que não pertencem a ninguém:

| IP | Cenário | Resultado esperado |
|---|---|---|
| 203.0.113.5 | Hydra: 12 falhas e depois entra como `root` | **crítico** |
| 198.51.100.7 | Bot em Go: varre a porta e tenta 7 contas | alto (brute force) |
| 203.0.113.88 | Nmap: só varredura | médio |
| 192.0.2.10 | `maria` erra a senha duas vezes e entra | baixo, não é suspeito |

## Estrutura

```
log_analyzer.py          parse_line → load_events → contagens → detecções → relatório
dashboard.py             análise extra (conexões, banners, varreduras) e geração do HTML
dashboard_template.html  HTML/CSS/JS do dashboard, sem dependências
sample_auth.log          log de exemplo
test_log_analyzer.py     testes (unittest)
```

## Próximos passos

- **v2:** falhas em janela de tempo (5 em 1 minuto é mais grave que 5 em um dia); `--threshold` e `--json`; logs de nginx/Apache (sequências de 404, `/wp-login.php`, `../`, `' OR 1=1`)
- **v3:** mandar só o resumo agregado (não o log cru) para um LLM explicar o incidente e sugerir a severidade

## Aviso

Use apenas em logs seus ou de laboratório.
