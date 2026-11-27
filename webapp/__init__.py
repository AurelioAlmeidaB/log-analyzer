"""
Aplicação web do Log Analyzer: contas com senha + 2FA, aplicações monitoradas,
envio de logs (agente ou upload) e o painel de ataques de cada aplicação.

Rodar em desenvolvimento, na pasta do projeto:
    flask --app webapp run

Variáveis de ambiente (todas opcionais):
    LA_SECRET_KEY     chave das sessões (sem ela, uma é gerada em instance/secret_key)
    LA_DATABASE       caminho do banco SQLite (padrão: instance/log_analyzer.db)
    LA_HTTPS=1        marque quando estiver atrás de HTTPS: cookie Secure + HSTS
    LA_BEHIND_PROXY=1 atrás de nginx/proxy: confia em X-Forwarded-For para o IP real
    LA_ALLOW_SIGNUP=0 fecha o cadastro de novas contas
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta


def _load_or_create_secret(instance_path: str) -> str:
    path = os.path.join(instance_path, "secret_key")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key)
        return key


def create_app(config: dict | None = None) -> Flask:
    from flask import Flask, render_template   # aqui dentro: o analisador e os testes rodam sem Flask

    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, mode=0o700, exist_ok=True)

    app.config.update(
        DATABASE=os.environ.get("LA_DATABASE", os.path.join(app.instance_path, "log_analyzer.db")),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,           # upload de até 10 MB
        SESSION_COOKIE_NAME="la_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("LA_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        ALLOW_SIGNUP=os.environ.get("LA_ALLOW_SIGNUP", "1") == "1",
    )
    if config:
        app.config.update(config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = os.environ.get("LA_SECRET_KEY") or _load_or_create_secret(app.instance_path)

    if os.environ.get("LA_BEHIND_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from . import alerts, auth, db, monitor, security, team

    db.init_app(app)
    security.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(monitor.bp)
    app.register_blueprint(team.bp)
    app.register_blueprint(alerts.bp)
    app.jinja_env.filters["ago"] = monitor.time_ago
    app.jinja_env.filters["ago_epoch"] = monitor.epoch_ago

    @app.errorhandler(403)
    def forbidden(_):
        from flask import g

        role = security.ROLE_LABELS.get(g.get("role"), "")
        return render_template(
            "error.html", title="Sem permissão",
            message=(f"Seu papel nesta organização ({role}) não permite esta ação. "
                     "Peça a um administrador." if role else "Você não tem permissão para esta ação.")), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", title="Página não encontrada",
                               message="O endereço não existe ou você não tem acesso a ele."), 404

    @app.errorhandler(400)
    def bad_request(err):
        return render_template("error.html", title="Pedido inválido",
                               message=getattr(err, "description", "") or "Recarregue a página e tente de novo."), 400

    @app.errorhandler(413)
    def too_large(_):
        return render_template("error.html", title="Arquivo grande demais",
                               message="O limite de upload é 10 MB. Para logs maiores, use o agente."), 413

    return app
