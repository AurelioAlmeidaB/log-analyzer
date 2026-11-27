"""Testes da aplicação web: login com 2FA, proteções e monitoramento. Precisam do Flask."""

import io
import os
import re
import sqlite3
import tempfile
import unittest

try:
    import flask  # noqa: F401
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("Flask não instalado: pip install -r requirements.txt")

from webapp import create_app, totp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "uma frase longa e boa"


class WebAppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.app = create_app({"TESTING": True, "DATABASE": self.db_path, "SECRET_KEY": "teste"})
        self.client = self.app.test_client()

    # --- ajudantes ---------------------------------------------------------------

    def csrf(self, client=None):
        """Token CSRF da sessão; abre uma página com formulário se ainda não existir."""
        client = client or self.client
        for page in (None, "/entrar", "/"):   # /entrar redireciona quem já está dentro
            if page:
                client.get(page)
            with client.session_transaction() as s:
                if "csrf" in s:
                    return s["csrf"]
        raise AssertionError("sem token CSRF")

    def post(self, url, data=None, client=None, **kwargs):
        client = client or self.client
        data = dict(data or {})
        data.setdefault("csrf_token", self.csrf(client))
        return client.post(url, data=data, **kwargs)

    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def secret_for(self, email):
        row = self.db().execute("SELECT totp_secret, totp_pending FROM users WHERE email = ?", (email,)).fetchone()
        return row["totp_secret"] or row["totp_pending"]

    def code(self, email, offset=0):
        return totp.code_at(self.secret_for(email), totp.current_step() + offset)

    def signup(self, email="maria@exemplo.com", client=None):
        """Cadastro completo com 2FA. Devolve os códigos de recuperação."""
        client = client or self.client
        response = self.post("/cadastro", {"email": email, "password": PASSWORD, "confirm": PASSWORD}, client=client)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/2fa/configurar"))
        client.get("/2fa/configurar")
        response = self.post("/2fa/configurar", {"code": self.code(email)}, client=client)
        self.assertEqual(response.status_code, 200)
        return re.findall(r"<li>([a-z2-9]{5}-[a-z2-9]{5})</li>", response.get_data(as_text=True))

    def login(self, email="maria@exemplo.com", password=PASSWORD, code_offset=1, client=None):
        client = client or self.client
        response = self.post("/entrar", {"email": email, "password": password}, client=client)
        if response.status_code != 302 or not response.location.endswith("/entrar/codigo"):
            return response
        return self.post("/entrar/codigo", {"code": self.code(email, code_offset)}, client=client)

    def logout(self, client=None):
        self.post("/sair", client=client)

    def new_app(self, name="Servidor de teste", kind="ssh", client=None):
        response = self.post("/apps/nova", {"name": name, "kind": kind, "threshold": "5"}, client=client)
        html = response.get_data(as_text=True)
        key = re.search(r'id="api-key" class="key">(la_[\w-]+)<', html).group(1)
        app_id = int(re.search(r"/apps/(\d+)/painel|/apps/(\d+)/upload", html).group(0).split("/")[2])
        return app_id, key


class TestSignupAndLogin(WebAppTestCase):
    def test_full_signup_shows_recovery_codes_and_logs_in(self):
        codes = self.signup()
        self.assertEqual(len(codes), 8)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_pages_require_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/entrar", response.location)

    def test_login_needs_password_and_code(self):
        self.signup()
        self.logout()
        response = self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD})
        self.assertTrue(response.location.endswith("/entrar/codigo"))
        self.assertEqual(self.client.get("/").status_code, 302)          # só a senha não basta
        response = self.post("/entrar/codigo", {"code": self.code("maria@exemplo.com", 1)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_wrong_password_has_generic_message(self):
        self.signup()
        self.logout()
        for email in ("maria@exemplo.com", "ninguem@exemplo.com"):
            html = self.post("/entrar", {"email": email, "password": "senha errada demais"}).get_data(as_text=True)
            self.assertIn("E-mail ou senha incorretos.", html)

    def test_totp_code_cannot_be_reused(self):
        self.signup()
        self.logout()
        self.assertEqual(self.login(code_offset=1).status_code, 302)
        self.logout()
        response = self.login(code_offset=1)                              # mesmo código de novo
        self.assertIn("Código incorreto ou já usado.", response.get_data(as_text=True))

    def test_recovery_code_works_once(self):
        codes = self.signup()
        self.logout()
        for expected in (302, 200):
            self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD})
            response = self.post("/entrar/codigo", {"code": codes[0]})
            self.assertEqual(response.status_code, expected)
            self.logout()

    def test_brute_force_on_login_is_blocked(self):
        self.signup()
        self.logout()
        for _ in range(5):
            self.post("/entrar", {"email": "maria@exemplo.com", "password": "senha errada demais"})
        response = self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD})
        self.assertEqual(response.status_code, 429)                       # nem a senha certa passa agora

    def test_brute_force_on_2fa_code_is_blocked(self):
        self.signup()
        self.logout()
        self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD})
        for _ in range(5):
            self.post("/entrar/codigo", {"code": "000000"})
        response = self.post("/entrar/codigo", {"code": self.code("maria@exemplo.com", 1)})
        self.assertEqual(response.status_code, 429)

    def test_weak_password_rejected(self):
        for password in ("curta", "1234567890", "maria@exemplo.com"):
            html = self.post("/cadastro", {"email": "maria@exemplo.com", "password": password,
                                            "confirm": password}).get_data(as_text=True)
            self.assertIn('class="alert error', html, password)

    def test_duplicate_email(self):
        self.signup()
        self.logout()
        html = self.post("/cadastro", {"email": "MARIA@exemplo.com", "password": PASSWORD,
                                        "confirm": PASSWORD}).get_data(as_text=True)
        self.assertIn("Já existe uma conta", html)

    def test_password_is_hashed(self):
        self.signup()
        stored = self.db().execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(stored.startswith("scrypt:"))
        self.assertNotIn(PASSWORD, stored)

    def test_open_redirect_is_ignored(self):
        self.signup()
        self.logout()
        self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD, "next": "//malicioso.example"})
        response = self.post("/entrar/codigo", {"code": self.code("maria@exemplo.com", 1)})
        self.assertNotIn("malicioso", response.location)

    def test_change_password(self):
        self.signup()
        new = "outra frase longa e boa"
        self.post("/conta/senha", {"current": PASSWORD, "new": new, "confirm": new})
        self.logout()
        self.assertEqual(self.post("/entrar", {"email": "maria@exemplo.com", "password": PASSWORD}).status_code, 200)
        response = self.post("/entrar", {"email": "maria@exemplo.com", "password": new})
        self.assertTrue(response.location.endswith("/entrar/codigo"))


class TestProtections(WebAppTestCase):
    def test_csrf_required(self):
        response = self.client.post("/entrar", data={"email": "a@b.co", "password": "x"})
        self.assertEqual(response.status_code, 400)

    def test_security_headers(self):
        response = self.client.get("/entrar")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_session_cookie_flags(self):
        self.signup()
        cookie = next(c for c in self.client._cookies.values() if c.key == "la_session")
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "Lax")


class TestMonitoring(WebAppTestCase):
    def setUp(self):
        super().setUp()
        self.signup()

    def test_create_app_shows_key_once(self):
        app_id, key = self.new_app()
        self.assertTrue(key.startswith("la_"))
        self.assertNotIn(key, self.client.get(f"/apps/{app_id}").get_data(as_text=True))
        stored = self.db().execute("SELECT api_key_hash FROM apps").fetchone()[0]
        self.assertNotIn(key, stored)

    def test_upload_and_dashboard(self):
        app_id, _ = self.new_app()
        with open(os.path.join(ROOT, "sample_auth.log"), "rb") as f:
            response = self.post(f"/apps/{app_id}/upload", {"logfile": (f, "auth.log")},
                                 content_type="multipart/form-data")
        self.assertTrue(response.location.endswith(f"/apps/{app_id}/painel"))
        page = self.client.get(f"/apps/{app_id}/painel")
        html = page.get_data(as_text=True)
        self.assertIn("Um atacante conseguiu entrar", html)
        nonce = re.search(r"'nonce-([\w-]+)'", page.headers["Content-Security-Policy"]).group(1)
        self.assertIn(f'<script nonce="{nonce}">', html)

    def test_agent_ingest_api(self):
        app_id, key = self.new_app(kind="web")
        with open(os.path.join(ROOT, "sample_access.log"), encoding="utf-8") as f:
            body = f.read()
        response = self.client.post("/api/ingest", data=body, headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(response.get_json(), {"recebidas": 63})
        html = self.client.get(f"/apps/{app_id}/painel").get_data(as_text=True)
        self.assertIn("Arquivo sensível exposto", html)

    def test_ingest_rejects_bad_key(self):
        self.new_app()
        for headers in ({}, {"Authorization": "Bearer la_errada"}, {"Authorization": "la_sem_bearer"}):
            self.assertEqual(self.client.post("/api/ingest", data="x", headers=headers).status_code, 401)

    def test_rotated_key_stops_old_one(self):
        app_id, old = self.new_app()
        html = self.post(f"/apps/{app_id}/chave").get_data(as_text=True)
        new = re.search(r'id="api-key" class="key">(la_[\w-]+)<', html).group(1)
        auth = lambda k: {"Authorization": f"Bearer {k}"}  # noqa: E731
        self.assertEqual(self.client.post("/api/ingest", data="x", headers=auth(old)).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest", data="x", headers=auth(new)).status_code, 200)

    def test_other_user_cannot_see_app(self):
        app_id, _ = self.new_app()
        other = self.app.test_client()
        self.signup("joao@exemplo.com", client=other)
        for url in (f"/apps/{app_id}", f"/apps/{app_id}/painel"):
            self.assertEqual(other.get(url).status_code, 404)
        response = self.post(f"/apps/{app_id}/excluir", {"confirm_name": "Servidor de teste"}, client=other)
        self.assertEqual(response.status_code, 404)

    def test_app_name_is_escaped(self):
        app_id, _ = self.new_app(name="<script>alert(1)</script>")
        html = self.client.get(f"/apps/{app_id}").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_delete_requires_typing_the_name(self):
        app_id, _ = self.new_app()
        self.post(f"/apps/{app_id}/excluir", {"confirm_name": "outro nome"})
        self.assertEqual(self.client.get(f"/apps/{app_id}").status_code, 200)
        self.post(f"/apps/{app_id}/excluir", {"confirm_name": "Servidor de teste"})
        self.assertEqual(self.client.get(f"/apps/{app_id}").status_code, 404)

    def test_agent_script_download(self):
        response = self.client.get("/agent.py")
        self.assertIn(b"log-analyzer-agent", response.data)


if __name__ == "__main__":
    unittest.main()
