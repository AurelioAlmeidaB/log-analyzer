"""
Testes de segurança: isolamento entre organizações, papéis (administrador x analista
SOC), convites, sessões e as falhas encontradas na revisão. Precisam do Flask.
"""

import hashlib
import os
import re
import sqlite3
import stat
import time
import unittest
from urllib.parse import urlparse

try:
    import flask  # noqa: F401
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("Flask não instalado: pip install -r requirements.txt")

import dashboard
import web_log_analyzer as web
from webapp import create_app, totp
from webapp.db import SCHEMA_V1
from webapp.security import safe_next

from tests.test_webapp import PASSWORD, ROOT, WebAppTestCase


class SecurityTestCase(WebAppTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client
        self.signup("alice@exemplo.com", client=self.admin)
        self.app_id, self.key = self.new_app(client=self.admin)
        self.upload(self.admin)

    def upload(self, client):
        with open(os.path.join(ROOT, "sample_auth.log"), "rb") as f:
            return self.post(f"/apps/{self.app_id}/upload", {"logfile": (f, "auth.log")}, client=client,
                             content_type="multipart/form-data")

    def new_client(self, email):
        client = self.app.test_client()
        self.signup(email, client=client)
        return client

    def invite(self, email, role="analyst", client=None):
        html = self.post("/equipe/convites", {"email": email, "role": role}, client=client or self.admin)
        link = re.search(r'id="invite-link" class="key">([^<]+)<', html.get_data(as_text=True)).group(1)
        return urlparse(link).path

    def accept(self, path, client):
        client.get(path)
        return self.post(path, {}, client=client)

    def line_count(self):
        return self.db().execute("SELECT COUNT(*) FROM log_lines WHERE app_id = ?", (self.app_id,)).fetchone()[0]

    def ingest_status(self, key=None):
        return self.client.post("/api/ingest", data="x",
                                headers={"Authorization": f"Bearer {key or self.key}"}).status_code

    def user_id(self, email):
        return self.db().execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]

    def org_of(self, email):
        return self.db().execute("SELECT org_id FROM memberships m JOIN users ON users.id = m.user_id "
                                 "WHERE email = ? ORDER BY org_id LIMIT 1", (email,)).fetchone()[0]

    # O que um papel sem permissão tenta e não pode conseguir.
    def assert_cannot_change_app(self, client, expected_status):
        lines_before = self.line_count()
        with open(os.path.join(ROOT, "sample_auth.log"), "rb") as f:
            attempts = [
                self.post(f"/apps/{self.app_id}/upload", {"logfile": (f, "x.log")}, client=client,
                          content_type="multipart/form-data"),
                self.post(f"/apps/{self.app_id}/chave", client=client),
                self.post(f"/apps/{self.app_id}/limpar", client=client),
                self.post(f"/apps/{self.app_id}/excluir", {"confirm_name": "Servidor de teste"}, client=client),
            ]
        self.assertEqual([r.status_code for r in attempts], [expected_status] * 4)
        self.assertEqual(self.line_count(), lines_before)           # nada apagado nem enviado
        self.assertEqual(self.ingest_status(), 200)                   # a chave continua a mesma


class TestTenantIsolation(SecurityTestCase):
    """Usuário X não acessa nada do usuário Y."""

    def setUp(self):
        super().setUp()
        self.intruder = self.new_client("bob@exemplo.com")

    def test_other_org_gets_404_on_every_page(self):
        for url in (f"/apps/{self.app_id}", f"/apps/{self.app_id}/painel", f"/apps/{self.app_id}/relatorio.json"):
            self.assertEqual(self.intruder.get(url).status_code, 404, url)

    def test_other_org_cannot_change_anything(self):
        self.assert_cannot_change_app(self.intruder, 404)

    def test_app_list_only_shows_own_org(self):
        html = self.intruder.get("/").get_data(as_text=True)
        self.assertNotIn("Servidor de teste", html)
        self.assertIn("Nenhuma aplicação ainda", html)

    def test_cannot_switch_into_foreign_org(self):
        response = self.post("/organizacoes/trocar", {"org_id": self.org_of("alice@exemplo.com")}, client=self.intruder)
        self.assertEqual(response.status_code, 404)

    def test_cannot_touch_foreign_members(self):
        alice = self.user_id("alice@exemplo.com")
        for url in (f"/equipe/membros/{alice}/remover", f"/equipe/membros/{alice}/papel"):
            self.assertEqual(self.post(url, {"role": "analyst"}, client=self.intruder).status_code, 404)

    def test_foreign_invite_cannot_be_cancelled(self):
        self.invite("carol@exemplo.com")
        invite_id = self.db().execute("SELECT id FROM invitations").fetchone()[0]
        self.assertEqual(self.post(f"/equipe/convites/{invite_id}/cancelar", client=self.intruder).status_code, 404)

    def test_ingest_key_only_feeds_its_own_app(self):
        _, bob_key = self.new_app("App do Bob", client=self.intruder)
        before = self.line_count()
        self.intruder.post("/api/ingest", data="linha do bob", headers={"Authorization": f"Bearer {bob_key}"})
        self.assertEqual(self.line_count(), before)


class TestRoles(SecurityTestCase):
    """Administrador controla tudo; analista SOC só vê e exporta."""

    def setUp(self):
        super().setUp()
        self.analyst = self.new_client("carol@exemplo.com")
        self.accept(self.invite("carol@exemplo.com", "analyst"), self.analyst)

    def test_analyst_can_view_and_export(self):
        self.assertEqual(self.analyst.get(f"/apps/{self.app_id}").status_code, 200)
        self.assertIn("Um atacante conseguiu entrar",
                      self.analyst.get(f"/apps/{self.app_id}/painel").get_data(as_text=True))
        report = self.analyst.get(f"/apps/{self.app_id}/relatorio.json")
        self.assertEqual(report.get_json()["totals"]["events"], 23)
        self.assertNotIn("lines", report.get_json())

    def test_analyst_cannot_change_apps(self):
        self.assert_cannot_change_app(self.analyst, 403)

    def test_analyst_cannot_manage_team_or_see_audit(self):
        for url in ("/apps/nova", "/equipe", "/atividade"):
            self.assertEqual(self.analyst.get(url).status_code, 403, url)
        self.assertEqual(self.post("/equipe/convites", {"email": "x@exemplo.com", "role": "admin"},
                                   client=self.analyst).status_code, 403)
        alice = self.user_id("alice@exemplo.com")
        self.assertEqual(self.post(f"/equipe/membros/{alice}/papel", {"role": "analyst"},
                                   client=self.analyst).status_code, 403)

    def test_analyst_cannot_promote_self(self):
        carol = self.user_id("carol@exemplo.com")
        self.post(f"/equipe/membros/{carol}/papel", {"role": "admin"}, client=self.analyst)
        role = self.db().execute("SELECT role FROM memberships WHERE user_id = ? AND org_id = ?",
                                 (carol, self.org_of("alice@exemplo.com"))).fetchone()[0]
        self.assertEqual(role, "analyst")

    def test_analyst_does_not_see_admin_controls(self):
        html = self.analyst.get(f"/apps/{self.app_id}").get_data(as_text=True)
        for hidden in ("Gerar nova chave", "Enviar e analisar", "Excluir aplicação", "la_"):
            self.assertNotIn(hidden, html)
        nav = self.analyst.get("/").get_data(as_text=True)
        self.assertNotIn('href="/equipe"', nav)
        self.assertNotIn('href="/atividade"', nav)
        self.assertIn("Analista SOC", nav)

    def test_role_change_takes_effect_immediately(self):
        carol = self.user_id("carol@exemplo.com")
        self.post(f"/equipe/membros/{carol}/papel", {"role": "admin"})
        self.assertEqual(self.analyst.get("/equipe").status_code, 200)
        self.post(f"/equipe/membros/{carol}/papel", {"role": "analyst"})
        self.assertEqual(self.analyst.get("/equipe").status_code, 403)

    def test_removed_member_loses_access_immediately(self):
        self.post(f"/equipe/membros/{self.user_id('carol@exemplo.com')}/remover")
        self.assertEqual(self.analyst.get(f"/apps/{self.app_id}").status_code, 404)

    def test_last_admin_cannot_be_demoted_or_removed(self):
        alice = self.user_id("alice@exemplo.com")
        self.post(f"/equipe/membros/{alice}/papel", {"role": "analyst"})
        self.post(f"/equipe/membros/{alice}/remover")
        self.assertEqual(self.admin.get("/equipe").status_code, 200)     # continua administradora

    def test_admin_actions_are_audited(self):
        self.post(f"/apps/{self.app_id}/chave")
        html = self.admin.get("/atividade").get_data(as_text=True)
        for text in ("criou a aplicação", "convidou", "entrou na organização como", "gerou nova chave para"):
            self.assertIn(text, html)


class TestInvitations(SecurityTestCase):
    def test_invite_only_works_for_invited_email(self):
        path = self.invite("carol@exemplo.com")
        dave = self.new_client("dave@exemplo.com")
        response = self.accept(path, dave)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(dave.get(f"/apps/{self.app_id}").status_code, 404)

    def test_invite_is_single_use(self):
        path = self.invite("carol@exemplo.com")
        carol = self.new_client("carol@exemplo.com")
        self.accept(path, carol)
        again = carol.get(path)
        self.assertEqual(again.status_code, 400)
        self.assertIn("já foi usado", again.get_data(as_text=True))

    def test_expired_invite(self):
        path = self.invite("carol@exemplo.com")
        db = self.db()
        db.execute("UPDATE invitations SET expires_at = ?", (time.time() - 1,))
        db.commit()
        carol = self.new_client("carol@exemplo.com")
        self.assertEqual(self.accept(path, carol).status_code, 400)
        self.assertEqual(carol.get(f"/apps/{self.app_id}").status_code, 404)

    def test_cancelled_invite(self):
        path = self.invite("carol@exemplo.com")
        invite_id = self.db().execute("SELECT id FROM invitations").fetchone()[0]
        self.post(f"/equipe/convites/{invite_id}/cancelar")
        self.assertEqual(self.new_client("carol@exemplo.com").get(path).status_code, 404)

    def test_token_is_stored_only_as_hash(self):
        path = self.invite("carol@exemplo.com")
        token = path.rsplit("/", 1)[1]
        stored = self.db().execute("SELECT token_hash FROM invitations").fetchone()[0]
        self.assertEqual(stored, hashlib.sha256(token.encode()).hexdigest())

    def test_new_person_signs_up_from_invite_link(self):
        path = self.invite("erin@exemplo.com")
        erin = self.app.test_client()
        response = erin.get(path)
        self.assertIn("/entrar?next=", response.location)
        self.post("/cadastro", {"email": "erin@exemplo.com", "password": PASSWORD, "confirm": PASSWORD,
                                "next": path}, client=erin)
        erin.get("/2fa/configurar")
        html = self.post("/2fa/configurar", {"code": self.code("erin@exemplo.com")}, client=erin).get_data(as_text=True)
        self.assertIn(f'href="{path}"', html)                          # "continuar" leva ao convite
        self.accept(path, erin)
        self.assertEqual(erin.get(f"/apps/{self.app_id}").status_code, 200)


class TestSessions(SecurityTestCase):
    def test_logout_revokes_copied_cookie(self):
        cookie = self.admin.get_cookie("la_session").value
        self.logout()
        thief = self.app.test_client()
        thief.set_cookie("la_session", cookie)
        self.assertEqual(thief.get("/").status_code, 302)

    def test_password_change_ends_other_sessions(self):
        other = self.app.test_client()
        self.login("alice@exemplo.com", client=other, code_offset=1)
        self.assertEqual(other.get("/").status_code, 200)
        new = "outra frase longa e boa"
        self.post("/conta/senha", {"current": PASSWORD, "new": new, "confirm": new})
        self.assertEqual(other.get("/").status_code, 302)
        self.assertEqual(self.admin.get("/").status_code, 200)        # quem trocou continua dentro

    def test_end_other_sessions(self):
        other = self.app.test_client()
        self.login("alice@exemplo.com", client=other, code_offset=1)
        self.post("/conta/sessoes/encerrar")
        self.assertEqual(other.get("/").status_code, 302)
        self.assertEqual(self.admin.get("/").status_code, 200)

    def test_idle_session_expires(self):
        db = self.db()
        db.execute("UPDATE user_sessions SET last_seen = ?", (time.time() - 3 * 3600,))
        db.commit()
        response = self.admin.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("Sua sessão terminou", self.admin.get(response.location).get_data(as_text=True))

    def test_account_lists_sessions(self):
        self.assertIn("esta sessão", self.admin.get("/conta").get_data(as_text=True))


class TestHardening(SecurityTestCase):
    def test_open_redirect_variants(self):
        for bad in ("//evil.example", "/\\evil.example", "/\\/evil.example", "https://evil.example",
                    "/\t/evil.example", "javascript:alert(1)"):
            self.assertIsNone(safe_next(bad), repr(bad))
        self.assertEqual(safe_next("/apps/1?x=2"), "/apps/1?x=2")

    def test_open_redirect_end_to_end(self):
        self.logout()
        self.post("/entrar", {"email": "alice@exemplo.com", "password": PASSWORD, "next": "/\\evil.example"})
        response = self.post("/entrar/codigo", {"code": self.code("alice@exemplo.com", 1)})
        self.assertNotIn("evil", response.location)

    def test_signup_cannot_be_used_to_enumerate_emails(self):
        probe = self.app.test_client()
        statuses = [self.post("/cadastro", {"email": "alice@exemplo.com", "password": PASSWORD,
                                            "confirm": PASSWORD}, client=probe).status_code for _ in range(12)]
        self.assertIn(429, statuses)

    def test_recovery_codes_are_peppered(self):
        codes = self.signup("frank@exemplo.com", client=self.app.test_client())
        stored = {r[0] for r in self.db().execute(
            "SELECT code_hash FROM recovery_codes JOIN users ON users.id = user_id WHERE email = 'frank@exemplo.com'")}
        self.assertNotIn(totp.legacy_hash_recovery_code(codes[0]), stored)
        self.assertIn(totp.hash_recovery_code(codes[0], "teste"), stored)

    def test_legacy_recovery_code_still_works_once(self):
        db = self.db()
        uid = self.user_id("alice@exemplo.com")
        db.execute("INSERT INTO recovery_codes (user_id, code_hash, scheme) VALUES (?, ?, 'sha256')",
                   (uid, totp.legacy_hash_recovery_code("abcde-fghjk")))
        db.commit()
        self.logout()
        for expected in (302, 200):
            self.post("/entrar", {"email": "alice@exemplo.com", "password": PASSWORD})
            self.assertEqual(self.post("/entrar/codigo", {"code": "abcde-fghjk"}).status_code, expected)
            self.logout()

    def test_database_file_is_private(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.db_path).st_mode), 0o600)

    def test_reset_authenticator_requires_password(self):
        response = self.post("/conta/2fa", {"password": "senha errada demais"})
        self.assertIn("Senha incorreta", self.admin.get(response.location).get_data(as_text=True))
        old_secret = self.secret_for("alice@exemplo.com")
        self.post("/conta/2fa", {"password": PASSWORD})
        new_secret = self.db().execute("SELECT totp_pending FROM users WHERE email = 'alice@exemplo.com'").fetchone()[0]
        self.post("/conta/2fa/configurar", {"code": totp.code_at(new_secret, totp.current_step())})
        stored = self.db().execute("SELECT totp_secret FROM users WHERE email = 'alice@exemplo.com'").fetchone()[0]
        self.assertEqual(stored, new_secret)
        self.assertNotEqual(stored, old_secret)

    def test_regexes_resist_redos(self):
        # "union/**/ /**/ ..." levava mais de 10 s antes da correção.
        hostile = [
            "/p?q=union" + "/**/ " * 13_000,
            "/p?q=union" + "/*" * 32_000,
            "/p?q=<img" + " " * 64_000,
            "/p?q='" + " or " * 16_000,
        ]
        for path in hostile:
            start = time.perf_counter()
            web.classify_request({"path": path, "ua": path})
            self.assertLess(time.perf_counter() - start, 0.5, path[:20])
        start = time.perf_counter()
        dashboard.SOFTWARE_RE.search("remote software version x" + " " * 64_000 + "y")
        self.assertLess(time.perf_counter() - start, 0.5)


class TestMigration(unittest.TestCase):
    def test_v1_database_is_upgraded_without_losing_data(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "antigo.db")
        old = sqlite3.connect(path)
        old.executescript(SCHEMA_V1)
        old.execute("INSERT INTO users (id, email, password_hash, totp_secret) VALUES (7, 'ana@exemplo.com', 'x', 'S')")
        old.execute("INSERT INTO apps (user_id, name, kind, api_key_hash, api_key_hint) "
                    "VALUES (7, 'Antiga', 'ssh', 'h', 'la_…')")
        old.commit()
        old.close()

        create_app({"TESTING": True, "DATABASE": path, "SECRET_KEY": "x"})
        db = sqlite3.connect(path)
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
        org_id, role = db.execute("SELECT org_id, role FROM memberships WHERE user_id = 7").fetchone()
        self.assertEqual(role, "admin")
        self.assertEqual(db.execute("SELECT org_id FROM apps WHERE name = 'Antiga'").fetchone()[0], org_id)
        self.assertEqual(db.execute("SELECT name FROM orgs").fetchone()[0], "Organização de ana")


if __name__ == "__main__":
    unittest.main()
