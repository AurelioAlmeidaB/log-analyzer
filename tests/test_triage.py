"""Testes da triagem de alertas (fila do analista SOC). Precisam do Flask."""

import unittest

try:
    import flask  # noqa: F401
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("Flask não instalado: pip install -r requirements.txt")

from tests.test_security import SecurityTestCase

FAILED = "Nov 23 03:00:{s:02d} web01 sshd[4001]: Failed password for root from 203.0.113.5 port 5{s:04d} ssh2"
ACCEPTED = "Nov 23 03:01:00 web01 sshd[4002]: Accepted password for root from 203.0.113.5 port 50999 ssh2"


class TriageTestCase(SecurityTestCase):
    def setUp(self):
        super().setUp()       # alice (admin) com a aplicação SSH e o sample_auth.log enviado
        self.analyst = self.new_client("carol@exemplo.com")
        self.accept(self.invite("carol@exemplo.com", "analyst"), self.analyst)
        self.analyst.get("/alertas")                 # sincroniza os alertas

    def alerts(self):
        return {(r["type"], r["ip"]): r for r in self.db().execute("SELECT * FROM alerts")}

    def alert_id(self, kind="ssh_compromise", ip="203.0.113.5"):
        return self.alerts()[(kind, ip)]["id"]

    def triage(self, alert_id, client=None, **form):
        return self.post(f"/alertas/{alert_id}", form, client=client or self.analyst)

    def status(self, alert_id):
        return self.db().execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]

    def send_attack_again(self):
        lines = "\n".join([FAILED.format(s=s) for s in range(6)] + [ACCEPTED])
        self.client.post("/api/ingest", data=lines, headers={"Authorization": f"Bearer {self.key}"})
        self.analyst.get("/alertas")


class TestAlertCreation(TriageTestCase):
    def test_one_alert_per_attack_and_ip(self):
        self.assertEqual(set(self.alerts()), {
            ("ssh_compromise", "203.0.113.5"),
            ("ssh_bruteforce", "203.0.113.5"), ("ssh_bruteforce", "198.51.100.7"),
            ("ssh_spraying", "203.0.113.5"), ("ssh_spraying", "198.51.100.7"),
            ("ssh_scan", "198.51.100.7"), ("ssh_scan", "203.0.113.88"),
        })
        self.assertTrue(all(a["status"] == "novo" for a in self.alerts().values()))

    def test_legit_user_has_no_alert(self):
        self.assertNotIn("192.0.2.10", {ip for _, ip in self.alerts()})

    def test_counts_and_evidence(self):
        brute = self.alerts()[("ssh_bruteforce", "203.0.113.5")]
        self.assertEqual(brute["occurrences"], 12)
        html = self.analyst.get(f"/alertas/{brute['id']}").get_data(as_text=True)
        self.assertIn("Failed password for root from 203.0.113.5", html)
        self.assertIn("/painel#L", html)                             # evidência leva à linha no painel

    def test_queue_sorted_by_severity(self):
        html = self.analyst.get("/alertas").get_data(as_text=True)
        self.assertLess(html.index("Login aceito depois de brute force"), html.index("Varredura da porta SSH"))

    def test_nav_shows_new_alert_count(self):
        self.assertIn('<span class="count" title="7 alertas novos">7</span>', self.analyst.get("/").get_data(as_text=True))

    def test_sending_more_lines_does_not_duplicate(self):
        self.upload(self.admin)
        self.analyst.get("/alertas")
        self.assertEqual(len(self.alerts()), 7)

    def test_dashboard_links_to_alerts(self):
        html = self.analyst.get(f"/apps/{self.app_id}/painel").get_data(as_text=True)
        self.assertIn(f'"href":"/alertas/{self.alert_id()}"', html)


class TestTriageFlow(TriageTestCase):
    def test_assume_puts_alert_in_analysis(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="assumir")
        row = self.db().execute("SELECT status, assignee_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        self.assertEqual(row["status"], "em_analise")
        self.assertEqual(row["assignee_id"], self.user_id("carol@exemplo.com"))

    def test_closing_requires_a_note(self):
        alert_id = self.alert_id()
        for status in ("resolvido", "falso_positivo"):
            self.triage(alert_id, action="atualizar", status=status, note="")
            self.assertEqual(self.status(alert_id), "novo")
        self.triage(alert_id, action="atualizar", status="resolvido", note="Senha do root trocada e IP bloqueado.")
        self.assertEqual(self.status(alert_id), "resolvido")

    def test_history_records_who_did_what(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="assumir")
        self.triage(alert_id, action="atualizar", status="em_analise", note="Vendo o bash_history.")
        self.triage(alert_id, action="atualizar", status="resolvido", note="Servidor reinstalado.")
        events = [(r["kind"], r["note"]) for r in self.db().execute(
            "SELECT kind, note FROM alert_events WHERE alert_id = ? ORDER BY id", (alert_id,))]
        self.assertEqual([k for k, _ in events], ["criado", "atribuido", "nota", "status"])
        self.assertEqual(events[-1][1], "Servidor reinstalado.")
        audit = self.admin.get("/atividade").get_data(as_text=True)
        self.assertIn("mudou o status do alerta", audit)
        self.assertIn("carol@exemplo.com", audit)

    def test_queue_filters(self):
        closed = self.alert_id("ssh_scan", "203.0.113.88")
        self.triage(closed, action="atualizar", status="falso_positivo", note="Scanner da nossa auditoria.")
        mine = self.alert_id()
        self.triage(mine, action="assumir")
        open_html = self.analyst.get("/alertas").get_data(as_text=True)
        self.assertNotIn(f"/alertas/{closed}\"", open_html)
        fp_html = self.analyst.get("/alertas?fila=falso_positivo").get_data(as_text=True)
        self.assertIn(f"/alertas/{closed}\"", fp_html)
        mine_html = self.analyst.get("/alertas?meus=1").get_data(as_text=True)
        self.assertIn(f"/alertas/{mine}\"", mine_html)
        self.assertNotIn(f"/alertas/{self.alert_id('ssh_bruteforce', '198.51.100.7')}\"", mine_html)

    def test_resolved_alert_reopens_when_attack_returns(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="atualizar", status="resolvido", note="Senha trocada.")
        self.send_attack_again()
        self.assertEqual(self.status(alert_id), "novo")
        kinds = [r[0] for r in self.db().execute("SELECT kind FROM alert_events WHERE alert_id = ?", (alert_id,))]
        self.assertEqual(kinds[-1], "reaberto")

    def test_false_positive_stays_closed(self):
        alert_id = self.alert_id("ssh_bruteforce", "203.0.113.5")
        self.triage(alert_id, action="atualizar", status="falso_positivo", note="IP do nosso teste de invasão.")
        before = self.alerts()[("ssh_bruteforce", "203.0.113.5")]["occurrences"]
        self.send_attack_again()
        row = self.alerts()[("ssh_bruteforce", "203.0.113.5")]
        self.assertEqual(row["status"], "falso_positivo")
        self.assertGreater(row["occurrences"], before)                # números continuam atualizados

    def test_resending_same_log_does_not_reopen_or_double_count(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="atualizar", status="resolvido", note="Senha trocada.")
        before = self.line_count()
        self.upload(self.admin)                                       # o mesmo sample_auth.log de novo
        self.analyst.get("/alertas")
        self.assertEqual(self.line_count(), before)
        self.assertEqual(self.status(alert_id), "resolvido")
        self.assertEqual(self.alerts()[("ssh_bruteforce", "203.0.113.5")]["occurrences"], 12)

    def test_release_only_by_assignee_or_admin(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="assumir", client=self.admin)
        other = self.new_client("dave@exemplo.com")
        self.accept(self.invite("dave@exemplo.com", "analyst"), other)
        self.assertEqual(self.triage(alert_id, client=other, action="liberar").status_code, 403)
        self.triage(alert_id, client=self.admin, action="liberar")
        self.assertIsNone(self.db().execute("SELECT assignee_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0])


class TestTriageSecurity(TriageTestCase):
    def test_other_org_cannot_see_or_triage(self):
        intruder = self.new_client("bob@exemplo.com")
        alert_id = self.alert_id()
        self.assertEqual(intruder.get(f"/alertas/{alert_id}").status_code, 404)
        self.assertEqual(self.triage(alert_id, client=intruder, action="assumir").status_code, 404)
        self.assertEqual(self.status(alert_id), "novo")
        self.assertNotIn("Login aceito depois de brute force", intruder.get("/alertas").get_data(as_text=True))

    def test_invalid_status_rejected(self):
        response = self.triage(self.alert_id(), action="atualizar", status="apagado", note="x")
        self.assertEqual(response.status_code, 400)

    def test_csrf_required(self):
        response = self.analyst.post(f"/alertas/{self.alert_id()}", data={"action": "assumir"})
        self.assertEqual(response.status_code, 400)

    def test_note_is_escaped(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="atualizar", status="em_analise", note="<script>alert(1)</script>")
        html = self.analyst.get(f"/alertas/{alert_id}").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_note_size_limit(self):
        alert_id = self.alert_id()
        self.triage(alert_id, action="atualizar", status="resolvido", note="x" * 2001)
        self.assertEqual(self.status(alert_id), "novo")

    def test_deleting_app_removes_its_alerts(self):
        self.post(f"/apps/{self.app_id}/excluir", {"confirm_name": "Servidor de teste"})
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
