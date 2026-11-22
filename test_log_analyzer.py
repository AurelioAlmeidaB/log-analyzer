"""Testes do analisador. Rodar com:  python -m unittest -v"""

import os
import tempfile
import unittest

import dashboard
from log_analyzer import (
    build_report,
    count_failures_by_ip,
    count_failures_by_user,
    detect_bruteforce,
    detect_success_after_failures,
    load_events,
    parse_line,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample_auth.log")


def ev(ip, status, user="root", time="Nov 22 00:00:00"):
    return {"time": time, "user": user, "ip": ip, "status": status}


def write_temp_log(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


# --- Passo 1: parse_line --------------------------------------------------------


class TestParseLine(unittest.TestCase):
    def test_failed_password(self):
        line = "Nov 22 02:47:10 web01 sshd[2108]: Failed password for root from 203.0.113.5 port 40124 ssh2"
        self.assertEqual(parse_line(line), {
            "time": "Nov 22 02:47:10", "user": "root", "ip": "203.0.113.5", "status": "failed",
        })

    def test_failed_invalid_user(self):
        line = "Nov 22 02:47:02 web01 sshd[2101]: Failed password for invalid user admin from 203.0.113.5 port 40110 ssh2"
        event = parse_line(line)
        self.assertEqual(event["user"], "admin")  # "invalid user" não vira parte do nome
        self.assertEqual(event["status"], "failed")

    def test_accepted_password(self):
        line = "Nov 22 02:47:16 web01 sshd[2110]: Accepted password for root from 203.0.113.5 port 40128 ssh2"
        event = parse_line(line)
        self.assertEqual(event["status"], "accepted")
        self.assertEqual(event["ip"], "203.0.113.5")

    def test_irrelevant_line_returns_none(self):
        self.assertIsNone(parse_line("Nov 22 08:00:01 web01 CRON[3120]: pam_unix(cron:session): session closed for user root"))
        self.assertIsNone(parse_line("Nov 22 02:47:01 web01 sshd[2101]: Invalid user admin from 203.0.113.5 port 40110"))
        self.assertIsNone(parse_line(""))

    def test_iso_timestamp_and_sshd_session(self):
        line = ("2026-11-22T02:47:10.123456-03:00 web01 sshd-session[2108]: "
                "Failed password for root from 203.0.113.5 port 40124 ssh2")
        event = parse_line(line)
        self.assertEqual(event["time"], "2026-11-22T02:47:10.123456-03:00")
        self.assertEqual(event["user"], "root")

    def test_ipv6(self):
        line = "Nov 22 02:47:10 web01 sshd[1]: Failed password for root from 2001:db8::5 port 40124 ssh2"
        self.assertEqual(parse_line(line)["ip"], "2001:db8::5")


# --- Passo 2: load_events -------------------------------------------------------


class TestLoadEvents(unittest.TestCase):
    def test_sample_counts(self):
        events = load_events(SAMPLE)
        self.assertEqual(len(events), 23)
        self.assertEqual(sum(e["status"] == "failed" for e in events), 21)

    def test_keeps_file_order(self):
        events = load_events(SAMPLE)
        self.assertEqual(events[0]["user"], "admin")
        self.assertEqual(events[-1]["user"], "git")

    def test_message_repeated_counts_each_attempt(self):
        path = write_temp_log(
            "Nov 22 01:00:00 web01 sshd[9]: Failed password for root from 198.51.100.9 port 1 ssh2\n"
            "Nov 22 01:00:05 web01 sshd[9]: message repeated 4 times: "
            "[ Failed password for root from 198.51.100.9 port 1 ssh2]\n"
        )
        self.addCleanup(os.remove, path)
        self.assertEqual(len(load_events(path)), 5)


# --- Passo 3: contagens ---------------------------------------------------------


class TestCounts(unittest.TestCase):
    def test_failures_by_ip(self):
        counts = count_failures_by_ip(load_events(SAMPLE))
        self.assertEqual(counts["203.0.113.5"], 12)
        self.assertEqual(counts["198.51.100.7"], 7)
        self.assertEqual(counts["192.0.2.10"], 2)

    def test_failures_by_user(self):
        counts = count_failures_by_user(load_events(SAMPLE))
        self.assertEqual(counts.most_common(2), [("root", 5), ("admin", 2)])

    def test_accepted_is_not_a_failure(self):
        events = [ev("1.1.1.1", "failed"), ev("1.1.1.1", "accepted")]
        self.assertEqual(count_failures_by_ip(events)["1.1.1.1"], 1)


# --- Passo 4: detecções ---------------------------------------------------------


class TestDetections(unittest.TestCase):
    def test_bruteforce_on_sample(self):
        suspects = detect_bruteforce(count_failures_by_ip(load_events(SAMPLE)))
        self.assertEqual(suspects, [("203.0.113.5", 12), ("198.51.100.7", 7)])

    def test_bruteforce_threshold_is_inclusive(self):
        events = [ev("1.1.1.1", "failed")] * 5 + [ev("2.2.2.2", "failed")] * 4
        self.assertEqual(detect_bruteforce(count_failures_by_ip(events), threshold=5), [("1.1.1.1", 5)])

    def test_success_after_failures_on_sample(self):
        alerts = detect_success_after_failures(load_events(SAMPLE))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "203.0.113.5")
        self.assertEqual(alerts[0]["user"], "root")
        self.assertEqual(alerts[0]["failures"], 12)

    def test_legit_user_with_typos_is_not_flagged(self):
        alerts = detect_success_after_failures(load_events(SAMPLE))
        self.assertNotIn("192.0.2.10", [a["ip"] for a in alerts])

    def test_order_matters(self):
        # Sucesso ANTES das falhas não é invasão: só a leitura em ordem percebe isso.
        success_first = [ev("1.1.1.1", "accepted")] + [ev("1.1.1.1", "failed")] * 6
        self.assertEqual(detect_success_after_failures(success_first), [])
        success_last = [ev("1.1.1.1", "failed")] * 6 + [ev("1.1.1.1", "accepted")]
        self.assertEqual(len(detect_success_after_failures(success_last)), 1)

    def test_failures_from_other_ip_do_not_count(self):
        events = [ev("1.1.1.1", "failed")] * 6 + [ev("2.2.2.2", "accepted")]
        self.assertEqual(detect_success_after_failures(events), [])


# --- Passo 5: relatório ---------------------------------------------------------


class TestReport(unittest.TestCase):
    def test_report_on_sample(self):
        report = build_report(load_events(SAMPLE))
        self.assertIn("Eventos de login: 23  |  Falhas: 21", report)
        self.assertIn('203.0.113.5  (12 falhas, depois sucesso como "root"', report)
        self.assertIn("198.51.100.7", report)
        self.assertNotIn("192.0.2.10", report)

    def test_report_without_events(self):
        report = build_report([])
        self.assertIn("Nenhum login aceito após falhas", report)
        self.assertIn("nenhum IP atingiu o limite", report)


# --- Dashboard ------------------------------------------------------------------


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = dashboard.analyze(SAMPLE)
        cls.by_ip = {a["ip"]: a for a in cls.data["attackers"]}

    def test_agrees_with_terminal_report(self):
        self.assertEqual(self.data["totals"]["events"], 23)
        self.assertEqual(self.data["totals"]["failed"], 21)
        self.assertEqual([a["ip"] for a in self.data["alerts"]], ["203.0.113.5"])

    def test_risk_levels(self):
        self.assertEqual(self.by_ip["203.0.113.5"]["risk"], "critico")
        self.assertEqual(self.by_ip["198.51.100.7"]["risk"], "alto")
        self.assertEqual(self.by_ip["203.0.113.88"]["risk"], "medio")
        self.assertEqual(self.by_ip["192.0.2.10"]["risk"], "baixo")

    def test_tools_from_client_banner(self):
        self.assertIn("Hydra", self.by_ip["203.0.113.5"]["tool"])
        self.assertIn("Go", self.by_ip["198.51.100.7"]["tool"])
        self.assertIn("Nmap", self.by_ip["203.0.113.88"]["tool"])

    def test_pace(self):
        self.assertTrue(self.by_ip["203.0.113.5"]["machine_pace"])
        self.assertFalse(self.by_ip["192.0.2.10"]["machine_pace"])

    def test_techniques(self):
        techniques = {t["id"]: t["ips"] for t in self.data["techniques"]}
        self.assertEqual(techniques["T1078"], ["203.0.113.5"])
        self.assertIn("198.51.100.7", techniques["T1110.003"])
        self.assertIn("203.0.113.88", techniques["T1046"])

    def test_target_port(self):
        self.assertEqual(self.data["targets"][0]["dst"], "10.0.0.5")
        self.assertEqual(self.data["targets"][0]["port"], "22")

    def test_accounts_exist_or_not(self):
        accounts = {a["user"]: a for a in self.data["accounts"]}
        self.assertTrue(accounts["root"]["exists"])
        self.assertTrue(accounts["root"]["compromised"])
        self.assertFalse(accounts["admin"]["exists"])

    def test_html_escapes_attacker_controlled_text(self):
        # O nome de usuário vem do atacante e não pode virar código no dashboard.
        path = write_temp_log(
            "Nov 22 01:00:00 web01 sshd[9]: Failed password for invalid user "
            "</script><script>alert(1)</script> from 198.51.100.9 port 1 ssh2\n"
        )
        self.addCleanup(os.remove, path)
        html = dashboard.render_html(dashboard.analyze(path))
        self.assertNotIn("<script>alert(1)", html)
        self.assertEqual(html.count("</script>"), 2)  # só os dois blocos do próprio template


if __name__ == "__main__":
    unittest.main()
