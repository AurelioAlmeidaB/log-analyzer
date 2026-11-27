"""Testes do agente contra um servidor HTTP de mentira (só biblioteca padrão)."""

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import agent

VALID_KEY = "la_chave-de-teste"


class FakeServer(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        if self.path != "/api/ingest" or self.headers["Authorization"] != f"Bearer {VALID_KEY}":
            self.send_response(401)
            self.end_headers()
            return
        lines = body.splitlines()
        FakeServer.received.extend(lines)
        payload = json.dumps({"recebidas": len(lines)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class TestAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeServer.received = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.log = os.path.join(self.tmp.name, "auth.log")

    def write(self, text, mode="a"):
        with open(self.log, mode, encoding="utf-8") as f:
            f.write(text)

    def run_agent(self, *extra, key=VALID_KEY):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return agent.main(["--servidor", self.url, "--arquivo", self.log, "--chave", key, "--uma-vez", *extra])

    def test_sends_only_new_lines(self):
        self.write("linha 1\nlinha 2\n")
        self.assertEqual(self.run_agent(), 0)
        self.write("linha 3\n")
        self.assertEqual(self.run_agent(), 0)
        self.assertEqual(FakeServer.received, ["linha 1", "linha 2", "linha 3"])

    def test_waits_for_incomplete_line(self):
        self.write("completa\nmetade")
        self.run_agent()
        self.write(" final\n")
        self.run_agent()
        self.assertEqual(FakeServer.received, ["completa", "metade final"])

    def test_detects_rotation(self):
        self.write("antes da rotação, uma linha comprida\n")
        self.run_agent()
        os.rename(self.log, self.log + ".1")      # logrotate
        self.write("novo\n", mode="w")
        self.run_agent()
        self.assertEqual(FakeServer.received, ["antes da rotação, uma linha comprida", "novo"])

    def test_from_end_skips_existing_content(self):
        self.write("velha\n")
        self.run_agent("--do-fim")
        self.write("nova\n")
        self.run_agent()
        self.assertEqual(FakeServer.received, ["nova"])

    def test_invalid_key(self):
        self.write("x\n")
        self.assertEqual(self.run_agent(key="la_errada"), 2)
        self.assertEqual(FakeServer.received, [])

    def test_big_file_in_batches(self):
        self.write("".join(f"linha {i}\n" for i in range(12_000)))
        self.run_agent()
        self.assertEqual(len(FakeServer.received), 12_000)
        self.assertEqual(FakeServer.received[-1], "linha 11999")


if __name__ == "__main__":
    unittest.main()
