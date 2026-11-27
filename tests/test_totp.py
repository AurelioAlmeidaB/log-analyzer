"""Testes do 2FA (TOTP) com os vetores oficiais do RFC 6238. Rodam sem Flask."""

import base64
import unittest

from webapp import totp

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


class TestTotp(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # Tabela do apêndice B do RFC 6238 (SHA-1, 8 dígitos).
        for unix_time, expected in [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"),
                                    (2000000000, "69279037"), (20000000000, "65353130")]:
            self.assertEqual(totp.code_at(RFC_SECRET, unix_time // 30, digits=8), expected)

    def test_verify_accepts_current_and_neighbor_step(self):
        secret = totp.new_secret()
        now = 1_800_000_000
        step = totp.current_step(now)
        self.assertEqual(totp.verify(secret, totp.code_at(secret, step), 0, now=now), step)
        self.assertEqual(totp.verify(secret, totp.code_at(secret, step - 1), 0, now=now), step - 1)
        self.assertIsNone(totp.verify(secret, totp.code_at(secret, step - 3), 0, now=now))

    def test_same_code_cannot_be_reused(self):
        secret = totp.new_secret()
        now = 1_800_000_000
        code = totp.code_at(secret, totp.current_step(now))
        used = totp.verify(secret, code, 0, now=now)
        self.assertIsNone(totp.verify(secret, code, used, now=now))

    def test_rejects_garbage(self):
        self.assertIsNone(totp.verify(totp.new_secret(), "12ab56", 0))
        self.assertIsNone(totp.verify(totp.new_secret(), "", 0))

    def test_recovery_codes(self):
        codes = totp.new_recovery_codes()
        self.assertEqual(len(set(codes)), 8)
        for code in codes:
            self.assertTrue(totp.looks_like_recovery_code(code))
            self.assertEqual(totp.hash_recovery_code(code), totp.hash_recovery_code(code.upper().replace("-", " ")))

    def test_provisioning_uri(self):
        uri = totp.provisioning_uri("ABC", "maria@exemplo.com")
        self.assertTrue(uri.startswith("otpauth://totp/Log%20Analyzer%3Amaria%40exemplo.com?secret=ABC"))


if __name__ == "__main__":
    unittest.main()
