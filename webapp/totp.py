"""
2FA por TOTP (RFC 6238): o código de 6 dígitos de apps como Google Authenticator,
Microsoft Authenticator, Authy, 1Password e Bitwarden. Só biblioteca padrão.

Também gera os códigos de recuperação, para quem perder o celular.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote

STEP = 30          # segundos que cada código vale
DIGITS = 6
ISSUER = "Log Analyzer"
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # sem 0/o, 1/l/i para não confundir


def new_secret() -> str:
    """Segredo de 160 bits em base32, o formato que os apps autenticadores esperam."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))


def code_at(secret: str, step: int, digits: int = DIGITS) -> str:
    """Código do passo de tempo `step` (HOTP do RFC 4226 com HMAC-SHA1)."""
    mac = hmac.new(_key(secret), step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, last_step: int, now: float | None = None, window: int = 1) -> int | None:
    """Passo de tempo do código, se for válido e ainda não usado; senão None.

    Aceita um passo de diferença para relógios um pouco fora de hora, e recusa
    qualquer passo <= last_step: o mesmo código não serve duas vezes.
    """
    code = code.replace(" ", "").strip()
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    now_step = current_step(now)
    for step in range(now_step - window, now_step + window + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, email: str) -> str:
    """Endereço otpauth:// que vira o QR code lido pelo app autenticador."""
    label = quote(f"{ISSUER}:{email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&digits={DIGITS}&period={STEP}"


def qr_svg(uri: str) -> str | None:
    """QR code em SVG, se a biblioteca segno estiver instalada; senão a pessoa digita a chave."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#0b0b0b", light="#ffffff")


def new_recovery_codes(count: int = 8) -> list[str]:
    """Códigos de uso único no formato xxxxx-xxxxx (cerca de 49 bits cada)."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def _normalize(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str, pepper: str) -> str:
    """HMAC com a chave secreta do servidor: com ~49 bits por código, um SHA-256 puro
    seria quebrado em horas por quem copiasse o banco; sem a chave, não."""
    return hmac.new(pepper.encode(), _normalize(code).encode(), hashlib.sha256).hexdigest()


def legacy_hash_recovery_code(code: str) -> str:
    """Formato antigo (SHA-256 puro), aceito só para códigos gerados antes da mudança."""
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def looks_like_recovery_code(code: str) -> bool:
    normalized = _normalize(code)
    return len(normalized) == 10 and all(c in RECOVERY_ALPHABET for c in normalized)
