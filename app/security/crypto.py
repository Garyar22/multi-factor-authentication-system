"""
Encryption of TOTP secrets at rest, plus token hashing helpers.

Threat addressed: an attacker who obtains a database dump (SQL injection,
stolen backup, insider access) must not come away with usable TOTP seeds.
Encrypting the seed with a key held outside the database means the dump alone
is not enough — the attacker also needs the application's environment.

Fernet (cryptography library) is used: AES-128-CBC for confidentiality with
HMAC-SHA256 for authenticity, so a tampered ciphertext is rejected rather
than silently decrypted to garbage.
"""

import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class EncryptionKeyMissing(RuntimeError):
    """Raised when MFA_ENCRYPTION_KEY is absent or malformed."""


def _fernet() -> Fernet:
    key = current_app.config.get("MFA_ENCRYPTION_KEY")
    if not key:
        raise EncryptionKeyMissing(
            "MFA_ENCRYPTION_KEY is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    if isinstance(key, str):
        key = key.encode()
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise EncryptionKeyMissing(
            "MFA_ENCRYPTION_KEY is not a valid 32-byte url-safe base64 Fernet key."
        ) from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret for storage. Returns url-safe base64 text."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a stored TOTP secret.

    Raises InvalidToken if the ciphertext was tampered with or the key is
    wrong — which is the desired behaviour: fail closed, never guess.
    """
    return _fernet().decrypt(ciphertext.encode()).decode()


def try_decrypt_secret(ciphertext: str) -> str | None:
    """Non-raising variant for defensive paths. Returns None on failure."""
    try:
        return decrypt_secret(ciphertext)
    except (InvalidToken, EncryptionKeyMissing, ValueError):
        return None


# ---------------------------------------------------------------------------
# Token generation and hashing
# ---------------------------------------------------------------------------

def generate_url_token(nbytes: int = 32) -> str:
    """Cryptographically secure, URL-safe random token (secrets module)."""
    return secrets.token_urlsafe(nbytes)


def generate_opaque_id(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    """
    SHA-256 digest used for password-reset tokens and pending-auth lookups.

    A plain hash is appropriate here (unlike for passwords) because the input
    is a 256-bit random value, not a low-entropy human secret, so there is
    nothing to brute-force.
    """
    return hashlib.sha256(value.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe comparison, to avoid leaking a token byte by byte."""
    return hmac.compare_digest(a or "", b or "")
