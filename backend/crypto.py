"""At-rest encryption for stored credentials (SMTP password, webhook URLs, API tokens).

Secrets live in the SQLite/Postgres DB. To keep a leaked DB file from exposing
them, each secret column is wrapped so it is encrypted on write and decrypted on
read (see models.EncryptedText).

Scheme: Fernet (AES-128-CBC + HMAC-SHA256, authenticated) with a key derived from
the app SECRET_KEY via PBKDF2-HMAC-SHA256 over a fixed salt, hashed 240k times
("salt several times") to make brute-forcing the key from the SECRET_KEY costly.
Ciphertext is stored with an `enc::` prefix; values without it are treated as
legacy plaintext (returned as-is, then re-encrypted on the next save) so existing
rows keep working without a migration.
"""
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

_SALT = b"vnotice-config-secret-v1"   # fixed app salt (rotating it re-keys all secrets)
_ITERATIONS = 240_000                  # PBKDF2 rounds
_PREFIX = "enc::"

_fernet = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        secret = os.getenv("SECRET_KEY", "supersecretkey_change_me_in_production").encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", secret, _SALT, _ITERATIONS)
        _fernet = Fernet(base64.urlsafe_b64encode(dk))
    return _fernet


def encrypt(value):
    """Return value encrypted with an `enc::` prefix. No-op on empty/already-encrypted."""
    if not value or not isinstance(value, str):
        return value
    if value.startswith(_PREFIX):
        return value
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt(value):
    """Reverse encrypt(). Legacy plaintext (no prefix) and undecryptable data pass through."""
    if not value or not isinstance(value, str) or not value.startswith(_PREFIX):
        return value
    try:
        return _get_fernet().decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return value
