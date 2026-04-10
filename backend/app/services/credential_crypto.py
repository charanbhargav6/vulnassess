import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _build_fernet() -> Fernet:
    configured_key = (settings.CREDENTIALS_ENCRYPTION_KEY or "").strip()
    if configured_key:
        return Fernet(configured_key.encode("utf-8"))

    # Fallback for existing deployments: derive a stable key from SECRET_KEY.
    derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    token = _build_fernet().encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(token: str | None) -> str | None:
    if not token:
        return None
    try:
        plain = _build_fernet().decrypt(token.encode("utf-8"))
        return plain.decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Invalid encrypted credential payload") from exc
