"""Authentication & authorization: JWT tokens, password hashing, sensor API keys."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import HTTPException, status
from jose import JWTError, jwt

from ..config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(sub: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "role": role,
        "type": "access",
        "iat": now,
        "jti": secrets.token_urlsafe(16),
        "iss": "attacksentry",
        "aud": "attacksentry-console",
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def create_refresh_token(sub: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "type": "refresh",
        "iat": now,
        "jti": secrets.token_urlsafe(16),
        "iss": "attacksentry",
        "aud": "attacksentry-console",
        "exp": now + timedelta(days=settings.refresh_token_expire_days),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer="attacksentry",
            audience="attacksentry-console",
        )
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")


# --- Sensor API keys -------------------------------------------------------- #

def generate_api_key() -> tuple[str, str]:
    """Return (key_id, secret). The secret is stored only as a hash."""
    key_id = "sk_" + secrets.token_hex(12)
    secret = secrets.token_urlsafe(48)
    return key_id, secret


def hash_api_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_api_secret(secret: str, secret_hash: str) -> bool:
    return secrets.compare_digest(hash_api_secret(secret), secret_hash)
