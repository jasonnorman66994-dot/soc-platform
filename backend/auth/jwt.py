from datetime import datetime, timedelta, timezone
import os
from jose import jwt, JWTError

SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
ALGORITHM = "HS256"


def create_access_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "token_type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def create_refresh_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "token_type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def verify_token(token: str, token_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        if payload.get("token_type") != token_type:
            raise ValueError("Invalid token type")
        return payload
    except JWTError as exc:
        raise ValueError("Invalid token") from exc
