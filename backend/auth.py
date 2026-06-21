import os
from functools import lru_cache
from typing import Optional

import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException


@lru_cache
def _jwks_client() -> PyJWKClient:
    url = os.environ.get("CLERK_JWKS_URL")
    if not url:
        raise RuntimeError("CLERK_JWKS_URL env var is not set")
    return PyJWKClient(url)


async def get_current_user_id(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.removeprefix("Bearer ")
    try:
        client = _jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
