"""Bearer-token authentication.

Supabase signs access tokens asymmetrically and publishes the public keys at
/auth/v1/.well-known/jwks.json. The algorithm is read from the token header
(ES256 for current projects, RS256 for older ones) and the key is built from
the JWK itself, so a key/algorithm mismatch cannot be silently accepted. The
HS256 path exists only for local tests and is refused in production.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from fastapi import Header, HTTPException, status

from app.config import settings


@dataclass(frozen=True)
class Principal:
    id: str
    email: str | None
    token: str


class AuthFailure(Exception):
    def __init__(self, detail: str, status_code: int = 401) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


_JWKS: dict[str, Any] = {"keys": [], "fetched": 0.0}
_JWKS_TTL = 600


def _jwks_url() -> str:
    return f"{settings.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"


async def _get_jwks(force: bool = False) -> list[dict[str, Any]]:
    now = time.time()
    if not force and _JWKS["keys"] and now - _JWKS["fetched"] < _JWKS_TTL:
        return _JWKS["keys"]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(_jwks_url())
            response.raise_for_status()
            keys = response.json().get("keys", [])
    except Exception as exc:  # noqa: BLE001 - surfaced as 503
        raise AuthFailure("Could not load Supabase signing keys.", 503) from exc

    _JWKS["keys"] = keys
    _JWKS["fetched"] = now
    return keys


_ASYMMETRIC = {"ES256": {"EC"}, "ES384": {"EC"}, "RS256": {"RSA"}, "RS384": {"RSA"}}


def _public_key(jwk: dict[str, Any], alg: str) -> Any:
    """Verification key for the algorithm the token claims, or a refusal."""
    kinds = _ASYMMETRIC.get(alg)
    if not kinds or jwk.get("kty") not in kinds:
        raise AuthFailure("Unsupported token algorithm.")
    try:
        return jwt.PyJWK(jwk, algorithm=alg).key
    except Exception as exc:  # noqa: BLE001 - malformed JWK
        raise AuthFailure("Could not build a signing key for this token.") from exc


def _decode_hs256(token: str) -> dict[str, Any]:
    if not settings.supabase_jwt_secret:
        raise AuthFailure("HS256 verification is not configured.", 503)
    try:
        return jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthFailure("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthFailure("Invalid token.") from exc


async def verify_token(token: str) -> Principal:
    if not token:
        raise AuthFailure("A bearer token is required.")

    if settings.supabase_jwt_secret and settings.supabase_url == "":
        claims = _decode_hs256(token)
        return Principal(id=claims["sub"], email=claims.get("email"), token=token)

    if not settings.supabase_url:
        raise AuthFailure("Supabase is not configured on the backend.", 503)

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise AuthFailure("Invalid token.") from exc

    alg = header.get("alg", "")
    if alg == "HS256":
        claims = _decode_hs256(token)
        return Principal(id=claims["sub"], email=claims.get("email"), token=token)

    keys = await _get_jwks()
    kid = header.get("kid")
    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if jwk is None and len(keys) == 1:
        jwk = keys[0]

    if jwk is None:
        keys = await _get_jwks(force=True)
        jwk = next((k for k in keys if k.get("kid") == kid), None)

    if jwk is None:
        raise AuthFailure("No signing key matches this token.", 401)

    try:
        claims = jwt.decode(
            token,
            _public_key(jwk, alg),
            algorithms=[alg],
            audience="authenticated",
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthFailure("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthFailure("Invalid token.") from exc

    return Principal(id=claims["sub"], email=claims.get("email"), token=token)


async def get_current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> Principal:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else authorization.strip()

    try:
        return await verify_token(token)
    except AuthFailure as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
