"""Minimal PostgREST client.

Customer requests use the caller's JWT so row-level security stays the
boundary. The worker uses the service role only for queue writes and
normalized findings.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import HTTPException, status

from app.config import settings

MANAGER_ROLES = ("owner", "admin")
WRITE_ROLES = ("owner", "admin", "analyst", "developer")


class SupabaseError(Exception):
    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class SupabaseRest:
    def __init__(self, token: str | None = None, *, service: bool = False) -> None:
        self._token = token
        self._service = service

    def _headers(self) -> dict[str, str]:
        if not settings.supabase_url:
            raise SupabaseError("Supabase is not configured.", 503)

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if self._service:
            if not settings.supabase_service_role_key:
                raise SupabaseError(
                    "SUPABASE_SERVICE_ROLE_KEY is required for scanner writes.", 503
                )
            headers["apikey"] = settings.supabase_service_role_key
            headers["Authorization"] = f"Bearer {settings.supabase_service_role_key}"
        else:
            if not settings.supabase_anon_key:
                raise SupabaseError("Supabase anon key is not configured.", 503)
            headers["apikey"] = settings.supabase_anon_key
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

        return headers

    async def request(
        self,
        method: str,
        table: str,
        *,
        params: dict[str, str] | None = None,
        json: Any = None,
        prefer: str | None = None,
    ) -> Any:
        headers = self._headers()
        if prefer:
            headers["Prefer"] = prefer

        url = f"{settings.supabase_url.rstrip('/')}/rest/v1/{table}"

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.request(
                    method, url, headers=headers, params=params, json=json
                )
        except httpx.HTTPError as exc:
            raise SupabaseError(f"Supabase request failed: {exc}", 502) from exc

        if response.status_code >= 400:
            detail: Any = None
            try:
                detail = response.json()
            except ValueError:
                detail = response.text
            raise SupabaseError(f"Supabase rejected the request: {detail}", 400)

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    async def select(
        self, table: str, *, params: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        rows = await self.request("GET", table, params=params)
        return rows or []

    async def insert(
        self,
        table: str,
        values: Any,
        *,
        prefer: str = "return=representation",
        on_conflict: str | None = None,
    ) -> Any:
        params = {"on_conflict": on_conflict} if on_conflict else None
        return await self.request(
            "POST", table, json=values, prefer=prefer, params=params
        )

    async def update(
        self, table: str, values: dict[str, Any], *, params: dict[str, str]
    ) -> Any:
        return await self.request(
            "PATCH", table, json=values, params=params, prefer="return=representation"
        )

    async def rpc(self, name: str, payload: dict[str, Any]) -> Any:
        return await self.request("POST", f"rpc/{name}", json=payload)


async def workspace_role(token: str, workspace_id: str) -> str | None:
    """Return the caller's role in *workspace_id*, or None."""
    db = SupabaseRest(token)
    rows = await db.select(
        "workspace_members",
        params={
            "workspace_id": f"eq.{workspace_id}",
            "select": "role",
            "limit": "1",
        },
    )
    if not rows:
        return None
    return rows[0].get("role")


def require_member(role: str | None) -> None:
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace was not found.",
        )


def require_role(role: str | None, allowed: tuple[str, ...]) -> None:
    require_member(role)
    if role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your workspace role does not allow this action.",
        )
