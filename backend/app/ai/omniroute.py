"""OmniRoute client.

OmniRoute is the only model gateway this backend talks to, and it is optional:
when it is not configured, or the request fails, callers get a typed failure
and the deterministic planner runs instead. Scanner execution never waits on
this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from app.ai.orchestrator import Plan, fallback_plan, validate_plan
from app.config import settings
from app.scanners.registry import availability

PROMPT_VERSION = "assess-plan-v1"

SYSTEM_PROMPT = """You plan security assessments for a code archive.
Reply with JSON only, shaped as {"steps":[{"tool":"<name>","reason":"<why>"}]}.
You may only use tools from the provided list. Never invent a tool, never ask
for shell access, and never claim a check has run. Keep at most 6 steps.
A step's reason must describe why the tool fits this archive, in one sentence."""


class OmniRouteError(Exception):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class Completion:
    text: str
    model: str
    usage: dict[str, Any]


class OmniRoute:
    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        self.base_url = (base_url if base_url is not None else settings.omniroute_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.omniroute_api_key
        self.model = settings.omniroute_default_model or "omniroute/auto"
        self.timeout = 45.0

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def complete(self, system: str, user: str, *, max_tokens: int = 900) -> Completion:
        if not self.configured:
            raise OmniRouteError("OmniRoute is not configured.")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise OmniRouteError(f"OmniRoute request failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            raise OmniRouteError(
                f"OmniRoute returned {response.status_code}.", status=response.status_code
            )

        try:
            body = response.json()
            text = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise OmniRouteError("OmniRoute response did not match the expected shape.") from exc

        if not isinstance(text, str) or not text.strip():
            raise OmniRouteError("OmniRoute returned an empty completion.")

        return Completion(
            text=text,
            model=body.get("model", self.model),
            usage=body.get("usage") or {},
        )

    async def health(self) -> dict[str, Any]:
        """Probe the gateway. "Configured" and "reachable" are different facts."""
        base = {
            "configured": self.configured,
            "base_url_set": bool(self.base_url),
            "api_key_set": bool(self.api_key),
            "model": self.model,
        }
        if not self.configured:
            return {
                **base,
                "reachable": None,
                "detail": "OMNIROUTE_BASE_URL and OMNIROUTE_API_KEY are not both set.",
            }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.base_url}/v1/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
        except httpx.HTTPError as exc:
            return {
                **base,
                "reachable": False,
                "detail": f"Probe failed: {type(exc).__name__}.",
            }

        if response.status_code >= 400:
            return {
                **base,
                "reachable": False,
                "status": response.status_code,
                "detail": f"Gateway rejected the probe with {response.status_code}.",
            }

        models: list[str] = []
        try:
            payload = response.json()
            entries = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(entries, list):
                models = [
                    str(item.get("id"))
                    for item in entries[:20]
                    if isinstance(item, dict) and item.get("id")
                ]
        except ValueError:
            models = []

        return {
            **base,
            "reachable": True,
            "status": response.status_code,
            "models": models,
            "detail": "The gateway answered a models request.",
        }

    async def plan(self, *, technologies: list[str], file_count: int, has_lockfiles: bool) -> Plan:
        """Ask for a plan; any failure yields the deterministic plan, marked as such."""
        available = availability()
        tools = [name for name, ok in available.items() if ok]
        if not self.configured:
            plan = Plan(steps=fallback_plan(available), source="fallback")
            plan.notes = "OmniRoute is not configured; deterministic plan used."
            return plan

        user = json.dumps(
            {
                "technologies": technologies,
                "file_count": file_count,
                "has_lockfiles": has_lockfiles,
                "available_tools": tools,
            }
        )
        try:
            completion = await self.complete(SYSTEM_PROMPT, user)
            raw = json.loads(completion.text)
        except (OmniRouteError, json.JSONDecodeError) as exc:
            plan = Plan(steps=fallback_plan(available), source="fallback")
            plan.notes = f"Model plan unavailable ({exc}); deterministic plan used."
            return plan

        plan = validate_plan(raw, available)
        if plan.source == "model" and plan.steps:
            plan.notes = (plan.notes + " " if plan.notes else "") + f"model={completion.model}"
        return plan

    async def analyse_finding(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Explain one finding. Returns None when the model is unavailable."""
        if not self.configured:
            return None
        system = (
            "Explain one security finding. Reply with JSON only: "
            '{"what_it_means":"...","preconditions":"...","fix_direction":"..."}. '
            "Use no more than 80 words per field. Do not claim exploitation and do not "
            "invent evidence beyond the supplied record."
        )
        try:
            completion = await self.complete(system, json.dumps(finding)[:6000], max_tokens=500)
            body = json.loads(completion.text)
        except (OmniRouteError, json.JSONDecodeError):
            return None
        if not isinstance(body, dict):
            return None
        return {
            "what_it_means": str(body.get("what_it_means", ""))[:1200],
            "preconditions": str(body.get("preconditions", ""))[:1200],
            "fix_direction": str(body.get("fix_direction", ""))[:1200],
            "model": completion.model,
            "prompt_version": PROMPT_VERSION,
        }
