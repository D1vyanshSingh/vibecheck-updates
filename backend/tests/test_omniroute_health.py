"""OmniRoute health reporting.

Nothing here reaches a real gateway: an unconfigured instance must say so, and a
configured one is only \"reachable\" when a models request actually answered.
"""

from __future__ import annotations

import httpx
import pytest

from app.ai.omniroute import OmniRoute


def _patch(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return real(transport=transport, *args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_unconfigured_reports_no_reachability_claim(monkeypatch):
    _patch(monkeypatch, lambda request: httpx.Response(200, json={"data": []}))

    health = await OmniRoute(base_url="", api_key="").health()

    assert health["configured"] is False
    assert health["reachable"] is None
    assert "not both set" in health["detail"]


@pytest.mark.asyncio
async def test_configured_gateway_lists_models(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/models"
        assert request.headers["authorization"] == "Bearer key"
        return httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o-mini"}, {"id": "claude-sonnet"}, {"nope": 1}]},
        )

    _patch(monkeypatch, handler)

    health = await OmniRoute(base_url="https://gateway.test", api_key="key").health()

    assert health["configured"] is True
    assert health["reachable"] is True
    assert health["models"] == ["gpt-4o-mini", "claude-sonnet"]


@pytest.mark.asyncio
async def test_gateway_error_is_reported_not_hidden(monkeypatch):
    _patch(monkeypatch, lambda request: httpx.Response(401, json={"error": "bad key"}))

    health = await OmniRoute(base_url="https://gateway.test", api_key="bad").health()

    assert health["configured"] is True
    assert health["reachable"] is False
    assert health["status"] == 401


@pytest.mark.asyncio
async def test_transport_failure_is_reported(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    _patch(monkeypatch, handler)

    health = await OmniRoute(base_url="https://gateway.test", api_key="key").health()

    assert health["reachable"] is False
    assert "ConnectError" in health["detail"]
