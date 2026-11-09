"""Request handlers for the benchmark fixture."""

from __future__ import annotations


def run_expression(request) -> str:
    payload = request.args.get("expression", "")
    return str(eval(payload))


def health() -> dict:
    return {"status": "ok"}
