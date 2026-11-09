"""Native asyncio first-bytes engine (standard library only).

Identification is done by ``scanner.probe_port``: one connection per port,
protocol classified from what the service sends, with a read-only probe on the
same socket when the service waits to be addressed. It remains the fallback
when nmap is unavailable and the only engine that works on a machine with
nothing but Python installed.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .. import __version__
from ..scanner import DEFAULT_TIMEOUT, PortService, run_scan

NAME = "native"


async def run(hosts: list[str], ports: list[int], *, timeout: float = DEFAULT_TIMEOUT,
              concurrency: int = 256,
              progress=None) -> tuple[list[PortService], dict]:
    """Scan with the built-in connect scanner; returns (services, metadata)."""
    started = time.monotonic()
    services = await run_scan(hosts, ports, timeout=timeout,
                              concurrency=concurrency, progress=progress)
    for svc in services:
        svc.source = NAME
    meta = {
        "engine": NAME,
        "version": f"vulnscan {__version__}",
        "argv": [],
        "privileged": False,
        "duration_seconds": round(time.monotonic() - started, 2),
        "open_ports": len(services),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return services, meta
