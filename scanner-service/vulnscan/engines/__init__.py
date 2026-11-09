"""Detection engine selection.

``auto`` prefers nmap when it is installed and falls back to the built-in
standard-library scanner. ``--engine nmap`` is strict: it fails rather than
silently scanning with something else. ``--engine native`` never looks for
nmap at all.
"""

from __future__ import annotations

import asyncio

from ..scanner import DEFAULT_TIMEOUT
from ..scanner import PortService
from . import nmap as nmap_engine
from . import native as native_engine
from .errors import EngineError, EngineUnavailable

ENGINE_CHOICES = ("auto", "native", "nmap")
DEFAULT_ENGINE = "auto"
NSE_CHOICES = tuple(nmap_engine.NSE_PROFILES)
DEFAULT_NSE = "safe"


def nse_scripts(profile: str = DEFAULT_NSE) -> list[str]:
    """NSE scripts for a named profile; the nmap engine is the only consumer."""
    if profile not in nmap_engine.NSE_PROFILES:
        raise EngineError(
            f"unknown NSE profile {profile!r}; choose from "
            f"{', '.join(NSE_CHOICES)}")
    return list(nmap_engine.NSE_PROFILES[profile])


def resolve(engine: str = DEFAULT_ENGINE) -> tuple[str, str | None]:
    """Choose an engine; returns (engine_name, fallback_reason)."""
    if engine not in ENGINE_CHOICES:
        raise EngineError(
            f"unknown engine {engine!r}; choose from {', '.join(ENGINE_CHOICES)}")
    if engine == "native":
        return "native", None
    if nmap_engine.find_nmap():
        return "nmap", None
    if engine == "nmap":
        raise EngineUnavailable(
            "nmap was requested but was not found; install nmap or use "
            "--engine native")
    return "native", "nmap not found; using the built-in scanner"


async def scan(hosts: list[str], ports: list[int], *, engine: str = DEFAULT_ENGINE,
               timeout: float = DEFAULT_TIMEOUT, concurrency: int = 256,
               progress=None, scripts: list[str] | None = None,
               version_intensity: int | None = None
               ) -> tuple[list[PortService], dict]:
    """Run the resolved engine and attach the provenance the report needs."""
    name, fallback_reason = resolve(engine)
    if name == "nmap":
        services, meta = await nmap_engine.run(
            hosts, ports, timeout=timeout, concurrency=concurrency,
            progress=progress, scripts=scripts,
            version_intensity=version_intensity)
    else:
        services, meta = await native_engine.run(
            hosts, ports, timeout=timeout, concurrency=concurrency,
            progress=progress)
    meta["requested_engine"] = engine
    meta["fallback_reason"] = fallback_reason or ""
    return services, meta


__all__ = [
    "DEFAULT_ENGINE", "DEFAULT_NSE", "ENGINE_CHOICES", "EngineError",
    "EngineUnavailable", "NSE_CHOICES", "nmap_engine", "native_engine",
    "nse_scripts", "resolve", "scan",
]
