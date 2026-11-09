"""AI orchestration.

The model plans and explains; it never executes anything. Every tool it can
name must exist in app.scanners.registry, and its output is validated against
that allowlist before use.
"""

from app.ai.orchestrator import PlanStep, correlate, fallback_plan, summarize, validate_plan
from app.ai.omniroute import OmniRoute, OmniRouteError

__all__ = [
    "PlanStep",
    "correlate",
    "fallback_plan",
    "summarize",
    "validate_plan",
    "OmniRoute",
    "OmniRouteError",
]
