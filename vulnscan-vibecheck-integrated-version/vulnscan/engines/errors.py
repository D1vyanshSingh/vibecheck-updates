"""Engine errors shared by the detection backends."""

from __future__ import annotations


class EngineError(RuntimeError):
    """A detection engine could not run (bad request, failed process, bad data)."""


class EngineUnavailable(EngineError):
    """The requested engine is not installed or cannot be executed."""
