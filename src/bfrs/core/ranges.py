"""Shared physical range predicates."""

from __future__ import annotations


def intersects(requested_start: int, requested_end: int,
               artifact_start: int, artifact_end: int) -> bool:
    """Return whether two half-open byte ranges ``[start, end)`` intersect."""
    if requested_start < 0 or artifact_start < 0:
        raise ValueError("range start must be nonnegative")
    if requested_end < requested_start or artifact_end < artifact_start:
        raise ValueError("range end must not precede range start")
    return requested_start < artifact_end and artifact_start < requested_end
