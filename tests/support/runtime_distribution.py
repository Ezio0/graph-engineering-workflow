"""Test-only issuer for a deterministic running distribution identity."""

from __future__ import annotations

from graph_engineering.adapters.runtime_locator import (
    RunningDistributionIdentity,
    _RUNNING_DISTRIBUTION_ISSUER,
)


def running_distribution(
    executable: str,
    package_origin: str,
    distribution_origin: str,
    *,
    distribution_name: str = "graph-engineering-workflow",
    distribution_version: str = "0.1.0",
) -> RunningDistributionIdentity:
    identity = object.__new__(RunningDistributionIdentity)
    for name, value in (
        ("executable", executable), ("package_origin", package_origin),
        ("distribution_name", distribution_name),
        ("distribution_version", distribution_version),
        ("distribution_origin", distribution_origin),
        ("_issuer", _RUNNING_DISTRIBUTION_ISSUER),
    ):
        object.__setattr__(identity, name, value)
    return identity
