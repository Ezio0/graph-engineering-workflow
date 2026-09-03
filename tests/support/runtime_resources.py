"""Test-only construction of a fresh configured runtime WorkContext."""

from __future__ import annotations

import json
import pathlib

from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
from graph_engineering.core.runtime import RuntimeResourceGuard, RuntimeResourcePolicy


ROOT = pathlib.Path(__file__).resolve().parents[2]


def runtime_resource_guard(**overrides: int) -> RuntimeResourceGuard:
    profile = ResourceProfile.from_dict(json.loads(
        (ROOT / "config/contracts/resource-profile-v1.json").read_text()
    ))
    schedule = CostSchedule.from_dict(json.loads(
        (ROOT / "config/contracts/cost-schedule-v1.json").read_text()
    ))
    document = json.loads(
        (ROOT / "config/contracts/runtime-resource-policy-v1.json").read_text()
    )
    document.update(overrides)
    if overrides:
        from graph_engineering.core.runtime import runtime_record_digest
        document["policy_digest"] = runtime_record_digest(
            "resource-policy",
            {key: value for key, value in document.items() if key != "policy_digest"},
        )
    return RuntimeResourceGuard(
        RuntimeResourcePolicy.from_dict(document), WorkContext(profile, schedule)
    )
