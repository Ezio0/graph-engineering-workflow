"""WP-07A installed action-adapter contract fixtures."""

from __future__ import annotations

import json
from functools import lru_cache

from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from tests.support.wp05a_security import ROOT, load_json


ACTION_ADAPTER_SCHEMA_NAMES = (
    "action-adapter-registry-1.0.0.json",
    "action-invocation-1.0.0.json",
    "action-receipt-1.0.0.json",
    "command-execution-request-1.0.0.json",
    "command-execution-result-1.0.0.json",
    "command-registry-1.0.0.json",
    "command-runtime-policy-1.0.0.json",
    "concrete-action-policy-1.0.0.json",
    "connector-capability-mismatch-1.0.0.json",
    "connector-registry-1.0.0.json",
    "git-adapter-configuration-1.0.0.json",
    "git-identity-observation-1.0.0.json",
    "git-ref-mutation-plan-1.0.0.json",
    "git-target-plan-1.0.0.json",
    "secret-provider-registry-1.0.0.json",
    "target-observation-1.0.0.json",
)


def action_adapter_schema_registry(context: WorkContext) -> ClosedSchemaRegistry:
    manifest = load_json(
        ROOT / "config" / "contracts" / "action-adapter-schema-registry-v1.json"
    )
    bodies: dict[str, bytes] = {}
    for name in ACTION_ADAPTER_SCHEMA_NAMES:
        path = ROOT / "config" / "contracts" / "schemas" / name
        schema_id = json.loads(path.read_text())["$id"]
        bodies[schema_id] = path.read_bytes()
    profile = ResourceProfile.from_dict(load_json(
        ROOT / "config" / "contracts" / "resource-profile-v1.json"
    ))
    policy = SchemaProfilePolicy.from_dict(load_json(
        ROOT / "config" / "contracts" / "schema-profile-v1.json"
    ))
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)


@lru_cache(maxsize=1)
def installed_action_adapter_attestation() -> object:
    """Issue a test adapter authority through a real durable installation runtime."""

    from graph_engineering.core.action_adapters import (
        ActionAdapterRegistry,
        ConcreteActionPolicy,
    )
    from tests.support.wp05_actions import action_stack

    registry = ActionAdapterRegistry.from_dict(load_json(
        ROOT / "config" / "contracts" / "action-adapter-registry-v1.json"
    ))
    concrete = ConcreteActionPolicy.from_dict(
        load_json(ROOT / "config" / "actions" / "concrete-action-policy-v1.json"),
        registry=registry,
    )
    schema_manifest = load_json(
        ROOT / "config" / "contracts" / "action-adapter-schema-registry-v1.json"
    )
    with action_stack() as fixture:
        return fixture.raw_coordinator._policy.issue_action_adapter_installation(
            concrete_policy_id=concrete.policy_id,
            concrete_policy_digest=concrete.policy_digest,
            registry_id=registry.registry_id,
            registry_digest=registry.registry_digest,
            schema_registry_id=schema_manifest["registry_id"],
            schema_registry_digest=schema_manifest["registry_digest"],
            runtime=fixture.issuer.runtime,
        )
