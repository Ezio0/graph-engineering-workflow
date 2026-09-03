from __future__ import annotations

import copy
import json
import pathlib
import unittest

from graph_engineering.core.action_adapters import (
    ActionAdapterContractError,
    ActionAdapterRegistry,
    ActionInvocation,
    ActionReceipt,
    ConcreteActionPolicy,
    TargetObservation,
)
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.schema import SchemaProfilePolicy, validate_schema_profile


ROOT = pathlib.Path(__file__).resolve().parents[2]
IDENTITY = "urn:gew:digest-projection:identity:1.0.0"


def digest(label: str) -> str:
    return semantic_digest(
        {"label": label},
        contract_type="urn:gew:contract:wp07a-test-value",
        projection_id=IDENTITY,
        schema_id="urn:gew:schema:wp07a-test-value:1.0.0",
    )


def invocation_document() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": "invocation-wp07a",
        "task_id": "task-wp07a",
        "action_id": "action-wp07a",
        "prepared_action_digest": digest("prepared"),
        "authority_digest": digest("authority"),
        "adapter_id": "git-native-v1",
        "operation_id": "git.update-ref",
        "target_id": "target-project",
        "target_digest": digest("target"),
        "resources": ["target:project", "task:task-wp07a"],
        "lease_id": "lease-wp07a",
        "fencing_tokens": [
            {"resource_id": "target:project", "token": 8},
            {"resource_id": "task:task-wp07a", "token": 3},
        ],
        "idempotency_class": "idempotent",
        "idempotency_key": "idempotency-wp07a",
        "payload_digest": ActionInvocation.payload_digest_for({"operation": "noop"}),
        "disclosure_plan_digest": digest("disclosure"),
    }
    value["invocation_digest"] = ActionInvocation.digest_document(value)
    return value


def receipt_document(invocation: ActionInvocation) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "receipt_id": "receipt-wp07a",
        "invocation_id": invocation.invocation_id,
        "invocation_digest": invocation.invocation_digest,
        "task_id": invocation.task_id,
        "action_id": invocation.action_id,
        "prepared_action_digest": invocation.prepared_action_digest,
        "authority_digest": invocation.authority_digest,
        "adapter_id": invocation.adapter_id,
        "operation_id": invocation.operation_id,
        "target_id": invocation.target_id,
        "target_digest": invocation.target_digest,
        "resources": list(invocation.resources),
        "lease_id": invocation.lease_id,
        "fencing_tokens": [dict(item) for item in invocation.fencing_tokens],
        "idempotency_class": invocation.idempotency_class,
        "idempotency_key": invocation.idempotency_key,
        "result": "succeeded",
        "result_digest": digest("result"),
        "receipt_source": "adapter-return",
    }
    value["receipt_digest"] = ActionReceipt.digest_document(value)
    return value


def observation_document(receipt: ActionReceipt) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "observation_id": "observation-wp07a",
        "receipt_id": receipt.receipt_id,
        "receipt_digest": receipt.receipt_digest,
        "invocation_id": receipt.invocation_id,
        "invocation_digest": receipt.invocation_digest,
        "task_id": receipt.task_id,
        "action_id": receipt.action_id,
        "prepared_action_digest": receipt.prepared_action_digest,
        "authority_digest": receipt.authority_digest,
        "adapter_id": receipt.adapter_id,
        "operation_id": receipt.operation_id,
        "target_id": receipt.target_id,
        "target_digest": receipt.target_digest,
        "resources": list(receipt.resources),
        "lease_id": receipt.lease_id,
        "fencing_tokens": [dict(item) for item in receipt.fencing_tokens],
        "fresh": True,
        "observation_revision": 9,
        "observed_state_digest": digest("observed-state"),
    }
    value["observation_digest"] = TargetObservation.digest_document(value)
    return value


class WP07AActionContractTests(unittest.TestCase):
    def test_gew_act_001_policy_and_registry_are_closed_self_digested_and_factory_ready(self) -> None:
        schema_names = (
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
        schema_policy = SchemaProfilePolicy.from_dict(json.loads(
            (ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()
        ))
        bodies: dict[str, bytes] = {}
        for name in schema_names:
            path = ROOT / "config" / "contracts" / "schemas" / name
            schema_id = validate_schema_profile(json.loads(path.read_text()), schema_policy)
            bodies[schema_id] = path.read_bytes()
        schema_manifest = json.loads(
            (ROOT / "config" / "contracts" / "action-adapter-schema-registry-v1.json").read_text()
        )
        self.assertEqual(
            schema_manifest,
            ClosedSchemaRegistry.create_manifest(
                "urn:gew:schema-registry:action-adapters:1.0.0", bodies
            ),
        )
        policy_document = json.loads(
            (ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()
        )
        registry_document = json.loads(
            (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
        )
        registry = ActionAdapterRegistry.from_dict(registry_document)
        policy = ConcreteActionPolicy.from_dict(policy_document, registry=registry)
        self.assertTrue(policy.real_local_actions_enabled)
        self.assertEqual(
            tuple(entry.adapter_kind for entry in registry.entries),
            ("git", "project-command", "target-query", "secret-provider", "connector"),
        )
        self.assertEqual(policy.registry_digest, registry.registry_digest)

        for document, loader, digest_field in (
            (policy_document, lambda value: ConcreteActionPolicy.from_dict(value, registry=registry), "policy_digest"),
            (registry_document, ActionAdapterRegistry.from_dict, "registry_digest"),
        ):
            with self.subTest(record=digest_field):
                changed = copy.deepcopy(document)
                changed[digest_field] = digest("substituted")
                with self.assertRaises(ActionAdapterContractError):
                    loader(changed)

    def test_gew_act_002_invocation_binds_exact_ordered_resources_and_full_fences(self) -> None:
        document = invocation_document()
        invocation = ActionInvocation.from_dict(document)
        self.assertEqual(
            tuple(item["resource_id"] for item in invocation.fencing_tokens),
            invocation.resources,
        )

        for mutation in ("missing", "extra", "reordered", "wrong-resource"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(document)
                fences = changed["fencing_tokens"]
                assert isinstance(fences, list)
                if mutation == "missing":
                    fences.pop()
                elif mutation == "extra":
                    fences.append({"resource_id": "target:other", "token": 1})
                elif mutation == "reordered":
                    fences.reverse()
                else:
                    assert isinstance(fences[0], dict)
                    fences[0]["resource_id"] = "target:other"
                changed["invocation_digest"] = ActionInvocation.digest_document(changed)
                with self.assertRaises(ActionAdapterContractError):
                    ActionInvocation.from_dict(changed)

        for field in ActionInvocation.binding_fields():
            with self.subTest(field=field):
                changed = copy.deepcopy(document)
                changed[field] = digest(field) if field.endswith("_digest") else "substituted"
                with self.assertRaises(ActionAdapterContractError):
                    ActionInvocation.from_dict(changed)

    def test_gew_act_003_receipt_rebinds_invocation_and_the_complete_fence_tuple(self) -> None:
        invocation = ActionInvocation.from_dict(invocation_document())
        receipt = ActionReceipt.from_dict(receipt_document(invocation))
        receipt.require_invocation(invocation)

        for field in ActionReceipt.invocation_binding_fields():
            with self.subTest(field=field):
                changed = receipt_document(invocation)
                if field == "fencing_tokens":
                    assert isinstance(changed[field], list)
                    changed[field] = list(reversed(changed[field]))
                elif field == "resources":
                    changed[field] = ["target:project"]
                else:
                    changed[field] = digest(field) if field.endswith("_digest") else "substituted"
                changed["receipt_digest"] = ActionReceipt.digest_document(changed)
                with self.assertRaises(ActionAdapterContractError):
                    candidate = ActionReceipt.from_dict(changed)
                    candidate.require_invocation(invocation)

    def test_gew_act_004_observation_is_fresh_and_rebinds_receipt_without_substitution(self) -> None:
        invocation = ActionInvocation.from_dict(invocation_document())
        receipt = ActionReceipt.from_dict(receipt_document(invocation))
        observation = TargetObservation.from_dict(observation_document(receipt))
        observation.require_receipt(receipt)

        for field in TargetObservation.receipt_binding_fields():
            with self.subTest(field=field):
                changed = observation_document(receipt)
                if field == "fencing_tokens":
                    assert isinstance(changed[field], list)
                    changed[field] = list(reversed(changed[field]))
                elif field == "resources":
                    changed[field] = ["target:project"]
                else:
                    changed[field] = digest(field) if field.endswith("_digest") else "substituted"
                changed["observation_digest"] = TargetObservation.digest_document(changed)
                with self.assertRaises(ActionAdapterContractError):
                    candidate = TargetObservation.from_dict(changed)
                    candidate.require_receipt(receipt)

        stale = observation_document(receipt)
        stale["fresh"] = False
        stale["observation_digest"] = TargetObservation.digest_document(stale)
        with self.assertRaises(ActionAdapterContractError):
            TargetObservation.from_dict(stale)


if __name__ == "__main__":
    unittest.main()
