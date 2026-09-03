from __future__ import annotations

import copy
import json
import pathlib
import unittest

from graph_engineering.core.actions import (
    ActionContractError,
    AuthorityEnvelope,
    IntentBaseline,
    PreparedAction,
)
from graph_engineering.core.contracts.digest import semantic_digest
from tests.support.wp05a_security import security_context


ROOT = pathlib.Path(__file__).resolve().parents[2]
IDENTITY = "urn:gew:digest-projection:identity:1.0.0"
CONTEXT = security_context()


def digest(label: str) -> str:
    return semantic_digest(
        {"label": label},
        contract_type="urn:gew:contract:wp05-test-value",
        projection_id=IDENTITY,
        schema_id="urn:gew:schema:wp05-test-value:1.0.0",
    )


def prepared_document() -> dict[str, object]:
    payload = {"set": {"version": 2}}
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "action_id": "action-wp05",
        "task_id": "task-wp05",
        "action_kind": "commit",
        "target_id": "target-project",
        "target_digest": digest("target"),
        "resources": ["target:project", "task:task-wp05"],
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, CONTEXT),
        "precondition": {"version": 1},
        "expected_postcondition": {"version": 2},
        "idempotency_class": "non-idempotent",
        "idempotency_key": "idempotency-wp05",
        "verification_plan": {"capability": "fresh-target-query", "predicate": "exact"},
        "rollback_plan": {"capability": "fake-compensation", "set": {"version": 1}},
        "required_capabilities": ["deterministic-fake-target-v1", "fresh-target-query"],
        "baseline_digest": digest("intent"),
        "snapshot_digest": digest("snapshot"),
    }
    value["prepared_action_digest"] = PreparedAction.digest_document(value, CONTEXT)
    return value


class WP05ActionContractTests(unittest.TestCase):
    def test_intent_authority_and_prepared_action_are_exact_and_digest_bound(self) -> None:
        baseline_value: dict[str, object] = {
            "schema_version": "1.0.0",
            "task_id": "task-wp05",
            "baseline_digest": digest("intent"),
            "approved_by": "owner-wp05",
            "approved_at": "2026-08-14T00:00:00Z",
        }
        baseline_value["record_digest"] = IntentBaseline.digest_document(baseline_value)
        self.assertEqual(IntentBaseline.from_dict(baseline_value).task_id, "task-wp05")

        prepared = PreparedAction.from_dict(prepared_document(), context=CONTEXT)
        authority_value: dict[str, object] = {
            "schema_version": "1.0.0",
            "authority_id": "authority-wp05",
            "task_id": prepared.task_id,
            "owner_id": "owner-wp05",
            "runtime_kind": "codex",
            "runtime_lineage_id": "lineage-wp05",
            "authorized_action_kind": prepared.action_kind,
            "authorized_resources": list(prepared.resources),
            "prepared_action_digest": prepared.prepared_action_digest,
            "baseline_digest": prepared.baseline_digest,
            "snapshot_digest": prepared.snapshot_digest,
            "issued_at": "2026-08-14T00:00:00Z",
            "expires_at": "2026-08-14T01:00:00Z",
            "status": "active",
        }
        authority_value["authority_digest"] = AuthorityEnvelope.digest_document(authority_value, CONTEXT)
        authority = AuthorityEnvelope.from_dict(authority_value, context=CONTEXT)
        self.assertEqual(authority.authorized_action_kind, "commit")

        for field in prepared_document():
            with self.subTest(field=field):
                changed = copy.deepcopy(prepared_document())
                changed.pop(field)
                with self.assertRaises(ActionContractError):
                    PreparedAction.from_dict(changed, context=CONTEXT)

    def test_irreversible_actions_are_separate_configured_authority_classes(self) -> None:
        policy = json.loads((ROOT / "config" / "actions" / "action-policy-v1.json").read_text())
        self.assertFalse(policy["real_external_actions_enabled"])
        self.assertEqual(
            set(policy["separately_authorized_action_kinds"]),
            {"commit", "push", "merge", "deploy", "release", "external-communication", "rollback"},
        )
        self.assertEqual(policy["enabled_adapter_capabilities"], ["deterministic-fake-target-v1"])


if __name__ == "__main__":
    unittest.main()
