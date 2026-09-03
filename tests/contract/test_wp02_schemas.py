from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.digest import (  # noqa: E402
    DigestProjection,
    validate_projection_schema_pair,
)
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry  # noqa: E402
from graph_engineering.core.contracts.geel import PredicateRegistry  # noqa: E402
from graph_engineering.core.contracts.immutable import thaw  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy, validate_schema_profile  # noqa: E402
from graph_engineering.core.graph.state import ArtifactRef, EvidenceRef, TaskSnapshot  # noqa: E402
from graph_engineering.core.graph.budget import LoopBudget, LoopBudgetRegistry  # noqa: E402
from graph_engineering.core.graph.completion import CompletionPolicyRegistry  # noqa: E402

class WP02SchemaTests(unittest.TestCase):
    def test_digest_projection_schema_pair_tamper_is_rejected(self) -> None:
        paths = tuple(
            ROOT / "config" / "contracts" / "schemas" / name
            for name in (
                "completion-policy-1.0.0.json", "completion-policy-registry-1.0.0.json",
                "graph-definition-1.0.0.json", "graph-definition-digest-input-1.0.0.json",
                "loop-budget-1.0.0.json", "loop-budget-registry-1.0.0.json",
                "node-payload-1.0.0.json", "task-snapshot-1.0.0.json",
                "task-snapshot-digest-input-1.0.0.json",
            )
        )
        bodies = {json.loads(path.read_text())["$id"]: path.read_bytes() for path in paths}
        profile = ResourceProfile.from_dict(
            json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        )
        policy = SchemaProfilePolicy.from_dict(
            json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text())
        )
        manifest = json.loads(
            (ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text()
        )
        registry = ClosedSchemaRegistry.build(manifest, bodies, profile, policy)
        cases = (
            (
                "urn:gew:schema:graph-definition:1.0.0",
                "urn:gew:schema:graph-definition-digest-input:1.0.0",
                DigestProjection(
                    "urn:gew:digest-projection:graph-definition:1.0.0",
                    "urn:gew:schema:graph-definition:1.0.0",
                    "urn:gew:schema:graph-definition-digest-input:1.0.0",
                    "digest", "urn:gew:contract:graph-definition",
                    "urn:gew:schema:graph-definition-digest-input:1.0.0",
                ),
            ),
            (
                "urn:gew:schema:task-snapshot:1.0.0",
                "urn:gew:schema:task-snapshot-digest-input:1.0.0",
                DigestProjection(
                    "urn:gew:digest-projection:task-snapshot:1.0.0",
                    "urn:gew:schema:task-snapshot:1.0.0",
                    "urn:gew:schema:task-snapshot-digest-input:1.0.0",
                    "snapshot_digest", "urn:gew:contract:task-snapshot",
                    "urn:gew:schema:task-snapshot-digest-input:1.0.0",
                ),
            ),
        )
        for source_id, input_id, projection in cases:
            tampered = thaw(registry.resource(input_id).schema)
            tampered["properties"]["task_revision" if "task-snapshot" in input_id else "graph_id"] = {"type": "null"}
            with self.subTest(input_id=input_id), self.assertRaisesRegex(ValueError, "structural diff"):
                validate_projection_schema_pair(
                    registry.resource(source_id).schema, tampered, projection,
                )

    def test_graph_and_snapshot_schemas_are_profile_valid_closed_and_executable(self) -> None:
        paths = (
            ROOT / "config" / "contracts" / "schemas" / "completion-policy-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "completion-policy-registry-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "graph-definition-digest-input-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "graph-definition-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "loop-budget-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "loop-budget-registry-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "node-payload-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "task-snapshot-1.0.0.json",
            ROOT / "config" / "contracts" / "schemas" / "task-snapshot-digest-input-1.0.0.json",
        )
        bodies = {json.loads(path.read_text())["$id"]: path.read_bytes() for path in paths}
        policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
        for schema_id, body in bodies.items():
            self.assertEqual(validate_schema_profile(json.loads(body), policy), schema_id)
        profile = ResourceProfile.from_dict(json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()))
        schedule = CostSchedule.from_dict(json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()))
        manifest = json.loads((ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text())
        self.assertEqual(
            manifest,
            ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:graph-kernel:1.0.0", bodies),
        )
        context = WorkContext(profile, schedule)
        registry = ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)
        validate_projection_schema_pair(
            registry.resource("urn:gew:schema:graph-definition:1.0.0").schema,
            registry.resource("urn:gew:schema:graph-definition-digest-input:1.0.0").schema,
            DigestProjection(
                projection_id="urn:gew:digest-projection:graph-definition:1.0.0",
                source_schema_id="urn:gew:schema:graph-definition:1.0.0",
                digest_input_schema_id="urn:gew:schema:graph-definition-digest-input:1.0.0",
                derived_field="digest",
                contract_type="urn:gew:contract:graph-definition",
                schema_id="urn:gew:schema:graph-definition-digest-input:1.0.0",
            ),
        )
        validate_projection_schema_pair(
            registry.resource("urn:gew:schema:task-snapshot:1.0.0").schema,
            registry.resource(
                "urn:gew:schema:task-snapshot-digest-input:1.0.0"
            ).schema,
            DigestProjection(
                projection_id="urn:gew:digest-projection:task-snapshot:1.0.0",
                source_schema_id="urn:gew:schema:task-snapshot:1.0.0",
                digest_input_schema_id=(
                    "urn:gew:schema:task-snapshot-digest-input:1.0.0"
                ),
                derived_field="snapshot_digest",
                contract_type="urn:gew:contract:task-snapshot",
                schema_id="urn:gew:schema:task-snapshot-digest-input:1.0.0",
            ),
        )
        predicates = PredicateRegistry.from_dict(
            json.loads((ROOT / "config" / "contracts" / "predicate-registry-v1.json").read_text())
        )
        error_rules = ErrorRuleRegistry.from_dict(
            json.loads((ROOT / "config" / "contracts" / "error-rule-registry-v1.json").read_text())
        )
        graph = json.loads((ROOT / "tests" / "fixtures" / "wp02-graph-definition.json").read_text())
        self.assertEqual(registry.validate("urn:gew:schema:graph-definition:1.0.0", graph, context), [])
        budget_document = json.loads((ROOT / "config" / "contracts" / "loop-budgets-v1.json").read_text())
        budget = budget_document["budgets"][0]
        self.assertEqual(registry.validate("urn:gew:schema:loop-budget:1.0.0", budget, context), [])
        loaded_budget = LoopBudget.from_dict(
            budget, schema_registry=registry, predicates=predicates,
            error_rules=error_rules, context=context,
        )
        self.assertEqual(loaded_budget.budget_id, "loop:bounded-v1")
        loaded_registry = LoopBudgetRegistry.from_dict(
            budget_document, schema_registry=registry, predicates=predicates,
            error_rules=error_rules, context=context,
        )
        self.assertEqual(loaded_registry.resolve("loop:bounded-v1").budget_id, budget["budget_id"])
        self.assertTrue(loaded_budget.allows_next(
            attempts_used=0, revisions_used=0, total_runs_used=0, context=context,
        ))
        self.assertEqual(registry.validate("urn:gew:schema:loop-budget-registry:1.0.0", budget_document, context), [])
        completion_document = json.loads((ROOT / "config" / "contracts" / "completion-policies-v1.json").read_text())
        completion = CompletionPolicyRegistry.from_dict(
            completion_document, schema_registry=registry, predicates=predicates,
            error_rules=error_rules, context=context,
        ).resolve("completion:all-required-v1")
        self.assertTrue(completion.satisfied(("finish",), ("finish",), context))
        self.assertEqual(registry.validate(
            "urn:gew:schema:completion-policy-registry:1.0.0", completion_document, context,
        ), [])
        snapshot = TaskSnapshot(
            1,
            "ready",
            1,
            {"task_id": "task-1", "owner_id": "owner-1", "runtime_kind": "codex", "runtime_lineage_id": "lineage-1"},
            {"scope_id": "scope-1", "version": 1, "digest": "scope-digest", "status": "frozen"},
            ({"kind": "intent", "version": 1, "digest": "baseline", "approved_by": "owner-1", "approved_at": "2026-08-14T00:00:00Z"},),
            {"graph_id": "delivery", "graph_version": "1.0.0", "graph_digest": "sha256-jcs-v1:" + "1" * 64, "profile_id": "new-feature", "profile_version": "1.0.0", "risk_path": "full-planned"},
            {},
            ("authority-1",),
            (ArtifactRef("artifact-1", "prd", "contract:prd-v1", 1, "artifact-digest", "independently_reviewed"),),
            (EvidenceRef("evidence-1", "test", "run-1", "evidence-digest", "validated"),),
            (),
            {},
            (),
            (),
            None,
            0,
            {
                "schema_registry": {"registry_id": registry.registry_id, "registry_digest": registry.registry_digest},
                "resource_profile": {"profile_id": context.profile.profile_id, "body_digest": context.profile.body_digest},
                "cost_schedule": {"schedule_id": context.schedule.schedule_id, "body_digest": context.schedule.body_digest},
            },
            registry,
            context,
        )
        self.assertEqual(registry.validate("urn:gew:schema:task-snapshot:1.0.0", snapshot.to_dict(), context), [])
        discovering = TaskSnapshot(
            1, "discovering", 1,
            {"task_id": "task-2", "owner_id": "owner-1", "runtime_kind": "hermes", "runtime_lineage_id": "lineage-2"},
            {}, (), {}, {}, (), (), (), (), {}, (), (), None, 0,
            {
                "schema_registry": {"registry_id": registry.registry_id, "registry_digest": registry.registry_digest},
                "resource_profile": {"profile_id": context.profile.profile_id, "body_digest": context.profile.body_digest},
                "cost_schedule": {"schedule_id": context.schedule.schedule_id, "body_digest": context.schedule.body_digest},
            },
            registry, context,
        )
        self.assertEqual(registry.validate(
            "urn:gew:schema:task-snapshot:1.0.0", discovering.to_dict(), context,
        ), [])

    def test_graph_registry_and_snapshot_schema_reject_unknown_properties(self) -> None:
        paths = tuple(
            ROOT / "config" / "contracts" / "schemas" / name
            for name in (
                "completion-policy-1.0.0.json", "completion-policy-registry-1.0.0.json",
                "graph-definition-digest-input-1.0.0.json", "graph-definition-1.0.0.json",
                "loop-budget-1.0.0.json",
                "loop-budget-registry-1.0.0.json", "node-payload-1.0.0.json",
                "task-snapshot-1.0.0.json",
                "task-snapshot-digest-input-1.0.0.json",
            )
        )
        bodies = {json.loads(path.read_text())["$id"]: path.read_bytes() for path in paths}
        profile = ResourceProfile.from_dict(json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()))
        policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
        schedule = CostSchedule.from_dict(json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()))
        manifest = json.loads((ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text())
        registry = ClosedSchemaRegistry.build(manifest, bodies, profile, policy)
        graph = json.loads((ROOT / "tests" / "fixtures" / "wp02-graph-definition.json").read_text())
        graph["unknown"] = True
        self.assertTrue(registry.validate(
            "urn:gew:schema:graph-definition:1.0.0", graph, WorkContext(profile, schedule),
        ))
        tampered = json.loads(json.dumps(manifest))
        tampered["resources"][0]["body_digest"] = "sha256-raw-v1:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            ClosedSchemaRegistry.build(tampered, bodies, profile, policy)


if __name__ == "__main__":
    unittest.main()
