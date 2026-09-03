from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.geel import PredicateRegistry  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.graph.definition import GraphDefinition, GraphValidationError  # noqa: E402
from graph_engineering.core.graph.budget import LoopBudgetRegistry  # noqa: E402
from graph_engineering.core.graph.completion import CompletionPolicyRegistry  # noqa: E402


GRAPH_CONTRACT = "urn:gew:contract:graph-definition"
GRAPH_PROJECTION = "urn:gew:digest-projection:graph-definition:1.0.0"
GRAPH_SCHEMA = "urn:gew:schema:graph-definition:1.0.0"
GRAPH_DIGEST_INPUT_SCHEMA = "urn:gew:schema:graph-definition-digest-input:1.0.0"
NODE_SCHEMA = "urn:gew:schema:node-payload:1.0.0"


def complete(candidate: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(candidate)
    result["digest"] = semantic_digest(
        result,
        contract_type=GRAPH_CONTRACT,
        projection_id=GRAPH_PROJECTION,
        schema_id=GRAPH_DIGEST_INPUT_SCHEMA,
    )
    return result


def registry_pins() -> dict[str, object]:
    files = {
        "schema": "graph-schema-registry-v1.json",
        "predicate": "predicate-registry-v1.json",
        "error_rule": "error-rule-registry-v1.json",
        "completion_policy": "completion-policies-v1.json",
        "loop_budget": "loop-budgets-v1.json",
    }
    result: dict[str, object] = {}
    for name, filename in files.items():
        document = json.loads((ROOT / "config" / "contracts" / filename).read_text())
        digest = document.get("registry_digest")
        if name in {"completion_policy", "loop_budget"}:
            digest = semantic_digest(
                document,
                contract_type=(
                    "urn:gew:contract:completion-policy-registry"
                    if name == "completion_policy"
                    else "urn:gew:contract:loop-budget-registry"
                ),
                projection_id="urn:gew:digest-projection:identity:1.0.0",
                schema_id=(
                    "urn:gew:schema:completion-policy-registry:1.0.0"
                    if name == "completion_policy"
                    else "urn:gew:schema:loop-budget-registry:1.0.0"
                ),
            )
        result[name] = {
            "registry_id": document["registry_id"],
            "registry_digest": digest,
        }
    return result


def resource_pins(
    profile: ResourceProfile | None = None,
    schedule: CostSchedule | None = None,
) -> dict[str, object]:
    profile = profile or ResourceProfile.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()
    ))
    schedule = schedule or CostSchedule.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()
    ))
    return {
        "resource_profile": {
            "profile_id": profile.profile_id,
            "body_digest": profile.body_digest,
        },
        "cost_schedule": {
            "schedule_id": schedule.schedule_id,
            "body_digest": schedule.body_digest,
        },
    }


def graph_candidate() -> dict[str, object]:
    node = {
        "node_kind": "deterministic",
        "input_schema_ref": NODE_SCHEMA,
        "output_schema_ref": NODE_SCHEMA,
        "executor_capability": "core:test",
        "authority_requirement": "none",
        "side_effect_class": "none",
        "review_policy_ref": "review:deterministic-v1",
        "loop_budget_ref": None,
        "timeout_policy_ref": "timeout:default-v1",
        "artifact_contract_refs": [],
        "failure_routes": {},
        "invalidation_tags": ["input"],
    }
    return {
        "schema_version": "1.0.0",
        "graph_id": "test-delivery",
        "graph_version": "1.0.0",
        "completion_policy_ref": "completion:all-required-v1",
        "registry_pins": registry_pins(),
        "resource_pins": resource_pins(),
        "trust_policy": {
            "levels": ["candidate", "validated", "independently_reviewed"],
            "upgrades": [
                {"from": "candidate", "to": "validated"},
                {"from": "validated", "to": "independently_reviewed"},
            ],
        },
        "condition_roots": [
            {"root": "from_output", "tokens": [], "value_type": "object"},
            {"root": "from_output", "tokens": ["enabled"], "value_type": "boolean"},
        ],
        "nodes": [
            {**node, "node_id": "start", "entrypoint": True, "completion_eligible": False},
            {**node, "node_id": "finish", "entrypoint": False, "completion_eligible": True},
        ],
        "edges": [
            {
                "edge_id": "start-to-finish",
                "from_node": "start",
                "to_node": "finish",
                "input_mapping": [{"source_path": [], "target_path": []}],
                "target_input_schema_ref": NODE_SCHEMA,
                "route_condition": {"op": "literal", "value": True},
                "route_priority": 1,
                "required_trust": "validated",
                "evidence_requirements": ["schema-validation"],
                "join_policy": {"kind": "all_required", "quorum": None},
                "invalidation_rule": "propagate",
                "failure_route": None,
            }
        ],
    }


def loop_budgets(
    schemas: ClosedSchemaRegistry | None = None,
    predicates: PredicateRegistry | None = None,
    error_rules: ErrorRuleRegistry | None = None,
    context: WorkContext | None = None,
) -> LoopBudgetRegistry:
    document = json.loads((ROOT / "config" / "contracts" / "loop-budgets-v1.json").read_text())
    return LoopBudgetRegistry.from_dict(
        document,
        schema_registry=graph_schemas() if schemas is None else schemas,
        predicates=predicate_registry() if predicates is None else predicates,
        error_rules=error_rule_registry() if error_rules is None else error_rules,
        context=work_context() if context is None else context,
    )


def completion_policies(
    schemas: ClosedSchemaRegistry | None = None,
    predicates: PredicateRegistry | None = None,
    error_rules: ErrorRuleRegistry | None = None,
    context: WorkContext | None = None,
) -> CompletionPolicyRegistry:
    document = json.loads((ROOT / "config" / "contracts" / "completion-policies-v1.json").read_text())
    return CompletionPolicyRegistry.from_dict(
        document,
        schema_registry=graph_schemas() if schemas is None else schemas,
        predicates=predicate_registry() if predicates is None else predicates,
        error_rules=error_rule_registry() if error_rules is None else error_rules,
        context=work_context() if context is None else context,
    )


def graph_schemas(additional: dict[str, bytes] | None = None) -> ClosedSchemaRegistry:
    names = {
        "completion-policy-1.0.0.json", "completion-policy-registry-1.0.0.json",
        "graph-definition-digest-input-1.0.0.json", "graph-definition-1.0.0.json",
        "loop-budget-1.0.0.json",
        "loop-budget-registry-1.0.0.json", "node-payload-1.0.0.json",
        "task-snapshot-1.0.0.json", "task-snapshot-digest-input-1.0.0.json",
    }
    paths = tuple(
        path for path in sorted((ROOT / "config" / "contracts" / "schemas").glob("*.json"))
        if path.name in names
    )
    bodies = {json.loads(path.read_text())["$id"]: path.read_bytes() for path in paths}
    bodies.update({} if additional is None else additional)
    profile = ResourceProfile.from_dict(json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()))
    policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
    manifest = (
        json.loads((ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text())
        if additional is None
        else ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:graph-test:1.0.0", bodies)
    )
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy)


def work_context(
    budget: int | None = None,
    limit_overrides: dict[str, int] | None = None,
) -> WorkContext:
    profile = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
    if limit_overrides is not None:
        profile["limits"].update(limit_overrides)
    return WorkContext(
        ResourceProfile.from_dict(profile),
        CostSchedule.from_dict(json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())),
        initial_balance=budget,
    )


def predicate_registry() -> PredicateRegistry:
    return PredicateRegistry.from_dict(
        json.loads((ROOT / "config" / "contracts" / "predicate-registry-v1.json").read_text())
    )


def error_rule_registry() -> ErrorRuleRegistry:
    return ErrorRuleRegistry.from_dict(
        json.loads((ROOT / "config" / "contracts" / "error-rule-registry-v1.json").read_text())
    )


def load_graph(
    value: dict[str, object],
    *,
    schemas: ClosedSchemaRegistry | None = None,
    context: WorkContext | None = None,
    loop_registry: LoopBudgetRegistry | None = None,
) -> GraphDefinition:
    active_schemas = graph_schemas() if schemas is None else schemas
    active_context = work_context() if context is None else context
    predicates = predicate_registry()
    error_rules = error_rule_registry()
    return GraphDefinition.from_dict(
        value,
        schema_registry=active_schemas,
        predicates=predicates,
        error_rules=error_rules,
        context=active_context,
        completion_policies=completion_policies(
            active_schemas, predicates, error_rules, active_context,
        ),
        loop_budgets=(
            loop_budgets(active_schemas, predicates, error_rules, active_context)
            if loop_registry is None else loop_registry
        ),
    )


class GraphDefinitionTests(unittest.TestCase):
    def test_graph_self_digest_is_schema_projected_charged_and_budget_bounded(self) -> None:
        schemas = graph_schemas()
        predicates = predicate_registry()
        error_rules = error_rule_registry()
        registry_context = work_context()
        completions = completion_policies(
            schemas, predicates, error_rules, registry_context,
        )
        budgets = loop_budgets(schemas, predicates, error_rules, registry_context)
        measured = work_context()
        created = GraphDefinition.create(
            graph_candidate(), schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=measured,
            completion_policies=completions, loop_budgets=budgets,
        )
        self.assertEqual(created, complete(graph_candidate()))
        events = [item["event_id"] for item in measured.trace]
        self.assertIn("schema.keyword", events)
        self.assertIn("canonical.output_byte", events)
        self.assertIn("digest.input_byte", events)
        spent = measured.profile.work_budget - measured.balance
        exact = work_context(spent)
        GraphDefinition.create(
            graph_candidate(), schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=exact,
            completion_policies=completions, loop_budgets=budgets,
        )
        self.assertEqual(exact.balance, 0)
        insufficient = work_context(spent - 1)
        with self.assertRaises(ContractError) as captured:
            GraphDefinition.create(
                graph_candidate(), schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=insufficient,
                completion_policies=completions, loop_budgets=budgets,
            )
        self.assertEqual(captured.exception.detail.code, "E_BUDGET")
        self.assertEqual(insufficient.trace[-1]["status"], "rejected")
        limited = work_context(limit_overrides={"result_bytes": 1})
        limited_candidate = graph_candidate()
        limited_candidate["resource_pins"] = resource_pins(
            limited.profile, limited.schedule,
        )
        with self.assertRaises(ContractError) as captured_limit:
            GraphDefinition.create(
                limited_candidate, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=limited,
                completion_policies=completions, loop_budgets=budgets,
            )
        self.assertEqual(captured_limit.exception.detail.code, "E_LIMIT")

    def test_policy_registries_use_schema_digest_and_geel_contracts(self) -> None:
        schemas = graph_schemas()
        predicates = predicate_registry()
        error_rules = error_rule_registry()
        completion_document = json.loads(
            (ROOT / "config" / "contracts" / "completion-policies-v1.json").read_text()
        )
        completion_load = work_context()
        completions = CompletionPolicyRegistry.from_dict(
            completion_document, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=completion_load,
        )
        completion_spent = completion_load.profile.work_budget - completion_load.balance
        exact_completion_load = work_context(completion_spent)
        CompletionPolicyRegistry.from_dict(
            completion_document, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=exact_completion_load,
        )
        self.assertEqual(exact_completion_load.balance, 0)
        insufficient_completion_load = work_context(completion_spent - 1)
        with self.assertRaises(ContractError) as completion_budget_error:
            CompletionPolicyRegistry.from_dict(
                completion_document, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=insufficient_completion_load,
            )
        self.assertEqual(completion_budget_error.exception.detail.code, "E_BUDGET")

        budget_document = json.loads(
            (ROOT / "config" / "contracts" / "loop-budgets-v1.json").read_text()
        )
        budget_load = work_context()
        budgets = LoopBudgetRegistry.from_dict(
            budget_document, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=budget_load,
        )
        budget_spent = budget_load.profile.work_budget - budget_load.balance
        exact_budget_load = work_context(budget_spent)
        LoopBudgetRegistry.from_dict(
            budget_document, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=exact_budget_load,
        )
        self.assertEqual(exact_budget_load.balance, 0)
        insufficient_budget_load = work_context(budget_spent - 1)
        with self.assertRaises(ContractError) as budget_error:
            LoopBudgetRegistry.from_dict(
                budget_document, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=insufficient_budget_load,
            )
        self.assertEqual(budget_error.exception.detail.code, "E_BUDGET")

        load_events = [
            item["event_id"] for item in (*completion_load.trace, *budget_load.trace)
        ]
        self.assertIn("schema.keyword", load_events)
        self.assertIn("canonical.output_byte", load_events)
        self.assertIn("digest.input_byte", load_events)

        completion_context = work_context()
        self.assertTrue(completions.resolve("completion:all-required-v1").satisfied(
            ("finish",), ("finish",), completion_context,
        ))
        completion_evaluation_spent = (
            completion_context.profile.work_budget - completion_context.balance
        )
        exact_completion_evaluation = work_context(completion_evaluation_spent)
        self.assertTrue(completions.resolve("completion:all-required-v1").satisfied(
            ("finish",), ("finish",), exact_completion_evaluation,
        ))
        self.assertEqual(exact_completion_evaluation.balance, 0)
        with self.assertRaisesRegex(ValueError, "failed closed"):
            completions.resolve("completion:all-required-v1").satisfied(
                ("finish",), ("finish",),
                work_context(completion_evaluation_spent - 1),
            )
        budget_context = work_context()
        self.assertTrue(budgets.resolve("loop:bounded-v1").allows_next(
            attempts_used=0, revisions_used=0, total_runs_used=0, context=budget_context,
        ))
        budget_evaluation_spent = budget_context.profile.work_budget - budget_context.balance
        exact_budget_evaluation = work_context(budget_evaluation_spent)
        self.assertTrue(budgets.resolve("loop:bounded-v1").allows_next(
            attempts_used=0, revisions_used=0, total_runs_used=0,
            context=exact_budget_evaluation,
        ))
        self.assertEqual(exact_budget_evaluation.balance, 0)
        with self.assertRaisesRegex(ValueError, "failed closed"):
            budgets.resolve("loop:bounded-v1").allows_next(
                attempts_used=0, revisions_used=0, total_runs_used=0,
                context=work_context(budget_evaluation_spent - 1),
            )
        self.assertIn("geel.node", [item["event_id"] for item in completion_context.trace])
        self.assertIn("geel.node", [item["event_id"] for item in budget_context.trace])

        invalid_completion = json.loads(
            (ROOT / "config" / "contracts" / "completion-policies-v1.json").read_text()
        )
        invalid_completion["policies"][0]["version"] = "v" * 65
        with self.assertRaisesRegex(ValueError, "schema validation"):
            CompletionPolicyRegistry.from_dict(
                invalid_completion, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=work_context(),
            )
        invalid_budget = json.loads(
            (ROOT / "config" / "contracts" / "loop-budgets-v1.json").read_text()
        )
        invalid_budget["budgets"][0]["version"] = "v" * 65
        with self.assertRaisesRegex(ValueError, "schema validation"):
            LoopBudgetRegistry.from_dict(
                invalid_budget, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=work_context(),
            )

    def test_loop_budget_registry_allows_last_slot_and_rejects_exhausted_counter(self) -> None:
        budget = loop_budgets().resolve("loop:bounded-v1")
        self.assertTrue(budget.allows_next(
            attempts_used=budget.max_attempts - 1,
            revisions_used=budget.max_revisions - 1,
            total_runs_used=budget.max_total_runs - 1,
            context=work_context(),
        ))
        self.assertFalse(budget.allows_next(
            attempts_used=budget.max_attempts,
            revisions_used=0,
            total_runs_used=0,
            context=work_context(),
        ))

    def test_valid_graph_is_immutable_digest_bound_and_deterministic(self) -> None:
        source = complete(graph_candidate())
        schemas = graph_schemas()
        first = load_graph(source, schemas=schemas)
        second = load_graph(json.loads(json.dumps(source, sort_keys=True)), schemas=schemas)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.entrypoints, ("start",))
        self.assertEqual(first.completion_nodes, ("finish",))
        self.assertTrue(first.completion_ready(("finish",), work_context()))
        self.assertFalse(first.completion_ready((), work_context()))
        self.assertEqual(first.outgoing("start")[0].edge_id, "start-to-finish")
        self.assertTrue(first.trust_policy.satisfies("independently_reviewed", "validated"))
        with self.assertRaises((AttributeError, TypeError)):
            first.nodes["start"] = first.nodes["finish"]  # type: ignore[index]
        tampered = copy.deepcopy(source)
        tampered["nodes"][0]["executor_capability"] = "core:changed"  # type: ignore[index]
        with self.assertRaisesRegex(GraphValidationError, "digest"):
            load_graph(tampered, schemas=schemas)
        unknown_completion = graph_candidate()
        unknown_completion["completion_policy_ref"] = "completion:unknown-v1"
        with self.assertRaisesRegex(GraphValidationError, "completion policy"):
            load_graph(complete(unknown_completion), schemas=schemas)
        wrong_pin = graph_candidate()
        wrong_pin["registry_pins"]["predicate"]["registry_digest"] = "sha256-jcs-v1:" + "0" * 64  # type: ignore[index]
        with self.assertRaisesRegex(GraphValidationError, "predicate registry pin"):
            load_graph(complete(wrong_pin), schemas=schemas)

    def test_graph_exact_pins_reject_registry_profile_schedule_and_content_drift(self) -> None:
        source = complete(graph_candidate())
        graph = load_graph(source)
        extra_schema = json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:gew:schema:rogue:1.0.0",
            "type": "object",
            "properties": {"schema_version": {"const": "1.0.0"}},
            "required": ["schema_version"],
            "unevaluatedProperties": False,
        }, separators=(",", ":")).encode()
        with self.assertRaisesRegex(GraphValidationError, "schema registry pin mismatch"):
            load_graph(source, schemas=graph_schemas({
                "urn:gew:schema:rogue:1.0.0": extra_schema,
            }))

        changed_profile_value = json.loads(
            (ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()
        )
        changed_profile_value["limits"]["ast_nodes"] -= 1
        changed_profile = ResourceProfile.from_dict(changed_profile_value)
        schedule = CostSchedule.from_dict(json.loads(
            (ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()
        ))
        with self.assertRaisesRegex(GraphValidationError, "resource_profile pin mismatch"):
            load_graph(source, context=WorkContext(changed_profile, schedule))

        changed_schedule_value = json.loads(
            (ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()
        )
        changed_schedule_value["coefficients"]["schema.keyword"] += 1
        changed_schedule = CostSchedule.from_dict(changed_schedule_value)
        with self.assertRaisesRegex(GraphValidationError, "cost_schedule pin mismatch"):
            load_graph(source, context=WorkContext(work_context().profile, changed_schedule))
        with self.assertRaisesRegex(GraphValidationError, "cost_schedule pin mismatch"):
            graph.completion_ready(("finish",), WorkContext(work_context().profile, changed_schedule))

        drifted = copy.deepcopy(source)
        drifted["nodes"][0]["executor_capability"] = "core:drifted"  # type: ignore[index]
        with self.assertRaisesRegex(GraphValidationError, "digest"):
            load_graph(drifted)

    def test_graph_rejects_unknown_shapes_references_types_and_ambiguity(self) -> None:
        mutations = []
        unknown = graph_candidate()
        unknown["unknown"] = True
        mutations.append(("schema validation", unknown))
        duplicate = graph_candidate()
        duplicate["nodes"].append(copy.deepcopy(duplicate["nodes"][0]))  # type: ignore[union-attr,index]
        mutations.append(("schema validation", duplicate))
        missing_node = graph_candidate()
        missing_node["edges"][0]["to_node"] = "missing"  # type: ignore[index]
        mutations.append(("unknown node", missing_node))
        wrong_schema = graph_candidate()
        wrong_schema["edges"][0]["target_input_schema_ref"] = "urn:gew:schema:wrong:1.0.0"  # type: ignore[index]
        mutations.append(("schema", wrong_schema))
        ambiguous = graph_candidate()
        ambiguous["edges"].append(copy.deepcopy(ambiguous["edges"][0]))  # type: ignore[union-attr,index]
        ambiguous["edges"][1]["edge_id"] = "duplicate-route"  # type: ignore[index]
        ambiguous["edges"][1]["route_condition"] = {"value": True, "op": "literal"}  # type: ignore[index]
        mutations.append(("route", ambiguous))
        bad_fallback = graph_candidate()
        bad_fallback["nodes"][0]["failure_routes"] = {"E_TEST": "missing"}  # type: ignore[index]
        mutations.append(("failure route", bad_fallback))
        bad_join = graph_candidate()
        third = copy.deepcopy(bad_join["nodes"][0])  # type: ignore[index]
        third.update({"node_id": "alternate", "entrypoint": True})
        bad_join["nodes"].append(third)  # type: ignore[union-attr]
        inbound = copy.deepcopy(bad_join["edges"][0])  # type: ignore[index]
        inbound.update({"edge_id": "alternate-to-finish", "from_node": "alternate"})
        inbound["join_policy"] = {"kind": "any_passed", "quorum": None}
        bad_join["edges"].append(inbound)  # type: ignore[union-attr]
        mutations.append(("join", bad_join))
        overlapping = graph_candidate()
        overlapping["edges"][0]["input_mapping"] = [  # type: ignore[index]
            {"source_path": [], "target_path": []},
            {"source_path": ["value"], "target_path": ["value"]},
        ]
        mutations.append(("overlapping", overlapping))
        for message, candidate in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(GraphValidationError, message):
                load_graph(complete(candidate))

    def test_equal_route_conditions_can_fan_out_to_distinct_targets(self) -> None:
        candidate = graph_candidate()
        alternate = copy.deepcopy(candidate["nodes"][1])  # type: ignore[index]
        alternate["node_id"] = "alternate-finish"
        candidate["nodes"].append(alternate)  # type: ignore[union-attr]
        edge = copy.deepcopy(candidate["edges"][0])  # type: ignore[index]
        edge.update({"edge_id": "start-to-alternate", "to_node": "alternate-finish"})
        candidate["edges"].append(edge)  # type: ignore[union-attr]
        graph = load_graph(complete(candidate))
        selected = graph.route(
            "start", {"from_output": {}},
            trust_by_edge={
                "start-to-finish": "validated", "start-to-alternate": "validated",
            },
            evidence_by_edge={
                "start-to-finish": ("schema-validation",),
                "start-to-alternate": ("schema-validation",),
            },
            context=work_context(),
        )
        self.assertEqual(tuple(item.edge_id for item in selected), ("start-to-alternate", "start-to-finish"))

    def test_graph_rejects_unreachable_dead_ends_and_unbudgeted_cycles(self) -> None:
        unreachable = graph_candidate()
        orphan = copy.deepcopy(unreachable["nodes"][0])  # type: ignore[index]
        orphan.update({"node_id": "orphan", "entrypoint": False, "completion_eligible": True})
        unreachable["nodes"].append(orphan)  # type: ignore[union-attr]
        with self.assertRaisesRegex(GraphValidationError, "unreachable"):
            load_graph(complete(unreachable))

        dead_end = graph_candidate()
        trap = copy.deepcopy(dead_end["nodes"][0])  # type: ignore[index]
        trap.update({"node_id": "trap", "entrypoint": False, "completion_eligible": False})
        dead_end["nodes"].append(trap)  # type: ignore[union-attr]
        trap_edge = copy.deepcopy(dead_end["edges"][0])  # type: ignore[index]
        trap_edge.update({"edge_id": "start-to-trap", "to_node": "trap", "route_priority": 2})
        dead_end["edges"].append(trap_edge)  # type: ignore[union-attr]
        with self.assertRaisesRegex(GraphValidationError, "dead-end"):
            load_graph(complete(dead_end))

        cyclic = graph_candidate()
        back = copy.deepcopy(cyclic["edges"][0])  # type: ignore[index]
        back.update({
            "edge_id": "finish-to-start",
            "from_node": "finish",
            "to_node": "start",
            "target_input_schema_ref": NODE_SCHEMA,
        })
        cyclic["edges"].append(back)  # type: ignore[union-attr]
        with self.assertRaisesRegex(GraphValidationError, "loop budget"):
            load_graph(complete(cyclic))
        for node in cyclic["nodes"]:  # type: ignore[union-attr]
            node["loop_budget_ref"] = "loop:bounded-v1"
        registry = loop_budgets()
        budget = registry.resolve("loop:bounded-v1")
        loaded = load_graph(complete(cyclic), loop_registry=registry)
        self.assertEqual(set(loaded.cyclic_nodes), {"start", "finish"})
        self.assertTrue(budget.allows_next(
            attempts_used=0, revisions_used=0, total_runs_used=0, context=work_context(),
        ))
        self.assertTrue(budget.allows_next(
            attempts_used=budget.max_attempts - 1,
            revisions_used=budget.max_revisions - 1,
            total_runs_used=budget.max_total_runs - 1,
            context=work_context(),
        ))
        self.assertFalse(budget.allows_next(
            attempts_used=budget.max_attempts,
            revisions_used=0,
            total_runs_used=0,
            context=work_context(),
        ))

    def test_failure_routes_are_executable_control_topology_and_budgeted(self) -> None:
        candidate = graph_candidate()
        recovery = copy.deepcopy(candidate["nodes"][0])  # type: ignore[index]
        recovery.update({
            "node_id": "recovery",
            "entrypoint": False,
            "completion_eligible": False,
        })
        candidate["nodes"].append(recovery)  # type: ignore[union-attr]
        recovery_edge = copy.deepcopy(candidate["edges"][0])  # type: ignore[index]
        recovery_edge.update({
            "edge_id": "recovery-to-finish",
            "from_node": "recovery",
            "route_priority": 2,
        })
        candidate["edges"].append(recovery_edge)  # type: ignore[union-attr]
        candidate["nodes"][0]["failure_routes"] = {"E_NODE": "recovery"}  # type: ignore[index]
        candidate["edges"][0]["failure_route"] = "recovery"  # type: ignore[index]
        for edge in candidate["edges"]:  # type: ignore[union-attr]
            edge["join_policy"] = {"kind": "any_passed", "quorum": None}

        graph = load_graph(complete(candidate))
        self.assertEqual(graph.failure_target("start", "E_NODE"), "recovery")
        self.assertEqual(
            graph.failure_target("start", "E_OTHER", edge_id="start-to-finish"),
            "recovery",
        )
        self.assertIsNone(graph.failure_target("start", "E_OTHER"))
        with self.assertRaisesRegex(GraphValidationError, "does not leave"):
            graph.failure_target("start", "E_OTHER", edge_id="recovery-to-finish")

        cyclic = copy.deepcopy(candidate)
        cyclic["nodes"][2]["failure_routes"] = {"E_RECOVERY": "start"}  # type: ignore[index]
        with self.assertRaisesRegex(GraphValidationError, "loop budget"):
            load_graph(complete(cyclic))
        cyclic["nodes"][0]["loop_budget_ref"] = "loop:bounded-v1"  # type: ignore[index]
        cyclic["nodes"][2]["loop_budget_ref"] = "loop:bounded-v1"  # type: ignore[index]
        loaded = load_graph(complete(cyclic), loop_registry=loop_budgets())
        self.assertEqual(set(loaded.cyclic_nodes), {"recovery", "start"})

    def test_failure_routes_reject_unrelated_edges_and_unbudgeted_fallback_cycles(self) -> None:
        candidate = graph_candidate()
        candidate["nodes"][1]["failure_routes"] = {"E_BACK": "start"}  # type: ignore[index]
        with self.assertRaisesRegex(GraphValidationError, "loop budget"):
            load_graph(complete(candidate))

        graph = load_graph(complete(graph_candidate()))
        with self.assertRaisesRegex(GraphValidationError, "unknown failure edge"):
            graph.failure_target("start", "E_TEST", edge_id="missing")

    def test_overlapping_route_mapping_targets_fail_closed(self) -> None:
        candidate = graph_candidate()
        candidate["edges"][0]["input_mapping"] = [  # type: ignore[index]
            {"source_path": [], "target_path": []},
            {"source_path": ["value"], "target_path": ["value"]},
        ]
        with self.assertRaisesRegex(GraphValidationError, "overlapping"):
            load_graph(complete(candidate))

    def test_completion_policy_is_closed_digest_bound_and_required_by_graph(self) -> None:
        registry = completion_policies()
        policy = registry.resolve("completion:all-required-v1")
        self.assertTrue(policy.satisfied(("finish",), ("finish",), work_context()))
        self.assertFalse(policy.satisfied(("start",), ("finish",), work_context()))
        document = json.loads((ROOT / "config" / "contracts" / "completion-policies-v1.json").read_text())
        document["policies"][0]["kind"] = "any_passed"
        schemas = graph_schemas()
        predicates = predicate_registry()
        error_rules = error_rule_registry()
        with self.assertRaisesRegex(ValueError, "condition"):
            CompletionPolicyRegistry.from_dict(
                document, schema_registry=schemas, predicates=predicates,
                error_rules=error_rules, context=work_context(),
            )

    def test_unknown_completion_policy_and_invalid_completion_inputs_fail_closed(self) -> None:
        candidate = graph_candidate()
        candidate["completion_policy_ref"] = "completion:unknown-v1"
        with self.assertRaisesRegex(GraphValidationError, "completion policy"):
            load_graph(complete(candidate))
        graph = load_graph(complete(graph_candidate()))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            graph.completion_ready(("finish", "finish"), work_context())

    def test_join_and_trust_semantics_fail_closed(self) -> None:
        graph = load_graph(complete(graph_candidate()))
        policy = graph.edges["start-to-finish"].join_policy
        join_context = work_context()
        self.assertTrue(policy.satisfied((True,), 1, join_context))
        join_spent = join_context.profile.work_budget - join_context.balance
        exact_join = work_context(join_spent)
        self.assertTrue(policy.satisfied((True,), 1, exact_join))
        self.assertEqual(exact_join.balance, 0)
        with self.assertRaisesRegex(GraphValidationError, "failed closed"):
            policy.satisfied((True,), 1, work_context(join_spent - 1))
        self.assertFalse(policy.satisfied((True, False), 1, work_context()))
        self.assertFalse(graph.trust_policy.satisfies("candidate", "validated"))
        with self.assertRaises(GraphValidationError):
            graph.trust_policy.satisfies("unknown", "validated")
        context = work_context()
        self.assertEqual(graph.route(
            "start",
            {"from_output": {}},
            trust_by_edge={"start-to-finish": "independently_reviewed"},
            evidence_by_edge={"start-to-finish": ("schema-validation",)},
            context=context,
        )[0].edge_id, "start-to-finish")
        self.assertEqual(graph.route(
            "start",
            {"from_output": {}},
            trust_by_edge={"start-to-finish": "candidate"},
            evidence_by_edge={"start-to-finish": ("schema-validation",)},
            context=context,
        ), ())
        with self.assertRaisesRegex(GraphValidationError, "unknown edge"):
            graph.route(
                "start", {"from_output": {}},
                trust_by_edge={"unknown": "validated"},
                evidence_by_edge={}, context=context,
            )
        with self.assertRaisesRegex(GraphValidationError, "evidence"):
            graph.route(
                "start", {"from_output": {}},
                trust_by_edge={"start-to-finish": "validated"},
                evidence_by_edge={"start-to-finish": ("schema-validation", "schema-validation")},
                context=context,
            )
        self.assertTrue(graph.join_ready(
            "finish", {"start-to-finish": True}, work_context(),
        ))
        self.assertFalse(graph.join_ready("finish", {}, work_context()))
        self.assertTrue(graph.completion_ready(("finish",), work_context()))
        self.assertFalse(graph.completion_ready(("start",), work_context()))

    def test_nonliteral_route_uses_static_geel_and_typed_mapping_registry(self) -> None:
        candidate = graph_candidate()
        candidate["edges"][0]["route_condition"] = {  # type: ignore[index]
            "op": "path", "root": "from_output", "tokens": ["enabled"],
        }
        candidate["edges"][0]["input_mapping"] = [{"source_path": ["value"], "target_path": ["value"]}]  # type: ignore[index]
        context = work_context()
        graph = load_graph(complete(candidate), context=context)
        selected = graph.route(
            "start", {"from_output": {"enabled": True}},
            trust_by_edge={"start-to-finish": "validated"},
            evidence_by_edge={"start-to-finish": ("schema-validation",)}, context=context,
        )
        self.assertEqual(tuple(edge.edge_id for edge in selected), ("start-to-finish",))
        self.assertEqual(graph.route(
            "start", {"from_output": {"enabled": False}},
            trust_by_edge={"start-to-finish": "validated"},
            evidence_by_edge={"start-to-finish": ("schema-validation",)}, context=context,
        ), ())
        text_body = json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:gew:schema:node-text-payload:1.0.0",
            "type": "object",
            "properties": {"schema_version": {"const": "1.0.0"}, "value": {"type": "string"}},
            "required": ["schema_version"],
            "unevaluatedProperties": False,
        }, sort_keys=True, separators=(",", ":")).encode()
        incompatible = graph_candidate()
        incompatible["nodes"][1]["input_schema_ref"] = "urn:gew:schema:node-text-payload:1.0.0"  # type: ignore[index]
        incompatible["edges"][0]["target_input_schema_ref"] = "urn:gew:schema:node-text-payload:1.0.0"  # type: ignore[index]
        incompatible["edges"][0]["input_mapping"] = [{"source_path": ["value"], "target_path": ["value"]}]  # type: ignore[index]
        custom_schemas = graph_schemas({"urn:gew:schema:node-text-payload:1.0.0": text_body})
        incompatible["registry_pins"]["schema"] = {  # type: ignore[index]
            "registry_id": custom_schemas.registry_id,
            "registry_digest": custom_schemas.registry_digest,
        }
        with self.assertRaisesRegex(GraphValidationError, "schema mapping"):
            load_graph(
                complete(incompatible),
                schemas=custom_schemas,
            )

    def test_typed_edge_exact_assignability_accepts_shared_referenced_location(self) -> None:
        dialect = "https://json-schema.org/draft/2020-12/schema"
        common_id = "urn:gew:schema:assignable-common:1.0.0"
        source_id = "urn:gew:schema:assignable-source:1.0.0"
        target_id = "urn:gew:schema:assignable-target:1.0.0"

        def body(schema_id: str, value: object, *, definitions: object | None = None) -> bytes:
            document: dict[str, object] = {
                "$schema": dialect,
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "schema_version": {"const": "1.0.0"},
                    "value": value,
                },
                "required": ["schema_version", "value"],
                "unevaluatedProperties": False,
            }
            if definitions is not None:
                document["$defs"] = definitions
            return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

        common = body(
            common_id,
            {"type": "integer"},
            definitions={"mapped": {"type": "integer", "minimum": 0, "maximum": 5}},
        )
        reference = {"$ref": f"{common_id}#/$defs/mapped"}
        schemas = graph_schemas({
            common_id: common,
            source_id: body(source_id, reference),
            target_id: body(target_id, reference),
        })
        candidate = graph_candidate()
        candidate["nodes"][0]["output_schema_ref"] = source_id  # type: ignore[index]
        candidate["nodes"][1]["input_schema_ref"] = target_id  # type: ignore[index]
        candidate["edges"][0]["target_input_schema_ref"] = target_id  # type: ignore[index]
        candidate["edges"][0]["input_mapping"] = [  # type: ignore[index]
            {"source_path": ["value"], "target_path": ["value"]},
        ]
        candidate["registry_pins"]["schema"] = {  # type: ignore[index]
            "registry_id": schemas.registry_id,
            "registry_digest": schemas.registry_digest,
        }
        graph = load_graph(complete(candidate), schemas=schemas)
        self.assertEqual(graph.edges["start-to-finish"].input_mapping[0].source_path, ("value",))

    def test_typed_edge_rejects_disjoint_constraint_object_and_array_contracts(self) -> None:
        dialect = "https://json-schema.org/draft/2020-12/schema"

        def body(schema_id: str, value: object) -> bytes:
            return json.dumps({
                "$schema": dialect,
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "schema_version": {"const": "1.0.0"},
                    "value": value,
                },
                "required": ["schema_version", "value"],
                "unevaluatedProperties": False,
            }, sort_keys=True, separators=(",", ":")).encode()

        cases = (
            (
                "range",
                {"type": "integer", "maximum": 5},
                {"type": "integer", "minimum": 10},
            ),
            (
                "const-enum",
                {"type": "integer", "const": 1},
                {"type": "integer", "enum": [2, 3]},
            ),
            (
                "required-object",
                {
                    "type": "object",
                    "properties": {"a": {"type": "integer"}},
                    "required": ["a"],
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {"b": {"type": "integer"}},
                    "required": ["b"],
                    "additionalProperties": False,
                },
            ),
            (
                "array-items",
                {"type": "array", "maxItems": 4, "items": {"type": "integer"}},
                {"type": "array", "maxItems": 4, "items": {"type": "string"}},
            ),
        )
        for name, source_fragment, target_fragment in cases:
            with self.subTest(name=name):
                source_id = f"urn:gew:schema:assignability-{name}-source:1.0.0"
                target_id = f"urn:gew:schema:assignability-{name}-target:1.0.0"
                schemas = graph_schemas({
                    source_id: body(source_id, source_fragment),
                    target_id: body(target_id, target_fragment),
                })
                candidate = graph_candidate()
                candidate["nodes"][0]["output_schema_ref"] = source_id  # type: ignore[index]
                candidate["nodes"][1]["input_schema_ref"] = target_id  # type: ignore[index]
                candidate["edges"][0]["target_input_schema_ref"] = target_id  # type: ignore[index]
                candidate["edges"][0]["input_mapping"] = [  # type: ignore[index]
                    {"source_path": ["value"], "target_path": ["value"]},
                ]
                candidate["registry_pins"]["schema"] = {  # type: ignore[index]
                    "registry_id": schemas.registry_id,
                    "registry_digest": schemas.registry_digest,
                }
                with self.assertRaisesRegex(GraphValidationError, "schema mapping"):
                    load_graph(complete(candidate), schemas=schemas)

        sibling_source_id = "urn:gew:schema:assignability-ref-sibling-source:1.0.0"
        sibling_target_id = "urn:gew:schema:assignability-ref-sibling-target:1.0.0"
        target_fragment = {"type": "integer", "minimum": 0}
        schemas = graph_schemas({
            sibling_source_id: body(sibling_source_id, {
                "$ref": f"{sibling_target_id}#/properties/value",
                "maximum": 5,
            }),
            sibling_target_id: body(sibling_target_id, target_fragment),
        })
        candidate = graph_candidate()
        candidate["nodes"][0]["output_schema_ref"] = sibling_source_id  # type: ignore[index]
        candidate["nodes"][1]["input_schema_ref"] = sibling_target_id  # type: ignore[index]
        candidate["edges"][0]["target_input_schema_ref"] = sibling_target_id  # type: ignore[index]
        candidate["edges"][0]["input_mapping"] = [  # type: ignore[index]
            {"source_path": ["value"], "target_path": ["value"]},
        ]
        candidate["registry_pins"]["schema"] = {  # type: ignore[index]
            "registry_id": schemas.registry_id,
            "registry_digest": schemas.registry_digest,
        }
        with self.assertRaisesRegex(
            GraphValidationError, "reference with sibling assertions",
        ):
            load_graph(complete(candidate), schemas=schemas)


if __name__ == "__main__":
    unittest.main()
