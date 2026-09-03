from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tests" / "contract"))

from graph_engineering.core.contracts.immutable import thaw  # noqa: E402
from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.core.contracts.digest import raw_digest  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.graph.definition import GraphDefinition, JoinPolicy  # noqa: E402
from graph_engineering.core.graph.state import TaskSnapshot  # noqa: E402
from test_wp02_graph import (  # noqa: E402
    GRAPH_CONTRACT,
    GRAPH_DIGEST_INPUT_SCHEMA,
    GRAPH_PROJECTION,
    complete,
    completion_policies,
    error_rule_registry,
    graph_candidate,
    graph_schemas,
    loop_budgets,
    predicate_registry,
    work_context,
)


class WP02CrossImplementationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which("node")
        if cls.node is None:
            raise RuntimeError("WP-02 independent Node.js reference implementation is required")
        schemas = graph_schemas()
        predicates = predicate_registry()
        error_rules = error_rule_registry()
        context = work_context()
        cls.completions = completion_policies(schemas, predicates, error_rules, context)
        cls.budgets = loop_budgets(schemas, predicates, error_rules, context)

    def reference(self, request: dict[str, object]) -> dict[str, object]:
        result = subprocess.run(
            [self.node, str(ROOT / "tests" / "support" / "wp01_reference.mjs")],
            input=json.dumps(request, ensure_ascii=False) + "\n",
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["status"], "ok", response)
        return response

    def test_graph_projection_digest_matches_independent_jcs_sha256(self) -> None:
        candidate = graph_candidate()
        graph = complete(candidate)
        reference = self.reference({
            "operation": "semantic_digest",
            "body": candidate,
            "contract_type": GRAPH_CONTRACT,
            "projection_id": GRAPH_PROJECTION,
            "schema_id": GRAPH_DIGEST_INPUT_SCHEMA,
        })
        self.assertEqual(reference["digest"], graph["digest"])

    def test_graph_and_snapshot_exact_traces_match_frozen_and_independent_digest(self) -> None:
        schemas = graph_schemas()
        predicates = predicate_registry()
        error_rules = error_rule_registry()
        registry_context = work_context()
        completions = completion_policies(
            schemas, predicates, error_rules, registry_context,
        )
        budgets = loop_budgets(schemas, predicates, error_rules, registry_context)
        traces: dict[str, list[dict[str, object]]] = {}
        graph_input = graph_candidate()
        graph_record = complete(graph_input)

        context = work_context()
        GraphDefinition.create(
            graph_input, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=context,
            completion_policies=completions, loop_budgets=budgets,
        )
        traces["graph_create"] = context.trace
        context = work_context()
        GraphDefinition.from_dict(
            graph_record, schema_registry=schemas, predicates=predicates,
            error_rules=error_rules, context=context,
            completion_policies=completions, loop_budgets=budgets,
        )
        traces["graph_load"] = context.trace
        context = work_context()
        snapshot = TaskSnapshot.initial(schemas, context)
        traces["snapshot_create"] = context.trace
        context = work_context()
        TaskSnapshot.from_dict(snapshot.to_dict(), schema_registry=schemas, context=context)
        traces["snapshot_restore"] = context.trace

        independent = self.reference({
            "operation": "wp02_traces",
            "inputs": {
                "graph_candidate": graph_input,
                "graph_record": graph_record,
                "graph_source_schema": thaw(
                    schemas.resource("urn:gew:schema:graph-definition:1.0.0").schema
                ),
                "graph_input_schema": thaw(
                    schemas.resource(
                        "urn:gew:schema:graph-definition-digest-input:1.0.0"
                    ).schema
                ),
                "snapshot_body": snapshot.to_body(),
                "snapshot_record": snapshot.to_dict(),
                "snapshot_source_schema": thaw(
                    schemas.resource("urn:gew:schema:task-snapshot:1.0.0").schema
                ),
                "snapshot_input_schema": thaw(
                    schemas.resource(
                        "urn:gew:schema:task-snapshot-digest-input:1.0.0"
                    ).schema
                ),
                "coefficients": dict(registry_context.schedule.coefficients),
                "initial_balance": registry_context.profile.work_budget,
            },
        })["traces"]

        goldens = json.loads(
            (ROOT / "tests" / "fixtures" / "wp02-charge-trace-goldens.json").read_text()
        )
        for name, trace in traces.items():
            with self.subTest(operation=name):
                self.assertEqual(
                    [record["event_ordinal"] for record in trace],
                    [str(index) for index in range(len(trace))],
                )
                self.assertTrue(all(record["operation_path"] for record in trace))
                python_digest = raw_digest(canonical_bytes(trace))
                self.assertEqual(independent[name], trace)
                self.assertEqual(len(trace), goldens[name]["event_count"])
                self.assertEqual(python_digest, goldens[name]["trace_digest"])
                self.assertEqual(raw_digest(canonical_bytes(independent[name])), python_digest)
                for record in trace:
                    amount = int(record["amount"])
                    cutoff = work_context(amount - 1)
                    with self.assertRaises(ContractError):
                        cutoff.emit(
                            record["event_id"],  # type: ignore[arg-type]
                            int(record["count"]),
                            operation_path=tuple(record["operation_path"]),  # type: ignore[arg-type]
                            multiplier=int(record["multiplier"]),
                            source_id="urn:gew:test:trace-cutoff",
                        )
                    if cutoff.trace[-1]["status"] != "rejected":
                        self.fail(
                            f"{name} occurrence {record['event_ordinal']} did not reject atomically"
                        )

    def test_completion_join_and_loop_conditions_match_independent_geel(self) -> None:
        completion = self.completions.resolve("completion:all-required-v1")
        completion_expression = thaw(completion._program.expression)
        for passed_count, required_count in ((0, 1), (1, 1), (1, 2), (2, 2)):
            with self.subTest(kind="completion", passed=passed_count, required=required_count):
                roots = {"completion": {
                    "passed_count": passed_count,
                    "required_count": required_count,
                }}
                reference = self.reference({
                    "operation": "geel", "expression": completion_expression, "roots": roots,
                })
                passed = tuple(f"node-{index}" for index in range(passed_count))
                required = tuple(f"node-{index}" for index in range(required_count))
                self.assertEqual(
                    reference["value"],
                    completion.satisfied(passed, required, work_context()),
                )

        predicates = predicate_registry()
        error_rules = error_rule_registry()
        join = JoinPolicy.from_dict(
            {"kind": "all_required", "quorum": None},
            predicates, error_rules, work_context(),
        )
        join_expression = thaw(join._program.expression)
        for passed, required_count in (((True,), 1), ((True, False), 2), ((True, False), 1)):
            with self.subTest(kind="join", passed=passed, required=required_count):
                roots = {"join": {
                    "passed_count": sum(passed),
                    "required_count": required_count,
                    "candidate_count": len(passed),
                }}
                reference = self.reference({
                    "operation": "geel", "expression": join_expression, "roots": roots,
                })
                self.assertEqual(reference["value"], join.satisfied(
                    passed, required_count, work_context(),
                ))

        budget = self.budgets.resolve("loop:bounded-v1")
        budget_expression = thaw(budget._program.expression)
        for attempts, revisions, total in (
            (0, 0, 0),
            (budget.max_attempts - 1, budget.max_revisions - 1, budget.max_total_runs - 1),
            (budget.max_attempts, 0, 0),
            (0, budget.max_revisions, 0),
            (0, 0, budget.max_total_runs),
        ):
            with self.subTest(kind="budget", attempts=attempts, revisions=revisions, total=total):
                roots = {"usage": {
                    "attempts_used": attempts,
                    "revisions_used": revisions,
                    "total_runs_used": total,
                }}
                reference = self.reference({
                    "operation": "geel", "expression": budget_expression, "roots": roots,
                })
                self.assertEqual(reference["value"], budget.allows_next(
                    attempts_used=attempts,
                    revisions_used=revisions,
                    total_runs_used=total,
                    context=work_context(),
                ))


if __name__ == "__main__":
    unittest.main()
