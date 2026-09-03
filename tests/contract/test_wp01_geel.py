from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry  # noqa: E402
from graph_engineering.core.contracts.geel import (  # noqa: E402
    GEELProgram,
    PredicateRegistry,
    PredicateSpec,
    RootPathType,
    StaticRootRegistry,
)
import graph_engineering.core.contracts.geel as geel_module  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402


class GEELContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        self.schedule_value = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        manifest = json.loads((ROOT / "config" / "contracts" / "predicate-registry-v1.json").read_text())
        self.predicates = PredicateRegistry.from_dict(manifest)
        error_rules = json.loads((ROOT / "config" / "contracts" / "error-rule-registry-v1.json").read_text())
        self.error_rules = ErrorRuleRegistry.from_dict(error_rules)
        self.roots = StaticRootRegistry([
            RootPathType("input", (), "object"),
            RootPathType("input", ("enabled",), "boolean"),
            RootPathType("input", ("count",), "integer"),
            RootPathType("input", ("name",), "string"),
            RootPathType("input", ("tags",), "array"),
            RootPathType("input", ("missing",), "string"),
            RootPathType("input", ("missing_bool",), "boolean"),
        ])

    def context(self, *, budget: int | None = None) -> WorkContext:
        value = json.loads(json.dumps(self.profile_value))
        if budget is not None:
            value["work_budget"] = budget
        return WorkContext(ResourceProfile.from_dict(value), CostSchedule.from_dict(self.schedule_value))

    def load(self, expression: dict[str, object], context: WorkContext | None = None) -> tuple[GEELProgram, WorkContext]:
        selected = context or self.context()
        return GEELProgram.load(expression, self.roots, self.predicates, self.error_rules, selected), selected

    def test_operator_truth_table_and_exact_types(self) -> None:
        expressions = [
            ({"op": "eq", "left": {"op": "literal", "value": 1}, "right": {"op": "literal", "value": 1}}, True),
            ({"op": "ne", "left": {"op": "literal", "value": "a"}, "right": {"op": "literal", "value": "b"}}, True),
            ({"op": "lt", "left": {"op": "literal", "value": 1}, "right": {"op": "literal", "value": 2}}, True),
            ({"op": "gte", "left": {"op": "literal", "value": "b"}, "right": {"op": "literal", "value": "a"}}, True),
            ({"op": "not", "arg": {"op": "literal", "value": False}}, True),
            ({"op": "all", "args": [{"op": "literal", "value": True}, {"op": "literal", "value": False}]}, False),
            ({"op": "any", "args": [{"op": "literal", "value": False}, {"op": "literal", "value": True}]}, True),
            ({"op": "contains", "container": {"op": "path", "root": "input", "tokens": ["tags"]}, "value": {"op": "literal", "value": "graph"}}, True),
            ({"op": "in", "value": {"op": "literal", "value": "graph"}, "container": {"op": "path", "root": "input", "tokens": ["tags"]}}, True),
            ({"op": "eq", "left": {"op": "length", "value": {"op": "path", "root": "input", "tokens": ["name"]}}, "right": {"op": "literal", "value": 4}}, True),
            ({"op": "exists", "root": "input", "tokens": ["missing"]}, False),
            ({"op": "is_type", "value": {"op": "path", "root": "input", "tokens": ["count"]}, "expected": "integer"}, True),
        ]
        roots = {"input": {"enabled": True, "count": 2, "name": "GEW!", "tags": ["graph", "agent"]}}
        for expression, expected in expressions:
            program, context = self.load(expression)
            with self.subTest(expression=expression):
                self.assertEqual(program.evaluate(roots, context), {"schema_version": "1.0.0", "status": "ok", "value": expected})

    def test_load_phases_fail_closed_for_shape_operator_path_and_type(self) -> None:
        cases = [
            ({"op": "all", "args": []}, "E_SCHEMA"),
            ({"op": "unknown"}, "E_OPERATOR"),
            ({"op": "path", "root": "unknown", "tokens": []}, "E_PATH_MISSING"),
            ({"op": "eq", "left": {"op": "literal", "value": 1}, "right": {"op": "literal", "value": True}}, "E_TYPE"),
            ({"op": "literal", "value": True, "rogue": 1}, "E_SCHEMA"),
            ({"op": "predicate", "predicate_id": "urn:gew:predicate:missing", "version": "1.0.0", "args": []}, "E_OPERATOR"),
        ]
        for expression, code in cases:
            with self.subTest(expression=expression), self.assertRaises(ContractError) as caught:
                self.load(expression)
            self.assertEqual(caught.exception.detail.code, code)

    def test_eager_error_order_and_budget_precedence_are_stable(self) -> None:
        expression = {
            "op": "all",
            "args": [
                {"op": "path", "root": "input", "tokens": ["missing_bool"]},
                {"op": "path", "root": "input", "tokens": ["enabled"]},
            ],
        }
        program, context = self.load(expression)
        result = program.evaluate({"input": {"enabled": True}}, context)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "E_PATH_MISSING")
        self.assertEqual(result["error"]["evaluation_path"], [0])
        self.assertEqual([record["event_id"] for record in context.trace[:5]], ["geel.node", "geel.operand", "geel.node", "geel.path_token", "geel.operand"])

        limited_context = self.context(budget=1)
        limited_program, _ = self.load(expression, limited_context)
        limited = limited_program.evaluate({"input": {}}, limited_context)
        self.assertEqual(limited["error"]["code"], "E_BUDGET")
        self.assertEqual(limited["error"]["rule_id"], "budget/geel.operand")
        self.assertEqual(limited_context.trace[-1]["status"], "rejected")

    def test_membership_trace_is_inline_and_does_not_short_circuit(self) -> None:
        expression = {"op": "contains", "container": {"op": "path", "root": "input", "tokens": ["tags"]}, "value": {"op": "literal", "value": "a"}}
        program, context = self.load(expression)
        result = program.evaluate({"input": {"tags": ["a", "b", "c"]}}, context)
        self.assertEqual(result["value"], True)
        events = [record["event_id"] for record in context.trace]
        membership_indexes = [index for index, event in enumerate(events) if event == "geel.membership_item"]
        self.assertEqual(len(membership_indexes), 3)
        self.assertTrue(all(events[index + 1] == "compare.base" for index in membership_indexes))

    def test_builtin_predicate_is_charged_before_call(self) -> None:
        expression = {
            "op": "predicate",
            "predicate_id": "urn:gew:predicate:string-starts-with",
            "version": "1.0.0",
            "args": [
                {"op": "path", "root": "input", "tokens": ["name"]},
                {"op": "literal", "value": "GE"},
            ],
        }
        program, context = self.load(expression)
        result = program.evaluate({"input": {"name": "GEW"}}, context)
        self.assertEqual(result["value"], True)
        events = [record["event_id"] for record in context.trace]
        executable = events.index("executable.base")
        self.assertEqual(events[executable:executable + 4], ["executable.base", "executable.input_node", "executable.input_scalar", "executable.input_byte"])
        executable_paths = {tuple(record["operation_path"]) for record in context.trace[executable:executable + 4]}
        self.assertEqual(executable_paths, {(2,)})

    def test_unknown_predicate_is_rejected_before_execution(self) -> None:
        expression = {
            "op": "predicate",
            "predicate_id": "urn:gew:predicate:not-installed",
            "version": "1.0.0",
            "args": [],
        }
        context = self.context()
        with self.assertRaises(ContractError) as caught:
            GEELProgram.load(expression, self.roots, self.predicates, self.error_rules, context)
        self.assertEqual(caught.exception.detail.code, "E_OPERATOR")
        self.assertEqual(context.trace, [])

    def test_predicate_manifest_tamper_and_callable_injection_are_rejected(self) -> None:
        manifest = json.loads((ROOT / "config" / "contracts" / "predicate-registry-v1.json").read_text())
        tampered = json.loads(json.dumps(manifest))
        tampered["predicates"][0]["implementation_digest"] = "sha256-raw-v1:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            PredicateRegistry.from_dict(tampered)
        with self.assertRaises(TypeError):
            PredicateRegistry("urn:gew:predicate-registry:evil:1.0.0", "x", {})  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            PredicateSpec(
                "urn:gew:predicate:string-starts-with", "1.0.0", ("string", "string"), "boolean",
                {"executable.base": 1, "executable.input_node": 1, "executable.input_scalar": 1, "executable.input_byte": 1},
                "builtin:string-starts-with:v1", "forged", lambda _arguments: True,
            )  # type: ignore[call-arg]
        installed = self.predicates.resolve("urn:gew:predicate:string-starts-with", "1.0.0")
        with self.assertRaises((AttributeError, TypeError)):
            self.predicates._values = {(installed.predicate_id, installed.version): installed}
        resolved = self.predicates.resolve("urn:gew:predicate:string-starts-with", "1.0.0")
        self.assertIs(resolved, installed)
        self.assertFalse(hasattr(resolved, "implementation"))

    def test_attested_geel_types_are_factory_only_final_and_exact(self) -> None:
        for final_type in (StaticRootRegistry, PredicateSpec, PredicateRegistry, GEELProgram):
            with self.subTest(final_type=final_type.__name__), self.assertRaises(TypeError):
                type(f"Forged{final_type.__name__}", (final_type,), {})
        for factory_only_type in (PredicateSpec, PredicateRegistry, GEELProgram):
            with self.subTest(factory_only_type=factory_only_type.__name__), self.assertRaises(TypeError):
                factory_only_type()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            GEELProgram(
                {"op": "literal", "value": 1},
                "boolean",
                self.predicates,
                self.error_rules,
            )
    def test_predicate_executes_only_the_frozen_registry_code_binding(self) -> None:
        expression = {
            "op": "predicate",
            "predicate_id": "urn:gew:predicate:string-starts-with",
            "version": "1.0.0",
            "args": [
                {"op": "path", "root": "input", "tokens": ["name"]},
                {"op": "literal", "value": "GE"},
            ],
        }

        changed_calls = 0

        def changed(arguments: tuple[object, ...]) -> object:
            nonlocal changed_calls
            del arguments
            changed_calls += 1
            return False

        def changed_code(arguments: tuple[object, ...]) -> object:
            del arguments
            return False

        program, replacement_context = self.load(expression)
        with mock.patch.object(geel_module, "_string_starts_with", changed):
            self.assertEqual(
                program.evaluate({"input": {"name": "GEW"}}, replacement_context)["value"],
                True,
            )
        self.assertEqual(changed_calls, 0)
        with mock.patch.object(geel_module, "_verified_predicate_implementation", changed, create=True):
            self.assertEqual(
                program.evaluate({"input": {"name": "GEW"}}, self.context())["value"],
                True,
            )
        self.assertEqual(changed_calls, 0)

        implementation = geel_module._string_starts_with
        original_code = implementation.__code__
        code_context = self.context()
        try:
            implementation.__code__ = changed_code.__code__
            self.assertEqual(program.evaluate({"input": {"name": "GEW"}}, code_context)["value"], True)
        finally:
            implementation.__code__ = original_code
        with self.assertRaises((AttributeError, TypeError)):
            self.predicates._implementation = self.predicates._implementation

    def test_digest_and_result_ignore_input_member_order(self) -> None:
        expression = {"op": "eq", "left": {"op": "path", "root": "input", "tokens": ["count"]}, "right": {"value": 2, "op": "literal"}}
        reordered = json.loads(json.dumps(expression, sort_keys=True))
        first, first_context = self.load(expression)
        second, second_context = self.load(reordered)
        expression["right"]["value"] = 3
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.evaluate({"input": {"count": 2}}, first_context), second.evaluate({"input": {"count": 2}}, second_context))
        with self.assertRaises(TypeError):
            self.predicates.resolve("urn:gew:predicate:string-starts-with", "1.0.0").multipliers["executable.base"] = 2  # type: ignore[index]
        with self.assertRaises(TypeError):
            self.predicates._values[("urn:gew:predicate:string-starts-with", "1.0.0")] = self.predicates.resolve("urn:gew:predicate:string-starts-with", "1.0.0")  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            first.expression = {"op": "literal", "value": False}  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
