from __future__ import annotations

import json
import hashlib
import pathlib
import shutil
import subprocess
import sys
import unittest
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.canonical import canonical_bytes, canonical_text, canonicalize  # noqa: E402
from graph_engineering.core.contracts.digest import (  # noqa: E402
    DigestProjection,
    create_self_digest,
    raw_digest,
    semantic_digest,
    semantic_digest_charged,
    semantic_preimage,
    verify_self_digest,
)
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry  # noqa: E402
from graph_engineering.core.contracts.formats import validate_format  # noqa: E402
from graph_engineering.core.contracts.geel import GEELProgram, PredicateRegistry, RootPathType, StaticRootRegistry  # noqa: E402
from graph_engineering.core.contracts.immutable import freeze, thaw  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry, _pointer_tokens, _split_reference  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext, build_result_record, compare_charge  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy, validate_instance, validate_schema_profile  # noqa: E402
from graph_engineering.core.contracts.strict_json import parse_json  # noqa: E402
from graph_engineering.core.contracts.versioning import CompatibilityMatrix, MigrationRegistry, _all_paths  # noqa: E402


@dataclass(frozen=True)
class _PathEdge:
    transform_id: str
    version: str
    source_contract_id: str
    target_contract_id: str


class CrossImplementationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = shutil.which("node")
        if cls.node is None:
            raise RuntimeError("WP-01 independent Node.js reference implementation is required")
        cls.corpus = json.loads((ROOT / "config" / "contracts" / "corpora" / "cross-implementation-v1.json").read_text())
        profile = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        schedule = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        cls.profile = ResourceProfile.from_dict(profile)
        cls.schedule = CostSchedule.from_dict(schedule)
        predicate_manifest = json.loads((ROOT / "config" / "contracts" / "predicate-registry-v1.json").read_text())
        cls.predicates = PredicateRegistry.from_dict(predicate_manifest)
        error_rules = json.loads((ROOT / "config" / "contracts" / "error-rule-registry-v1.json").read_text())
        cls.error_rules = ErrorRuleRegistry.from_dict(error_rules)

    def reference(self, request: dict[str, object]) -> dict[str, object]:
        response = self.invoke_reference(request)
        self.assertEqual(response["status"], "ok", response)
        return response

    def invoke_reference(self, request: dict[str, object]) -> dict[str, object]:
        result = subprocess.run(
            [self.node, str(ROOT / "tests" / "support" / "wp01_reference.mjs")],
            input=json.dumps(request, ensure_ascii=False) + "\n",
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def trace_scenario(self, scenario: str, budget: int) -> tuple[WorkContext, object]:
        profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        profile_value["work_budget"] = budget
        profile = ResourceProfile.from_dict(profile_value)
        context = WorkContext(profile, self.schedule)
        source_id = "urn:gew:corpus:boundary"
        try:
            parse_inputs = {
                "parse-null": "null",
                "parse-string": '"é"',
                "parse-array": "[1,true]",
                "parse-object": '{"a":1,"b":"x"}',
                "parse-nested": '{"a":[{"b":2}]}',
            }
            if scenario in parse_inputs:
                return context, canonical_text(parse_json(parse_inputs[scenario], context=context, source_id=source_id))

            schema_scenarios: dict[str, tuple[object, object]] = {
                "schema-integer": ({"type": "integer", "minimum": 1}, 2),
                "schema-properties": ({"type": "object", "properties": {"x": {"type": "integer"}}}, {"x": 1}),
                "schema-items": ({"type": "array", "items": {"type": "integer"}}, [1, 2]),
                "schema-all-of": ({"allOf": [{"type": "integer"}, {"minimum": 1}]}, 2),
                "schema-any-of": ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 2),
                "schema-one-of": ({"oneOf": [{"const": 1}, {"const": 2}]}, 2),
                "schema-not": ({"not": {"type": "string"}}, 2),
                "schema-if-then": ({"if": {"type": "integer"}, "then": {"minimum": 1}, "else": {"type": "string"}}, 2),
                "schema-format-id": ({"type": "string", "format": "gew-id"}, "node-1"),
                "schema-format-opaque": ({"type": "string", "format": "gew-opaque-ref"}, "Z3JhcGg"),
                "schema-unique": ({"type": "array", "uniqueItems": True}, [1, 2, 3]),
                "schema-contains": ({"type": "array", "contains": {"type": "integer"}}, [1, "x", 2]),
                "schema-unevaluated-properties": ({"type": "object", "properties": {"x": {"type": "integer"}}, "unevaluatedProperties": False}, {"x": 1}),
                "schema-unevaluated-items": ({"type": "array", "prefixItems": [{"type": "integer"}], "unevaluatedItems": False}, [1]),
            }
            if scenario in schema_scenarios:
                schema, instance = schema_scenarios[scenario]
                return context, [
                    failure.as_dict()
                    for failure in validate_instance(schema, instance, source_id=source_id, context=context)  # type: ignore[arg-type]
                ]
            if scenario == "schema-ref":
                target = {"type": "object", "properties": {"x": {"type": "integer"}}}

                def resolver(_current_id: str, _reference: str) -> tuple[object, str]:
                    return target, "urn:gew:schema:boundary-target:1.0.0"

                failures = validate_instance(
                    {"$ref": "urn:gew:schema:boundary-target:1.0.0"},
                    {"x": 1},
                    source_id=source_id,
                    resolver=resolver,
                    context=context,
                )
                return context, [failure.as_dict() for failure in failures]

            if scenario in {"registry-single", "registry-ref", "registry-two-resources"}:
                policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
                dialect = policy.dialect_id
                base = {
                    "$schema": dialect, "$id": "urn:gew:schema:boundary-base:1.0.0", "type": "object",
                    "properties": {"schema_version": {"const": "1.0.0"}, "value": {"type": "integer"}},
                    "required": ["schema_version", "value"], "unevaluatedProperties": False,
                }
                wrapper = {
                    "$schema": dialect, "$id": "urn:gew:schema:boundary-wrapper:1.0.0", "type": "object",
                    "properties": {"schema_version": {"const": "1.0.0"}, "payload": {"$ref": base["$id"] + "#/properties/value"}},
                    "required": ["schema_version", "payload"], "unevaluatedProperties": False,
                }
                selected = [base] if scenario == "registry-single" else [base, wrapper]
                bodies = {
                    item["$id"]: json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                    for item in selected
                }
                manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:boundary:1.0.0", bodies)
                registry = ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)
                if scenario == "registry-two-resources":
                    return context, sorted(registry._resources)
                return context, registry.registry_digest

            geel_scenarios: dict[str, tuple[dict[str, object], dict[str, object], list[RootPathType]]] = {
                "geel-literal": ({"op": "literal", "value": True}, {}, []),
                "geel-path": ({"op": "path", "root": "input", "tokens": ["enabled"]}, {"input": {"enabled": True}}, [RootPathType("input", (), "object"), RootPathType("input", ("enabled",), "boolean")]),
                "geel-equality": ({"op": "eq", "left": {"op": "literal", "value": 1}, "right": {"op": "literal", "value": 1}}, {}, []),
                "geel-membership": ({"op": "contains", "container": {"op": "path", "root": "input", "tokens": ["items"]}, "value": {"op": "literal", "value": 2}}, {"input": {"items": [1, 2, 3]}}, [RootPathType("input", (), "object"), RootPathType("input", ("items",), "array")]),
                "geel-predicate": ({"op": "predicate", "predicate_id": "urn:gew:predicate:string-starts-with", "version": "1.0.0", "args": [{"op": "literal", "value": "graph"}, {"op": "literal", "value": "gra"}]}, {}, []),
                "geel-eager-error": ({"op": "all", "args": [{"op": "literal", "value": False}, {"op": "path", "root": "input", "tokens": ["missing"]}]}, {"input": {}}, [RootPathType("input", (), "object"), RootPathType("input", ("missing",), "boolean")]),
            }
            if scenario in geel_scenarios:
                expression, roots, declarations = geel_scenarios[scenario]
                program = GEELProgram.load(expression, StaticRootRegistry(declarations), self.predicates, self.error_rules, context)
                return context, program.evaluate(roots, context)

            canonical_values = {
                "canonical-integer": 1,
                "canonical-string": "é",
                "canonical-object": {"b": 2, "a": "x"},
                "canonical-array": [1, "x", True],
            }
            if scenario in canonical_values:
                return context, canonicalize(canonical_values[scenario], context, source_id=source_id).decode()
            compare_values = {
                "compare-integer": (1, 1),
                "compare-string": ("é", "é"),
                "compare-object": ({"a": 1}, {"a": 2}),
                "compare-array": ([1, 2], [1, 3]),
            }
            if scenario in compare_values:
                left, right = compare_values[scenario]
                compare_charge(left, right, context, operation_path=(), source_id=source_id)
                return context, True
            digest_values = {"digest-integer": 1, "digest-object": {"a": 1, "b": "x"}}
            if scenario in digest_values:
                return context, semantic_digest_charged(
                    digest_values[scenario], context,
                    contract_type="urn:gew:contract:boundary",
                    projection_id="urn:gew:digest-projection:identity:1.0.0",
                    schema_id="urn:gew:schema:boundary:1.0.0",
                )
            if scenario == "result-nested":
                return context, build_result_record(
                    (("schema_version", "1.0.0"), ("status", "ok"), ("value", {"items": [1, "x"]})),
                    context,
                    source_id=source_id,
                )
            if scenario == "migration-success":
                migration = MigrationRegistry.from_dict(json.loads((ROOT / "config" / "contracts" / "migration-registry-v1.json").read_text()))
                schema_manifest = json.loads((ROOT / "config" / "contracts" / "migration-schema-registry-v1.json").read_text())
                bodies = {}
                for path in sorted((ROOT / "config" / "contracts" / "schemas").glob("contract-stack-*.json")):
                    body = path.read_bytes()
                    bodies[json.loads(body)["$id"]] = body
                policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
                schema_registry = ClosedSchemaRegistry.build(schema_manifest, bodies, profile, policy)
                value = {"schema_version": "1.0.0", "value": 1}
                expected_source_digest = semantic_digest(
                    value,
                    contract_type="urn:gew:contract-stack:1.0.0",
                    projection_id="urn:gew:digest-projection:identity:1.0.0",
                    schema_id="urn:gew:schema:contract-stack:1.0.0",
                )
                return context, migration.migrate(
                    value,
                    source_contract_id="urn:gew:contract-stack:1.0.0",
                    target_contract_id="urn:gew:contract-stack:1.0.1",
                    expected_source_digest=expected_source_digest,
                    expected_schema_registry_id=schema_manifest["registry_id"],
                    expected_schema_registry_digest=schema_manifest["registry_digest"],
                    actor_id="codex:boundary",
                    transaction_id="boundary-tx",
                    schema_registry=schema_registry,
                    context=context,
                )
            raise AssertionError(f"unknown trace scenario: {scenario}")
        except ContractError as error:
            return context, {"contract_error": error.detail.as_dict()}

    def production_boundary(self, scenario: str) -> dict[str, object]:
        baseline, _ = self.trace_scenario(scenario, self.profile.work_budget)
        self.assertTrue(baseline.trace, scenario)
        observations: list[dict[str, object]] = []
        cumulative = 0
        for ordinal, baseline_attempt in enumerate(baseline.trace):
            amount = int(baseline_attempt["amount"])
            attempts: dict[str, dict[str, object]] = {}
            for label, delta in (("before", -1), ("exact", 0), ("after", 1)):
                rerun, _ = self.trace_scenario(scenario, cumulative + amount + delta)
                self.assertGreater(len(rerun.trace), ordinal, (scenario, ordinal, label))
                attempt = rerun.trace[ordinal]
                attempts[label] = {
                    "event_id": attempt["event_id"],
                    "operation_path": attempt["operation_path"],
                    "pre_balance": attempt["pre_balance"],
                    "status": attempt["status"],
                    **({"post_balance": attempt["post_balance"]} if "post_balance" in attempt else {}),
                }
            self.assertEqual(attempts["before"]["status"], "rejected", (scenario, ordinal))
            self.assertEqual(attempts["exact"].get("post_balance"), "0", (scenario, ordinal))
            self.assertEqual(attempts["after"].get("post_balance"), "1", (scenario, ordinal))
            observations.append({
                "amount": baseline_attempt["amount"],
                "coefficient": baseline_attempt["coefficient"],
                "count": baseline_attempt["count"],
                "event_id": baseline_attempt["event_id"],
                "multiplier": baseline_attempt["multiplier"],
                "operation_path": baseline_attempt["operation_path"],
                "ordinal": str(ordinal),
                "attempts": attempts,
            })
            cumulative += amount
        paths = sorted({tuple(item["operation_path"]) for item in baseline.trace})
        return {
            "boundary_digest": raw_digest(canonical_bytes(observations)),
            "event_count": len(baseline.trace),
            "event_ids": sorted({item["event_id"] for item in baseline.trace}),
            "operation_paths": [list(path) for path in paths],
            "total_cost": str(cumulative),
        }

    def test_canonical_and_digest_bytes_match_independent_implementation(self) -> None:
        for case in self.corpus["canonical"]:
            with self.subTest(case=case["case_id"]):
                reference = self.reference({"operation": "canonical", "value": case["value"]})
                self.assertEqual(reference["canonical"], canonical_text(case["value"]))
                arguments = {
                    "contract_type": "urn:gew:contract:cross-implementation",
                    "projection_id": "urn:gew:digest-projection:identity:1.0.0",
                    "schema_id": "urn:gew:schema:cross-implementation:1.0.0",
                }
                reference_digest = self.reference({"operation": "semantic_digest", "body": case["value"], **arguments})
                self.assertEqual(reference_digest["digest"], semantic_digest(case["value"], **arguments))

    def test_geel_results_match_independent_evaluator(self) -> None:
        declarations = [
            RootPathType("input", (), "object"),
            RootPathType("input", ("enabled",), "boolean"),
            RootPathType("input", ("tags",), "array"),
        ]
        roots = StaticRootRegistry(declarations)
        for case in self.corpus["geel"]:
            with self.subTest(case=case["case_id"]):
                context = WorkContext(self.profile, self.schedule)
                program = GEELProgram.load(case["expression"], roots, self.predicates, self.error_rules, context)
                python_result = program.evaluate(case["roots"], context)
                reference = self.reference({"operation": "geel", "expression": case["expression"], "roots": case["roots"]})
                self.assertEqual(reference["value"], python_result["value"])

    def test_schema_accept_reject_matches_independent_evaluator(self) -> None:
        for case in self.corpus["schema"]:
            with self.subTest(case=case["case_id"]):
                python_rules = sorted(failure.rule_id for failure in validate_instance(case["schema"], case["instance"], source_id="urn:gew:schema:cross-implementation:1.0.0"))
                reference = self.reference({"operation": "schema", "schema": case["schema"], "instance": case["instance"]})
                self.assertEqual(reference["failures"], python_rules)

    def python_case(self, request: dict[str, object]) -> dict[str, object]:
        operation = request["operation"]
        if operation == "strict_json":
            try:
                return {"status": "ok", "canonical": canonical_text(parse_json(request["raw"]))}  # type: ignore[arg-type]
            except (UnicodeDecodeError, ValueError) as error:
                message = str(error)
                code = "DUPLICATE" if "duplicate" in message else "NUMBER" if "number" in message or "integer" in message or "range" in message else "BOM" if "BOM" in message else "SURROGATE" if "surrogate" in message else "SYNTAX"
                return {"status": "error", "code": code}
        if operation == "schema":
            return {"failures": sorted(failure.rule_id for failure in validate_instance(request["schema"], request["instance"], source_id="urn:gew:schema:corpus:1.0.0"))}
        if operation == "schema_profile":
            policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
            try:
                validate_schema_profile(request["schema"], policy)  # type: ignore[arg-type]
                return {"valid": True}
            except ValueError:
                return {"valid": False}
        if operation == "registry_ref":
            try:
                _, pointer = _split_reference("urn:gew:schema:current:1.0.0", request["reference"])  # type: ignore[arg-type]
                _pointer_tokens(pointer)
                return {"valid": True}
            except ValueError:
                return {"valid": False}
        if operation == "registry_contract":
            profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
            for limit_id, value in request.get("limit_override", {}).items():  # type: ignore[union-attr]
                profile_value["limits"][limit_id] = value
            profile = ResourceProfile.from_dict(profile_value)
            context = WorkContext(profile, self.schedule)
            policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
            bodies = {schema_id: raw.encode() for schema_id, raw in request["bodies"].items()}  # type: ignore[union-attr]
            try:
                ClosedSchemaRegistry.build(request["manifest"], bodies, profile, policy, context)  # type: ignore[arg-type]
                resource_ids = [record["schema_id"] for record in request["manifest"]["resources"]]  # type: ignore[index]
                return {"status": "ok", "resource_ids": resource_ids}
            except ContractError as error:
                return {"status": "error", "code": "LIMIT" if error.detail.code == "E_LIMIT" else error.detail.code}
            except ValueError as error:
                message = str(error)
                code = (
                    "MANIFEST" if "manifest digest" in message else
                    "DIGEST" if "body digest" in message else
                    "CYCLE" if "cyclic" in message else
                    "BODY" if "undeclared" in message or "duplicate or missing" in message else
                    "REF"
                )
                return {"status": "error", "code": code}
        if operation == "canonical":
            return {"canonical": canonical_text(request["value"])}
        if operation == "format":
            return {"valid": validate_format(request["format_id"], request["value"])}  # type: ignore[arg-type]
        if operation == "semantic_digest":
            return {"digest": semantic_digest(
                request["body"],
                contract_type=request["contract_type"],  # type: ignore[arg-type]
                projection_id=request["projection_id"],  # type: ignore[arg-type]
                schema_id=request["schema_id"],  # type: ignore[arg-type]
            )}
        if operation == "digest_contract":
            action = request["action"]
            if action == "identity":
                arguments = {
                    "contract_type": request["contract_type"],
                    "projection_id": request["projection_id"],
                    "schema_id": request["schema_id"],
                }
                body = request["body"]
                return {
                    "status": "ok",
                    "projected_body": body,
                    "preimage": semantic_preimage(body, **arguments).decode(),  # type: ignore[arg-type]
                    "digest": semantic_digest(body, **arguments),  # type: ignore[arg-type]
                }
            projection = DigestProjection(**request["projection"])  # type: ignore[arg-type]

            def validate_input(value: object) -> None:
                if not isinstance(value, dict) or set(value) != {"schema_version", "value"} or value.get("schema_version") != "1.0.0":
                    raise ValueError("invalid digest input")

            def validate_source(value: object) -> None:
                if not isinstance(value, dict) or set(value) != {"schema_version", "value", "digest"} or value.get("schema_version") != "1.0.0":
                    raise ValueError("invalid digest source")

            try:
                if action == "create-self":
                    candidate = request["candidate"]
                    complete = create_self_digest(candidate, projection, validate_input=validate_input, validate_source=validate_source)  # type: ignore[arg-type]
                    projected = candidate
                    return {
                        "status": "ok", "complete": complete, "projected_body": projected,
                        "preimage": semantic_preimage(
                            projected,
                            contract_type=projection.contract_type,
                            projection_id=projection.projection_id,
                            schema_id=projection.schema_id,
                        ).decode(),
                        "digest": complete[projection.derived_field],
                    }
                if action == "verify-self":
                    record = request["record"]
                    complete = verify_self_digest(record, projection, validate_input=validate_input, validate_source=validate_source)  # type: ignore[arg-type]
                    projected = {key: value for key, value in complete.items() if key != projection.derived_field}
                    return {"status": "ok", "complete": complete, "projected_body": projected, "digest": complete[projection.derived_field]}
                raise AssertionError(action)
            except ValueError as error:
                message = str(error)
                code = "SOURCE" if "source" in message else "DIGEST_FIELD" if "valid derived digest" in message else "MISMATCH" if "mismatch" in message else "INPUT"
                return {"status": "error", "code": code}
        if operation == "geel_summary":
            roots = StaticRootRegistry([
                RootPathType(item["root"], tuple(item["tokens"]), item["value_type"])  # type: ignore[arg-type]
                for item in request["declarations"]  # type: ignore[union-attr]
            ])
            context = WorkContext(self.profile, self.schedule)
            try:
                program = GEELProgram.load(request["expression"], roots, self.predicates, self.error_rules, context)  # type: ignore[arg-type]
                result = program.evaluate(request["roots"], context)  # type: ignore[arg-type]
                return {"status": "ok", "value": result["value"]} if result["status"] == "ok" else {"status": "error", "code": result["error"]["code"]}  # type: ignore[index]
            except ContractError as error:
                return {"status": "error", "code": error.detail.code}
        if operation == "production_trace":
            profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
            profile_value["work_budget"] = request["budget"]
            context = WorkContext(ResourceProfile.from_dict(profile_value), self.schedule)
            try:
                kind = request["kind"]
                if kind == "parse-null":
                    output = canonical_text(parse_json("null", context=context, source_id="urn:gew:corpus"))
                elif kind == "parse-array":
                    output = canonical_text(parse_json("[1]", context=context, source_id="urn:gew:corpus"))
                elif kind == "schema-valid":
                    output = [failure.rule_id for failure in validate_instance({"type": "integer", "minimum": 1}, 2, source_id="urn:gew:corpus", context=context)]
                elif kind == "schema-format":
                    output = [failure.rule_id for failure in validate_instance({"type": "string", "format": "gew-id"}, "node-1", source_id="urn:gew:corpus", context=context)]
                elif kind == "geel-literal":
                    roots = StaticRootRegistry([])
                    output = GEELProgram.load({"op": "literal", "value": True}, roots, self.predicates, self.error_rules, context).evaluate({}, context)
                    if output["status"] == "error":
                        return {"status": "error", "code": output["error"]["code"], "balance": context.balance, "trace": context.trace}  # type: ignore[index]
                elif kind == "canonical":
                    output = canonicalize(1, context, source_id="urn:gew:corpus").decode()
                elif kind == "compare":
                    compare_charge(1, 1, context, operation_path=(), source_id="urn:gew:corpus")
                    output = True
                elif kind == "digest":
                    output = semantic_digest_charged(
                        {"a": 1}, context,
                        contract_type="urn:gew:contract:trace",
                        projection_id="urn:gew:digest-projection:identity:1.0.0",
                        schema_id="urn:gew:schema:trace:1.0.0",
                    )
                else:
                    raise AssertionError(kind)
                return {"status": "ok", "balance": context.balance, "trace": context.trace, "output": output}
            except ContractError as error:
                return {"status": "error", "code": error.detail.code, "balance": context.balance, "trace": context.trace}
        if operation == "production_boundary":
            return self.production_boundary(request["scenario"])  # type: ignore[arg-type]
        if operation == "immutable":
            frozen = freeze(request["value"])
            round_trip = freeze(thaw(frozen))
            value = request["value"]
            value_type = "null" if value is None else "boolean" if type(value) is bool else "integer" if type(value) is int else "string" if type(value) is str else "array" if isinstance(value, list) else "object"
            return {"canonical": canonical_text(thaw(frozen)), "round_trip_canonical": canonical_text(thaw(round_trip)), "json_type": value_type}
        if operation == "immutable_alias":
            shared = thaw(freeze(request["shared"]))
            source = {"left": shared, "right": shared}
            frozen = freeze(source)
            if isinstance(shared, dict):
                shared["mutation"] = request["mutation"]
            else:
                shared.append(request["mutation"])
            mutation_rejected = False
            try:
                frozen["left"]["mutation"] = request["mutation"]  # type: ignore[index]
            except (AttributeError, TypeError):
                mutation_rejected = True
            return {
                "frozen_canonical": canonical_text(thaw(frozen)),
                "mutated_source_canonical": canonical_text(source),
                "mutation_rejected": mutation_rejected,
            }
        if operation == "compatibility":
            manifest = CompatibilityMatrix.create_manifest("urn:gew:compatibility-matrix:corpus:1.0.0", request["rows"])  # type: ignore[arg-type]
            matrix = CompatibilityMatrix.from_dict(manifest)
            try:
                matrix.require(request["reader_id"], request["writer_id"])  # type: ignore[arg-type]
                return {"compatible": True}
            except ValueError:
                return {"compatible": False}
        if operation == "migration":
            try:
                registry = MigrationRegistry.from_dict(request["manifest"])  # type: ignore[arg-type]
                context = WorkContext(self.profile, self.schedule)
                schema_manifest = json.loads((ROOT / "config" / "contracts" / "migration-schema-registry-v1.json").read_text())
                bodies = {}
                for path in sorted((ROOT / "config" / "contracts" / "schemas").glob("contract-stack-*.json")):
                    body = path.read_bytes()
                    bodies[json.loads(body)["$id"]] = body
                policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
                schema_registry = ClosedSchemaRegistry.build(schema_manifest, bodies, self.profile, policy, context)
                result = registry.migrate(
                    request["value"],
                    source_contract_id=request["source_contract_id"],  # type: ignore[arg-type]
                    target_contract_id=request["target_contract_id"],  # type: ignore[arg-type]
                    actor_id=request["actor_id"],  # type: ignore[arg-type]
                    transaction_id=request["transaction_id"],  # type: ignore[arg-type]
                    expected_source_digest=request["expected_source_digest"],  # type: ignore[arg-type]
                    expected_schema_registry_id=request["expected_schema_registry_id"],  # type: ignore[arg-type]
                    expected_schema_registry_digest=request["expected_schema_registry_digest"],  # type: ignore[arg-type]
                    schema_registry=schema_registry,
                    context=context,
                )
                return {"status": "ok", **result}
            except (TypeError, ValueError) as error:
                message = str(error)
                code = "REGISTRY" if "registry" in message or "implementation" in message else "PATH" if "path" in message else "DIGEST" if "source digest" in message else "SOURCE"
                return {"status": "error", "code": code}
        if operation == "migration_path":
            specifications = tuple(
                _PathEdge(
                    transform_id=f"urn:gew:migration:corpus-{index}",
                    version="1.0.0",
                    source_contract_id=edge["source"],
                    target_contract_id=edge["target"],
                )
                for index, edge in enumerate(request["edges"])
            )
            return {"path_count": len(_all_paths(specifications, request["source"], request["target"]))}  # type: ignore[arg-type]
        raise AssertionError(f"unknown corpus operation: {operation}")

    def test_complete_gew_con_001_through_250_matches_frozen_and_independent_results(self) -> None:
        cases = self.corpus["cases"]
        self.assertEqual([case["case_id"] for case in cases], [f"GEW-CON-{index:03d}" for index in range(1, 251)])
        unsigned = dict(self.corpus)
        corpus_digest = unsigned.pop("corpus_digest")
        self.assertEqual(corpus_digest, raw_digest(canonical_bytes(unsigned)))
        self.assertNotEqual(
            hashlib.sha256((ROOT / "tests" / "support" / "wp01_reference.mjs").read_bytes()).hexdigest(),
            hashlib.sha256((ROOT / "core" / "graph_engineering" / "core" / "contracts" / "canonical.py").read_bytes()).hexdigest(),
        )
        envelope_operations = {"strict_json", "registry_contract", "digest_contract", "geel_summary", "production_trace", "migration"}
        for case in cases:
            with self.subTest(case=case["case_id"]):
                unsigned_case = dict(case)
                vector_digest = unsigned_case.pop("vector_digest")
                self.assertEqual(vector_digest, raw_digest(canonical_bytes(unsigned_case)))
                python_result = self.python_case(case["request"])
                node_result = self.invoke_reference(case["request"])
                if case["request"]["operation"] not in envelope_operations:
                    node_result.pop("status", None)
                self.assertEqual(case["expected"], python_result)
                self.assertEqual(case["expected"], node_result)


if __name__ == "__main__":
    unittest.main()
