from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry, SchemaResource  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.schema import (  # noqa: E402
    SchemaProfileError,
    SchemaProfilePolicy,
    validate_instance,
    validate_schema_profile,
)


def object_schema(dialect_id: str, name: str, properties: dict[str, object], required: list[str], **extra: object) -> dict[str, object]:
    return {
        "$schema": dialect_id,
        "$id": f"urn:gew:schema:{name}:1.0.0",
        "type": "object",
        "properties": {"schema_version": {"const": "1.0.0"}, **properties},
        "required": ["schema_version", *required],
        "unevaluatedProperties": False,
        **extra,
    }


class SchemaRegistryTests(unittest.TestCase):
    def test_enum_validation_is_identical_before_and_after_registry_freeze(self) -> None:
        schema = object_schema(
            self.schema_policy.dialect_id,
            "enum-freeze",
            {"mode": {"enum": ["a", "b"]}},
            ["mode"],
        )
        bodies = {schema["$id"]: json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()}
        manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:enum-freeze:1.0.0", bodies)
        context = WorkContext(self.profile, self.schedule)
        registry = ClosedSchemaRegistry.build(manifest, bodies, self.profile, self.schema_policy, context)
        self.assertEqual(registry.validate(schema["$id"], {"schema_version": "1.0.0", "mode": "a"}, context), [])
        self.assertTrue(registry.validate(schema["$id"], {"schema_version": "1.0.0", "mode": "c"}, context))

    def test_frozen_schema_arrays_preserve_validation_and_exact_charge_trace(self) -> None:
        schema = object_schema(
            self.schema_policy.dialect_id,
            "frozen-arrays",
            {
                "choice": {"anyOf": [{"const": "a"}, {"const": "b"}]},
                "tuple": {
                    "type": "array",
                    "maxItems": 2,
                    "prefixItems": [{"type": "integer"}, {"type": "string"}],
                },
                "trigger": {"type": "boolean"},
                "dependent": {"type": "integer"},
            },
            ["choice", "tuple"],
            dependentRequired={"trigger": ["dependent"]},
        )
        bodies = {
            schema["$id"]: json.dumps(
                schema, sort_keys=True, separators=(",", ":"),
            ).encode(),
        }
        manifest = ClosedSchemaRegistry.create_manifest(
            "urn:gew:schema-registry:frozen-arrays:1.0.0", bodies,
        )
        registry = ClosedSchemaRegistry.build(
            manifest, bodies, self.profile, self.schema_policy,
        )
        frozen_schema = registry.resource(schema["$id"]).schema
        instances = {
            "valid": {
                "schema_version": "1.0.0", "choice": "a", "tuple": [1, "x"],
                "trigger": True, "dependent": 1,
            },
            "invalid": {
                "schema_version": "1.0.0", "choice": "c", "tuple": ["x", 1],
                "trigger": True,
            },
            "missing": {"schema_version": "1.0.0"},
        }
        failures: dict[str, list[object]] = {}
        for name, instance in instances.items():
            raw_context = WorkContext(self.profile, self.schedule)
            frozen_context = WorkContext(self.profile, self.schedule)
            raw_failures = validate_instance(
                schema, instance, source_id=schema["$id"], context=raw_context,
            )
            frozen_failures = validate_instance(
                frozen_schema, instance, source_id=schema["$id"], context=frozen_context,
            )
            with self.subTest(name=name):
                self.assertEqual(raw_failures, frozen_failures)
                self.assertEqual(raw_context.trace, frozen_context.trace)
                self.assertEqual(raw_context.balance, frozen_context.balance)
            failures[name] = raw_failures

        self.assertEqual(failures["valid"], [])
        self.assertIn("schema/required", {item.rule_id for item in failures["missing"]})
        self.assertTrue({"schema/anyOf", "schema/type", "schema/dependentRequired"}.issubset(
            {item.rule_id for item in failures["invalid"]}
        ))

    def setUp(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        self.profile = ResourceProfile.from_dict(value)
        schedule = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        self.schedule = CostSchedule.from_dict(schedule)
        policy = json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text())
        self.schema_policy = SchemaProfilePolicy.from_dict(policy)

    def test_profile_is_closed_and_rejects_unknown_numeric_and_unbounded_array(self) -> None:
        valid = object_schema(
            self.schema_policy.dialect_id,
            "sample",
            {
                "count": {"type": "integer", "minimum": 0},
                "tags": {"type": "array", "items": {"type": "string", "format": "gew-id"}, "maxItems": 4},
            },
            ["count", "tags"],
        )
        self.assertEqual(validate_schema_profile(valid, self.schema_policy), "urn:gew:schema:sample:1.0.0")
        mutations = [
            ("unknown", lambda value: value.update({"pattern": "x"})),
            ("number", lambda value: value["properties"]["count"].update({"type": "number"})),
            ("unbounded", lambda value: value["properties"]["tags"].pop("maxItems")),
            ("unknown-format", lambda value: value["properties"]["count"].update({"format": "email"})),
            ("nested-id", lambda value: value["properties"]["count"].update({"$id": "urn:gew:schema:nested:1.0.0"})),
        ]
        for name, mutate in mutations:
            changed = json.loads(json.dumps(valid))
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(SchemaProfileError):
                validate_schema_profile(changed, self.schema_policy)

    def test_validation_has_exact_types_formats_combinators_and_stable_error_order(self) -> None:
        schema = object_schema(
            self.schema_policy.dialect_id,
            "validation",
            {
                "identifier": {"type": "string", "format": "gew-id"},
                "count": {"type": "integer", "minimum": 1},
                "enabled": {"type": "boolean"},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2, "uniqueItems": True},
            },
            ["identifier", "count", "enabled", "tags"],
            allOf=[{"properties": {"count": {"maximum": 3}}}],
        )
        validate_schema_profile(schema, self.schema_policy)
        valid = {"schema_version": "1.0.0", "identifier": "node-1", "count": 2, "enabled": True, "tags": ["a", "b"]}
        self.assertEqual(validate_instance(schema, valid, source_id=schema["$id"]), [])
        invalid = {"schema_version": "1.0.0", "identifier": "Node", "count": True, "enabled": 1, "tags": ["a", "a"], "rogue": 1}
        first = validate_instance(schema, invalid, source_id=schema["$id"])
        second = validate_instance(json.loads(json.dumps(schema, sort_keys=True)), invalid, source_id=schema["$id"])
        self.assertEqual(first, second)
        self.assertTrue({failure.rule_id for failure in first}.issuperset({"schema/type", "schema/uniqueItems", "schema/unevaluatedProperties"}))
        self.assertEqual(first, sorted(first, key=lambda failure: (canonical_bytes(list(failure.instance_path)), failure.rule_id.encode(), canonical_bytes(list(failure.definition_path)), failure.source_id.encode())))

    def test_registry_is_digest_locked_offline_and_resolves_only_registered_pointers(self) -> None:
        base = object_schema(self.schema_policy.dialect_id, "base", {"value": {"type": "integer"}}, ["value"])
        wrapper = object_schema(self.schema_policy.dialect_id, "wrapper", {"payload": {"$ref": "urn:gew:schema:base:1.0.0"}}, ["payload"])
        bodies = {
            base["$id"]: json.dumps(base, sort_keys=True, separators=(",", ":")).encode(),
            wrapper["$id"]: json.dumps(wrapper, sort_keys=True, separators=(",", ":")).encode(),
        }
        manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:test:1.0.0", bodies)
        context = WorkContext(self.profile, self.schedule)
        with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("network used")):
            registry = ClosedSchemaRegistry.build(manifest, bodies, self.profile, self.schema_policy, context)
        registry_events = {record["event_id"] for record in context.trace}
        self.assertTrue({"registry.resource", "registry.schema_byte", "registry.schema_location", "registry.ref_edge", "registry.digest_compare"}.issubset(registry_events))
        resource_traces: dict[tuple[int, ...], list[str]] = {}
        for record in context.trace:
            if record["event_id"].startswith("registry."):
                resource_traces.setdefault(tuple(record["operation_path"]), []).append(record["event_id"])
        self.assertEqual(len(resource_traces), 2)
        for events in resource_traces.values():
            self.assertEqual(events[:2], ["registry.resource", "registry.schema_byte"])
            self.assertEqual(events[-1], "registry.digest_compare")
            self.assertIn("registry.schema_location", events[2:-1])
            if "registry.ref_edge" in events:
                self.assertLess(events.index("registry.ref_edge"), events.index("registry.digest_compare"))
        self.assertEqual(registry.validate(wrapper["$id"], {"schema_version": "1.0.0", "payload": {"schema_version": "1.0.0", "value": 2}}, WorkContext(self.profile, self.schedule)), [])
        self.assertTrue(registry.validate(wrapper["$id"], {"schema_version": "1.0.0", "payload": {"schema_version": "1.0.0", "value": True}}, WorkContext(self.profile, self.schedule)))
        with self.assertRaises(TypeError):
            registry.resource(base["$id"]).schema["type"] = "string"  # type: ignore[index]
        with self.assertRaises(TypeError):
            registry._resources[base["$id"]] = registry.resource(base["$id"])  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            registry._resources = {}
        with self.assertRaises((AttributeError, TypeError)):
            registry.registry_digest = "forged"
        with self.assertRaises(TypeError):
            ClosedSchemaRegistry("urn:gew:schema-registry:forged:1.0.0", "forged", {})  # type: ignore[call-arg]
        tampered = dict(bodies)
        tampered[base["$id"]] += b" "
        with self.assertRaisesRegex(ValueError, "digest"):
            ClosedSchemaRegistry.build(manifest, tampered, self.profile, self.schema_policy)
        swapped = json.loads(json.dumps(manifest))
        swapped["registry_digest"] = "sha256-jcs-v1:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            ClosedSchemaRegistry.build(swapped, bodies, self.profile, self.schema_policy)

    def test_direct_schema_resource_constructor_is_not_an_unattested_path(self) -> None:
        source = {"type": "object", "properties": {"value": {"type": "integer"}}}
        raw = b'{"properties":{"value":{"type":"integer"}},"type":"object"}'
        with self.assertRaises(TypeError):
            SchemaResource("urn:gew:schema:direct:1.0.0", raw, "sha256-raw-v1:" + "0" * 64, source)  # type: ignore[call-arg]
        for factory_only_type in (SchemaResource, ClosedSchemaRegistry):
            with self.subTest(factory_only_type=factory_only_type.__name__), self.assertRaises(TypeError):
                factory_only_type()  # type: ignore[call-arg]
            with self.subTest(factory_only_type=factory_only_type.__name__), self.assertRaises(TypeError):
                type(f"Forged{factory_only_type.__name__}", (factory_only_type,), {})
    def test_unevaluated_annotations_propagate_across_applicators_and_refs(self) -> None:
        all_of_schema = {
            "type": "object",
            "allOf": [{"properties": {"x": {"type": "integer"}}}],
            "unevaluatedProperties": False,
        }
        self.assertEqual(validate_instance(all_of_schema, {"x": 1}, source_id="urn:gew:schema:test:1.0.0"), [])
        self.assertTrue(validate_instance(all_of_schema, {"x": True}, source_id="urn:gew:schema:test:1.0.0"))
        contains_schema = {
            "type": "array",
            "contains": {"type": "integer"},
            "unevaluatedItems": False,
        }
        self.assertEqual(validate_instance(contains_schema, [1, 2], source_id="urn:gew:schema:test:1.0.0"), [])
        self.assertTrue(validate_instance(contains_schema, [1, "x"], source_id="urn:gew:schema:test:1.0.0"))

        target = {"properties": {"x": {"type": "integer"}}}
        ref_schema = {"$ref": "urn:gew:schema:target:1.0.0", "unevaluatedProperties": False}

        def resolver(_source: str, _reference: str) -> tuple[object, str]:
            return target, "urn:gew:schema:target:1.0.0"

        self.assertEqual(validate_instance(ref_schema, {"x": 1}, source_id="urn:gew:schema:ref:1.0.0", resolver=resolver), [])

    def test_schema_format_combinator_unique_and_result_work_is_recursively_charged(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "identifier": {"type": "string", "format": "gew-id"},
                "values": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "contains": {"type": "integer"},
                    "maxItems": 4,
                    "uniqueItems": True,
                },
            },
            "allOf": [{"required": ["identifier", "values"]}],
            "unevaluatedProperties": False,
        }
        context = WorkContext(self.profile, self.schedule)
        self.assertEqual(
            validate_instance(schema, {"identifier": "node-1", "values": [1, 2]}, source_id="urn:gew:schema:charge:1.0.0", context=context),
            [],
        )
        events = [record["event_id"] for record in context.trace]
        for expected in (
            "schema.instance_visit", "schema.keyword", "schema.property", "schema.item",
            "schema.branch", "schema.format", "format.scalar", "unique.pair", "compare.base",
        ):
            self.assertIn(expected, events)
        self.assertEqual(context._temporary_units, 0)

    def test_registry_rejects_remote_relative_unknown_pointer_and_cycles(self) -> None:
        for name, reference in (
            ("remote", "https://example.test/schema"),
            ("relative", "other.json"),
            ("pointer", "#/missing"),
            ("dynamic", "#anchor"),
        ):
            schema = object_schema(self.schema_policy.dialect_id, name, {"value": {"$ref": reference}}, ["value"])
            bodies = {schema["$id"]: json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()}
            manifest = ClosedSchemaRegistry.create_manifest(f"urn:gew:schema-registry:{name}:1.0.0", bodies)
            with self.subTest(name=name), self.assertRaises(ValueError):
                ClosedSchemaRegistry.build(manifest, bodies, self.profile, self.schema_policy)
        cycle = object_schema(self.schema_policy.dialect_id, "cycle", {"value": {"$ref": "#/properties/value"}}, ["value"])
        bodies = {cycle["$id"]: json.dumps(cycle, sort_keys=True, separators=(",", ":")).encode()}
        manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:cycle:1.0.0", bodies)
        with self.assertRaisesRegex(ValueError, "cyclic"):
            ClosedSchemaRegistry.build(manifest, bodies, self.profile, self.schema_policy)

    def test_registry_limits_fail_with_stable_e_limit_and_validation_requires_context(self) -> None:
        schema = object_schema(self.schema_policy.dialect_id, "limited", {"value": {"type": "integer"}}, ["value"])
        bodies = {schema["$id"]: json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()}
        manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:limited:1.0.0", bodies)
        for limit_id in ("registry_resources", "schema_bytes", "schema_locations"):
            changed = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
            changed["limits"][limit_id] = 1
            if limit_id == "registry_resources":
                second = object_schema(self.schema_policy.dialect_id, "limited-second", {}, [])
                limited_bodies = dict(bodies)
                limited_bodies[second["$id"]] = json.dumps(second, sort_keys=True, separators=(",", ":")).encode()
                limited_manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:limited:1.0.0", limited_bodies)
            else:
                limited_bodies = bodies
                limited_manifest = manifest
            profile = ResourceProfile.from_dict(changed)
            with self.subTest(limit_id=limit_id), self.assertRaises(ContractError) as caught:
                ClosedSchemaRegistry.build(limited_manifest, limited_bodies, profile, self.schema_policy)
            self.assertEqual(caught.exception.detail.code, "E_LIMIT")
            self.assertEqual(caught.exception.detail.rule_id, f"limit/{limit_id}")

        context = WorkContext(self.profile, self.schedule)
        registry = ClosedSchemaRegistry.build(manifest, bodies, self.profile, self.schema_policy, context)
        validation_context = WorkContext(self.profile, self.schedule)
        self.assertEqual(
            registry.validate(schema["$id"], {"schema_version": "1.0.0", "value": 1}, validation_context),
            [],
        )
        self.assertIn("schema.instance_visit", {record["event_id"] for record in validation_context.trace})
        with self.assertRaises(TypeError):
            registry.validate(schema["$id"], {"schema_version": "1.0.0", "value": 1})  # type: ignore[call-arg]


if __name__ == "__main__":
    unittest.main()
