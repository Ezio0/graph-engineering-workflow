from __future__ import annotations

import json
import inspect
import pathlib
import sys
import unittest
from dataclasses import dataclass
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.contracts.versioning import CompatibilityMatrix, MigrationRegistry, MigrationSpec, _all_paths  # noqa: E402
import graph_engineering.core.contracts.versioning as versioning_module  # noqa: E402


SCHEMA_REGISTRY_ID = "urn:gew:schema-registry:migration:1.0.0"
SCHEMA_REGISTRY_DIGEST = "sha256-jcs-v1:7886b195ddd46637995cc1aae91e6612315965bd5ccc2df8f17b19bce85954f0"


@dataclass(frozen=True)
class _PathEdge:
    transform_id: str
    version: str
    source_contract_id: str
    target_contract_id: str


class VersioningContractTests(unittest.TestCase):
    def context(self) -> WorkContext:
        profile = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        schedule = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        return WorkContext(ResourceProfile.from_dict(profile), CostSchedule.from_dict(schedule))

    def schema_registry(self, context: WorkContext) -> ClosedSchemaRegistry:
        manifest = json.loads((ROOT / "config" / "contracts" / "migration-schema-registry-v1.json").read_text())
        bodies = {}
        for path in sorted((ROOT / "config" / "contracts" / "schemas").glob("contract-stack-*.json")):
            body = path.read_bytes()
            bodies[json.loads(body)["$id"]] = body
        policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()))
        profile = ResourceProfile.from_dict(json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()))
        return ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)

    def test_exact_declared_reader_writer_pair_passes(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "compatibility-matrix-v1.json").read_text())
        matrix = CompatibilityMatrix.from_dict(value)
        matrix.require("urn:gew:contract-stack:1.0.0", "urn:gew:contract-stack:1.0.0")

    def test_unknown_or_directionally_undeclared_version_fails(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "compatibility-matrix-v1.json").read_text())
        matrix = CompatibilityMatrix.from_dict(value)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            matrix.require("urn:gew:contract-stack:1.0.0", "urn:gew:contract-stack:1.0.1")
        with self.assertRaisesRegex(ValueError, "incompatible"):
            matrix.require("urn:gew:contract-stack:1.0.1", "urn:gew:contract-stack:1.0.0")
        with self.assertRaises(TypeError):
            matrix.readers["urn:gew:contract-stack:1.0.0"] = frozenset({"urn:gew:contract-stack:1.0.1"})  # type: ignore[index]
        tampered = json.loads(json.dumps(value))
        tampered["rows"][0]["accepted_writer_ids"].append("urn:gew:contract-stack:1.0.1")
        with self.assertRaisesRegex(ValueError, "digest"):
            CompatibilityMatrix.from_dict(tampered)
        with self.assertRaises(TypeError):
            CompatibilityMatrix("urn:gew:compatibility-matrix:direct:1.0.0", "digest", {"reader": {"writer"}})  # type: ignore[call-arg]
        with self.assertRaises((AttributeError, TypeError)):
            matrix.readers = {"forged": frozenset({"writer"})}
        with self.assertRaises(TypeError):
            CompatibilityMatrix()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            type("ForgedCompatibilityMatrix", (CompatibilityMatrix,), {})
    def test_migration_is_unique_digest_locked_and_byte_identical(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "migration-registry-v1.json").read_text())
        registry = MigrationRegistry.from_dict(value)
        self.assertNotIn("validators", inspect.signature(registry.migrate).parameters)
        with self.assertRaises(TypeError):
            MigrationRegistry(registry.registry_id, registry.registry_digest, registry._specifications)  # type: ignore[call-arg]

        source = {"schema_version": "1.0.0", "value": 1}
        expected_source_digest = semantic_digest(
            source,
            contract_type="urn:gew:contract-stack:1.0.0",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id="urn:gew:schema:contract-stack:1.0.0",
        )
        arguments = {
            "source_contract_id": "urn:gew:contract-stack:1.0.0",
            "target_contract_id": "urn:gew:contract-stack:1.0.1",
            "actor_id": "codex:test",
            "transaction_id": "tx-1",
            "expected_source_digest": expected_source_digest,
            "expected_schema_registry_id": SCHEMA_REGISTRY_ID,
            "expected_schema_registry_digest": SCHEMA_REGISTRY_DIGEST,
        }
        first_context = self.context()
        second_context = self.context()
        first = registry.migrate(source, context=first_context, schema_registry=self.schema_registry(first_context), **arguments)
        second = registry.migrate({"value": 1, "schema_version": "1.0.0"}, context=second_context, schema_registry=self.schema_registry(second_context), **arguments)
        self.assertEqual(first, second)
        self.assertEqual(first["output"]["schema_version"], "1.0.1")
        self.assertEqual(first["output_canonical"], '{"schema_version":"1.0.1","value":1}')
        self.assertEqual(first["provenance_canonical"], json.dumps(first["provenance"], sort_keys=True, separators=(",", ":")))
        first_events = [record["event_id"] for record in first_context.trace]
        executable = first_events.index("executable.base")
        self.assertIn("digest.input_byte", first_events[:executable])
        self.assertIn("digest.input_byte", first_events[executable + 1:])
        self.assertEqual(first_events.count("canonical.value"), 4)
        self.assertEqual(first_context._temporary_units, 0)
        changed_arguments = dict(arguments)
        changed_arguments["expected_source_digest"] = "sha256-jcs-v1:" + "0" * 64
        mismatch_context = self.context()
        with self.assertRaisesRegex(ValueError, "source digest"):
            registry.migrate(source, context=mismatch_context, schema_registry=self.schema_registry(mismatch_context), **changed_arguments)
        for field, wrong_value in (
            ("expected_schema_registry_id", "urn:gew:schema-registry:migration:9.9.9"),
            ("expected_schema_registry_digest", "sha256-jcs-v1:" + "0" * 64),
        ):
            wrong_registry_arguments = dict(arguments)
            wrong_registry_arguments[field] = wrong_value
            wrong_context = self.context()
            with self.assertRaisesRegex(ValueError, "schema registry"):
                registry.migrate(
                    source,
                    context=wrong_context,
                    schema_registry=self.schema_registry(wrong_context),
                    **wrong_registry_arguments,
                )
        missing_registry_pin = dict(arguments)
        del missing_registry_pin["expected_schema_registry_digest"]
        missing_context = self.context()
        with self.assertRaises(TypeError):
            registry.migrate(
                source,
                context=missing_context,
                schema_registry=self.schema_registry(missing_context),
                **missing_registry_pin,
            )
        with self.assertRaisesRegex(TypeError, "closed schema registry"):
            registry.migrate(source, context=self.context(), schema_registry=None, **arguments)
        sealed_context = self.context()
        sealed_schema_registry = self.schema_registry(sealed_context)
        with self.assertRaises((AttributeError, TypeError)):
            sealed_schema_registry._resources = {}
        rogue = {"schema_version": "1.0.0", "rogue": 1}
        rogue_arguments = dict(arguments)
        rogue_arguments["expected_source_digest"] = semantic_digest(
            rogue,
            contract_type="urn:gew:contract-stack:1.0.0",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id="urn:gew:schema:contract-stack:1.0.0",
        )
        with self.assertRaisesRegex(ValueError, "source schema"):
            registry.migrate(
                rogue,
                context=self.context(),
                schema_registry=sealed_schema_registry,
                **rogue_arguments,
            )
        with self.assertRaisesRegex(ValueError, "found 0"):
            registry.resolve_unique_path("urn:gew:contract-stack:1.0.1", "urn:gew:contract-stack:1.0.0")
        with self.assertRaisesRegex(ValueError, "path must be unique"):
            registry.resolve_unique_path("urn:gew:contract-stack:1.0.0", "urn:gew:contract-stack:1.0.0")

        tampered = json.loads(json.dumps(value))
        tampered["transforms"][0]["implementation_digest"] = "sha256-raw-v1:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            MigrationRegistry.from_dict(tampered)

        installed = registry._specifications[0]
        self.assertFalse(hasattr(installed, "implementation"))
        with self.assertRaises(TypeError):
            MigrationRegistry()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            type("ForgedMigrationRegistry", (MigrationRegistry,), {})
        with self.assertRaises(TypeError):
            type("ForgedMigrationSpec", (MigrationSpec,), {})
        with self.assertRaises(TypeError):
            MigrationSpec(
                transform_id="urn:gew:migration:unattested",
                version="9.9.9",
                source_contract_id="urn:gew:contract:a",
                target_contract_id="urn:gew:contract:b",
                input_schema_id="urn:gew:schema:a:1.0.0",
                output_schema_id="urn:gew:schema:b:1.0.0",
                multipliers={event_id: 1 for event_id in (
                    "executable.base", "executable.input_node", "executable.input_scalar", "executable.input_byte",
                )},
                implementation_id="extension:unattested",
                implementation_digest="sha256-raw-v1:" + "0" * 64,
            )
        direct = _PathEdge(
            installed.transform_id,
            installed.version,
            installed.source_contract_id,
            installed.target_contract_id,
        )
        first_leg = _PathEdge(
            "urn:gew:migration:first-leg",
            installed.version,
            installed.source_contract_id,
            "urn:gew:contract-stack:1.0.0-mid",
        )
        second_leg = _PathEdge(
            "urn:gew:migration:second-leg",
            installed.version,
            "urn:gew:contract-stack:1.0.0-mid",
            installed.target_contract_id,
        )
        self.assertEqual(
            len(_all_paths((direct, first_leg, second_leg), "urn:gew:contract-stack:1.0.0", "urn:gew:contract-stack:1.0.1")),  # type: ignore[arg-type]
            2,
        )
        with self.assertRaises(TypeError):
            installed.multipliers["executable.base"] = 2  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            registry._specifications = ()
    def test_migration_executes_only_the_frozen_registry_code_binding(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "migration-registry-v1.json").read_text())
        registry = MigrationRegistry.from_dict(value)
        source = {"schema_version": "1.0.0", "value": 1}
        expected_source_digest = semantic_digest(
            source,
            contract_type="urn:gew:contract-stack:1.0.0",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id="urn:gew:schema:contract-stack:1.0.0",
        )
        arguments = {
            "source_contract_id": "urn:gew:contract-stack:1.0.0",
            "target_contract_id": "urn:gew:contract-stack:1.0.1",
            "actor_id": "codex:test",
            "transaction_id": "tx-attestation",
            "expected_source_digest": expected_source_digest,
            "expected_schema_registry_id": SCHEMA_REGISTRY_ID,
            "expected_schema_registry_digest": SCHEMA_REGISTRY_DIGEST,
        }

        def changed(value: object) -> object:
            del value
            return {"schema_version": "1.0.1", "value": 999}

        for target in ("_upgrade_contract_stack_1_0_0_to_1_0_1", "_verified_migration_implementation", "thaw"):
            context = self.context()
            schema_registry = self.schema_registry(context)
            with mock.patch.object(versioning_module, target, changed, create=True):
                result = registry.migrate(source, context=context, schema_registry=schema_registry, **arguments)
            self.assertEqual(result["output"]["value"], 1)

        implementation = versioning_module._upgrade_contract_stack_1_0_0_to_1_0_1
        original_code = implementation.__code__
        code_context = self.context()
        try:
            implementation.__code__ = changed.__code__
            result = registry.migrate(
                source,
                context=code_context,
                schema_registry=self.schema_registry(code_context),
                **arguments,
            )
            self.assertEqual(result["output"]["value"], 1)
        finally:
            implementation.__code__ = original_code
        with self.assertRaises((AttributeError, TypeError)):
            registry._implementation = registry._implementation

    def test_migration_result_and_provenance_bytes_are_charged_before_allocation(self) -> None:
        registry = MigrationRegistry.from_dict(json.loads((ROOT / "config" / "contracts" / "migration-registry-v1.json").read_text()))
        source = {"schema_version": "1.0.0", "value": 1}
        expected_source_digest = semantic_digest(
            source,
            contract_type="urn:gew:contract-stack:1.0.0",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id="urn:gew:schema:contract-stack:1.0.0",
        )
        baseline = self.context()
        registry.migrate(
            source,
            source_contract_id="urn:gew:contract-stack:1.0.0",
            target_contract_id="urn:gew:contract-stack:1.0.1",
            actor_id="codex:test",
            transaction_id="tx-budget",
            expected_source_digest=expected_source_digest,
            expected_schema_registry_id=SCHEMA_REGISTRY_ID,
            expected_schema_registry_digest=SCHEMA_REGISTRY_DIGEST,
            schema_registry=self.schema_registry(baseline),
            context=baseline,
        )
        output_byte_attempts = [record for record in baseline.trace if record["event_id"] == "canonical.output_byte"]
        self.assertGreater(len(output_byte_attempts), 0)
        consumed = baseline.profile.work_budget - baseline.balance

        profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        profile_value["work_budget"] = consumed - 1
        schedule_value = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        constrained = WorkContext(ResourceProfile.from_dict(profile_value), CostSchedule.from_dict(schedule_value))
        with self.assertRaises(ContractError) as caught:
            registry.migrate(
                source,
                source_contract_id="urn:gew:contract-stack:1.0.0",
                target_contract_id="urn:gew:contract-stack:1.0.1",
                actor_id="codex:test",
                transaction_id="tx-budget",
                expected_source_digest=expected_source_digest,
                expected_schema_registry_id=SCHEMA_REGISTRY_ID,
                expected_schema_registry_digest=SCHEMA_REGISTRY_DIGEST,
                schema_registry=self.schema_registry(constrained),
                context=constrained,
            )
        self.assertEqual(caught.exception.detail.code, "E_BUDGET")
        self.assertEqual(constrained.trace[-1]["status"], "rejected")
        self.assertEqual(constrained.trace[-1]["event_id"], "result.output_byte")
        self.assertEqual(constrained._temporary_units, 0)


if __name__ == "__main__":
    unittest.main()
