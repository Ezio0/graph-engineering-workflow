from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT))

from graph_engineering.core.artifacts import (  # noqa: E402
    ArtifactContract,
    ArtifactContractError,
    ArtifactContractRegistry,
    ArtifactValidator,
    LogicalBodyManifest,
)
from graph_engineering.core.artifacts.contracts import ARTIFACT_TYPES, VALIDATOR_IDS  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.schema import (  # noqa: E402
    SchemaProfilePolicy,
    validate_schema_profile,
)
from tests.support.wp04a_artifacts import (  # noqa: E402
    contract_registry,
    load_json,
    loaded_golden,
    schema_registry,
    work_context,
)


class ArtifactContractTests(unittest.TestCase):
    def test_artifact_schema_registry_is_exact_profile_valid_and_digest_locked(self) -> None:
        names = (
            "artifact-contract-registry-1.0.0.json",
            "artifact-lifecycle-event-1.0.0.json",
            "artifact-record-1.0.0.json",
            "logical-body-manifest-1.0.0.json",
        )
        bodies: dict[str, bytes] = {}
        policy = SchemaProfilePolicy.from_dict(load_json(
            ROOT / "config" / "contracts" / "schema-profile-v1.json"
        ))
        for name in names:
            path = ROOT / "config" / "contracts" / "schemas" / name
            value = json.loads(path.read_text())
            schema_id = validate_schema_profile(value, policy)
            bodies[schema_id] = path.read_bytes()
        manifest = load_json(
            ROOT / "config" / "contracts" / "artifact-schema-registry-v1.json"
        )
        self.assertEqual(
            manifest,
            ClosedSchemaRegistry.create_manifest(
                "urn:gew:schema-registry:artifact-engine:1.0.0",
                bodies,
            ),
        )
        self.assertEqual(
            schema_registry().registry_digest,
            "sha256-jcs-v1:e678e63be62fc5dccd3d3b25d9367db660c25bfd3ef17b965b54696d3c3ee41d",
        )

    def test_contract_registry_contains_exact_ten_types_and_validator_set(self) -> None:
        context = work_context()
        schemas = schema_registry(context)
        registry = contract_registry(schemas, context)
        self.assertEqual(tuple(registry.contracts), ARTIFACT_TYPES)
        self.assertEqual(len(registry.contracts), 10)
        self.assertEqual(
            registry.registry_digest,
            "sha256-jcs-v1:dceeae0ad7e9b94054411d4b4e144f8655d3b1f494a87f438bf736465ed7c1ab",
        )
        for artifact_type, contract in registry.contracts.items():
            with self.subTest(artifact_type=artifact_type):
                self.assertEqual(contract.artifact_type, artifact_type)
                self.assertEqual(contract.validator_ids, VALIDATOR_IDS)
                self.assertTrue(contract.review_policy["independent"])
                self.assertEqual(
                    contract.exit_status,
                    "approved" if artifact_type in {"positioning", "prd", "tech-spec"}
                    else "accepted_for_next_node",
                )

    def test_contract_registry_tamper_unknown_and_construction_bypasses_fail_closed(self) -> None:
        context = work_context()
        schemas = schema_registry(context)
        source = load_json(ROOT / "config" / "contracts" / "artifact-contracts-v1.json")
        cases = []
        changed_digest = copy.deepcopy(source)
        changed_digest["contracts"][0]["required_semantic_fields"].pop()
        cases.append(changed_digest)
        unknown_type = copy.deepcopy(source)
        unknown_type["contracts"][0]["artifact_type"] = "unknown"
        cases.append(unknown_type)
        missing_contract = copy.deepcopy(source)
        missing_contract["contracts"].pop()
        cases.append(missing_contract)
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ArtifactContractError, ValueError)):
                ArtifactContractRegistry.from_dict(
                    value,
                    schema_registry=schemas,
                    context=context,
                    expected_registry_id=source["registry_id"],
                    expected_registry_digest=source["registry_digest"],
                )
        with self.assertRaises(TypeError):
            ArtifactContract()
        with self.assertRaises(TypeError):
            ArtifactContractRegistry()
        with self.assertRaises(TypeError):
            LogicalBodyManifest()
        registry = contract_registry(schemas, context)
        with self.assertRaisesRegex(ArtifactContractError, "unknown"):
            registry.resolve("unknown")
        with self.assertRaises(ArtifactContractError):
            ArtifactContractRegistry.from_dict(
                source,
                schema_registry=schemas,
                context=context,
                expected_registry_id=source["registry_id"],
                expected_registry_digest="sha256-jcs-v1:" + "0" * 64,
            )

    def test_every_declared_required_property_has_a_failing_mutation(self) -> None:
        record, _manifest, _contracts, _schemas, context, validation = loaded_golden("prd")
        artifact_schema = load_json(
            ROOT / "config" / "contracts" / "schemas" / "artifact-record-1.0.0.json"
        )
        for property_name in artifact_schema["required"]:
            mutated = copy.deepcopy(record)
            del mutated[property_name]
            with self.subTest(schema="artifact-record", property=property_name):
                self.assertEqual(
                    ArtifactValidator.validate(
                        mutated,
                        context=context,
                        **validation,
                    ).status,
                    "FAIL",
                )
        source = load_json(ROOT / "config" / "contracts" / "artifact-contracts-v1.json")
        registry_schema = load_json(
            ROOT / "config" / "contracts" / "schemas" / "artifact-contract-registry-1.0.0.json"
        )
        for property_name in registry_schema["required"]:
            mutated = copy.deepcopy(source)
            del mutated[property_name]
            with self.subTest(schema="contract-registry", property=property_name), self.assertRaises((ArtifactContractError, ValueError)):
                ArtifactContractRegistry.from_dict(
                    mutated,
                    schema_registry=validation["schema_registry"],
                    context=context,
                    expected_registry_id=source["registry_id"],
                    expected_registry_digest=source["registry_digest"],
                )
        for property_name in source["contracts"][0]:
            mutated = copy.deepcopy(source)
            del mutated["contracts"][0][property_name]
            with self.subTest(schema="artifact-contract", property=property_name), self.assertRaises((ArtifactContractError, ValueError)):
                ArtifactContractRegistry.from_dict(
                    mutated,
                    schema_registry=validation["schema_registry"],
                    context=context,
                    expected_registry_id=source["registry_id"],
                    expected_registry_digest=source["registry_digest"],
                )


if __name__ == "__main__":
    unittest.main()
