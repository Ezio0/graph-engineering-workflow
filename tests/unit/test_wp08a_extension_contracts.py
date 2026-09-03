"""WP-08A extension trust contract slice (GEW-EXT-001..003)."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import ResourceProfile
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.security import extensions


ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256-jcs-v1:" + "a" * 64
RAW_DIGEST = "sha256-raw-v1:" + "b" * 64


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _identity_body() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "publisher_id": "publisher.example",
        "extension_id": "extension.example",
        "extension_version": "1.2.3",
        "release_id": "release.example.1",
        "package_class": "data-only",
        "extension_points": [
            {"kind": "schema", "id": "schema.example", "contract_digest": DIGEST}
        ],
        "exported_identities": [
            {"kind": "schema", "id": "schema.example", "contract_digest": DIGEST}
        ],
        "input_schema_ids": ["urn:gew:schema:input-example:1.0.0"],
        "output_schema_ids": ["urn:gew:schema:output-example:1.0.0"],
        "contract_registry_digest": DIGEST,
        "compatibility": {
            "core_version_range": ">=1.0.0,<2.0.0",
            "cli_protocol_range": ">=1.0.0,<2.0.0",
            "schema_profile_range": ">=1.0.0,<2.0.0",
            "geel_range": ">=1.0.0,<2.0.0",
            "runtime_capabilities_digest": DIGEST,
        },
        "requested_capabilities": [],
        "operation_classes": [],
        "ordered_resources": [],
        "side_effects": [],
        "idempotency_semantics": {
            "contract_id": "contract.idempotency",
            "contract_version": "1.0.0",
            "contract_digest": DIGEST,
        },
        "failure_semantics": {
            "contract_id": "contract.failure",
            "contract_version": "1.0.0",
            "contract_digest": DIGEST,
        },
        "verification_semantics": {
            "contract_id": "contract.verification",
            "contract_version": "1.0.0",
            "contract_digest": DIGEST,
        },
        "executable_contract": None,
    }


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    result = copy.deepcopy(body)
    result[field] = _digest(body, name)
    return result


def _genesis_policy() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "installation_id": "installation.example",
        "generation": 0,
        "previous_policy_digest": None,
        "revocation_high_water": 0,
        "revocations": [],
        "trust_keys": [],
        "production_policies": [],
        "source_rules": [],
        "namespace_rules": [],
        "extension_kind_rules": [],
        "capability_ceilings": [],
        "compatibility_floors": [],
        "resource_policy_digest": DIGEST,
        "reducer_id": "gew.extension-trust-policy-reducer",
        "reducer_version": "1.0.0",
        "reducer_implementation_digest": extensions.EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST,
    }
    return _complete(body, "extension-trust-policy", "policy_digest")


class ExtensionContractTests(unittest.TestCase):
    def test_gew_ext_001_package_identity_and_manifest_are_exact_and_reconstructable(self) -> None:
        identity_type = getattr(extensions, "ExtensionPackageIdentity")
        manifest_type = getattr(extensions, "ExtensionPackageManifest")
        body = _identity_body()
        identity_document = _complete(body, "extension-package-identity", "package_identity_digest")
        identity = identity_type.from_dict(identity_document)
        self.assertEqual(identity.to_dict(), identity_document)

        manifest_body = {
            **copy.deepcopy(body),
            "source_attestation_digest": DIGEST,
            "build_attestation_digest": DIGEST,
            "payload_root_digest": DIGEST,
            "package_identity_digest": identity.package_identity_digest,
            "signing_suite": "ed25519-v1",
            "publisher_key_id": "publisher.key.1",
            "revocation_sequence_floor": 0,
        }
        manifest_document = _complete(
            manifest_body, "extension-package-manifest", "manifest_digest"
        )
        manifest = manifest_type.from_dict(manifest_document)
        self.assertEqual(manifest.package_identity_digest, identity.package_identity_digest)
        self.assertEqual(manifest.reconstructed_identity().to_dict(), identity_document)

        alias = copy.deepcopy(identity_document)
        alias["exported_ids"] = alias.pop("exported_identities")
        del alias["package_identity_digest"]
        alias["package_identity_digest"] = _digest(alias, "extension-package-identity")
        with self.assertRaisesRegex(ValueError, "exact|properties"):
            identity_type.from_dict(alias)

        substituted = copy.deepcopy(manifest_document)
        substituted["extension_points"][0]["id"] = "schema.other"  # type: ignore[index]
        del substituted["manifest_digest"]
        substituted["manifest_digest"] = _digest(substituted, "extension-package-manifest")
        with self.assertRaisesRegex(ValueError, "identity"):
            manifest_type.from_dict(substituted)

    def test_gew_ext_002_trust_policy_and_transaction_contracts_are_closed(self) -> None:
        policy_type = getattr(extensions, "ExtensionTrustPolicy")
        ledger_type = getattr(extensions, "ExtensionTrustLedgerRecord")
        genesis = policy_type.from_dict(_genesis_policy())
        self.assertEqual(genesis.generation, 0)

        candidate_body = copy.deepcopy(_genesis_policy())
        candidate_body.update(
            generation=1,
            previous_policy_digest=genesis.policy_digest,
            revocation_high_water=1,
        )
        del candidate_body["policy_digest"]
        candidate = policy_type.from_dict(
            _complete(candidate_body, "extension-trust-policy", "policy_digest"),
            previous=genesis,
        )
        self.assertEqual(candidate.generation, 1)

        prepared_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "record_type": "prepared",
            "installation_id": "installation.example",
            "transaction_id": "transaction.example.1",
            "record_sequence": 1,
            "previous_record_digest": None,
            "expected_head_digest": DIGEST,
            "owner_identity": "owner.example",
            "owner_decision_digest": DIGEST,
            "owner_authority_digest": DIGEST,
            "created_at": "2026-08-20T00:00:00Z",
            "expected_generation": 0,
            "expected_policy_digest": genesis.policy_digest,
            "expected_revocation_high_water": 0,
            "candidate_generation": 1,
            "candidate_policy_digest": candidate.policy_digest,
            "candidate_revocation_high_water": 1,
            "ordered_operations_digest": DIGEST,
        }
        prepared_document = _complete(
            prepared_body, "extension-trust-prepared", "record_digest"
        )
        prepared = ledger_type.from_dict(prepared_document, current_policy=genesis)
        self.assertEqual(prepared.record_type, "prepared")

        extra = copy.deepcopy(prepared_document)
        extra["wildcard"] = "*"
        del extra["record_digest"]
        extra["record_digest"] = _digest(extra, "extension-trust-prepared")
        with self.assertRaisesRegex(ValueError, "exact|properties"):
            ledger_type.from_dict(extra, current_policy=genesis)

        rollback = copy.deepcopy(candidate.to_dict())
        rollback.update(generation=2, previous_policy_digest=candidate.policy_digest, revocation_high_water=0)
        del rollback["policy_digest"]
        rollback["policy_digest"] = _digest(rollback, "extension-trust-policy")
        with self.assertRaisesRegex(ValueError, "high-water"):
            policy_type.from_dict(rollback, previous=candidate)

    def test_gew_ext_003_schema_registry_is_closed_and_executable_gate_has_no_bypass(self) -> None:
        registry_path = ROOT / "config/contracts/extension-schema-registry-v1.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        expected_schema_ids = {
            f"urn:gew:schema:{name}{suffix}:1.0.0"
            for name in (
                "extension-package-identity",
                "extension-package-manifest",
                "extension-publisher-revocation",
                "extension-source-attestation",
                "extension-attestation-production-policy",
                "extension-build-attestation",
                "extension-publisher-signature",
                "extension-install-request",
                "extension-ingest-record",
                "extension-installed-content",
                "extension-activation-request",
                "extension-activation-manifest",
                "extension-active-set-pointer",
                "extension-active-set-request",
                "extension-activation-policy",
                "extension-built-in-registry",
                "extension-core-invariant-set",
                "extension-data-node",
                "extension-data-edge",
                "extension-data-policy",
                "extension-data-template",
                "extension-data-registry",
                "extension-task-pin-request",
                "extension-activation-record",
                "extension-task-pin-record",
                "extension-diagnostic-record",
                "extension-trust-policy",
                "extension-trust-prepared",
                "extension-trust-commit",
                "extension-trust-abort",
                "extension-trust-rollback",
                "extension-trust-policy-head",
            )
            for suffix in ("", "-input")
        }
        expected_schema_ids.add("urn:gew:schema:extension-payload-root-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-conflict-override-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-capability-request-set-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-capability-set-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-coverage-execution-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-coverage-execution:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-coverage-candidate-context-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-coverage-candidate-context:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-capability-profile-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-activation-resource-binding-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-active-package-binding-input:1.0.0")
        expected_schema_ids.add("urn:gew:schema:extension-activation-tombstone-input:1.0.0")
        self.assertEqual(
            {item["schema_id"] for item in registry["resources"]}, expected_schema_ids
        )
        bodies: dict[str, bytes] = {}
        for item in registry["resources"]:
            filename = item["schema_id"].removeprefix("urn:gew:schema:").replace(":", "-")
            path = ROOT / "config/contracts/schemas" / f"{filename}.json"
            self.assertTrue(path.is_file())
            bodies[item["schema_id"]] = path.read_bytes()
        self.assertEqual(
            registry,
            ClosedSchemaRegistry.create_manifest(
                "urn:gew:schema-registry:extensions:1.0.0", bodies
            ),
        )
        profile = ResourceProfile.from_dict(json.loads(
            (ROOT / "config/contracts/resource-profile-v1.json").read_text(encoding="utf-8")
        ))
        policy = SchemaProfilePolicy.from_dict(json.loads(
            (ROOT / "config/contracts/schema-profile-v1.json").read_text(encoding="utf-8")
        ))
        built = ClosedSchemaRegistry.build(registry, bodies, profile, policy)
        self.assertEqual(built.registry_digest, registry["registry_digest"])

        for extension_kind in (
            "node",
            "predicate",
            "validator",
            "transform",
            "adapter",
            "connector",
            "presentation",
        ):
            with self.assertRaisesRegex(
                extensions.ExtensionError, "E_EXTENSION_EXECUTABLE_CONTRACT_GATE"
            ):
                extensions.ExtensionGate.require_non_builtin_executable_disabled(extension_kind)


if __name__ == "__main__":
    unittest.main()
