"""WP-08A categorized data-only activation and task pinning (GEW-EXT-010..013)."""

from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace

from graph_engineering.application.extensions import (
    ExtensionInstallationApplication,
    ExtensionManagementApplication,
)
from graph_engineering.application.runtime import RuntimeSession
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.extension_activation import (
    ExtensionActivationRequest,
    ExtensionTaskPinRequest,
)
from graph_engineering.core.extension_bundle import (
    ExtensionAttestationProductionPolicy,
    ExtensionInstallRequest,
)
from graph_engineering.core.security.extensions import ExtensionGate, ExtensionTrustPolicy
from tests.integration.test_wp07_runtime_parity import (
    FIXTURE,
    adapter_document,
    compatibility,
    production_adapter_for_test,
    raw_input,
    resign_configuration,
)
from tests.support.wp03_repository import ROOT, repository_stack
from tests.support.runtime import runtime_context
from tests.support.wp08a_extension_bundle import DIGEST, trust_policy_chain, valid_bundle
from tests.support.wp08a_trust import authorize_operations, operations_for_candidate


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    return {**body, field: _digest(body, name)}


def _authorization(transaction_id: str, expected_head_digest: str) -> dict[str, object]:
    return {
        "transaction_id": transaction_id, "expected_head_digest": expected_head_digest,
        "owner_identity": "owner-fixture", "owner_decision_digest": DIGEST,
        "owner_authority_digest": DIGEST, "ordered_operations_digest": DIGEST,
        "created_at": "2026-08-20T00:00:00Z",
    }


def _session() -> RuntimeSession:
    cell = FIXTURE["cells"][0]
    document = copy.deepcopy(adapter_document(cell))
    document["capabilities"] = sorted(
        [
            *document["capabilities"],
            "extension.activate",
            "extension.install",
            "extension.pin-task",
            "extension.trust",
        ]
    )
    resign_configuration(document)
    return RuntimeSession.establish(
        production_adapter_for_test(cell, document), raw_input(cell), compatibility(cell)
    )


def _points(*pairs: tuple[str, str]) -> list[dict[str, object]]:
    values = [
        {"kind": kind, "id": identity, "contract_digest": DIGEST}
        for kind, identity in pairs
    ]
    return sorted(values, key=canonical_bytes)


@contextmanager
def _environment(
    *,
    points: list[dict[str, object]],
    requested_capabilities: list[dict[str, object]] | None = None,
    extension_id: str = "extension.example",
    extension_version: str = "1.0.0",
    compatibility_document: dict[str, object] | None = None,
    data_records: list[dict[str, object]] | None = None,
    activation_fault=lambda _point: None,  # type: ignore[no-untyped-def]
):
    from graph_engineering.adapters.extension_crypto import PycaEd25519CandidateVerifier
    from graph_engineering.storage.extension_activation import ExtensionActivationRepository
    from graph_engineering.storage.extension_bundle import ExtensionBundleReader
    from graph_engineering.storage.extension_install import ExtensionBundleInstaller
    from graph_engineering.storage.extensions import ExtensionTrustRepository

    with tempfile.TemporaryDirectory(prefix="gew-extension-activation-") as directory, repository_stack() as (
        _root, factory, _locks, _objects, _tasks, _leases,
    ):
        root = pathlib.Path(directory).resolve(strict=True)
        installation_id = factory._test_installation_scope.context.installation_id
        factory._test_installation_scope.__exit__(None, None, None)
        manager = factory._test_installation_manager
        genesis, candidate = trust_policy_chain(
            installation_id,
            requested_capabilities=requested_capabilities,
            compatibility=compatibility_document,
        )
        trust = ExtensionTrustRepository.initialize(
            manager, genesis,
            policy_document=json.loads(
                (ROOT / "config/extensions/extension-storage-policy-v1.json").read_text()
            ),
            bootstrap_terminal_record_digest=DIGEST,
        )
        verifier = PycaEd25519CandidateVerifier.from_requirement(
            json.loads(
                (ROOT / "config/supply-chain/extension-crypto-provider-requirement-v1.json").read_text()
            )
        )
        _policy_bundle, policy_metadata = valid_bundle()
        initial = trust.current()
        operations = operations_for_candidate(initial.policy, candidate)
        current = trust._commit_operations_issued(
            operations,
            authorization=authorize_operations(
                _authorization("transaction.extension.activation.policy", initial.head.head_digest),
                operations,
            ),
            runtime=runtime_context(
                "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                "2026-08-20T00:00:00Z", 1,
            ),
            production_policy=ExtensionAttestationProductionPolicy.from_dict(
                policy_metadata["production_policy"]
            ),
            verifier=verifier,
        )
        installer = ExtensionBundleInstaller.create(
            trust,
            ExtensionBundleReader.from_dict(
                json.loads(
                    (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
                )
            ),
            verifier,
        )
        install_application = ExtensionInstallationApplication(installer)
        activation = ExtensionActivationRepository.create(
            trust,
            installer,
            policy_document=json.loads(
                (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text()
            ),
            built_in_registry_document=json.loads(
                (ROOT / "config/extensions/extension-built-in-identities-v1.json").read_text()
            ),
            core_invariant_document=json.loads(
                (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
            ),
            fault_hook=activation_fault,
        )
        management = ExtensionManagementApplication(activation)
        session = _session()
        environment = SimpleNamespace(
            root=root, installation_id=installation_id, trust=trust, current=current,
            installer=installer, install_application=install_application,
            activation=activation, management=management, session=session, next_ingest=1,
            factory=factory, locks=_locks, manager=manager,
        )
        environment.restart_activation = lambda: ExtensionActivationRepository.create(
            trust,
            installer,
            policy_document=json.loads(
                (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text()
            ),
            built_in_registry_document=json.loads(
                (ROOT / "config/extensions/extension-built-in-identities-v1.json").read_text()
            ),
            core_invariant_document=json.loads(
                (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
            ),
        )
        environment.initial_receipt = _install(
            environment,
            valid_bundle(
                extension_id=extension_id,
                extension_version=extension_version,
                extension_points=points,
                exported_identities=points,
                requested_capabilities=requested_capabilities,
                compatibility=compatibility_document,
                data_records=data_records,
            )[0],
        )
        try:
            yield environment
        finally:
            session.close()


def _install(environment, bundle: bytes):  # type: ignore[no-untyped-def]
    number = environment.next_ingest
    environment.next_ingest += 1
    path = environment.root / f"extension-{number}.gewx"
    path.write_bytes(bundle)
    current = environment.trust.current()
    request = ExtensionInstallRequest.from_dict(
        _complete(
            {
                "schema_version": "1.0.0", "ingest_id": f"ingest.example.{number}",
                "installation_id": environment.installation_id,
                "owner_id": environment.session.proof.owner_id,
                "runtime_kind": environment.session.capabilities.runtime_kind,
                "runtime_lineage_id": environment.session.proof.lineage_id,
                "bundle_path": str(path), "expected_bundle_raw_digest": raw_digest(bundle),
                "expected_trust_head_digest": current.head.head_digest,
                "expected_trust_policy_digest": current.policy.policy_digest,
                "owner_decision_digest": DIGEST, "owner_authority_digest": DIGEST,
                "requested_at": "2026-08-20T00:02:00Z",
            },
            "extension-install-request", "request_digest",
        )
    )
    return environment.install_application.install(
        environment.session, environment.session.proof, request,
        occurred_at="2026-08-20T00:02:00Z", lease_ttl_ns=1,
    )


def _activation_request(environment, receipt, activation_id: str, override: str | None = None):  # type: ignore[no-untyped-def]
    current = environment.trust.current()
    active = environment.activation.snapshot().active_manifest
    return ExtensionActivationRequest.from_dict(
        _complete(
            {
                "schema_version": "1.0.0", "activation_id": activation_id,
                "installation_id": environment.installation_id,
                "ingest_record_digest": receipt.record_digest,
                "owner_id": environment.session.proof.owner_id,
                "runtime_kind": environment.session.capabilities.runtime_kind,
                "runtime_lineage_id": environment.session.proof.lineage_id,
                "expected_trust_head_digest": current.head.head_digest,
                "expected_trust_policy_digest": current.policy.policy_digest,
                "expected_revocation_high_water": current.policy.revocation_high_water,
                "expected_active_generation": 0 if active is None else active["generation"],
                "expected_active_manifest_digest": (
                    None if active is None else active["manifest_digest"]
                ),
                "conflict_override_digest": override,
                "owner_decision_digest": DIGEST, "owner_authority_digest": DIGEST,
                "requested_at": "2026-08-20T00:03:00Z",
            },
            "extension-activation-request", "request_digest",
        )
    )


def _activate(environment, request):  # type: ignore[no-untyped-def]
    return environment.management.activate(
        environment.session, environment.session.proof, request,
        occurred_at="2026-08-20T00:03:00Z", lease_ttl_ns=1,
    )


def _pin_request(
    environment, activation_digests: list[str], pin_id: str, graph_digest: str = DIGEST,
):  # type: ignore[no-untyped-def]
    current = environment.trust.current()
    active = environment.activation.snapshot()
    return ExtensionTaskPinRequest.from_dict(
        _complete(
            {
                "schema_version": "1.0.0", "pin_id": pin_id, "task_id": f"task.{pin_id}",
                "installation_id": environment.installation_id,
                "activation_record_digests": sorted(activation_digests),
                "graph_digest": graph_digest,
                "expected_active_generation": active.active_manifest["generation"],
                "expected_active_manifest_digest": active.active_manifest["manifest_digest"],
                "expected_contract_registry_digest": active.data_registry["registry_digest"],
                "expected_capability_profile_digest": (
                    environment.activation.capability_profile_digest
                ),
                "owner_id": environment.session.proof.owner_id,
                "runtime_kind": environment.session.capabilities.runtime_kind,
                "runtime_lineage_id": environment.session.proof.lineage_id,
                "expected_trust_head_digest": current.head.head_digest,
                "expected_trust_policy_digest": current.policy.policy_digest,
                "expected_revocation_high_water": current.policy.revocation_high_water,
                "owner_decision_digest": DIGEST, "owner_authority_digest": DIGEST,
                "requested_at": "2026-08-20T00:04:00Z",
            },
            "extension-task-pin-request", "request_digest",
        )
    )


class ExtensionActivationTests(unittest.TestCase):
    def test_gew_ext_010_data_only_categories_activate_under_exact_local_gate(self) -> None:
        points = _points(
            ("edge", "extension.edge"), ("node", "extension.node"),
            ("policy", "extension.policy"), ("template", "extension.template"),
        )
        with _environment(points=points) as environment:
            receipt = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.example.1"),
            )
            self.assertEqual(receipt.categories, ("edge", "node", "policy", "template"))
            self.assertEqual(receipt.local_status, "local-data-only-active")
            self.assertEqual(
                receipt.formal_release_status,
                "blocked-pending-wp10-release-install-manifest",
            )
            snapshot = environment.activation.snapshot()
            self.assertEqual((len(snapshot.activations), len(snapshot.diagnostics)), (1, 0))

    def test_gew_ext_011_compatibility_capability_conflict_and_builtin_collision_fail_closed(self) -> None:
        capability = {
            "capability_id": "network.external", "parameter_schema_id": "schema.none",
            "parameter_constraint_digest": DIGEST,
        }
        with _environment(
            points=_points(("node", "extension.node")),
            requested_capabilities=[capability],
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_CAPABILITY_INTERSECTION"):
                _activate(
                    environment,
                    _activation_request(environment, environment.initial_receipt, "activation.capability"),
                )
            self.assertEqual(len(environment.activation.snapshot().activations), 0)

        incompatible = {
            "core_version_range": ">=9,<10", "cli_protocol_range": ">=1,<2",
            "schema_profile_range": ">=1,<2", "geel_range": ">=1,<2",
            "runtime_capabilities_digest": DIGEST,
        }
        with _environment(
            points=_points(("node", "extension.node")),
            compatibility_document=incompatible,
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_COMPATIBILITY"):
                _activate(
                    environment,
                    _activation_request(environment, environment.initial_receipt, "activation.incompatible"),
                )
            self.assertEqual(len(environment.activation.snapshot().activations), 0)

        with _environment(points=_points(("node", "core.task-runner"))) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_BUILTIN_IDENTITY"):
                _activate(
                    environment,
                    _activation_request(environment, environment.initial_receipt, "activation.builtin"),
                )
            self.assertEqual(len(environment.activation.snapshot().activations), 0)

            from graph_engineering.storage.extension_activation import (
                ExtensionActivationRepository,
            )

            substituted = json.loads(
                (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text()
            )
            substituted["available_capabilities"] = ["network.external"]
            substituted.pop("policy_digest")
            substituted["policy_digest"] = _digest(
                substituted, "extension-activation-policy"
            )
            with self.assertRaisesRegex(ValueError, "installation-authorized"):
                ExtensionActivationRepository.create(
                    environment.trust,
                    environment.installer,
                    policy_document=substituted,
                    built_in_registry_document=json.loads(
                        (
                            ROOT
                            / "config/extensions/extension-built-in-identities-v1.json"
                        ).read_text()
                    ),
                    core_invariant_document=json.loads(
                        (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
                    ),
                )
            self.assertEqual(len(environment.activation.snapshot().activations), 0)

        with _environment(points=_points(("node", "extension.node"))) as environment:
            first = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.first"),
            )
            second_bundle = valid_bundle(
                extension_id="extension.example", extension_version="2.0.0",
                extension_points=_points(("node", "extension.node.v2")),
                exported_identities=_points(("node", "extension.node.v2")),
            )[0]
            second_ingest = _install(environment, second_bundle)
            request = _activation_request(environment, second_ingest, "activation.second")
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_UPDATE_CONFLICT"):
                _activate(environment, request)
            override = _digest(
                {
                    "schema_version": "1.0.0", "activation_id": "activation.second",
                    "candidate_ingest_record_digest": second_ingest.record_digest,
                    "existing_activation_record_digests": [first.record_digest],
                    "owner_decision_digest": DIGEST,
                },
                "extension-conflict-override",
            )
            second = _activate(
                environment,
                _activation_request(environment, second_ingest, "activation.second", override),
            )
            self.assertEqual(second.extension_version, "2.0.0")

    def test_gew_ext_012_task_start_pin_and_revocation_are_exact_and_restart_stable(self) -> None:
        from graph_engineering.storage.extension_activation import ExtensionActivationRepository

        with _environment(points=_points(("node", "extension.node"))) as environment:
            activation = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.pin"),
            )
            pin = environment.management.pin_task(
                environment.session,
                environment.session.proof,
                _pin_request(environment, [activation.record_digest], "pin.example.1"),
                occurred_at="2026-08-20T00:04:00Z", lease_ttl_ns=1,
            )
            self.assertEqual(pin.activation_record_digests, (activation.record_digest,))
            pinned_package = environment.activation.snapshot().task_pins[0]["packages"][0]
            self.assertEqual(
                {
                    "extension_version": pinned_package["extension_version"],
                    "package_identity_digest": pinned_package["package_identity_digest"],
                    "manifest_digest": pinned_package["manifest_digest"],
                    "archive_raw_digest": pinned_package["archive_raw_digest"],
                    "trust_policy_digest": pinned_package["trust_policy_digest"],
                    "revocation_high_water": pinned_package["revocation_high_water"],
                },
                {
                    "extension_version": "1.0.0",
                    "package_identity_digest": environment.initial_receipt.package_identity_digest,
                    "manifest_digest": environment.initial_receipt.manifest_digest,
                    "archive_raw_digest": environment.initial_receipt.archive_raw_digest,
                    "trust_policy_digest": environment.current.policy.policy_digest,
                    "revocation_high_water": 0,
                },
            )

            current = environment.trust.current()
            body = current.policy.to_dict()
            body.update(
                generation=current.policy.generation + 1,
                previous_policy_digest=current.policy.policy_digest,
                revocation_high_water=current.policy.revocation_high_water + 1,
                revocations=[
                    {
                        "target_kind": "extension", "target_identity_digest": environment.initial_receipt.package_identity_digest,
                        "input_kind": "owner-revocation", "input_digest": DIGEST,
                        "reason_code": "extension.revoked", "local_sequence": 1,
                        "effective_generation": current.policy.generation + 1,
                        "owner_decision_digest": DIGEST,
                    }
                ],
            )
            body.pop("policy_digest")
            candidate = ExtensionTrustPolicy.from_dict(
                _complete(body, "extension-trust-policy", "policy_digest"),
                previous=current.policy,
            )
            operations = operations_for_candidate(current.policy, candidate)
            environment.trust._commit_operations_issued(
                operations,
                authorization=authorize_operations(
                    _authorization("transaction.extension.revocation", current.head.head_digest),
                    operations,
                ),
                runtime=runtime_context(
                    "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                    "2026-08-20T00:00:00Z", 1,
                ),
            )
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_REVOKED"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.revoked"
                    ),
                )
            self.assertEqual(len(environment.activation.snapshot().activations), 1)
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_TASK_PIN_REVOKED"):
                environment.management.pin_task(
                    environment.session,
                    environment.session.proof,
                    _pin_request(environment, [activation.record_digest], "pin.example.2"),
                    occurred_at="2026-08-20T00:05:00Z", lease_ttl_ns=1,
                )
            restarted = ExtensionActivationRepository.create(
                environment.trust,
                environment.installer,
                policy_document=json.loads(
                    (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text()
                ),
                built_in_registry_document=json.loads(
                    (ROOT / "config/extensions/extension-built-in-identities-v1.json").read_text()
                ),
                core_invariant_document=json.loads(
                    (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
                ),
            )
            snapshot = restarted.snapshot()
            self.assertEqual((len(snapshot.activations), len(snapshot.task_pins)), (1, 1))
            self.assertEqual(snapshot.diagnostics[-1]["code"], "E_EXTENSION_TASK_PIN_REVOKED")

    def test_gew_ext_013_diagnostics_are_stable_and_executable_and_wp10_gates_remain_closed(self) -> None:
        from graph_engineering.storage.extension_activation import ExtensionActivationRepository

        with _environment(points=_points(("node", "core.task-runner"))) as environment:
            request = _activation_request(
                environment, environment.initial_receipt, "activation.diagnostic"
            )
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_BUILTIN_IDENTITY"):
                _activate(environment, request)
            restarted = ExtensionActivationRepository.create(
                environment.trust,
                environment.installer,
                policy_document=json.loads(
                    (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text()
                ),
                built_in_registry_document=json.loads(
                    (ROOT / "config/extensions/extension-built-in-identities-v1.json").read_text()
                ),
                core_invariant_document=json.loads(
                    (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
                ),
            )
            diagnostic = restarted.snapshot().diagnostics[-1]
            self.assertEqual(diagnostic["code"], "E_EXTENSION_BUILTIN_IDENTITY")
            self.assertEqual(diagnostic["subject_digest"], request.request_digest)
        for kind in ("node", "predicate", "validator", "transform", "adapter", "connector", "presentation"):
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_EXECUTABLE_CONTRACT_GATE"):
                ExtensionGate.require_non_builtin_executable_disabled(kind)


if __name__ == "__main__":
    unittest.main()
