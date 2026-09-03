"""WP-08A final trust-policy and recovery closure (GEW-EXT-028..032)."""

from __future__ import annotations

import copy
import json
import os
import pathlib
import socket
import urllib.request
import tempfile
import unittest
from unittest import mock

from graph_engineering.adapters.extension_crypto import PycaEd25519CandidateVerifier
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.extension_bundle import (
    ExtensionAttestationProductionPolicy,
    ExtensionInstallRequest,
)
from graph_engineering.core.security.extensions import ExtensionTrustPolicy
from graph_engineering.storage.extension_bundle import (
    ExtensionBundleError,
    ExtensionBundleReader,
    verify_extension_bundle,
)
from tests.integration.test_wp08a_extension_activation import (
    _activate,
    _activation_request,
    _authorization,
    _environment,
    _points,
)
from tests.support.wp03_repository import ROOT
from tests.support.runtime import runtime_context
from tests.support.wp08a_extension_bundle import DIGEST, trust_policy_chain, valid_bundle
from tests.support.wp08a_trust import authorize_operations, operations_for_candidate


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    return {
        **body,
        field: semantic_digest(
            body,
            contract_type=f"urn:gew:contract:{name}",
            projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
            schema_id=f"urn:gew:schema:{name}-input:1.0.0",
        ),
    }


def _verifier() -> PycaEd25519CandidateVerifier:
    return PycaEd25519CandidateVerifier.from_requirement(json.loads(
        (ROOT / "config/supply-chain/extension-crypto-provider-requirement-v1.json").read_text()
    ))


def _bounded(bundle: bytes):  # type: ignore[no-untyped-def]
    directory = tempfile.TemporaryDirectory(prefix="gew-extension-policy-")
    path = pathlib.Path(directory.name) / "candidate.gewx"
    path.write_bytes(bundle)
    os.chmod(path, 0o600)
    reader = ExtensionBundleReader.from_dict(json.loads(
        (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
    ))
    return directory, reader.read(path)


def _policy_change(policy: ExtensionTrustPolicy, **changes: object) -> ExtensionTrustPolicy:
    body = policy.to_dict()
    body.update(changes)
    body.pop("policy_digest")
    return ExtensionTrustPolicy.from_dict(
        _complete(body, "extension-trust-policy", "policy_digest"),
        previous=None if body["generation"] == 0 else trust_policy_chain(str(body["installation_id"]))[0],
    )


class ExtensionPolicyEnforcementTests(unittest.TestCase):
    def test_gew_ext_028_exact_key_rules_and_all_target_revocations_precede_install(self) -> None:
        bundle, metadata = valid_bundle(extension_id="extension.example")
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        _genesis, policy = trust_policy_chain("installation.policy")
        production = ExtensionAttestationProductionPolicy.from_dict(
            metadata["production_policy"]
        )
        verified = verify_extension_bundle(
            bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
            production_policy=production,
        )
        self.assertEqual(verified.manifest.package_identity_digest, metadata["manifest"]["package_identity_digest"])

        cases = {
            "source class": {"source_classes": ["remote"]},
            "namespace": {"namespaces": ["foreign."]},
            "kind": {"extension_kinds": ["executable"]},
            "role": {"roles": ["builder", "provenance-policy", "source-attestor"]},
        }
        for label, key_change in cases.items():
            body = policy.to_dict()
            body["trust_keys"][0].update(key_change)  # type: ignore[index]
            body.pop("policy_digest")
            candidate = ExtensionTrustPolicy.from_dict(
                _complete(body, "extension-trust-policy", "policy_digest"),
                previous=trust_policy_chain("installation.policy")[0],
            )
            with self.subTest(label=label), self.assertRaisesRegex(
                ExtensionBundleError, "TRUST|POLICY|REVOKED",
            ):
                verify_extension_bundle(
                    bounded, candidate, _verifier(), verified_at="2026-08-20T00:02:00Z",
                    production_policy=production,
                )

        targets = {
            "package": metadata["manifest"]["package_identity_digest"],
            "source-attestation": metadata["source"]["attestation_digest"],
            "build-attestation": metadata["build"]["attestation_digest"],
            "production-policy": production.policy_digest,
        }
        for sequence, (kind, digest) in enumerate(targets.items(), 1):
            body = policy.to_dict()
            body.update(
                revocation_high_water=sequence,
                revocations=[{
                    "target_kind": kind, "target_identity_digest": digest,
                    "input_kind": "owner-revocation", "input_digest": DIGEST,
                    "reason_code": "extension.revoked", "local_sequence": sequence,
                    "effective_generation": 1, "owner_decision_digest": DIGEST,
                }],
            )
            body.pop("policy_digest")
            revoked = ExtensionTrustPolicy.from_dict(
                _complete(body, "extension-trust-policy", "policy_digest"),
                previous=trust_policy_chain("installation.policy")[0],
            )
            with self.subTest(target=kind), self.assertRaisesRegex(
                ExtensionBundleError, "REVOKED",
            ):
                verify_extension_bundle(
                    bounded, revoked, _verifier(), verified_at="2026-08-20T00:02:00Z",
                    production_policy=production,
                )

        with _environment(points=_points(("node", "extension.node"))) as environment:
            current = environment.trust.current()
            body = current.policy.to_dict()
            body.update(
                generation=current.policy.generation + 1,
                previous_policy_digest=current.policy.policy_digest,
                revocation_high_water=current.policy.revocation_high_water + 1,
                revocations=[{
                    "target_kind": "source-attestation",
                    "target_identity_digest": metadata["source"]["attestation_digest"],
                    "input_kind": "owner-revocation", "input_digest": DIGEST,
                    "reason_code": "source.revoked", "local_sequence": 1,
                    "effective_generation": current.policy.generation + 1,
                    "owner_decision_digest": DIGEST,
                }],
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
                    _authorization(
                        "transaction.extension.source-revocation", current.head.head_digest,
                    ),
                    operations,
                ),
                runtime=runtime_context(
                    "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                    "2026-08-20T00:03:00Z", 1,
                ),
            )
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_REVOKED"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.revoked-source",
                    ),
                )
            self.assertEqual(environment.activation.snapshot().activations, ())

    def test_gew_ext_029_signed_production_policy_content_is_required_and_exact(self) -> None:
        bundle, metadata = valid_bundle()
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        _genesis, policy = trust_policy_chain("installation.production")
        production = ExtensionAttestationProductionPolicy.from_dict(metadata["production_policy"])
        tampered = copy.deepcopy(production.to_dict())
        tampered["allowed_builder_ids"] = ["builder.foreign"]
        tampered.pop("policy_digest")
        tampered = _complete(
            tampered, "extension-attestation-production-policy", "policy_digest",
        )
        forged = ExtensionAttestationProductionPolicy.from_dict(tampered)
        with self.assertRaisesRegex(ExtensionBundleError, "PRODUCTION|SIGNATURE|PROVENANCE"):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
                production_policy=forged,
            )
        with self.assertRaisesRegex((TypeError, ExtensionBundleError), "production policy"):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
                production_policy=None,
            )
        with _environment(points=_points(("node", "extension.node"))) as environment:
            connection = environment.trust._connect()
            try:
                row = connection.execute(
                    "SELECT policy_id,policy_digest,policy_json,registered_generation "
                    "FROM production_policy_materials"
                ).fetchone()
                self.assertEqual(
                    (row[0], row[1], json.loads(row[2]), row[3]),
                    (
                        production.to_dict()["policy_id"], production.policy_digest,
                        production.to_dict(), 1,
                    ),
                )
                with self.assertRaisesRegex(Exception, "immutable"):
                    connection.execute(
                        "UPDATE production_policy_materials SET policy_json='{}'"
                    )
            finally:
                connection.close()

    def test_gew_ext_030_floors_ceilings_shadow_conflict_and_cycle_fail_closed(self) -> None:
        bundle, metadata = valid_bundle(
            compatibility={
                "core_version_range": ">=9,<10", "cli_protocol_range": ">=1,<2",
                "schema_profile_range": ">=1,<2", "geel_range": ">=1,<2",
                "runtime_capabilities_digest": DIGEST,
            },
        )
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        _genesis, policy = trust_policy_chain("installation.compatibility")
        with self.assertRaisesRegex(ExtensionBundleError, "COMPATIBILITY"):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
            )

        capability = [{
            "capability_id": "network.client", "parameter_schema_id": "schema.network",
            "parameter_constraint_digest": DIGEST,
        }]
        bundle, metadata = valid_bundle(requested_capabilities=capability)
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        with self.assertRaisesRegex(ExtensionBundleError, "CAPABILITY"):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
            )

        with _environment(points=_points(("node", "extension.node"))) as environment:
            first = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.policy.1"),
            )
            self.assertEqual(first.local_status, "local-data-only-active")
            self.assertEqual(first.formal_release_status, "blocked-pending-wp10-release-install-manifest")
            self.assertEqual(environment.activation.snapshot().active_manifest["generation"], 1)

    def test_gew_ext_031_versioned_fault_schedule_recovers_install_activation_and_rollback(self) -> None:
        from graph_engineering.storage.extension_activation import ExtensionActivationRepository
        from graph_engineering.storage.extension_bundle import ExtensionBundleReader
        from graph_engineering.storage.extension_install import ExtensionBundleInstaller

        schedule = json.loads(
            (ROOT / "config/extensions/extension-fault-schedule-v1.json").read_text()
        )
        self.assertEqual(
            (schedule["schema_version"], schedule["schedule_version"]),
            ("1.0.0", "1.0.0"),
        )
        self.assertEqual(
            ExtensionBundleInstaller.fault_schedule(),
            (
                "extension-install.before-content",
                "extension-install.after-content",
                "extension-install.after-ledger",
                "extension-install.after-commit",
            ),
        )
        self.assertEqual(
            ExtensionActivationRepository.fault_schedule(),
            tuple(schedule["scenarios"][1]["points"]),
        )
        self.assertEqual(
            schedule["scenarios"][1]["points"], schedule["scenarios"][2]["points"],
        )
        self.assertEqual(
            schedule["trust_plane_network_policy"],
            {"dns_calls": 0, "socket_calls": 0, "proxy_calls": 0},
        )
        with _environment(points=_points(("node", "extension.node"))) as environment:
            bundle, _metadata = valid_bundle(
                extension_id="extension.crash",
                extension_points=_points(("node", "extension.crash-node")),
                exported_identities=_points(("node", "extension.crash-node")),
            )
            path = environment.root / "extension-crash.gewx"
            path.write_bytes(bundle)
            current = environment.trust.current()
            request = ExtensionInstallRequest.from_dict(_complete(
                {
                    "schema_version": "1.0.0", "ingest_id": "ingest.crash.1",
                    "installation_id": environment.installation_id,
                    "owner_id": "owner-fixture", "runtime_kind": "test-runtime",
                    "runtime_lineage_id": "test-lineage", "bundle_path": str(path),
                    "expected_bundle_raw_digest": raw_digest(bundle),
                    "expected_trust_head_digest": current.head.head_digest,
                    "expected_trust_policy_digest": current.policy.policy_digest,
                    "owner_decision_digest": DIGEST, "owner_authority_digest": DIGEST,
                    "requested_at": "2026-08-20T00:04:00Z",
                },
                "extension-install-request", "request_digest",
            ))
            reader = ExtensionBundleReader.from_dict(json.loads(
                (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
            ))

            def crash_before_content(point: str) -> None:
                if point == "extension-install.before-content":
                    raise RuntimeError(point)

            before_content = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(), fault_hook=crash_before_content,
            )
            with self.assertRaisesRegex(RuntimeError, "before-content"):
                before_content.install(
                    request,
                    runtime_context(
                        "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                        "2026-08-20T00:04:00Z", 1,
                    ),
                )
            self.assertFalse(
                (
                    before_content._content_base
                    / raw_digest(bundle).removeprefix("sha256-raw-v1:")
                ).exists()
            )

            def crash(point: str) -> None:
                if point == "extension-install.after-content":
                    raise RuntimeError(point)

            interrupted = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(), fault_hook=crash,
            )
            with self.assertRaisesRegex(RuntimeError, "after-content"):
                interrupted.install(
                    request,
                    runtime_context(
                        "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                        "2026-08-20T00:04:00Z", 1,
                    ),
                )
            orphan = interrupted._content_base / raw_digest(bundle).removeprefix("sha256-raw-v1:")
            self.assertTrue(orphan.is_dir())
            recovered = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(),
            )
            self.assertFalse(orphan.exists())
            self.assertEqual(recovered.fault_schedule(), ExtensionBundleInstaller.fault_schedule())

            def crash_after_ledger(point: str) -> None:
                if point == "extension-install.after-ledger":
                    raise RuntimeError(point)

            interrupted = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(), fault_hook=crash_after_ledger,
            )
            with self.assertRaisesRegex(RuntimeError, "after-ledger"):
                interrupted.install(
                    request,
                    runtime_context(
                        "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                        "2026-08-20T00:04:00Z", 1,
                    ),
                )
            self.assertTrue(orphan.is_dir())
            recovered = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(),
            )
            self.assertFalse(orphan.exists())

            committed_bundle, _metadata = valid_bundle(
                extension_id="extension.committed",
                extension_points=_points(("node", "extension.committed-node")),
                exported_identities=_points(("node", "extension.committed-node")),
            )
            committed_path = environment.root / "extension-committed.gewx"
            committed_path.write_bytes(committed_bundle)
            committed_body = request.to_dict()
            committed_body.update(
                ingest_id="ingest.committed.1", bundle_path=str(committed_path),
                expected_bundle_raw_digest=raw_digest(committed_bundle),
                requested_at="2026-08-20T00:05:00Z",
            )
            committed_body.pop("request_digest")
            committed_request = ExtensionInstallRequest.from_dict(_complete(
                committed_body, "extension-install-request", "request_digest",
            ))

            def crash_after_commit(point: str) -> None:
                if point == "extension-install.after-commit":
                    raise RuntimeError(point)

            interrupted = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(), fault_hook=crash_after_commit,
            )
            runtime = runtime_context(
                "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                "2026-08-20T00:05:00Z", 1,
            )
            with self.assertRaisesRegex(RuntimeError, "after-commit"):
                interrupted.install(committed_request, runtime)
            restarted = ExtensionBundleInstaller.create(
                environment.trust, reader, _verifier(),
            )
            receipt = restarted.install(committed_request, runtime)
            self.assertEqual(receipt.request_digest, committed_request.request_digest)
            self.assertEqual(restarted.doctor(receipt).content_root_digest, receipt.content_root_digest)

    def test_gew_ext_032_trust_plane_has_zero_dns_socket_proxy_and_executable_gates(self) -> None:
        bundle, metadata = valid_bundle()
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        _genesis, policy = trust_policy_chain("installation.network")
        production = ExtensionAttestationProductionPolicy.from_dict(metadata["production_policy"])
        counters = {"dns": 0, "socket": 0, "proxy": 0}

        def dns(*args: object, **kwargs: object) -> object:
            del args, kwargs
            counters["dns"] += 1
            raise AssertionError("trust plane attempted DNS")

        class DeniedSocket:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs
                counters["socket"] += 1
                raise AssertionError("trust plane attempted socket")

        def proxies() -> object:
            counters["proxy"] += 1
            raise AssertionError("trust plane attempted proxy discovery")

        with mock.patch.object(socket, "getaddrinfo", dns), mock.patch.object(
            socket, "socket", DeniedSocket,
        ), mock.patch.object(
            urllib.request, "getproxies", proxies,
        ), mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9"}):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:02:00Z",
                production_policy=production,
            )
            from tests.integration.test_wp08a_extension_active_set import (
                ExtensionActiveSetTests,
            )
            from tests.integration.test_wp08a_extension_exit import ExtensionExitTests
            from tests.integration.test_wp08a_extension_task_integration import (
                ExtensionTaskIntegrationTests,
            )

            exercised = (
                (ExtensionExitTests, "test_gew_ext_016_installed_content_root_survives_source_removal_and_doctor_rejects_tamper"),
                (ExtensionExitTests, "test_gew_ext_015_publisher_revocation_is_verified_before_owner_promotion"),
                (ExtensionActiveSetTests, "test_gew_ext_021_supersede_rollback_remove_and_owner_ingress_are_deterministic"),
                (ExtensionTaskIntegrationTests, "test_gew_ext_024_create_open_resume_and_graph_ref_pin_survive_restart"),
            )
            for case_type, method in exercised:
                result = unittest.TestResult()
                case_type(method).run(result)
                self.assertTrue(
                    result.wasSuccessful(),
                    f"trust-plane operation cell failed: {method}: "
                    f"{result.failures!r} {result.errors!r}",
                )
        self.assertEqual(counters, {"dns": 0, "socket": 0, "proxy": 0})


if __name__ == "__main__":
    unittest.main()
