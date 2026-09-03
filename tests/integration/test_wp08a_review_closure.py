"""Independent WP-08A review closure (WP08A-QR-R1-001..007)."""

from __future__ import annotations

import inspect
import json
import pathlib
import copy
import base64
import types
import unittest

from graph_engineering.application.extensions import ExtensionTrustApplication
from graph_engineering.core.extension_bundle import ExtensionSourceAttestation
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security import extensions as trust_contracts
from graph_engineering.storage.extension_activation import (
    ExtensionActivationRepository,
    ExtensionTaskPinAuthority,
)
from graph_engineering.storage.extension_install import ExtensionBundleInstaller
from graph_engineering.storage.extensions import ExtensionTrustRepository
from tests.support.wp03_repository import ROOT
from tests.support.wp08a_extension_bundle import DIGEST, trust_policy_chain, valid_bundle


class ExtensionReviewClosureTests(unittest.TestCase):
    def test_wp08a_qr_r1_001_product_attested_reducer_is_only_candidate_authority(self) -> None:
        reducer = getattr(trust_contracts, "ExtensionTrustPolicyReducer")
        self.assertEqual(
            reducer.OPERATION_KINDS,
            (
                "add-key", "retire-key", "rotate-key", "register-production-policy",
                "retire-production-policy", "set-source-rule", "set-namespace-rule",
                "set-extension-kind-rule", "set-capability-ceiling",
                "set-compatibility-floor", "apply-local-revocation",
                "apply-publisher-revocation",
            ),
        )
        parameters = inspect.signature(ExtensionTrustApplication.commit).parameters
        self.assertIn("operations", parameters)
        self.assertNotIn("candidate", parameters)
        self.assertFalse(hasattr(ExtensionTrustRepository, "_commit_issued"))

    def test_wp08a_qr_r1_002_historical_task_pin_policy_is_selective(self) -> None:
        semantics = ExtensionActivationRepository.task_pin_policy()
        self.assertEqual(
            semantics,
            {
                "preserve": (
                    "unrelated-activation", "side-by-side-update", "key-addition",
                    "capability-ceiling-expansion",
                ),
                "block": (
                    "matching-key-tightening", "matching-production-policy-tightening",
                    "matching-source-tightening", "matching-namespace-tightening",
                    "matching-kind-tightening", "matching-revocation",
                    "capability-ceiling-contraction", "resource-policy-change",
                    "compatibility-floor",
                ),
                "upgrade": "explicit-owner-rebase-new-generation",
            },
        )

        requested_capabilities = [{"capability_id": "capability.read", "parameters": {}}]
        _genesis, pinned = trust_policy_chain(
            "installation.pin-tightening",
            requested_capabilities=requested_capabilities,
        )
        _bundle, metadata = valid_bundle(requested_capabilities=requested_capabilities)

        class InstalledMembers:
            def _load_installed_members_under_lock(self, _receipt: object) -> dict[str, bytes]:
                from graph_engineering.core.contracts.canonical import canonical_bytes

                return {
                    "META-INF/source-attestation.json": canonical_bytes(metadata["source"]),
                    "META-INF/build-attestation.json": canonical_bytes(metadata["build"]),
                    "META-INF/publisher-signature.json": canonical_bytes(
                        metadata["publisher_signature"]
                    ),
                }

        authority = object.__new__(ExtensionTaskPinAuthority)
        authority._activation = types.SimpleNamespace(  # type: ignore[attr-defined]
            _installer=InstalledMembers(), _receipt_from_ingest=lambda _value: object(),
        )
        package = metadata["manifest"]

        def changed(field: str, transform):  # type: ignore[no-untyped-def]
            body = pinned.to_dict()
            records = copy.deepcopy(body[field])
            transform(records)
            body[field] = sorted(records, key=canonical_bytes)
            body.update(
                generation=pinned.generation + 1,
                previous_policy_digest=pinned.policy_digest,
            )
            body.pop("policy_digest")
            body["policy_digest"] = semantic_digest(
                body,
                contract_type="urn:gew:contract:extension-trust-policy",
                projection_id="urn:gew:digest-projection:extension-trust-policy:1.0.0",
                schema_id="urn:gew:schema:extension-trust-policy-input:1.0.0",
            )
            return trust_contracts.ExtensionTrustPolicy.from_dict(body, previous=pinned)

        mutations = {
            "matching-key-tightening": ("trust_keys", lambda rows: rows[0].update(status="retired")),
            "matching-production-policy-tightening": (
                "production_policies", lambda rows: rows[0].update(status="retired")
            ),
            "matching-source-tightening": (
                "source_rules", lambda rows: rows[0].update(allowed_source_ids=[])
            ),
            "matching-namespace-tightening": (
                "namespace_rules", lambda rows: rows[0].update(allowed_extension_kinds=[])
            ),
            "matching-kind-tightening": (
                "extension_kind_rules", lambda rows: rows[0].update(data_allowed=False)
            ),
            "matching-ceiling-tightening": (
                "capability_ceilings",
                lambda rows: rows[0].update(
                    capability_ids=[],
                    capability_set_digest=trust_contracts.extension_capability_set_digest(
                        rows[0]["subject_kind"], rows[0]["subject_id"], []
                    ),
                ),
            ),
        }
        for dimension, (field, transform) in mutations.items():
            with self.subTest(dimension=dimension):
                self.assertTrue(authority._has_relevant_security_tightening(
                    pinned, changed(field, transform), package, {},
                ))

        def add_unrelated_key(rows: list[dict[str, object]]) -> None:
            key = copy.deepcopy(rows[0])
            key.update(key_id="key.unrelated", added_generation=pinned.generation + 1)
            rows.append(key)

        self.assertFalse(authority._has_relevant_security_tightening(
            pinned, changed("trust_keys", add_unrelated_key), package, {},
        ))

        def rotate_without_revocation(rows: list[dict[str, object]]) -> None:
            rows[0].update(
                ed25519_public_key=base64.urlsafe_b64encode(b"\x02" * 32).rstrip(b"=").decode(),
                not_after="2028-08-20T00:00:00Z",
                added_generation=pinned.generation + 1,
            )

        self.assertFalse(authority._has_relevant_security_tightening(
            pinned, changed("trust_keys", rotate_without_revocation), package, {},
        ))

        def expand_capabilities(rows: list[dict[str, object]]) -> None:
            capabilities = sorted([*rows[0]["capability_ids"], "capability.expanded"])
            rows[0].update(
                capability_ids=capabilities,
                capability_set_digest=trust_contracts.extension_capability_set_digest(
                    rows[0]["subject_kind"], rows[0]["subject_id"], capabilities
                ),
            )

        self.assertFalse(authority._has_relevant_security_tightening(
            pinned, changed("capability_ceilings", expand_capabilities), package, {},
        ))

    def test_wp08a_qr_r1_003_trust_post_commit_matrix_is_closed(self) -> None:
        self.assertEqual(
            ExtensionTrustRepository.post_commit_fault_schedule(),
            (
                "extension-trust.after-commit-durability",
                "extension-trust.before-restoration-publication",
                "extension-trust.after-restoration-durability",
                "extension-trust.after-restoration-reread",
            ),
        )

    def test_wp08a_qr_r1_004_activation_post_publish_doctor_is_closed(self) -> None:
        self.assertEqual(
            ExtensionActivationRepository.post_publish_fault_schedule(),
            (
                "extension-activation.after-publish-durability",
                "extension-activation.before-restoration-publication",
                "extension-activation.after-restoration-durability",
                "extension-activation.after-restoration-reread",
            ),
        )

    def test_wp08a_qr_r1_005_cross_attestation_chronology_is_explicit(self) -> None:
        chronology = getattr(trust_contracts, "EXTENSION_ATTESTATION_CHRONOLOGY")
        self.assertEqual(
            chronology,
            ("source.issued_at", "build.started_at", "build.finished_at", "ingest.verified_at"),
        )
        from tests.integration.test_wp08a_extension_policy_enforcement import _bounded, _verifier
        from graph_engineering.core.extension_bundle import ExtensionAttestationProductionPolicy
        from graph_engineering.storage.extension_bundle import ExtensionBundleError, verify_extension_bundle

        bundle, metadata = valid_bundle(
            source_issued_at="2026-08-20T00:02:00Z",
            build_started_at="2026-08-20T00:01:00Z",
            build_finished_at="2026-08-20T00:03:00Z",
        )
        directory, bounded = _bounded(bundle)
        self.addCleanup(directory.cleanup)
        _genesis, policy = trust_policy_chain("installation.chronology")
        with self.assertRaisesRegex(ExtensionBundleError, "chronology"):
            verify_extension_bundle(
                bounded, policy, _verifier(), verified_at="2026-08-20T00:04:00Z",
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
            )

    def test_wp08a_qr_r1_006_previous_source_attestation_is_optional_but_exact(self) -> None:
        self.assertIn("previous_attestation_digest", ExtensionSourceAttestation.FIELDS)
        schema = json.loads(
            (ROOT / "config/contracts/schemas/extension-source-attestation-1.0.0.json").read_text()
        )
        self.assertIn("previous_attestation_digest", schema["properties"])
        self.assertNotIn("previous_attestation_digest", schema["required"])
        _bundle, absent = valid_bundle()
        self.assertNotIn("previous_attestation_digest", absent["source"])
        ExtensionSourceAttestation.from_dict(absent["source"])
        _bundle, linked = valid_bundle(previous_attestation_digest=DIGEST)
        self.assertEqual(
            ExtensionSourceAttestation.from_dict(linked["source"]).to_dict()[
                "previous_attestation_digest"
            ],
            DIGEST,
        )
        for invalid in (None, "not-a-digest"):
            _bundle, malformed = valid_bundle(previous_attestation_digest=invalid)
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "previous"):
                ExtensionSourceAttestation.from_dict(malformed["source"])
        substituted = copy.deepcopy(linked["source"])
        substituted["previous_attestation_digest"] = "sha256-jcs-v1:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            ExtensionSourceAttestation.from_dict(substituted)

    def test_wp08a_qr_r1_007_trace_and_oracle_manifests_are_schema_locked(self) -> None:
        from graph_engineering.core.extension_coverage import (
            ExtensionCoverageError,
            ExtensionCoverageMatrix,
            ExtensionOracleManifest,
        )
        trace = pathlib.Path(ROOT / "config/release-coverage/trace-matrix-v1.json")
        oracle = pathlib.Path(ROOT / "config/release-coverage/oracle-manifest-v1.json")
        self.assertTrue(trace.is_file())
        self.assertTrue(oracle.is_file())
        trace_document = json.loads(trace.read_text())
        oracle_document = json.loads(oracle.read_text())
        self.assertEqual(trace_document["schema_version"], "1.0.0")
        self.assertEqual(oracle_document["schema_version"], "1.0.0")
        required = {
            "GEW-REQ-FR18-P", "GEW-REQ-FR18-R",
            "GEW-WP-08A-EXIT-P", "GEW-WP-08A-EXIT-R",
            "GEW-WP-08A-TRUST-FAULT-P", "GEW-WP-08A-ACTIVATION-FAULT-P",
            "GEW-WP-08A-ROLLBACK-P",
            "ADR4-PKG-P-001",
            *(f"ADR4-PKG-R-{index:03d}" for index in range(1, 11)),
        }
        self.assertEqual(set(trace_document["test_ids"]), required)
        matrix = ExtensionCoverageMatrix.from_dict(trace_document)
        self.assertEqual(set(trace_document["executions"]), required)
        oracle = ExtensionOracleManifest.from_dict(oracle_document)
        from graph_engineering.core.extension_coverage import (
            ExtensionCoverageAuthority,
            ExtensionCoverageCandidateContext,
        )
        context = ExtensionCoverageCandidateContext.verify_current(
            "candidate.wp08a.review",
            ROOT.resolve(strict=True),
        )
        authority = ExtensionCoverageAuthority.issue(matrix, oracle, context)
        runnable_results = tuple(
            authority.execute(
                test_id,
                occurred_at="2026-08-21T00:00:00Z",
            )
            for test_id in trace_document["executions"]
        )
        self.assertEqual(matrix.reduce_results(runnable_results), frozenset(required))
        for field in (
            "requirement_rows", "work_package_rows", "adr4_vectors", "test_ids", "executions",
        ):
            deleted = copy.deepcopy(trace_document)
            if isinstance(deleted[field], dict):
                deleted[field].pop(next(iter(deleted[field])))
            else:
                deleted[field].pop()
            with self.subTest(field=field), self.assertRaises(ExtensionCoverageError):
                ExtensionCoverageMatrix.from_dict(deleted)
            substituted = copy.deepcopy(trace_document)
            if isinstance(substituted[field], dict):
                first = next(iter(substituted[field]))
                substituted[field][first]["expected_result"] = "substituted"
            else:
                substituted[field][0] = copy.deepcopy(substituted[field][0])
                if isinstance(substituted[field][0], dict):
                    first_key = next(iter(substituted[field][0]))
                    substituted[field][0][first_key] = "substituted"
                else:
                    substituted[field][0] = "substituted"
            with self.subTest(substituted_field=field), self.assertRaises(ExtensionCoverageError):
                ExtensionCoverageMatrix.from_dict(substituted)
        for counter in ("dns", "socket", "proxy"):
            substituted = copy.deepcopy(oracle_document)
            substituted["trust_plane_network_counters"][counter] = 1
            with self.subTest(counter=counter), self.assertRaises(ExtensionCoverageError):
                ExtensionOracleManifest.from_dict(substituted)
        for schedule, points in oracle_document["fault_schedules"].items():
            deleted = copy.deepcopy(oracle_document)
            deleted["fault_schedules"][schedule].pop()
            substituted = copy.deepcopy(oracle_document)
            substituted["fault_schedules"][schedule][0] = "substituted.cut"
            for mutation in (deleted, substituted):
                with self.subTest(schedule=schedule), self.assertRaises(ExtensionCoverageError):
                    ExtensionOracleManifest.from_dict(mutation)
            self.assertTrue(points)


if __name__ == "__main__":
    unittest.main()
