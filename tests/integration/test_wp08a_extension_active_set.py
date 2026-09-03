"""WP-08A exact activation manifest and active-set transitions (GEW-EXT-020..023)."""

from __future__ import annotations

import copy
import json
import sqlite3
import unittest

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.extensions import (
    ExtensionTrustPolicy,
    extension_capability_set_digest,
)
from graph_engineering.storage.extension_activation import ExtensionActivationRepository
from tests.integration.test_wp08a_extension_activation import (
    _activate,
    _activation_request,
    _authorization,
    _environment,
    _install,
    _pin_request,
    _points,
)
from tests.support.wp03_repository import ROOT
from tests.support.runtime import runtime_context
from tests.support.wp08a_extension_bundle import DIGEST, valid_bundle
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


def _set_request(
    environment,  # type: ignore[no-untyped-def]
    transition_id: str,
    transition_kind: str,
    extension_id: str,
    target: str | None,
):
    from graph_engineering.core.extension_activation import ExtensionActiveSetRequest

    snapshot = environment.activation.snapshot()
    active = snapshot.active_manifest
    current = environment.trust.current()
    return ExtensionActiveSetRequest.from_dict(
        _complete(
            {
                "schema_version": "1.0.0",
                "transition_id": transition_id,
                "transition_kind": transition_kind,
                "installation_id": environment.installation_id,
                "extension_id": extension_id,
                "target_activation_record_digest": target,
                "expected_active_generation": 0 if active is None else active["generation"],
                "expected_active_manifest_digest": (
                    None if active is None else active["manifest_digest"]
                ),
                "owner_id": environment.session.proof.owner_id,
                "runtime_kind": environment.session.capabilities.runtime_kind,
                "runtime_lineage_id": environment.session.proof.lineage_id,
                "expected_trust_head_digest": current.head.head_digest,
                "expected_trust_policy_digest": current.policy.policy_digest,
                "expected_revocation_high_water": current.policy.revocation_high_water,
                "owner_decision_digest": DIGEST,
                "owner_authority_digest": DIGEST,
                "reason_code": "owner.active-set-change",
                "requested_at": "2026-08-20T00:06:00Z",
            },
            "extension-active-set-request",
            "request_digest",
        )
    )


def _transition(environment, request):  # type: ignore[no-untyped-def]
    return environment.management.transition_active_set(
        environment.session,
        environment.session.proof,
        request,
        occurred_at="2026-08-20T00:06:00Z",
        lease_ttl_ns=1,
    )


def _supersede(environment, suffix: str):  # type: ignore[no-untyped-def]
    first = _activate(
        environment,
        _activation_request(environment, environment.initial_receipt, f"activation.v1.{suffix}"),
    )
    second_ingest = _install(
        environment,
        valid_bundle(
            extension_id="extension.example",
            extension_version="2.0.0",
            extension_points=_points(("node", "extension.node.v2")),
            exported_identities=_points(("node", "extension.node.v2")),
        )[0],
    )
    override = _digest(
        {
            "schema_version": "1.0.0",
            "activation_id": f"activation.v2.{suffix}",
            "candidate_ingest_record_digest": second_ingest.record_digest,
            "existing_activation_record_digests": [first.record_digest],
            "owner_decision_digest": DIGEST,
        },
        "extension-conflict-override",
    )
    second = _activate(
        environment,
        _activation_request(
            environment, second_ingest, f"activation.v2.{suffix}", override
        ),
    )
    return first, second


def _commit_policy_change(environment, suffix: str, mutate):  # type: ignore[no-untyped-def]
    current = environment.trust.current()
    body = current.policy.to_dict()
    mutate(body, current.policy)
    for field in (
        "revocations", "trust_keys", "production_policies", "source_rules",
        "namespace_rules", "extension_kind_rules", "capability_ceilings",
        "compatibility_floors",
    ):
        body[field] = sorted(body[field], key=canonical_bytes)
    body.update(
        generation=current.policy.generation + 1,
        previous_policy_digest=current.policy.policy_digest,
    )
    body.pop("policy_digest")
    candidate = ExtensionTrustPolicy.from_dict(
        _complete(body, "extension-trust-policy", "policy_digest"),
        previous=current.policy,
    )
    operations = operations_for_candidate(current.policy, candidate)
    return environment.trust._commit_operations_issued(
        operations,
        authorization=authorize_operations(
            _authorization(f"transaction.rollback-current.{suffix}", current.head.head_digest),
            operations,
        ),
        runtime=runtime_context(
            "owner-fixture", "test-runtime", "test-lineage", "test-actor",
            "2026-08-20T00:05:00Z", 1,
        ),
    )


def _activation_storage_rows(environment):  # type: ignore[no-untyped-def]
    connection = environment.trust._connect()
    try:
        return tuple(
            tuple(connection.execute(query).fetchall())
            for query in (
                "SELECT record_sequence,record_digest,record_json "
                "FROM extension_activation_ledger ORDER BY record_sequence",
                "SELECT generation,registry_digest,registry_json "
                "FROM extension_data_registries ORDER BY generation",
                "SELECT generation,manifest_digest,manifest_json "
                "FROM extension_activation_manifests ORDER BY generation",
                "SELECT generation,manifest_digest,pointer_digest,pointer_json "
                "FROM extension_active_set_pointer ORDER BY singleton",
            )
        )
    finally:
        connection.close()


class ExtensionActiveSetTests(unittest.TestCase):
    def test_gew_ext_020_manifest_pointer_cas_and_cross_bindings_are_exact(self) -> None:
        from graph_engineering.core.extension_activation import (
            ExtensionActivationManifest,
            ExtensionActiveSetPointer,
        )

        with _environment(points=_points(("node", "extension.node"))) as environment:
            stale = _activation_request(
                environment, environment.initial_receipt, "activation.stale"
            )
            receipt = _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.first"
                ),
            )
            snapshot = environment.activation.snapshot()
            manifest = ExtensionActivationManifest.from_dict(snapshot.active_manifest)
            pointer = ExtensionActiveSetPointer.from_dict(snapshot.active_pointer)
            body = manifest.to_dict()
            self.assertEqual(
                (
                    body["generation"], body["transition_kind"],
                    body["data_registry_digest"], body["trust_head_digest"],
                    body["active_packages"][0]["activation_record_digest"],  # type: ignore[index]
                    pointer.to_dict()["manifest_digest"],
                ),
                (
                    1, "activate", snapshot.data_registry["registry_digest"],
                    environment.trust.current().head.head_digest, receipt.record_digest,
                    body["manifest_digest"],
                ),
            )
            self.assertEqual(
                body["active_packages"][0]["content_root_digest"],  # type: ignore[index]
                environment.initial_receipt.content_root_digest,
            )
            with self.assertRaisesRegex(ValueError, "CAS|stale"):
                _activate(environment, stale)
            self.assertEqual(environment.activation.snapshot().active_manifest, body)

            substituted = copy.deepcopy(body)
            substituted["active_packages"][0]["content_root_digest"] = DIGEST  # type: ignore[index]
            substituted["manifest_digest"] = _digest(
                {key: value for key, value in substituted.items() if key != "manifest_digest"},
                "extension-activation-manifest",
            )
            with self.assertRaisesRegex(ValueError, "binding|manifest"):
                ExtensionActivationManifest.from_dict(substituted)

    def test_gew_ext_021_supersede_rollback_remove_and_owner_ingress_are_deterministic(self) -> None:
        with _environment(points=_points(("node", "extension.node"))) as environment:
            first = _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.v1"
                ),
            )
            second_ingest = _install(
                environment,
                valid_bundle(
                    extension_id="extension.example",
                    extension_version="2.0.0",
                    extension_points=_points(("node", "extension.node.v2")),
                    exported_identities=_points(("node", "extension.node.v2")),
                )[0],
            )
            override = _digest(
                {
                    "schema_version": "1.0.0",
                    "activation_id": "activation.v2",
                    "candidate_ingest_record_digest": second_ingest.record_digest,
                    "existing_activation_record_digests": [first.record_digest],
                    "owner_decision_digest": DIGEST,
                },
                "extension-conflict-override",
            )
            second = _activate(
                environment,
                _activation_request(
                    environment, second_ingest, "activation.v2", override
                ),
            )
            self.assertEqual(
                (
                    environment.activation.snapshot().active_manifest["generation"],
                    environment.activation.snapshot().active_manifest["transition_kind"],
                ),
                (2, "supersede"),
            )

            rolled_back = _transition(
                environment,
                _set_request(
                    environment,
                    "transition.rollback.v1",
                    "rollback",
                    "extension.example",
                    first.record_digest,
                ),
            )
            self.assertEqual((rolled_back.generation, rolled_back.transition_kind), (3, "rollback"))
            active = environment.activation.snapshot().active_manifest
            self.assertEqual(active["active_packages"][0]["activation_record_digest"], first.record_digest)
            self.assertNotEqual(active["active_packages"][0]["activation_record_digest"], second.record_digest)
            environment.management.pin_task(
                environment.session,
                environment.session.proof,
                _pin_request(environment, [first.record_digest], "pin.rollback.active"),
                occurred_at="2026-08-20T00:06:00Z",
                lease_ttl_ns=1,
            )
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_TASK_PIN_MISSING"):
                environment.management.pin_task(
                    environment.session,
                    environment.session.proof,
                    _pin_request(environment, [second.record_digest], "pin.superseded"),
                    occurred_at="2026-08-20T00:06:00Z",
                    lease_ttl_ns=1,
                )

            request = _set_request(
                environment,
                "transition.remove",
                "remove",
                "extension.example",
                None,
            )
            forged = request.to_dict()
            forged["owner_id"] = "owner.foreign"
            forged["request_digest"] = _digest(
                {key: value for key, value in forged.items() if key != "request_digest"},
                "extension-active-set-request",
            )
            from graph_engineering.core.extension_activation import ExtensionActiveSetRequest

            before = environment.activation.snapshot()
            with self.assertRaisesRegex(ValueError, "unavailable"):
                _transition(environment, ExtensionActiveSetRequest.from_dict(forged))
            self.assertEqual(environment.activation.snapshot(), before)

            removed = _transition(environment, request)
            snapshot = environment.activation.snapshot()
            self.assertEqual((removed.generation, removed.transition_kind), (4, "remove"))
            self.assertEqual(snapshot.active_manifest["active_packages"], [])
            self.assertEqual(
                snapshot.active_manifest["tombstones"][-1]["extension_id"],
                "extension.example",
            )
            self.assertEqual(snapshot.data_registry["entries"], [])
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_TASK_PIN_MISSING"):
                environment.management.pin_task(
                    environment.session,
                    environment.session.proof,
                    _pin_request(environment, [first.record_digest], "pin.removed"),
                    occurred_at="2026-08-20T00:06:00Z",
                    lease_ttl_ns=1,
                )

        revocation_kinds = (
            "activation-record", "ingest-record", "package-identity", "manifest",
            "source-attestation", "build-attestation", "publisher-signature",
            "production-policy",
        )
        for index, target_kind in enumerate(revocation_kinds, 1):
            suffix = f"revocation.{index}"
            with self.subTest(current_revocation=target_kind), _environment(
                points=_points(("node", "extension.node"))
            ) as environment:
                first, _second = _supersede(environment, suffix)
                ingest = environment.installer._test_records()[0]
                subjects = {
                    "activation-record": first.record_digest,
                    "ingest-record": ingest["record_digest"],
                    "package-identity": ingest["package_identity_digest"],
                    "manifest": ingest["manifest_digest"],
                    "source-attestation": ingest["source_attestation_digest"],
                    "build-attestation": ingest["build_attestation_digest"],
                    "publisher-signature": ingest["publisher_signature_digest"],
                    "production-policy": ingest["production_policy_digest"],
                }

                def revoke(body, current, kind=target_kind):  # type: ignore[no-untyped-def]
                    sequence = current.revocation_high_water + 1
                    body["revocation_high_water"] = sequence
                    body["revocations"] = sorted(
                        [
                            *body["revocations"],
                            {
                                "target_kind": kind,
                                "target_identity_digest": subjects[kind],
                                "input_kind": "owner-revocation",
                                "input_digest": DIGEST,
                                "reason_code": "extension.revoked",
                                "local_sequence": sequence,
                                "effective_generation": current.generation + 1,
                                "owner_decision_digest": DIGEST,
                            },
                        ],
                        key=canonical_bytes,
                    )

                committed = _commit_policy_change(environment, suffix, revoke)
                before_snapshot = environment.activation.snapshot()
                before_rows = _activation_storage_rows(environment)
                with self.assertRaisesRegex(ValueError, "E_EXTENSION_REVOKED"):
                    _transition(
                        environment,
                        _set_request(
                            environment,
                            f"transition.rollback.revoked.{index}",
                            "rollback",
                            "extension.example",
                            first.record_digest,
                        ),
                    )
                self.assertEqual(environment.activation.snapshot(), before_snapshot)
                self.assertEqual(_activation_storage_rows(environment), before_rows)
                restarted = environment.restart_activation().doctor()
                self.assertEqual(restarted, before_snapshot)
                self.assertEqual(restarted.active_manifest["generation"], 2)
                self.assertEqual(
                    environment.trust.current().policy.revocation_high_water,
                    committed.policy.revocation_high_water,
                )

        def retire_key(body, current):  # type: ignore[no-untyped-def]
            body["revocation_high_water"] = current.revocation_high_water + 1
            body["trust_keys"][0].update(  # type: ignore[index]
                status="retired",
                revocation_sequence=current.revocation_high_water + 1,
            )

        def retire_production(body, _current):  # type: ignore[no-untyped-def]
            body["production_policies"][0]["status"] = "retired"  # type: ignore[index]

        def tighten_source(body, _current):  # type: ignore[no-untyped-def]
            body["source_rules"][0]["allowed_source_ids"] = []  # type: ignore[index]

        def tighten_namespace(body, _current):  # type: ignore[no-untyped-def]
            body["namespace_rules"][0]["allowed_extension_kinds"] = []  # type: ignore[index]

        def tighten_kind(body, _current):  # type: ignore[no-untyped-def]
            body["extension_kind_rules"][0]["data_allowed"] = False  # type: ignore[index]

        def tighten_capability(body, _current):  # type: ignore[no-untyped-def]
            capabilities = ["capability.unrelated"]
            body["capability_ceilings"][0].update(  # type: ignore[index]
                capability_ids=capabilities,
                capability_set_digest=extension_capability_set_digest(
                    "publisher", "publisher.example", capabilities
                ),
            )

        def tighten_floor(body, _current):  # type: ignore[no-untyped-def]
            body["compatibility_floors"][0]["compatibility_policy_digest"] = DIGEST  # type: ignore[index]

        tightening_cases = (
            ("key", retire_key),
            ("production-policy", retire_production),
            ("source", tighten_source),
            ("namespace", tighten_namespace),
            ("kind", tighten_kind),
            ("capability", tighten_capability),
            ("compatibility-floor", tighten_floor),
        )
        for index, (dimension, mutate) in enumerate(tightening_cases, 1):
            suffix = f"tightening.{index}"
            with self.subTest(current_tightening=dimension), _environment(
                points=_points(("node", "extension.node"))
            ) as environment:
                first, _second = _supersede(environment, suffix)
                committed = _commit_policy_change(environment, suffix, mutate)
                before_snapshot = environment.activation.snapshot()
                before_rows = _activation_storage_rows(environment)
                with self.assertRaisesRegex(ValueError, "E_EXTENSION_CURRENT_TRUST"):
                    _transition(
                        environment,
                        _set_request(
                            environment,
                            f"transition.rollback.tightened.{index}",
                            "rollback",
                            "extension.example",
                            first.record_digest,
                        ),
                    )
                self.assertEqual(environment.activation.snapshot(), before_snapshot)
                self.assertEqual(_activation_storage_rows(environment), before_rows)
                restarted = environment.restart_activation().doctor()
                self.assertEqual(restarted, before_snapshot)
                self.assertEqual(restarted.active_manifest["generation"], 2)
                self.assertEqual(
                    environment.trust.current().policy.revocation_high_water,
                    committed.policy.revocation_high_water,
                )

        with self.subTest(current_tightening="resource-binding"), _environment(
            points=_points(("node", "extension.node"))
        ) as environment:
            first, _second = _supersede(environment, "resource")
            environment.activation._resource_binding_digest = DIGEST
            before_snapshot = environment.activation.snapshot()
            before_rows = _activation_storage_rows(environment)
            high_water = environment.trust.current().policy.revocation_high_water
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_CURRENT_TRUST"):
                _transition(
                    environment,
                    _set_request(
                        environment,
                        "transition.rollback.tightened.resource",
                        "rollback",
                        "extension.example",
                        first.record_digest,
                    ),
                )
            self.assertEqual(environment.activation.snapshot(), before_snapshot)
            self.assertEqual(_activation_storage_rows(environment), before_rows)
            restarted = environment.restart_activation().doctor()
            self.assertEqual(restarted, before_snapshot)
            self.assertEqual(restarted.active_manifest["generation"], 2)
            self.assertEqual(
                environment.trust.current().policy.revocation_high_water,
                high_water,
            )

        for expanded in (False, True):
            suffix = "expanded" if expanded else "unchanged"
            with self.subTest(eligible_current_policy=suffix), _environment(
                points=_points(("node", "extension.node"))
            ) as environment:
                first, _second = _supersede(environment, suffix)
                if expanded:
                    def add_unrelated_key(body, current):  # type: ignore[no-untyped-def]
                        unrelated = copy.deepcopy(body["trust_keys"][0])  # type: ignore[index]
                        unrelated.update(
                            publisher_id="publisher.unrelated",
                            key_id="key.unrelated",
                            namespaces=["unrelated."],
                            added_generation=current.generation + 1,
                            revocation_sequence=current.revocation_high_water,
                        )
                        body["trust_keys"] = sorted(
                            [*body["trust_keys"], unrelated], key=canonical_bytes
                        )

                    _commit_policy_change(environment, suffix, add_unrelated_key)
                high_water = environment.trust.current().policy.revocation_high_water
                rolled_back = _transition(
                    environment,
                    _set_request(
                        environment,
                        f"transition.rollback.eligible.{suffix}",
                        "rollback",
                        "extension.example",
                        first.record_digest,
                    ),
                )
                restarted = environment.restart_activation().doctor()
                self.assertEqual((rolled_back.generation, restarted.active_manifest["generation"]), (3, 3))
                self.assertEqual(
                    restarted.active_manifest["active_packages"][0][
                        "activation_record_digest"
                    ],
                    first.record_digest,
                )
                self.assertEqual(
                    environment.trust.current().policy.revocation_high_water,
                    high_water,
                )

    def test_gew_ext_022_fault_cuts_restart_to_exact_old_or_new_generation(self) -> None:
        cuts = (
            *ExtensionActivationRepository.fault_schedule(),
            *ExtensionActivationRepository.post_publish_fault_schedule(),
        )
        for cut in cuts:
            def fault(point: str, expected: str = cut) -> None:
                if point == expected:
                    raise RuntimeError(expected)
                if (
                    expected in ExtensionActivationRepository.post_publish_fault_schedule()
                    and expected != "extension-activation.after-publish-durability"
                    and point == "extension-activation.after-publish-durability"
                ):
                    raise RuntimeError("force extension activation restoration")

            with self.subTest(cut=cut), _environment(
                points=_points(("node", "extension.node")), activation_fault=fault
            ) as environment:
                with self.assertRaisesRegex(RuntimeError, cut):
                    _activate(
                        environment,
                        _activation_request(
                            environment, environment.initial_receipt, f"activation.{cut}"
                        ),
                    )
                recovered = environment.restart_activation().doctor()
                post_publish = cut in ExtensionActivationRepository.post_publish_fault_schedule()
                expected = (
                    1
                    if cut == "extension-activation.before-restoration-publication"
                    else 2 if post_publish else (1 if cut.endswith("after-commit") else 0)
                )
                self.assertEqual(len(recovered.activation_manifests), expected)
                self.assertEqual(
                    None if expected == 0 else recovered.active_manifest["generation"],
                    None if expected == 0 else expected,
                )
                if post_publish and expected == 2:
                    self.assertEqual(recovered.active_manifest["active_packages"], [])
                    self.assertEqual(
                        recovered.active_manifest["transition_kind"], "rollback"
                    )
        for cut in ExtensionActivationRepository.fault_schedule():
            state = {"armed": False}

            def rollback_fault(point: str, expected: str = cut) -> None:
                if state["armed"] and point == expected:
                    raise RuntimeError(expected)

            with self.subTest(rollback_cut=cut), _environment(
                points=_points(("node", "extension.node")),
                activation_fault=rollback_fault,
            ) as environment:
                first = _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, f"activation.rollback-base.{cut}"
                    ),
                )
                second_ingest = _install(
                    environment,
                    valid_bundle(
                        extension_id="extension.example",
                        extension_version="2.0.0",
                        extension_points=_points(("node", "extension.node.v2")),
                        exported_identities=_points(("node", "extension.node.v2")),
                    )[0],
                )
                override = _digest(
                    {
                        "schema_version": "1.0.0",
                        "activation_id": f"activation.rollback-head.{cut}",
                        "candidate_ingest_record_digest": second_ingest.record_digest,
                        "existing_activation_record_digests": [first.record_digest],
                        "owner_decision_digest": DIGEST,
                    },
                    "extension-conflict-override",
                )
                _activate(
                    environment,
                    _activation_request(
                        environment,
                        second_ingest,
                        f"activation.rollback-head.{cut}",
                        override,
                    ),
                )
                state["armed"] = True
                with self.assertRaisesRegex(RuntimeError, cut):
                    _transition(
                        environment,
                        _set_request(
                            environment,
                            f"transition.fault.{cut}",
                            "rollback",
                            "extension.example",
                            first.record_digest,
                        ),
                    )
                state["armed"] = False
                recovered = environment.restart_activation().doctor()
                expected_generation = 3 if cut == "extension-activation.after-commit" else 2
                self.assertEqual(
                    recovered.active_manifest["generation"], expected_generation
                )
                expected_record = (
                    first.record_digest
                    if expected_generation == 3
                    else recovered.activations[-1]["record_digest"]
                )
                self.assertEqual(
                    recovered.active_manifest["active_packages"][0][
                        "activation_record_digest"
                    ],
                    expected_record,
                )

    def test_gew_ext_023_doctor_rejects_orphan_duplicate_and_tampered_chain(self) -> None:
        with _environment(points=_points(("node", "extension.node"))) as environment:
            _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.doctor"
                ),
            )
            self.assertEqual(environment.activation.doctor().active_manifest["generation"], 1)
            connection = sqlite3.connect(environment.trust._path)
            try:
                manifest = copy.deepcopy(environment.activation.snapshot().active_manifest)
                manifest.update(
                    generation=2,
                    previous_manifest_digest=manifest["manifest_digest"],
                    transition_id="transition.orphan",
                )
                manifest.pop("manifest_digest")
                manifest["manifest_digest"] = _digest(
                    manifest, "extension-activation-manifest"
                )
                connection.execute(
                    "INSERT INTO extension_activation_manifests"
                    "(generation,transition_id,manifest_digest,manifest_json) VALUES(?,?,?,?)",
                    (
                        2,
                        "transition.orphan",
                        manifest["manifest_digest"],
                        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ValueError, "orphan|chain|pointer"):
                environment.restart_activation()

        with _environment(points=_points(("node", "extension.node"))) as environment:
            _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.tamper"
                ),
            )
            connection = sqlite3.connect(environment.trust._path)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO extension_activation_manifests"
                        "(generation,transition_id,manifest_digest,manifest_json) "
                        "SELECT generation,'duplicate',manifest_digest,manifest_json "
                        "FROM extension_activation_manifests WHERE generation=1"
                    )
                connection.rollback()
                connection.execute("DROP TRIGGER extension_activation_manifest_no_update")
                connection.execute(
                    "UPDATE extension_activation_manifests SET manifest_json='{}' WHERE generation=1"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ValueError, "manifest|chain"):
                environment.restart_activation()


if __name__ == "__main__":
    unittest.main()
