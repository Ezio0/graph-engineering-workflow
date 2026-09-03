"""WP-08A trusted mutation ingress and immutable installed content (GEW-EXT-014..016)."""

from __future__ import annotations

import base64
import copy
import json
import pathlib
import tempfile
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.extension_bundle import ExtensionAttestationProductionPolicy
from graph_engineering.core.security.extensions import (
    ExtensionPublisherRevocationStatement,
    ExtensionTrustPolicy,
)
from tests.integration.test_wp08a_extension_activation import _environment, _points
from tests.integration.test_wp08a_extension_trust_repository import (
    DIGEST,
    _authorization,
    _candidate,
)
from tests.support.wp03_repository import ROOT, repository_stack
from tests.support.wp08a_extension_bundle import SEED, trust_policy_chain, valid_bundle
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


def _verifier():  # type: ignore[no-untyped-def]
    from graph_engineering.adapters.extension_crypto import PycaEd25519CandidateVerifier

    return PycaEd25519CandidateVerifier.from_requirement(
        json.loads(
            (
                ROOT
                / "config/supply-chain/extension-crypto-provider-requirement-v1.json"
            ).read_text()
        )
    )


def _trust_session():  # type: ignore[no-untyped-def]
    from tests.integration.test_wp08a_extension_activation import _session

    return _session()


def _owner_authorization(session, transaction_id: str, head_digest: str):  # type: ignore[no-untyped-def]
    document = _authorization(transaction_id, head_digest)
    document["owner_identity"] = session.proof.owner_id
    return document


def _statement(
    sequence: int = 1,
    *,
    signature_override: str | None = None,
    issued_at: str = "2026-08-20T00:00:00Z",
    key_id: str = "key.example.1",
):  # type: ignore[no-untyped-def]
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "publisher_id": "publisher.example",
        "publisher_key_id": key_id,
        "target_kind": "extension",
        "target_identity_digest": DIGEST,
        "publisher_sequence": sequence,
        "reason_code": "publisher.revoked",
        "issued_at": issued_at,
    }
    signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(
        b"GEW-EXTENSION-PUBLISHER-REVOCATION-V1\0" + canonical_bytes(body)
    )
    body["signature"] = signature_override or base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return ExtensionPublisherRevocationStatement.from_dict(
        _complete(body, "extension-publisher-revocation", "statement_digest")
    )


class ExtensionExitTests(unittest.TestCase):
    def test_gew_ext_014_all_trust_mutations_require_live_factory_issued_owner_authority(self) -> None:
        from graph_engineering.application.extensions import ExtensionTrustApplication
        from graph_engineering.storage.extensions import ExtensionTrustRepository

        with repository_stack() as (_root, factory, _locks, _objects, _tasks, _leases):
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            genesis, candidate = trust_policy_chain(installation_id)
            repository = ExtensionTrustRepository.initialize(
                manager,
                genesis,
                policy_document=json.loads(
                    (ROOT / "config/extensions/extension-storage-policy-v1.json").read_text()
                ),
                bootstrap_terminal_record_digest=DIGEST,
            )
            session = _trust_session()
            authorization = _owner_authorization(
                session, "transaction.trust.live.1", repository.current().head.head_digest
            )
            with self.assertRaisesRegex((TypeError, ValueError), "runtime|application|authority"):
                repository.commit(candidate, authorization=authorization)
            with self.assertRaisesRegex(TypeError, "application"):
                repository.abort(candidate=candidate, authorization=authorization)
            with self.assertRaisesRegex(TypeError, "application"):
                repository.rollback(candidate, authorization=authorization)
            with self.assertRaisesRegex(TypeError, "application"):
                repository.apply_publisher_revocation(
                    _statement(), candidate=candidate, authorization=authorization
                )
            self.assertEqual(repository.current().policy.generation, 0)

            application = ExtensionTrustApplication(repository, _verifier())
            _bundle, metadata = valid_bundle()
            operations = operations_for_candidate(repository.current().policy, candidate)
            committed = application.commit(
                session, session.proof, operations,
                authorize_operations(authorization, operations),
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
                occurred_at="2026-08-20T00:00:00Z", lease_ttl_ns=1,
            )
            self.assertEqual(committed.policy.generation, 1)

            next_candidate = _candidate(candidate)
            next_operations = operations_for_candidate(committed.policy, next_candidate)
            aborted = application.abort(
                session,
                session.proof,
                operations=next_operations,
                authorization=authorize_operations(
                    _owner_authorization(
                        session, "transaction.trust.abort.1", committed.head.head_digest
                    ),
                    next_operations,
                ),
                reason_code="policy.rejected",
                occurred_at="2026-08-20T00:01:00Z",
                lease_ttl_ns=1,
            )
            self.assertEqual(aborted.policy.generation, 1)
            rolled_back = application.rollback(
                session,
                session.proof,
                next_operations,
                rollback_of_record_digest=committed.ledger[-1].record_digest,
                restore_content_from_policy_digest=genesis.policy_digest,
                authorization=authorize_operations(
                    _owner_authorization(
                        session, "transaction.trust.rollback.1", aborted.head.head_digest
                    ),
                    next_operations,
                ),
                occurred_at="2026-08-20T00:02:00Z",
                lease_ttl_ns=1,
            )
            self.assertEqual(rolled_back.policy.generation, 2)
            session.close()

    def test_gew_ext_015_publisher_revocation_is_verified_before_owner_promotion(self) -> None:
        from graph_engineering.application.extensions import ExtensionTrustApplication
        from graph_engineering.storage.extensions import ExtensionTrustRepository

        with repository_stack() as (_root, factory, _locks, _objects, _tasks, _leases):
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            genesis, current_policy = trust_policy_chain(installation_id)
            document = current_policy.to_dict()
            document["trust_keys"][0]["roles"] = sorted(  # type: ignore[index]
                [*document["trust_keys"][0]["roles"], "publisher-revocation"]  # type: ignore[index]
            )
            document.pop("policy_digest")
            current_policy = ExtensionTrustPolicy.from_dict(
                _complete(document, "extension-trust-policy", "policy_digest"), previous=genesis
            )
            repository = ExtensionTrustRepository.initialize(
                manager,
                genesis,
                policy_document=json.loads(
                    (ROOT / "config/extensions/extension-storage-policy-v1.json").read_text()
                ),
                bootstrap_terminal_record_digest=DIGEST,
            )
            session = _trust_session()
            application = ExtensionTrustApplication(repository, _verifier())
            _bundle, metadata = valid_bundle()
            initial_operations = operations_for_candidate(repository.current().policy, current_policy)
            with self.assertRaisesRegex(ValueError, "key role|time"):
                application.apply_publisher_revocation(
                    session, session.proof, _statement(), initial_operations[-1],
                    authorize_operations(
                        _owner_authorization(
                            session, "transaction.revocation.no-role", repository.current().head.head_digest
                        ),
                        (initial_operations[-1],),
                    ),
                    occurred_at="2026-08-20T00:01:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(repository.current().policy.generation, 0)
            operations = operations_for_candidate(repository.current().policy, current_policy)
            first = application.commit(
                session, session.proof, operations,
                authorize_operations(
                    _owner_authorization(
                        session, "transaction.trust.key.1", repository.current().head.head_digest
                    ),
                    operations,
                ),
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
                occurred_at="2026-08-20T00:00:00Z", lease_ttl_ns=1,
            )
            statement = _statement()
            candidate_body = first.policy.to_dict()
            candidate_body.update(
                generation=2,
                previous_policy_digest=first.policy.policy_digest,
                revocation_high_water=1,
                revocations=[{
                    "target_kind": "extension", "target_identity_digest": DIGEST,
                    "input_kind": "publisher-revocation", "input_digest": statement.statement_digest,
                    "reason_code": "publisher.revoked", "local_sequence": 1,
                    "effective_generation": 2, "owner_decision_digest": DIGEST,
                }],
            )
            candidate_body.pop("policy_digest")
            candidate = ExtensionTrustPolicy.from_dict(
                _complete(candidate_body, "extension-trust-policy", "policy_digest"),
                previous=first.policy,
            )
            revocation_operation = operations_for_candidate(first.policy, candidate)[0]
            before = len(first.ledger)
            bad = copy.deepcopy(statement.to_dict())
            bad["signature"] = "A" * 86
            bad.pop("statement_digest")
            bad_statement = ExtensionPublisherRevocationStatement.from_dict(
                _complete(bad, "extension-publisher-revocation", "statement_digest")
            )
            with self.assertRaisesRegex(ValueError, "signature"):
                application.apply_publisher_revocation(
                    session, session.proof, bad_statement, revocation_operation,
                    authorize_operations(
                        _owner_authorization(
                            session, "transaction.revocation.bad", first.head.head_digest
                        ),
                        (revocation_operation,),
                    ),
                    occurred_at="2026-08-20T00:01:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(repository.current().ledger), before)
            with self.assertRaisesRegex(ValueError, "key role|time"):
                application.apply_publisher_revocation(
                    session, session.proof,
                    _statement(2, issued_at="2028-08-20T00:00:00Z"), revocation_operation,
                    authorize_operations(
                        _owner_authorization(
                            session, "transaction.revocation.future", first.head.head_digest
                        ),
                        (revocation_operation,),
                    ),
                    occurred_at="2026-08-20T00:01:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(repository.current().ledger), before)
            promoted = application.apply_publisher_revocation(
                session, session.proof, statement, revocation_operation,
                authorize_operations(
                    _owner_authorization(
                        session, "transaction.revocation.good", first.head.head_digest
                    ),
                    (revocation_operation,),
                ),
                occurred_at="2026-08-20T00:01:00Z", lease_ttl_ns=1,
            )
            self.assertEqual(promoted.policy.revocation_high_water, 1)
            replay_body = promoted.policy.to_dict()
            replay_body.update(
                generation=3,
                previous_policy_digest=promoted.policy.policy_digest,
                revocation_high_water=2,
                revocations=[{
                    "target_kind": "extension", "target_identity_digest": DIGEST,
                    "input_kind": "publisher-revocation", "input_digest": statement.statement_digest,
                    "reason_code": "publisher.revoked", "local_sequence": 2,
                    "effective_generation": 3, "owner_decision_digest": DIGEST,
                }],
            )
            replay_body.pop("policy_digest")
            replay_candidate = ExtensionTrustPolicy.from_dict(
                _complete(replay_body, "extension-trust-policy", "policy_digest"),
                previous=promoted.policy,
            )
            replay_operation = operations_for_candidate(promoted.policy, replay_candidate)[0]
            with self.assertRaisesRegex(ValueError, "sequence"):
                application.apply_publisher_revocation(
                    session, session.proof, statement, replay_operation,
                    authorize_operations(
                        _owner_authorization(
                            session, "transaction.revocation.replay", promoted.head.head_digest
                        ),
                        (replay_operation,),
                    ),
                    occurred_at="2026-08-20T00:02:00Z", lease_ttl_ns=1,
                )
            session.close()

    def test_gew_ext_016_installed_content_root_survives_source_removal_and_doctor_rejects_tamper(self) -> None:
        with _environment(points=_points(("node", "extension.node"))) as environment:
            receipt = environment.initial_receipt
            (environment.root / "extension-1.gewx").unlink()
            observed = environment.installer.doctor(receipt)
            self.assertEqual(observed.content_root_digest, receipt.content_root_digest)
            with self.assertRaisesRegex(ValueError, "ledger binding"):
                environment.installer.doctor(replace(receipt, content_root_digest=DIGEST))
            root = environment.installer._test_content_path(receipt)
            payload = root / "payload/hello.txt"
            payload.chmod(0o600)
            payload.write_bytes(b"tampered")
            payload.chmod(0o400)
            before = len(environment.installer._test_records())
            with self.assertRaisesRegex(ValueError, "content|tamper|digest"):
                environment.installer.doctor(receipt)
            self.assertEqual(len(environment.installer._test_records()), before)
            self.assertFalse((root.parent / "unrelated").exists())


if __name__ == "__main__":
    unittest.main()
