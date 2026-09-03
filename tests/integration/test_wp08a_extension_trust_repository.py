"""WP-08A durable installation trust ledger (GEW-EXT-004..006)."""

from __future__ import annotations

import copy
import json
import unittest

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.extensions import (
    EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST,
    ExtensionTrustPolicy,
)
from graph_engineering.storage.extensions import ExtensionTrustRepository
from tests.support.wp03_repository import ROOT, repository_stack
from tests.support.runtime import runtime_context
from tests.support.wp08a_trust import authorize_operations, operations_for_candidate


DIGEST = "sha256-jcs-v1:" + "a" * 64


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    result = copy.deepcopy(body)
    result[field] = _digest(body, name)
    return result


def _genesis(installation_id: str) -> ExtensionTrustPolicy:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "installation_id": installation_id,
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
        "reducer_implementation_digest": EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST,
    }
    return ExtensionTrustPolicy.from_dict(
        _complete(body, "extension-trust-policy", "policy_digest")
    )


def _candidate(
    previous: ExtensionTrustPolicy,
    *,
    revocation: dict[str, object] | None = None,
) -> ExtensionTrustPolicy:
    body = previous.to_dict()
    body.update(
        generation=previous.generation + 1,
        previous_policy_digest=previous.policy_digest,
        revocation_high_water=previous.revocation_high_water + (1 if revocation else 0),
        revocations=[] if revocation is None else [revocation],
        compatibility_floors=[{
            "component_kind": "test-generation",
            "compatibility_policy_digest": _digest(
                {"generation": previous.generation + 1}, "test-trust-generation",
            ),
        }],
    )
    del body["policy_digest"]
    return ExtensionTrustPolicy.from_dict(
        _complete(body, "extension-trust-policy", "policy_digest"), previous=previous
    )


def _authorization(transaction_id: str, expected_head_digest: str) -> dict[str, object]:
    return {
        "transaction_id": transaction_id,
        "expected_head_digest": expected_head_digest,
        "owner_identity": "owner.example",
        "owner_decision_digest": DIGEST,
        "owner_authority_digest": DIGEST,
        "ordered_operations_digest": DIGEST,
        "created_at": "2026-08-20T00:00:00Z",
    }


class ExtensionTrustRepositoryTests(unittest.TestCase):
    @staticmethod
    def _runtime(occurred_at: str = "2026-08-20T00:00:00Z"):  # type: ignore[no-untyped-def]
        return runtime_context(
            "owner.example", "test-runtime", "test-lineage", "test-actor", occurred_at, 1
        )

    def _repository(self, manager, genesis, *, fault=lambda _point: None):  # type: ignore[no-untyped-def]
        from graph_engineering.storage.extensions import ExtensionTrustRepository

        policy = json.loads(
            (ROOT / "config/extensions/extension-storage-policy-v1.json").read_text()
        )
        return ExtensionTrustRepository.initialize(
            manager,
            genesis,
            policy_document=policy,
            bootstrap_terminal_record_digest=DIGEST,
            fault_hook=fault,
        )

    def test_gew_ext_004_commit_abort_rollback_chain_and_cas_are_exact(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, _tasks, _leases):
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            genesis = _genesis(installation_id)
            repository = self._repository(manager, genesis)
            initial = repository.current()
            self.assertEqual((initial.policy.generation, initial.ledger), (0, ()))

            authority_candidate = _candidate(
                genesis,
                revocation={
                    "target_kind": "extension", "target_identity_digest": DIGEST,
                    "input_kind": "owner-revocation", "input_digest": DIGEST,
                    "reason_code": "security.denied", "local_sequence": 1,
                    "effective_generation": 1, "owner_decision_digest": DIGEST,
                },
            )
            authority_operations = operations_for_candidate(
                initial.policy, authority_candidate
            )
            self.assertGreater(len(authority_operations), 1)
            reversed_operations = tuple(reversed(authority_operations))
            with self.assertRaisesRegex(ValueError, "canonical"):
                repository._commit_operations_issued(
                    reversed_operations,
                    authorization=authorize_operations(
                        _authorization("transaction.order.1", initial.head.head_digest),
                        reversed_operations,
                    ),
                    runtime=self._runtime(),
                )
            authorization = authorize_operations(
                _authorization("transaction.authority.1", initial.head.head_digest),
                authority_operations,
            )
            decision = copy.deepcopy(authorization["owner_decision"])
            assert isinstance(decision, dict)
            decision["expansion_targets"].pop()  # type: ignore[union-attr]
            decision.pop("decision_digest")
            decision["decision_digest"] = _digest(
                decision, "extension-trust-owner-decision"
            )
            authorization["owner_decision"] = decision
            authorization["owner_decision_digest"] = decision["decision_digest"]
            with self.assertRaisesRegex(ValueError, "coverage"):
                repository._commit_operations_issued(
                    authority_operations,
                    authorization=authorization,
                    runtime=self._runtime(),
                )
            self.assertEqual(repository.current().ledger, ())

            first = _candidate(genesis)
            operations = operations_for_candidate(initial.policy, first)
            committed = repository._commit_operations_issued(
                operations,
                authorization=authorize_operations(
                    _authorization("transaction.commit.1", initial.head.head_digest), operations,
                ),
                runtime=self._runtime(),
            )
            self.assertEqual(committed.policy.generation, 1)
            self.assertEqual([item.record_type for item in committed.ledger], ["prepared", "commit"])

            stale = _candidate(first)
            with self.assertRaisesRegex(ValueError, "CAS|head"):
                stale_operations = operations_for_candidate(committed.policy, stale)
                repository._commit_operations_issued(
                    stale_operations,
                    authorization=authorize_operations(
                        _authorization("transaction.stale.1", initial.head.head_digest),
                        stale_operations,
                    ),
                    runtime=self._runtime(),
                )
            self.assertEqual(repository.current().head.head_digest, committed.head.head_digest)
            self.assertEqual(len(repository.current().ledger), 2)

            aborted = repository._abort_issued(
                operations=(abort_operations := operations_for_candidate(committed.policy, stale)),
                authorization=authorize_operations(
                    _authorization("transaction.abort.1", committed.head.head_digest),
                    abort_operations,
                ),
                reason_code="policy.rejected",
                runtime=self._runtime("2026-08-20T00:01:00Z"),
            )
            self.assertEqual(aborted.policy.policy_digest, first.policy_digest)
            self.assertEqual([item.record_type for item in aborted.ledger][-2:], ["prepared", "abort"])

            rollback = _candidate(first)
            rollback_operations = operations_for_candidate(committed.policy, rollback)
            rolled_back = repository._rollback_operations_issued(
                rollback_operations,
                rollback_of_record_digest=committed.ledger[-1].record_digest,
                restore_content_from_policy_digest=genesis.policy_digest,
                authorization=authorize_operations(
                    _authorization("transaction.rollback.1", committed.head.head_digest),
                    rollback_operations,
                ),
                runtime=self._runtime(),
            )
            self.assertEqual(rolled_back.policy.generation, 2)
            self.assertEqual([item.record_type for item in rolled_back.ledger][-2:], ["prepared", "rollback"])
            self.assertEqual(
                [item.to_dict()["record_sequence"] for item in rolled_back.ledger],
                list(range(1, 7)),
            )

    def test_wp08a_qr_r1_001_every_invalid_kind_is_zero_write(self) -> None:
        from tests.integration.test_wp08a_extension_activation import _environment, _points
        from tests.unit.test_wp08a_trust_reducer import _operation, _transition_cases

        with _environment(points=_points(("node", "extension.node"))) as environment:
            current = environment.trust.current()
            before = tuple(item.record_digest for item in current.ledger)
            cases = _transition_cases(current.policy)
            self.assertEqual(tuple(item[0] for item in cases), (
                "add-key", "retire-key", "rotate-key", "register-production-policy",
                "retire-production-policy", "set-source-rule", "set-namespace-rule",
                "set-extension-kind-rule", "set-capability-ceiling",
                "set-compatibility-floor", "apply-local-revocation",
                "apply-publisher-revocation",
            ))
            for kind, target, old, _valid, invalid_new in cases:
                with self.subTest(kind=kind):
                    with self.assertRaises(ValueError):
                        invalid = _operation(
                            current.policy.policy_digest, kind, target, old, invalid_new
                        )
                        environment.trust._commit_operations_issued(
                            (invalid,),
                            authorization=authorize_operations(
                                _authorization(
                                    f"transaction.invalid.{kind}",
                                    current.head.head_digest,
                                ),
                                (invalid,),
                            ),
                            runtime=self._runtime(),
                        )
                    observed = environment.trust.current()
                    self.assertEqual(observed.policy.policy_digest, current.policy.policy_digest)
                    self.assertEqual(
                        tuple(item.record_digest for item in observed.ledger), before
                    )

    def test_gew_ext_005_fault_cuts_are_atomic_and_restart_recovers_exact_old_or_new(self) -> None:
        cuts = (
            "extension-trust.after-prepared",
            "extension-trust.after-policy",
            "extension-trust.after-terminal",
            "extension-trust.after-head-cas",
        )
        for cut in cuts:
            with self.subTest(cut=cut), repository_stack() as (
                _root, factory, _locks, _objects, _tasks, _leases,
            ):
                installation_id = factory._test_installation_scope.context.installation_id
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                genesis = _genesis(installation_id)
                repository = self._repository(
                    manager,
                    genesis,
                    fault=lambda point, expected=cut: (_ for _ in ()).throw(RuntimeError(expected))
                    if point == expected
                    else None,
                )
                initial = repository.current()
                with self.assertRaisesRegex(RuntimeError, cut):
                    candidate = _candidate(genesis)
                    operations = operations_for_candidate(initial.policy, candidate)
                    repository._commit_operations_issued(
                        operations,
                        authorization=authorize_operations(
                            _authorization("transaction.crash.1", initial.head.head_digest),
                            operations,
                        ),
                        runtime=self._runtime(),
                    )
                recovered = repository.recover()
                self.assertEqual(recovered.policy.generation, 0)
                self.assertEqual(
                    [item.record_type for item in recovered.ledger], ["prepared", "abort"]
                )
        for cut in ExtensionTrustRepository.post_commit_fault_schedule():
            with self.subTest(post_commit_cut=cut), repository_stack() as (
                _root, factory, _locks, _objects, _tasks, _leases,
            ):
                installation_id = factory._test_installation_scope.context.installation_id
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                genesis = _genesis(installation_id)
                def post_commit_fault(point: str, expected: str = cut) -> None:
                    if point == expected:
                        raise RuntimeError(expected)
                    if (
                        expected != "extension-trust.after-commit-durability"
                        and point == "extension-trust.after-commit-durability"
                    ):
                        raise RuntimeError("force extension trust restoration")

                repository = self._repository(manager, genesis, fault=post_commit_fault)
                initial = repository.current()
                revocation = {
                    "target_kind": "extension",
                    "target_identity_digest": DIGEST,
                    "input_kind": "owner-revocation",
                    "input_digest": DIGEST,
                    "reason_code": "security.denied",
                    "local_sequence": 1,
                    "effective_generation": 1,
                    "owner_decision_digest": DIGEST,
                }
                candidate = _candidate(genesis, revocation=revocation)
                operations = operations_for_candidate(initial.policy, candidate)
                with self.assertRaisesRegex(RuntimeError, cut):
                    repository._commit_operations_issued(
                        operations,
                        authorization=authorize_operations(
                            _authorization("transaction.postcommit.1", initial.head.head_digest),
                            operations,
                        ),
                        runtime=self._runtime(),
                    )
                restored = repository.current()
                before_restoration = (
                    cut == "extension-trust.before-restoration-publication"
                )
                self.assertEqual(restored.policy.generation, 1 if before_restoration else 2)
                self.assertEqual(restored.policy.revocation_high_water, 1)
                self.assertEqual(restored.policy.to_dict()["revocations"], [revocation])
                if before_restoration:
                    self.assertNotEqual(
                        restored.policy.to_dict()["compatibility_floors"], []
                    )
                    self.assertEqual(
                        [item.record_type for item in restored.ledger],
                        ["prepared", "commit"],
                    )
                else:
                    self.assertNotEqual(restored.policy.to_dict()["compatibility_floors"], [])
                    self.assertEqual(
                        [item.record_type for item in restored.ledger],
                        ["prepared", "commit", "prepared", "rollback"],
                    )

        with repository_stack() as (
            _root, factory, _locks, _objects, _tasks, _leases,
        ):
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            armed = False

            def unprovable_fault(point: str) -> None:
                if armed and point == "extension-trust.after-commit-durability":
                    raise RuntimeError("force unprovable restoration")

            repository = self._repository(
                factory._test_installation_manager,
                _genesis(installation_id),
                fault=unprovable_fault,
            )
            initial = repository.current()
            first_candidate = _candidate(initial.policy)
            first_operations = operations_for_candidate(initial.policy, first_candidate)
            first = repository._commit_operations_issued(
                first_operations,
                authorization=authorize_operations(
                    _authorization("transaction.join-base.1", initial.head.head_digest),
                    first_operations,
                ),
                runtime=self._runtime(),
            )
            second_candidate = _candidate(first.policy)
            second_operations = operations_for_candidate(first.policy, second_candidate)
            armed = True
            with self.assertRaisesRegex(Exception, "blocked"):
                repository._commit_operations_issued(
                    second_operations,
                    authorization=authorize_operations(
                        _authorization("transaction.join-blocked.1", first.head.head_digest),
                        second_operations,
                    ),
                    runtime=self._runtime(),
                )
            with self.assertRaisesRegex(Exception, "blocked"):
                repository.current()

    def test_gew_ext_006_publisher_statement_is_bounded_input_until_owner_commit(self) -> None:
        from graph_engineering.core.security.extensions import ExtensionPublisherRevocationStatement

        statement_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "publisher_id": "publisher.example",
            "publisher_key_id": "publisher.key.1",
            "target_kind": "extension",
            "target_identity_digest": DIGEST,
            "publisher_sequence": 7,
            "reason_code": "publisher.revoked",
            "issued_at": "2026-08-20T00:00:00Z",
            "signature": "test-signature",
        }
        statement = ExtensionPublisherRevocationStatement.from_dict(
            _complete(statement_body, "extension-publisher-revocation", "statement_digest")
        )
        with repository_stack() as (_root, factory, _locks, _objects, _tasks, _leases):
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            genesis = _genesis(installation_id)
            repository = self._repository(manager, genesis)
            initial = repository.current()
            with self.assertRaisesRegex(ValueError, "Owner authorization"):
                repository._apply_publisher_revocation_issued(  # type: ignore[arg-type]
                    statement, operation=None, authorization=None, runtime=self._runtime()
                )
            self.assertEqual(repository.current().ledger, ())

            revocation = {
                "target_kind": "extension",
                "target_identity_digest": DIGEST,
                "input_kind": "publisher-revocation",
                "input_digest": statement.statement_digest,
                "reason_code": "publisher.revoked",
                "local_sequence": 1,
                "effective_generation": 1,
                "owner_decision_digest": DIGEST,
            }
            candidate = _candidate(genesis, revocation=revocation)
            with self.assertRaisesRegex(TypeError, "application"):
                repository.apply_publisher_revocation(
                    statement,
                    candidate=candidate,
                    authorization=_authorization("transaction.revocation.1", initial.head.head_digest),
                )
            self.assertEqual(repository.current().policy.revocation_high_water, 0)


if __name__ == "__main__":
    unittest.main()
