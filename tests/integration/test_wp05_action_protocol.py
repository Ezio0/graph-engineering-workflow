from __future__ import annotations

import inspect
import json
import unittest

from graph_engineering.application.actions import ActionCoordinator, ActionOutcome
from graph_engineering.core.actions import ActionGateError, PreparedAction
from graph_engineering.storage.errors import RepositoryIntegrityError
from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
from graph_engineering.storage.actions import ActionJournalRepository
from tests.support.wp05_actions import (
    action_stack,
    ACTION_DOCUMENT_CONTEXT,
    authority_document,
    compensation_prepared_document,
    disclosure_plan,
    prepared_document,
)


class WP05ActionProtocolTests(unittest.TestCase):
    @staticmethod
    def _deep_body(depth: int = 140) -> dict[str, object]:
        value: dict[str, object] = {"leaf": True}
        for _ in range(depth):
            value = {"nested": value}
        return value

    def test_receipt_and_compensation_have_no_direct_durable_or_adapter_bypass(self) -> None:
        self.assertFalse(hasattr(ActionJournalRepository, "record_receipt"))
        target = DeterministicFakeTarget(
            target_id="target-project", target_digest=prepared_document()["target_digest"],
            resource_id="target:project", initial_state={"version": 1},
        )
        self.assertFalse(hasattr(target, "compensate"))

    def test_prepare_authorize_started_claim_call_receipt_and_target_reconcile(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            authority = fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project",
                target_digest=prepared.target_digest,
                resource_id="target:project",
                initial_state={"version": 1},
            )
            outcome = fixture.coordinator.execute(
                prepared.action_id,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                lease=fixture.action_lease,
                target=target,
                observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            self.assertIsInstance(outcome, ActionOutcome)
            self.assertEqual(outcome.route, "reconciled-effect-verified")
            self.assertEqual(target.call_count, 1)
            self.assertTrue(target.started_was_durable)
            self.assertEqual(target.observe()["state"], {"version": 2})
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "reconciled")
            self.assertEqual(fixture.leases.unresolved_claims(), ())
            self.assertEqual(authority.authorized_action_kind, "commit")

    def test_wp05_code_r1_002_normal_receipt_object_is_durable_and_exactly_bound(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
            )
            fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            receipt = fixture.journal.load(prepared.action_id).receipt
            self.assertIsNotNone(receipt)
            object_digest = receipt["raw_receipt_object_digest"]
            body = fixture.objects.get(object_digest, require_referenced=True)
            self.assertEqual(json.loads(body), {
                "contract": "bounded-redacted-fake-receipt-v1",
                "effect": "applied",
                "receipt_source": "tool-return",
                "result": "succeeded",
                "schema_version": "1.0.0",
            })
            receipt_event = next(
                event for event in fixture.repository.replay(prepared.task_id)
                if event["event_type"] == "action.receipt_recorded"
            )
            self.assertEqual(
                receipt_event["payload"]["raw_receipt_object_digest"],
                object_digest,
            )

    def test_non_idempotent_timeout_is_unknown_and_never_auto_replayed(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project",
                target_digest=prepared.target_digest,
                resource_id="target:project",
                initial_state={"version": 1},
                failure_mode="timeout-after-effect",
            )
            plan = disclosure_plan(fixture, prepared)
            outcome = fixture.coordinator.execute(
                prepared.action_id,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                lease=fixture.action_lease,
                target=target,
                observer=target.observer_port(),
                disclosure_plan=plan,
            )
            self.assertEqual(outcome.route, "manual-reconciliation")
            self.assertEqual(target.call_count, 1)
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
            with self.assertRaises(ActionGateError) as caught:
                fixture.coordinator.execute(
                    prepared.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=fixture.action_lease,
                    target=target,
                    observer=target.observer_port(),
                    disclosure_plan=plan,
                )
            self.assertEqual(caught.exception.code, "GEW-AUT-PRECONDITION-CHANGED")
            self.assertEqual(target.call_count, 1)
            reconciled = fixture.coordinator.reconcile_unknown(
                prepared.action_id,
                lease=fixture.action_lease,
                observer=target.observer_port(),
            )
            self.assertEqual(reconciled.route, "reconciled-effect-verified")
            self.assertEqual(target.call_count, 1)
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_crash_after_effect_leaves_started_claim_and_never_replays(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="crash-after-effect",
            )
            with self.assertRaisesRegex(RuntimeError, "crash after effect"):
                fixture.coordinator.execute(
                    prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=target, observer=target.observer_port(),
                    disclosure_plan=disclosure_plan(fixture, prepared),
                )
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "executing")
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
            self.assertEqual(target.call_count, 1)
            recovered = fixture.coordinator.reconcile_unknown(
                prepared.action_id, lease=fixture.action_lease, observer=target.observer_port(),
            )
            self.assertEqual(recovered.route, "reconciled-effect-verified")
            self.assertEqual(target.call_count, 1)

    def test_failure_before_effect_reconciles_no_effect_without_replay(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="failure-before-effect",
            )
            outcome = fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            self.assertEqual((outcome.state, outcome.route), ("failed", "manual-reconciliation"))
            recovered = fixture.coordinator.reconcile_unknown(
                prepared.action_id, lease=fixture.action_lease, observer=target.observer_port(),
            )
            self.assertEqual(recovered.route, "reconciled-no-effect")
            self.assertEqual(target.call_count, 1)

    def test_success_receipt_with_target_mismatch_remains_durably_unreconciled(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="success-without-effect",
            )
            outcome = fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            self.assertEqual((outcome.state, outcome.route), ("succeeded", "manual-target-reconciliation"))
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "succeeded")
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_post_call_observation_binding_mutations_never_consume_claim(self) -> None:
        for mutation in ("stale", "target-id", "target-digest", "resource", "unverifiable"):
            with self.subTest(mutation=mutation), action_stack() as fixture:
                prepared = fixture.coordinator.prepare(prepared_document())
                fixture.coordinator.authorize(authority_document(prepared))
                target = DeterministicFakeTarget(
                    target_id="target-project", target_digest=prepared.target_digest,
                    resource_id="target:project", initial_state={"version": 1},
                )
                base = target.observer_port()

                class MutatingObserver:
                    is_test_double = True
                    is_read_only_observer = True
                    target_id = base.target_id
                    target_digest = base.target_digest
                    resource_id = base.resource_id
                    capabilities = base.capabilities

                    def __init__(self) -> None:
                        self.count = 0

                    def observe(self):
                        self.count += 1
                        if self.count >= 2 and mutation == "unverifiable":
                            raise ValueError("unverifiable")
                        value = base.observe()
                        if self.count < 2:
                            return value
                        if mutation == "stale":
                            value["fresh"] = False
                        elif mutation == "target-id":
                            value["target_id"] = "wrong-target"
                        elif mutation == "target-digest":
                            value["target_digest"] = prepared.baseline_digest
                        elif mutation == "resource":
                            value["resource_id"] = "target:other"
                        return value

                outcome = fixture.coordinator.execute(
                    prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=target, observer=MutatingObserver(),
                    disclosure_plan=disclosure_plan(fixture, prepared),
                )
                self.assertEqual(outcome.route, "manual-target-reconciliation")
                self.assertEqual(fixture.journal.load(prepared.action_id).state, "succeeded")
                self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_reconcile_observation_binding_mutations_never_consume_claim(self) -> None:
        for mutation in ("stale", "target-id", "target-digest", "resource", "unverifiable"):
            with self.subTest(mutation=mutation), action_stack() as fixture:
                prepared = fixture.coordinator.prepare(prepared_document())
                fixture.coordinator.authorize(authority_document(prepared))
                target = DeterministicFakeTarget(
                    target_id="target-project", target_digest=prepared.target_digest,
                    resource_id="target:project", initial_state={"version": 1},
                    failure_mode="failure-before-effect",
                )
                plan = disclosure_plan(fixture, prepared)
                fixture.coordinator.execute(
                    prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=target, observer=target.observer_port(), disclosure_plan=plan,
                )
                target.failure_mode = None
                base = target.observer_port()

                class MutatingObserver:
                    is_test_double = True
                    is_read_only_observer = True
                    target_id = base.target_id
                    target_digest = base.target_digest
                    resource_id = base.resource_id
                    capabilities = base.capabilities

                    def observe(self):
                        if mutation == "unverifiable":
                            raise ValueError("unverifiable")
                        value = base.observe()
                        if mutation == "stale":
                            value["fresh"] = False
                        elif mutation == "target-id":
                            value["target_id"] = "wrong-target"
                        elif mutation == "target-digest":
                            value["target_digest"] = prepared.baseline_digest
                        elif mutation == "resource":
                            value["resource_id"] = "target:other"
                        return value

                outcome = fixture.coordinator.reconcile_unknown(
                    prepared.action_id, lease=fixture.action_lease,
                    observer=MutatingObserver(),
                )
                self.assertEqual(outcome.route, "manual-reconciliation")
                self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_succeeded_unresolved_action_can_later_reconcile_with_fresh_exact_evidence(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="success-without-effect",
            )
            outcome = fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            self.assertEqual(outcome.route, "manual-target-reconciliation")
            target.failure_mode = None
            target._state = {"version": 2}
            reconciled = fixture.coordinator.reconcile_unknown(
                prepared.action_id, lease=fixture.action_lease,
                observer=target.observer_port(),
            )
            self.assertEqual(reconciled.route, "reconciled-effect-verified")
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_compensation_with_stale_snapshot_is_zero_write_rejected(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="timeout-after-effect",
            )
            fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, prepared),
            )
            target.failure_mode = None
            compensation = fixture.coordinator.prepare(compensation_prepared_document())
            before = fixture.journal.load(compensation.action_id)
            with self.assertRaisesRegex(ValueError, "stale_binding"):
                fixture.coordinator.authorize(authority_document(compensation))
            after = fixture.journal.load(compensation.action_id)
            self.assertEqual((after.state, after.revision), (before.state, before.revision))
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "unknown")
            self.assertEqual(target.call_count, 1)
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_missing_repository_authority_membership_is_zero_write_fail_closed(self) -> None:
        with action_stack() as fixture:
            value = prepared_document()
            value["action_id"] = "action-wp05-unattested"
            value["idempotency_key"] = "idempotency-wp05-unattested"
            value["prepared_action_digest"] = PreparedAction.digest_document(
                value, ACTION_DOCUMENT_CONTEXT,
            )
            prepared = fixture.raw_coordinator.prepare(value)
            authority = fixture.coordinator.authorize(authority_document(prepared))
            from graph_engineering.storage.codec import canonical_json, semantic_record_digest
            with fixture.repository._factory.open("application") as connection:
                with connection.transaction():
                    row = connection.execute("SELECT state_json FROM task_security_states WHERE task_id=?", (prepared.task_id,)).fetchone()
                    state = json.loads(row[0])
                    state["authority_digests"].remove(authority.authority_digest)
                    digest = semantic_record_digest({"contract":"task-security-state-v1","value":state})
                    connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                        (canonical_json(state),digest,prepared.task_id))
            before = fixture.journal.load(prepared.action_id)
            with self.assertRaisesRegex(ValueError, "not present in current durable"):
                fixture.raw_coordinator.authorize(fixture.journal._journal.authority_document(authority))
            after = fixture.journal.load(prepared.action_id)
            self.assertEqual((after.state, after.revision), (before.state, before.revision))
            self.assertNotIn(
                "trusted_authority_bootstrap",
                inspect.signature(ActionCoordinator).parameters,
            )

    def test_durable_action_bodies_are_bounded_before_model_digest_or_use(self) -> None:
        for column in ("prepared_json", "receipt_json", "reconciliation_json"):
            with self.subTest(column=column), action_stack() as fixture:
                prepared = fixture.coordinator.prepare(prepared_document())
                fixture.journal.test_only_replace_body(
                    prepared.action_id, column, self._deep_body(),
                )
                with self.assertRaisesRegex(RepositoryIntegrityError, "over budget"):
                    fixture.journal.load(prepared.action_id)


if __name__ == "__main__":
    unittest.main()
