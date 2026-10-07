from __future__ import annotations

import dataclasses
import copy
import json
import os
import signal
from concurrent.futures import ThreadPoolExecutor
import unittest

from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
from graph_engineering.storage.errors import (
    LockUnavailableError,
    RepositoryConflictError,
    RepositoryIntegrityError,
)
from graph_engineering.core.actions import PreparedAction
from graph_engineering.storage.codec import semantic_record_digest
from graph_engineering.storage.ports import CommitBatch
from graph_engineering.storage.repository import make_event
from graph_engineering.application.actions import ActionCoordinator
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.storage.actions import ActionJournalRepository
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.security import SecurityStateRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from tests.support.wp05_actions import (
    action_coordinator_for_thread,
    action_stack,
    authority_document,
    compensation_prepared_document,
    disclosure_plan,
    ACTION_DOCUMENT_CONTEXT,
    ROOT,
    prepared_document,
)


class WP05RecoveryClaimTests(unittest.TestCase):
    @staticmethod
    def _append_invocation(path, label: str) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, f"{label}\n".encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _assert_invocation_log_at_most_once(self, path) -> None:
        calls = [] if not path.exists() else path.read_text().splitlines()
        self.assertLessEqual(len(calls), 1, f"durable invocation log detected replay: {calls}")

    def _unknown_original(self, fixture):
        prepared = fixture.coordinator.prepare(prepared_document())
        fixture.coordinator.authorize(authority_document(prepared))
        target = DeterministicFakeTarget(
            target_id="target-project",
            target_digest=prepared.target_digest,
            resource_id="target:project",
            initial_state={"version": 1},
            failure_mode="timeout-after-effect",
        )
        fixture.coordinator.execute(
            prepared.action_id,
            owner_id="owner-wp05",
            runtime_kind="codex",
            runtime_lineage_id="lineage-wp05",
            lease=fixture.action_lease,
            target=target,
            observer=target.observer_port(),
            disclosure_plan=disclosure_plan(fixture, prepared),
        )
        self.assertEqual(fixture.journal.load(prepared.action_id).state, "unknown")
        self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
        return prepared, target

    def _authorize_compensation(self, fixture):
        compensation = fixture.coordinator.prepare(compensation_prepared_document(
            snapshot_digest=fixture.current_task_snapshot_digest(),
        ))
        fixture.coordinator.authorize(authority_document(compensation))
        return compensation

    def _receipt_recorded_recovery(self, fixture):
        original, target = self._unknown_original(fixture)
        fixture.expire_action_lease()
        compensation = self._authorize_compensation(fixture)
        plan = disclosure_plan(fixture, compensation)
        target.failure_mode = "crash-after-effect"
        with self.assertRaises(RuntimeError):
            fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(), disclosure_plan=plan,
            )
        target.failure_mode = "stale-query"
        outcome = fixture.coordinator.compensate_unknown(
            original.action_id, compensation_action_id=compensation.action_id,
            recovery_lease=fixture.action_lease, owner_id="owner-wp05",
            runtime_kind="codex", runtime_lineage_id="lineage-wp05",
            target=target, observer=target.observer_port(), disclosure_plan=plan,
        )
        self.assertEqual(outcome.route, "manual-reconciliation")
        claim = fixture.leases.load_claim(f"claim:{original.action_id}")
        attempt = fixture.recovery_attempt(original.action_id)
        self.assertEqual((claim["state"], attempt["state"]), ("unresolved", "receipt_recorded"))
        target.failure_mode = None
        return original, compensation, target, claim, attempt

    def _direct_reconcile_commit(self, fixture, original, compensation, claim, attempt, observation):
        receipt = attempt["receipt"]
        observation = copy.deepcopy(observation)
        observation["bound_receipt_digest"] = receipt["receipt_digest"]
        observation["observation_digest"] = semantic_record_digest({
            "contract": "fresh-target-observation-v1",
            "value": {
                key: value for key, value in observation.items()
                if key not in {"bound_receipt_digest", "observation_digest"}
            },
        })
        head = fixture.journal._journal.current_task_head(original.task_id)
        event = make_event(
            task_id=original.task_id, sequence=head.sequence + 1,
            event_id=f"{attempt['attempt_id']}:direct-reconcile",
            event_type="action.compensation_reconciled",
            occurred_at=fixture.journal._journal.current_time(),
            actor={"kind": "deterministic", "id": "repository-boundary-test"},
            expected_task_revision=head.revision,
            baseline_digests=[original.baseline_digest],
            payload={
                "attempt_id": attempt["attempt_id"], "claim_id": claim["claim_id"],
                "compensation_action_id": compensation.action_id,
                "start_event_digest": attempt["start_event_digest"],
                "receipt_event_digest": attempt["receipt_event_digest"],
                "receipt_digest": receipt["receipt_digest"],
                "fresh_observation_digest": observation["observation_digest"],
                "fresh_observation_revision": observation["observation_revision"],
                "verified_outcome": "compensation_reconciled",
            }, previous_event_digest=head.head_digest,
        )
        snapshot = copy.deepcopy(head.snapshot)
        snapshot.update({"task_id": original.task_id, "revision": head.revision + 1})
        fixture.repository.commit(CommitBatch(
            transaction_id=f"{attempt['attempt_id']}:direct-reconcile",
            task_id=original.task_id, expected_task_revision=head.revision,
            events=(event,), snapshot=snapshot, catalog_delta={},
            lease_assertion={
                "lease_id": fixture.action_lease.lease_id,
                "resource_id": f"task:{original.task_id}",
                "fencing_token": dict(fixture.action_lease.fencing_tokens)[f"task:{original.task_id}"],
            },
            claim_compensation_delta=fixture.leases.reconcile_claim_compensation(
                claim, attempt=attempt, reconciled_event_digest=event["event_digest"],
                fresh_observation=observation,
            ),
            action_journal_delta=fixture.journal._journal.compensation_reconcile_delta(
                fixture.journal.load(original.action_id),
                fixture.journal.load(compensation.action_id), observation,
            ),
        ))

    def _assert_reconcile_rejection_frozen(self, fixture, original, compensation, claim, attempt, observation):
        head_before = fixture.journal._journal.current_task_head(original.task_id)
        original_before = fixture.journal.load(original.action_id)
        compensation_before = fixture.journal.load(compensation.action_id)
        with self.assertRaises(RepositoryIntegrityError):
            self._direct_reconcile_commit(
                fixture, original, compensation, claim, attempt, observation,
            )
        self.assertEqual(fixture.journal._journal.current_task_head(original.task_id), head_before)
        self.assertEqual(fixture.journal.load(original.action_id), original_before)
        self.assertEqual(fixture.journal.load(compensation.action_id), compensation_before)
        self.assertEqual(fixture.leases.load_claim(claim["claim_id"]), claim)
        self.assertEqual(fixture.recovery_attempt(original.action_id), attempt)
        for index, resource in enumerate(claim["resources"]):
            with self.assertRaises(RepositoryConflictError):
                fixture.leases.acquire_many(
                    lease_id=f"frozen-probe-{index}", task_id=original.task_id,
                    run_id="frozen-probe", operation_id="frozen-probe",
                    resources=(resource,), ttl_ns=10**9,
                )

    def test_wp05_code_r1_001_rejects_recomputed_wrong_observation_resource(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, compensation, target, claim, attempt = self._receipt_recorded_recovery(fixture)
            observation = target.observer_port().observe()
            observation["resource_id"] = f"task:{original.task_id}"
            self._assert_reconcile_rejection_frozen(
                fixture, original, compensation, claim, attempt, observation,
            )

    def test_wp05_code_r1_001_rejects_recomputed_wrong_rollback_state(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, compensation, target, claim, attempt = self._receipt_recorded_recovery(fixture)
            observation = target.observer_port().observe()
            observation["state"] = {"version": 999}
            self._assert_reconcile_rejection_frozen(
                fixture, original, compensation, claim, attempt, observation,
            )

    def test_gew_act_recovery_claim_expired_p(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            target.failure_mode = None
            outcome = fixture.coordinator.compensate_unknown(
                original.action_id,
                compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                target=target,
                observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, compensation),
            )
            self.assertEqual((outcome.state, outcome.route), ("compensated", "compensation-reconciled"))
            self.assertEqual(fixture.recovery_attempt(original.action_id)["state"], "reconciled")
            self.assertEqual(fixture.leases.unresolved_claims(), ())
            self.assertEqual(target.call_count, 2)

    def test_wp05_code_r1_002_compensation_receipt_object_is_durable_and_exactly_bound(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            target.failure_mode = None
            fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, compensation),
            )
            attempt = fixture.recovery_attempt(original.action_id)
            receipt = attempt["receipt"]
            object_digest = receipt["raw_receipt_object_digest"]
            self.assertEqual(attempt["receipt_object_digest"], object_digest)
            body = fixture.objects.get(object_digest, require_referenced=True)
            self.assertEqual(json.loads(body), {
                "contract": "bounded-redacted-fake-receipt-v1",
                "effect": "applied",
                "receipt_source": "tool-return",
                "result": "succeeded",
                "schema_version": "1.0.0",
            })
            receipt_event = next(
                event for event in fixture.repository.replay(original.task_id)
                if event["event_type"] == "action.compensation_receipt_recorded"
            )
            self.assertEqual(
                receipt_event["payload"]["raw_receipt_object_digest"],
                object_digest,
            )

    def test_gew_act_recovery_claim_live_p(self) -> None:
        with action_stack() as fixture:
            original, target = self._unknown_original(fixture)
            compensation = self._authorize_compensation(fixture)
            target.failure_mode = None
            outcome = fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, compensation),
            )
            self.assertEqual(outcome.route, "compensation-reconciled")
            self.assertEqual(target.call_count, 2)
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_gew_act_recovery_start_replay_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            compensation_disclosure = disclosure_plan(fixture, compensation)
            target.failure_mode = "crash-after-effect"
            with self.assertRaisesRegex(RuntimeError, "crash after effect"):
                fixture.coordinator.compensate_unknown(
                    original.action_id,
                    compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    target=target,
                    observer=target.observer_port(),
                    disclosure_plan=compensation_disclosure,
                )
            attempt = fixture.recovery_attempt(original.action_id)
            self.assertEqual(attempt["state"], "started")
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
            calls_after_crash = target.call_count
            target.failure_mode = None
            recovered = fixture.coordinator.compensate_unknown(
                original.action_id,
                compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                target=target,
                observer=target.observer_port(),
                disclosure_plan=compensation_disclosure,
            )
            self.assertEqual(recovered.state, "compensated")
            self.assertEqual(target.call_count, calls_after_crash)
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_gew_act_recovery_claim_exact_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            target.failure_mode = None
            wrong = dataclasses.replace(
                fixture.action_lease,
                resources=("task:task-wp05",),
                fencing_tokens=(("task:task-wp05", dict(fixture.action_lease.fencing_tokens)["task:task-wp05"]),),
            )
            with self.assertRaises((RepositoryConflictError, ValueError)):
                fixture.coordinator.compensate_unknown(
                    original.action_id,
                    compensation_action_id=compensation.action_id,
                    recovery_lease=wrong,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    target=target,
                    observer=target.observer_port(),
                    disclosure_plan=disclosure_plan(fixture, compensation),
                )
            self.assertEqual(target.call_count, 1)
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_gew_act_recovery_no_new_lease_claim_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            self._unknown_original(fixture)
            fixture.expire_action_lease()
            with self.assertRaisesRegex(RepositoryConflictError, "frozen by unresolved"):
                fixture.leases.acquire_many(
                    lease_id="replacement-lease",
                    task_id="task-wp05",
                    run_id="replacement-run",
                    operation_id="rollback",
                    resources=("target:project", "task:task-wp05"),
                    ttl_ns=10**9,
                )
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_gew_act_recovery_authority_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            fixture.journal.test_only_mutate_authority(compensation.action_id, "expiry")
            calls_before = target.call_count
            with self.assertRaises(ValueError):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(),
                    disclosure_plan=disclosure_plan(fixture, compensation),
                )
            self.assertEqual(target.call_count, calls_before)
            self.assertIsNone(fixture.leases.recovery_attempt(f"claim:{original.action_id}"))

    def test_gew_act_recovery_compensation_only_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            value = compensation_prepared_document(
                snapshot_digest=fixture.current_task_snapshot_digest(),
            )
            value.update({
                "action_id": "action-wp05-not-rollback",
                "action_kind": "commit",
                "idempotency_key": "idempotency-wp05-not-rollback",
            })
            value["prepared_action_digest"] = PreparedAction.digest_document(
                value, ACTION_DOCUMENT_CONTEXT,
            )
            wrong = fixture.coordinator.prepare(value)
            fixture.coordinator.authorize(authority_document(wrong))
            calls_before = target.call_count
            with self.assertRaisesRegex(ValueError, "exactly bound"):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=wrong.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(),
                    disclosure_plan=disclosure_plan(fixture, wrong),
                )
            self.assertEqual(target.call_count, calls_before)

    def test_gew_act_recovery_verify_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = None
            base_observer = target.observer_port()

            class StaleAfterCallObserver:
                is_test_double = True
                is_read_only_observer = True
                target_id = base_observer.target_id
                target_digest = base_observer.target_digest
                resource_id = base_observer.resource_id
                capabilities = base_observer.capabilities

                def __init__(self) -> None:
                    self.count = 0

                def observe(self):
                    self.count += 1
                    value = base_observer.observe()
                    if self.count >= 2:
                        value["fresh"] = False
                    return value

            outcome = fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=StaleAfterCallObserver(), disclosure_plan=plan,
            )
            self.assertEqual((outcome.state, outcome.route), ("unknown", "manual-reconciliation"))
            self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
            self.assertEqual(fixture.recovery_attempt(original.action_id)["state"], "receipt_recorded")

    def test_gew_act_recovery_attempt_id_p(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, _target = self._unknown_original(fixture)
            compensation = self._authorize_compensation(fixture)
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            authority = fixture.journal.load(compensation.action_id).authority
            self.assertIsNotNone(authority)
            first = fixture.leases.compensation_attempt_id(
                claim, compensation_action_id=compensation.action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared_action_digest,
            )
            second = fixture.leases.compensation_attempt_id(
                claim, compensation_action_id=compensation.action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared_action_digest,
            )
            self.assertEqual(first, second)

    def test_gew_act_recovery_concurrency_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = None

            lineage = fixture.issuer.issue_task_context(original.task_id).binding.runtime_lineage_id
            def run() -> str:
                try:
                    with action_coordinator_for_thread(fixture) as coordinator:
                        return coordinator.compensate_unknown(
                            original.action_id, compensation_action_id=compensation.action_id,
                            recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                            runtime_kind="codex", runtime_lineage_id=lineage,
                            target=target, observer=target.observer_port(), disclosure_plan=plan,
                        ).route
                except (LockUnavailableError, RepositoryConflictError, ValueError):
                    return "conflict"

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = tuple(executor.map(lambda _item: run(), range(2)))
            self.assertEqual(results.count("compensation-reconciled"), 1)
            self.assertEqual(target.call_count, 2)
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_gew_act_recovery_lock_span_p(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, original_target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)

            class LockAssertingTarget(DeterministicFakeTarget):
                def invoke(self, **kwargs):
                    self.asserted_lock_span = fixture.locks.installation_held_by_current_thread()
                    held = tuple(
                        lock_id
                        for token in fixture.locks._thread_tokens.get(__import__("threading").get_ident(), ())
                        for lock_id in token.lock_ids
                    )
                    self.asserted_lock_span = self.asserted_lock_span and all(
                        f"resource:{resource}" in held for resource in fixture.action_lease.resources
                    )
                    return super().invoke(**kwargs)

            target = LockAssertingTarget(
                target_id=original_target.target_id, target_digest=original_target.target_digest,
                resource_id=original_target.resource_id, initial_state={"version": 2},
            )
            outcome = fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture, compensation),
            )
            self.assertTrue(target.asserted_lock_span)
            self.assertEqual(outcome.route, "compensation-reconciled")

    def test_gew_act_recovery_verify_p(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            target.failure_mode = None
            observer = target.observer_port()
            outcome = fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=observer,
                disclosure_plan=disclosure_plan(fixture, compensation),
            )
            self.assertGreaterEqual(observer.query_count, 1)
            self.assertEqual(outcome.state, "compensated")
            self.assertEqual(fixture.leases.unresolved_claims(), ())

    def test_gew_act_recovery_no_replay_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = "crash-after-effect"
            with self.assertRaises(RuntimeError):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(), disclosure_plan=plan,
                )
            calls = target.call_count
            target.failure_mode = None
            fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(), disclosure_plan=plan,
            )
            self.assertEqual(target.call_count, calls)

    def test_gew_act_recovery_attempt_id_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, _target = self._unknown_original(fixture)
            compensation = self._authorize_compensation(fixture)
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            authority = fixture.journal.load(compensation.action_id).authority
            self.assertIsNotNone(authority)
            original_id = fixture.leases.compensation_attempt_id(
                claim, compensation_action_id=compensation.action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared_action_digest,
            )
            for field, value in (
                ("revision", claim["revision"] + 1),
                ("action_id", "changed-original-action"),
                ("started_event_digest", original.target_digest),
            ):
                with self.subTest(field=field):
                    changed = copy.deepcopy(claim)
                    changed[field] = value
                    changed_id = fixture.leases.compensation_attempt_id(
                        changed, compensation_action_id=compensation.action_id,
                        compensation_authority_digest=authority.authority_digest,
                        compensation_prepared_digest=compensation.prepared_action_digest,
                    )
                    self.assertNotEqual(original_id, changed_id)

    def test_gew_act_recovery_receipt_binding_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = "crash-after-effect"
            with self.assertRaises(RuntimeError):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(), disclosure_plan=plan,
                )
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            attempt = fixture.recovery_attempt(original.action_id)
            raw_receipt_body = json.dumps({
                "contract": "bounded-redacted-fake-receipt-v1",
                "receipt_source": "post-crash-target-query",
                "result": "unknown",
                "schema_version": "1.0.0",
            }, sort_keys=True, separators=(",", ":")).encode()
            raw_receipt_object_digest = fixture.objects.digest(raw_receipt_body)
            fixture.objects.put_verified(raw_receipt_body, raw_receipt_object_digest)
            receipt = {
                "protocol_version": "1.0.0", "attempt_id": attempt["attempt_id"],
                "claim_id": claim["claim_id"], "task_id": claim["task_id"],
                "original_action_id": claim["action_id"],
                "compensation_action_id": compensation.action_id,
                "start_event_digest": attempt["start_event_digest"],
                "authority_digest": attempt["compensation_authority_digest"],
                "prepared_action_digest": attempt["compensation_prepared_digest"],
                "target_id": attempt["target_id"], "target_digest": attempt["target_digest"],
                "lease_id": attempt["lease_id"], "resources": attempt["resources"],
                "fencing_tokens": attempt["fencing_tokens"],
                "receipt_source": "post-crash-target-query", "result": "unknown",
                "raw_result_digest": semantic_record_digest({
                    "contract": "bounded-redacted-fake-receipt-v1",
                    "value": json.loads(raw_receipt_body),
                }),
                "raw_receipt_object_digest": raw_receipt_object_digest,
            }
            receipt["receipt_digest"] = semantic_record_digest({
                "contract": "claim-compensation-receipt-v1", "value": receipt,
            })
            exact_payload = {
                "attempt_id": attempt["attempt_id"],
                "start_event_digest": attempt["start_event_digest"],
                "claim_id": claim["claim_id"], "compensation_action_id": compensation.action_id,
                "task_id": claim["task_id"], "receipt_digest": receipt["receipt_digest"],
                "raw_receipt_object_digest": raw_receipt_object_digest,
                "receipt_source": receipt["receipt_source"], "target_id": attempt["target_id"],
                "target_digest": attempt["target_digest"], "lease_id": attempt["lease_id"],
                "resources": attempt["resources"], "fencing_tokens": attempt["fencing_tokens"],
                "result": receipt["result"],
            }
            for mutation in ("missing", "extra", "substitution"):
                with self.subTest(mutation=mutation):
                    payload = copy.deepcopy(exact_payload)
                    if mutation == "missing":
                        payload.pop("receipt_source")
                    elif mutation == "extra":
                        payload["unexpected"] = True
                    else:
                        payload["start_event_digest"] = original.target_digest
                    head = fixture.journal._journal.current_task_head(original.task_id)
                    event = make_event(
                        task_id=original.task_id, sequence=head.sequence + 1,
                        event_id=f"{attempt['attempt_id']}:bad-receipt:{mutation}",
                        event_type="action.compensation_receipt_recorded",
                        occurred_at=fixture.journal._journal.current_time(),
                        actor={"kind": "deterministic", "id": "receipt-binding-test"},
                        expected_task_revision=head.revision,
                        baseline_digests=[original.baseline_digest], payload=payload,
                        previous_event_digest=head.head_digest,
                    )
                    delta = fixture.leases.record_compensation_receipt(
                        claim, attempt=attempt, receipt_event_digest=event["event_digest"], receipt=receipt,
                    )
                    snapshot = copy.deepcopy(head.snapshot)
                    snapshot.update({"task_id": original.task_id, "revision": head.revision + 1})
                    with self.assertRaisesRegex(RepositoryIntegrityError, "payload is not exact"):
                        fixture.repository.commit(CommitBatch(
                            transaction_id=f"{attempt['attempt_id']}:bad-receipt:{mutation}",
                            task_id=original.task_id, expected_task_revision=head.revision,
                            events=(event,), snapshot=snapshot, catalog_delta={},
                            object_digests=(raw_receipt_object_digest,),
                            lease_assertion={
                                "lease_id": fixture.action_lease.lease_id,
                                "resource_id": f"task:{original.task_id}",
                                "fencing_token": dict(fixture.action_lease.fencing_tokens)[f"task:{original.task_id}"],
                            }, claim_compensation_delta=delta,
                            action_journal_delta=fixture.journal._journal.compensation_receipt_delta(
                                fixture.journal.load(compensation.action_id),
                                state="unknown", receipt=receipt,
                            ),
                        ))
            self.assertEqual(fixture.recovery_attempt(original.action_id)["state"], "started")

    def test_gew_act_recovery_start_event_payload_exact_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, _target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            compensation_record = fixture.journal.load(compensation.action_id)
            authority = compensation_record.authority
            self.assertIsNotNone(authority)
            attempt_id = fixture.leases.compensation_attempt_id(
                claim, compensation_action_id=compensation.action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared_action_digest,
            )
            exact_payload = {
                "attempt_id": attempt_id, "claim_id": claim["claim_id"],
                "original_action_id": original.action_id,
                "original_started_event_digest": claim["started_event_digest"],
                "compensation_action_id": compensation.action_id,
                "compensation_authority_digest": authority.authority_digest,
                "compensation_prepared_digest": compensation.prepared_action_digest,
                "task_id": original.task_id, "lease_id": fixture.action_lease.lease_id,
                "resources": list(fixture.action_lease.resources),
                "fencing_tokens": dict(fixture.action_lease.fencing_tokens),
                "target_id": compensation.target_id, "target_digest": compensation.target_digest,
                "baseline_digest": compensation.baseline_digest,
                "snapshot_digest": compensation.snapshot_digest,
                "disclosure_plan_digest": plan.plan_digest,
            }
            for mutation in ("missing", "extra", "substitution"):
                with self.subTest(mutation=mutation):
                    payload = copy.deepcopy(exact_payload)
                    if mutation == "missing":
                        payload.pop("target_digest")
                    elif mutation == "extra":
                        payload["unexpected"] = True
                    else:
                        payload["target_digest"] = original.baseline_digest
                    head = fixture.journal._journal.current_task_head(original.task_id)
                    event = make_event(
                        task_id=original.task_id, sequence=head.sequence + 1,
                        event_id=f"{attempt_id}:invalid-start:{mutation}",
                        event_type="action.compensation_execution_started",
                        occurred_at=fixture.journal._journal.current_time(),
                        actor={"kind": "deterministic", "id": "start-payload-test"},
                        expected_task_revision=head.revision,
                        baseline_digests=[original.baseline_digest], payload=payload,
                        previous_event_digest=head.head_digest,
                    )
                    delta = fixture.leases.start_claim_compensation(
                        claim, attempt_id=attempt_id,
                        compensation_action_id=compensation.action_id,
                        compensation_authority_digest=authority.authority_digest,
                        compensation_prepared_digest=compensation.prepared_action_digest,
                        start_event_digest=event["event_digest"], target_id=compensation.target_id,
                        target_digest=compensation.target_digest,
                        baseline_digest=compensation.baseline_digest,
                        snapshot_digest=compensation.snapshot_digest,
                        disclosure_plan_digest=plan.plan_digest,
                    )
                    snapshot = copy.deepcopy(head.snapshot)
                    snapshot.update({"task_id": original.task_id, "revision": head.revision + 1})
                    with self.assertRaisesRegex(RepositoryIntegrityError, "payload is not exact"):
                        fixture.repository.commit(CommitBatch(
                            transaction_id=f"{attempt_id}:invalid-start:{mutation}",
                            task_id=original.task_id, expected_task_revision=head.revision,
                            events=(event,), snapshot=snapshot, catalog_delta={},
                            lease_assertion={
                                "lease_id": fixture.action_lease.lease_id,
                                "resource_id": f"task:{original.task_id}",
                                "fencing_token": dict(fixture.action_lease.fencing_tokens)[f"task:{original.task_id}"],
                            }, claim_compensation_delta=delta,
                            action_journal_delta=fixture.journal._journal.compensation_start_delta(
                                compensation_record,
                            ),
                        ))
                    self.assertIsNone(fixture.leases.recovery_attempt(claim["claim_id"]))
            head = fixture.journal._journal.current_task_head(original.task_id)
            event = make_event(
                task_id=original.task_id, sequence=head.sequence + 1,
                event_id=f"{attempt_id}:invalid-protocol", event_type="action.compensation_execution_started",
                occurred_at=fixture.journal._journal.current_time(),
                actor={"kind": "deterministic", "id": "protocol-version-test"},
                expected_task_revision=head.revision,
                baseline_digests=[original.baseline_digest], payload=exact_payload,
                previous_event_digest=head.head_digest,
            )
            protocol_delta = fixture.leases.start_claim_compensation(
                claim, attempt_id=attempt_id, compensation_action_id=compensation.action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared_action_digest,
                start_event_digest=event["event_digest"], target_id=compensation.target_id,
                target_digest=compensation.target_digest, baseline_digest=compensation.baseline_digest,
                snapshot_digest=compensation.snapshot_digest,
                disclosure_plan_digest=plan.plan_digest,
            )
            protocol_delta["protocol_version"] = "2.0.0"
            snapshot = copy.deepcopy(head.snapshot)
            snapshot.update({"task_id": original.task_id, "revision": head.revision + 1})
            with self.assertRaisesRegex(RepositoryIntegrityError, "identity/resources"):
                fixture.repository.commit(CommitBatch(
                    transaction_id=f"{attempt_id}:invalid-protocol", task_id=original.task_id,
                    expected_task_revision=head.revision, events=(event,), snapshot=snapshot,
                    catalog_delta={}, lease_assertion={
                        "lease_id": fixture.action_lease.lease_id,
                        "resource_id": f"task:{original.task_id}",
                        "fencing_token": dict(fixture.action_lease.fencing_tokens)[f"task:{original.task_id}"],
                    }, claim_compensation_delta=protocol_delta,
                    action_journal_delta=fixture.journal._journal.compensation_start_delta(
                        compensation_record,
                    ),
                ))

    def test_gew_act_recovery_reconcile_event_payload_exact_r(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = "crash-after-effect"
            with self.assertRaises(RuntimeError):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(), disclosure_plan=plan,
                )
            target.failure_mode = "stale-query"
            manual = fixture.coordinator.compensate_unknown(
                original.action_id, compensation_action_id=compensation.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                target=target, observer=target.observer_port(), disclosure_plan=plan,
            )
            self.assertEqual(manual.route, "manual-reconciliation")
            target.failure_mode = None
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            attempt = fixture.recovery_attempt(original.action_id)
            receipt = attempt["receipt"]
            self.assertIsInstance(receipt, dict)
            observation = target.observer_port().observe()
            observation["bound_receipt_digest"] = receipt["receipt_digest"]
            observation["observation_digest"] = semantic_record_digest({
                "contract": "fresh-target-observation-v1",
                "value": {
                    key: value for key, value in observation.items()
                    if key not in {"bound_receipt_digest", "observation_digest"}
                },
            })
            exact_payload = {
                "attempt_id": attempt["attempt_id"], "claim_id": claim["claim_id"],
                "compensation_action_id": compensation.action_id,
                "start_event_digest": attempt["start_event_digest"],
                "receipt_event_digest": attempt["receipt_event_digest"],
                "receipt_digest": receipt["receipt_digest"],
                "fresh_observation_digest": observation["observation_digest"],
                "fresh_observation_revision": observation["observation_revision"],
                "verified_outcome": "compensation_reconciled",
            }
            for mutation in ("missing", "extra", "substitution"):
                with self.subTest(mutation=mutation):
                    payload = copy.deepcopy(exact_payload)
                    if mutation == "missing":
                        payload.pop("fresh_observation_revision")
                    elif mutation == "extra":
                        payload["unexpected"] = True
                    else:
                        payload["receipt_digest"] = original.target_digest
                    head = fixture.journal._journal.current_task_head(original.task_id)
                    event = make_event(
                        task_id=original.task_id, sequence=head.sequence + 1,
                        event_id=f"{attempt['attempt_id']}:bad-reconcile:{mutation}",
                        event_type="action.compensation_reconciled",
                        occurred_at=fixture.journal._journal.current_time(),
                        actor={"kind": "deterministic", "id": "reconcile-payload-test"},
                        expected_task_revision=head.revision,
                        baseline_digests=[original.baseline_digest], payload=payload,
                        previous_event_digest=head.head_digest,
                    )
                    delta = fixture.leases.reconcile_claim_compensation(
                        claim, attempt=attempt, reconciled_event_digest=event["event_digest"],
                        fresh_observation=observation,
                    )
                    snapshot = copy.deepcopy(head.snapshot)
                    snapshot.update({"task_id": original.task_id, "revision": head.revision + 1})
                    with self.assertRaisesRegex(RepositoryIntegrityError, "payload is not exact"):
                        fixture.repository.commit(CommitBatch(
                            transaction_id=f"{attempt['attempt_id']}:bad-reconcile:{mutation}",
                            task_id=original.task_id, expected_task_revision=head.revision,
                            events=(event,), snapshot=snapshot, catalog_delta={},
                            lease_assertion={
                                "lease_id": fixture.action_lease.lease_id,
                                "resource_id": f"task:{original.task_id}",
                                "fencing_token": dict(fixture.action_lease.fencing_tokens)[f"task:{original.task_id}"],
                            }, claim_compensation_delta=delta,
                            action_journal_delta=fixture.journal._journal.compensation_reconcile_delta(
                                fixture.journal.load(original.action_id),
                                fixture.journal.load(compensation.action_id), observation,
                            ),
                        ))
            self.assertEqual(fixture.leases.load_claim(claim["claim_id"])["state"], "unresolved")

    def test_gew_act_recovery_claim_freeze_p(self) -> None:
        with action_stack(action_ttl_ns=10) as fixture:
            original, target = self._unknown_original(fixture)
            fixture.expire_action_lease()
            compensation = self._authorize_compensation(fixture)
            plan = disclosure_plan(fixture, compensation)
            target.failure_mode = "crash-after-effect"
            with self.assertRaises(RuntimeError):
                fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=target, observer=target.observer_port(), disclosure_plan=plan,
                )
            claim = fixture.leases.load_claim(f"claim:{original.action_id}")
            self.assertEqual(claim["state"], "unresolved")
            with self.assertRaises(RepositoryConflictError):
                fixture.leases.acquire_many(
                    lease_id="freeze-probe", task_id=original.task_id, run_id="freeze-run",
                    operation_id="freeze-probe", resources=fixture.action_lease.resources,
                    ttl_ns=10**9,
                )

    def test_gew_act_recovery_process_crash_matrix(self) -> None:
        schedule = json.loads(
            (ROOT / "config/contracts/action-recovery-fault-schedule-v2.json").read_text(),
        )
        expected_points = {
            "claim.after-consume", "gate.before-start", "query.after-observation",
            "receipt-object.before-durable", "receipt-object.after-durable",
            "receipt-event.after-journal-apply-before-commit",
            "receipt-event.after-commit", "receipt-event.before-commit", "reconcile.after-commit",
            "reconcile.before-commit", "start.after-commit", "start.before-commit",
            "tool.after-effect",
        }
        self.assertEqual(set(schedule["points"]), expected_points)
        repository_points = {
            "start.before-commit": (1, "commit.before_commit"),
            "start.after-commit": (1, "commit.after_commit"),
            "receipt-event.after-journal-apply-before-commit": (
                2, "commit.after_recovery_journal_apply",
            ),
            "receipt-event.before-commit": (2, "commit.before_commit"),
            "receipt-event.after-commit": (2, "commit.after_commit"),
            "reconcile.before-commit": (3, "commit.before_commit"),
            "reconcile.after-commit": (3, "commit.after_commit"),
            "claim.after-consume": (3, "commit.after_commit"),
        }

        for point in schedule["points"]:
            with self.subTest(point=point), action_stack(action_ttl_ns=10) as fixture:
                original, _target = self._unknown_original(fixture)
                fixture.expire_action_lease()
                compensation = self._authorize_compensation(fixture)
                plan = disclosure_plan(fixture, compensation)
                factory = fixture.factory
                target_path = factory.data_root / "wp05-crash-target.json"
                target_path.write_text('{"version":2}')
                invocation_path = factory.data_root / "wp05-crash-invocations.log"
                read_fd, write_fd = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    try:
                        commit_number = 0

                        def stop() -> None:
                            os.write(write_fd, b"ready")
                            signal.pause()

                        def repository_fault(step: str) -> None:
                            nonlocal commit_number
                            if step == "commit.before_transaction":
                                commit_number += 1
                            selected = repository_points.get(point)
                            if selected is not None and selected == (commit_number, step):
                                stop()

                        def action_fault(step: str) -> None:
                            selected = {
                                "receipt-object.before-durable": "receipt-object.before-durable",
                                "receipt-object.after-durable": "receipt-object.after-durable",
                            }.get(point)
                            if selected == step:
                                stop()

                        class FileObserver:
                            is_test_double = True
                            is_read_only_observer = True
                            target_id = "target-project"
                            target_digest = original.target_digest
                            resource_id = "target:project"
                            capabilities = ("fresh-target-query",)

                            def __init__(self) -> None:
                                self.stopped = False
                                self.query_count = 0

                            def observe(self):
                                self.query_count += 1
                                state = json.loads(target_path.read_text())
                                if point == "query.after-observation" and not self.stopped:
                                    self.stopped = True
                                    stop()
                                return {
                                    "target_id": self.target_id,
                                    "target_digest": self.target_digest,
                                    "resource_id": self.resource_id,
                                    "fresh": True,
                                    "observation_revision": self.query_count,
                                    "state": state,
                                }

                        class FileTarget:
                            is_test_double = True
                            target_id = "target-project"
                            target_digest = original.target_digest
                            resource_id = "target:project"
                            capabilities = (
                                "deterministic-fake-target-v1", "fresh-target-query",
                                "fake-compensation",
                            )

                            def invoke(self, *, payload, fencing_token, started_was_durable):
                                self.call_count += 1
                                WP05RecoveryClaimTests._append_invocation(
                                    invocation_path, "child",
                                )
                                target_path.write_text(json.dumps(dict(payload["set"]), sort_keys=True, separators=(",", ":")))
                                if point == "tool.after-effect":
                                    stop()
                                return {"result": "succeeded", "effect": "applied"}

                            def __init__(self) -> None:
                                self.call_count = 0

                        if point == "gate.before-start":
                            stop()
                        child_locks = LockedFileRegistry(factory)
                        maintenance_objects = ObjectRepository(
                            factory._for_maintenance(), child_locks,
                        )
                        child_manager = InstallationMigrationRepository.attach_command_plane(
                            factory, child_locks, maintenance_objects,
                            control_root=factory._test_installation_control_root,
                            policy_document=factory._test_migration_policy,
                        )
                        with child_manager.command_scope() as child_scope:
                            child_factory = factory.bind_command_scope(child_scope)
                            child_objects = ObjectRepository(child_factory, child_locks)
                            child_leases = ResourceLeaseRepository(child_factory, child_locks)
                            child_journal = ActionJournalRepository(
                                child_factory, schema_registry=fixture.schemas,
                                context=fixture.context,
                            )
                            child_repository = TaskRepository(
                                child_factory, child_locks, child_objects,
                                fault_hook=repository_fault, action_journal=child_journal,
                                command_scope=child_scope,
                            )
                            child_issuer = SecurityContextIssuer(
                                SecurityStateRepository(child_factory), schema_registry=fixture.schemas,
                                context=fixture.context,
                            )
                            child_coordinator = ActionCoordinator(
                                journal=child_journal, repository=child_repository,
                                leases=child_leases, locks=child_locks, objects=child_objects,
                                security_issuer=child_issuer,
                                action_policy=fixture.raw_coordinator._policy,
                                installation_scope=child_scope,
                                fault_hook=action_fault,
                            )
                            child_target = FileTarget()
                            child_coordinator.compensate_unknown(
                                original.action_id,
                                compensation_action_id=compensation.action_id,
                                recovery_lease=fixture.action_lease,
                                owner_id="owner-wp05", runtime_kind="codex",
                                runtime_lineage_id=child_issuer.issue_task_context(original.task_id).binding.runtime_lineage_id, target=child_target,
                                observer=FileObserver(), disclosure_plan=plan,
                            )
                        child_manager.close()
                        maintenance_objects.close()
                    except BaseException:
                        os.write(write_fd, b"error")
                        os._exit(3)
                    os._exit(2)
                os.close(write_fd)
                message = os.read(read_fd, 16)
                os.close(read_fd)
                if message != b"ready":
                    os.waitpid(child, 0)
                    self.fail(f"crash harness failed at {point}: {message!r}")
                os.kill(child, signal.SIGKILL)
                _, child_status = os.waitpid(child, 0)
                self.assertTrue(os.WIFSIGNALED(child_status))
                pre_recovery_claim = fixture.leases.load_claim(f"claim:{original.action_id}")
                pre_recovery_attempt = fixture.leases.recovery_attempt(
                    f"claim:{original.action_id}",
                )
                if pre_recovery_attempt is None or pre_recovery_attempt["state"] != "reconciled":
                    self.assertEqual(pre_recovery_claim["state"], "unresolved")

                class ParentFileObserver:
                    is_test_double = True
                    is_read_only_observer = True
                    target_id = "target-project"
                    target_digest = original.target_digest
                    resource_id = "target:project"
                    capabilities = ("fresh-target-query",)

                    def __init__(self) -> None:
                        self.query_count = 0

                    def observe(self):
                        self.query_count += 1
                        return {
                            "target_id": self.target_id, "target_digest": self.target_digest,
                            "resource_id": self.resource_id, "fresh": True,
                            "observation_revision": self.query_count,
                            "state": json.loads(target_path.read_text()),
                        }

                class ParentFileTarget:
                    is_test_double = True
                    target_id = "target-project"
                    target_digest = original.target_digest
                    resource_id = "target:project"
                    capabilities = (
                        "deterministic-fake-target-v1", "fresh-target-query", "fake-compensation",
                    )

                    def __init__(self) -> None:
                        self.call_count = 0

                    def invoke(self, *, payload, fencing_token, started_was_durable):
                        self.call_count += 1
                        WP05RecoveryClaimTests._append_invocation(
                            invocation_path, "parent",
                        )
                        target_path.write_text(json.dumps(dict(payload["set"]), sort_keys=True, separators=(",", ":")))
                        return {"result": "succeeded", "effect": "applied"}

                parent_target = ParentFileTarget()
                recovered = fixture.coordinator.compensate_unknown(
                    original.action_id, compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=parent_target, observer=ParentFileObserver(), disclosure_plan=plan,
                )
                if point == "start.after-commit":
                    self.assertEqual(recovered.route, "manual-reconciliation")
                    self.assertEqual(len(fixture.leases.unresolved_claims()), 1)
                else:
                    self.assertEqual(recovered.route, "compensation-reconciled")
                    self.assertEqual(fixture.leases.unresolved_claims(), ())
                self.assertEqual(
                    parent_target.call_count,
                    1 if point in {
                        "gate.before-start", "query.after-observation", "start.before-commit",
                    } else 0,
                )
                self._assert_invocation_log_at_most_once(invocation_path)
                calls = [] if not invocation_path.exists() else invocation_path.read_text().splitlines()
                self.assertEqual(len(calls), 0 if point == "start.after-commit" else 1)
                attempt = fixture.recovery_attempt(original.action_id)
                receipt = attempt["receipt"]
                self.assertIsInstance(receipt, dict)
                self.assertEqual(
                    attempt["receipt_object_digest"],
                    receipt["raw_receipt_object_digest"],
                )
                fixture.objects.get(
                    attempt["receipt_object_digest"], require_referenced=True,
                )
                receipt_event = next(
                    event for event in fixture.repository.replay(original.task_id)
                    if event["event_type"] == "action.compensation_receipt_recorded"
                )
                self.assertEqual(
                    receipt_event["payload"]["raw_receipt_object_digest"],
                    attempt["receipt_object_digest"],
                )

    def test_wp05_code_r1_002_invocation_oracle_rejects_known_double_call_mutation(self) -> None:
        with action_stack() as fixture:
            invocation_path = fixture.journal._factory.data_root / "wp05-double-call.log"
            effect_path = fixture.journal._factory.data_root / "wp05-double-call-effect.json"
            child = os.fork()
            if child == 0:
                class MutatedChildFileTarget:
                    def __init__(self) -> None:
                        self.call_count = 0

                    def invoke(self, *, payload, fencing_token, started_was_durable):
                        self.call_count += 1
                        WP05RecoveryClaimTests._append_invocation(
                            invocation_path, f"mutated-child-call-{self.call_count}",
                        )
                        effect_path.write_text(json.dumps(
                            dict(payload["set"]), sort_keys=True, separators=(",", ":"),
                        ))
                        return {"result": "succeeded", "effect": "applied"}

                mutated_tool = MutatedChildFileTarget()
                mutated_tool.invoke(
                    payload={"set": {"version": 1}}, fencing_token=1,
                    started_was_durable=True,
                )
                mutated_tool.invoke(
                    payload={"set": {"version": 1}}, fencing_token=1,
                    started_was_durable=True,
                )
                os._exit(0)
            _, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
            self.assertEqual(json.loads(effect_path.read_text()), {"version": 1})
            with self.assertRaisesRegex(AssertionError, "durable invocation log detected replay"):
                self._assert_invocation_log_at_most_once(invocation_path)


if __name__ == "__main__":
    unittest.main()
