from __future__ import annotations

import copy
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.errors import (  # noqa: E402
    RepositoryConflictError,
    RepositoryIntegrityError,
)
from graph_engineering.storage.ports import CommitBatch  # noqa: E402
from graph_engineering.storage.repository import make_event  # noqa: E402
from tests.support.wp03_repository import ManualTime, repository_stack  # noqa: E402


class LeaseClaimConformanceTests(unittest.TestCase):
    def test_expiry_observation_persists_high_water_and_clock_rollback_cannot_revive(self) -> None:
        clock = ManualTime(100)
        with repository_stack(manual_time=clock) as (
            _root, factory, _locks, _objects, _repository, leases,
        ):
            lease = leases.acquire_many(
                lease_id="lease-clock", task_id="task-1", run_id="run-1",
                operation_id="clock", resources=("resource-clock",), ttl_ns=50,
            )
            token = dict(lease.fencing_tokens)["resource-clock"]
            clock.set(200)
            self.assertFalse(leases.validate_fence(
                lease_id=lease.lease_id,
                resource_id="resource-clock",
                fencing_token=token,
            ))
            clock.set(120)
            self.assertFalse(leases.validate_fence(
                lease_id=lease.lease_id,
                resource_id="resource-clock",
                fencing_token=token,
            ))
            with factory._for_maintenance().open("application") as connection:
                self.assertEqual(connection.execute(
                    "SELECT value FROM repository_meta WHERE key='clock_high_water_ns'",
                ).fetchone()[0], "200")

    def test_acquire_many_is_atomic_sorted_and_fencing_is_monotonic(self) -> None:
        clock = ManualTime()
        with repository_stack(manual_time=clock) as (
            _root, _factory, _locks, _objects, _repository, leases,
        ):
            first = leases.acquire_many(
                lease_id="lease-1", task_id="task-1", run_id="run-1", operation_id="op-1",
                resources=("resource-b",), ttl_ns=10,
            )
            self.assertEqual(first.fencing_tokens, (("resource-b", 1),))
            clock.set(1)
            with self.assertRaises(RepositoryConflictError):
                leases.acquire_many(
                    lease_id="lease-conflict", task_id="task-2", run_id="run-2",
                    operation_id="op-2", resources=("resource-b", "resource-a"),
                    ttl_ns=8,
                )
            independent = leases.acquire_many(
                lease_id="lease-a", task_id="task-2", run_id="run-2", operation_id="op-2",
                resources=("resource-a",), ttl_ns=8,
            )
            self.assertEqual(independent.fencing_tokens, (("resource-a", 1),))
            clock.set(10)
            after_expiry = leases.acquire_many(
                lease_id="lease-2", task_id="task-2", run_id="run-2", operation_id="op-2",
                resources=("resource-b",), ttl_ns=10,
            )
            self.assertEqual(after_expiry.fencing_tokens, (("resource-b", 2),))
            self.assertFalse(leases.validate_fence(
                lease_id="lease-1", resource_id="resource-b", fencing_token=1,
            ))
            self.assertTrue(leases.validate_fence(
                lease_id="lease-2", resource_id="resource-b", fencing_token=2,
            ))
            clock.set(5)
            self.assertTrue(leases.validate_fence(
                lease_id="lease-2", resource_id="resource-b", fencing_token=2,
            ))
            with _factory._for_maintenance().open("application") as connection:
                self.assertEqual(connection.execute(
                    "SELECT value FROM repository_meta WHERE key='clock_high_water_ns'",
                ).fetchone()[0], "10")
            with self.assertRaises(RepositoryIntegrityError):
                leases.validate_fence(
                    lease_id="lease-2", resource_id="resource-b", fencing_token=True,
                )

    def test_renew_is_revision_bound_and_release_is_exact(self) -> None:
        clock = ManualTime()
        with repository_stack(manual_time=clock) as (
            _root, _factory, _locks, _objects, _repository, leases,
        ):
            grant = leases.acquire_many(
                lease_id="lease-1", task_id="task-1", run_id="run-1", operation_id="op-1",
                resources=("resource-a",), ttl_ns=10,
            )
            clock.set(1)
            renewed = leases.renew(
                grant.lease_id, expected_heartbeat_revision=0, ttl_ns=19,
            )
            self.assertEqual(renewed.heartbeat_revision, 1)
            clock.set(2)
            with self.assertRaises(RepositoryConflictError):
                leases.renew(
                    grant.lease_id, expected_heartbeat_revision=0, ttl_ns=28,
                )
            leases.release(grant.lease_id)
            with self.assertRaises(RepositoryConflictError):
                leases.release(grant.lease_id)

    def test_unresolved_claim_survives_lease_expiry_and_blocks_gc_and_other_task(self) -> None:
        clock = ManualTime()
        with repository_stack(manual_time=clock) as (
            _root, _factory, _locks, objects, repository, leases,
        ):
            body = b"raw-receipt"
            digest = objects.digest(body)
            objects.put_verified(body, digest)
            grant = leases.acquire_many(
                lease_id="lease-1", task_id="task-1", run_id="run-1", operation_id="op-1",
                resources=("resource-a", "task:task-1"), ttl_ns=5,
            )
            event = make_event(
                task_id="task-1", sequence=1, event_id="event-started",
                event_type="action.execution_started", occurred_at="t-1",
                actor={"id": "runtime-1"}, expected_task_revision=0,
                baseline_digests=[], payload={"action_id": "action-1"},
                previous_event_digest=None,
            )
            claim = leases.claim_action(
                claim_id="claim-1", action_id="action-1", task_id="task-1", lease=grant,
                started_event_digest=event["event_digest"],
                object_digests=(digest,),
            )
            repository.commit(CommitBatch(
                "transaction-1", "task-1", 0, (event,),
                {"task_id": "task-1", "revision": 1, "state": "running"},
                {"owner": "owner-1"},
                {
                    "lease_id": grant.lease_id,
                    "resource_id": "task:task-1",
                    "fencing_token": dict(grant.fencing_tokens)["task:task-1"],
                },
                (digest,), claim,
            ))
            self.assertEqual(leases.unresolved_claims()[0]["claim_id"], "claim-1")
            with self.assertRaises(RepositoryConflictError):
                leases.release("lease-1")
            clock.set(5)
            with self.assertRaises(RepositoryConflictError):
                leases.acquire_many(
                    lease_id="lease-2", task_id="task-2", run_id="run-2", operation_id="op-2",
                    resources=("resource-a",), ttl_ns=5,
                )
            self.assertFalse(objects.purge(digest))
            reconciliation_event = make_event(
                task_id="task-1", sequence=2, event_id="event-reconciled",
                event_type="action.reconciled_no_effect", occurred_at="t-2",
                actor={"id": "runtime-1"}, expected_task_revision=1,
                baseline_digests=[], payload={"claim_id": "claim-1"},
                previous_event_digest=event["event_digest"],
            )
            reconciliation = leases.reconcile_claim(
                "claim-1", "reconciled_no_effect", {"target_state": "unchanged"},
                reconciliation_event["event_digest"],
            )
            repository.commit(CommitBatch(
                "transaction-2", "task-1", 1, (reconciliation_event,),
                {"task_id": "task-1", "revision": 2, "state": "running"},
                {"owner": "owner-1"},
                {
                    "lease_id": grant.lease_id,
                    "resource_id": "task:task-1",
                    "fencing_token": dict(grant.fencing_tokens)["task:task-1"],
                },
                claim_reconciliation_delta=reconciliation,
            ))
            leases.release("lease-1")
            second = leases.acquire_many(
                lease_id="lease-2", task_id="task-2", run_id="run-2", operation_id="op-2",
                resources=("resource-a",), ttl_ns=5,
            )
            self.assertEqual(second.fencing_tokens, (("resource-a", 2),))

    def test_claim_and_reconciliation_bind_exact_same_transaction_event_payload(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            grant = leases.acquire_many(
                lease_id="lease-1", task_id="task-1", run_id="run-1", operation_id="op-1",
                resources=("resource-a", "task:task-1"), ttl_ns=10,
            )
            wrong_start = make_event(
                task_id="task-1", sequence=1, event_id="event-wrong-start",
                event_type="action.execution_started", occurred_at="t-1",
                actor={"id": "runtime-1"}, expected_task_revision=0,
                baseline_digests=[], payload={"action_id": "another-action"},
                previous_event_digest=None,
            )
            claim = leases.claim_action(
                claim_id="claim-1", action_id="action-1", task_id="task-1", lease=grant,
                started_event_digest=wrong_start["event_digest"],
            )
            assertion = {
                "lease_id": grant.lease_id,
                "resource_id": "task:task-1",
                "fencing_token": dict(grant.fencing_tokens)["task:task-1"],
            }
            with self.assertRaises(RepositoryIntegrityError):
                repository.commit(CommitBatch(
                    "transaction-wrong-start", "task-1", 0, (wrong_start,),
                    {"task_id": "task-1", "revision": 1}, {}, assertion,
                    claim_delta=claim,
                ))
            incomplete_start = make_event(
                task_id="task-1", sequence=1, event_id="event-incomplete-start",
                event_type="action.execution_started", occurred_at="t-1",
                actor={"id": "runtime-1"}, expected_task_revision=0,
                baseline_digests=[], payload={"action_id": "action-1"},
                previous_event_digest=None,
            )
            exact_claim = leases.claim_action(
                claim_id="claim-1", action_id="action-1", task_id="task-1", lease=grant,
                started_event_digest=incomplete_start["event_digest"],
            )
            claim_mutations: list[tuple[str, dict[str, object]]] = []
            missing = copy.deepcopy(exact_claim)
            missing["resources"] = ["task:task-1"]
            missing["fencing_tokens"] = {
                "task:task-1": dict(grant.fencing_tokens)["task:task-1"],
            }
            claim_mutations.append(("missing-resource", missing))
            extra = copy.deepcopy(exact_claim)
            extra["resources"].append("resource-extra")  # type: ignore[union-attr]
            extra["fencing_tokens"]["resource-extra"] = 1  # type: ignore[index]
            claim_mutations.append(("extra-resource", extra))
            empty = copy.deepcopy(exact_claim)
            empty["resources"] = []
            empty["fencing_tokens"] = {}
            claim_mutations.append(("empty-resource-set", empty))
            stale = copy.deepcopy(exact_claim)
            stale["fencing_tokens"]["resource-a"] += 1  # type: ignore[index,operator]
            claim_mutations.append(("stale-fence", stale))
            wrong_lease = copy.deepcopy(exact_claim)
            wrong_lease["lease_id"] = "another-lease"
            claim_mutations.append(("wrong-lease", wrong_lease))
            for name, changed_claim in claim_mutations:
                with self.subTest(name=name), self.assertRaises(RepositoryIntegrityError):
                    repository.commit(CommitBatch(
                        f"transaction-invalid-claim-{name}", "task-1", 0,
                        (incomplete_start,), {"task_id": "task-1", "revision": 1},
                        {}, assertion, claim_delta=changed_claim,
                    ))
            start = make_event(
                task_id="task-1", sequence=1, event_id="event-start",
                event_type="action.execution_started", occurred_at="t-1",
                actor={"id": "runtime-1"}, expected_task_revision=0,
                baseline_digests=[], payload={"action_id": "action-1"},
                previous_event_digest=None,
            )
            claim["started_event_digest"] = start["event_digest"]
            first = repository.commit(CommitBatch(
                "transaction-start", "task-1", 0, (start,),
                {"task_id": "task-1", "revision": 1}, {}, assertion,
                claim_delta=claim,
            ))
            wrong_reconciliation = make_event(
                task_id="task-1", sequence=2, event_id="event-wrong-reconciliation",
                event_type="action.reconciled_no_effect", occurred_at="t-2",
                actor={"id": "runtime-1"}, expected_task_revision=1,
                baseline_digests=[], payload={"claim_id": "another-claim"},
                previous_event_digest=first.head_digest,
            )
            reconciliation = leases.reconcile_claim(
                "claim-1", "reconciled_no_effect", {"state": "unchanged"},
                wrong_reconciliation["event_digest"],
            )
            with self.assertRaises(RepositoryIntegrityError):
                repository.commit(CommitBatch(
                    "transaction-wrong-reconciliation", "task-1", 1,
                    (wrong_reconciliation,), {"task_id": "task-1", "revision": 2}, {},
                    assertion, claim_reconciliation_delta=reconciliation,
                ))
            self.assertEqual(leases.unresolved_claims()[0]["claim_id"], "claim-1")


if __name__ == "__main__":
    unittest.main()
