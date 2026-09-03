from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.errors import ObjectIntegrityError, RepositoryConflictError  # noqa: E402
from graph_engineering.storage.faults import (  # noqa: E402
    FaultController,
    InjectedPersistenceFault,
    PersistenceFaultSchedule,
)
from graph_engineering.storage.ports import CommitBatch, LeaseGrant  # noqa: E402
from graph_engineering.storage.repository import make_event  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


def schedule() -> PersistenceFaultSchedule:
    return PersistenceFaultSchedule.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "persistence-fault-schedule-v1.json").read_text()
    ))


def commit_batch(lease: LeaseGrant) -> CommitBatch:
    event = make_event(
        task_id="task-1", sequence=1, event_id="event-1", event_type="task.created",
        occurred_at="t-1", actor={"id": "runtime-1"}, expected_task_revision=0,
        baseline_digests=[], payload={}, previous_event_digest=None,
    )
    return CommitBatch(
        "transaction-1", "task-1", 0, (event,),
        {"task_id": "task-1", "revision": 1}, {},
        {
            "lease_id": lease.lease_id, "resource_id": "task:task-1",
            "fencing_token": dict(lease.fencing_tokens)["task:task-1"],
        },
    )


class PersistenceFaultMatrixTests(unittest.TestCase):
    def test_every_declared_step_and_fault_kind_has_old_new_or_recoverable_state(self) -> None:
        fault_schedule = schedule()
        commit_states = {
            "commit.before_transaction": "old",
            "commit.after_events": "old",
            "commit.before_commit": "old",
            "commit.after_commit": "new",
        }
        object_states = {
            "object.before_staging_open": "old",
            "object.after_file_fsync": "old",
            "object.after_staging_directory_fsync": "old",
            "object.after_publication": "old",
            "object.after_object_directory_fsync": "old",
            "object.before_metadata_commit": "old",
            "object.after_metadata_commit": "new",
        }
        purge_steps = {"purge.after_deleting_commit", "purge.after_directory_fsync"}
        self.assertEqual(
            set(commit_states) | set(object_states) | purge_steps,
            set(fault_schedule.steps),
        )
        for kind in fault_schedule.fault_kinds:
            for step, expected in commit_states.items():
                with self.subTest(kind=kind, step=step):
                    controller = FaultController(
                        fault_schedule, selected_step=step, fault_kind=kind,
                    )
                    with repository_stack(repository_fault=controller) as (
                        _root, _factory, _locks, _objects, repository, leases,
                    ):
                        lease = leases.acquire_many(
                            lease_id="lease-1", task_id="task-1", run_id="run-1",
                            operation_id="write", resources=("task:task-1",), ttl_ns=100,
                        )
                        with self.assertRaises(InjectedPersistenceFault):
                            repository.commit(commit_batch(lease))
                        recovered = repository.recover("transaction-1")
                        self.assertEqual(recovered is not None, expected == "new")
                        if expected == "old":
                            with self.assertRaises(RepositoryConflictError):
                                repository.load("task-1")
                        else:
                            self.assertEqual(repository.load("task-1")["revision"], 1)
            for step, expected in object_states.items():
                with self.subTest(kind=kind, step=step):
                    controller = FaultController(
                        fault_schedule, selected_step=step, fault_kind=kind,
                    )
                    with repository_stack(object_fault=controller) as (
                        _root, _factory, _locks, objects, _repository, _leases,
                    ):
                        body = b"fault-matrix-object"
                        digest = objects.digest(body)
                        with self.assertRaises(InjectedPersistenceFault):
                            objects.put_verified(body, digest)
                        if expected == "old":
                            objects.recover_untrusted()
                            with self.assertRaises(ObjectIntegrityError):
                                objects.get(digest, require_referenced=False)
                        else:
                            self.assertEqual(
                                objects.get(digest, require_referenced=False), body,
                            )
            for step in sorted(purge_steps):
                with self.subTest(kind=kind, step=step):
                    controller = FaultController(
                        fault_schedule, selected_step=step, fault_kind=kind,
                    )
                    with repository_stack(object_fault=controller) as (
                        _root, _factory, _locks, objects, _repository, _leases,
                    ):
                        body = b"fault-matrix-purge"
                        digest = objects.digest(body)
                        objects.put_verified(body, digest)
                        with self.assertRaises(InjectedPersistenceFault):
                            objects.purge(digest)
                        self.assertEqual(objects.recover_deleting(), (digest,))
                        with self.assertRaises(ObjectIntegrityError):
                            objects.get(digest, require_referenced=False)


if __name__ == "__main__":
    unittest.main()
