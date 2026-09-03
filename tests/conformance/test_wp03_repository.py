from __future__ import annotations

import dataclasses
import os
import pathlib
import signal
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.errors import (  # noqa: E402
    ObjectIntegrityError,
    RepositoryConflictError,
    RepositoryIntegrityError,
)
from graph_engineering.storage.ports import CommitBatch, LeaseGrant  # noqa: E402
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from graph_engineering.storage.objects import ObjectRepository  # noqa: E402
from graph_engineering.storage.repository import TaskRepository  # noqa: E402
from graph_engineering.storage.repository import make_event  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


def batch(
    transaction_id: str,
    lease: LeaseGrant,
    *,
    revision: int = 0,
    previous_digest: str | None = None,
    object_digests: tuple[str, ...] = (),
    event_type: str = "task.created",
    claim_delta: dict[str, object] | None = None,
) -> CommitBatch:
    event = make_event(
        task_id="task-1",
        sequence=revision + 1,
        event_id=f"event-{revision + 1}",
        event_type=event_type,
        occurred_at=f"t-{revision + 1}",
        actor={"kind": "runtime", "id": "runtime-1"},
        expected_task_revision=revision,
        baseline_digests=[],
        payload={"revision": revision + 1},
        previous_event_digest=previous_digest,
    )
    if claim_delta is not None:
        claim_delta = dict(claim_delta)
        claim_delta["started_event_digest"] = event["event_digest"]
    return CommitBatch(
        transaction_id,
        "task-1",
        revision,
        (event,),
        {"task_id": "task-1", "revision": revision + 1, "state": "ready"},
        {"owner": "owner-1", "runtime": "runtime-1"},
        {
            "lease_id": lease.lease_id,
            "resource_id": "task:task-1",
            "fencing_token": dict(lease.fencing_tokens)["task:task-1"],
        },
        object_digests,
        claim_delta,
    )


class RepositoryConformanceTests(unittest.TestCase):
    def test_atomic_commit_replay_catalog_cas_and_idempotent_recovery(self) -> None:
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            body = b"artifact-body"
            digest = objects.digest(body)
            objects.put_verified(body, digest)
            with self.assertRaises(ObjectIntegrityError):
                objects.get(digest)
            request = batch("transaction-1", lease, object_digests=(digest,))
            stale_assertion = dict(request.lease_assertion)
            stale_assertion["fencing_token"] = stale_assertion["fencing_token"] + 1
            with self.assertRaises(RepositoryConflictError):
                repository.commit(dataclasses.replace(
                    request, transaction_id="transaction-stale-fence",
                    lease_assertion=stale_assertion,
                ))
            self.assertIsNone(repository.recover("transaction-stale-fence"))
            result = repository.commit(request)
            self.assertEqual((result.status, result.revision), ("COMMITTED", 1))
            self.assertEqual(repository.commit(request), result)
            self.assertEqual(repository.recover("transaction-1"), result)
            self.assertEqual(repository.load("task-1")["revision"], 1)
            self.assertEqual(len(repository.replay("task-1")), 1)
            self.assertEqual(repository.query_catalog({"owner": "owner-1"})[0]["task_id"], "task-1")
            self.assertEqual(objects.get(digest), body)
            changed = dataclasses.replace(
                request, snapshot={"task_id": "task-1", "revision": 1, "state": "changed"},
            )
            with self.assertRaises(RepositoryConflictError):
                repository.commit(changed)
            with self.assertRaises(RepositoryConflictError):
                repository.commit(batch("transaction-stale", lease))
            second = batch(
                "transaction-2", lease, revision=1, previous_digest=result.head_digest,
            )
            self.assertEqual(repository.commit(second).revision, 2)
            self.assertEqual([item["sequence"] for item in repository.replay("task-1")], [1, 2])

    def test_before_commit_fault_is_old_and_after_commit_fault_is_recoverable_new(self) -> None:
        before_steps: list[str] = []

        def before_fault(step: str) -> None:
            before_steps.append(step)
            if step == "commit.before_commit":
                raise RuntimeError("injected-before-commit")

        with repository_stack(repository_fault=before_fault) as (
            _root, _factory, _locks, _objects, repository, leases,
        ):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            with self.assertRaisesRegex(RuntimeError, "injected-before"):
                repository.commit(batch("transaction-before", lease))
            self.assertIsNone(repository.recover("transaction-before"))
            with self.assertRaises(RepositoryConflictError):
                repository.load("task-1")
            self.assertIn("commit.after_events", before_steps)

        def after_fault(step: str) -> None:
            if step == "commit.after_commit":
                raise RuntimeError("lost-response-after-commit")

        with repository_stack(repository_fault=after_fault) as (
            _root, _factory, _locks, _objects, repository, leases,
        ):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            with self.assertRaisesRegex(RuntimeError, "lost-response"):
                repository.commit(batch("transaction-after", lease))
            recovered = repository.recover("transaction-after")
            self.assertIsNotNone(recovered)
            self.assertEqual(recovered.revision, 1)  # type: ignore[union-attr]
            self.assertEqual(repository.load("task-1")["revision"], 1)

    def test_corruption_or_missing_committed_object_blocks_integrity(self) -> None:
        with repository_stack() as (root, factory, _locks, objects, repository, leases):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            body = b"body"
            digest = objects.digest(body)
            objects.put_verified(body, digest)
            repository.commit(batch("transaction-1", lease, object_digests=(digest,)))
            path = objects._path(digest)
            path.write_bytes(b"tampered")
            path.chmod(factory.policy.file_mode)
            with self.assertRaises(RepositoryIntegrityError):
                repository.load("task-1")
            self.assertTrue(root.exists())

    def test_replay_binds_index_columns_and_transaction_revision_and_head(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            committed = repository.commit(batch("transaction-1", lease))
            mutations = (
                ("event-type", "UPDATE events SET event_type='forged' WHERE task_id='task-1'", ()),
                ("event-sequence", "UPDATE events SET sequence=9 WHERE task_id='task-1'", ()),
                (
                    "event-transaction",
                    "UPDATE events SET transaction_id='forged-transaction' WHERE task_id='task-1'",
                    (),
                ),
                (
                    "transaction-revision",
                    "UPDATE transactions SET revision=9 WHERE transaction_id='transaction-1'",
                    (),
                ),
                (
                    "transaction-head",
                    "UPDATE transactions SET head_digest=? WHERE transaction_id='transaction-1'",
                    ("sha256-jcs-v1:" + "0" * 64,),
                ),
                (
                    "transaction-task",
                    "UPDATE transactions SET task_id='forged-task' WHERE transaction_id='transaction-1'",
                    (),
                ),
            )
            for name, sql, parameters in mutations:
                with self.subTest(name=name):
                    with factory._for_maintenance().open("application") as connection:
                        with connection.transaction():
                            connection.execute(sql, parameters)
                    with self.assertRaises(RepositoryIntegrityError):
                        repository.replay("task-1")
                    with self.assertRaises(RepositoryIntegrityError):
                        repository.recover("transaction-1")
                    with factory._for_maintenance().open("application") as connection:
                        with connection.transaction():
                            connection.execute(
                                "UPDATE events SET sequence=1,event_type='task.created',"
                                "transaction_id='transaction-1' WHERE event_id='event-1'",
                            )
                            connection.execute(
                                "UPDATE transactions SET task_id='task-1',revision=1,head_digest=? "
                                "WHERE transaction_id='transaction-1'",
                                (committed.head_digest,),
                            )
                    self.assertEqual(len(repository.replay("task-1")), 1)
                    self.assertEqual(repository.recover("transaction-1"), committed)

    def test_snapshot_is_derived_and_can_only_be_repaired_from_valid_committed_head(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
                resources=("task:task-1",), ttl_ns=100,
            )
            result = repository.commit(batch("transaction-1", lease))
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE tasks SET snapshot_json=?,snapshot_digest=? WHERE task_id=?",
                        ('{"revision":99,"task_id":"task-1"}', "sha256-jcs-v1:" + "0" * 64, "task-1"),
                    )
            with self.assertRaises(RepositoryIntegrityError):
                repository.load("task-1")
            repaired = {"task_id": "task-1", "revision": 1, "state": "ready"}
            digest = repository.repair_snapshot("task-1", result.head_digest, repaired)
            self.assertTrue(digest.startswith("sha256-jcs-v1:"))
            self.assertEqual(repository.load("task-1"), repaired)
            with self.assertRaises(RepositoryConflictError):
                repository.repair_snapshot(
                    "task-1", "sha256-jcs-v1:" + "1" * 64, repaired,
                )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_real_process_kill_exposes_only_old_before_commit_or_new_after_commit(self) -> None:
        for target, committed in (
            ("commit.before_commit", False),
            ("commit.after_commit", True),
        ):
            with self.subTest(target=target), repository_stack() as (
                _root, factory, _locks, _objects, repository, leases,
            ):
                lease = leases.acquire_many(
                    lease_id="task-lease", task_id="task-1", run_id="run-1",
                    operation_id="write", resources=("task:task-1",),
                    ttl_ns=100,
                )
                read_fd, write_fd = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    try:
                        def stop_at(step: str) -> None:
                            if step == target:
                                os.write(write_fd, b"ready")
                                signal.pause()

                        child_locks = LockedFileRegistry(factory)
                        child_objects = ObjectRepository(factory, child_locks)
                        child_repository = TaskRepository._for_maintenance(
                            factory, child_locks, child_objects, fault_hook=stop_at,
                        )
                        child_repository.commit(batch("transaction-kill", lease))
                    except BaseException:
                        os.write(write_fd, b"error")
                        os._exit(3)
                    os._exit(2)
                os.close(write_fd)
                child_message = os.read(read_fd, 16)
                os.close(read_fd)
                if child_message != b"ready":
                    os.waitpid(child, 0)
                    self.fail(f"child crash harness failed before target: {child_message!r}")
                os.kill(child, signal.SIGKILL)
                _, child_status = os.waitpid(child, 0)
                self.assertTrue(os.WIFSIGNALED(child_status))
                recovered = repository.recover("transaction-kill")
                self.assertEqual(recovered is not None, committed)
                if committed:
                    self.assertEqual(repository.load("task-1")["revision"], 1)
                else:
                    with self.assertRaises(RepositoryConflictError):
                        repository.load("task-1")


if __name__ == "__main__":
    unittest.main()
