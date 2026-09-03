from __future__ import annotations

import pathlib
import sys
import threading
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.connection import BoundDirectory  # noqa: E402
from graph_engineering.storage.errors import (  # noqa: E402
    LockUnavailableError,
    ObjectIntegrityError,
    RepositoryConfigurationError,
)
from graph_engineering.storage.ports import CommitBatch, LeaseGrant  # noqa: E402
from graph_engineering.storage.objects import ObjectRepository  # noqa: E402
from graph_engineering.storage.repository import make_event  # noqa: E402
from tests.support.wp03_repository import command_scope_for_test, repository_stack  # noqa: E402


def reference_batch(digest: str, lease: LeaseGrant) -> CommitBatch:
    event = make_event(
        task_id="task-objects", sequence=1, event_id="event-objects", event_type="task.created",
        occurred_at="t-1", actor={"id": "runtime-1"}, expected_task_revision=0,
        baseline_digests=[], payload={}, previous_event_digest=None,
    )
    return CommitBatch(
        "transaction-objects", "task-objects", 0, (event,),
        {"task_id": "task-objects", "revision": 1}, {"owner": "owner-1"},
        {
            "lease_id": lease.lease_id,
            "resource_id": "task:task-objects",
            "fencing_token": dict(lease.fencing_tokens)["task:task-objects"],
        },
        (digest,),
    )


class ObjectRepositoryConformanceTests(unittest.TestCase):
    def test_verified_publication_deduplicates_and_rejects_digest_or_symlink_tamper(self) -> None:
        with repository_stack() as (_root, factory, _locks, objects, _repository, _leases):
            body = b"verified-object"
            digest = objects.digest(body)
            with self.assertRaises(ObjectIntegrityError):
                objects.put_verified(body + b"x", digest)
            objects.put_verified(body, digest)
            objects.put_verified(body, digest)
            self.assertEqual(objects.get(digest, require_referenced=False), body)
            path = objects._path(digest)
            path.unlink()
            path.symlink_to(factory.data_root / factory.policy.database_filename)
            with self.assertRaises(ObjectIntegrityError):
                objects.get(digest, require_referenced=False)

    def test_fanout_symlink_is_rejected_before_external_or_staging_mutation(self) -> None:
        with repository_stack() as (root, factory, _locks, objects, _repository, _leases):
            body = b"fanout-symlink-probe"
            digest = objects.digest(body)
            fanout = objects._path(digest).parent
            external = root.parent / "external-fanout"
            external.mkdir(mode=0o755)
            fanout.symlink_to(external, target_is_directory=True)
            staging = root / factory.policy.staging_directory
            with self.assertRaises(ObjectIntegrityError):
                objects.put_verified(body, digest)
            self.assertEqual(external.stat().st_mode & 0o777, 0o755)
            self.assertEqual(tuple(staging.iterdir()), ())

    def test_post_initialization_objects_and_staging_replacement_have_zero_external_effect(self) -> None:
        for component in ("objects", "staging"):
            fault_steps: list[str] = []
            with self.subTest(component=component), repository_stack(
                object_fault=fault_steps.append,
            ) as (root, factory, _locks, objects, _repository, _leases):
                body = f"replaced-{component}".encode()
                digest = objects.digest(body)
                path = root / getattr(factory.policy, f"{component}_directory")
                original = root / f"{component}-attested-original"
                path.rename(original)
                external = root.parent / f"external-{component}"
                external.mkdir(mode=factory.policy.root_mode)
                path.symlink_to(external, target_is_directory=True)
                before_mode = external.stat().st_mode & 0o777
                with self.assertRaises(RepositoryConfigurationError):
                    objects.put_verified(body, digest)
                self.assertEqual(tuple(external.iterdir()), ())
                self.assertEqual(external.stat().st_mode & 0o777, before_mode)
                self.assertEqual(fault_steps, [])

    def test_concurrent_staging_and_final_replacement_cannot_publish_wrong_bytes(self) -> None:
        cases = (
            ("object.after_staging_directory_fsync", b"tampered-staging"),
            ("object.after_publication", b"tampered-final"),
            ("object.after_object_directory_fsync", b"tampered-pre-transaction"),
            ("object.before_metadata_commit", b"tampered-transaction-window"),
        )
        for target_step, tampered in cases:
            ready = threading.Event()
            changed = threading.Event()
            errors: list[BaseException] = []

            def fault(step: str) -> None:
                if step == target_step:
                    ready.set()
                    if not changed.wait(timeout=2):
                        raise RuntimeError("replacement thread did not complete")

            with self.subTest(target_step=target_step), repository_stack(
                object_fault=fault,
            ) as (root, factory, _locks, objects, _repository, _leases):
                body = f"approved-{target_step}".encode()
                digest = objects.digest(body)

                def replace_name() -> None:
                    try:
                        if not ready.wait(timeout=2):
                            raise RuntimeError("publication did not reach replacement barrier")
                        if target_step == "object.after_staging_directory_fsync":
                            staging = root / factory.policy.staging_directory
                            names = tuple(staging.iterdir())
                            if len(names) != 1:
                                raise RuntimeError("staging entry is not unique")
                            path = names[0]
                        else:
                            path = objects._path(digest)
                        path.unlink()
                        path.write_bytes(tampered)
                        path.chmod(factory.policy.file_mode)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        changed.set()

                thread = threading.Thread(target=replace_name)
                thread.start()
                with self.assertRaises(ObjectIntegrityError):
                    objects.put_verified(body, digest)
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertFalse(objects._path(digest).exists())
                self.assertEqual(
                    tuple((root / factory.policy.staging_directory).iterdir()),
                    (),
                )
                with factory._for_maintenance().open("application") as connection:
                    self.assertIsNone(connection.execute(
                        "SELECT state FROM objects WHERE digest=?", (digest,),
                    ).fetchone())

    def test_deduplicated_replacement_quarantines_preexisting_metadata(self) -> None:
        for target_step in (
            "object.after_object_directory_fsync",
            "object.before_metadata_commit",
        ):
            ready = threading.Event()
            changed = threading.Event()
            armed = False
            errors: list[BaseException] = []

            def fault(step: str) -> None:
                if armed and step == target_step:
                    ready.set()
                    if not changed.wait(timeout=2):
                        raise RuntimeError("dedup replacement thread did not complete")

            with self.subTest(target_step=target_step), repository_stack(
                object_fault=fault,
            ) as (root, factory, _locks, objects, _repository, _leases):
                body = f"deduplicated-{target_step}".encode()
                digest = objects.digest(body)
                objects.put_verified(body, digest)
                with factory._for_maintenance().open("application") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT state FROM objects WHERE digest=?", (digest,),
                    ).fetchone()[0], "available")

                def replace_final() -> None:
                    try:
                        if not ready.wait(timeout=2):
                            raise RuntimeError("dedup publication did not reach barrier")
                        path = objects._path(digest)
                        path.unlink()
                        path.write_bytes(b"tampered-deduplicated-final")
                        path.chmod(factory.policy.file_mode)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        changed.set()

                thread = threading.Thread(target=replace_final)
                thread.start()
                armed = True
                with self.assertRaises(ObjectIntegrityError):
                    objects.put_verified(body, digest)
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertFalse(objects._path(digest).exists())
                self.assertEqual(
                    tuple((root / factory.policy.staging_directory).iterdir()),
                    (),
                )
                with factory._for_maintenance().open("application") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT state FROM objects WHERE digest=?", (digest,),
                    ).fetchone()[0], "quarantined")

    def test_stale_cleanup_is_serialized_before_a_later_verified_writer(self) -> None:
        for target_step in (
            "object.after_object_directory_fsync",
            "object.before_metadata_commit",
        ):
            replace_ready = threading.Event()
            replaced = threading.Event()
            cleanup_ready = threading.Event()
            allow_cleanup = threading.Event()
            writer_b_blocked = threading.Event()
            writer_b_complete = threading.Event()
            writer_a_errors: list[BaseException] = []
            writer_b_errors: list[BaseException] = []

            def fault(step: str) -> None:
                if threading.current_thread().name == "writer-a" and step == target_step:
                    replace_ready.set()
                    if not replaced.wait(timeout=2):
                        raise RuntimeError("replacement thread did not complete")

            with self.subTest(target_step=target_step), repository_stack(
                object_fault=fault,
            ) as (root, factory, _locks, objects, _repository, _leases):
                body = f"cleanup-isolation-{target_step}".encode()
                digest = objects.digest(body)
                filename = objects._path(digest).name
                original_unlink = BoundDirectory.unlink
                cleanup_delayed = False

                def delayed_unlink(directory: BoundDirectory, name: str) -> None:
                    nonlocal cleanup_delayed
                    if (
                        threading.current_thread().name == "writer-a"
                        and name == filename
                        and not cleanup_delayed
                    ):
                        cleanup_delayed = True
                        cleanup_ready.set()
                        if not allow_cleanup.wait(timeout=2):
                            raise RuntimeError("cleanup release did not arrive")
                    original_unlink(directory, name)

                def replace_final() -> None:
                    if not replace_ready.wait(timeout=2):
                        writer_a_errors.append(RuntimeError("replacement barrier was not reached"))
                        replaced.set()
                        return
                    path = objects._path(digest)
                    path.unlink()
                    path.write_bytes(b"invalid-concurrent-final")
                    path.chmod(factory.policy.file_mode)
                    replaced.set()

                def writer_a() -> None:
                    try:
                        with command_scope_for_test(factory, _locks, objects) as scope:
                            local_objects = ObjectRepository(
                                factory.bind_command_scope(scope), _locks,
                                fault_hook=objects._fault,
                            )
                            try:
                                local_objects.put_verified(body, digest)
                            finally:
                                local_objects.close()
                    except BaseException as error:
                        writer_a_errors.append(error)

                def writer_b() -> None:
                    try:
                        with command_scope_for_test(factory, _locks, objects) as scope:
                            local_objects = ObjectRepository(
                                factory.bind_command_scope(scope), _locks,
                                fault_hook=objects._fault,
                            )
                            try:
                                while True:
                                    try:
                                        local_objects.put_verified(body, digest)
                                        writer_b_complete.set()
                                        return
                                    except LockUnavailableError:
                                        writer_b_blocked.set()
                                        time.sleep(0.001)
                            finally:
                                local_objects.close()
                    except BaseException as error:
                        writer_b_errors.append(error)

                replacement = threading.Thread(target=replace_final, name="replacer")
                first_writer = threading.Thread(target=writer_a, name="writer-a")
                second_writer = threading.Thread(target=writer_b, name="writer-b")
                with mock.patch.object(BoundDirectory, "unlink", new=delayed_unlink):
                    replacement.start()
                    first_writer.start()
                    self.assertTrue(cleanup_ready.wait(timeout=2))
                    second_writer.start()
                    self.assertTrue(writer_b_blocked.wait(timeout=2))
                    self.assertFalse(writer_b_complete.is_set())
                    allow_cleanup.set()
                    replacement.join(timeout=2)
                    first_writer.join(timeout=2)
                    second_writer.join(timeout=2)
                self.assertFalse(replacement.is_alive())
                self.assertFalse(first_writer.is_alive())
                self.assertFalse(second_writer.is_alive())
                self.assertEqual(len(writer_a_errors), 1)
                self.assertIsInstance(writer_a_errors[0], ObjectIntegrityError)
                self.assertEqual(writer_b_errors, [])
                self.assertTrue(writer_b_complete.is_set())
                self.assertEqual(objects.get(digest, require_referenced=False), body)
                self.assertEqual(
                    tuple((root / factory.policy.staging_directory).iterdir()),
                    (),
                )
                with factory._for_maintenance().open("application") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT size,state FROM objects WHERE digest=?", (digest,),
                    ).fetchone(), (len(body), "available"))

    def test_publication_composes_with_held_call_span_resources(self) -> None:
        resource_sets = (
            ("000-before-publication", "task:task-1"),
            ("task:task-1", "zzz-after-publication"),
        )
        for resources in resource_sets:
            with self.subTest(resources=resources), repository_stack() as (
                _root, _factory, locks, objects, _repository, _leases,
            ):
                body = ("receipt:" + ",".join(resources)).encode()
                digest = objects.digest(body)
                installation = locks.acquire_installation("shared")
                call_span = locks.acquire_resources(resources)
                try:
                    objects.put_verified(body, digest)
                    self.assertTrue(locks.installation_held_by_current_thread())
                finally:
                    locks.release(call_span)
                    locks.release(installation)
                self.assertEqual(objects.get(digest, require_referenced=False), body)

    def test_purge_only_deletes_unreferenced_unheld_objects_and_recovers_deleting(self) -> None:
        with repository_stack() as (_root, factory, _locks, objects, repository, leases):
            orphan = objects.digest(b"orphan")
            objects.put_verified(b"orphan", orphan)
            self.assertTrue(objects.purge(orphan))
            with self.assertRaises(ObjectIntegrityError):
                objects.get(orphan, require_referenced=False)

            referenced = objects.digest(b"referenced")
            objects.put_verified(b"referenced", referenced)
            task_lease = leases.acquire_many(
                lease_id="task-lease", task_id="task-objects", run_id="run-1",
                operation_id="write", resources=("task:task-objects",),
                ttl_ns=100,
            )
            repository.commit(reference_batch(referenced, task_lease))
            self.assertFalse(objects.purge(referenced))
            self.assertEqual(objects.get(referenced), b"referenced")

            held = objects.digest(b"held")
            objects.put_verified(b"held", held)
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO export_holds(export_id,digest,snapshot_digest) VALUES(?,?,?)",
                        ("export-1", held, "sha256-jcs-v1:" + "1" * 64),
                    )
            self.assertFalse(objects.purge(held))

        injected = False

        def fault(step: str) -> None:
            nonlocal injected
            if step == "purge.after_deleting_commit" and not injected:
                injected = True
                raise RuntimeError("crash-after-deleting")

        with repository_stack(object_fault=fault) as (
            _root, _factory, _locks, objects, _repository, _leases,
        ):
            digest = objects.digest(b"recover")
            objects.put_verified(b"recover", digest)
            with self.assertRaisesRegex(RuntimeError, "crash-after"):
                objects.purge(digest)
            self.assertEqual(objects.recover_deleting(), (digest,))

    def test_quarantine_is_not_readable_or_purge_eligible(self) -> None:
        with repository_stack() as (_root, _factory, _locks, objects, _repository, _leases):
            digest = objects.digest(b"quarantine")
            objects.put_verified(b"quarantine", digest)
            objects.quarantine(digest)
            with self.assertRaises(ObjectIntegrityError):
                objects.get(digest, require_referenced=False)
            self.assertFalse(objects.purge(digest))

    def test_recovery_removes_crash_left_staging_and_physical_orphans(self) -> None:
        staging_injected = False

        def staging_fault(step: str) -> None:
            nonlocal staging_injected
            if step == "object.after_file_fsync" and not staging_injected:
                staging_injected = True
                raise RuntimeError("crash-with-staging")

        with repository_stack(object_fault=staging_fault) as (
            _root, _factory, _locks, objects, _repository, _leases,
        ):
            digest = objects.digest(b"staging")
            with self.assertRaisesRegex(RuntimeError, "staging"):
                objects.put_verified(b"staging", digest)
            removed = objects.recover_untrusted()
            self.assertEqual(len(removed), 1)
            self.assertTrue(removed[0].startswith("staging:"))

        orphan_injected = False

        def orphan_fault(step: str) -> None:
            nonlocal orphan_injected
            if step == "object.after_publication" and not orphan_injected:
                orphan_injected = True
                raise RuntimeError("crash-with-orphan")

        with repository_stack(object_fault=orphan_fault) as (
            _root, _factory, _locks, objects, _repository, _leases,
        ):
            digest = objects.digest(b"orphan-file")
            with self.assertRaisesRegex(RuntimeError, "orphan"):
                objects.put_verified(b"orphan-file", digest)
            self.assertEqual(objects.recover_untrusted(), (digest,))


if __name__ == "__main__":
    unittest.main()
