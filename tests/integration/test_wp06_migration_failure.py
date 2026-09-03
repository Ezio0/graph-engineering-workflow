from __future__ import annotations

import json
import os
import pathlib
import signal
import sys
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.migration import (  # noqa: E402
    ImportedRepository,
    InstallationMigrationRepository,
    MigrationRepositoryError,
)
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from graph_engineering.storage.objects import ObjectRepository  # noqa: E402
from graph_engineering.storage.repository import TaskRepository  # noqa: E402
from tests.conformance.test_wp03_repository import batch  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class WP06MigrationFailureTests(unittest.TestCase):
    def _policy(self) -> dict[str, object]:
        return json.loads((ROOT / "config" / "contracts" / "migration-storage-policy-v1.json").read_text())

    def _seed(self, objects, repository, leases) -> None:
        lease = leases.acquire_many(
            lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
            resources=("task:task-1",), ttl_ns=100,
        )
        body = b"wp06-failure-object"
        value = objects.digest(body)
        objects.put_verified(body, value)
        repository.commit(batch("transaction-1", lease, object_digests=(value,)))
        leases.release(lease.lease_id)

    def test_gew_mig_017_fault_schedule_is_exact_sorted_and_executable(self) -> None:
        schedule = json.loads((ROOT / "config" / "contracts" / "migration-fault-schedule-v1.json").read_text())
        points = schedule["points"]
        self.assertEqual(points, sorted(set(points)))
        observed: list[str] = []
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-fault-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(), fault_hook=observed.append,
                )
                migration.export_bundle(parent / "bundle", export_id="export-1")
        self.assertEqual(
            [point for point in points if point.startswith("export.")],
            [point for point in points if point in observed],
        )

    def test_gew_mig_018_interrupted_export_hold_requires_explicit_recovery(self) -> None:
        def fail(point: str) -> None:
            if point == "export.after_hold":
                raise RuntimeError("injected-export-interruption")

        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-fault-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(), fault_hook=fail,
                )
                with self.assertRaisesRegex(RuntimeError, "injected-export"):
                    migration.export_bundle(parent / "bundle", export_id="export-1")
                with factory.open("doctor") as connection:
                    self.assertGreater(connection.execute(
                        "SELECT COUNT(*) FROM export_holds WHERE export_id='export-1'"
                    ).fetchone()[0], 0)
                migration.recover_export("export-1", parent / "bundle")
                with factory.open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM export_holds WHERE export_id='export-1'"
                    ).fetchone()[0], 0)

    def test_gew_mig_019_concurrent_public_exports_do_not_reenter_or_partial_publish(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-fault-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(),
                )
                outcomes: list[str] = []

                def run(index: int) -> None:
                    try:
                        migration.export_bundle(parent / f"bundle-{index}", export_id=f"export-{index}")
                        outcomes.append("PASS")
                    except MigrationRepositoryError:
                        outcomes.append("BLOCKED")

                threads = (threading.Thread(target=run, args=(1,)), threading.Thread(target=run, args=(2,)))
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertEqual(len(outcomes), 2)
                self.assertIn("PASS", outcomes)
                self.assertTrue(all(item in {"PASS", "BLOCKED"} for item in outcomes))

    def _assert_activation_sigkill_recovery(
        self,
        fault_point: str,
        *,
        expected_repository_id: str,
        expected_generation: int,
    ) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-activation-crash-") as directory:
                parent = pathlib.Path(directory)
                policy = self._policy()
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                read_fd, write_fd = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    try:
                        def stop_at(point: str) -> None:
                            if point == fault_point:
                                os.write(write_fd, b"ready")
                                signal.pause()

                        source_locks = LockedFileRegistry(factory)
                        source_objects = ObjectRepository(factory, source_locks)
                        candidate_locks = LockedFileRegistry(imported.factory)
                        candidate_objects = ObjectRepository(imported.factory, candidate_locks)
                        candidate_repository = TaskRepository._for_maintenance(
                            imported.factory, candidate_locks, candidate_objects,
                        )
                        child_imported = ImportedRepository(
                            imported.root,
                            imported.factory,
                            candidate_locks,
                            candidate_objects,
                            candidate_repository,
                            imported.bundle_digest,
                            imported.repository_digest,
                            imported.source_manifest_digest,
                            imported.source_repository_digest,
                            imported.bundle_root,
                            imported.candidate_records_digest,
                        )
                        child_migration = InstallationMigrationRepository.initialize(
                            factory,
                            source_locks,
                            source_objects,
                            control_root=parent / "control",
                            policy_document=policy,
                            fault_hook=stop_at,
                        )
                        child_migration.activate(
                            child_imported,
                            release_id="release-candidate",
                            contract_id="repository-contract-1",
                        )
                    except BaseException:
                        os.write(write_fd, b"error")
                        os._exit(3)
                    os._exit(2)
                os.close(write_fd)
                child_message = os.read(read_fd, 16)
                os.close(read_fd)
                if child_message != b"ready":
                    os.waitpid(child, 0)
                    self.fail(f"activation crash harness failed: {child_message!r}")
                os.kill(child, signal.SIGKILL)
                _, child_status = os.waitpid(child, 0)
                self.assertTrue(os.WIFSIGNALED(child_status))
                recovered = migration.recover_activation()
                self.assertEqual(recovered.mode, "active")
                self.assertEqual(recovered.repository_id, expected_repository_id)
                self.assertEqual(recovered.generation, expected_generation)
                imported.close()

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_gew_mig_020_sigkill_before_verifying_preserves_old_active(self) -> None:
        self._assert_activation_sigkill_recovery(
            "activation.before_verifying_manifest",
            expected_repository_id="repository-test-v1",
            expected_generation=1,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_gew_mig_021_sigkill_after_verifying_rolls_back_to_old_active(self) -> None:
        self._assert_activation_sigkill_recovery(
            "activation.after_verifying_manifest",
            expected_repository_id="repository-test-v1",
            expected_generation=3,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_gew_mig_022_sigkill_before_active_rolls_back_to_old_active(self) -> None:
        self._assert_activation_sigkill_recovery(
            "activation.before_active_manifest",
            expected_repository_id="repository-test-v1",
            expected_generation=3,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_gew_mig_023_sigkill_after_active_preserves_new_active(self) -> None:
        self._assert_activation_sigkill_recovery(
            "activation.after_active_manifest",
            expected_repository_id="repository-candidate",
            expected_generation=3,
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process concurrency harness required")
    def test_gew_mig_024_two_process_activation_has_one_authority(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-activation-race-") as directory:
                parent = pathlib.Path(directory)
                policy = self._policy()
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                children: list[tuple[int, int, int]] = []
                for _index in range(2):
                    ready_read, ready_write = os.pipe()
                    go_read, go_write = os.pipe()
                    result_read, result_write = os.pipe()
                    child = os.fork()
                    if child == 0:
                        os.close(ready_read)
                        os.close(go_write)
                        os.close(result_read)
                        try:
                            def hold_at_switch(point: str) -> None:
                                if point == "activation.before_verifying_manifest":
                                    os.write(result_write, b"H")
                                    os.read(go_read, 1)

                            source_locks = LockedFileRegistry(factory)
                            source_objects = ObjectRepository(factory, source_locks)
                            candidate_locks = LockedFileRegistry(imported.factory)
                            candidate_objects = ObjectRepository(imported.factory, candidate_locks)
                            child_imported = ImportedRepository(
                                imported.root, imported.factory, candidate_locks, candidate_objects,
                                TaskRepository._for_maintenance(
                                    imported.factory, candidate_locks, candidate_objects,
                                ),
                                imported.bundle_digest, imported.repository_digest,
                                imported.source_manifest_digest, imported.source_repository_digest,
                                imported.bundle_root, imported.candidate_records_digest,
                            )
                            child_migration = InstallationMigrationRepository.initialize(
                                factory, source_locks, source_objects,
                                control_root=parent / "control", policy_document=policy,
                                fault_hook=hold_at_switch,
                            )
                            os.write(ready_write, b"R")
                            os.read(go_read, 1)
                            child_migration.activate(
                                child_imported,
                                release_id="release-candidate",
                                contract_id="repository-contract-1",
                            )
                            os.write(result_write, b"P")
                        except MigrationRepositoryError:
                            os.write(result_write, b"B")
                        except BaseException:
                            os.write(result_write, b"E")
                        os._exit(0)
                    os.close(ready_write)
                    os.close(go_read)
                    os.close(result_write)
                    self.assertEqual(os.read(ready_read, 1), b"R")
                    os.close(ready_read)
                    children.append((child, go_write, result_read))

                for _child, go_write, _result_read in children:
                    os.write(go_write, b"S")
                first = [os.read(result_read, 1) for _child, _go_write, result_read in children]
                self.assertEqual(sorted(first), [b"B", b"H"])
                winner = first.index(b"H")
                os.write(children[winner][1], b"C")
                self.assertEqual(os.read(children[winner][2], 1), b"P")
                for child, go_write, result_read in children:
                    os.close(go_write)
                    os.close(result_read)
                    _pid, status = os.waitpid(child, 0)
                    self.assertTrue(os.WIFEXITED(status))
                recovered = migration.recover_activation()
                self.assertEqual((recovered.mode, recovered.repository_id), ("active", "repository-candidate"))
                self.assertEqual(recovered.generation, 3)
                imported.close()

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process concurrency harness required")
    def test_gew_mig_025_command_shared_scope_cannot_cross_activation_switch(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-command-switch-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(),
                )
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                with factory.open("doctor") as connection:
                    revision, head_digest = connection.execute(
                        "SELECT revision,head_digest FROM tasks WHERE task_id='task-1'"
                    ).fetchone()
                lease = leases.acquire_many(
                    lease_id="command-lease", task_id="task-1", run_id="run-2",
                    operation_id="write", resources=("task:task-1",), ttl_ns=100,
                )
                ready_read, ready_write = os.pipe()
                release_read, release_write = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(ready_read)
                    os.close(release_write)
                    try:
                        child_locks = LockedFileRegistry(factory)
                        child_objects = ObjectRepository(factory, child_locks)
                        child_repository = TaskRepository._for_maintenance(
                            factory, child_locks, child_objects,
                        )
                        command_scope = child_locks.acquire_installation("shared")
                        child_repository.commit(batch(
                            "transaction-command",
                            lease,
                            revision=revision,
                            previous_digest=head_digest,
                            event_type="task.updated",
                        ))
                        os.write(ready_write, b"H")
                        os.read(release_read, 1)
                        child_locks.release(command_scope)
                    except BaseException:
                        os.write(ready_write, b"E")
                        os._exit(3)
                    os._exit(0)
                os.close(ready_write)
                os.close(release_read)
                self.assertEqual(os.read(ready_read, 1), b"H")
                with self.assertRaisesRegex(
                    MigrationRepositoryError, "activation lock|quiescence",
                ):
                    migration.activate(
                        imported,
                        release_id="release-candidate",
                        contract_id="repository-contract-1",
                    )
                active_document = json.loads(
                    (parent / "control" / self._policy()["active_manifest_filename"]).read_text()
                )
                self.assertEqual((active_document["generation"], active_document["mode"]), (1, "active"))
                os.write(release_write, b"R")
                os.close(release_write)
                os.close(ready_read)
                _pid, status = os.waitpid(child, 0)
                self.assertTrue(os.WIFEXITED(status))
                leases.release(lease.lease_id)
                with self.assertRaisesRegex(MigrationRepositoryError, "source repository changed"):
                    migration.activate(
                        imported,
                        release_id="release-candidate",
                        contract_id="repository-contract-1",
                    )
                active_document = json.loads(
                    (parent / "control" / self._policy()["active_manifest_filename"]).read_text()
                )
                self.assertEqual((active_document["generation"], active_document["mode"]), (1, "active"))
                imported.close()

    def test_gew_mig_026_corrupt_history_publishes_stable_explicit_blocked(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-blocked-recovery-") as directory:
                parent = pathlib.Path(directory)
                policy = self._policy()
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                history = parent / "control" / policy["manifest_history_directory"]
                corrupt = history / "00000000000000000002-corrupt.json"
                corrupt.write_text("{not-canonical", encoding="utf-8")
                os.chmod(corrupt, policy["file_mode"])
                blocked = migration.recover_activation()
                self.assertEqual((blocked.mode, blocked.generation), ("blocked", 2))
                self.assertFalse(blocked.ordinary_commands_allowed)
                self.assertEqual(migration.recover_activation().manifest_digest, blocked.manifest_digest)
                active_document = json.loads(
                    (parent / "control" / policy["active_manifest_filename"]).read_text()
                )
                self.assertEqual(active_document["manifest_digest"], blocked.manifest_digest)


if __name__ == "__main__":
    unittest.main()
