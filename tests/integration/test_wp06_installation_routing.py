from __future__ import annotations

import json
import dataclasses
import os
import pathlib
import sys
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage", "application", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.migration import (  # noqa: E402
    InstallationMigrationRepository,
    MigrationRepositoryError,
)
from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.core.migration import ActiveRepositoryManifest  # noqa: E402
from graph_engineering.storage.connection import RepositoryConfigurationError  # noqa: E402
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from graph_engineering.storage.objects import ObjectRepository  # noqa: E402
from graph_engineering.storage.repository import TaskRepository  # noqa: E402
from graph_engineering.application.actions import ActionCoordinator  # noqa: E402
from graph_engineering.adapters.fake_actions import DeterministicFakeTarget  # noqa: E402
from tests.support.wp05_actions import (  # noqa: E402
    action_stack,
    authority_document,
    disclosure_plan,
    prepared_document,
)
from tests.conformance.test_wp03_repository import batch  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class WP06InstallationRoutingTests(unittest.TestCase):
    def _policy(self) -> dict[str, object]:
        return json.loads((ROOT / "config" / "contracts" / "migration-storage-policy-v1.json").read_text())

    @staticmethod
    def _seed(objects, repository, leases) -> None:
        lease = leases.acquire_many(
            lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
            resources=("task:task-1",), ttl_ns=100,
        )
        body = b"wp06-routing-object"
        value = objects.digest(body)
        objects.put_verified(body, value)
        repository.commit(batch("transaction-1", lease, object_digests=(value,)))
        leases.release(lease.lease_id)

    def test_gew_mig_027_command_scope_routes_exact_active_repository_locator(self) -> None:
        with repository_stack() as (source_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-routing-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(),
                )
                with migration.command_scope() as context:
                    self.assertEqual(context.repository_id, factory.repository_id)
                    self.assertEqual(context.repository_root, source_root.resolve())
                    self.assertEqual((context.generation, context.activation_epoch), (1, 1))
                    context.require_current()
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                active = migration.activate(
                    imported, release_id="release-candidate", contract_id="repository-contract-1",
                )
                with migration.command_scope() as context:
                    self.assertEqual(context.repository_id, active.repository_id)
                    self.assertEqual(context.repository_root, imported.root.resolve())
                    self.assertEqual(
                        (context.installation_id, context.generation, context.activation_epoch),
                        (active.installation_id, active.generation, active.activation_epoch),
                    )
                    context.require_current()
                imported.close()

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process concurrency harness required")
    def test_gew_mig_028_control_shared_command_blocks_switch_then_routes_new(self) -> None:
        with repository_stack() as (_source_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-routing-race-") as directory:
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
                ready_read, ready_write = os.pipe()
                release_read, release_write = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(ready_read)
                    os.close(release_write)
                    try:
                        child_locks = LockedFileRegistry(factory)
                        child_objects = ObjectRepository(factory, child_locks)
                        child_migration = InstallationMigrationRepository.initialize(
                            factory, child_locks, child_objects, control_root=parent / "control",
                            policy_document=policy,
                        )
                        with child_migration.command_scope() as context:
                            if context.repository_id != factory.repository_id:
                                raise RuntimeError("child routed unexpected repository")
                            os.write(ready_write, b"H")
                            os.read(release_read, 1)
                            context.require_current()
                    except BaseException:
                        os.write(ready_write, b"E")
                        os._exit(3)
                    os._exit(0)
                os.close(ready_write)
                os.close(release_read)
                self.assertEqual(os.read(ready_read, 1), b"H")
                with self.assertRaisesRegex(MigrationRepositoryError, "control lock"):
                    migration.activate(
                        imported,
                        release_id="release-candidate",
                        contract_id="repository-contract-1",
                    )
                os.write(release_write, b"R")
                os.close(release_write)
                os.close(ready_read)
                _pid, status = os.waitpid(child, 0)
                self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
                migration.activate(
                    imported,
                    release_id="release-candidate",
                    contract_id="repository-contract-1",
                )
                with migration.command_scope() as context:
                    self.assertEqual(context.repository_id, "repository-candidate")
                imported.close()

    def test_gew_mig_029_stale_released_or_forged_scope_rejects_connection_and_commit(self) -> None:
        with repository_stack() as (_source_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with factory.open("doctor") as connection:
                revision, head_digest = connection.execute(
                    "SELECT revision,head_digest FROM tasks WHERE task_id='task-1'"
                ).fetchone()
            lease = leases.acquire_many(
                lease_id="command-lease", task_id="task-1", run_id="run-2",
                operation_id="write", resources=("task:task-1",), ttl_ns=100,
            )
            with tempfile.TemporaryDirectory(prefix="gew-wp06-stale-scope-") as directory:
                parent = pathlib.Path(directory)
                policy = self._policy()
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                active_path = parent / "control" / policy["active_manifest_filename"]
                original_body = active_path.read_bytes()
                with migration.command_scope() as scope:
                    bound_factory = factory.bind_command_scope(scope)
                    bound_repository = TaskRepository(
                        factory, locks, objects, command_scope=scope,
                    )
                    with bound_factory.open("doctor") as connection:
                        self.assertEqual(connection.execute("SELECT 1").fetchone(), (1,))
                    current = migration._current_manifest()
                    stale_successor = ActiveRepositoryManifest.create(
                        installation_id=current.installation_id,
                        generation=current.generation + 1,
                        activation_epoch=current.activation_epoch + 1,
                        repository_id=current.repository_id,
                        repository_digest=current.repository_digest,
                        repository_locator_ref=current.repository_locator_ref,
                        repository_locator_digest=current.repository_locator_digest,
                        release_id=current.release_id,
                        contract_id=current.contract_id,
                        mode="active",
                        previous_manifest_digest=current.manifest_digest,
                        fencing_high_water=current.fencing_high_water,
                        restore_gap_digest=None,
                    )
                    successor_body = dataclasses.asdict(stale_successor)
                    successor_body["fencing_high_water"] = [
                        list(item) for item in stale_successor.fencing_high_water
                    ]
                    active_path.write_bytes(canonical_bytes(successor_body))
                    with factory.open("doctor") as connection:
                        counts_before = connection.execute(
                            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM transactions)"
                        ).fetchone()
                    with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                        bound_factory.open("doctor")
                    with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                        bound_repository.commit(batch(
                            "transaction-stale", lease, revision=revision,
                            previous_digest=head_digest, event_type="task.updated",
                        ))
                    with factory.open("doctor") as connection:
                        self.assertEqual(connection.execute(
                            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM transactions)"
                        ).fetchone(), counts_before)
                active_path.write_bytes(original_body)
                with self.assertRaisesRegex(MigrationRepositoryError, "closed"):
                    bound_factory.open("doctor")
                with self.assertRaises(RepositoryConfigurationError):
                    factory.bind_command_scope(object())
            leases.release(lease.lease_id)

    def test_gew_mig_030_one_descriptor_registry_allows_two_thread_shared_scopes(self) -> None:
        with repository_stack() as (_source_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-shared-registry-") as directory:
                parent = pathlib.Path(directory)
                policy = self._policy()
                first = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                second = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=policy,
                )
                self.assertEqual(
                    first._control_lock.inode_identity,
                    second._control_lock.inode_identity,
                )
                self.assertIs(first._control_lock._entry, second._control_lock._entry)
                entered = threading.Barrier(3)
                release = threading.Event()
                results: list[str] = []

                def read(manager: InstallationMigrationRepository) -> None:
                    try:
                        with manager.command_scope() as scope:
                            results.append(scope.repository_id)
                            entered.wait(timeout=5)
                            release.wait(timeout=5)
                            scope.require_current()
                    except BaseException as error:
                        results.append(type(error).__name__)

                threads = (
                    threading.Thread(target=read, args=(first,)),
                    threading.Thread(target=read, args=(second,)),
                )
                for thread in threads:
                    thread.start()
                entered.wait(timeout=5)
                with self.assertRaisesRegex(MigrationRepositoryError, "held"):
                    second.close()
                release.set()
                for thread in threads:
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(results, [factory.repository_id, factory.repository_id])
                second.close()
                with first.command_scope() as scope:
                    self.assertEqual(scope.repository_id, factory.repository_id)
                scope = first.command_scope()
                scope.__enter__()
                connection = factory.bind_command_scope(scope).open("doctor")
                with self.assertRaisesRegex(MigrationRepositoryError, "open connections"):
                    scope.__exit__(None, None, None)
                connection.close()
                scope.__exit__(None, None, None)
                first.close()

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork harness required")
    def test_gew_mig_031_fork_child_cannot_use_inherited_command_scope(self) -> None:
        with repository_stack() as (_source_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-fork-scope-") as directory:
                parent = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=parent / "control",
                    policy_document=self._policy(),
                )
                with migration.command_scope() as scope:
                    read_fd, write_fd = os.pipe()
                    child = os.fork()
                    if child == 0:
                        os.close(read_fd)
                        try:
                            scope.require_current()
                        except MigrationRepositoryError:
                            os.write(write_fd, b"R")
                            os._exit(0)
                        os.write(write_fd, b"E")
                        os._exit(3)
                    os.close(write_fd)
                    self.assertEqual(os.read(read_fd, 1), b"R")
                    os.close(read_fd)
                    _pid, status = os.waitpid(child, 0)
                    self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
                    scope.require_current()

    def test_gew_mig_032_action_requires_same_live_scope_and_stale_is_zero_call(self) -> None:
        with action_stack() as fixture:
            with self.assertRaisesRegex(ValueError, "scope"):
                ActionCoordinator(
                    journal=fixture.raw_coordinator._journal,
                    repository=fixture.repository,
                    leases=fixture.leases,
                    locks=fixture.locks,
                    objects=fixture.objects,
                    security_issuer=fixture.issuer,
                    action_policy=fixture.raw_coordinator._policy,
                    installation_scope=object(),
                )
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            plan = disclosure_plan(fixture, prepared)
            target = DeterministicFakeTarget(
                target_id="target-project",
                target_digest=prepared.target_digest,
                resource_id="target:project",
                initial_state={"version": 1},
            )
            scope = fixture.repository.command_scope
            manager = scope._manager
            active_path = manager._control / manager._policy.active_manifest_filename
            original_body = active_path.read_bytes()
            current = manager._current_manifest()
            stale_successor = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=current.generation + 1,
                activation_epoch=current.activation_epoch + 1,
                repository_id=current.repository_id,
                repository_digest=current.repository_digest,
                repository_locator_ref=current.repository_locator_ref,
                repository_locator_digest=current.repository_locator_digest,
                release_id=current.release_id,
                contract_id=current.contract_id,
                mode="active",
                previous_manifest_digest=current.manifest_digest,
                fencing_high_water=current.fencing_high_water,
                restore_gap_digest=None,
            )
            successor_body = dataclasses.asdict(stale_successor)
            successor_body["fencing_high_water"] = [
                list(item) for item in stale_successor.fencing_high_water
            ]
            with manager._factory.open("doctor") as connection:
                before = connection.execute(
                    "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM transactions)"
                ).fetchone()
            try:
                active_path.write_bytes(canonical_bytes(successor_body))
                with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                    fixture.raw_coordinator.execute(
                        prepared.action_id,
                        owner_id="owner-wp05",
                        runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05",
                        lease=fixture.action_lease,
                        target=target,
                        observer=target.observer_port(),
                        disclosure_plan=plan,
                    )
                with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                    fixture.raw_coordinator._journal.record_prepared(prepared)
                self.assertEqual(target.call_count, 0)
                with manager._factory.open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM transactions)"
                    ).fetchone(), before)
            finally:
                active_path.write_bytes(original_body)

    def test_gew_mig_033_raw_or_stale_factory_lease_and_object_mutations_are_zero_write(self) -> None:
        with repository_stack() as (_source_root, factory, locks, objects, repository, leases):
            with self.assertRaisesRegex(RepositoryConfigurationError, "command scope"):
                factory.open("application")
            manager = repository.command_scope._manager
            active_path = manager._control / manager._policy.active_manifest_filename
            original_body = active_path.read_bytes()
            current = manager._current_manifest()
            successor = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=current.generation + 1,
                activation_epoch=current.activation_epoch + 1,
                repository_id=current.repository_id,
                repository_digest=current.repository_digest,
                repository_locator_ref=current.repository_locator_ref,
                repository_locator_digest=current.repository_locator_digest,
                release_id=current.release_id,
                contract_id=current.contract_id,
                mode="active",
                previous_manifest_digest=current.manifest_digest,
                fencing_high_water=current.fencing_high_water,
                restore_gap_digest=None,
            )
            successor_body = dataclasses.asdict(successor)
            successor_body["fencing_high_water"] = [list(item) for item in successor.fencing_high_water]
            body = b"stale-object-must-not-publish"
            value = objects.digest(body)
            with factory.open("doctor") as connection:
                before = connection.execute(
                    "SELECT (SELECT COUNT(*) FROM objects),(SELECT COUNT(*) FROM leases),"
                    "(SELECT COUNT(*) FROM resource_fences)"
                ).fetchone()
            try:
                active_path.write_bytes(canonical_bytes(successor_body))
                with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                    objects.put_verified(body, value)
                with self.assertRaisesRegex(MigrationRepositoryError, "stale"):
                    leases.acquire_many(
                        lease_id="stale-lease", task_id="task-stale", run_id="run-stale",
                        operation_id="write", resources=("task:task-stale",), ttl_ns=100,
                    )
                self.assertFalse(objects._path(value).exists())
                with factory.open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT (SELECT COUNT(*) FROM objects),(SELECT COUNT(*) FROM leases),"
                        "(SELECT COUNT(*) FROM resource_fences)"
                    ).fetchone(), before)
            finally:
                active_path.write_bytes(original_body)


if __name__ == "__main__":
    unittest.main()
