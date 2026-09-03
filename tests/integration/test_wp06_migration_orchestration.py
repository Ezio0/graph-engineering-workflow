from __future__ import annotations

import json
import os
import pathlib
import signal
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.migration import (  # noqa: E402
    InstallationMigrationRepository,
    MigrationRepositoryError,
)
from graph_engineering.storage.codec import canonical_json, semantic_record_digest  # noqa: E402
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from graph_engineering.storage.objects import ObjectRepository  # noqa: E402
from tests.conformance.test_wp03_repository import batch  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class WP06MigrationOrchestrationTests(unittest.TestCase):
    def _policy(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "config" / "contracts" / "migration-storage-policy-v1.json").read_text(),
        )

    @staticmethod
    def _seed(objects, repository, leases) -> None:
        lease = leases.acquire_many(
            lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
            resources=("task:task-1",), ttl_ns=100,
        )
        body = b"wp06-orchestrated-migration"
        digest = objects.digest(body)
        objects.put_verified(body, digest)
        repository.commit(batch("transaction-1", lease, object_digests=(digest,)))
        leases.release(lease.lease_id)

    @staticmethod
    def _authorize_gap_clear(factory, manager, gap, blocked):
        authority = "sha256-jcs-v1:" + "a" * 64
        with factory._for_maintenance().open("migration") as connection:
            with connection.transaction():
                task = connection.execute(
                    "SELECT revision,snapshot_digest FROM tasks WHERE task_id='task-1'",
                ).fetchone()
                security_state = {
                    "schema_version": "1.0.0", "task_id": "task-1",
                    "task_revision": task[0], "task_snapshot_digest": task[1],
                    "binding": {"task_id": "task-1", "snapshot_digest": task[1]},
                    "destinations": {}, "authority_digests": [authority], "data_refs": {},
                    "evidence_expectations": {}, "retention_subjects": {},
                }
                connection.execute(
                    "INSERT INTO task_security_states(task_id,task_revision,task_snapshot_digest,"
                    "state_json,state_digest) VALUES(?,?,?,?,?)",
                    (
                        "task-1", task[0], task[1], canonical_json(security_state),
                        semantic_record_digest({
                            "contract": "task-security-state-v1", "value": security_state,
                        }),
                    ),
                )
        unsigned = {
            "resource_id": "task:task-1", "target_id": "task-1",
            "target_state_digest": task[1], "observation_revision": task[0],
            "observed_at_ns": 1,
            "observer_binding_digest": semantic_record_digest({
                "kind": "repository-task-observer", "repository_id": blocked.repository_id,
                "task_id": "task-1", "blocked_manifest_digest": blocked.manifest_digest,
            }),
            "gap_digest": gap.gap_digest, "blocked_manifest_digest": blocked.manifest_digest,
        }
        return authority, dict(unsigned, observation_digest=semantic_record_digest(unsigned))

    def test_gew_mig_040_one_control_authority_spans_exact_durable_migration_graph(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-orchestration-") as directory:
                root = pathlib.Path(directory)
                blocked: list[str] = []
                contender = None

                def observe(point: str) -> None:
                    if contender is None:
                        return
                    with self.assertRaisesRegex(MigrationRepositoryError, "busy|reentrant|unavailable"):
                        contender.export_bundle(
                            root / f"contender-{len(blocked)}", export_id=f"blocked-{len(blocked)}",
                        )
                    blocked.append(point)

                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=root / "control",
                    policy_document=self._policy(), fault_hook=observe,
                )
                contender = InstallationMigrationRepository.attach_command_plane(
                    factory, locks, objects, control_root=root / "control",
                    policy_document=self._policy(),
                )
                completed = migration.migrate(
                    migration_id="migration-1", export_id="export-1",
                    bundle_destination=root / "bundle",
                    candidate_destination=root / "candidate",
                    candidate_repository_id="repository-candidate",
                    release_id="release-candidate", contract_id="repository-contract-1",
                )
                try:
                    states = [record["migration"]["state"] for record in completed.history]
                    self.assertEqual(states, [
                        "requested", "upgrade_locked", "quiescence_verified", "exported",
                        "imported_isolated", "replayed", "compatible", "activation_prepared",
                        "verifying_reference", "post_switch_verified", "active", "completed",
                    ])
                    self.assertEqual(
                        [record["migration"]["revision"] for record in completed.history],
                        list(range(1, 13)),
                    )
                    self.assertEqual(len({
                        tuple(record["control_lock_identity"]) for record in completed.history
                    }), 1)
                    self.assertTrue(all(
                        record["source_manifest"]["manifest_digest"]
                        == completed.history[0]["source_manifest"]["manifest_digest"]
                        for record in completed.history
                    ))
                    self.assertEqual(
                        (completed.active_manifest.mode, completed.active_manifest.repository_id),
                        ("active", "repository-candidate"),
                    )
                    scheduled = json.loads(
                        (ROOT / "config" / "contracts" / "migration-fault-schedule-v2.json").read_text(),
                    )["points"]
                    terminal = {
                        "migration.after_state.blocked",
                        "migration.after_state.recovered_new_active",
                        "migration.after_state.recovered_old_active",
                        "migration.after_state.recovered_rolled_back",
                    }
                    reachable = [
                        point for point in scheduled
                        if not point.startswith(("recovery.", "restore_gap."))
                        and point not in terminal
                    ]
                    self.assertEqual(sorted(set(blocked)), reachable)
                    restarted = InstallationMigrationRepository.initialize(
                        completed.imported.factory, completed.imported.locks,
                        completed.imported.objects, control_root=root / "control",
                        policy_document=self._policy(),
                    )
                    self.assertEqual(len(restarted.migration_history("migration-1")), 12)
                    restarted.close()
                finally:
                    completed.close()

    def test_gew_mig_041_ledger_history_and_head_tamper_fail_exact_validation(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-ledger-") as directory:
                root = pathlib.Path(directory)
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=root / "control",
                    policy_document=self._policy(),
                )
                completed = migration.migrate(
                    migration_id="migration-1", export_id="export-1",
                    bundle_destination=root / "bundle", candidate_destination=root / "candidate",
                    candidate_repository_id="repository-candidate",
                    release_id="release-candidate", contract_id="repository-contract-1",
                )
                try:
                    self.assertEqual(len(migration.migration_history("migration-1")), 12)
                    with completed.imported.factory.open("migration") as connection:
                        with connection.transaction():
                            record = json.loads(connection.execute(
                                "SELECT record_json FROM migration_ledger_transitions "
                                "WHERE migration_id='migration-1' AND revision=8",
                            ).fetchone()[0])
                            record["candidate"]["repository_id"] = "repository-substituted"
                            connection.execute(
                                "UPDATE migration_ledger_transitions SET record_json=? "
                                "WHERE migration_id='migration-1' AND revision=8",
                                (canonical_json(record),),
                            )
                    with self.assertRaisesRegex(MigrationRepositoryError, "history"):
                        migration.migration_history("migration-1")
                finally:
                    completed.close()

    def test_post_activation_operations_route_only_current_repository(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-current-authority-") as directory:
                root = pathlib.Path(directory)
                manager = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=root / "control",
                    policy_document=self._policy(),
                )
                completed = manager.migrate(
                    migration_id="migration-1", export_id="export-1",
                    bundle_destination=root / "bundle-1",
                    candidate_destination=root / "candidate-1",
                    candidate_repository_id="repository-candidate-1",
                    release_id="release-candidate-1", contract_id="repository-contract-1",
                )
                try:
                    second = manager.export_bundle(root / "bundle-2", export_id="export-2")
                    self.assertEqual(
                        second.snapshot_identity.source_repository_id,
                        completed.active_manifest.repository_id,
                    )
                    with factory.open("doctor") as stale:
                        self.assertEqual(stale.execute(
                            "SELECT COUNT(*) FROM export_holds WHERE export_id='export-2'",
                        ).fetchone()[0], 0)
                    with completed.imported.factory.open("doctor") as current:
                        self.assertEqual(current.execute(
                            "SELECT COUNT(*) FROM export_holds WHERE export_id='export-2'",
                        ).fetchone()[0], 0)
                    migrated_again = manager.migrate(
                        migration_id="migration-2", export_id="export-3",
                        bundle_destination=root / "bundle-3",
                        candidate_destination=root / "candidate-2",
                        candidate_repository_id="repository-candidate-2",
                        release_id="release-candidate-2",
                        contract_id="repository-contract-1",
                    )
                    try:
                        self.assertEqual(
                            migrated_again.history[0]["source_manifest"]["repository_id"],
                            "repository-candidate-1",
                        )
                        self.assertEqual(
                            migrated_again.active_manifest.repository_id,
                            "repository-candidate-2",
                        )
                        gap = manager.register_restore_gap(
                            second,
                            resources=migrated_again.active_manifest.fencing_high_water,
                        )
                        with migrated_again.imported.factory.open("doctor") as current:
                            self.assertEqual(current.execute(
                                "SELECT state FROM migration_ledger WHERE migration_id=?",
                                (gap.gap_id,),
                            ).fetchone(), ("restore_gap_open",))
                        with factory.open("doctor") as stale:
                            self.assertIsNone(stale.execute(
                                "SELECT state FROM migration_ledger WHERE migration_id=?",
                                (gap.gap_id,),
                            ).fetchone())
                        self.assertEqual(manager.recover_activation().mode, "blocked")
                    finally:
                        migrated_again.close()
                finally:
                    completed.close()

    def test_gew_mig_042_versioned_fault_schedule_covers_every_production_cut(self) -> None:
        schedule = json.loads(
            (ROOT / "config" / "contracts" / "migration-fault-schedule-v2.json").read_text(),
        )
        self.assertEqual(schedule["schema_version"], "2.0")
        self.assertEqual(schedule["points"], sorted(set(schedule["points"])))
        self.assertEqual(
            schedule["process_crash_points"], sorted(set(schedule["process_crash_points"])),
        )
        self.assertTrue(set(schedule["process_crash_points"]).issubset(schedule["points"]))
        self.assertEqual(schedule["concurrency_scenarios"], sorted(set(schedule["concurrency_scenarios"])))
        self.assertEqual(
            (len(schedule["points"]), len(schedule["process_crash_points"]),
             len(schedule["concurrency_scenarios"])),
            (51, 31, 4),
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process crash harness required")
    def test_gew_mig_043_every_durable_cut_sigkill_recovers_active_or_blocked(self) -> None:
        schedule = json.loads(
            (ROOT / "config" / "contracts" / "migration-fault-schedule-v2.json").read_text(),
        )
        migration_points = [
            point for point in schedule["process_crash_points"]
            if not point.startswith(("recovery.", "restore_gap."))
        ]
        for index, fault_point in enumerate(migration_points):
            with self.subTest(fault_point=fault_point):
                with repository_stack() as (_root, factory, locks, objects, repository, leases):
                    self._seed(objects, repository, leases)
                    with tempfile.TemporaryDirectory(
                        prefix=f"gew-wp06-migration-sigkill-{index}-",
                    ) as directory:
                        root = pathlib.Path(directory)
                        policy = self._policy()
                        migration = InstallationMigrationRepository.initialize(
                            factory, locks, objects, control_root=root / "control",
                            policy_document=policy,
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

                                child_locks = LockedFileRegistry(factory)
                                child_objects = ObjectRepository(factory, child_locks)
                                child_migration = InstallationMigrationRepository.initialize(
                                    factory, child_locks, child_objects,
                                    control_root=root / "control", policy_document=policy,
                                    fault_hook=stop_at,
                                )
                                child_migration.migrate(
                                    migration_id="migration-1", export_id="export-1",
                                    bundle_destination=root / "bundle",
                                    candidate_destination=root / "candidate",
                                    candidate_repository_id="repository-candidate",
                                    release_id="release-candidate",
                                    contract_id="repository-contract-1",
                                )
                            except BaseException:
                                os.write(write_fd, b"error")
                                os._exit(3)
                            os._exit(2)
                        os.close(write_fd)
                        message = os.read(read_fd, 16)
                        os.close(read_fd)
                        if message != b"ready":
                            os.waitpid(child, 0)
                            self.fail(f"migration crash harness failed at {fault_point}: {message!r}")
                        os.kill(child, signal.SIGKILL)
                        _pid, status = os.waitpid(child, 0)
                        self.assertTrue(os.WIFSIGNALED(status))
                        recovered = migration.recover_migration("migration-1")
                        candidate_points = {
                            "activation.after_active_manifest",
                            "migration.after_state.active",
                            "migration.after_state.completed",
                        }
                        rollback_points = {
                            "activation.after_verifying_manifest",
                            "activation.before_active_manifest",
                            "migration.after_state.post_switch_verified",
                            "migration.after_state.verifying_reference",
                        }
                        expected_repository = (
                            "repository-candidate" if fault_point in candidate_points
                            else "repository-test-v1"
                        )
                        expected_generation = 3 if fault_point in candidate_points | rollback_points else 1
                        self.assertEqual(
                            (recovered.mode, recovered.repository_id, recovered.generation),
                            ("active", expected_repository, expected_generation),
                        )
                        with factory.open("doctor") as connection:
                            durable = connection.execute(
                                "SELECT 1 FROM migration_ledger WHERE migration_id='migration-1'",
                            ).fetchone()
                            self.assertEqual(connection.execute(
                                "SELECT COUNT(*) FROM export_holds WHERE export_id='export-1'",
                            ).fetchone()[0], 0)
                        if durable is not None:
                            history = migration.migration_history("migration-1")
                            self.assertEqual(
                                [record["migration"]["revision"] for record in history],
                                list(range(1, len(history) + 1)),
                            )
                            if history[-1]["migration"]["state"] != "completed":
                                expected_terminal = (
                                    "recovered_new_active" if fault_point in candidate_points
                                    else "recovered_rolled_back" if fault_point in rollback_points
                                    else "recovered_old_active"
                                )
                                self.assertEqual(
                                    history[-1]["migration"]["state"], expected_terminal,
                                )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process concurrency harness required")
    def test_gew_mig_044_two_process_orchestrators_have_one_exact_authority(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-migration-race-") as directory:
                root = pathlib.Path(directory)
                policy = self._policy()
                migration = InstallationMigrationRepository.initialize(
                    factory, locks, objects, control_root=root / "control",
                    policy_document=policy,
                )
                children: list[tuple[int, int, int]] = []
                for index in range(2):
                    ready_read, ready_write = os.pipe()
                    go_read, go_write = os.pipe()
                    result_read, result_write = os.pipe()
                    child = os.fork()
                    if child == 0:
                        os.close(ready_read)
                        os.close(go_write)
                        os.close(result_read)
                        try:
                            child_locks = LockedFileRegistry(factory)
                            child_objects = ObjectRepository(factory, child_locks)
                            child_migration = InstallationMigrationRepository.initialize(
                                factory, child_locks, child_objects,
                                control_root=root / "control", policy_document=policy,
                            )
                            os.write(ready_write, b"R")
                            os.read(go_read, 1)
                            completed = child_migration.migrate(
                                migration_id="migration-1", export_id=f"export-{index}",
                                bundle_destination=root / f"bundle-{index}",
                                candidate_destination=root / f"candidate-{index}",
                                candidate_repository_id=f"repository-candidate-{index}",
                                release_id=f"release-candidate-{index}",
                                contract_id="repository-contract-1",
                            )
                            completed.close()
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
                    os.write(go_write, b"G")
                outcomes = [
                    os.read(result_read, 1)
                    for _child, _go_write, result_read in children
                ]
                self.assertEqual(sorted(outcomes), [b"B", b"P"])
                for child, go_write, result_read in children:
                    os.close(go_write)
                    os.close(result_read)
                    _pid, status = os.waitpid(child, 0)
                    self.assertTrue(os.WIFEXITED(status))
                recovered = migration.recover_activation()
                self.assertEqual(recovered.mode, "active")
                self.assertIn(recovered.repository_id, {
                    "repository-candidate-0", "repository-candidate-1",
                })
                self.assertEqual(len(migration.migration_history("migration-1")), 12)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process recovery harness required")
    def test_gew_mig_045_recovery_cuts_preserve_hold_and_rollback_oracles(self) -> None:
        scenarios = {
            "recovery.after_export_hold_recovery": (
                "export.after_hold", "recovered_old_active", 1,
            ),
            "recovery.after_rollback_manifest": (
                "activation.after_verifying_manifest", "recovered_rolled_back", 3,
            ),
        }
        for recovery_point, (setup_point, terminal_state, generation) in scenarios.items():
            with self.subTest(recovery_point=recovery_point):
                with repository_stack() as (_root, factory, locks, objects, repository, leases):
                    self._seed(objects, repository, leases)
                    with tempfile.TemporaryDirectory(prefix="gew-wp06-recovery-cut-") as directory:
                        root = pathlib.Path(directory)
                        policy = self._policy()
                        migration = InstallationMigrationRepository.initialize(
                            factory, locks, objects, control_root=root / "control",
                            policy_document=policy,
                        )

                        def fork_and_kill(point: str, *, recover: bool) -> None:
                            read_fd, write_fd = os.pipe()
                            child = os.fork()
                            if child == 0:
                                os.close(read_fd)
                                try:
                                    def stop_at(observed: str) -> None:
                                        if observed == point:
                                            os.write(write_fd, b"ready")
                                            signal.pause()

                                    child_locks = LockedFileRegistry(factory)
                                    child_objects = ObjectRepository(factory, child_locks)
                                    child_migration = InstallationMigrationRepository.initialize(
                                        factory, child_locks, child_objects,
                                        control_root=root / "control", policy_document=policy,
                                        fault_hook=stop_at,
                                    )
                                    if recover:
                                        child_migration.recover_migration("migration-1")
                                    else:
                                        child_migration.migrate(
                                            migration_id="migration-1", export_id="export-1",
                                            bundle_destination=root / "bundle",
                                            candidate_destination=root / "candidate",
                                            candidate_repository_id="repository-candidate",
                                            release_id="release-candidate",
                                            contract_id="repository-contract-1",
                                        )
                                except BaseException:
                                    os.write(write_fd, b"error")
                                    os._exit(3)
                                os._exit(2)
                            os.close(write_fd)
                            message = os.read(read_fd, 16)
                            os.close(read_fd)
                            if message != b"ready":
                                os.waitpid(child, 0)
                                self.fail(f"recovery harness failed at {point}: {message!r}")
                            os.kill(child, signal.SIGKILL)
                            _pid, status = os.waitpid(child, 0)
                            self.assertTrue(os.WIFSIGNALED(status))

                        fork_and_kill(setup_point, recover=False)
                        fork_and_kill(recovery_point, recover=True)
                        recovered = migration.recover_migration("migration-1")
                        self.assertEqual(
                            (recovered.mode, recovered.repository_id, recovered.generation),
                            ("active", "repository-test-v1", generation),
                        )
                        history = migration.migration_history("migration-1")
                        self.assertEqual(history[-1]["migration"]["state"], terminal_state)
                        with factory.open("doctor") as connection:
                            self.assertEqual(connection.execute(
                                "SELECT COUNT(*) FROM export_holds WHERE export_id='export-1'",
                            ).fetchone()[0], 0)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX restore-gap crash harness required")
    def test_gew_mig_046_restore_gap_cuts_recover_blocked_or_reactivated(self) -> None:
        def kill_at(factory, root, policy, point: str, operation) -> None:
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                try:
                    def stop_at(observed: str) -> None:
                        if observed == point:
                            os.write(write_fd, b"ready")
                            signal.pause()

                    child_locks = LockedFileRegistry(factory)
                    child_objects = ObjectRepository(factory, child_locks)
                    child_manager = InstallationMigrationRepository.initialize(
                        factory, child_locks, child_objects,
                        control_root=root / "control", policy_document=policy,
                        fault_hook=stop_at,
                    )
                    operation(child_manager)
                except BaseException:
                    os.write(write_fd, b"error")
                    os._exit(3)
                os._exit(2)
            os.close(write_fd)
            message = os.read(read_fd, 16)
            os.close(read_fd)
            if message != b"ready":
                os.waitpid(child, 0)
                self.fail(f"restore-gap harness failed at {point}: {message!r}")
            os.kill(child, signal.SIGKILL)
            _pid, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFSIGNALED(status))

        for point in ("restore_gap.after_ledger_commit", "restore_gap.after_blocked_manifest"):
            with self.subTest(point=point):
                with repository_stack() as (_root, factory, locks, objects, repository, leases):
                    self._seed(objects, repository, leases)
                    with tempfile.TemporaryDirectory(prefix="gew-wp06-gap-register-") as directory:
                        root = pathlib.Path(directory)
                        policy = self._policy()
                        manager = InstallationMigrationRepository.initialize(
                            factory, locks, objects, control_root=root / "control",
                            policy_document=policy,
                        )
                        bundle = manager.export_bundle(root / "bundle", export_id="stale")
                        with factory._for_maintenance().open("migration") as connection:
                            with connection.transaction():
                                connection.execute(
                                    "UPDATE resource_fences SET fencing_token=9 "
                                    "WHERE resource_id='task:task-1'",
                                )
                        kill_at(
                            factory, root, policy, point,
                            lambda child_manager: child_manager.register_restore_gap(
                                bundle, resources=(("task:task-1", 9),),
                            ),
                        )
                        recovered = manager.recover_activation()
                        self.assertEqual(
                            (recovered.mode, recovered.repository_id, recovered.generation),
                            ("blocked", "repository-test-v1", 2),
                        )
                        self.assertIsNotNone(recovered.restore_gap_digest)

        for point in (
            "restore_gap.after_reconcile_commit", "restore_gap.after_reactivation_manifest",
        ):
            with self.subTest(point=point):
                with repository_stack() as (_root, factory, locks, objects, repository, leases):
                    self._seed(objects, repository, leases)
                    with tempfile.TemporaryDirectory(prefix="gew-wp06-gap-clear-") as directory:
                        root = pathlib.Path(directory)
                        policy = self._policy()
                        manager = InstallationMigrationRepository.initialize(
                            factory, locks, objects, control_root=root / "control",
                            policy_document=policy,
                        )
                        bundle = manager.export_bundle(root / "bundle", export_id="stale")
                        with factory._for_maintenance().open("migration") as connection:
                            with connection.transaction():
                                connection.execute(
                                    "UPDATE resource_fences SET fencing_token=9 "
                                    "WHERE resource_id='task:task-1'",
                                )
                        gap = manager.register_restore_gap(
                            bundle, resources=(("task:task-1", 9),),
                        )
                        blocked = manager._current_manifest()
                        authority, observation = self._authorize_gap_clear(
                            factory, manager, gap, blocked,
                        )
                        kill_at(
                            factory, root, policy, point,
                            lambda child_manager: child_manager.clear_restore_gap(
                                gap, fences=(("task:task-1", 10),),
                                authority_digest=authority,
                                fresh_observations=(observation,),
                            ),
                        )
                        recovered = manager.recover_activation()
                        self.assertEqual(
                            (recovered.mode, recovered.repository_id, recovered.generation),
                            ("active", "repository-test-v1", 3),
                        )
                        self.assertEqual(dict(recovered.fencing_high_water)["task:task-1"], 10)


if __name__ == "__main__":
    unittest.main()
