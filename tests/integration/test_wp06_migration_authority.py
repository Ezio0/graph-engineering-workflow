from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.core.migration import ExportSnapshotIdentity, RestoreGap  # noqa: E402
from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.storage.codec import (  # noqa: E402
    canonical_json,
    parse_canonical_json,
    semantic_record_digest,
)
from graph_engineering.storage.leases import ResourceLeaseRepository  # noqa: E402
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from graph_engineering.storage.migration import MigrationRepositoryError  # noqa: E402
from tests.conformance.test_wp03_repository import batch  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class WP06MigrationAuthorityTests(unittest.TestCase):
    def _seed(self, objects, repository, leases) -> str:
        lease = leases.acquire_many(
            lease_id="seed-lease", task_id="task-1", run_id="seed-run",
            operation_id="write", resources=("task:task-1",), ttl_ns=100,
        )
        body = b"wp06-authority-bundle-object"
        digest = objects.digest(body)
        objects.put_verified(body, digest)
        repository.commit(batch("seed-transaction", lease, object_digests=(digest,)))
        leases.release(lease.lease_id)
        return digest

    @staticmethod
    def _release_fixture_command(factory) -> object:
        scope = factory._test_installation_scope
        scope.__exit__(None, None, None)
        return factory._test_installation_manager

    def test_gew_mig_034_export_uses_exact_stable_control_exclusive(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-export-authority-") as directory:
                parent = pathlib.Path(directory)
                control_token = manager._control_lock.acquire("exclusive")
                local_token = locks.acquire_installation("exclusive")
                try:
                    with self.assertRaisesRegex(MigrationRepositoryError, "control"):
                        manager.export_bundle_under_installation_exclusive(
                            local_token, parent / "substituted", export_id="substituted",
                        )
                    bundle = manager.export_bundle_under_installation_exclusive(
                        control_token, parent / "bundle", export_id="export-authority",
                    )
                    self.assertEqual(bundle.export_id, "export-authority")
                    with self.assertRaisesRegex(MigrationRepositoryError, "reentrant|busy"):
                        manager.export_bundle(parent / "reentrant", export_id="reentrant")
                finally:
                    locks.release(local_token)
                    manager._control_lock.release(control_token)

                entered = threading.Event()
                release = threading.Event()

                def command() -> None:
                    with manager.command_scope():
                        entered.set()
                        release.wait(timeout=5)

                thread = threading.Thread(target=command)
                thread.start()
                self.assertTrue(entered.wait(timeout=5))
                with self.assertRaisesRegex(MigrationRepositoryError, "unavailable|busy"):
                    manager.export_bundle(parent / "blocked", export_id="blocked")
                release.set()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def test_gew_mig_035_bundle_binds_approved_snapshot_identity(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            referenced_digest = self._seed(objects, repository, leases)
            orphan_body = b"unreferenced-export-orphan"
            orphan_digest = objects.digest(orphan_body)
            objects.put_verified(orphan_body, orphan_digest)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-snapshot-identity-") as directory:
                bundle = manager.export_bundle(pathlib.Path(directory) / "bundle", export_id="identity")
                manifest = parse_canonical_json(
                    (bundle.root / manager._policy.bundle_manifest_filename).read_text(),
                )
                identity = manifest["snapshot_identity"]
                rebuilt = ExportSnapshotIdentity.create(
                    export_id=identity["export_id"],
                    source_repository_id=identity["source_repository_id"],
                    activation_epoch=identity["activation_epoch"],
                    backup_head_digest=identity["backup_head_digest"],
                    backup_revision=identity["backup_revision"],
                    schema_manifest_digest=identity["schema_manifest_digest"],
                    object_manifest_digest=identity["object_manifest_digest"],
                    object_digests=tuple(identity["object_digests"]),
                )
                self.assertEqual(rebuilt.snapshot_digest, identity["snapshot_digest"])
                self.assertEqual(bundle.snapshot_digest, rebuilt.snapshot_digest)
                self.assertIn(referenced_digest, bundle.object_digests)
                self.assertNotIn(orphan_digest, bundle.object_digests)
                with factory._for_maintenance().open("application") as connection:
                    with connection.transaction():
                        connection.execute(
                            "UPDATE objects SET state='quarantined' WHERE digest=?",
                            (referenced_digest,),
                        )
                with self.assertRaisesRegex(MigrationRepositoryError, "referenced.*unavailable"):
                    manager.export_bundle(
                        pathlib.Path(directory) / "unavailable",
                        export_id="unavailable",
                    )

    def test_gew_mig_036_bundle_reader_is_exact_bounded_and_no_follow(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            object_digest = self._seed(objects, repository, leases)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-bounded-bundle-") as directory:
                parent = pathlib.Path(directory)
                first = manager.export_bundle(parent / "bundle-extra", export_id="extra")
                (first.root / "unexpected").write_text("not-declared")
                with self.assertRaisesRegex(MigrationRepositoryError, "exact|unexpected"):
                    manager.validate_bundle(first.root)

                second = manager.export_bundle(parent / "bundle-link", export_id="link")
                object_path = second.object_path(object_digest)
                external = parent / "external-object"
                external.write_bytes(object_path.read_bytes())
                object_path.unlink()
                object_path.symlink_to(external)
                with self.assertRaisesRegex(MigrationRepositoryError, "symlink|no-follow|regular"):
                    manager.validate_bundle(second.root)

                third = manager.export_bundle(parent / "bundle-hardlink", export_id="hardlink")
                manifest_path = third.root / manager._policy.bundle_manifest_filename
                external_manifest = parent / "external-manifest"
                external_manifest.write_bytes(manifest_path.read_bytes())
                external_manifest.chmod(manager._policy.file_mode)
                manifest_path.unlink()
                os.link(external_manifest, manifest_path)
                with self.assertRaisesRegex(MigrationRepositoryError, "regular|changed"):
                    manager.validate_bundle(third.root)

                fourth = manager.export_bundle(parent / "bundle-bounds", export_id="bounds")
                original_policy = manager._policy
                try:
                    manager._policy = dataclasses.replace(
                        original_policy, max_bundle_total_bytes=1, max_json_depth=1,
                    )
                    with self.assertRaisesRegex(MigrationRepositoryError, "bounds|aggregate"):
                        manager.validate_bundle(fourth.root)
                finally:
                    manager._policy = original_policy

    def test_gew_mig_037_activation_recomputes_exact_candidate(self) -> None:
        with repository_stack() as (source_root, factory, _locks, objects, repository, leases):
            object_digest = self._seed(objects, repository, leases)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-candidate-recompute-") as directory:
                parent = pathlib.Path(directory)
                bundle = manager.export_bundle(parent / "bundle", export_id="candidate")
                imported = manager.import_bundle(
                    bundle.root, parent / "candidate", repository_id="candidate-repository",
                )
                exact_repository_digest = imported.repository_digest
                imported.repository_digest = "sha256-jcs-v1:" + "f" * 64
                with self.assertRaisesRegex(MigrationRepositoryError, "candidate|recomput"):
                    manager.activate(
                        imported, release_id="candidate-release",
                        contract_id="repository-contract-1",
                    )
                self.assertEqual(manager._current_manifest().repository_id, factory.repository_id)
                imported.repository_digest = exact_repository_digest
                with self.assertRaisesRegex(MigrationRepositoryError, "contract"):
                    manager.activate(
                        imported, release_id="candidate-release", contract_id="wrong-contract",
                    )
                imported.close()

                for index, mutation in enumerate(
                    ("db", "object", "schema", "locator", "fence", "bundle"), 1,
                ):
                    with self.subTest(mutation=mutation):
                        candidate_bundle = manager.export_bundle(
                            parent / f"bundle-{mutation}", export_id=f"candidate-{mutation}",
                        )
                        candidate = manager.import_bundle(
                            candidate_bundle.root,
                            parent / f"candidate-{mutation}",
                            repository_id=f"candidate-repository-{index}",
                        )

                        def mutate(point: str) -> None:
                            if point != "activation.after_verifying_manifest":
                                return
                            if mutation == "object":
                                path = candidate.objects._path(object_digest)
                                path.write_bytes(b"post-switch-object-substitution")
                            elif mutation in {"db", "schema", "fence"}:
                                with candidate.factory.open("migration") as connection:
                                    with connection.transaction():
                                        if mutation == "db":
                                            connection.execute(
                                                "INSERT INTO repository_meta(key,value) VALUES('forged','1')",
                                            )
                                        elif mutation == "schema":
                                            connection.execute(
                                                "UPDATE schema_versions SET version='forged' "
                                                "WHERE component='storage'",
                                            )
                                        else:
                                            connection.execute(
                                                "UPDATE resource_fences SET fencing_token=999",
                                            )
                            elif mutation == "locator":
                                registry_path = (
                                    manager._control
                                    / manager._policy.repository_locator_registry_filename
                                )
                                registry = parse_canonical_json(registry_path.read_text())
                                source_metadata = source_root.lstat()
                                for entry in registry["repositories"]:
                                    if entry["repository_id"] == candidate.factory.repository_id:
                                        entry.update({
                                            "root": source_root.as_posix(),
                                            "device": source_metadata.st_dev,
                                            "inode": source_metadata.st_ino,
                                        })
                                        entry["locator_digest"] = semantic_record_digest({
                                            key: value for key, value in entry.items()
                                            if key != "locator_digest"
                                        })
                                registry_path.write_bytes(canonical_bytes(registry))
                            else:
                                manifest_path = (
                                    candidate.bundle_root
                                    / manager._policy.bundle_manifest_filename
                                )
                                manifest = parse_canonical_json(manifest_path.read_text())
                                manifest["records_digest"] = "sha256-raw-v1:" + "0" * 64
                                manifest_path.write_bytes(canonical_bytes(manifest))

                        manager._fault = mutate
                        with self.assertRaises(MigrationRepositoryError):
                            manager.activate(
                                candidate, release_id=f"candidate-release-{index}",
                                contract_id="repository-contract-1",
                            )
                        verifying = manager._current_manifest()
                        self.assertEqual(verifying.mode, "verifying")
                        manager._fault = lambda _point: None
                        recovered = manager.recover_activation()
                        self.assertEqual(
                            (recovered.mode, recovered.repository_id),
                            ("active", factory.repository_id),
                        )
                        self.assertGreater(recovered.generation, verifying.generation)
                        candidate.close()

    def test_gew_mig_038_activation_seeds_candidate_fencing_high_water(self) -> None:
        with repository_stack() as (_root, factory, _locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-fence-seed-") as directory:
                parent = pathlib.Path(directory)
                bundle = manager.export_bundle(parent / "bundle", export_id="fences")
                with factory._for_maintenance().open("application") as connection:
                    with connection.transaction():
                        connection.execute(
                            "UPDATE resource_fences SET fencing_token=9 WHERE resource_id='task:task-1'",
                        )
                imported = manager.import_bundle(
                    bundle.root, parent / "candidate", repository_id="candidate-repository",
                )
                active = manager.activate(
                    imported, release_id="candidate-release",
                    contract_id="repository-contract-1",
                )
                self.assertEqual(dict(active.fencing_high_water)["task:task-1"], 9)
                with imported.factory.open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT fencing_token FROM resource_fences WHERE resource_id='task:task-1'",
                    ).fetchone(), (9,))
                with manager.command_scope() as scope:
                    candidate_factory = imported.factory.bind_command_scope(scope)
                    candidate_leases = ResourceLeaseRepository(candidate_factory, imported.locks)
                    lease = candidate_leases.acquire_many(
                        lease_id="post-activation", task_id="task-1", run_id="post",
                        operation_id="write", resources=("task:task-1",), ttl_ns=100,
                    )
                    self.assertEqual(dict(lease.fencing_tokens)["task:task-1"], 10)
                    candidate_leases.release(lease.lease_id)
                imported.close()

    def test_gew_mig_039_restore_gap_is_persistent_and_blocks_commands(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            manager = self._release_fixture_command(factory)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-restore-gap-") as directory:
                bundle = manager.export_bundle(pathlib.Path(directory) / "bundle", export_id="stale")
                with factory._for_maintenance().open("application") as connection:
                    with connection.transaction():
                        connection.execute(
                            "UPDATE resource_fences SET fencing_token=9 WHERE resource_id='task:task-1'",
                        )
                gap = manager.register_restore_gap(bundle, resources=(("task:task-1", 9),))
                blocked = manager._current_manifest()
                self.assertEqual((blocked.mode, blocked.restore_gap_digest), ("blocked", gap.gap_digest))
                with manager._factory.open("doctor") as connection:
                    row = connection.execute(
                        "SELECT state,record_json,record_digest FROM migration_ledger WHERE migration_id=?",
                        (gap.gap_id,),
                    ).fetchone()
                self.assertEqual(row[0], "restore_gap_open")
                with self.assertRaisesRegex(MigrationRepositoryError, "blocked"):
                    with manager.command_scope():
                        pass
                with manager._factory.open("migration") as connection:
                    with connection.transaction():
                        connection.execute(
                            "DELETE FROM migration_ledger WHERE migration_id=?", (gap.gap_id,),
                        )
                restarted = type(manager).initialize(
                    factory, locks, objects,
                    control_root=factory._test_installation_control_root,
                    policy_document=factory._test_migration_policy,
                )
                self.assertEqual(restarted._current_manifest().mode, "blocked")
                restarted.close()
                with manager._factory.open("migration") as connection:
                    with connection.transaction():
                        connection.execute(
                            "INSERT INTO migration_ledger(migration_id,state,record_json,record_digest) "
                            "VALUES(?,?,?,?)",
                            (gap.gap_id, row[0], row[1], row[2]),
                        )
                        connection.execute(
                            "UPDATE migration_ledger SET record_digest=? WHERE migration_id=?",
                            ("sha256-jcs-v1:" + "0" * 64, gap.gap_id),
                        )
                restarted = type(manager).initialize(
                    factory, locks, objects,
                    control_root=factory._test_installation_control_root,
                    policy_document=factory._test_migration_policy,
                )
                self.assertEqual(restarted._current_manifest().mode, "blocked")
                restarted.close()
                with manager._factory.open("migration") as connection:
                    with connection.transaction():
                        connection.execute(
                            "UPDATE migration_ledger SET record_digest=? WHERE migration_id=?",
                            (row[2], gap.gap_id),
                        )
                authority = "sha256-jcs-v1:" + "a" * 64
                security_state = {
                    "schema_version": "1.0.0",
                    "task_id": "task-1",
                    "task_revision": 1,
                    "task_snapshot_digest": "",
                    "binding": {},
                    "destinations": {},
                    "authority_digests": [authority],
                    "data_refs": {},
                    "evidence_expectations": {},
                    "retention_subjects": {},
                }
                with manager._factory.open("migration") as connection:
                    with connection.transaction():
                        task = connection.execute(
                            "SELECT revision,snapshot_digest FROM tasks WHERE task_id='task-1'",
                        ).fetchone()
                        security_state.update({
                            "task_revision": task[0],
                            "task_snapshot_digest": task[1],
                            "binding": {
                                "task_id": "task-1", "snapshot_digest": task[1],
                            },
                        })
                        security_state_digest = semantic_record_digest({
                            "contract": "task-security-state-v1", "value": security_state,
                        })
                        connection.execute(
                            "INSERT INTO task_security_states(task_id,task_revision,"
                            "task_snapshot_digest,state_json,state_digest) VALUES(?,?,?,?,?)",
                            (
                                "task-1", task[0], task[1], canonical_json(security_state),
                                security_state_digest,
                            ),
                        )
                observation_unsigned = {
                    "resource_id": "task:task-1",
                    "target_id": "task-1",
                    "target_state_digest": task[1],
                    "observation_revision": 1,
                    "observed_at_ns": 1,
                    "observer_binding_digest": semantic_record_digest({
                        "kind": "repository-task-observer",
                        "repository_id": blocked.repository_id,
                        "task_id": "task-1",
                        "blocked_manifest_digest": blocked.manifest_digest,
                    }),
                    "gap_digest": gap.gap_digest,
                    "blocked_manifest_digest": blocked.manifest_digest,
                }
                observation = dict(
                    observation_unsigned,
                    observation_digest=semantic_record_digest(observation_unsigned),
                )

                def assert_stays_blocked(observations, candidate_authority=authority) -> None:
                    with self.assertRaises(MigrationRepositoryError):
                        manager.clear_restore_gap(
                            gap, fences=(("task:task-1", 10),),
                            authority_digest=candidate_authority,
                            fresh_observations=observations,
                        )
                    self.assertEqual(manager._current_manifest().manifest_digest, blocked.manifest_digest)

                assert_stays_blocked(())
                assert_stays_blocked((dict(observation, observation_digest="sha256-jcs-v1:" + "c" * 64),))
                random_state_unsigned = dict(
                    observation_unsigned,
                    target_state_digest="sha256-jcs-v1:" + "e" * 64,
                )
                assert_stays_blocked((dict(
                    random_state_unsigned,
                    observation_digest=semantic_record_digest(random_state_unsigned),
                ),))
                substituted_unsigned = dict(observation_unsigned, target_id="other-task")
                assert_stays_blocked((dict(
                    substituted_unsigned,
                    observation_digest=semantic_record_digest(substituted_unsigned),
                ),))
                stale_unsigned = dict(
                    observation_unsigned,
                    blocked_manifest_digest=gap.source_manifest_digest,
                )
                assert_stays_blocked((dict(
                    stale_unsigned, observation_digest=semantic_record_digest(stale_unsigned),
                ),))
                extra_unsigned = dict(observation_unsigned, resource_id="task:extra", target_id="extra")
                extra = dict(extra_unsigned, observation_digest=semantic_record_digest(extra_unsigned))
                assert_stays_blocked((observation, extra))
                assert_stays_blocked((observation,), "sha256-jcs-v1:" + "d" * 64)
                reconciled = manager.clear_restore_gap(
                    gap, fences=(("task:task-1", 10),), authority_digest=authority,
                    fresh_observations=(observation,),
                )
                self.assertTrue(reconciled.external_actions_allowed)
                current = manager._current_manifest()
                self.assertEqual((current.mode, current.restore_gap_digest), ("active", None))
                with manager.command_scope() as scope:
                    self.assertEqual(scope.repository_id, factory.repository_id)

                active = manager._current_manifest()
                dangling = RestoreGap.create(
                    gap_id="restore-gap-dangling-restart",
                    source_manifest_digest=active.manifest_digest,
                    restored_manifest_digest=bundle.source_manifest_digest,
                    resources=active.fencing_high_water,
                )
                dangling_body = dataclasses.asdict(dangling)
                dangling_body["resources"] = [list(item) for item in dangling.resources]
                dangling_record = {
                    "schema_version": "1.0",
                    "gap": dangling_body,
                    "bundle_digest": bundle.bundle_digest,
                    "bundle_snapshot_digest": bundle.snapshot_digest,
                    "unresolved_claim_ids": [],
                    "unresolved_action_ids": [],
                    "fresh_observations": [],
                }
                with manager._factory.open("migration") as connection:
                    with connection.transaction():
                        connection.execute(
                            "INSERT INTO migration_ledger(migration_id,state,record_json,record_digest) "
                            "VALUES(?,?,?,?)",
                            (
                                dangling.gap_id, "restore_gap_open",
                                canonical_json(dangling_record),
                                semantic_record_digest(dangling_record),
                            ),
                        )
                restarted = type(manager).initialize(
                    factory, locks, objects,
                    control_root=factory._test_installation_control_root,
                    policy_document=factory._test_migration_policy,
                )
                recovered_blocked = restarted._current_manifest()
                self.assertEqual(
                    (recovered_blocked.mode, recovered_blocked.restore_gap_digest),
                    ("blocked", dangling.gap_digest),
                )
                restarted.close()


if __name__ == "__main__":
    unittest.main()
