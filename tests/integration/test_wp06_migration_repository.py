from __future__ import annotations

import pathlib
import json
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
from tests.conformance.test_wp03_repository import batch  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class WP06MigrationRepositoryTests(unittest.TestCase):
    def _migration(self, factory, locks, objects, control_root):
        policy = json.loads(
            (ROOT / "config" / "contracts" / "migration-storage-policy-v1.json").read_text()
        )
        return InstallationMigrationRepository.initialize(
            factory, locks, objects, control_root=control_root, policy_document=policy,
        )

    def _seed(self, objects, repository, leases) -> tuple[bytes, str]:
        lease = leases.acquire_many(
            lease_id="task-lease", task_id="task-1", run_id="run-1", operation_id="write",
            resources=("task:task-1",), ttl_ns=100,
        )
        body = b"wp06-export-object"
        object_digest = objects.digest(body)
        objects.put_verified(body, object_digest)
        repository.commit(batch("transaction-1", lease, object_digests=(object_digest,)))
        leases.release(lease.lease_id)
        return body, object_digest

    def test_gew_mig_011_public_export_is_complete_and_clears_durable_hold(self) -> None:
        with repository_stack() as (root, factory, locks, objects, repository, leases):
            body, object_digest = self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                self.assertEqual(bundle.object_digests, (object_digest,))
                self.assertEqual(bundle.object_body(object_digest), body)
                with factory.open("doctor") as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM export_holds").fetchone()[0], 0)
                self.assertTrue(root.exists())

    def test_gew_mig_012_migration_held_export_reuses_exact_exclusive_token(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                token = migration._control_lock.acquire("exclusive")
                try:
                    bundle = migration.export_bundle_under_installation_exclusive(
                        token, parent / "bundle", export_id="export-held",
                    )
                    self.assertEqual(bundle.export_id, "export-held")
                finally:
                    migration._control_lock.release(token)
                with self.assertRaises(MigrationRepositoryError):
                    migration.export_bundle_under_installation_exclusive(
                        token, parent / "other", export_id="export-stale",
                    )

    def test_gew_mig_013_bundle_tamper_or_missing_object_fails_validation(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            _body, object_digest = self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                bundle.object_path(object_digest).write_bytes(b"tampered")
                with self.assertRaises(MigrationRepositoryError):
                    migration.validate_bundle(bundle.root)

    def test_gew_mig_014_import_replays_exact_history_and_objects_in_isolated_root(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            body, object_digest = self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                self.assertEqual(imported.repository.replay("task-1"), repository.replay("task-1"))
                self.assertEqual(imported.objects.get(object_digest), body)
                imported.close()

    def test_gew_mig_015_activation_recovery_exposes_only_verified_active_or_blocked(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                imported = migration.import_bundle(
                    bundle.root, parent / "candidate", repository_id="repository-candidate",
                )
                active = migration.activate(
                    imported, release_id="release-candidate", contract_id="repository-contract-1",
                )
                self.assertEqual(active.mode, "active")
                self.assertEqual(migration.recover_activation().manifest_digest, active.manifest_digest)
                imported.close()

    def test_gew_mig_016_stale_restore_creates_gap_and_never_lowers_fence(self) -> None:
        with repository_stack() as (_root, factory, locks, objects, repository, leases):
            self._seed(objects, repository, leases)
            with tempfile.TemporaryDirectory(prefix="gew-wp06-control-") as directory:
                parent = pathlib.Path(directory)
                migration = self._migration(factory, locks, objects, parent / "control")
                bundle = migration.export_bundle(parent / "bundle", export_id="export-1")
                gap = migration.register_restore_gap(bundle, resources=(("task:task-1", 1),))
                self.assertFalse(gap.external_actions_allowed)
                with self.assertRaises(MigrationRepositoryError):
                    migration.clear_restore_gap(gap, fences=(("task:task-1", 1),), authority_digest=None)


if __name__ == "__main__":
    unittest.main()
