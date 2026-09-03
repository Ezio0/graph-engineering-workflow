from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.migration import (  # noqa: E402
    ActiveRepositoryManifest,
    ExportSnapshotIdentity,
    MigrationControlError,
    MigrationState,
    RestoreGap,
    select_committed_manifest,
)


def digest(character: str) -> str:
    return "sha256-jcs-v1:" + character * 64


def manifest(*, generation: int = 1, epoch: int = 1, mode: str = "active") -> ActiveRepositoryManifest:
    return ActiveRepositoryManifest.create(
        installation_id="installation-main",
        generation=generation,
        activation_epoch=epoch,
        repository_id=f"repository-{generation}",
        repository_digest=digest(str(generation % 10)),
        repository_locator_ref=f"locator-{generation}",
        repository_locator_digest=digest(str(generation % 10)),
        release_id=f"release-{generation}",
        contract_id="repository-contract-1",
        mode=mode,
        previous_manifest_digest=None if generation == 1 else digest(str((generation - 1) % 10)),
        fencing_high_water=(("resource-a", generation),),
        restore_gap_digest=None,
    )


class WP06MigrationControlTests(unittest.TestCase):
    def test_gew_mig_001_export_snapshot_identity_is_exact_and_canonical(self) -> None:
        snapshot = ExportSnapshotIdentity.create(
            export_id="export-1", source_repository_id="repository-1", activation_epoch=2,
            backup_head_digest=digest("1"), backup_revision=4,
            schema_manifest_digest=digest("2"), object_manifest_digest=digest("3"),
            object_digests=(digest("4"), digest("5")),
        )
        self.assertEqual(snapshot.object_digests, tuple(sorted(snapshot.object_digests)))

    def test_gew_mig_002_export_snapshot_rejects_duplicates_and_noncanonical_objects(self) -> None:
        with self.assertRaises(MigrationControlError):
            ExportSnapshotIdentity.create(
                export_id="export-1", source_repository_id="repository-1", activation_epoch=2,
                backup_head_digest=digest("1"), backup_revision=4,
                schema_manifest_digest=digest("2"), object_manifest_digest=digest("3"),
                object_digests=(digest("5"), digest("4"), digest("4")),
            )

    def test_gew_mig_003_migration_state_machine_accepts_only_frozen_path(self) -> None:
        state = MigrationState.start("migration-1", manifest())
        for target in (
            "upgrade_locked", "quiescence_verified", "exported", "imported_isolated",
            "replayed", "compatible", "activation_prepared", "verifying_reference",
            "post_switch_verified", "active", "completed",
        ):
            state = state.advance(target)
        self.assertEqual(state.state, "completed")

    def test_gew_mig_004_migration_state_machine_rejects_skip_and_reentry(self) -> None:
        state = MigrationState.start("migration-1", manifest())
        with self.assertRaises(MigrationControlError):
            state.advance("exported")
        state = state.advance("upgrade_locked")
        with self.assertRaises(MigrationControlError):
            state.advance("upgrade_locked")

    def test_gew_mig_005_ordinary_command_sees_only_active_or_blocked(self) -> None:
        self.assertTrue(manifest(mode="active").ordinary_commands_allowed)
        self.assertFalse(manifest(mode="verifying").ordinary_commands_allowed)
        self.assertFalse(manifest(mode="blocked").ordinary_commands_allowed)

    def test_gew_mig_006_manifest_generation_epoch_and_fences_never_decrease(self) -> None:
        current = manifest(generation=3, epoch=5)
        candidate = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=4, activation_epoch=6,
            repository_id="repository-4", repository_digest=digest("4"),
            repository_locator_ref="locator-4", repository_locator_digest=digest("4"),
            release_id="release-4", contract_id="repository-contract-1", mode="active",
            previous_manifest_digest=current.manifest_digest,
            fencing_high_water=(("resource-a", 4),), restore_gap_digest=None,
        )
        candidate.require_successor_of(current)
        wrong_chain = manifest(generation=4, epoch=6)
        with self.assertRaises(MigrationControlError):
            wrong_chain.require_successor_of(current)
        stale = manifest(generation=4, epoch=4)
        with self.assertRaises(MigrationControlError):
            stale.require_successor_of(current)

    def test_gew_mig_007_rollback_is_a_new_generation_and_epoch(self) -> None:
        previous = manifest(generation=2, epoch=2)
        current = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=3, activation_epoch=3,
            repository_id="repository-3", repository_digest=digest("3"),
            repository_locator_ref="locator-3", repository_locator_digest=digest("3"),
            release_id="release-3", contract_id="repository-contract-1", mode="active",
            previous_manifest_digest=previous.manifest_digest,
            fencing_high_water=(("resource-a", 3),), restore_gap_digest=None,
        )
        rollback = ActiveRepositoryManifest.rollback_to(
            current=current, previous=previous,
            repository_digest=digest("9"),
        )
        self.assertEqual((rollback.generation, rollback.activation_epoch), (4, 4))
        self.assertEqual(rollback.repository_id, "repository-2")
        with self.assertRaises(MigrationControlError):
            ActiveRepositoryManifest.rollback_to(
                current=current, previous=manifest(generation=1, epoch=1),
                repository_digest=digest("9"),
            )

    def test_gew_mig_008_restore_gap_blocks_until_exact_reconciliation(self) -> None:
        gap = RestoreGap.create(
            gap_id="restore-gap-1", source_manifest_digest=digest("1"),
            restored_manifest_digest=digest("2"), resources=(("resource-a", 7), ("resource-b", 3)),
        )
        self.assertFalse(gap.external_actions_allowed)
        with self.assertRaises(MigrationControlError):
            gap.reconcile((("resource-a", 7), ("resource-b", 4)), authority_digest=None)
        closed = gap.reconcile(
            (("resource-a", 8), ("resource-b", 4)), authority_digest=digest("3"),
        )
        self.assertTrue(closed.external_actions_allowed)

    def test_gew_mig_009_stale_bundle_cannot_lower_fencing_high_water(self) -> None:
        current = manifest(generation=8, epoch=8)
        candidate = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=9, activation_epoch=9,
            repository_id="repository-restored", repository_digest=digest("2"),
            repository_locator_ref="locator-restored", repository_locator_digest=digest("2"),
            release_id="release-restored", contract_id="repository-contract-1", mode="active",
            previous_manifest_digest=current.manifest_digest,
            fencing_high_water=(("resource-a", 2),), restore_gap_digest=None,
        )
        with self.assertRaises(MigrationControlError):
            candidate.require_successor_of(current)

    def test_gew_mig_010_recovery_selects_highest_valid_committed_manifest(self) -> None:
        first = manifest(generation=1, epoch=1)
        verifying = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=2, activation_epoch=2,
            repository_id="repository-2", repository_digest=digest("2"),
            repository_locator_ref="locator-2", repository_locator_digest=digest("2"),
            release_id="release-2", contract_id="repository-contract-1", mode="verifying",
            previous_manifest_digest=first.manifest_digest,
            fencing_high_water=(("resource-a", 2),), restore_gap_digest=None,
        )
        active = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=3, activation_epoch=3,
            repository_id="repository-2", repository_digest=digest("2"),
            repository_locator_ref="locator-2", repository_locator_digest=digest("2"),
            release_id="release-2", contract_id="repository-contract-1", mode="active",
            previous_manifest_digest=verifying.manifest_digest,
            fencing_high_water=(("resource-a", 3),), restore_gap_digest=None,
        )
        self.assertEqual(select_committed_manifest((active, first, verifying)), active)
        with self.assertRaises(MigrationControlError):
            select_committed_manifest((verifying,))
        broken = manifest(generation=4, epoch=4)
        with self.assertRaises(MigrationControlError):
            select_committed_manifest((first, verifying, active, broken))
        duplicate_epoch = ActiveRepositoryManifest.create(
            installation_id="installation-main", generation=4, activation_epoch=3,
            repository_id="repository-4", repository_digest=digest("4"),
            repository_locator_ref="locator-4", repository_locator_digest=digest("4"),
            release_id="release-4", contract_id="repository-contract-1", mode="active",
            previous_manifest_digest=active.manifest_digest,
            fencing_high_water=(("resource-a", 4),), restore_gap_digest=None,
        )
        with self.assertRaises(MigrationControlError):
            select_committed_manifest((first, verifying, active, duplicate_epoch))


if __name__ == "__main__":
    unittest.main()
