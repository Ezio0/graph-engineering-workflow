"""Backend-neutral export, activation, restore-gap, and fencing contracts."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, replace

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest


class MigrationControlError(ValueError):
    """A migration control record or transition is unsafe."""


def _identity(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise MigrationControlError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise MigrationControlError(f"{label} is invalid")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise MigrationControlError(f"{label} is invalid")
    return value


_OBJECT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _canonical_digests(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if type(values) is not tuple or any(
        type(item) is not str
        or (SEMANTIC_DIGEST.fullmatch(item) is None and _OBJECT_DIGEST.fullmatch(item) is None)
        for item in values
    ):
        raise MigrationControlError(f"{label} is invalid")
    if values != tuple(sorted(set(values))):
        raise MigrationControlError(f"{label} must be canonical, unique, and sorted")
    return values


def _canonical_fences(values: tuple[tuple[str, int], ...]) -> tuple[tuple[str, int], ...]:
    if type(values) is not tuple:
        raise MigrationControlError("fencing high-water must be a tuple")
    checked = tuple((_identity(resource, "resource ID"), _positive(counter, "fencing counter")) for resource, counter in values)
    if checked != tuple(sorted(set(checked))) or len({resource for resource, _ in checked}) != len(checked):
        raise MigrationControlError("fencing high-water must be canonical and unique")
    return checked


@dataclass(frozen=True, slots=True)
class ExportSnapshotIdentity:
    export_id: str
    source_repository_id: str
    activation_epoch: int
    backup_head_digest: str
    backup_revision: int
    schema_manifest_digest: str
    object_manifest_digest: str
    object_digests: tuple[str, ...]
    snapshot_digest: str

    @classmethod
    def create(
        cls,
        *,
        export_id: str,
        source_repository_id: str,
        activation_epoch: int,
        backup_head_digest: str,
        backup_revision: int,
        schema_manifest_digest: str,
        object_manifest_digest: str,
        object_digests: tuple[str, ...],
    ) -> ExportSnapshotIdentity:
        body = {
            "export_id": _identity(export_id, "export ID"),
            "source_repository_id": _identity(source_repository_id, "source repository ID"),
            "activation_epoch": _positive(activation_epoch, "activation epoch"),
            "backup_head_digest": _digest(backup_head_digest, "backup head digest"),
            "backup_revision": _positive(backup_revision, "backup revision"),
            "schema_manifest_digest": _digest(schema_manifest_digest, "schema manifest digest"),
            "object_manifest_digest": _digest(object_manifest_digest, "object manifest digest"),
            "object_digests": _canonical_digests(object_digests, "object digests"),
        }
        snapshot_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:export-snapshot-identity",
            projection_id="urn:gew:projection:export-snapshot-identity:1.0.0",
            schema_id="urn:gew:schema:export-snapshot-identity:1.0.0",
        )
        return cls(**body, snapshot_digest=snapshot_digest)


@dataclass(frozen=True, slots=True)
class ActiveRepositoryManifest:
    installation_id: str
    generation: int
    activation_epoch: int
    repository_id: str
    repository_digest: str
    repository_locator_ref: str
    repository_locator_digest: str
    release_id: str
    contract_id: str
    mode: str
    previous_manifest_digest: str | None
    fencing_high_water: tuple[tuple[str, int], ...]
    restore_gap_digest: str | None
    manifest_digest: str

    @classmethod
    def create(
        cls,
        *,
        installation_id: str,
        generation: int,
        activation_epoch: int,
        repository_id: str,
        repository_digest: str,
        repository_locator_ref: str,
        repository_locator_digest: str,
        release_id: str,
        contract_id: str,
        mode: str,
        previous_manifest_digest: str | None,
        fencing_high_water: tuple[tuple[str, int], ...],
        restore_gap_digest: str | None,
    ) -> ActiveRepositoryManifest:
        if mode not in {"verifying", "active", "blocked"}:
            raise MigrationControlError("active repository manifest mode is invalid")
        if previous_manifest_digest is not None:
            previous_manifest_digest = _digest(previous_manifest_digest, "previous manifest digest")
        if restore_gap_digest is not None:
            restore_gap_digest = _digest(restore_gap_digest, "restore-gap digest")
        if restore_gap_digest is not None and mode == "active":
            raise MigrationControlError("manifest with an open restore gap cannot be active")
        body = {
            "installation_id": _identity(installation_id, "installation ID"),
            "generation": _positive(generation, "manifest generation"),
            "activation_epoch": _positive(activation_epoch, "activation epoch"),
            "repository_id": _identity(repository_id, "repository ID"),
            "repository_digest": _digest(repository_digest, "repository digest"),
            "repository_locator_ref": _identity(repository_locator_ref, "repository locator ref"),
            "repository_locator_digest": _digest(repository_locator_digest, "repository locator digest"),
            "release_id": _identity(release_id, "release ID"),
            "contract_id": _identity(contract_id, "repository contract ID"),
            "mode": mode,
            "previous_manifest_digest": previous_manifest_digest,
            "fencing_high_water": _canonical_fences(fencing_high_water),
            "restore_gap_digest": restore_gap_digest,
        }
        manifest_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:active-repository-manifest",
            projection_id="urn:gew:projection:active-repository-manifest:1.0.0",
            schema_id="urn:gew:schema:active-repository-manifest:1.0.0",
        )
        return cls(**body, manifest_digest=manifest_digest)

    @property
    def ordinary_commands_allowed(self) -> bool:
        return self.mode == "active" and self.restore_gap_digest is None

    def require_successor_of(self, current: ActiveRepositoryManifest) -> None:
        if type(current) is not ActiveRepositoryManifest:
            raise MigrationControlError("manifest predecessor is invalid")
        if self.installation_id != current.installation_id:
            raise MigrationControlError("installation identity changed")
        if self.generation != current.generation + 1 or self.activation_epoch <= current.activation_epoch:
            raise MigrationControlError("manifest generation or activation epoch did not advance")
        if self.previous_manifest_digest != current.manifest_digest:
            raise MigrationControlError("manifest predecessor digest mismatch")
        if self.repository_id == current.repository_id and (
            self.repository_locator_ref != current.repository_locator_ref
            or self.repository_locator_digest != current.repository_locator_digest
        ):
            raise MigrationControlError("repository locator changed without repository identity change")
        current_fences = dict(current.fencing_high_water)
        candidate_fences = dict(self.fencing_high_water)
        if any(candidate_fences.get(resource, 0) < counter for resource, counter in current_fences.items()):
            raise MigrationControlError("manifest lowered installation fencing high-water")

    @classmethod
    def rollback_to(
        cls,
        *,
        current: ActiveRepositoryManifest,
        previous: ActiveRepositoryManifest,
        repository_digest: str,
    ) -> ActiveRepositoryManifest:
        if current.installation_id != previous.installation_id or previous.mode != "active":
            raise MigrationControlError("rollback target is not a verified prior repository")
        if current.previous_manifest_digest != previous.manifest_digest:
            raise MigrationControlError("rollback target is not the exact bound previous manifest")
        fences = dict(previous.fencing_high_water)
        for resource, counter in current.fencing_high_water:
            fences[resource] = max(fences.get(resource, 0), counter)
        return cls.create(
            installation_id=current.installation_id,
            generation=current.generation + 1,
            activation_epoch=current.activation_epoch + 1,
            repository_id=previous.repository_id,
            repository_digest=repository_digest,
            repository_locator_ref=previous.repository_locator_ref,
            repository_locator_digest=previous.repository_locator_digest,
            release_id=previous.release_id,
            contract_id=previous.contract_id,
            mode="active",
            previous_manifest_digest=current.manifest_digest,
            fencing_high_water=tuple(sorted(fences.items())),
            restore_gap_digest=None,
        )


@dataclass(frozen=True, slots=True)
class RepositoryCommandContext:
    """Audit tuple selected while a storage-owned installation scope is held."""

    installation_id: str
    generation: int
    activation_epoch: int
    repository_id: str
    repository_locator_ref: str
    repository_locator_digest: str
    manifest_digest: str

    @classmethod
    def from_active_manifest(
        cls,
        manifest: ActiveRepositoryManifest,
    ) -> RepositoryCommandContext:
        if type(manifest) is not ActiveRepositoryManifest or not manifest.ordinary_commands_allowed:
            raise MigrationControlError("command context requires an exact active manifest")
        return cls(
            installation_id=manifest.installation_id,
            generation=manifest.generation,
            activation_epoch=manifest.activation_epoch,
            repository_id=manifest.repository_id,
            repository_locator_ref=manifest.repository_locator_ref,
            repository_locator_digest=manifest.repository_locator_digest,
            manifest_digest=manifest.manifest_digest,
        )


_MIGRATION_SEQUENCE = (
    "requested", "upgrade_locked", "quiescence_verified", "exported", "imported_isolated",
    "replayed", "compatible", "activation_prepared", "verifying_reference",
    "post_switch_verified", "active", "completed",
)

_MIGRATION_RECOVERY_STATES = frozenset({
    "recovered_old_active", "recovered_rolled_back", "recovered_new_active", "blocked",
})


@dataclass(frozen=True, slots=True)
class MigrationState:
    migration_id: str
    source_manifest_digest: str
    state: str
    revision: int

    @classmethod
    def start(cls, migration_id: str, source: ActiveRepositoryManifest) -> MigrationState:
        if type(source) is not ActiveRepositoryManifest or not source.ordinary_commands_allowed:
            raise MigrationControlError("migration source must be verified active")
        return cls(_identity(migration_id, "migration ID"), source.manifest_digest, "requested", 1)

    def advance(self, target: str) -> MigrationState:
        try:
            current_index = _MIGRATION_SEQUENCE.index(self.state)
            target_index = _MIGRATION_SEQUENCE.index(target)
        except ValueError as error:
            raise MigrationControlError("unknown migration state") from error
        if target_index != current_index + 1:
            raise MigrationControlError("migration transition is not the unique next state")
        return replace(self, state=target, revision=self.revision + 1)

    def recover(self, target: str) -> MigrationState:
        if self.state in _MIGRATION_RECOVERY_STATES or self.state == "completed":
            raise MigrationControlError("completed migration state cannot be recovered again")
        if target not in _MIGRATION_RECOVERY_STATES:
            raise MigrationControlError("migration recovery outcome is invalid")
        return replace(self, state=target, revision=self.revision + 1)


@dataclass(frozen=True, slots=True)
class RestoreGap:
    gap_id: str
    source_manifest_digest: str
    restored_manifest_digest: str
    resources: tuple[tuple[str, int], ...]
    authority_digest: str | None
    state: str
    gap_digest: str

    @classmethod
    def create(
        cls,
        *,
        gap_id: str,
        source_manifest_digest: str,
        restored_manifest_digest: str,
        resources: tuple[tuple[str, int], ...],
    ) -> RestoreGap:
        body = {
            "gap_id": _identity(gap_id, "restore-gap ID"),
            "source_manifest_digest": _digest(source_manifest_digest, "source manifest digest"),
            "restored_manifest_digest": _digest(restored_manifest_digest, "restored manifest digest"),
            "resources": _canonical_fences(resources),
            "authority_digest": None,
            "state": "open",
        }
        gap_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:restore-gap",
            projection_id="urn:gew:projection:restore-gap:1.0.0",
            schema_id="urn:gew:schema:restore-gap:1.0.0",
        )
        return cls(**body, gap_digest=gap_digest)

    @property
    def external_actions_allowed(self) -> bool:
        return self.state == "reconciled" and self.authority_digest is not None

    def reconcile(
        self,
        fences: tuple[tuple[str, int], ...],
        *,
        authority_digest: str | None,
    ) -> RestoreGap:
        if self.state != "open" or authority_digest is None:
            raise MigrationControlError("restore gap requires fresh action reauthorization")
        authority_digest = _digest(authority_digest, "restore-gap authority digest")
        candidate = dict(_canonical_fences(fences))
        if set(candidate) != {resource for resource, _ in self.resources}:
            raise MigrationControlError("restore-gap resource set changed")
        if any(candidate[resource] <= counter for resource, counter in self.resources):
            raise MigrationControlError("restore-gap fences must exceed installation high-water")
        body = {
            "gap_id": self.gap_id,
            "source_manifest_digest": self.source_manifest_digest,
            "restored_manifest_digest": self.restored_manifest_digest,
            "resources": tuple(sorted(candidate.items())),
            "authority_digest": authority_digest,
            "state": "reconciled",
        }
        gap_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:restore-gap",
            projection_id="urn:gew:projection:restore-gap:1.0.0",
            schema_id="urn:gew:schema:restore-gap:1.0.0",
        )
        return RestoreGap(**body, gap_digest=gap_digest)


def select_committed_manifest(
    candidates: tuple[ActiveRepositoryManifest, ...],
) -> ActiveRepositoryManifest:
    if type(candidates) is not tuple or not candidates or any(type(item) is not ActiveRepositoryManifest for item in candidates):
        raise MigrationControlError("manifest candidates are invalid")
    installations = {item.installation_id for item in candidates}
    if (
        len(installations) != 1
        or len({item.generation for item in candidates}) != len(candidates)
        or len({item.activation_epoch for item in candidates}) != len(candidates)
    ):
        raise MigrationControlError("manifest candidates conflict")
    ordered = tuple(sorted(candidates, key=lambda item: item.generation))
    if ordered[0].previous_manifest_digest is not None:
        raise MigrationControlError("manifest chain has no trusted root")
    for previous, current in zip(ordered, ordered[1:]):
        current.require_successor_of(previous)
    usable = [item for item in candidates if item.mode in {"active", "blocked"}]
    if not usable:
        raise MigrationControlError("no verified active or explicit blocked manifest exists")
    return max(usable, key=lambda item: item.generation)
