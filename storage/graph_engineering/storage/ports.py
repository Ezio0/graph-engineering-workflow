"""Backend-neutral repository commands and results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CommitBatch:
    transaction_id: str
    task_id: str
    expected_task_revision: int
    events: tuple[dict[str, object], ...]
    snapshot: dict[str, object]
    catalog_delta: dict[str, object]
    lease_assertion: dict[str, object]
    object_digests: tuple[str, ...] = ()
    claim_delta: dict[str, object] | None = None
    claim_reconciliation_delta: dict[str, object] | None = None
    claim_compensation_delta: dict[str, object] | None = None
    action_journal_delta: dict[str, object] | None = None
    project_scope_delta: dict[str, object] | None = None
    lifecycle_assertion: dict[str, object] | None = None
    lifecycle_plan_delta: dict[str, object] | None = None
    scope_graph_definition: object | None = None
    concrete_action_delta: dict[str, object] | None = None
    extension_pin_delta: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class CommitResult:
    status: str
    revision: int
    head_digest: str


@dataclass(frozen=True, slots=True)
class LeaseGrant:
    lease_id: str
    resources: tuple[str, ...]
    fencing_tokens: tuple[tuple[str, int], ...]
    heartbeat_revision: int
    expires_at: int


class TaskRepositoryPort(Protocol):
    def load(self, task_id: str) -> dict[str, object]: ...

    def commit(self, batch: CommitBatch) -> CommitResult: ...

    def replay(self, task_id: str) -> tuple[dict[str, object], ...]: ...

    def referenced_objects(self, task_id: str) -> tuple[tuple[str, bytes], ...]: ...

    def recover(self, transaction_id: str) -> CommitResult | None: ...

    def lifecycle_facts(self, task_id: str) -> dict[str, object]: ...

    def project_scope_change(
        self, task_id: str, candidate: object, graph: object | None = None,
    ) -> dict[str, object]: ...

    def load_for_extension_rebase(
        self, task_id: str, new_pin_digest: str,
    ) -> dict[str, object]: ...

    def replay_for_extension_rebase(
        self, task_id: str, new_pin_digest: str,
    ) -> tuple[dict[str, object], ...]: ...


class ObjectRepositoryPort(Protocol):
    def put_verified(self, body: bytes, object_digest: str) -> None: ...

    def get(self, object_digest: str, *, require_referenced: bool = True) -> bytes: ...

    def quarantine(self, object_digest: str) -> None: ...

    def purge(self, object_digest: str) -> bool: ...


class TaskCatalogPort(Protocol):
    def query_catalog(self, filters: dict[str, object]) -> tuple[dict[str, object], ...]: ...


class ResourceLeaseRepositoryPort(Protocol):
    def acquire_many(
        self,
        *,
        lease_id: str,
        task_id: str,
        run_id: str,
        operation_id: str,
        resources: tuple[str, ...],
        ttl_ns: int,
    ) -> LeaseGrant: ...

    def validate_fence(
        self,
        *,
        lease_id: str,
        resource_id: str,
        fencing_token: int,
    ) -> bool: ...

    def release(self, lease_id: str) -> None: ...


class MigrationRepositoryPort(Protocol):
    def export_bundle(self, scope: dict[str, object]) -> dict[str, object]: ...

    def validate_bundle(self, bundle: dict[str, object]) -> dict[str, object]: ...

    def import_bundle(self, bundle: dict[str, object]) -> dict[str, object]: ...
