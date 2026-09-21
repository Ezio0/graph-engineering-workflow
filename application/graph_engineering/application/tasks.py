"""Task commands and read-only queries over the durable repository ports."""

from __future__ import annotations

import hashlib
import copy
import os
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.graph.state import (
    DomainEvent,
    TaskCommand,
    TaskSnapshot,
    TASK_TRANSITIONS,
    apply_events,
    decide_command,
)
from graph_engineering.core.project import ProjectScope
from graph_engineering.core.actions import PreparedAction
from graph_engineering.storage.ports import (
    CommitBatch,
    ResourceLeaseRepositoryPort,
    TaskCatalogPort,
    TaskRepositoryPort,
)
from graph_engineering.storage.repository import make_event
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.codec import semantic_record_digest

if TYPE_CHECKING:
    from graph_engineering.application.completion import CompletionDecision, CompletionGate
    from graph_engineering.application.runner import ApplicationRunner, ReviewResult
    from graph_engineering.core.artifacts.records import ArtifactRecord
    from graph_engineering.core.graph.budget import LoopBudgetRegistry
    from graph_engineering.core.graph.definition import GraphDefinition
    from graph_engineering.core.profiles import MaterializedProfileGraph
    from graph_engineering.storage.ports import ObjectRepositoryPort


class ApplicationError(ValueError):
    """A stable fail-closed application command or query rejection."""


def action_task_snapshot(
    snapshot: Mapping[str, object],
    *,
    task_id: str,
    revision: int,
    action_state: str,
) -> dict[str, object]:
    """Advance repository state without adding action fields to domain state."""

    if (
        not isinstance(snapshot, Mapping)
        or type(revision) is not int or revision < 1
        or type(snapshot.get("revision")) is not int
        or snapshot.get("revision") != revision or snapshot.get("task_id") != task_id
    ):
        raise ApplicationError("action snapshot head binding is invalid")
    domain_task = "domain" in snapshot or "runner" in snapshot
    if domain_task:
        domain = snapshot.get("domain")
        if (
            set(snapshot) != {"task_id", "revision", "domain", "runner"}
            or not isinstance(snapshot.get("runner"), Mapping)
            or not isinstance(domain, Mapping)
            or not isinstance(domain.get("identity"), Mapping)
            or domain["identity"].get("task_id") != task_id
            or type(domain.get("task_revision")) is not int
            or domain["task_revision"] < 1
            or type(domain.get("last_event_seq")) is not int
            or domain["last_event_seq"] != domain["task_revision"]
        ):
            raise ApplicationError("action domain snapshot wrapper is invalid")
    result = thaw(freeze(snapshot))
    assert type(result) is dict
    result.update(task_id=task_id, revision=revision + 1)
    if not domain_task:
        result["action_state"] = action_state
    return result


@dataclass(frozen=True, slots=True, init=False)
class RepositoryIdentityObservation:
    resolver_id: str
    scope_digest: str
    binding_id: str
    planned_target_id: str
    locator_ref: str
    allowed_path_boundary: str
    observed_path_boundary: str
    actual_git_identity: str
    observed_at: str
    observation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("repository identity observations are resolver-issued")

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class CanonicalGitIdentityResolver:
    """Platform-neutral trust boundary around one configured Git identity adapter."""

    def __init__(
        self,
        resolver_id: str,
        resolve: Callable[[str, str], Mapping[str, object]],
    ) -> None:
        if type(resolver_id) is not str or not resolver_id or not callable(resolve):
            raise ApplicationError("Git identity resolver configuration is invalid")
        self._resolver_id = resolver_id
        self._resolve = resolve
        self._issued: dict[int, RepositoryIdentityObservation] = {}

    def observe_source(
        self,
        source: Mapping[str, object],
        binding_id: str,
    ) -> RepositoryIdentityObservation:
        repositories = source.get("repositories")
        binding = next(
            (item for item in repositories if isinstance(item, Mapping) and item.get("binding_id") == binding_id),
            None,
        ) if isinstance(repositories, list) else None
        if not isinstance(binding, Mapping) or binding.get("mode") != "create_new":
            raise ApplicationError("repository realization does not name an approved new repository")
        locator = binding.get("locator_ref")
        boundary = binding.get("allowed_path_boundary")
        planned = binding.get("planned_target_id")
        if any(type(item) is not str or not item for item in (locator, boundary, planned)):
            raise ApplicationError("approved repository realization binding is invalid")
        raw = self._resolve(locator, boundary)  # type: ignore[arg-type]
        if not isinstance(raw, Mapping) or set(raw) != {
            "actual_git_identity", "observed_path_boundary", "observed_at",
        }:
            raise ApplicationError("Git resolver observation is not exact")
        actual = raw.get("actual_git_identity")
        observed_boundary = raw.get("observed_path_boundary")
        observed_at = raw.get("observed_at")
        if (
            type(actual) is not str or not actual
            or observed_boundary != boundary
            or type(observed_at) is not str or not observed_at
        ):
            raise ApplicationError("Git resolver observation violates the approved path boundary")
        body = {
            "resolver_id": self._resolver_id, "scope_digest": source.get("scope_digest"),
            "binding_id": binding_id, "planned_target_id": planned, "locator_ref": locator,
            "allowed_path_boundary": boundary, "observed_path_boundary": observed_boundary,
            "actual_git_identity": actual, "observed_at": observed_at,
        }
        observation = object.__new__(RepositoryIdentityObservation)
        for name, value in body.items():
            object.__setattr__(observation, name, value)
        object.__setattr__(
            observation, "observation_digest",
            TaskRepository.identity_observation_digest(body),
        )
        self._issued[id(observation)] = observation
        return observation

    def observe(self, scope: ProjectScope, binding_id: str) -> RepositoryIdentityObservation:
        if type(scope) is not ProjectScope:
            raise ApplicationError("ProjectScope is missing or forged")
        return self.observe_source(scope.to_dict(), binding_id)

    def require_issued(self, observation: RepositoryIdentityObservation) -> None:
        if self._issued.get(id(observation)) is not observation:
            raise ApplicationError("repository identity observation was not issued by this resolver")


class _TransitionAuthority:
    """Opaque, application-issued authority for one exact internal transition."""

    __slots__ = ()

    def __new__(cls) -> _TransitionAuthority:
        raise TypeError("transition authorities are issued only by TaskApplication")


class _RunnerTransitionChannel:
    """Factory-only channel that never reveals the one-use transition authority."""

    __slots__ = ("__application",)

    def __new__(cls) -> _RunnerTransitionChannel:
        raise TypeError("runner transition channels are factory-only")

    def commit(
        self,
        task_id: str,
        source_snapshot_digest: str,
        events: tuple[DomainEvent, ...],
        runner_state: Mapping[str, object],
        runtime: RuntimeContext,
        *,
        operation_id: str,
        object_digests: tuple[str, ...] = (),
    ) -> CommandReceipt:
        return self.__application._commit_from_runner_channel(
            self,
            task_id,
            source_snapshot_digest,
            events,
            runner_state,
            runtime,
            operation_id=operation_id,
            object_digests=object_digests,
        )

    def record_review(
        self,
        task_id: str,
        source_snapshot_digest: str,
        run_id: str,
        result: ReviewResult,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        return self.__application._record_review_from_runner_channel(
            self, task_id, source_snapshot_digest, run_id, result, runtime,
        )

    def pass_review(
        self,
        task_id: str,
        source_snapshot_digest: str,
        run_id: str,
        graph: GraphDefinition,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        return self.__application._pass_review_from_runner_channel(
            self, task_id, source_snapshot_digest, run_id, graph, runtime,
        )

    def show(self, task_id: str) -> TaskView:
        return self.__application._show_from_runner_channel(self, task_id)


_ISSUED_RUNTIME_CONTEXTS: dict[
    int, tuple["RuntimeContext", int, int, Callable[[], None]]
] = {}


@dataclass(frozen=True, slots=True, init=False)
class RuntimeContext:
    owner_id: str
    runtime_kind: str
    runtime_lineage_id: str
    actor_id: str
    occurred_at: str
    lease_ttl_ns: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("runtime contexts are issued only by an established runtime session")

    def _validate(self) -> None:
        identities = (
            self.owner_id,
            self.runtime_kind,
            self.runtime_lineage_id,
            self.actor_id,
            self.occurred_at,
        )
        if any(type(item) is not str or not item or item != item.strip() for item in identities):
            raise ApplicationError("runtime context identities must be non-empty canonical strings")
        if type(self.lease_ttl_ns) is not int or self.lease_ttl_ns <= 0:
            raise ApplicationError("runtime lease TTL must be a positive exact integer")

    def require_issued(self) -> None:
        issued = _ISSUED_RUNTIME_CONTEXTS.get(id(self))
        if (
            issued is None or issued[0] is not self
            or issued[1] != os.getpid() or issued[2] != threading.get_ident()
        ):
            raise ApplicationError("runtime context is missing, foreign, or expired")
        try:
            issued[3]()
        except Exception as error:
            raise ApplicationError("runtime context is missing, foreign, or expired") from error


@dataclass(frozen=True, slots=True)
class CommandReceipt:
    request_id: str
    task_id: str
    lifecycle: str
    task_revision: int
    repository_revision: int
    head_digest: str
    snapshot_digest: str
    event_types: tuple[str, ...]
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class TaskView:
    task_id: str
    repository_revision: int
    snapshot: TaskSnapshot
    runner_state: Mapping[str, object]


class TaskApplication:
    """Own the command transaction boundary without embedding backend policy."""

    _WRAPPER_FIELDS = frozenset({"task_id", "revision", "domain", "runner"})
    _RUNNER_FIELDS = frozenset({
        "schema_version", "runtime_lineage_id", "graph_digest", "node_outputs",
        "selected_edges", "failure_routes", "findings", "review_history",
    })
    _RUNNER_EVENT_TYPES = frozenset({
        "node.run_created", "node.ready", "node.leased", "node.started",
        "node.output_produced", "node.validation_started", "node.review_started",
        "node.review_recorded", "node.passed", "node.revise_requested",
        "node.awaiting_human", "node.blocked", "finding.opened", "finding.closed",
        "task.human_decision_required", "task.blocked", "task.completion_started",
    })
    _ACTION_EVENT_TYPES = frozenset({
        "action.execution_started", "action.receipt_recorded",
        "action.reconciled_effect_verified", "action.reconciled_no_effect",
        "action.compensation_execution_started", "action.compensation_receipt_recorded",
        "action.compensation_reconciled",
    })

    @classmethod
    def _repository_sequence(
        cls, view: TaskView, replay: tuple[dict[str, object], ...],
    ) -> int:
        """Join verified repository ordinals to unchanged domain ordinals."""

        domain_types = {kind for _state, kind in TASK_TRANSITIONS} | cls._RUNNER_EVENT_TYPES
        domain_count = 0
        previous_revision = -1
        previous_action = False
        for sequence, event in enumerate(replay, start=1):
            revision = event.get("expected_task_revision")
            kind = event.get("event_type")
            is_action = kind in cls._ACTION_EVENT_TYPES
            if (
                event.get("task_id") != view.task_id
                or type(event.get("sequence")) is not int or event["sequence"] != sequence
                or type(revision) is not int or revision not in {previous_revision, previous_revision + 1}
                or revision < 0
                or kind not in domain_types | cls._ACTION_EVENT_TYPES
                or revision == previous_revision and (is_action or previous_action)
            ):
                raise ApplicationError("repository/domain event mapping is invalid")
            domain_count += int(not is_action)
            previous_revision, previous_action = revision, is_action
        if (
            not replay or domain_count < 1
            or previous_revision + 1 != view.repository_revision
            or domain_count != view.snapshot.task_revision
            or domain_count != view.snapshot.last_event_seq
        ):
            raise ApplicationError("repository/domain event mapping is stale")
        return len(replay)

    def __init__(
        self,
        repository: TaskRepositoryPort,
        catalog: TaskCatalogPort,
        leases: ResourceLeaseRepositoryPort,
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        project_resolver: CanonicalGitIdentityResolver | None = None,
        materialization_objects: ObjectRepository | None = None,
    ) -> None:
        if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
            raise ApplicationError("application requires attested contracts and work context")
        if (
            type(repository) is not TaskRepository
            or catalog is not repository
            or not repository.command_context_bound
        ):
            raise ApplicationError("application requires the routed installation command repository")
        self._repository = repository
        self._catalog = catalog
        self._leases = leases
        self._schemas = schema_registry
        self._context = context
        if project_resolver is not None and type(project_resolver) is not CanonicalGitIdentityResolver:
            raise ApplicationError("project resolver is missing or forged")
        self._project_resolver = project_resolver
        if materialization_objects is not None and type(materialization_objects) is not ObjectRepository:
            raise ApplicationError("materialization object repository is missing or forged")
        self._materialization_objects = materialization_objects
        self.__transition_authorities: dict[
            _TransitionAuthority,
            tuple[str, str, str, str, tuple[str, ...]],
        ] = {}
        self.__runner_channels: set[_RunnerTransitionChannel] = set()
        self.__materialization_references: dict[int, tuple[object, bytes]] = {}

    def preauthorize_materialization(self, record: object) -> object:
        """Publish an issued record and return this repository's opaque authority proof."""

        from graph_engineering.core.profiles import (
            MaterializationRecord,
            ProfileContractError,
            UntrustedMaterializationRecord,
        )

        if self._materialization_objects is None or type(record) is not MaterializationRecord:
            raise ApplicationError("materialization persistence authority is unavailable")
        try:
            record.require_issued()
            body = record.to_bytes()
        except ProfileContractError as error:
            raise ApplicationError("materialization record is missing or forged") from error
        self._materialization_objects.put_verified(body, record.object_digest)
        reread = self._materialization_objects.get(
            record.object_digest, require_referenced=False,
        )
        parsed = UntrustedMaterializationRecord.from_persisted_bytes(
            reread, expected_object_digest=record.object_digest,
        )
        if (
            parsed.graph_ref_body != record.graph_ref_body
            or parsed.loop_budget_registry_id != record.loop_budget_registry_id
            or parsed.loop_budget_registry_digest != record.loop_budget_registry_digest
        ):
            raise ApplicationError("published materialization record changed")
        return self._issue_materialization_reference(parsed, reread)

    def _issue_materialization_reference(self, parsed: object, body: bytes) -> object:
        from graph_engineering.core.profiles import (
            MaterializationObjectReference,
            UntrustedMaterializationRecord,
        )

        if type(parsed) is not UntrustedMaterializationRecord or type(body) is not bytes:
            raise ApplicationError("materialization object data is not exact")
        reference = object.__new__(MaterializationObjectReference)
        for name, item in (
            ("graph_ref_body", parsed.graph_ref_body),
            ("record_digest", parsed.record_digest),
            ("object_digest", parsed.object_digest),
            ("_authority", self),
        ):
            object.__setattr__(reference, name, item)
        self.__materialization_references[id(reference)] = (reference, body)
        return reference

    def _require_materialization_reference(
        self, reference: object, graph_ref: object,
    ) -> Mapping[str, object]:
        from graph_engineering.core.profiles import (
            MaterializationObjectReference,
            ProfileContractError,
            UntrustedMaterializationRecord,
        )

        if type(reference) is not MaterializationObjectReference:
            raise ProfileContractError("materialization object reference is forged")
        if reference._authority is not self:
            raise ProfileContractError("materialization object reference authority is foreign")
        issued = self.__materialization_references.get(id(reference))
        if issued is None or issued[0] is not reference:
            raise ProfileContractError("materialization object reference is not factory-issued")
        if self._materialization_objects is None:
            raise ProfileContractError("materialization object repository is unavailable")
        try:
            body = self._materialization_objects.get(
                reference.object_digest, require_referenced=False,
            )
            parsed = UntrustedMaterializationRecord.from_persisted_bytes(
                body, expected_object_digest=reference.object_digest,
            )
        except Exception as error:
            raise ProfileContractError("materialization object is unavailable or stale") from error
        if body != issued[1] or parsed.graph_ref_body != reference.graph_ref_body:
            raise ProfileContractError("materialization object reference binding changed")
        if not isinstance(graph_ref, Mapping) or freeze(graph_ref) != reference.graph_ref_body:
            raise ProfileContractError("materialized graph ref differs from its object authority")
        return graph_ref

    def _materialization_for_graph_ref(
        self,
        task_id: str,
        graph_ref: object,
    ) -> object | None:
        if not isinstance(graph_ref, Mapping) or "materialization_digest" not in graph_ref:
            return None
        from graph_engineering.core.profiles import (
            ProfileContractError,
            UntrustedMaterializationRecord,
        )

        parsed_records: list[tuple[UntrustedMaterializationRecord, bytes]] = []
        for digest, body in self._repository.referenced_objects(task_id):
            try:
                record = UntrustedMaterializationRecord.from_persisted_bytes(
                    body, expected_object_digest=digest,
                )
            except ProfileContractError:
                continue
            parsed_records.append((record, body))
        matches = [
            item for item in parsed_records if item[0].graph_ref_body == freeze(graph_ref)
        ]
        if len(parsed_records) != 1 or len(matches) != 1:
            raise ApplicationError("materialized graph authority is absent, duplicated, or stale")
        return self._issue_materialization_reference(matches[0][0], matches[0][1])

    @staticmethod
    def _identity(value: object, label: str) -> str:
        if type(value) is not str or not value or value != value.strip() or "\x00" in value:
            raise ApplicationError(f"{label} is invalid")
        return value

    @classmethod
    def _request_id(
        cls,
        task_id: str,
        command: TaskCommand,
        runtime: RuntimeContext,
    ) -> str:
        runtime.require_issued()
        request = {
            "contract": "application-command-v1",
            "task_id": task_id,
            "command": {
                "command_type": command.command_type,
                "expected_task_revision": command.expected_task_revision,
                "payload": dict(command.payload),
            },
            "runtime": {
                "owner_id": runtime.owner_id,
                "runtime_kind": runtime.runtime_kind,
                "runtime_lineage_id": runtime.runtime_lineage_id,
                "actor_id": runtime.actor_id,
                "occurred_at": runtime.occurred_at,
            },
        }
        return "application-command-sha256:" + hashlib.sha256(canonical_bytes(request)).hexdigest()

    def _task_wrapper(self, value: object) -> tuple:
        if not isinstance(value, Mapping) or set(value) != self._WRAPPER_FIELDS:
            raise ApplicationError("repository task snapshot wrapper is not exact")
        task_id = self._identity(value.get("task_id"), "task ID")
        revision = value.get("revision")
        if type(revision) is not int or revision < 1:
            raise ApplicationError("repository revision is invalid")
        runner = value.get("runner")
        if not isinstance(runner, Mapping) or set(runner) != self._RUNNER_FIELDS:
            raise ApplicationError("runner snapshot is not exact")
        if (
            runner.get("schema_version") != "1.0.0"
            or type(runner.get("runtime_lineage_id")) is not str
            or runner.get("graph_digest") is not None
            and type(runner.get("graph_digest")) is not str
            or not isinstance(runner.get("node_outputs"), Mapping)
            or type(runner.get("selected_edges")) is not list
            or not isinstance(runner.get("failure_routes"), Mapping)
            or not isinstance(runner.get("findings"), Mapping)
            or type(runner.get("review_history")) is not list
        ):
            raise ApplicationError("runner snapshot fields are invalid")
        domain = value.get("domain")
        if not isinstance(domain, Mapping):
            raise ApplicationError("domain snapshot is not an object")
        return task_id, revision, runner, domain

    def _view_with_materialization(self, task_id, revision, runner, domain, materialization_record):
        snapshot = TaskSnapshot.from_dict(
            domain,
            schema_registry=self._schemas,
            context=self._context,
            materialization_record=materialization_record,
        )
        if snapshot.identity.get("task_id") != task_id:
            raise ApplicationError("repository and domain task identities differ")
        return TaskView(task_id, revision, snapshot, runner)

    def _restore(self, value: object) -> TaskView:
        task_id, revision, runner, domain = self._task_wrapper(value)
        materialization_record = self._materialization_for_graph_ref(
            task_id, domain.get("graph_ref"),
        )
        return self._view_with_materialization(task_id, revision, runner, domain, materialization_record)

    @contextmanager
    def _cold_task_view(self, capture, *, policy, runtime):
        """Validate the owned capture without resolving or issuing authority."""
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.core.profile_execution import CategoryExecutionPolicy
        from dataclasses import fields
        from graph_engineering.core.graph.state import NodeRun, ArtifactRef, EvidenceRef
        from graph_engineering.storage.repository import (
            _RecoveryReadBudget, _recovery_adopt, _recovery_clear_exception_frames,
        )

        budget = getattr(self._context, "_recovery_read_budget", None)
        if (type(budget) is not _RecoveryReadBudget
                or type(policy) is not CategoryExecutionPolicy or type(runtime) is not RuntimeContext
                or any(getattr(port, "_recovery_read_budget", None) is not budget
                       for port in (self, self._repository, self._materialization_objects))
                or budget.command_scope is not self._repository.command_scope):
            raise ApplicationError("cold task view has no exact installed participants")
        budget._require_active()
        owned = budget._projections.get(id(capture))
        if (owned is None or owned[0] is not capture or capture.get("phase") != "sources"
                or capture["task"]["task_id"] != budget.task_id):
            raise ApplicationError("cold task view requires its owned source capture")
        record = policy.materialization_record
        size = (canonical_byte_length(capture["snapshot"]) + canonical_byte_length(capture["events"])
                + canonical_byte_length(record.graph_ref_body) + canonical_byte_length(record.output_body) + 512)
        view = None
        try:
            with budget.reserve(self._context, units=8 * size, byte_count=4 * size,
                                source_id="cold-task-view") as frame:
                record.require_issued()
                matches = [body for ref, body in capture["objects"] if ref == record.object_digest]
                if len(matches) != 1 or matches[0] != record.to_bytes():
                    raise ApplicationError("cold task materialization is absent, ambiguous or changed")
                value = thaw(capture["snapshot"])
                task_id, revision, runner, domain = self._task_wrapper(value)
                view = self._view_with_materialization(task_id, revision, runner, domain, record)
                self._runtime_matches(view.snapshot, runtime)
                if (runner["runtime_lineage_id"] != runtime.runtime_lineage_id
                        or runner["graph_digest"] != record.graph_ref_body["graph_digest"]):
                    raise ApplicationError("cold runner lineage or materialization differs")
                self._repository_sequence(view, tuple(thaw(item["event"]) for item in capture["events"]))
                replayed = None
                ordinal = 0
                for row in capture["events"]:
                    raw = row["event"]
                    if raw["event_type"] in self._ACTION_EVENT_TYPES:
                        continue
                    ordinal += 1
                    replayed = apply_events(replayed, (DomainEvent(ordinal, ordinal - 1,
                        raw["event_type"], thaw(raw["payload"])),), schema_registry=self._schemas,
                        context=self._context, materialization_record=record)
                if replayed is None or replayed.snapshot_digest != view.snapshot.snapshot_digest:
                    raise ApplicationError("cold domain replay differs from the captured snapshot")
                # Retire replay intermediates before the view escapes. The parsed
                # view itself remains covered until its exact graph is adopted.
                matches = value = runner = domain = replayed = raw = None
                frame.shrink(units=2 * size, byte_count=size)
                _recovery_adopt(view, self._context, budget,
                    record_fields={kind: tuple(field.name for field in fields(kind))
                        for kind in (TaskView, TaskSnapshot, NodeRun, ArtifactRef, EvidenceRef)},
                    source_id="cold-task-view-result")
            yield view
        except BaseException as error:
            _recovery_clear_exception_frames(error)
            raise
        finally:
            if view is not None and id(view) in budget._projections:
                budget.release_projection(view)
            self = capture = policy = runtime = record = view = budget = None
            matches = value = runner = domain = replayed = raw = None

    @staticmethod
    def _runner_state(snapshot: TaskSnapshot, runtime: RuntimeContext) -> dict[str, object]:
        graph_digest = snapshot.graph_ref.get("graph_digest") if snapshot.graph_ref else None
        return {
            "schema_version": "1.0.0",
            "runtime_lineage_id": runtime.runtime_lineage_id,
            "graph_digest": graph_digest,
            "node_outputs": {},
            "selected_edges": [],
            "failure_routes": {},
            "findings": {},
            "review_history": [],
        }

    @staticmethod
    def _runtime_matches(snapshot: TaskSnapshot, runtime: RuntimeContext) -> None:
        runtime.require_issued()
        identity = snapshot.identity
        if (
            identity.get("owner_id") != runtime.owner_id
            or identity.get("runtime_kind") != runtime.runtime_kind
            or identity.get("runtime_lineage_id") != runtime.runtime_lineage_id
        ):
            raise ApplicationError("runtime owner or lineage does not match the task")

    def _validate_lifecycle_preconditions(
        self,
        task_id: str,
        snapshot: TaskSnapshot,
        command: TaskCommand,
        lifecycle_plan_delta: dict[str, object] | None = None,
    ) -> dict[str, object]:
        facts = self._repository.lifecycle_facts(task_id)
        durable_claims = facts.get("unresolved_claims")
        durable_leases = facts.get("live_leases")
        if (
            type(durable_claims) is not tuple
            or type(durable_leases) is not tuple
            or tuple(snapshot.unresolved_action_claims) != durable_claims
            or tuple(snapshot.resource_leases) != durable_leases
        ):
            raise ApplicationError("durable lifecycle coordination differs from the task snapshot")
        if command.command_type == "rollback":
            requested = command.payload.get("compensable_action_refs")
            if requested != facts.get("compensable_action_refs"):
                raise ApplicationError("rollback compensable action set is not exact and current")
            authority = command.payload.get("authority_ref")
            if type(authority) is not str or authority not in snapshot.authorities:
                raise ApplicationError("rollback authority is not active for the task")
        elif command.command_type == "archive":
            if lifecycle_plan_delta is None or (
                command.payload.get("retention_plan_ref") != facts.get("retention_plan_ref")
                or command.payload.get("rollback_clearance_ref") != facts.get("rollback_clearance_ref")
                or facts.get("retention_plan_ref") is None
            ):
                if lifecycle_plan_delta is None:
                    raise ApplicationError("archive retention or rollback clearance is not exact and current")
        return facts

    def __show(self, task_id: str) -> TaskView:
        """Load and verify one task without acquiring a write lease."""

        task_id = self._identity(task_id, "task ID")
        view = self._restore(self._repository.load(task_id))
        self._repository_sequence(view, self._repository.replay(task_id))
        realizations = self._repository.project_realizations(task_id) if view.snapshot.project_scope_ref else ()
        if realizations:
            if self._project_resolver is None:
                raise ApplicationError("repository realization requires a fresh configured Git resolver")
            state = self._repository.project_scope_state(task_id)
            source = state.get("source")
            if not isinstance(source, Mapping):
                raise ApplicationError("durable ProjectScope source is invalid")
            for realization in realizations:
                durable = realization.get("observation")
                current = self._project_resolver.observe_source(source, realization["binding_id"])  # type: ignore[arg-type]
                fields = {
                    "resolver_id", "scope_digest", "binding_id", "planned_target_id", "locator_ref",
                    "allowed_path_boundary", "observed_path_boundary", "actual_git_identity",
                }
                if not isinstance(durable, Mapping) or any(
                    durable.get(field) != getattr(current, field) for field in fields
                ):
                    raise ApplicationError("fresh Git resolver identity differs from durable realization")
        return view

    def show(self, task_id: str) -> TaskView:
        del task_id
        raise ApplicationError("runtime query authority is required")

    def search(self, filters: Mapping[str, object] | None = None) -> tuple[dict[str, object], ...]:
        del filters
        raise ApplicationError("runtime query authority is required")

    def list(self) -> tuple[dict[str, object], ...]:
        raise ApplicationError("runtime query authority is required")

    def runtime_show(self, task_id: str, runtime: RuntimeContext) -> TaskView:
        runtime.require_issued()
        view = self.__show(task_id)
        identity = view.snapshot.identity
        if (
            identity.get("owner_id") != runtime.owner_id
            or identity.get("runtime_kind") != runtime.runtime_kind
            or identity.get("runtime_lineage_id") != runtime.runtime_lineage_id
        ):
            raise ApplicationError("runtime query is not authorized")
        return view

    def runtime_search(
        self,
        filters: Mapping[str, object] | None,
        runtime: RuntimeContext,
    ) -> tuple[dict[str, object], ...]:
        """Return only the exact live session's catalog projection."""

        runtime.require_issued()
        query = {} if filters is None else dict(filters)
        protected = {
            "owner_id": runtime.owner_id,
            "runtime_kind": runtime.runtime_kind,
            "runtime_lineage_id": runtime.runtime_lineage_id,
        }
        if any(key in query and query[key] != value for key, value in protected.items()):
            raise ApplicationError("runtime query is not authorized")
        query.update(protected)
        return self._catalog.query_catalog(query)

    def _show_from_runner_channel(
        self, channel: _RunnerTransitionChannel, task_id: str,
    ) -> TaskView:
        if channel not in self.__runner_channels:
            raise ApplicationError("runner query channel is invalid")
        return self.__show(task_id)

    def create_runner(
        self,
        objects: ObjectRepositoryPort,
        loop_budgets: LoopBudgetRegistry,
        *,
        context: WorkContext,
        materialization: MaterializedProfileGraph | None = None,
    ) -> ApplicationRunner:
        """Create the only supported runner binding without exposing its authority."""

        from graph_engineering.application.runner import ApplicationRunner
        from graph_engineering.core.profiles import (
            MaterializedProfileGraph,
            ProfileContractError,
        )

        if materialization is not None:
            if type(materialization) is not MaterializedProfileGraph:
                raise ApplicationError("runner materialization must be factory-issued")
            try:
                materialization.require_loop_budget_registry(loop_budgets)
            except ProfileContractError as error:
                raise ApplicationError(
                    "runner materialized loop budget authority changed"
                ) from error

        channel = object.__new__(_RunnerTransitionChannel)
        channel._RunnerTransitionChannel__application = self
        runner = ApplicationRunner(
            self,
            objects,
            loop_budgets,
            context=context,
            materialization=materialization,
            _channel=channel,
        )
        if materialization is not None:
            try:
                materialization.require_loop_budget_registry(loop_budgets)
            except ProfileContractError as error:
                raise ApplicationError(
                    "runner materialized loop budget authority changed before channel install"
                ) from error
        self.__runner_channels.add(channel)
        return runner

    def _commit_from_runner_channel(
        self,
        channel: _RunnerTransitionChannel,
        task_id: str,
        source_snapshot_digest: str,
        events: tuple[DomainEvent, ...],
        runner_state: Mapping[str, object],
        runtime: RuntimeContext,
        *,
        operation_id: str,
        object_digests: tuple[str, ...] = (),
    ) -> CommandReceipt:
        """Mint and consume a runner authority without returning it to the caller."""

        if channel not in self.__runner_channels:
            raise ApplicationError("runner transition channel is not registered")
        if type(events) is not tuple or not events:
            raise ApplicationError("runner transition events are invalid")
        event_types = tuple(item.event_type for item in events)
        critical = {"node.review_recorded", "node.passed", "task.completed"}
        if any(item in critical for item in event_types):
            raise ApplicationError("critical review or completion transition requires semantic API")
        if any(item not in self._RUNNER_EVENT_TYPES for item in event_types):
            raise ApplicationError("runner transition event type is outside its closed scope")
        authority = object.__new__(_TransitionAuthority)
        self.__transition_authorities[authority] = (
            "runner",
            task_id,
            source_snapshot_digest,
            operation_id,
            event_types,
        )
        return self._commit_internal(
            authority,
            task_id,
            events,
            runner_state,
            runtime,
            operation_id=operation_id,
            object_digests=object_digests,
        )

    def _record_review_from_runner_channel(
        self,
        channel: _RunnerTransitionChannel,
        task_id: str,
        source_snapshot_digest: str,
        run_id: str,
        result: ReviewResult,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        """Own construction of durable review state from an exact adapter result."""

        from graph_engineering.application.runner import ReviewResult, RunnerSnapshot

        if channel not in self.__runner_channels or type(result) is not ReviewResult:
            raise ApplicationError("review record channel or result is invalid")
        view = self.__show(task_id)
        if view.snapshot.snapshot_digest != source_snapshot_digest:
            raise ApplicationError("review record source snapshot is stale")
        run = view.snapshot.node_runs.get(run_id)
        runner = RunnerSnapshot(view.runner_state)
        if run is None or run.status != "reviewing":
            raise ApplicationError("review record requires a current reviewing run")
        output = runner.node_outputs.get(run.node_id)
        if (
            output is None
            or output["run_id"] != run.run_id
            or output["attempt"] != run.attempt
            or output["trust"] != "validated"
            or output["verdict"] is not None
            or output["reviewer_id"] is not None
            or output["author_id"].casefold() == result.reviewer_id.casefold()
            or any(item.owning_node != run.node_id for item in result.findings)
        ):
            raise ApplicationError("review result does not match the current validated candidate")
        review = {
            "node_id": run.node_id,
            "run_id": run.run_id,
            "attempt": run.attempt,
            "body_digest": output["body_digest"],
            "reviewer_id": result.reviewer_id,
            "verdict": result.verdict,
            "finding_ids": [item.finding_id for item in result.findings],
            "findings": [
                item.to_dict(
                    body_digest=output["body_digest"],  # type: ignore[arg-type]
                    reviewer_id=result.reviewer_id,
                )
                for item in result.findings
            ],
        }
        runner.review_history.append(review)
        output["verdict"] = result.verdict
        output["reviewer_id"] = result.reviewer_id
        event = DomainEvent(
            view.snapshot.last_event_seq + 1,
            view.snapshot.task_revision,
            "node.review_recorded",
            {"run_id": run.run_id},
        )
        operation_id = (
            f"review-record:{run.run_id}:{run.attempt}:"
            f"{output['body_digest']}:{result.verdict}"
        )
        authority = object.__new__(_TransitionAuthority)
        self.__transition_authorities[authority] = (
            "runner", task_id, source_snapshot_digest,
            operation_id, ("node.review_recorded",),
        )
        return self._commit_internal(
            authority,
            task_id,
            (event,),
            runner.to_dict(),
            runtime,
            operation_id=operation_id,
        )

    def _pass_review_from_runner_channel(
        self,
        channel: _RunnerTransitionChannel,
        task_id: str,
        source_snapshot_digest: str,
        run_id: str,
        graph: GraphDefinition,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        """Derive PASS state only from the already durable current review."""

        from graph_engineering.application.runner import RunnerSnapshot
        from graph_engineering.core.graph.definition import GraphDefinition

        if channel not in self.__runner_channels or type(graph) is not GraphDefinition:
            raise ApplicationError("review pass channel or graph is invalid")
        view = self.__show(task_id)
        if view.snapshot.snapshot_digest != source_snapshot_digest:
            raise ApplicationError("review pass source snapshot is stale")
        run = view.snapshot.node_runs.get(run_id)
        runner = RunnerSnapshot(view.runner_state)
        if run is None or run.status != "reviewing" or not runner.review_history:
            raise ApplicationError("review pass requires a durable current review")
        output = runner.node_outputs.get(run.node_id)
        review = runner.review_history[-1]
        if (
            output is None
            or output["trust"] != "validated"
            or output["verdict"] != "PASS"
            or review["node_id"] != run.node_id
            or review["run_id"] != run.run_id
            or review["attempt"] != run.attempt
            or review["body_digest"] != output["body_digest"]
            or review["reviewer_id"] != output["reviewer_id"]
            or review["verdict"] != "PASS"
            or output["author_id"].casefold() == output["reviewer_id"].casefold()
            or view.snapshot.graph_ref.get("graph_digest") != graph.digest
        ):
            raise ApplicationError("durable review does not authorize this node pass")
        open_for_node = {
            finding_id: record
            for finding_id, record in runner.findings.items()
            if record["owning_node"] == run.node_id and record["status"] == "open"
        }
        if any(record["body_digest"] == output["body_digest"] for record in open_for_node.values()) or any(
            item["node_id"] == run.node_id
            and item["verdict"] == "REVISE"
            and item["body_digest"] == output["body_digest"]
            for item in runner.review_history[:-1]
        ):
            raise ApplicationError("durable review pass has no body-digest progress")
        output["trust"] = "independently_reviewed"
        declarations: list[tuple[str, Mapping[str, object]]] = [
            ("finding.closed", {"finding_id": finding_id})
            for finding_id in sorted(open_for_node)
        ]
        for _event_type, payload in declarations:
            runner.findings[payload["finding_id"]]["status"] = "closed"  # type: ignore[index]
        selected = graph.route(
            run.node_id,
            output["route_roots"],  # type: ignore[arg-type]
            trust_by_edge={
                edge.edge_id: "independently_reviewed"
                for edge in graph.outgoing(run.node_id)
            },
            evidence_by_edge={
                edge.edge_id: tuple(output["evidence_refs"])
                for edge in graph.outgoing(run.node_id)
            },
            context=self._context,
        )
        runner.selected_edges = sorted(
            set(runner.selected_edges) | {item.edge_id for item in selected}
        )
        declarations.append(("node.passed", {"run_id": run.run_id}))
        events = tuple(
            DomainEvent(
                view.snapshot.last_event_seq + offset,
                view.snapshot.task_revision + offset - 1,
                event_type,
                payload,
            )
            for offset, (event_type, payload) in enumerate(declarations, start=1)
        )
        operation_id = f"review-pass:{run.run_id}:{run.attempt}:{output['body_digest']}"
        event_types = tuple(item.event_type for item in events)
        authority = object.__new__(_TransitionAuthority)
        self.__transition_authorities[authority] = (
            "runner", task_id, source_snapshot_digest, operation_id, event_types,
        )
        return self._commit_internal(
            authority,
            task_id,
            events,
            runner.to_dict(),
            runtime,
            operation_id=operation_id,
        )

    def complete(
        self,
        gate: CompletionGate,
        task_id: str,
        runtime: RuntimeContext,
        graph: GraphDefinition,
        evidence: Mapping[str, object],
        *,
        candidate_review_record: ArtifactRecord,
        completion_record: ArtifactRecord,
    ) -> CompletionDecision:
        """Evaluate the current state and commit completion inside one trusted boundary."""

        from graph_engineering.application.completion import CompletionGate

        if type(gate) is not CompletionGate or type(runtime) is not RuntimeContext:
            raise ApplicationError("completion requires the exact deterministic gate and runtime")
        view = self.__show(task_id)
        decision = gate.evaluate(
            view.snapshot,
            graph,
            evidence,
            candidate_review_record=candidate_review_record,
            completion_record=completion_record,
        )
        if not decision.passed:
            return decision
        event = DomainEvent(
            view.snapshot.last_event_seq + 1,
            view.snapshot.task_revision,
            "task.completed",
            {},
        )
        operation_id = f"completion:{decision.assessment_digest}"
        authority = object.__new__(_TransitionAuthority)
        self.__transition_authorities[authority] = (
            "completion", task_id, view.snapshot.snapshot_digest,
            operation_id, ("task.completed",),
        )
        self._commit_internal(
            authority,
            task_id,
            (event,),
            view.runner_state,
            runtime,
            operation_id=operation_id,
        )
        return decision

    def complete_category(
        self,
        oracle: object,
        assessment: object,
        runtime: RuntimeContext,
        objects: ObjectRepository,
        fence_request: object,
        source_fence_request: object,
    ) -> CommandReceipt:
        """Atomically bind one factory-issued WP-08 assessment to completion."""

        from graph_engineering.application.profile_execution import (
            CategoryCompletionOracle,
            CategorySourceFenceRequest,
            TargetObservationFenceRequest,
        )
        from graph_engineering.core.profile_execution import CategoryCompletionAssessment

        if (
            type(oracle) is not CategoryCompletionOracle
            or type(assessment) is not CategoryCompletionAssessment
            or type(runtime) is not RuntimeContext
            or type(objects) is not ObjectRepository
            or type(fence_request) is not TargetObservationFenceRequest
            or type(source_fence_request) is not CategorySourceFenceRequest
        ):
            raise ApplicationError(
                "category completion requires exact oracle, runtime, and object authority"
            )
        oracle.require_issued(assessment)
        if (
            assessment.release_operations_projection is not None
            and fence_request._completion_binding != (oracle, assessment)
        ):
            raise ApplicationError("release completion requires its final live evidence fence")
        view = self.__show(assessment.task_id)
        self._runtime_matches(view.snapshot, runtime)
        if (
            view.snapshot.lifecycle != "completing"
            or view.snapshot.task_revision != assessment.task_revision
            or view.snapshot.snapshot_digest != assessment.snapshot_digest
            or view.snapshot.invalidation_epoch != assessment.invalidation_epoch
        ):
            raise ApplicationError("category assessment is stale for current completion")
        body = assessment.to_bytes()
        objects.put_verified(body, assessment.object_digest)
        if objects.get(
            assessment.object_digest,
            require_referenced=False,
        ) != body:
            raise ApplicationError("category assessment object changed after publication")
        oracle.require_issued(assessment)
        current = self.__show(assessment.task_id)
        if current.snapshot.snapshot_digest != view.snapshot.snapshot_digest:
            raise ApplicationError("category completion task changed before commit")
        event = DomainEvent(
            view.snapshot.last_event_seq + 1,
            view.snapshot.task_revision,
            "task.category_assessed",
            {
                "evidence_ref": {
                    "evidence_id": assessment.assessment_digest,
                    "evidence_type": "category-completion-assessment",
                    "source_ref": assessment.object_digest,
                    "digest": assessment.assessment_digest,
                    "trust": "factory-attested",
                },
            },
        )
        operation_id = f"category-completion:{assessment.assessment_digest}"
        authority = object.__new__(_TransitionAuthority)
        self.__transition_authorities[authority] = (
            "category",
            assessment.task_id,
            assessment.snapshot_digest,
            operation_id,
            ("task.category_assessed",),
        )
        return self._commit_internal(
            authority,
            assessment.task_id,
            (event,),
            view.runner_state,
            runtime,
            operation_id=operation_id,
            object_digests=(assessment.object_digest,),
            fence_request=fence_request,
            source_fence_request=source_fence_request,
        )

    @staticmethod
    def _runner_transition_corresponds(
        view: TaskView,
        events: tuple[DomainEvent, ...],
        runner_state: Mapping[str, object],
    ) -> None:
        outputs = runner_state.get("node_outputs")
        reviews = runner_state.get("review_history")
        findings = runner_state.get("findings")
        prior_outputs = view.runner_state.get("node_outputs")
        prior_reviews = view.runner_state.get("review_history")
        if (
            not isinstance(outputs, Mapping)
            or type(reviews) is not list
            or not isinstance(findings, Mapping)
            or not isinstance(prior_outputs, Mapping)
            or type(prior_reviews) is not list
        ):
            raise ApplicationError("runner transition evidence is malformed")
        prior_findings = view.runner_state.get("findings")
        if not isinstance(prior_findings, Mapping):
            raise ApplicationError("prior runner finding index is malformed")
        for event in events:
            if event.event_type != "node.review_recorded":
                continue
            run_id = event.payload.get("run_id")
            run = view.snapshot.node_runs.get(run_id) if type(run_id) is str else None
            if run is None or run.status != "reviewing":
                raise ApplicationError("review record does not follow a reviewing run")
            prior_output = prior_outputs.get(run.node_id)
            output = outputs.get(run.node_id)
            if not isinstance(prior_output, Mapping) or not isinstance(output, Mapping):
                raise ApplicationError("review record has no current candidate")
            if (
                prior_output.get("trust") != "validated"
                or output.get("trust") != "validated"
                or output.get("run_id") != run.run_id
                or output.get("attempt") != run.attempt
                or output.get("body_digest") != prior_output.get("body_digest")
                or output.get("author_id") != prior_output.get("author_id")
                or type(output.get("reviewer_id")) is not str
                or type(output.get("verdict")) is not str
                or output["author_id"].casefold() == output["reviewer_id"].casefold()
                or reviews[:-1] != prior_reviews
                or len(reviews) != len(prior_reviews) + 1
            ):
                raise ApplicationError("review record does not match the durable current candidate")
            review = reviews[-1]
            if not isinstance(review, Mapping) or any((
                review.get("node_id") != run.node_id,
                review.get("run_id") != run.run_id,
                review.get("attempt") != run.attempt,
                review.get("body_digest") != output["body_digest"],
                review.get("reviewer_id") != output["reviewer_id"],
                review.get("verdict") != output["verdict"],
            )):
                raise ApplicationError("durable review and candidate fields differ")
        closed_by_event = {
            event.payload.get("finding_id")
            for event in events
            if event.event_type == "finding.closed"
        }
        for event in events:
            if event.event_type != "node.passed":
                continue
            run_id = event.payload.get("run_id")
            if type(run_id) is not str:
                raise ApplicationError("node pass event has no exact run identity")
            run = view.snapshot.node_runs.get(run_id)
            if run is None or run.status != "reviewing":
                raise ApplicationError("node pass does not follow a reviewing run")
            output = outputs.get(run.node_id)
            prior_output = prior_outputs.get(run.node_id)
            if not isinstance(output, Mapping) or not isinstance(prior_output, Mapping):
                raise ApplicationError("node pass has no reviewed output")
            if (
                prior_output.get("run_id") != run.run_id
                or prior_output.get("attempt") != run.attempt
                or prior_output.get("trust") != "validated"
                or prior_output.get("verdict") != "PASS"
                or output.get("body_digest") != prior_output.get("body_digest")
                or output.get("author_id") != prior_output.get("author_id")
                or output.get("reviewer_id") != prior_output.get("reviewer_id")
                or output.get("run_id") != run.run_id
                or output.get("attempt") != run.attempt
                or output.get("trust") != "independently_reviewed"
                or output.get("verdict") != "PASS"
                or type(output.get("body_digest")) is not str
                or type(output.get("author_id")) is not str
                or type(output.get("reviewer_id")) is not str
                or output["author_id"].casefold() == output["reviewer_id"].casefold()
            ):
                raise ApplicationError("node pass lacks exact independent-review trust")
            if not prior_reviews or reviews != prior_reviews:
                raise ApplicationError("node pass must consume an already durable review")
            review = prior_reviews[-1]
            if not isinstance(review, Mapping) or any((
                review.get("node_id") != run.node_id,
                review.get("run_id") != run.run_id,
                review.get("attempt") != run.attempt,
                review.get("body_digest") != output["body_digest"],
                review.get("reviewer_id") != output["reviewer_id"],
                review.get("verdict") != "PASS",
            )):
                raise ApplicationError("node pass and latest review record differ")
            owned_open = {
                finding_id
                for finding_id, record in prior_findings.items()
                if isinstance(record, Mapping)
                and record.get("owning_node") == run.node_id
                and record.get("status") == "open"
            }
            if not owned_open.issubset(closed_by_event):
                raise ApplicationError("node pass leaves prior owned findings unclosed")
            if any(
                isinstance(prior_findings.get(finding_id), Mapping)
                and prior_findings[finding_id].get("body_digest") == output["body_digest"]  # type: ignore[index]
                for finding_id in owned_open
            ) or any(
                isinstance(item, Mapping)
                and item.get("node_id") == run.node_id
                and item.get("verdict") == "REVISE"
                and item.get("body_digest") == output["body_digest"]
                for item in prior_reviews[:-1]
            ):
                raise ApplicationError("node pass has no body-digest progress")
            if any(
                not isinstance(findings.get(finding_id), Mapping)
                or findings[finding_id].get("status") != "closed"  # type: ignore[index]
                for finding_id in owned_open
            ):
                raise ApplicationError("node pass finding state differs from close events")

    def _commit_internal(
        self,
        authority: _TransitionAuthority,
        task_id: str,
        events: tuple[DomainEvent, ...],
        runner_state: Mapping[str, object],
        runtime: RuntimeContext,
        *,
        operation_id: str,
        object_digests: tuple[str, ...] = (),
        fence_request: object | None = None,
        source_fence_request: object | None = None,
    ) -> CommandReceipt:
        """Consume one opaque capability and persist its exact internal transition."""

        task_id = self._identity(task_id, "task ID")
        operation_id = self._identity(operation_id, "operation ID")
        if (
            type(events) is not tuple
            or not events
            or any(type(item) is not DomainEvent for item in events)
            or type(runtime) is not RuntimeContext
            or tuple(sorted(set(object_digests))) != object_digests
        ):
            raise ApplicationError("internal transition inputs are invalid")
        view = self.__show(task_id)
        self._runtime_matches(view.snapshot, runtime)
        granted = self.__transition_authorities.pop(authority, None)
        event_types = tuple(item.event_type for item in events)
        if event_types == ("task.category_assessed",):
            grant_kind = "category"
        elif event_types == ("task.completed",):
            grant_kind = "completion"
        else:
            grant_kind = "runner"
        expected_grant = (
            grant_kind,
            task_id,
            view.snapshot.snapshot_digest,
            operation_id,
            event_types,
        )
        if granted != expected_grant:
            raise ApplicationError("internal transition authority is absent, stale, or out of scope")
        if granted[0] == "runner":
            if "task.completed" in event_types:
                raise ApplicationError("runner authority cannot complete a task")
            self._runner_transition_corresponds(view, events, runner_state)
        elif (
            event_types not in {("task.completed",), ("task.category_assessed",)}
            or view.snapshot.lifecycle != "completing"
        ):
            raise ApplicationError("completion authority is invalid for the current transition")
        next_snapshot = apply_events(
            view.snapshot,
            events,
            schema_registry=self._schemas,
            context=self._context,
        )
        frozen_runner = freeze(runner_state)
        stored_runner = thaw(frozen_runner)
        if not isinstance(stored_runner, dict) or set(stored_runner) != self._RUNNER_FIELDS:
            raise ApplicationError("internal runner state is not exact")
        if stored_runner.get("schema_version") != "1.0.0":
            raise ApplicationError("internal runner state version is invalid")
        if stored_runner.get("runtime_lineage_id") != runtime.runtime_lineage_id:
            raise ApplicationError("internal runner state lineage is invalid")
        from graph_engineering.application.runner import RunnerSnapshot

        RunnerSnapshot(stored_runner)
        expected_graph = next_snapshot.graph_ref.get("graph_digest") if next_snapshot.graph_ref else None
        if stored_runner.get("graph_digest") != expected_graph:
            raise ApplicationError("internal runner state graph binding is stale")

        event_values = []
        for event in events:
            payload = thaw(event.payload)
            if not isinstance(payload, dict):
                raise ApplicationError("domain event payload is not an object")
            event_values.append({
                "sequence": event.sequence,
                "expected_task_revision": event.expected_task_revision,
                "event_type": event.event_type,
                "payload": payload,
            })
        request_value = {
            "contract": "application-internal-transition-v1",
            "task_id": task_id,
            "operation_id": operation_id,
            "source_snapshot_digest": view.snapshot.snapshot_digest,
            "events": event_values,
            "runner_state": stored_runner,
            "object_digests": list(object_digests),
            "runtime_lineage_id": runtime.runtime_lineage_id,
            "occurred_at": runtime.occurred_at,
        }
        request_id = "application-internal-sha256:" + hashlib.sha256(
            canonical_bytes(request_value)
        ).hexdigest()
        recovered = self._repository.recover(request_id)
        if recovered is not None:
            current = self.__show(task_id)
            replay = self._repository.replay(task_id)
            self._repository_sequence(current, replay)
            head = replay[-1]["event_digest"] if replay else recovered.head_digest
            if type(head) is not str:
                raise ApplicationError("repository head digest is invalid")
            return CommandReceipt(
                request_id, task_id, current.snapshot.lifecycle, current.snapshot.task_revision,
                current.repository_revision, head, current.snapshot.snapshot_digest, (), True,
            )

        replay = self._repository.replay(task_id)
        repository_sequence = self._repository_sequence(view, replay)
        previous_digest = replay[-1]["event_digest"] if replay else None
        if previous_digest is not None and type(previous_digest) is not str:
            raise ApplicationError("repository head digest is invalid")
        baseline_digests = sorted(
            item["digest"] for item in next_snapshot.baseline_refs
            if type(item.get("digest")) is str
        )
        envelopes: list[dict[str, object]] = []
        chain = previous_digest
        for offset, (event, event_value) in enumerate(zip(events, event_values, strict=True), start=1):
            envelope = make_event(
                task_id=task_id,
                sequence=repository_sequence + offset,
                event_id=f"{request_id}:{offset}",
                event_type=event.event_type,
                occurred_at=runtime.occurred_at,
                actor={"kind": "runtime", "id": runtime.actor_id},
                expected_task_revision=view.repository_revision,
                baseline_digests=baseline_digests,
                payload=event_value["payload"],  # type: ignore[arg-type]
                previous_event_digest=chain,
            )
            envelopes.append(envelope)
            chain = envelope["event_digest"]  # type: ignore[assignment]

        lease_id = f"lease:{request_id}"
        lease = self._leases.acquire_many(
            lease_id=lease_id,
            task_id=task_id,
            run_id=operation_id,
            operation_id=request_id,
            resources=(f"task:{task_id}",),
            ttl_ns=runtime.lease_ttl_ns,
        )
        installation_lock = None
        target_lock = None
        fence_token = None
        try:
            if fence_request is not None:
                from graph_engineering.application.profile_execution import (
                    TargetObservationFenceRequest,
                )

                if type(fence_request) is not TargetObservationFenceRequest:
                    raise ApplicationError("target fence request is forged")
                if fence_request._locks is not self._repository._locks:
                    raise ApplicationError("target fence lock authority is foreign")
                installation_lock = self._repository._locks.acquire_installation("shared")
                target_lock = self._repository._locks.acquire_resources(
                    (fence_request.resource_id,),
                )
                fence_token = fence_request._authority.seal_fence(fence_request)
            result = self._repository.commit(CommitBatch(
                transaction_id=request_id,
                task_id=task_id,
                expected_task_revision=view.repository_revision,
                events=tuple(envelopes),
                snapshot={
                    "task_id": task_id,
                    "revision": view.repository_revision + 1,
                    "domain": next_snapshot.to_dict(),
                    "runner": stored_runner,
                },
                catalog_delta={
                    "owner_id": runtime.owner_id,
                    "runtime_kind": runtime.runtime_kind,
                    "runtime_lineage_id": runtime.runtime_lineage_id,
                    "lifecycle": next_snapshot.lifecycle,
                    "task_revision": next_snapshot.task_revision,
                    "snapshot_digest": next_snapshot.snapshot_digest,
                    "graph_digest": expected_graph,
                },
                lease_assertion={
                    "lease_id": lease.lease_id,
                    "resource_id": f"task:{task_id}",
                    "fencing_token": dict(lease.fencing_tokens)[f"task:{task_id}"],
                },
                object_digests=object_digests,
            ), fence_token=fence_token, source_fence_token=source_fence_request)
        finally:
            if target_lock is not None:
                self._repository._locks.release(target_lock)
            if installation_lock is not None:
                self._repository._locks.release(installation_lock)
            self._leases.release(lease_id)
        return CommandReceipt(
            request_id, task_id, next_snapshot.lifecycle, next_snapshot.task_revision,
            result.revision, result.head_digest, next_snapshot.snapshot_digest,
            tuple(item.event_type for item in events), False,
        )

    def execute(
        self,
        task_id: str,
        command: TaskCommand,
        runtime: RuntimeContext,
        *,
        materialization_reference: object | None = None,
    ) -> CommandReceipt:
        if command.command_type in {
            "bind_project_scope", "propose_scope_change", "realize_repository", "update_scope_metadata",
            "rebase_extensions",
        }:
            raise ApplicationError("ProjectScope mutation requires its exact production application path")
        if command.command_type == "archive":
            raise ApplicationError("archive requires its exact durable retention plan path")
        if command.command_type == "cancel":
            raise ApplicationError("cancel requires its exact durable retention plan path")
        if command.command_type == "rollback":
            raise ApplicationError("rollback requires its exact durable rollback plan path")
        project_scope_delta: dict[str, object] | None = None
        if command.command_type == "approve_prd":
            command_payload = thaw(command.payload)
            if not isinstance(command_payload, dict):
                raise ApplicationError("ProjectScope approval payload is invalid")
            authority_expansion = command_payload.pop("authority_expansion", None)
            try:
                state = self._repository.project_scope_state(task_id)
            except Exception as error:
                raise ApplicationError("ProjectScope approval has no exact durable draft") from error
            reference = thaw(command.payload.get("project_scope_ref"))
            expected = {
                "scope_id": state["scope_id"], "version": state["version"],
                "digest": state["scope_digest"], "status": "frozen",
            }
            if state.get("status") != "drafted" or reference != expected:
                raise ApplicationError("ProjectScope approval does not bind the exact durable draft")
            change = state.get("change")
            if isinstance(change, Mapping) and change.get("requires_authority_expansion") is True:
                view = self.__show(task_id)
                authorities = command_payload.get("authority_refs")
                fields = {
                    "schema_version", "authority_id", "task_id", "owner_id",
                    "candidate_scope_digest", "owner_decision_ref",
                    "authorized_resource_ids", "authorized_operation_classes",
                    "status", "authority_digest",
                }
                if (
                    not isinstance(authority_expansion, dict)
                    or set(authority_expansion) != fields
                    or authority_expansion.get("schema_version") != "1.0"
                    or authority_expansion.get("task_id") != task_id
                    or authority_expansion.get("owner_id") != view.snapshot.identity.get("owner_id")
                    or authority_expansion.get("status") != "active"
                    or authority_expansion.get("candidate_scope_digest") != state["scope_digest"]
                    or authority_expansion.get("owner_decision_ref")
                    != command_payload.get("owner_decision_ref")
                    or authority_expansion.get("authorized_resource_ids")
                    != change.get("added_resource_ids")
                    or authority_expansion.get("authorized_operation_classes")
                    != change.get("added_operation_classes")
                    or type(authority_expansion.get("authority_id")) is not str
                    or authorities != sorted(
                        tuple(view.snapshot.authorities)
                        + (authority_expansion["authority_id"],)
                    )
                    or authority_expansion.get("authority_digest") != semantic_record_digest({
                        "contract": "project-scope-authority-envelope-v1",
                        "value": {
                            key: authority_expansion[key] for key in fields
                            if key != "authority_digest"
                        },
                    })
                ):
                    raise ApplicationError("ProjectScope authority expansion is not approved")
            elif authority_expansion is not None:
                raise ApplicationError("ProjectScope authority expansion is not required")
            project_scope_delta = {
                "operation": "approve", "scope_digest": state["scope_digest"],
                "authority_expansion": authority_expansion,
            }
            command = TaskCommand(
                command.command_type, command.expected_task_revision, command_payload,
            )
        return self._execute(
            task_id,
            command,
            runtime,
            project_scope_delta=project_scope_delta,
            materialization_reference=materialization_reference,
        )

    def create_with_extension_pin(
        self,
        task_id: str,
        command: TaskCommand,
        pin_digest: str,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        if command.command_type != "create":
            raise ApplicationError("extension-pinned creation requires the create command")
        self._identity(pin_digest, "extension pin digest")
        return self._execute(
            task_id,
            command,
            runtime,
            project_scope_delta=None,
            extension_pin_delta={"operation": "create", "pin_digest": pin_digest},
        )

    def rebase_extension_pin(
        self,
        task_id: str,
        expected_task_revision: int,
        pin_digest: str,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        self._identity(pin_digest, "extension pin digest")
        command = TaskCommand(
            "rebase_extensions", expected_task_revision, {"pin_digest": pin_digest},
        )
        return self._execute(
            task_id,
            command,
            runtime,
            project_scope_delta=None,
            extension_pin_delta={"operation": "rebase", "pin_digest": pin_digest},
        )

    def execute_scope(
        self,
        task_id: str,
        command: TaskCommand,
        scope: ProjectScope,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        if command.command_type != "bind_project_scope" or type(scope) is not ProjectScope:
            raise ApplicationError("ProjectScope bind requires an exact validated ProjectScope")
        expected = {
            "scope_id": scope.scope_id, "version": scope.version,
            "digest": scope.scope_digest, "status": "drafted",
        }
        if thaw(command.payload) != {"project_scope_ref": expected}:
            raise ApplicationError("ProjectScope bind reference does not match the validated source")
        source = scope.to_dict()
        delta = {
            "operation": "draft", "source": source,
            "source_digest": self._repository._scope_source_digest(source), "change": None,
        }
        return self._execute(task_id, command, runtime, project_scope_delta=delta)

    def propose_scope_change(
        self,
        task_id: str,
        expected_task_revision: int,
        candidate: ProjectScope,
        graph: GraphDefinition,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        from graph_engineering.core.graph.definition import GraphDefinition

        if type(candidate) is not ProjectScope or type(graph) is not GraphDefinition:
            raise ApplicationError("candidate ProjectScope is missing or forged")
        view = self.__show(task_id)
        if (
            view.snapshot.graph_ref.get("graph_id") != graph.graph_id
            or view.snapshot.graph_ref.get("graph_version") != graph.graph_version
            or view.snapshot.graph_ref.get("graph_digest") != graph.digest
        ):
            raise ApplicationError("scope change graph is not the approved current graph")
        try:
            change = self._repository.project_scope_change(task_id, candidate, graph)
        except Exception as error:
            raise ApplicationError("candidate ProjectScope dependency cannot be classified") from error
        if change.get("requires_reapproval") is not True:
            raise ApplicationError("metadata-only ProjectScope changes use the metadata update path")
        reference = {
            "scope_id": candidate.scope_id, "version": candidate.version,
            "digest": candidate.scope_digest, "status": "drafted",
        }
        command = TaskCommand("propose_scope_change", expected_task_revision, {
            "project_scope_ref": reference,
            "scope_diff_digest": change["change_digest"],
            "run_ids": tuple(change["invalidated_run_ids"]),
        })
        source = candidate.to_dict()
        delta = {
            "operation": "draft", "source": source,
            "source_digest": self._repository._scope_source_digest(source), "change": change,
        }
        return self._execute(
            task_id, command, runtime,
            project_scope_delta=delta, scope_graph_definition=graph,
        )

    def realize_repository(
        self,
        task_id: str,
        observation: RepositoryIdentityObservation,
        action_id: str,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        if type(observation) is not RepositoryIdentityObservation:
            raise ApplicationError("repository realization requires a resolver-issued observation")
        if self._project_resolver is None:
            raise ApplicationError("repository realization requires the configured Git resolver")
        self._project_resolver.require_issued(observation)
        state = self._repository.project_scope_state(task_id)
        source = state.get("source")
        repositories = source.get("repositories") if isinstance(source, Mapping) else None
        binding = next(
            (item for item in repositories if isinstance(item, Mapping) and item.get("binding_id") == observation.binding_id),
            None,
        ) if isinstance(repositories, list) else None
        if (
            state.get("status") != "frozen" or state.get("scope_digest") != observation.scope_digest
            or not isinstance(binding, Mapping)
            or binding.get("planned_target_id") != observation.planned_target_id
            or binding.get("locator_ref") != observation.locator_ref
            or binding.get("allowed_path_boundary") != observation.allowed_path_boundary
            or observation.observed_path_boundary != observation.allowed_path_boundary
        ):
            raise ApplicationError("repository realization planned target is not exact")
        try:
            action = self._repository.project_action_state(task_id, action_id)
            prepared = PreparedAction.from_dict(action["prepared"], context=self._context)
        except Exception as error:
            raise ApplicationError("repository realization action/receipt is not exact and current") from error
        receipt = action["receipt"]
        reconciliation = action["reconciliation"]
        if (
            prepared.action_id != action_id or prepared.task_id != task_id
            or prepared.target_id != observation.planned_target_id
            or prepared.target_digest != observation.scope_digest
            or f"repository:{observation.binding_id}" not in prepared.resources
            or receipt.get("action_id") != action_id
            or receipt.get("target_id") != observation.planned_target_id
            or receipt.get("result") != "succeeded"
            or reconciliation.get("fresh") is not True
            or reconciliation.get("target_id") != observation.planned_target_id
            or reconciliation.get("resource_id") != f"repository:{observation.binding_id}"
        ):
            raise ApplicationError("repository realization action target/resource binding is invalid")
        view = self.__show(task_id)
        command = TaskCommand("realize_repository", view.snapshot.task_revision, {
            "binding_id": observation.binding_id, "git_identity": observation.actual_git_identity,
        })
        delta = {
            "operation": "realize", "observation": observation.to_dict(), "action_id": action_id,
            "prepared_action_digest": action["prepared_digest"],
            "receipt_digest": receipt["receipt_digest"],
        }
        return self._execute(task_id, command, runtime, project_scope_delta=delta)

    def update_scope_metadata(
        self,
        task_id: str,
        expected_task_revision: int,
        candidate: ProjectScope,
        runtime: RuntimeContext,
    ) -> CommandReceipt:
        if type(candidate) is not ProjectScope:
            raise ApplicationError("metadata-only ProjectScope is missing or forged")
        try:
            change = self._repository.project_scope_change(task_id, candidate)
        except Exception as error:
            raise ApplicationError("metadata-only ProjectScope cannot be classified") from error
        if change.get("change_class") != "metadata-only":
            raise ApplicationError("metadata-only ProjectScope path rejects semantic changes")
        source = candidate.to_dict()
        source_digest = self._repository._scope_source_digest(source)
        command = TaskCommand("update_scope_metadata", expected_task_revision, {
            "scope_digest": candidate.scope_digest,
            "metadata_revision": candidate.metadata_revision,
            "source_digest": source_digest,
        })
        delta = {
            "operation": "metadata", "source": source, "source_digest": source_digest,
            "change": change,
        }
        return self._execute(task_id, command, runtime, project_scope_delta=delta)

    def _prepare_lifecycle_plan(
        self,
        task_id: str,
        *,
        kind: str,
        trigger: str,
        authority_ref: str | None,
        runtime: RuntimeContext,
    ) -> dict[str, object]:
        task_id = self._identity(task_id, "task ID")
        view = self.__show(task_id)
        self._runtime_matches(view.snapshot, runtime)
        attempt = {
            "contract": "lifecycle-plan-attempt-v1", "task_id": task_id,
            "kind": kind, "trigger": trigger, "authority_ref": authority_ref,
            "repository_revision": view.repository_revision,
            "runtime": {
                "owner_id": runtime.owner_id, "runtime_kind": runtime.runtime_kind,
                "runtime_lineage_id": runtime.runtime_lineage_id,
                "actor_id": runtime.actor_id, "occurred_at": runtime.occurred_at,
            },
        }
        attempt_id = hashlib.sha256(canonical_bytes(attempt)).hexdigest()
        lease_id = f"lease:lifecycle-plan:{attempt_id}"
        lease = self._leases.acquire_many(
            lease_id=lease_id, task_id=task_id, run_id=f"plan:{kind}",
            operation_id=f"plan:{kind}:{attempt_id}",
            resources=(f"task:{task_id}",), ttl_ns=runtime.lease_ttl_ns,
        )
        try:
            return self._repository.prepare_lifecycle_plan(
                task_id, kind=kind, trigger=trigger, authority_ref=authority_ref,
                lease_assertion={
                    "lease_id": lease.lease_id, "resource_id": f"task:{task_id}",
                    "fencing_token": dict(lease.fencing_tokens)[f"task:{task_id}"],
                },
            )
        finally:
            self._leases.release(lease.lease_id)

    def prepare_retention_plan(
        self,
        task_id: str,
        trigger: str,
        runtime: RuntimeContext,
    ) -> dict[str, object]:
        if trigger not in {"archive", "cancel"}:
            raise ApplicationError("retention plan trigger is invalid")
        return self._prepare_lifecycle_plan(
            task_id, kind="retention", trigger=trigger, authority_ref=None, runtime=runtime,
        )

    def prepare_controlled_rollback(
        self,
        task_id: str,
        authority_ref: str,
        runtime: RuntimeContext,
    ) -> dict[str, object]:
        view = self.__show(task_id)
        self._runtime_matches(view.snapshot, runtime)
        if authority_ref not in view.snapshot.authorities:
            raise ApplicationError("controlled rollback request authority is not active")
        return self._prepare_lifecycle_plan(
            task_id, kind="rollback", trigger="rollback",
            authority_ref=authority_ref, runtime=runtime,
        )

    def _consume_lifecycle_plan(
        self,
        task_id: str,
        expected_task_revision: int,
        plan_id: str,
        runtime: RuntimeContext,
        *,
        kind: str,
        trigger: str,
    ) -> CommandReceipt:
        try:
            plan = self._repository.lifecycle_plan(plan_id)
        except Exception as error:
            raise ApplicationError(f"durable {kind} plan is missing or invalid") from error
        body = plan.get("body")
        if (
            plan.get("task_id") != task_id or plan.get("kind") != kind
            or plan.get("trigger") != trigger or plan.get("state") != "prepared"
            or not isinstance(body, Mapping)
        ):
            raise ApplicationError(f"durable {kind} plan is stale or substituted")
        if kind == "retention" and trigger == "archive":
            command = TaskCommand("archive", expected_task_revision, {
                "retention_plan_ref": plan_id,
                "rollback_clearance_ref": body["rollback_clearance_ref"],
            })
        elif kind == "retention":
            command = TaskCommand("cancel", expected_task_revision, {})
        else:
            command = TaskCommand("rollback", expected_task_revision, {
                "compensable_action_refs": tuple(body["compensable_action_refs"]),
                "rollback_plan_ref": plan_id, "authority_ref": body["request_authority_ref"],
            })
        return self._execute(
            task_id, command, runtime, project_scope_delta=None,
            lifecycle_plan_delta={"plan_id": plan_id, "trigger": trigger},
        )

    def archive_with_retention(
        self, task_id: str, expected_task_revision: int, plan_id: str, runtime: RuntimeContext,
    ) -> CommandReceipt:
        return self._consume_lifecycle_plan(
            task_id, expected_task_revision, plan_id, runtime, kind="retention", trigger="archive",
        )

    def cancel_with_retention(
        self, task_id: str, expected_task_revision: int, plan_id: str, runtime: RuntimeContext,
    ) -> CommandReceipt:
        return self._consume_lifecycle_plan(
            task_id, expected_task_revision, plan_id, runtime, kind="retention", trigger="cancel",
        )

    def request_controlled_rollback(
        self, task_id: str, expected_task_revision: int, plan_id: str, runtime: RuntimeContext,
    ) -> CommandReceipt:
        return self._consume_lifecycle_plan(
            task_id, expected_task_revision, plan_id, runtime, kind="rollback", trigger="rollback",
        )

    def _execute(
        self,
        task_id: str,
        command: TaskCommand,
        runtime: RuntimeContext,
        *,
        project_scope_delta: dict[str, object] | None,
        lifecycle_plan_delta: dict[str, object] | None = None,
        scope_graph_definition: object | None = None,
        extension_pin_delta: dict[str, object] | None = None,
        materialization_reference: object | None = None,
    ) -> CommandReceipt:
        task_id = self._identity(task_id, "task ID")
        if type(command) is not TaskCommand or type(runtime) is not RuntimeContext:
            raise ApplicationError("command and runtime context must be exact application types")
        materialization_object_digests: tuple[str, ...] = ()
        graph_ref = command.payload.get("graph_ref") if command.command_type == "approve_prd" else None
        is_materialized = isinstance(graph_ref, Mapping) and "materialization_digest" in graph_ref
        if is_materialized:
            from graph_engineering.core.profiles import (
                MaterializationObjectReference,
                ProfileContractError,
            )

            if type(materialization_reference) is not MaterializationObjectReference:
                raise ApplicationError("materialized graph requires its issued object authority")
            try:
                self._require_materialization_reference(
                    materialization_reference, graph_ref,
                )
            except ProfileContractError as error:
                raise ApplicationError("materialized graph object authority is stale") from error
            materialization_object_digests = (
                materialization_reference.object_digest,
            )
        elif materialization_reference is not None:
            raise ApplicationError("materialization authority is outside this command scope")
        request_id = self._request_id(task_id, command, runtime)
        recovered = self._repository.recover(request_id)
        if recovered is not None:
            view = self.__show(task_id)
            self._runtime_matches(view.snapshot, runtime)
            replay = self._repository.replay(task_id)
            self._repository_sequence(view, replay)
            head = replay[-1]["event_digest"] if replay else recovered.head_digest
            if type(head) is not str:
                raise ApplicationError("repository head digest is invalid")
            return CommandReceipt(
                request_id, task_id, view.snapshot.lifecycle, view.snapshot.task_revision,
                view.repository_revision, head, view.snapshot.snapshot_digest, (), True,
            )

        if command.command_type == "create":
            current: TaskSnapshot | None = None
            repository_revision = 0
            repository_sequence = 0
            previous_digest: str | None = None
            lifecycle_assertion: dict[str, object] | None = None
        else:
            rebase_pin = (
                extension_pin_delta.get("pin_digest")
                if extension_pin_delta is not None
                and extension_pin_delta.get("operation") == "rebase"
                else None
            )
            view = (
                self._restore(self._repository.load_for_extension_rebase(task_id, rebase_pin))
                if type(rebase_pin) is str
                else self.__show(task_id)
            )
            current = view.snapshot
            repository_revision = view.repository_revision
            self._runtime_matches(current, runtime)
            replay = (
                self._repository.replay_for_extension_rebase(task_id, rebase_pin)
                if type(rebase_pin) is str
                else self._repository.replay(task_id)
            )
            repository_sequence = self._repository_sequence(view, replay)
            previous_digest = replay[-1]["event_digest"] if replay else None
            if previous_digest is not None and type(previous_digest) is not str:
                raise ApplicationError("repository head digest is invalid")
            lifecycle_facts = self._validate_lifecycle_preconditions(
                task_id, current, command, lifecycle_plan_delta,
            )
            assertion = lifecycle_facts.get("assertion")
            if not isinstance(assertion, dict):
                raise ApplicationError("durable lifecycle fact assertion is absent")
            lifecycle_assertion = assertion

        events = decide_command(
            current,
            command,
            schema_registry=self._schemas,
            context=self._context,
            materialization_record=materialization_reference,
        )
        next_snapshot = apply_events(
            current,
            events,
            schema_registry=self._schemas,
            context=self._context,
            materialization_record=materialization_reference,
        )
        if next_snapshot.identity.get("task_id") != task_id:
            raise ApplicationError("command task identity does not match the target")
        self._runtime_matches(next_snapshot, runtime)

        envelopes: list[dict[str, object]] = []
        chain = previous_digest
        baseline_digests = sorted(
            item["digest"] for item in next_snapshot.baseline_refs
            if type(item.get("digest")) is str
        )
        for offset, event in enumerate(events, start=1):
            event_payload = thaw(event.payload)
            if not isinstance(event_payload, dict):
                raise ApplicationError("domain event payload is not an object")
            envelope = make_event(
                task_id=task_id,
                sequence=repository_sequence + offset,
                event_id=f"{request_id}:{offset}",
                event_type=event.event_type,
                occurred_at=runtime.occurred_at,
                actor={"kind": "runtime", "id": runtime.actor_id},
                expected_task_revision=repository_revision,
                baseline_digests=baseline_digests,
                payload=event_payload,
                previous_event_digest=chain,
            )
            envelopes.append(envelope)
            chain = envelope["event_digest"]  # type: ignore[assignment]

        lease_id = f"lease:{request_id}"
        lease = self._leases.acquire_many(
            lease_id=lease_id,
            task_id=task_id,
            run_id=f"command:{command.command_type}",
            operation_id=request_id,
            resources=(f"task:{task_id}",),
            ttl_ns=runtime.lease_ttl_ns,
        )
        try:
            if materialization_reference is not None:
                try:
                    self._require_materialization_reference(
                        materialization_reference, graph_ref,
                    )
                except Exception as error:
                    raise ApplicationError(
                        "materialized graph object authority changed before commit"
                    ) from error
            if lifecycle_assertion is not None:
                lifecycle_assertion = copy.deepcopy(lifecycle_assertion)
                fences = {
                    item[0]: item[1]
                    for item in lifecycle_assertion["fencing_high_water"]  # type: ignore[index]
                }
                fences[f"task:{task_id}"] = dict(lease.fencing_tokens)[f"task:{task_id}"]
                lifecycle_assertion["fencing_high_water"] = [
                    [resource, token] for resource, token in sorted(fences.items())
                ]
                lifecycle_assertion["facts_digest"] = self._repository.lifecycle_facts_digest(
                    lifecycle_assertion,
                )
            runner_state = self._runner_state(next_snapshot, runtime)
            if current is not None:
                stored = (
                    self._repository.load_for_extension_rebase(
                        task_id, str(extension_pin_delta["pin_digest"]),
                    )
                    if extension_pin_delta is not None
                    and extension_pin_delta.get("operation") == "rebase"
                    else self._repository.load(task_id)
                )
                if not isinstance(stored, Mapping) or not isinstance(stored.get("runner"), Mapping):
                    raise ApplicationError("stored runner state is invalid")
                runner_state = dict(stored["runner"])
                runner_state["graph_digest"] = (
                    next_snapshot.graph_ref.get("graph_digest") if next_snapshot.graph_ref else None
                )
            result = self._repository.commit(CommitBatch(
                transaction_id=request_id,
                task_id=task_id,
                expected_task_revision=repository_revision,
                events=tuple(envelopes),
                snapshot={
                    "task_id": task_id,
                    "revision": repository_revision + 1,
                    "domain": next_snapshot.to_dict(),
                    "runner": runner_state,
                },
                catalog_delta={
                    "owner_id": runtime.owner_id,
                    "runtime_kind": runtime.runtime_kind,
                    "runtime_lineage_id": runtime.runtime_lineage_id,
                    "lifecycle": next_snapshot.lifecycle,
                    "task_revision": next_snapshot.task_revision,
                    "snapshot_digest": next_snapshot.snapshot_digest,
                    "graph_digest": (
                        next_snapshot.graph_ref.get("graph_digest")
                        if next_snapshot.graph_ref else None
                    ),
                },
                lease_assertion={
                    "lease_id": lease.lease_id,
                    "resource_id": f"task:{task_id}",
                    "fencing_token": dict(lease.fencing_tokens)[f"task:{task_id}"],
                },
                project_scope_delta=project_scope_delta,
                lifecycle_assertion=lifecycle_assertion,
                lifecycle_plan_delta=lifecycle_plan_delta,
                scope_graph_definition=scope_graph_definition,
                extension_pin_delta=extension_pin_delta,
                object_digests=materialization_object_digests,
            ))
        finally:
            self._leases.release(lease_id)
        return CommandReceipt(
            request_id, task_id, next_snapshot.lifecycle, next_snapshot.task_revision,
            result.revision, result.head_digest, next_snapshot.snapshot_digest,
            tuple(item.event_type for item in events), False,
        )
