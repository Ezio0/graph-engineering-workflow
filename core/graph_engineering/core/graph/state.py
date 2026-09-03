"""Pure task and node-run reducers with default-deny transitions."""

from __future__ import annotations

import hmac
from collections.abc import Iterable, Mapping
from dataclasses import InitVar, dataclass, field, replace

from graph_engineering.core.contracts.digest import (
    DigestProjection,
    SEMANTIC_DIGEST,
    semantic_digest,
    semantic_digest_charged,
    validate_projection_schema_pair,
)
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext


SNAPSHOT_SCHEMA = "urn:gew:schema:task-snapshot:1.0.0"
SNAPSHOT_DIGEST_INPUT_SCHEMA = "urn:gew:schema:task-snapshot-digest-input:1.0.0"
SNAPSHOT_PROJECTION = DigestProjection(
    projection_id="urn:gew:digest-projection:task-snapshot:1.0.0",
    source_schema_id=SNAPSHOT_SCHEMA,
    digest_input_schema_id=SNAPSHOT_DIGEST_INPUT_SCHEMA,
    derived_field="snapshot_digest",
    contract_type="urn:gew:contract:task-snapshot",
    schema_id=SNAPSHOT_DIGEST_INPUT_SCHEMA,
)


class ReducerError(ValueError):
    """Rejected event sequence or state transition."""


CONTRACT_PIN_NAMES = frozenset({
    "schema_registry", "resource_profile", "cost_schedule",
})
CONTRACT_PIN_SHAPES = dict((
    ("schema_registry", ("registry_id", "registry_digest")),
    ("resource_profile", ("profile_id", "body_digest")),
    ("cost_schedule", ("schedule_id", "body_digest")),
))


def _actual_contract_pins(
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> dict[str, object]:
    return {
        "schema_registry": {
            "registry_id": schema_registry.registry_id,
            "registry_digest": schema_registry.registry_digest,
        },
        "resource_profile": {
            "profile_id": context.profile.profile_id,
            "body_digest": context.profile.body_digest,
        },
        "cost_schedule": {
            "schedule_id": context.schedule.schedule_id,
            "body_digest": context.schedule.body_digest,
        },
    }


def _validate_contract_pins(
    value: object,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> FrozenMap:
    if not isinstance(value, Mapping) or set(value) != CONTRACT_PIN_NAMES:
        raise ReducerError("snapshot contract pins are not exact")
    expected = _actual_contract_pins(schema_registry, context)
    normalized: dict[str, object] = {}
    for name in sorted(CONTRACT_PIN_NAMES):
        raw = value[name]
        id_field, digest_field = CONTRACT_PIN_SHAPES[name]
        if not isinstance(raw, Mapping) or set(raw) != {id_field, digest_field}:
            raise ReducerError(f"{name} contract pin is not exact")
        identity = raw[id_field]
        digest = raw[digest_field]
        actual = expected[name]
        if (
            type(identity) is not str
            or not identity
            or type(digest) is not str
            or SEMANTIC_DIGEST.fullmatch(digest) is None
            or identity != actual[id_field]  # type: ignore[index]
            or not hmac.compare_digest(digest, actual[digest_field])  # type: ignore[index]
        ):
            raise ReducerError(f"{name} contract pin mismatch")
        normalized[name] = {id_field: identity, digest_field: digest}
    frozen = freeze(normalized)
    if not isinstance(frozen, FrozenMap):
        raise AssertionError("contract pins must freeze to an object")
    return frozen


@dataclass(frozen=True, slots=True)
class DomainEvent:
    sequence: int
    expected_task_revision: int
    event_type: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ReducerError("event sequence must be a positive integer")
        if type(self.expected_task_revision) is not int or self.expected_task_revision < 0:
            raise ReducerError("expected task revision must be a nonnegative integer")
        if type(self.event_type) is not str or not self.event_type:
            raise ReducerError("event type must be a non-empty string")
        if not isinstance(self.payload, Mapping) or any(type(key) is not str for key in self.payload):
            raise ReducerError("event payload must be a string-keyed mapping")
        frozen = freeze(self.payload)
        if not isinstance(frozen, FrozenMap):
            raise ReducerError("event payload must freeze to an object")
        object.__setattr__(self, "payload", frozen)


@dataclass(frozen=True, slots=True)
class NodeRun:
    run_id: str
    node_id: str
    attempt: int
    status: str

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or not self.run_id
            or type(self.node_id) is not str
            or not self.node_id
            or type(self.attempt) is not int
            or self.attempt < 1
        ):
            raise ReducerError("invalid node run identity")
        if type(self.status) is not str or self.status not in NODE_STATUSES:
            raise ReducerError("unknown node run status")


@dataclass(frozen=True, slots=True)
class TaskCommand:
    command_type: str
    expected_task_revision: int
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.command_type) is not str or not self.command_type:
            raise ReducerError("command type must be a non-empty string")
        if type(self.expected_task_revision) is not int or self.expected_task_revision < 0:
            raise ReducerError("command revision must be a nonnegative integer")
        frozen = freeze(self.payload)
        if not isinstance(frozen, FrozenMap):
            raise ReducerError("command payload must be an object")
        object.__setattr__(self, "payload", frozen)


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    contract_ref: str
    revision: int
    digest: str
    trust: str

    def __post_init__(self) -> None:
        if any(type(item) is not str or not item for item in (
            self.artifact_id, self.artifact_type, self.contract_ref, self.digest, self.trust,
        )):
            raise ReducerError("invalid artifact ref")
        if type(self.revision) is not int or self.revision < 1:
            raise ReducerError("invalid artifact revision")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "contract_ref": self.contract_ref,
            "revision": self.revision,
            "digest": self.digest,
            "trust": self.trust,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    evidence_type: str
    source_ref: str
    digest: str
    trust: str

    def __post_init__(self) -> None:
        if any(type(item) is not str or not item for item in (
            self.evidence_id, self.evidence_type, self.source_ref, self.digest, self.trust,
        )):
            raise ReducerError("invalid evidence ref")

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source_ref": self.source_ref,
            "digest": self.digest,
            "trust": self.trust,
        }


@dataclass(frozen=True, slots=True)
class TaskSnapshot:
    task_revision: int
    lifecycle: str
    last_event_seq: int
    identity: Mapping[str, object]
    project_scope_ref: Mapping[str, object]
    baseline_refs: tuple[Mapping[str, object], ...]
    graph_ref: Mapping[str, object]
    node_runs: Mapping[str, NodeRun]
    authorities: tuple[str, ...]
    artifacts: tuple[ArtifactRef, ...]
    evidence: tuple[EvidenceRef, ...]
    unresolved_action_claims: tuple[str, ...]
    action_claim_authorities: Mapping[str, str]
    resource_leases: tuple[str, ...]
    open_findings: tuple[str, ...]
    desired_state: str | None
    invalidation_epoch: int
    contract_pins: Mapping[str, object]
    schema_registry: InitVar[ClosedSchemaRegistry]
    context: InitVar[WorkContext]
    expected_snapshot_digest: InitVar[str | None] = None
    source_prevalidated: InitVar[bool] = False
    operation_path: InitVar[tuple[int, ...]] = ()
    snapshot_digest: str = field(init=False)

    @classmethod
    def initial(
        cls,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        *,
        operation_path: tuple[int, ...] = (),
    ) -> TaskSnapshot:
        if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
            raise ReducerError("snapshot requires an attested schema registry and work context")
        return cls(
            0, "nonexistent", 0, {}, {}, (), {}, {}, (), (), (), (), {}, (), (), None, 0,
            _actual_contract_pins(schema_registry, context), schema_registry, context,
            None, False, operation_path,
        )

    def __post_init__(
        self,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        expected_snapshot_digest: str | None,
        source_prevalidated: bool,
        operation_path: tuple[int, ...],
    ) -> None:
        if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
            raise ReducerError("snapshot requires an attested schema registry and work context")
        if (
            type(operation_path) is not tuple
            or any(type(item) is not int or item < 0 for item in operation_path)
            or type(source_prevalidated) is not bool
        ):
            raise ReducerError("snapshot operation frame is invalid")
        pins = _validate_contract_pins(self.contract_pins, schema_registry, context)
        object.__setattr__(self, "contract_pins", pins)
        if self.lifecycle not in LIFECYCLES:
            raise ReducerError("unknown task lifecycle")
        if type(self.task_revision) is not int or self.task_revision < 0:
            raise ReducerError("invalid task revision")
        if type(self.last_event_seq) is not int or self.last_event_seq < 0:
            raise ReducerError("invalid event sequence")
        if self.task_revision != self.last_event_seq:
            raise ReducerError("task revision and event sequence diverge")
        if type(self.invalidation_epoch) is not int or self.invalidation_epoch < 0:
            raise ReducerError("invalid invalidation epoch")
        if self.desired_state not in {None, "paused"}:
            raise ReducerError("invalid desired state")
        for name in ("identity", "project_scope_ref", "graph_ref"):
            frozen = freeze(getattr(self, name))
            if not isinstance(frozen, FrozenMap):
                raise ReducerError(f"{name} must be an object")
            object.__setattr__(self, name, frozen)
        frozen_baselines: list[Mapping[str, object]] = []
        for baseline in self.baseline_refs:
            frozen = freeze(baseline)
            if not isinstance(frozen, FrozenMap):
                raise ReducerError("baseline ref must be an object")
            frozen_baselines.append(frozen)
        object.__setattr__(self, "baseline_refs", tuple(frozen_baselines))
        if any(type(key) is not str or type(value) is not NodeRun or key != value.run_id for key, value in self.node_runs.items()):
            raise ReducerError("invalid node runs")
        object.__setattr__(self, "node_runs", FrozenMap.from_dict(dict(self.node_runs)))
        if any(type(item) is not ArtifactRef for item in self.artifacts):
            raise ReducerError("invalid artifacts")
        if any(type(item) is not EvidenceRef for item in self.evidence):
            raise ReducerError("invalid evidence")
        artifact_ids = tuple(item.artifact_id for item in self.artifacts)
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(artifact_ids) != len(set(artifact_ids)) or len(evidence_ids) != len(set(evidence_ids)):
            raise ReducerError("duplicate artifact or evidence ref")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        for name in (
            "authorities", "unresolved_action_claims", "resource_leases", "open_findings",
        ):
            values = getattr(self, name)
            if any(type(item) is not str or not item for item in values) or len(values) != len(set(values)):
                raise ReducerError(f"invalid {name}")
            object.__setattr__(self, name, tuple(values))
        claim_authorities = self.action_claim_authorities
        if (
            not isinstance(claim_authorities, Mapping)
            or any(type(key) is not str or not key or type(value) is not str or not value for key, value in claim_authorities.items())
            or set(claim_authorities) - set(self.unresolved_action_claims)
        ):
            raise ReducerError("invalid action claim authority bindings")
        object.__setattr__(self, "action_claim_authorities", FrozenMap.from_dict(dict(claim_authorities)))
        if self.lifecycle == "nonexistent":
            if (
                self.identity or self.project_scope_ref or self.baseline_refs or self.graph_ref
                or self.node_runs or self.authorities or self.artifacts or self.evidence
                or self.unresolved_action_claims or self.resource_leases or self.open_findings
                or self.desired_state is not None or self.invalidation_epoch != 0
            ):
                raise ReducerError("nonexistent snapshot cannot contain task bindings")
        else:
            _validate_identity(self.identity)
            if self.project_scope_ref:
                _validate_scope_ref(self.project_scope_ref)
            if self.baseline_refs:
                _validate_baseline_refs(self.baseline_refs)
            if self.graph_ref:
                _validate_graph_ref_shape(self.graph_ref)
            post_approval = self.lifecycle in {
                "ready", "running", "paused", "awaiting_human", "blocked", "failed",
                "rollback_pending", "rolling_back", "rolled_back", "completing", "completed",
            } or bool(self.baseline_refs or self.graph_ref or self.authorities)
            if post_approval and (
                not self.project_scope_ref
                or self.project_scope_ref.get("status") != "frozen"
                or not self.baseline_refs
                or not self.graph_ref
            ):
                raise ReducerError("post-approval snapshot bindings are incomplete")
        try:
            validate_projection_schema_pair(
                schema_registry.resource(SNAPSHOT_SCHEMA).schema,
                schema_registry.resource(SNAPSHOT_DIGEST_INPUT_SCHEMA).schema,
                SNAPSHOT_PROJECTION,
            )
        except ValueError as error:
            raise ReducerError("snapshot digest projection is not registered exactly") from error
        body = self.to_body()
        if schema_registry.validate(
            SNAPSHOT_DIGEST_INPUT_SCHEMA,
            body,
            context,
            operation_path=context.child_path(operation_path),
        ):
            raise ReducerError("snapshot digest-input schema validation failed")
        digest = semantic_digest_charged(
            body,
            context,
            contract_type=SNAPSHOT_PROJECTION.contract_type,
            projection_id=SNAPSHOT_PROJECTION.projection_id,
            schema_id=SNAPSHOT_PROJECTION.schema_id,
            operation_path=context.child_path(operation_path),
        )
        complete = dict(body)
        complete[SNAPSHOT_PROJECTION.derived_field] = digest
        if source_prevalidated:
            if type(expected_snapshot_digest) is not str or SEMANTIC_DIGEST.fullmatch(
                expected_snapshot_digest,
            ) is None:
                raise ReducerError("snapshot digest is invalid")
            if not hmac.compare_digest(expected_snapshot_digest, digest):
                raise ReducerError("snapshot digest mismatch")
        else:
            if expected_snapshot_digest is not None:
                raise ReducerError("snapshot creation cannot supply an expected digest")
            if schema_registry.validate(
                SNAPSHOT_SCHEMA,
                complete,
                context,
                operation_path=context.child_path(operation_path),
            ):
                raise ReducerError("snapshot source schema validation failed")
        object.__setattr__(self, "snapshot_digest", digest)

    def to_body(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "task_revision": self.task_revision,
            "identity": thaw(self.identity),
            "project_scope_ref": thaw(self.project_scope_ref),
            "baseline_refs": [thaw(item) for item in self.baseline_refs],
            "graph_ref": thaw(self.graph_ref),
            "contract_pins": thaw(self.contract_pins),
            "lifecycle": self.lifecycle,
            "node_runs": {
                key: {
                    "run_id": item.run_id,
                    "node_id": item.node_id,
                    "attempt": item.attempt,
                    "status": item.status,
                }
                for key, item in sorted(self.node_runs.items())
            },
            "authorities": list(self.authorities),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "evidence": [item.to_dict() for item in self.evidence],
            "resource_leases": list(self.resource_leases),
            "unresolved_action_claims": list(self.unresolved_action_claims),
            "action_claim_authorities": dict(sorted(self.action_claim_authorities.items())),
            "open_findings": list(self.open_findings),
            "invalidation_epoch": self.invalidation_epoch,
            "last_event_seq": self.last_event_seq,
            "desired_state": self.desired_state,
        }

    def to_dict(self) -> dict[str, object]:
        result = self.to_body()
        result["snapshot_digest"] = self.snapshot_digest
        return result

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        operation_path: tuple[int, ...] = (),
        materialization_record: object | None = None,
    ) -> TaskSnapshot:
        fields = {
            "schema_version", "task_revision", "identity", "project_scope_ref", "baseline_refs",
            "graph_ref", "lifecycle", "node_runs", "authorities", "artifacts", "evidence",
            "resource_leases", "unresolved_action_claims", "action_claim_authorities", "open_findings", "invalidation_epoch",
            "last_event_seq", "desired_state", "contract_pins", "snapshot_digest",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise ReducerError("snapshot properties are not exact")
        expected = value.get("snapshot_digest")
        if type(expected) is not str or SEMANTIC_DIGEST.fullmatch(expected) is None:
            raise ReducerError("snapshot digest is invalid")
        contract_pins = _validate_contract_pins(
            value.get("contract_pins"), schema_registry, context,
        )
        if schema_registry.validate(
            SNAPSHOT_SCHEMA,
            value,
            context,
            operation_path=context.child_path(operation_path),
        ):
            raise ReducerError("snapshot source schema validation failed")

        def exact_ref(raw: object, required: set[str], label: str) -> Mapping[str, object]:
            if not isinstance(raw, Mapping) or set(raw) != required:
                raise ReducerError(f"{label} is not exact")
            return raw

        raw_identity = value.get("identity")
        identity = (
            {}
            if isinstance(raw_identity, Mapping) and not raw_identity
            else exact_ref(
                raw_identity,
                {"task_id", "owner_id", "runtime_kind", "runtime_lineage_id"},
                "task identity",
            )
        )
        raw_scope = value.get("project_scope_ref")
        scope = {} if isinstance(raw_scope, Mapping) and not raw_scope else exact_ref(raw_scope, {"scope_id", "version", "digest", "status"}, "project scope ref")
        raw_graph = value.get("graph_ref")
        graph = (
            {}
            if isinstance(raw_graph, Mapping) and not raw_graph
            else _validate_graph_ref(
                raw_graph, materialization_record=materialization_record,
            )
        )
        raw_baselines = value.get("baseline_refs")
        if not isinstance(raw_baselines, list):
            raise ReducerError("baseline refs must be an array")
        baselines = tuple(exact_ref(item, {"kind", "version", "digest", "approved_by", "approved_at"}, "baseline ref") for item in raw_baselines)
        raw_runs = value.get("node_runs")
        if not isinstance(raw_runs, Mapping):
            raise ReducerError("node runs must be an object")
        runs: dict[str, NodeRun] = {}
        for run_id, raw in raw_runs.items():
            if type(run_id) is not str:
                raise ReducerError("node run key must be a string")
            record = exact_ref(raw, {"run_id", "node_id", "attempt", "status"}, "node run")
            if record["run_id"] != run_id:
                raise ReducerError("node run key does not match identity")
            if type(record["node_id"]) is not str or type(record["attempt"]) is not int or type(record["status"]) is not str:
                raise ReducerError("node run fields are invalid")
            runs[run_id] = NodeRun(run_id, record["node_id"], record["attempt"], record["status"])

        def strings(name: str) -> tuple[str, ...]:
            raw = value.get(name)
            if not isinstance(raw, list) or any(type(item) is not str for item in raw):
                raise ReducerError(f"{name} must be a string array")
            return tuple(raw)

        raw_artifacts = value.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise ReducerError("artifacts must be an array")
        artifacts: list[ArtifactRef] = []
        for raw in raw_artifacts:
            record = exact_ref(raw, {"artifact_id", "artifact_type", "contract_ref", "revision", "digest", "trust"}, "artifact ref")
            artifacts.append(ArtifactRef(
                record["artifact_id"], record["artifact_type"], record["contract_ref"],
                record["revision"], record["digest"], record["trust"],  # type: ignore[arg-type]
            ))
        raw_evidence = value.get("evidence")
        if not isinstance(raw_evidence, list):
            raise ReducerError("evidence must be an array")
        evidence: list[EvidenceRef] = []
        for raw in raw_evidence:
            record = exact_ref(raw, {"evidence_id", "evidence_type", "source_ref", "digest", "trust"}, "evidence ref")
            evidence.append(EvidenceRef(
                record["evidence_id"], record["evidence_type"], record["source_ref"],
                record["digest"], record["trust"],  # type: ignore[arg-type]
            ))
        raw_claim_authorities = value.get("action_claim_authorities")
        if not isinstance(raw_claim_authorities, Mapping):
            raise ReducerError("action claim authority bindings must be an object")

        desired = value.get("desired_state")
        if desired is not None and type(desired) is not str:
            raise ReducerError("desired state must be string or null")
        result = cls(
            value["task_revision"], value["lifecycle"], value["last_event_seq"],  # type: ignore[arg-type]
            identity, scope, baselines, graph, runs, strings("authorities"),
            tuple(artifacts), tuple(evidence), strings("unresolved_action_claims"), raw_claim_authorities,
            strings("resource_leases"),
            strings("open_findings"), desired, value["invalidation_epoch"],  # type: ignore[arg-type]
            contract_pins, schema_registry, context, expected, True, operation_path,
        )
        return result

    def with_coordination(
        self,
        *,
        claims: tuple[str, ...],
        leases: tuple[str, ...],
        claim_authorities: Mapping[str, str] | None = None,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> TaskSnapshot:
        if len(claims) != len(set(claims)) or len(leases) != len(set(leases)):
            raise ReducerError("duplicate coordination identity")
        bindings = {} if claim_authorities is None else dict(claim_authorities)
        return replace(
            self,
            unresolved_action_claims=tuple(claims),
            action_claim_authorities=bindings,
            resource_leases=tuple(leases),
            schema_registry=schema_registry,
            context=context,
        )


LIFECYCLES = frozenset({
    "nonexistent", "discovering", "awaiting_prd_approval", "ready", "running", "paused",
    "awaiting_human", "blocked", "failed", "canceling", "canceled", "rollback_pending",
    "rolling_back", "rolled_back", "completing", "completed", "archived",
})
NODE_STATUSES = frozenset({
    "pending", "ready", "leased", "running", "produced", "validating", "reviewing",
    "awaiting_human", "invalidated", "blocked", "passed", "cancelled",
})

TASK_TRANSITIONS: dict[tuple[str, str], str] = {
    ("nonexistent", "task.created"): "discovering",
    ("discovering", "project.scope_drafted"): "discovering",
    ("discovering", "task.prd_approval_requested"): "awaiting_prd_approval",
    ("awaiting_prd_approval", "task.discovery_reopened"): "discovering",
    ("awaiting_prd_approval", "project.scope_frozen"): "awaiting_prd_approval",
    ("awaiting_prd_approval", "project.scope_rebased"): "awaiting_prd_approval",
    ("awaiting_prd_approval", "task.prd_approved"): "ready",
    ("awaiting_prd_approval", "task.prd_reapproved"): "ready",
    ("ready", "task.run_started"): "running",
    ("ready", "task.paused"): "paused",
    ("running", "task.paused"): "paused",
    ("running", "task.pause_deferred"): "awaiting_human",
    ("awaiting_human", "task.paused"): "paused",
    ("running", "task.human_decision_required"): "awaiting_human",
    ("running", "task.blocked"): "blocked",
    ("completing", "task.blocked"): "blocked",
    ("running", "task.failed"): "failed",
    ("rolling_back", "task.failed"): "failed",
    ("completing", "task.failed"): "failed",
    ("running", "task.cancel_requested"): "canceling",
    ("canceling", "task.canceled"): "canceled",
    ("running", "task.completion_started"): "completing",
    ("completing", "task.category_assessed"): "completed",
    ("completing", "task.completed"): "completed",
    ("completing", "task.completion_rejected"): "ready",
    ("rollback_pending", "task.rollback_started"): "rolling_back",
    ("rolling_back", "task.rollback_completed"): "rolled_back",
}
for _state in ("discovering", "awaiting_prd_approval", "ready", "paused", "awaiting_human", "blocked", "failed"):
    TASK_TRANSITIONS[(_state, "task.cancel_requested")] = "canceling"
for _state in ("paused", "awaiting_human", "blocked", "failed"):
    TASK_TRANSITIONS[(_state, "task.resumed")] = "ready"
for _state in ("discovering", "awaiting_prd_approval", "ready", "paused", "awaiting_human", "blocked", "failed"):
    TASK_TRANSITIONS[(_state, "task.canceled")] = "canceled"
for _state in ("paused", "awaiting_human", "blocked", "failed", "canceled", "completed"):
    TASK_TRANSITIONS[(_state, "task.rollback_requested")] = "rollback_pending"
for _state in ("paused", "blocked", "failed", "canceled", "rolled_back", "completed"):
    TASK_TRANSITIONS[(_state, "task.archived")] = "archived"
for _state in ("ready", "paused", "awaiting_human", "blocked", "failed", "completed"):
    TASK_TRANSITIONS[(_state, "project.scope_change_proposed")] = "awaiting_prd_approval"
for _state in (
    "ready", "running", "paused", "awaiting_human",
    "blocked", "failed", "canceling", "rollback_pending", "rolling_back", "completing",
):
    TASK_TRANSITIONS[(_state, "authority.revoked")] = _state
for _state in LIFECYCLES - {"nonexistent", "archived"}:
    TASK_TRANSITIONS[(_state, "task.extension_pin_rebased")] = _state
TASK_TRANSITIONS[("running", "task.authority_reconciliation_required")] = "awaiting_human"
TASK_TRANSITIONS[("rollback_pending", "task.authority_reconciliation_required")] = "awaiting_human"
TASK_TRANSITIONS[("rolling_back", "task.authority_reconciliation_required")] = "awaiting_human"
TASK_TRANSITIONS[("completing", "task.authority_reconciliation_required")] = "awaiting_human"
TASK_TRANSITIONS[("awaiting_prd_approval", "task.downstream_invalidated")] = "awaiting_prd_approval"
for _state in ("ready", "running", "paused", "awaiting_human", "blocked", "failed", "completed"):
    TASK_TRANSITIONS[(_state, "project.repository_realized")] = _state
    TASK_TRANSITIONS[(_state, "project.scope_metadata_updated")] = _state

COORDINATION_CLEAR_EVENTS = frozenset({
    "task.run_started", "task.paused", "task.resumed", "task.canceled",
    "task.rollback_requested", "task.rollback_started", "task.rollback_completed",
    "task.completion_started", "task.completed", "task.archived",
    "task.category_assessed",
    "project.scope_change_proposed",
})
CLOSED = frozenset({"canceled", "rolled_back", "completed", "archived"})

EMPTY_PAYLOAD_EVENTS = frozenset({
    "task.discovery_reopened", "task.paused", "task.cancel_requested", "task.canceled",
    "task.human_decision_required", "task.blocked", "task.failed",
    "task.completion_started", "task.completed", "task.completion_rejected", "task.rollback_started",
    "task.rollback_completed", "task.authority_reconciliation_required",
})

NODE_TRANSITIONS: dict[tuple[str, str], str] = {
    ("pending", "node.ready"): "ready",
    ("ready", "node.leased"): "leased",
    ("leased", "node.started"): "running",
    ("running", "node.output_produced"): "produced",
    ("produced", "node.validation_started"): "validating",
    ("validating", "node.review_started"): "reviewing",
    ("reviewing", "node.review_recorded"): "reviewing",
    ("reviewing", "node.passed"): "passed",
    ("reviewing", "node.revise_requested"): "pending",
}
for _status in ("pending", "ready", "leased", "running", "produced", "validating", "reviewing", "awaiting_human", "blocked", "passed"):
    NODE_TRANSITIONS[(_status, "node.invalidated")] = "invalidated"
for _status in ("running", "produced", "validating", "reviewing"):
    NODE_TRANSITIONS[(_status, "node.blocked")] = "blocked"
    NODE_TRANSITIONS[(_status, "node.awaiting_human")] = "awaiting_human"
for _status in ("leased", "running", "blocked"):
    NODE_TRANSITIONS[(_status, "node.retry_requested")] = "pending"
for _status in ("produced", "validating"):
    NODE_TRANSITIONS[(_status, "node.revise_requested")] = "pending"
for _status in (
    "pending", "ready", "leased", "running", "produced", "validating", "reviewing",
    "blocked", "awaiting_human",
):
    NODE_TRANSITIONS[(_status, "node.cancelled")] = "cancelled"


def transition_node(run: NodeRun, event_type: str) -> NodeRun:
    try:
        target = NODE_TRANSITIONS[(run.status, event_type)]
    except KeyError as error:
        raise ReducerError(f"unlisted node transition: {run.status} + {event_type}") from error
    attempt = run.attempt + 1 if event_type in {"node.revise_requested", "node.retry_requested"} else run.attempt
    return replace(run, status=target, attempt=attempt)


def _exact_payload(event: DomainEvent, fields: frozenset[str]) -> None:
    if set(event.payload) != fields:
        raise ReducerError(f"{event.event_type} payload is not exact")


def _exact_ref(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReducerError(f"{label} is not exact")
    return value


def _nonempty_strings(record: Mapping[str, object], names: Iterable[str], label: str) -> None:
    if any(type(record[name]) is not str or not record[name] for name in names):
        raise ReducerError(f"{label} string fields are invalid")


def _nonempty_string_tuple(value: object, label: str) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or not value
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ReducerError(f"{label} must be a non-empty unique string array")
    return value


def _validate_identity(value: object) -> Mapping[str, object]:
    record = _exact_ref(value, frozenset({"task_id", "owner_id", "runtime_kind", "runtime_lineage_id"}), "task identity")
    _nonempty_strings(record, record, "task identity")
    if record["runtime_kind"] not in {"codex", "hermes"}:
        raise ReducerError("unsupported runtime kind")
    return record


def _validate_scope_ref(value: object, *, expected_status: str | None = None) -> Mapping[str, object]:
    record = _exact_ref(value, frozenset({"scope_id", "version", "digest", "status"}), "project scope ref")
    _nonempty_strings(record, ("scope_id", "digest", "status"), "project scope ref")
    if type(record["version"]) is not int or record["version"] < 1:
        raise ReducerError("project scope version is invalid")
    if expected_status is not None and record["status"] != expected_status:
        raise ReducerError(f"project scope status must be {expected_status}")
    return record


def _validate_baseline_refs(value: object) -> tuple[Mapping[str, object], ...]:
    if type(value) is not tuple or not value:
        raise ReducerError("baseline refs must be a non-empty array")
    records: list[Mapping[str, object]] = []
    identities: set[tuple[object, object]] = set()
    for item in value:
        record = _exact_ref(item, frozenset({"kind", "version", "digest", "approved_by", "approved_at"}), "baseline ref")
        _nonempty_strings(record, ("kind", "digest", "approved_by", "approved_at"), "baseline ref")
        if type(record["version"]) is not int or record["version"] < 1:
            raise ReducerError("baseline version is invalid")
        identity = (record["kind"], record["version"])
        if identity in identities:
            raise ReducerError("duplicate baseline ref")
        identities.add(identity)
        records.append(record)
    return tuple(records)


def _validate_graph_ref_shape(value: object) -> Mapping[str, object]:
    legacy_fields = frozenset({
        "graph_id", "graph_version", "graph_digest", "profile_id", "profile_version",
        "risk_path",
    })
    materialized_fields = legacy_fields | frozenset({
        "profile_digest", "overlay_id", "overlay_version", "overlay_digest",
        "project_config_digest", "support_matrix_digest", "materialization_digest",
    })
    if not isinstance(value, Mapping):
        raise ReducerError("graph ref is not exact")
    actual_fields = frozenset(value)
    if actual_fields not in {legacy_fields, materialized_fields}:
        raise ReducerError("graph ref is not exact")
    record = _exact_ref(
        value,
        actual_fields,
        "graph ref",
    )
    _nonempty_strings(record, record, "graph ref")
    if SEMANTIC_DIGEST.fullmatch(record["graph_digest"]) is None:  # type: ignore[arg-type]
        raise ReducerError("graph ref digest is invalid")
    if record["risk_path"] not in {"full-planned", "compact-planned", "emergency"}:
        raise ReducerError("unknown risk path")
    if set(record) == materialized_fields:
        for field in (
            "profile_digest", "overlay_digest", "project_config_digest",
            "support_matrix_digest", "materialization_digest",
        ):
            if SEMANTIC_DIGEST.fullmatch(record[field]) is None:  # type: ignore[arg-type]
                raise ReducerError("materialized graph ref digest is invalid")
        if record["overlay_id"] != record["risk_path"]:
            raise ReducerError("materialized graph ref risk overlay identity changed")
    return record


def _validate_graph_ref(
    value: object,
    *,
    materialization_record: object | None = None,
) -> Mapping[str, object]:
    record = _validate_graph_ref_shape(value)
    if "materialization_digest" in record:
        from graph_engineering.core.profiles import (
            MaterializationObjectReference,
            MaterializationRecord,
            ProfileContractError,
        )

        if type(materialization_record) not in (
            MaterializationRecord, MaterializationObjectReference,
        ):
            raise ReducerError("materialized graph ref lacks issued authority")
        try:
            materialization_record.require_graph_ref(record)
        except ProfileContractError as error:
            raise ReducerError("materialized graph ref authority mismatch") from error
    return record


def _validate_authority_refs(value: object) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or not value
        or any(type(item) is not str or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ReducerError("authority refs must be a non-empty unique array")
    return value


def _node_event(
    snapshot: TaskSnapshot,
    event: DomainEvent,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> TaskSnapshot | None:
    if event.event_type == "node.run_created":
        if snapshot.lifecycle != "running":
            raise ReducerError("node run can only be created while task is running")
        _exact_payload(event, frozenset({"run_id", "node_id"}))
        run_id = event.payload["run_id"]
        node_id = event.payload["node_id"]
        if type(run_id) is not str or type(node_id) is not str or not run_id or not node_id or run_id in snapshot.node_runs:
            raise ReducerError("invalid or duplicate node run identity")
        values = dict(snapshot.node_runs)
        values[run_id] = NodeRun(run_id, node_id, 1, "pending")
        return replace(
            snapshot, node_runs=values, schema_registry=schema_registry, context=context,
        )
    if not event.event_type.startswith("node."):
        return None
    allowed_lifecycles = (
        {"running", "canceling"}
        if event.event_type == "node.cancelled"
        else {"running", "completing"}
        if event.event_type == "node.invalidated"
        else {"running"}
    )
    if snapshot.lifecycle not in allowed_lifecycles:
        raise ReducerError("node event is not allowed in the current task lifecycle")
    _exact_payload(event, frozenset({"run_id"}))
    run_id = event.payload["run_id"]
    if type(run_id) is not str or run_id not in snapshot.node_runs:
        raise ReducerError("unknown node run")
    values = dict(snapshot.node_runs)
    values[run_id] = transition_node(values[run_id], event.event_type)
    epoch = snapshot.invalidation_epoch + 1 if event.event_type == "node.invalidated" else snapshot.invalidation_epoch
    return replace(
        snapshot, node_runs=values, invalidation_epoch=epoch,
        schema_registry=schema_registry, context=context,
    )


def _finding_event(
    snapshot: TaskSnapshot,
    event: DomainEvent,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> TaskSnapshot | None:
    if event.event_type not in {"finding.opened", "finding.closed"}:
        return None
    if snapshot.lifecycle not in {"running", "completing"}:
        raise ReducerError("finding event is not allowed in the current task lifecycle")
    _exact_payload(event, frozenset({"finding_id"}))
    finding_id = event.payload["finding_id"]
    if type(finding_id) is not str or not finding_id:
        raise ReducerError("finding identity is invalid")
    current = set(snapshot.open_findings)
    if event.event_type == "finding.opened":
        if finding_id in current:
            raise ReducerError("finding is already open")
        current.add(finding_id)
    else:
        if finding_id not in current:
            raise ReducerError("finding is not open")
        current.remove(finding_id)
    return replace(
        snapshot,
        open_findings=tuple(sorted(current)),
        schema_registry=schema_registry,
        context=context,
    )


def _apply(
    snapshot: TaskSnapshot,
    event: DomainEvent,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
    materialization_record: object | None = None,
) -> TaskSnapshot:
    if event.sequence != snapshot.last_event_seq + 1:
        raise ReducerError("event sequence is not contiguous")
    if event.expected_task_revision != snapshot.task_revision:
        raise ReducerError("event expected task revision mismatch")
    if snapshot.lifecycle == "archived":
        raise ReducerError("archived task has no transitions")
    node_result = _node_event(snapshot, event, schema_registry, context)
    if node_result is not None:
        return replace(
            node_result,
            task_revision=snapshot.task_revision + 1,
            last_event_seq=event.sequence,
            schema_registry=schema_registry,
            context=context,
        )
    finding_result = _finding_event(snapshot, event, schema_registry, context)
    if finding_result is not None:
        return replace(
            finding_result,
            task_revision=snapshot.task_revision + 1,
            last_event_seq=event.sequence,
            schema_registry=schema_registry,
            context=context,
        )
    try:
        target = TASK_TRANSITIONS[(snapshot.lifecycle, event.event_type)]
    except KeyError as error:
        raise ReducerError(f"unlisted task transition: {snapshot.lifecycle} + {event.event_type}") from error
    if event.event_type in EMPTY_PAYLOAD_EVENTS:
        _exact_payload(event, frozenset())
    if event.event_type in COORDINATION_CLEAR_EVENTS and (snapshot.unresolved_action_claims or snapshot.resource_leases):
        raise ReducerError("coordination must be clear before transition")
    desired = snapshot.desired_state
    if event.event_type == "task.pause_deferred":
        if set(event.payload) != {"desired_state"} or event.payload["desired_state"] != "paused":
            raise ReducerError("pause-deferred payload is not exact")
        if not snapshot.unresolved_action_claims and not snapshot.resource_leases:
            raise ReducerError("pause-deferred requires active coordination")
        desired = "paused"
    elif event.event_type == "task.paused":
        desired = None
    identity = snapshot.identity
    scope = snapshot.project_scope_ref
    baselines = snapshot.baseline_refs
    graph_ref = snapshot.graph_ref
    authorities = snapshot.authorities
    evidence = snapshot.evidence
    node_runs: Mapping[str, NodeRun] = snapshot.node_runs
    if event.event_type == "task.created":
        _exact_payload(event, frozenset({"identity"}))
        identity = _validate_identity(event.payload["identity"])
    elif event.event_type in {"project.scope_drafted", "project.scope_frozen", "project.scope_rebased"}:
        _exact_payload(event, frozenset({"project_scope_ref"}))
        expected_status = "drafted" if event.event_type == "project.scope_drafted" else "frozen"
        scope = _validate_scope_ref(event.payload["project_scope_ref"], expected_status=expected_status)
    elif event.event_type in {"task.prd_approved", "task.prd_reapproved"}:
        _exact_payload(event, frozenset({
            "baseline_refs", "graph_ref", "authority_refs", "owner_decision_ref",
        }))
        if snapshot.project_scope_ref.get("status") != "frozen":
            raise ReducerError("PRD approval requires a frozen project scope")
        _nonempty_strings(event.payload, ("owner_decision_ref",), "PRD approval")
        raw_baselines = event.payload["baseline_refs"]
        baselines = _validate_baseline_refs(raw_baselines)
        graph_ref = _validate_graph_ref(
            event.payload["graph_ref"], materialization_record=materialization_record,
        )
        authorities = _validate_authority_refs(event.payload["authority_refs"])
    elif event.event_type == "task.downstream_invalidated":
        _exact_payload(event, frozenset({"run_ids"}))
        run_ids = event.payload["run_ids"]
        if type(run_ids) is not tuple or any(type(item) is not str for item in run_ids):
            raise ReducerError("invalidated run IDs must be an array")
        values = dict(snapshot.node_runs)
        for run_id in run_ids:
            if run_id not in values:
                raise ReducerError("unknown invalidated node run")
            values[run_id] = transition_node(values[run_id], "node.invalidated")
        node_runs = values
    elif event.event_type == "project.scope_change_proposed":
        _exact_payload(event, frozenset({"project_scope_ref", "scope_diff_digest"}))
        _validate_scope_ref(event.payload["project_scope_ref"], expected_status="drafted")
        if type(event.payload["scope_diff_digest"]) is not str or not event.payload["scope_diff_digest"]:
            raise ReducerError("scope diff digest is invalid")
    elif event.event_type == "authority.revoked":
        _exact_payload(event, frozenset({"authority_id"}))
        authority_id = event.payload["authority_id"]
        if type(authority_id) is not str or authority_id not in snapshot.authorities:
            raise ReducerError("revoked authority is not active")
        authorities = tuple(item for item in snapshot.authorities if item != authority_id)
    elif event.event_type == "project.repository_realized":
        _exact_payload(event, frozenset({"binding_id", "git_identity"}))
        _nonempty_strings(event.payload, ("binding_id", "git_identity"), "repository realization")
    elif event.event_type == "project.scope_metadata_updated":
        _exact_payload(event, frozenset({"scope_digest", "metadata_revision", "source_digest"}))
        _nonempty_strings(event.payload, ("scope_digest", "source_digest"), "scope metadata")
        if type(event.payload["metadata_revision"]) is not int or event.payload["metadata_revision"] <= 1:
            raise ReducerError("scope metadata revision is invalid")
    elif event.event_type == "task.extension_pin_rebased":
        _exact_payload(event, frozenset({"pin_digest"}))
        _nonempty_strings(event.payload, ("pin_digest",), "extension pin rebase")
    elif event.event_type == "task.category_assessed":
        _exact_payload(event, frozenset({"evidence_ref"}))
        raw_evidence = event.payload["evidence_ref"]
        if not isinstance(raw_evidence, Mapping) or set(raw_evidence) != {
            "evidence_id", "evidence_type", "source_ref", "digest", "trust",
        }:
            raise ReducerError("category assessment evidence ref is not exact")
        reference = EvidenceRef(
            evidence_id=raw_evidence["evidence_id"],  # type: ignore[arg-type]
            evidence_type=raw_evidence["evidence_type"],  # type: ignore[arg-type]
            source_ref=raw_evidence["source_ref"],  # type: ignore[arg-type]
            digest=raw_evidence["digest"],  # type: ignore[arg-type]
            trust=raw_evidence["trust"],  # type: ignore[arg-type]
        )
        if reference.evidence_type != "category-completion-assessment" or (
            reference.trust != "factory-attested"
        ):
            raise ReducerError("category assessment evidence authority is invalid")
        if any(item.evidence_id == reference.evidence_id for item in evidence):
            raise ReducerError("category assessment evidence is duplicated")
        evidence = (*evidence, reference)
    elif event.event_type == "task.prd_approval_requested":
        _exact_payload(event, frozenset({"prd_candidate_ref"}))
        _nonempty_strings(event.payload, ("prd_candidate_ref",), "PRD approval request")
        if snapshot.project_scope_ref.get("status") != "drafted":
            raise ReducerError("PRD approval request requires a drafted project scope")
    elif event.event_type == "task.run_started":
        _exact_payload(event, frozenset({"compatibility_evidence_ref", "lease_plan_ref"}))
        _nonempty_strings(event.payload, event.payload, "run precondition")
    elif event.event_type == "task.resumed":
        _exact_payload(event, frozenset({"resolution_evidence_refs", "compatibility_evidence_ref"}))
        _nonempty_strings(event.payload, ("compatibility_evidence_ref",), "resume precondition")
        _nonempty_string_tuple(event.payload["resolution_evidence_refs"], "resolution evidence refs")
    elif event.event_type == "task.rollback_requested":
        _exact_payload(event, frozenset({
            "compensable_action_refs", "rollback_plan_ref", "authority_ref",
        }))
        _nonempty_strings(event.payload, ("rollback_plan_ref", "authority_ref"), "rollback precondition")
        _nonempty_string_tuple(event.payload["compensable_action_refs"], "compensable action refs")
        if event.payload["authority_ref"] not in snapshot.authorities:
            raise ReducerError("rollback authority is not active")
    elif event.event_type == "task.archived":
        _exact_payload(event, frozenset({"retention_plan_ref", "rollback_clearance_ref"}))
        _nonempty_strings(event.payload, event.payload, "archive precondition")
    if (
        event.event_type == "task.cancel_requested"
        and snapshot.lifecycle != "running"
        and not snapshot.unresolved_action_claims
        and not snapshot.resource_leases
    ):
        raise ReducerError("deferred cancellation requires active coordination")
    if event.event_type in {"task.resumed", "task.completion_started"} and snapshot.open_findings:
        raise ReducerError(f"{event.event_type} requires resolved findings")
    if target in CLOSED and (snapshot.unresolved_action_claims or snapshot.resource_leases):
        raise ReducerError("closed state requires clear coordination")
    if target in CLOSED:
        authorities = ()
    epoch = snapshot.invalidation_epoch + 1 if event.event_type in {
        "project.scope_rebased", "task.downstream_invalidated",
    } else snapshot.invalidation_epoch
    return replace(
        snapshot,
        lifecycle=target,
        task_revision=snapshot.task_revision + 1,
        last_event_seq=event.sequence,
        desired_state=desired,
        invalidation_epoch=epoch,
        identity=identity,
        project_scope_ref=scope,
        baseline_refs=baselines,
        graph_ref=graph_ref,
        authorities=authorities,
        evidence=evidence,
        node_runs=node_runs,
        schema_registry=schema_registry,
        context=context,
    )


def apply_events(
    snapshot: TaskSnapshot | None,
    events: Iterable[DomainEvent],
    *,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
    materialization_record: object | None = None,
) -> TaskSnapshot:
    current = TaskSnapshot.initial(schema_registry, context) if snapshot is None else snapshot
    if snapshot is not None:
        _validate_contract_pins(current.contract_pins, schema_registry, context)
    for event in events:
        current = _apply(
            current, event, schema_registry, context, materialization_record,
        )
    return current


public_transition_events = {
    "create": "task.created",
    "bind_project_scope": "project.scope_drafted",
    "request_prd_approval": "task.prd_approval_requested",
    "revise_discovery": "task.discovery_reopened",
    "run": "task.run_started",
    "resume": "task.resumed",
    "rollback": "task.rollback_requested",
    "archive": "task.archived",
    "realize_repository": "project.repository_realized",
    "update_scope_metadata": "project.scope_metadata_updated",
    "rebase_extensions": "task.extension_pin_rebased",
}


def _event(current: TaskSnapshot, offset: int, event_type: str, payload: Mapping[str, object]) -> DomainEvent:
    return DomainEvent(
        current.last_event_seq + offset,
        current.task_revision + offset - 1,
        event_type,
        payload,
    )


def decide_command(
    snapshot: TaskSnapshot | None,
    command: TaskCommand,
    *,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
    materialization_record: object | None = None,
) -> tuple[DomainEvent, ...]:
    """Translate the closed public task command set into reducer events."""

    current = TaskSnapshot.initial(schema_registry, context) if snapshot is None else snapshot
    if snapshot is not None:
        _validate_contract_pins(current.contract_pins, schema_registry, context)
    if command.expected_task_revision != current.task_revision:
        raise ReducerError("command expected task revision mismatch")
    payload_commands = {
        "create", "bind_project_scope", "request_prd_approval", "approve_prd",
        "propose_scope_change", "run", "resume", "revoke", "rollback", "archive",
        "realize_repository",
        "update_scope_metadata",
        "rebase_extensions",
    }
    if command.command_type not in payload_commands and command.payload:
        raise ReducerError("command payload must be empty")
    event_type = public_transition_events.get(command.command_type)
    payload: Mapping[str, object] = command.payload
    if command.command_type in {"run", "resume", "rollback"} and (
        current.unresolved_action_claims or current.resource_leases
    ):
        raise ReducerError(f"{command.command_type} requires clear coordination")
    if command.command_type == "pause":
        if current.lifecycle not in {"ready", "running"}:
            raise ReducerError("pause is not a public command in the current state")
        if current.lifecycle == "running" and (current.unresolved_action_claims or current.resource_leases):
            event_type = "task.pause_deferred"
            payload = {"desired_state": "paused"}
        else:
            event_type = "task.paused"
    elif command.command_type == "cancel":
        direct = current.lifecycle in {
            "discovering", "awaiting_prd_approval", "ready", "paused", "awaiting_human", "blocked", "failed",
        } and not current.unresolved_action_claims and not current.resource_leases
        event_type = "task.canceled" if direct else "task.cancel_requested"
    elif command.command_type == "propose_scope_change":
        required = {"project_scope_ref", "scope_diff_digest", "run_ids"}
        if set(command.payload) != required:
            raise ReducerError("propose_scope_change payload is not exact")
        first = _event(current, 1, "project.scope_change_proposed", {
            "project_scope_ref": command.payload["project_scope_ref"],
            "scope_diff_digest": command.payload["scope_diff_digest"],
        })
        second = _event(current, 2, "task.downstream_invalidated", {"run_ids": command.payload["run_ids"]})
        apply_events(
            current, (first, second), schema_registry=schema_registry, context=context,
            materialization_record=materialization_record,
        )
        return first, second
    elif command.command_type == "revoke":
        if set(command.payload) != {"authority_id"}:
            raise ReducerError("revoke payload is not exact")
        authority_id = command.payload["authority_id"]
        if type(authority_id) is not str or authority_id not in current.authorities:
            raise ReducerError("revoked authority is not active")
        first = _event(current, 1, "authority.revoked", {"authority_id": authority_id})
        second_type: str | None = None
        if current.lifecycle in {"ready", "running"}:
            second_type = (
                "task.authority_reconciliation_required"
                if authority_id in current.action_claim_authorities.values()
                else "task.paused"
            )
        elif current.lifecycle in {"rollback_pending", "rolling_back", "completing"}:
            second_type = "task.authority_reconciliation_required"
        events = (first,) if second_type is None else (first, _event(current, 2, second_type, {}))
        apply_events(
            current, events, schema_registry=schema_registry, context=context,
            materialization_record=materialization_record,
        )
        return events
    elif command.command_type == "approve_prd":
        required = {
            "project_scope_ref", "baseline_refs", "graph_ref", "authority_refs",
            "owner_decision_ref",
        }
        if set(command.payload) != required:
            raise ReducerError("approve_prd payload is not exact")
        reapproval = bool(current.baseline_refs)
        scope_type = "project.scope_rebased" if reapproval else "project.scope_frozen"
        approval_type = "task.prd_reapproved" if reapproval else "task.prd_approved"
        first = _event(
            current,
            1,
            scope_type,
            {"project_scope_ref": command.payload["project_scope_ref"]},
        )
        second = _event(
            current,
            2,
            approval_type,
            {
                "baseline_refs": command.payload["baseline_refs"],
                "graph_ref": command.payload["graph_ref"],
                "authority_refs": command.payload["authority_refs"],
                "owner_decision_ref": command.payload["owner_decision_ref"],
            },
        )
        apply_events(
            current, (first, second), schema_registry=schema_registry, context=context,
            materialization_record=materialization_record,
        )
        return first, second
    if event_type is None:
        raise ReducerError("unknown task command")
    event = DomainEvent(current.last_event_seq + 1, current.task_revision, event_type, payload)
    apply_events(
        current, (event,), schema_registry=schema_registry, context=context,
        materialization_record=materialization_record,
    )
    return (event,)
