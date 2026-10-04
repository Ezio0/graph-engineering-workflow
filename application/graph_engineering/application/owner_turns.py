"""Versioned single-operation owner-turn application use case."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from graph_engineering.application.runtime import (
    RuntimeMutationGateway,
    RuntimeQueryGateway,
    RuntimeSession,
)
from graph_engineering.application.tasks import TaskApplication
from graph_engineering.core.graph.state import TaskCommand
from graph_engineering.core.project import ProjectScope
from graph_engineering.core.runtime import (
    DeliveryPresentation,
    HumanDecisionRequest,
    runtime_record_digest,
)


class OwnerTurnError(RuntimeError):
    """Stable fail-closed owner-turn rejection."""


OPERATIONS = frozenset({
    "discover", "create", "clarify", "approve", "run",
    "status", "resume", "escalate", "result",
    "grant_learning", "revoke_learning", "record_learning_context",
    "collect_learning", "report_learning", "purge_learning",
})
_NO_TASK = frozenset({"discover", "create"})
_PAYLOAD_FIELDS = {
    "grant_learning": frozenset({"expected_generation", "metric_ids", "expires_at_ns"}),
    "revoke_learning": frozenset({"expected_generation"}),
    "record_learning_context": frozenset({"expected_generation", "expected_context_version", "abandonment_code", "prior_task_id"}),
    "collect_learning": frozenset({"expected_head", "expected_generation", "expected_context_version"}),
    "report_learning": frozenset({"experiment_id", "task_ids"}),
    "purge_learning": frozenset({"trigger", "expected_generation"}),
    "discover": frozenset(),
    "create": frozenset({"occurred_at", "lease_ttl_ns"}),
    "clarify": frozenset({
        "expected_task_revision", "occurred_at", "lease_ttl_ns",
        "project_scope", "prd_candidate_ref",
    }),
    "approve": frozenset({
        "expected_task_revision", "occurred_at", "lease_ttl_ns", "approval",
    }),
    "run": frozenset({
        "expected_task_revision", "occurred_at", "lease_ttl_ns",
        "compatibility_evidence_ref", "lease_plan_ref",
    }),
    "status": frozenset(),
    "resume": frozenset(),
    "escalate": frozenset({
        "request_id", "decision_kind", "decision_payload_ref",
        "decision_payload_digest",
    }),
    "result": frozenset({"presentation"}),
}


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise OwnerTurnError(f"owner-turn {label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class OwnerTurnRequest:
    schema_version: str
    turn_id: str
    operation: str
    task_id: str | None
    owner_id: str
    runtime_kind: str
    runtime_lineage_id: str
    payload: Mapping[str, object]
    request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> OwnerTurnRequest:
        fields = {
            "schema_version", "turn_id", "operation", "task_id", "owner_id",
            "runtime_kind", "runtime_lineage_id", "payload", "request_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise OwnerTurnError("owner-turn request is not exact")
        if value["schema_version"] != "1.0":
            raise OwnerTurnError("owner-turn schema version is incompatible")
        operation = _text(value["operation"], "operation")
        if operation not in OPERATIONS:
            raise OwnerTurnError("owner-turn operation is unknown")
        task_id = value["task_id"]
        if operation in _NO_TASK:
            if task_id is not None:
                raise OwnerTurnError("owner-turn operation does not accept a task ID")
        elif task_id is None:
            raise OwnerTurnError("owner-turn operation requires a task ID")
        else:
            task_id = _text(task_id, "task ID")
        payload = value["payload"]
        if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_FIELDS[operation]:
            raise OwnerTurnError("owner-turn operation payload is not exact")
        if operation in {
            "grant_learning", "revoke_learning", "record_learning_context",
            "collect_learning", "report_learning", "purge_learning",
        }:
            from graph_engineering.core.learning import LearningError
            from graph_engineering.application.learning import LearningPolicyLoader

            try:
                LearningPolicyLoader.from_installation().validate_request({
                    "schema_version": "1.0.0", "operation": operation,
                    "request_id": value["turn_id"], "task_id": task_id, **payload,
                })
            except LearningError:
                raise OwnerTurnError("owner-turn learning payload is invalid") from None
        for name in ("schema_version", "turn_id", "owner_id", "runtime_kind", "runtime_lineage_id"):
            _text(value[name], name)
        if operation in {"create", "clarify", "approve", "run"}:
            _text(payload["occurred_at"], "occurred at")
            if type(payload["lease_ttl_ns"]) is not int or payload["lease_ttl_ns"] < 1:
                raise OwnerTurnError("owner-turn lease TTL is invalid")
        if operation in {"clarify", "approve", "run"} and (
            type(payload["expected_task_revision"]) is not int
            or payload["expected_task_revision"] < 1
        ):
            raise OwnerTurnError("owner-turn expected task revision is invalid")
        text_payload_fields = {
            "clarify": ("prd_candidate_ref",),
            "run": ("compatibility_evidence_ref", "lease_plan_ref"),
            "escalate": (
                "request_id", "decision_kind", "decision_payload_ref",
                "decision_payload_digest",
            ),
        }.get(operation, ())
        for name in text_payload_fields:
            _text(payload[name], name)
        if operation == "clarify" and not isinstance(payload["project_scope"], Mapping):
            raise OwnerTurnError("owner-turn ProjectScope is invalid")
        if operation == "approve" and not isinstance(payload["approval"], Mapping):
            raise OwnerTurnError("owner-turn approval is invalid")
        if operation == "result" and not isinstance(payload["presentation"], Mapping):
            raise OwnerTurnError("owner-turn presentation is invalid")
        body = {key: item for key, item in value.items() if key != "request_digest"}
        expected = runtime_record_digest("owner-turn-request", body)
        if value["request_digest"] != expected:
            raise OwnerTurnError("owner-turn request digest is invalid")
        return cls(
            value["schema_version"], value["turn_id"], operation, task_id,
            value["owner_id"], value["runtime_kind"], value["runtime_lineage_id"],
            dict(payload), value["request_digest"],
        )

    def require_binding(self, owner_id: str, runtime_kind: str, lineage_id: str) -> None:
        if (self.owner_id, self.runtime_kind, self.runtime_lineage_id) != (
            owner_id, runtime_kind, lineage_id,
        ):
            raise OwnerTurnError("owner-turn request is not authorized")

    def require_runtime(self, session: RuntimeSession) -> None:
        self.require_binding(
            session.proof.owner_id, session.capabilities.runtime_kind, session.proof.lineage_id,
        )


class OwnerTurnApplication:
    """Dispatch exactly one installed owner turn to existing application use cases."""

    __slots__ = ("_tasks", "_scope_loader", "_session_factory")

    def __init__(
        self,
        tasks: TaskApplication,
        scope_loader: Callable[[Mapping[str, object]], ProjectScope],
        session_factory: Callable[[], RuntimeSession],
    ) -> None:
        if type(tasks) is not TaskApplication or not callable(scope_loader) or not callable(session_factory):
            raise OwnerTurnError("owner-turn application dependencies are invalid")
        self._tasks = tasks
        self._scope_loader = scope_loader
        self._session_factory = session_factory

    @staticmethod
    def _task_id(request: OwnerTurnRequest) -> str:
        if request.operation == "create":
            return "task:" + request.request_digest.removeprefix("sha256-jcs-v1:")
        if request.task_id is None:
            raise OwnerTurnError("owner-turn operation has no task")
        return request.task_id

    def execute(self, request: OwnerTurnRequest) -> dict[str, object]:
        session = self._session_factory()
        try:
            request.require_runtime(session)
            task_id = None if request.operation == "discover" else self._task_id(request)
            result = self._dispatch(session, request, task_id)
            body: dict[str, object] = {
                "schema_version": "1.0", "turn_id": request.turn_id,
                "operation": request.operation, "task_id": task_id,
                "owner_id": session.proof.owner_id,
                "runtime_kind": session.capabilities.runtime_kind,
                "runtime_lineage_id": session.proof.lineage_id,
                "status": "succeeded", "exit_code": 0, "result": result,
            }
            return {
                **body, "result_digest": runtime_record_digest("owner-turn-result", body),
            }
        finally:
            session.close()

    def _dispatch(
        self,
        session: RuntimeSession,
        request: OwnerTurnRequest,
        task_id: str | None,
    ) -> Mapping[str, object]:
        operation = request.operation
        payload = request.payload
        if operation == "discover":
            return {"capability_digest": session.capabilities.capability_digest}
        assert task_id is not None
        if operation in {
            "grant_learning", "revoke_learning", "record_learning_context",
            "collect_learning", "report_learning", "purge_learning",
        }:
            learning_request = {
                "schema_version": "1.0.0", "operation": operation,
                "task_id": task_id, "request_id": request.turn_id, **payload,
            }
            return RuntimeMutationGateway.invoke(
                session, session.proof,
                lambda runtime: self._tasks.learning(learning_request, runtime),
            )
        if operation == "create":
            identity = {
                "task_id": task_id, "owner_id": session.proof.owner_id,
                "runtime_kind": session.capabilities.runtime_kind,
                "runtime_lineage_id": session.proof.lineage_id,
            }
            receipt = RuntimeMutationGateway.create(
                session, session.proof, identity,
                lambda runtime: self._tasks.execute(
                    task_id, TaskCommand("create", 0, {"identity": identity}), runtime,
                ),
                occurred_at=payload["occurred_at"],  # type: ignore[arg-type]
                lease_ttl_ns=payload["lease_ttl_ns"],  # type: ignore[arg-type]
            )
            return {"task_revision": receipt.task_revision, "event_types": list(receipt.event_types)}
        if operation == "clarify":
            project_scope = self._scope_loader(payload["project_scope"])  # type: ignore[arg-type]
            clarified = RuntimeMutationGateway.task(
                session, session.proof, self._tasks, task_id,
                lambda runtime: self._tasks.execute_scope(
                    task_id,
                    TaskCommand("bind_project_scope", payload["expected_task_revision"], {
                        "project_scope_ref": {
                            "scope_id": project_scope.scope_id, "version": project_scope.version,
                            "digest": project_scope.scope_digest, "status": "drafted",
                        },
                    }),
                    project_scope, runtime,
                ),
                occurred_at=payload["occurred_at"],  # type: ignore[arg-type]
                lease_ttl_ns=payload["lease_ttl_ns"],  # type: ignore[arg-type]
            )
            requested = RuntimeMutationGateway.task(
                session, session.proof, self._tasks, task_id,
                lambda runtime: self._tasks.execute(
                    task_id,
                    TaskCommand("request_prd_approval", clarified.task_revision, {
                        "prd_candidate_ref": payload["prd_candidate_ref"],
                    }),
                    runtime,
                ),
                occurred_at=payload["occurred_at"],  # type: ignore[arg-type]
                lease_ttl_ns=payload["lease_ttl_ns"],  # type: ignore[arg-type]
            )
            return {"task_revision": requested.task_revision, "event_types": list(requested.event_types)}
        if operation == "approve":
            current = RuntimeQueryGateway.show(session, session.proof, self._tasks, task_id)
            scope_ref = dict(current.snapshot.project_scope_ref or {})
            scope_ref["status"] = "frozen"
            approval = dict(payload["approval"])  # type: ignore[arg-type]
            approval["project_scope_ref"] = scope_ref
            receipt = RuntimeMutationGateway.task(
                session, session.proof, self._tasks, task_id,
                lambda runtime: self._tasks.execute(
                    task_id,
                    TaskCommand("approve_prd", payload["expected_task_revision"], approval),
                    runtime,
                ),
                occurred_at=payload["occurred_at"],  # type: ignore[arg-type]
                lease_ttl_ns=payload["lease_ttl_ns"],  # type: ignore[arg-type]
            )
            return {"task_revision": receipt.task_revision, "event_types": list(receipt.event_types)}
        if operation == "run":
            receipt = RuntimeMutationGateway.task(
                session, session.proof, self._tasks, task_id,
                lambda runtime: self._tasks.execute(
                    task_id,
                    TaskCommand("run", payload["expected_task_revision"], {
                        "compatibility_evidence_ref": payload["compatibility_evidence_ref"],
                        "lease_plan_ref": payload["lease_plan_ref"],
                    }),
                    runtime,
                ),
                occurred_at=payload["occurred_at"],  # type: ignore[arg-type]
                lease_ttl_ns=payload["lease_ttl_ns"],  # type: ignore[arg-type]
            )
            return {"task_revision": receipt.task_revision, "event_types": list(receipt.event_types)}
        if operation in {"status", "resume"}:
            view = RuntimeQueryGateway.show(session, session.proof, self._tasks, task_id)
            return {
                "task_revision": view.snapshot.task_revision,
                "repository_revision": view.repository_revision,
                "lifecycle": view.snapshot.lifecycle,
                "snapshot_digest": view.snapshot.snapshot_digest,
            }
        if operation == "escalate":
            body = {
                "schema_version": "1.0", "request_id": payload["request_id"],
                "task_id": task_id, "owner_id": session.proof.owner_id,
                "decision_kind": payload["decision_kind"],
                "decision_payload_ref": payload["decision_payload_ref"],
                "decision_payload_digest": payload["decision_payload_digest"],
            }
            decision = session.request_human(HumanDecisionRequest.from_dict({
                **body, "request_digest": runtime_record_digest("human-decision-request", body),
            }))
            return decision.to_dict()
        if operation == "result":
            presentation = DeliveryPresentation.from_dict(payload["presentation"])
            if presentation.task_id != task_id:
                raise OwnerTurnError("owner-turn presentation task binding is invalid")
            current = RuntimeQueryGateway.show(session, session.proof, self._tasks, task_id)
            if presentation.content_digest != current.snapshot.snapshot_digest:
                raise OwnerTurnError("owner-turn presentation snapshot binding is invalid")
            return session.present(presentation).to_dict()
        raise OwnerTurnError("owner-turn operation is not implemented")
