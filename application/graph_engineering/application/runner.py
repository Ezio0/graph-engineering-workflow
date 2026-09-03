"""Bounded in-request graph scheduling and reviewer convergence."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from graph_engineering.application.tasks import (
    ApplicationError,
    RuntimeContext,
    TaskApplication,
    _RunnerTransitionChannel,
)
from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.graph.budget import LoopBudgetError, LoopBudgetRegistry
from graph_engineering.core.graph.definition import GraphDefinition, NodeDefinition
from graph_engineering.core.graph.state import DomainEvent, NodeRun, TaskSnapshot
from graph_engineering.core.profiles import MaterializedProfileGraph, ProfileContractError
from graph_engineering.storage.ports import ObjectRepositoryPort


class RunnerError(ValueError):
    """A deterministic runner invariant or adapter-result rejection."""


class NodeRuntimeFailure(RuntimeError):
    """A runtime-declared stable failure that may select a graph fallback."""

    def __init__(self, error_code: str, *, edge_id: str | None = None) -> None:
        self.error_code = _identity(error_code, "runtime error code")
        self.edge_id = None if edge_id is None else _identity(edge_id, "runtime failure edge")
        super().__init__(self.error_code)


def _identity(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise RunnerError(f"{label} is invalid")
    return value


def _actor(value: object, label: str) -> str:
    actor = _identity(value, label)
    if not actor.isascii():
        raise RunnerError(f"{label} must be ASCII canonical identity")
    return actor.casefold()


def _strings(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or any(type(item) is not str or not item for item in value):
        raise RunnerError(f"{label} must be a string array")
    result = tuple(value)
    if len(result) != len(set(result)) or (not allow_empty and not result):
        raise RunnerError(f"{label} must be unique and non-empty where required")
    return result


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    severity: str
    evidence: tuple[str, ...]
    required_change: str
    verification: str
    owning_node: str

    def __post_init__(self) -> None:
        _identity(self.finding_id, "finding ID")
        _identity(self.required_change, "required change")
        _identity(self.verification, "finding verification")
        _identity(self.owning_node, "finding owner")
        if self.severity not in {"blocker", "major", "minor"}:
            raise RunnerError("finding severity is invalid")
        _strings(self.evidence, "finding evidence", allow_empty=False)

    def to_dict(self, *, body_digest: str, reviewer_id: str, status: str = "open") -> dict[str, object]:
        if status not in {"open", "closed"}:
            raise RunnerError("finding status is invalid")
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "status": status,
            "evidence": list(self.evidence),
            "required_change": self.required_change,
            "verification": self.verification,
            "owning_node": self.owning_node,
            "body_digest": body_digest,
            "reviewer_id": reviewer_id,
        }


@dataclass(frozen=True, slots=True)
class NodeCandidate:
    body: bytes
    body_digest: str
    author_id: str
    route_roots: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.body) is not bytes:
            raise RunnerError("candidate body must be exact bytes")
        expected = "sha256:" + hashlib.sha256(self.body).hexdigest()
        if self.body_digest != expected:
            raise RunnerError("candidate body digest mismatch")
        _actor(self.author_id, "candidate author")
        try:
            frozen = freeze(self.route_roots)
        except (TypeError, ValueError) as error:
            raise RunnerError("candidate route roots are not exact JSON") from error
        if not isinstance(frozen, Mapping):
            raise RunnerError("candidate route roots must be an object")
        object.__setattr__(self, "route_roots", frozen)


@dataclass(frozen=True, slots=True)
class ValidationResult:
    passed: bool
    evidence_refs: tuple[str, ...]
    trust: str
    finding: Finding | None = None

    def __post_init__(self) -> None:
        if type(self.passed) is not bool:
            raise RunnerError("validation result must be exact boolean")
        _strings(self.evidence_refs, "validation evidence", allow_empty=not self.passed)
        if self.passed:
            if self.trust != "validated" or self.finding is not None:
                raise RunnerError("passing validation must yield validated trust and no finding")
        elif self.trust != "candidate" or type(self.finding) is not Finding:
            raise RunnerError("failed validation must yield one owned finding")


@dataclass(frozen=True, slots=True)
class ReviewResult:
    verdict: str
    reviewer_id: str
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict not in {"PASS", "REVISE", "ESCALATE", "BLOCKED"}:
            raise RunnerError("review verdict is invalid")
        _actor(self.reviewer_id, "reviewer")
        if any(type(item) is not Finding for item in self.findings):
            raise RunnerError("review findings are invalid")
        ids = tuple(item.finding_id for item in self.findings)
        if len(ids) != len(set(ids)):
            raise RunnerError("review finding identities are duplicated")
        if self.verdict == "PASS" and self.findings:
            raise RunnerError("PASS review cannot contain findings")
        if self.verdict == "REVISE" and not self.findings:
            raise RunnerError("REVISE review requires findings")


class NodeRuntime(Protocol):
    def execute(
        self,
        node: NodeDefinition,
        *,
        run_id: str,
        attempt: int,
        runtime: RuntimeContext,
    ) -> NodeCandidate: ...


class CandidateValidator(Protocol):
    def validate(
        self,
        node: NodeDefinition,
        candidate: NodeCandidate,
        *,
        context: WorkContext,
    ) -> ValidationResult: ...


class CandidateReviewer(Protocol):
    def review(
        self,
        node: NodeDefinition,
        candidate: NodeCandidate,
        validation: ValidationResult,
        *,
        runtime: RuntimeContext,
    ) -> ReviewResult: ...


@dataclass(frozen=True, slots=True)
class RunResult:
    task_id: str
    lifecycle: str
    task_revision: int
    status: str
    steps: int
    ready_node_ids: tuple[str, ...]


class RunnerSnapshot:
    OUTPUT_FIELDS = frozenset({
        "node_id", "run_id", "attempt", "body_digest", "author_id", "trust",
        "evidence_refs", "verdict", "reviewer_id", "route_roots",
    })
    FINDING_FIELDS = frozenset({
        "finding_id", "severity", "status", "evidence", "required_change",
        "verification", "owning_node", "body_digest", "reviewer_id",
    })
    REVIEW_FIELDS = frozenset({
        "node_id", "run_id", "attempt", "body_digest", "reviewer_id", "verdict",
        "finding_ids", "findings",
    })

    def __init__(self, value: Mapping[str, object]) -> None:
        fields = {
            "schema_version", "runtime_lineage_id", "graph_digest", "node_outputs",
            "selected_edges", "failure_routes", "findings", "review_history",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise RunnerError("runner snapshot properties are not exact")
        self.runtime_lineage_id = _identity(value.get("runtime_lineage_id"), "runner lineage")
        self.graph_digest = _identity(value.get("graph_digest"), "runner graph digest")
        raw_outputs = value.get("node_outputs")
        raw_findings = value.get("findings")
        raw_reviews = value.get("review_history")
        if not isinstance(raw_outputs, Mapping) or not isinstance(raw_findings, Mapping):
            raise RunnerError("runner output or finding index is invalid")
        if type(raw_reviews) is not list:
            raise RunnerError("runner review history is invalid")
        self.selected_edges = list(_strings(value.get("selected_edges"), "selected edges"))
        raw_failure_routes = value.get("failure_routes")
        if (
            not isinstance(raw_failure_routes, Mapping)
            or any(
                type(source) is not str or not source or type(target) is not str or not target
                for source, target in raw_failure_routes.items()
            )
        ):
            raise RunnerError("runner failure routes are invalid")
        self.failure_routes = dict(raw_failure_routes)
        self.node_outputs: dict[str, dict[str, object]] = {}
        for node_id, raw in raw_outputs.items():
            if type(node_id) is not str or not isinstance(raw, Mapping) or set(raw) != self.OUTPUT_FIELDS:
                raise RunnerError("runner node output is not exact")
            if raw.get("node_id") != node_id:
                raise RunnerError("runner node output key mismatch")
            self._validate_output(raw)
            self.node_outputs[node_id] = thaw(freeze(raw))  # type: ignore[assignment]
        self.findings: dict[str, dict[str, object]] = {}
        for finding_id, raw in raw_findings.items():
            if type(finding_id) is not str or not isinstance(raw, Mapping) or set(raw) != self.FINDING_FIELDS:
                raise RunnerError("runner finding is not exact")
            if raw.get("finding_id") != finding_id:
                raise RunnerError("runner finding key mismatch")
            self._validate_finding(raw)
            self.findings[finding_id] = thaw(freeze(raw))  # type: ignore[assignment]
        self.review_history: list[dict[str, object]] = []
        for raw in raw_reviews:
            if not isinstance(raw, Mapping) or set(raw) != self.REVIEW_FIELDS:
                raise RunnerError("runner review record is not exact")
            self._validate_review(raw)
            self.review_history.append(thaw(freeze(raw)))  # type: ignore[arg-type]

    @staticmethod
    def _validate_output(raw: Mapping[str, object]) -> None:
        for field in ("node_id", "run_id", "body_digest", "author_id", "trust"):
            _identity(raw.get(field), f"output {field}")
        if type(raw.get("attempt")) is not int or raw["attempt"] < 1:  # type: ignore[operator]
            raise RunnerError("output attempt is invalid")
        _actor(raw.get("author_id"), "output author")
        if raw.get("trust") not in {"candidate", "validated", "independently_reviewed"}:
            raise RunnerError("output trust is invalid")
        _strings(raw.get("evidence_refs"), "output evidence")
        if raw.get("verdict") not in {None, "PASS", "REVISE", "ESCALATE", "BLOCKED"}:
            raise RunnerError("output verdict is invalid")
        if raw.get("reviewer_id") is not None:
            _actor(raw.get("reviewer_id"), "output reviewer")
        if not isinstance(raw.get("route_roots"), Mapping):
            raise RunnerError("output route roots are invalid")

    @staticmethod
    def _validate_finding(raw: Mapping[str, object]) -> None:
        for field in (
            "finding_id", "required_change", "verification", "owning_node",
            "body_digest", "reviewer_id",
        ):
            _identity(raw.get(field), f"finding {field}")
        if raw.get("severity") not in {"blocker", "major", "minor"}:
            raise RunnerError("stored finding severity is invalid")
        if raw.get("status") not in {"open", "closed"}:
            raise RunnerError("stored finding status is invalid")
        _strings(raw.get("evidence"), "stored finding evidence", allow_empty=False)
        _actor(raw.get("reviewer_id"), "stored finding reviewer")

    @staticmethod
    def _validate_review(raw: Mapping[str, object]) -> None:
        for field in ("node_id", "run_id", "body_digest", "reviewer_id"):
            _identity(raw.get(field), f"review {field}")
        if type(raw.get("attempt")) is not int or raw["attempt"] < 1:  # type: ignore[operator]
            raise RunnerError("review attempt is invalid")
        if raw.get("verdict") not in {"PASS", "REVISE", "ESCALATE", "BLOCKED"}:
            raise RunnerError("stored review verdict is invalid")
        _strings(raw.get("finding_ids"), "stored review finding IDs")
        raw_findings = raw.get("findings")
        if type(raw_findings) is not list:
            raise RunnerError("stored review findings are invalid")
        for finding in raw_findings:
            if not isinstance(finding, Mapping) or set(finding) != RunnerSnapshot.FINDING_FIELDS:
                raise RunnerError("stored review finding is not exact")
            RunnerSnapshot._validate_finding(finding)
        if [finding["finding_id"] for finding in raw_findings] != raw.get("finding_ids"):
            raise RunnerError("stored review finding identities differ")
        _actor(raw.get("reviewer_id"), "stored review reviewer")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "runtime_lineage_id": self.runtime_lineage_id,
            "graph_digest": self.graph_digest,
            "node_outputs": self.node_outputs,
            "selected_edges": self.selected_edges,
            "failure_routes": self.failure_routes,
            "findings": self.findings,
            "review_history": self.review_history,
        }


class ApplicationRunner:
    """Advance one task only while the current runtime request remains active."""

    STABLE_LIFECYCLES = frozenset({
        "paused", "awaiting_human", "blocked", "failed", "canceling", "canceled",
        "rollback_pending", "rolling_back", "rolled_back", "completing", "completed", "archived",
    })

    def __init__(
        self,
        application: TaskApplication,
        objects: ObjectRepositoryPort,
        loop_budgets: LoopBudgetRegistry,
        *,
        context: WorkContext,
        materialization: MaterializedProfileGraph | None = None,
        _channel: _RunnerTransitionChannel | None = None,
    ) -> None:
        if type(application) is not TaskApplication or type(loop_budgets) is not LoopBudgetRegistry:
            raise RunnerError("runner requires exact application and loop-budget registry")
        if type(context) is not WorkContext:
            raise RunnerError("runner requires an exact work context")
        if type(_channel) is not _RunnerTransitionChannel:
            raise RunnerError("runner must be created by TaskApplication.create_runner")
        if materialization is not None and type(materialization) is not MaterializedProfileGraph:
            raise RunnerError("runner materialization must be factory-issued")
        if materialization is not None:
            try:
                materialization.require_loop_budget_registry(loop_budgets)
            except ProfileContractError as error:
                raise RunnerError("runner materialization is not current") from error
        self._application = application
        self._objects = objects
        self._budgets = loop_budgets
        self._materialization = materialization
        self._context = context
        self.__transition_channel = _channel

    @staticmethod
    def _events(snapshot: TaskSnapshot, declarations: Sequence[tuple[str, Mapping[str, object]]]) -> tuple[DomainEvent, ...]:
        return tuple(
            DomainEvent(
                snapshot.last_event_seq + offset,
                snapshot.task_revision + offset - 1,
                event_type,
                payload,
            )
            for offset, (event_type, payload) in enumerate(declarations, start=1)
        )

    @staticmethod
    def _run_by_node(snapshot: TaskSnapshot) -> dict[str, NodeRun]:
        result: dict[str, NodeRun] = {}
        for run in snapshot.node_runs.values():
            previous = result.get(run.node_id)
            if previous is not None and previous.run_id != run.run_id:
                raise RunnerError("v1 runner does not accept concurrent runs for one node")
            result[run.node_id] = run
        return result

    @staticmethod
    def _candidate(record: Mapping[str, object], body: bytes) -> NodeCandidate:
        roots = record.get("route_roots")
        if not isinstance(roots, Mapping):
            raise RunnerError("stored candidate route roots are invalid")
        return NodeCandidate(
            body,
            record["body_digest"],  # type: ignore[arg-type]
            record["author_id"],  # type: ignore[arg-type]
            roots,
        )

    def _commit(
        self,
        task_id: str,
        snapshot: TaskSnapshot,
        runner: RunnerSnapshot,
        runtime: RuntimeContext,
        declarations: Sequence[tuple[str, Mapping[str, object]]],
        *,
        operation_id: str,
        object_digests: tuple[str, ...] = (),
    ) -> None:
        events = self._events(snapshot, declarations)
        self.__transition_channel.commit(
            task_id,
            snapshot.snapshot_digest,
            events,
            runner.to_dict(),
            runtime,
            operation_id=operation_id,
            object_digests=object_digests,
        )

    def _ready_nodes(
        self,
        graph: GraphDefinition,
        snapshot: TaskSnapshot,
        runner: RunnerSnapshot,
    ) -> tuple[str, ...]:
        runs = self._run_by_node(snapshot)
        passed = {node_id for node_id, run in runs.items() if run.status == "passed"}
        candidates: list[str] = []
        for node_id in sorted(graph.nodes):
            if node_id in runs or node_id in passed:
                continue
            if node_id in runner.failure_routes.values():
                candidates.append(node_id)
                continue
            if node_id in graph.entrypoints:
                candidates.append(node_id)
                continue
            passed_by_edge = {
                edge.edge_id: edge.edge_id in runner.selected_edges and edge.from_node in passed
                for edge in graph.edges.values()
                if edge.to_node == node_id
            }
            if graph.join_ready(node_id, passed_by_edge, self._context):
                candidates.append(node_id)
        return tuple(candidates)

    def _can_revise(self, graph: GraphDefinition, node: NodeDefinition, run: NodeRun, runner: RunnerSnapshot) -> bool:
        if node.loop_budget_ref is None:
            return False
        try:
            budget = self._budgets.resolve(node.loop_budget_ref)
        except LoopBudgetError:
            return False
        revisions = sum(
            item["node_id"] == node.node_id and item["verdict"] == "REVISE"
            for item in runner.review_history
        )
        allowed = budget.allows_next(
            attempts_used=run.attempt,
            revisions_used=revisions,
            total_runs_used=len(runner.review_history),
            context=self._context,
        )
        if not allowed or self._materialization is None:
            return allowed
        maximum = self._materialization.budget_limits.get(node.loop_budget_ref)
        if type(maximum) is not int or maximum < 1:
            return False
        return (
            run.attempt < maximum
            and revisions < maximum
            and len(runner.review_history) < maximum
        )

    @staticmethod
    def _finding_conflicts(runner: RunnerSnapshot, finding: Finding) -> bool:
        existing = runner.findings.get(finding.finding_id)
        if existing is None:
            return False
        return any((
            existing["severity"] != finding.severity,
            tuple(existing["evidence"]) != finding.evidence,
            existing["required_change"] != finding.required_change,
            existing["verification"] != finding.verification,
            existing["owning_node"] != finding.owning_node,
        ))

    @staticmethod
    def _review_record(
        node: NodeDefinition,
        run: NodeRun,
        output: Mapping[str, object],
        result: ReviewResult,
    ) -> dict[str, object]:
        return {
            "node_id": node.node_id,
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

    @staticmethod
    def _stored_review_result(record: Mapping[str, object]) -> ReviewResult:
        raw_findings = record.get("findings")
        if type(raw_findings) is not list:
            raise RunnerError("durable review findings are invalid")
        findings = tuple(
            Finding(
                item["finding_id"],
                item["severity"],
                tuple(item["evidence"]),
                item["required_change"],
                item["verification"],
                item["owning_node"],
            )
            for item in raw_findings
            if isinstance(item, Mapping)
        )
        if len(findings) != len(raw_findings):
            raise RunnerError("durable review finding is malformed")
        return ReviewResult(
            record["verdict"],  # type: ignore[arg-type]
            record["reviewer_id"],  # type: ignore[arg-type]
            findings,
        )

    def _route_failure(
        self,
        task_id: str,
        snapshot: TaskSnapshot,
        runner: RunnerSnapshot,
        runtime: RuntimeContext,
        graph: GraphDefinition,
        run: NodeRun,
        failure: NodeRuntimeFailure,
    ) -> None:
        target = graph.failure_target(
            run.node_id,
            failure.error_code,
            edge_id=failure.edge_id,
        )
        declarations: tuple[tuple[str, Mapping[str, object]], ...]
        if target is None:
            declarations = (
                ("node.blocked", {"run_id": run.run_id}),
                ("task.blocked", {}),
            )
        else:
            existing = runner.failure_routes.get(run.node_id)
            if existing is not None and existing != target:
                raise RunnerError("runtime failure route conflicts with committed route")
            runner.failure_routes[run.node_id] = target
            declarations = (("node.blocked", {"run_id": run.run_id}),)
        self._commit(
            task_id,
            snapshot,
            runner,
            runtime,
            declarations,
            operation_id=f"failure:{run.run_id}:{run.attempt}:{failure.error_code}",
        )

    def run_until_stable(
        self,
        task_id: str,
        runtime: RuntimeContext,
        graph: GraphDefinition,
        node_runtime: NodeRuntime,
        validator: CandidateValidator,
        reviewer: CandidateReviewer,
        *,
        max_steps: int,
    ) -> RunResult:
        if type(runtime) is not RuntimeContext or type(graph) is not GraphDefinition:
            raise RunnerError("runner invocation requires exact runtime and graph")
        if type(max_steps) is not int or max_steps < 1:
            raise RunnerError("runner max steps must be a positive exact integer")
        if self._materialization is not None:
            try:
                self._materialization.require_loop_budget_registry(self._budgets)
            except ProfileContractError as error:
                raise RunnerError("runner materialization is stale") from error
            if (
                self._materialization.graph_id != graph.graph_id
                or self._materialization.graph_version != graph.graph_version
                or self._materialization.graph_digest != graph.digest
            ):
                raise RunnerError("runner materialization does not bind the executable graph")
            loop_refs = {
                node.loop_budget_ref for node in graph.nodes.values()
                if node.loop_budget_ref is not None
            }
            if not loop_refs.issubset(self._materialization.budget_limits):
                raise RunnerError("runner graph has an unmaterialized loop budget")
        steps = 0
        while steps < max_steps:
            view = self.__transition_channel.show(task_id)
            snapshot = view.snapshot
            if snapshot.identity.get("owner_id") != runtime.owner_id or (
                snapshot.identity.get("runtime_kind") != runtime.runtime_kind
                or snapshot.identity.get("runtime_lineage_id") != runtime.runtime_lineage_id
            ):
                raise RunnerError("runtime owner or lineage does not match the task")
            if snapshot.graph_ref.get("graph_digest") != graph.digest:
                raise RunnerError("task graph binding does not match the executable graph")
            runner = RunnerSnapshot(view.runner_state)
            if runner.graph_digest != graph.digest or runner.runtime_lineage_id != runtime.runtime_lineage_id:
                raise RunnerError("runner snapshot binding is stale")
            if snapshot.lifecycle in self.STABLE_LIFECYCLES:
                return RunResult(task_id, snapshot.lifecycle, snapshot.task_revision, "stable", steps, ())
            if snapshot.lifecycle != "running":
                raise RunnerError("task must be running before graph execution")

            runs = self._run_by_node(snapshot)
            pending_ready = self._ready_nodes(graph, snapshot, runner)
            if pending_ready:
                node_id = pending_ready[0]
                run_id = f"node:{node_id}:run:1"
                self._commit(
                    task_id, snapshot, runner, runtime,
                    (("node.run_created", {"run_id": run_id, "node_id": node_id}),
                     ("node.ready", {"run_id": run_id})),
                    operation_id=f"schedule:{run_id}",
                )
                steps += 1
                continue

            active = tuple(sorted(
                (
                    run for run in runs.values()
                    if run.status not in {"passed", "cancelled", "invalidated"}
                    and not (
                        run.status == "blocked" and run.node_id in runner.failure_routes
                    )
                ),
                key=lambda item: (item.node_id, item.run_id),
            ))
            if not active:
                passed = tuple(sorted(node_id for node_id, run in runs.items() if run.status == "passed"))
                status = "completion_ready" if graph.completion_ready(passed, self._context) else "idle"
                return RunResult(task_id, snapshot.lifecycle, snapshot.task_revision, status, steps, ())
            run = active[0]
            node = graph.nodes[run.node_id]

            if run.status == "pending":
                self._commit(
                    task_id, snapshot, runner, runtime,
                    (("node.ready", {"run_id": run.run_id}),),
                    operation_id=f"ready:{run.run_id}:{run.attempt}",
                )
            elif run.status == "ready":
                self._commit(
                    task_id, snapshot, runner, runtime,
                    (("node.leased", {"run_id": run.run_id}),
                     ("node.started", {"run_id": run.run_id})),
                    operation_id=f"start:{run.run_id}:{run.attempt}",
                )
            elif run.status == "leased":
                self._commit(
                    task_id, snapshot, runner, runtime,
                    (("node.started", {"run_id": run.run_id}),),
                    operation_id=f"resume-start:{run.run_id}:{run.attempt}",
                )
            elif run.status == "running":
                if node.side_effect_class != "none":
                    self._commit(
                        task_id, snapshot, runner, runtime,
                        (("node.awaiting_human", {"run_id": run.run_id}),
                         ("task.human_decision_required", {})),
                        operation_id=f"side-effect-boundary:{run.run_id}:{run.attempt}",
                    )
                else:
                    try:
                        candidate = node_runtime.execute(
                            node, run_id=run.run_id, attempt=run.attempt, runtime=runtime,
                        )
                    except NodeRuntimeFailure as failure:
                        self._route_failure(
                            task_id, snapshot, runner, runtime, graph, run, failure,
                        )
                        steps += 1
                        continue
                    if type(candidate) is not NodeCandidate:
                        raise RunnerError("runtime returned a non-candidate result")
                    self._objects.put_verified(candidate.body, candidate.body_digest)
                    runner.node_outputs[node.node_id] = {
                        "node_id": node.node_id,
                        "run_id": run.run_id,
                        "attempt": run.attempt,
                        "body_digest": candidate.body_digest,
                        "author_id": candidate.author_id,
                        "trust": "candidate",
                        "evidence_refs": [],
                        "verdict": None,
                        "reviewer_id": None,
                        "route_roots": thaw(candidate.route_roots),
                    }
                    self._commit(
                        task_id, snapshot, runner, runtime,
                        (("node.output_produced", {"run_id": run.run_id}),),
                        operation_id=f"candidate:{run.run_id}:{run.attempt}:{candidate.body_digest}",
                        object_digests=(candidate.body_digest,),
                    )
            elif run.status == "produced":
                self._commit(
                    task_id, snapshot, runner, runtime,
                    (("node.validation_started", {"run_id": run.run_id}),),
                    operation_id=f"validate-start:{run.run_id}:{run.attempt}",
                )
            elif run.status == "validating":
                output = runner.node_outputs.get(node.node_id)
                if output is None or output["run_id"] != run.run_id or output["attempt"] != run.attempt:
                    raise RunnerError("validating node has no exact current candidate")
                body = self._objects.get(output["body_digest"])  # type: ignore[arg-type]
                candidate = self._candidate(output, body)
                result = validator.validate(node, candidate, context=self._context)
                if type(result) is not ValidationResult:
                    raise RunnerError("validator returned a non-validation result")
                if result.passed:
                    output["trust"] = result.trust
                    output["evidence_refs"] = list(result.evidence_refs)
                    self._commit(
                        task_id, snapshot, runner, runtime,
                        (("node.review_started", {"run_id": run.run_id}),),
                        operation_id=f"review-start:{run.run_id}:{run.attempt}:{candidate.body_digest}",
                    )
                else:
                    assert result.finding is not None
                    finding = result.finding
                    if finding.owning_node != node.node_id:
                        raise RunnerError("validation finding is routed to the wrong owner")
                    if self._finding_conflicts(runner, finding):
                        self._commit(
                            task_id, snapshot, runner, runtime,
                            (("node.awaiting_human", {"run_id": run.run_id}),
                             ("task.human_decision_required", {})),
                            operation_id=f"validation-conflict:{run.run_id}:{run.attempt}",
                        )
                    else:
                        is_new = finding.finding_id not in runner.findings or runner.findings[finding.finding_id]["status"] == "closed"
                        runner.findings[finding.finding_id] = finding.to_dict(
                            body_digest=candidate.body_digest,
                            reviewer_id="deterministic-validator",
                        )
                        declarations: list[tuple[str, Mapping[str, object]]] = []
                        if is_new:
                            declarations.append(("finding.opened", {"finding_id": finding.finding_id}))
                        if self._can_revise(graph, node, run, runner):
                            declarations.append(("node.revise_requested", {"run_id": run.run_id}))
                        else:
                            declarations.extend((
                                ("node.awaiting_human", {"run_id": run.run_id}),
                                ("task.human_decision_required", {}),
                            ))
                        self._commit(
                            task_id, snapshot, runner, runtime, tuple(declarations),
                            operation_id=f"validation-result:{run.run_id}:{run.attempt}:{candidate.body_digest}",
                        )
            elif run.status == "reviewing":
                output = runner.node_outputs.get(node.node_id)
                if output is None or output["trust"] != "validated":
                    raise RunnerError("reviewing node has no validated candidate")
                body = self._objects.get(output["body_digest"])  # type: ignore[arg-type]
                candidate = self._candidate(output, body)
                validation = ValidationResult(
                    True,
                    tuple(output["evidence_refs"]),  # type: ignore[arg-type]
                    "validated",
                )
                current_review = (
                    runner.review_history[-1]
                    if runner.review_history
                    and runner.review_history[-1]["node_id"] == node.node_id
                    and runner.review_history[-1]["run_id"] == run.run_id
                    and runner.review_history[-1]["attempt"] == run.attempt
                    and runner.review_history[-1]["body_digest"] == candidate.body_digest
                    and output["verdict"] == runner.review_history[-1]["verdict"]
                    and output["reviewer_id"] == runner.review_history[-1]["reviewer_id"]
                    else None
                )
                if current_review is None:
                    result = reviewer.review(node, candidate, validation, runtime=runtime)
                    if type(result) is not ReviewResult:
                        raise RunnerError("reviewer returned a non-review result")
                    if _actor(result.reviewer_id, "reviewer") == _actor(candidate.author_id, "author"):
                        raise RunnerError("author and reviewer must be independent canonical actors")
                    if any(item.owning_node != node.node_id for item in result.findings):
                        raise RunnerError("review finding is routed to the wrong owner")
                    self.__transition_channel.record_review(
                        task_id,
                        snapshot.snapshot_digest,
                        run.run_id,
                        result,
                        runtime,
                    )
                    steps += 1
                    continue
                result = self._stored_review_result(current_review)
                if _actor(result.reviewer_id, "reviewer") == _actor(candidate.author_id, "author"):
                    raise RunnerError("author and reviewer must be independent canonical actors")
                if any(item.owning_node != node.node_id for item in result.findings):
                    raise RunnerError("review finding is routed to the wrong owner")
                if result.verdict == "PASS":
                    open_for_node = {
                        finding_id: record
                        for finding_id, record in runner.findings.items()
                        if record["owning_node"] == node.node_id and record["status"] == "open"
                    }
                    same_digest_revise = any(
                        item["node_id"] == node.node_id
                        and item["verdict"] == "REVISE"
                        and item["body_digest"] == candidate.body_digest
                        for item in runner.review_history[:-1]
                    )
                    same_digest_finding = any(
                        record["body_digest"] == candidate.body_digest
                        for record in open_for_node.values()
                    )
                    if same_digest_revise or same_digest_finding:
                        self._commit(
                            task_id,
                            snapshot,
                            runner,
                            runtime,
                            (("node.awaiting_human", {"run_id": run.run_id}),
                             ("task.human_decision_required", {})),
                            operation_id=(
                                f"review-no-progress:{run.run_id}:{run.attempt}:"
                                f"{candidate.body_digest}"
                            ),
                        )
                    else:
                        self.__transition_channel.pass_review(
                            task_id,
                            snapshot.snapshot_digest,
                            run.run_id,
                            graph,
                            runtime,
                        )
                elif result.verdict == "REVISE":
                    conflict = any(self._finding_conflicts(runner, item) for item in result.findings)
                    prior_same_digest = any(
                        item["node_id"] == node.node_id
                        and item["verdict"] == "REVISE"
                        and item["body_digest"] == candidate.body_digest
                        for item in runner.review_history[:-1]
                    )
                    declarations = []
                    if not conflict:
                        for finding in result.findings:
                            is_new = finding.finding_id not in runner.findings or runner.findings[finding.finding_id]["status"] == "closed"
                            runner.findings[finding.finding_id] = finding.to_dict(
                                body_digest=candidate.body_digest,
                                reviewer_id=result.reviewer_id,
                            )
                            if is_new:
                                declarations.append(("finding.opened", {"finding_id": finding.finding_id}))
                    if conflict or prior_same_digest or not self._can_revise(graph, node, run, runner):
                        declarations.extend((
                            ("node.awaiting_human", {"run_id": run.run_id}),
                            ("task.human_decision_required", {}),
                        ))
                    else:
                        declarations.append(("node.revise_requested", {"run_id": run.run_id}))
                    self._commit(
                        task_id, snapshot, runner, runtime, tuple(declarations),
                        operation_id=f"review-revise:{run.run_id}:{run.attempt}:{candidate.body_digest}",
                    )
                elif result.verdict == "ESCALATE":
                    self._commit(
                        task_id, snapshot, runner, runtime,
                        (("node.awaiting_human", {"run_id": run.run_id}),
                         ("task.human_decision_required", {})),
                        operation_id=f"review-escalate:{run.run_id}:{run.attempt}",
                    )
                else:
                    self._commit(
                        task_id, snapshot, runner, runtime,
                        (("node.blocked", {"run_id": run.run_id}), ("task.blocked", {})),
                        operation_id=f"review-blocked:{run.run_id}:{run.attempt}",
                    )
            else:
                raise RunnerError(f"runner cannot advance node status: {run.status}")
            steps += 1

        view = self.__transition_channel.show(task_id)
        ready = self._ready_nodes(graph, view.snapshot, RunnerSnapshot(view.runner_state))
        return RunResult(task_id, view.snapshot.lifecycle, view.snapshot.task_revision, "step_limit", steps, ready)

    def begin_completion(
        self,
        task_id: str,
        runtime: RuntimeContext,
        graph: GraphDefinition,
    ) -> None:
        """Enter the two-phase completion state only from a genuinely ready graph."""

        view = self.__transition_channel.show(task_id)
        snapshot = view.snapshot
        runner = RunnerSnapshot(view.runner_state)
        if snapshot.lifecycle != "running" or snapshot.open_findings:
            raise RunnerError("completion cannot start from the current task state")
        if snapshot.graph_ref.get("graph_digest") != graph.digest or runner.graph_digest != graph.digest:
            raise RunnerError("completion graph binding is stale")
        runs = self._run_by_node(snapshot)
        if any(
            run.status != "passed"
            and not (run.status == "blocked" and run.node_id in runner.failure_routes)
            for run in runs.values()
        ):
            raise RunnerError("completion requires every materialized run to pass")
        passed = tuple(sorted(run.node_id for run in runs.values()))
        if self._ready_nodes(graph, snapshot, runner) or not graph.completion_ready(passed, self._context):
            raise RunnerError("completion policy is not satisfied")
        self._commit(
            task_id,
            snapshot,
            runner,
            runtime,
            (("task.completion_started", {}),),
            operation_id=f"completion-start:{snapshot.snapshot_digest}",
        )
