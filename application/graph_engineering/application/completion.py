"""Deterministic Candidate and Completion Gate evaluation."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.application.tasks import RuntimeContext, TaskApplication
from graph_engineering.core.artifacts.records import ArtifactRecord
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.graph.definition import GraphDefinition
from graph_engineering.core.graph.state import TaskSnapshot


class CompletionGateError(ValueError):
    """The Completion Gate input itself is malformed or unattested."""


@dataclass(frozen=True, slots=True)
class CompletionDecision:
    status: str
    failures: tuple[str, ...]
    assessment_digest: str

    @property
    def passed(self) -> bool:
        return self.status == "PASS"


class CompletionGate:
    """Prove the nine completion conditions without natural-language inference."""

    FIELDS = frozenset({
        "task_id", "snapshot_digest", "graph_digest", "project_scope_digest",
        "baseline_digests", "authority_refs", "required_node_ids", "passed_node_ids",
        "must_requirement_ids", "traced_requirement_ids", "required_gate_ids",
        "passed_gate_ids", "candidate_review", "required_external_action_ids",
        "verified_external_action_ids", "target_binding_ids", "matched_target_binding_ids",
        "open_blocking_finding_ids", "unknown_side_effect_refs", "live_node_lease_ids",
        "live_tool_lease_ids", "evidence_task_id", "evidence_snapshot_digest",
        "evidence_baseline_digests", "completion_record",
    })
    REVIEW_FIELDS = frozenset({
        "artifact_id", "artifact_digest", "verdict", "author_id", "reviewer_id", "trust",
    })
    RECORD_FIELDS = frozenset({
        "artifact_id", "artifact_digest", "status", "snapshot_digest",
    })

    def __init__(self, *, context: WorkContext) -> None:
        if type(context) is not WorkContext:
            raise CompletionGateError("completion gate requires an exact work context")
        self._context = context

    @staticmethod
    def _strings(value: object, label: str) -> tuple[str, ...]:
        if (
            type(value) is not list
            or any(type(item) is not str or not item for item in value)
            or value != sorted(set(value))
        ):
            raise CompletionGateError(f"{label} must be a sorted unique string array")
        return tuple(value)

    @staticmethod
    def _identity(value: object, label: str) -> str:
        if type(value) is not str or not value or value != value.strip() or "\x00" in value:
            raise CompletionGateError(f"{label} is invalid")
        return value

    @classmethod
    def _record(cls, value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping) or set(value) != fields:
            raise CompletionGateError(f"{label} is not exact")
        return value

    @staticmethod
    def _actor(value: object, label: str) -> str:
        actor = CompletionGate._identity(value, label)
        if not actor.isascii():
            raise CompletionGateError(f"{label} must be ASCII canonical identity")
        return actor.casefold()

    @staticmethod
    def _actual_passed_nodes(snapshot: TaskSnapshot) -> tuple[str, ...]:
        by_node: dict[str, str] = {}
        for run in snapshot.node_runs.values():
            previous = by_node.get(run.node_id)
            if previous is not None and previous != run.status:
                raise CompletionGateError("multiple current runs for one node are incomparable")
            by_node[run.node_id] = run.status
        return tuple(sorted(node_id for node_id, status in by_node.items() if status == "passed"))

    def evaluate(
        self,
        snapshot: TaskSnapshot,
        graph: GraphDefinition,
        evidence: Mapping[str, object],
        *,
        candidate_review_record: ArtifactRecord,
        completion_record: ArtifactRecord,
    ) -> CompletionDecision:
        if type(snapshot) is not TaskSnapshot or type(graph) is not GraphDefinition:
            raise CompletionGateError("completion gate requires exact snapshot and graph")
        if type(candidate_review_record) is not ArtifactRecord or type(completion_record) is not ArtifactRecord:
            raise CompletionGateError("completion gate requires validated artifact records")
        if not isinstance(evidence, Mapping) or set(evidence) != self.FIELDS:
            raise CompletionGateError("completion evidence properties are not exact")
        try:
            canonical = canonical_bytes(evidence)
        except (TypeError, ValueError) as error:
            raise CompletionGateError("completion evidence is not exact canonical JSON") from error
        arrays = {
            name: self._strings(evidence[name], name)
            for name in (
                "baseline_digests", "authority_refs", "required_node_ids", "passed_node_ids",
                "must_requirement_ids", "traced_requirement_ids", "required_gate_ids",
                "passed_gate_ids", "required_external_action_ids", "verified_external_action_ids",
                "target_binding_ids", "matched_target_binding_ids", "open_blocking_finding_ids",
                "unknown_side_effect_refs", "live_node_lease_ids", "live_tool_lease_ids",
                "evidence_baseline_digests",
            )
        }
        for field in (
            "task_id", "snapshot_digest", "graph_digest", "project_scope_digest",
            "evidence_task_id", "evidence_snapshot_digest",
        ):
            self._identity(evidence[field], field)
        review = self._record(evidence["candidate_review"], self.REVIEW_FIELDS, "candidate review")
        record = self._record(evidence["completion_record"], self.RECORD_FIELDS, "completion record")
        for field in self.REVIEW_FIELDS - {"verdict", "trust"}:
            self._identity(review[field], f"candidate review {field}")
        for field in self.RECORD_FIELDS - {"status"}:
            self._identity(record[field], f"completion record {field}")

        failures: set[str] = set()
        task_id = snapshot.identity.get("task_id")
        baseline_digests = tuple(sorted(
            item["digest"] for item in snapshot.baseline_refs if type(item.get("digest")) is str
        ))
        passed_nodes = self._actual_passed_nodes(snapshot)
        required_nodes = tuple(sorted(graph.completion_nodes))

        if snapshot.lifecycle != "completing":
            failures.add("lifecycle")
        if evidence["task_id"] != task_id:
            failures.add("task_binding")
        if evidence["snapshot_digest"] != snapshot.snapshot_digest:
            failures.add("snapshot_binding")
        if evidence["graph_digest"] != graph.digest or snapshot.graph_ref.get("graph_digest") != graph.digest:
            failures.add("graph_binding")
        if arrays["required_node_ids"] != required_nodes or arrays["passed_node_ids"] != passed_nodes:
            failures.add("required_nodes")
        else:
            try:
                if not graph.completion_ready(passed_nodes, self._context):
                    failures.add("required_nodes")
            except ValueError:
                failures.add("required_nodes")

        if arrays["baseline_digests"] != baseline_digests:
            failures.add("intent_baseline")
        if arrays["authority_refs"] != tuple(sorted(snapshot.authorities)) or not snapshot.authorities:
            failures.add("authority")
        if (
            evidence["project_scope_digest"] != snapshot.project_scope_ref.get("digest")
            or snapshot.project_scope_ref.get("status") != "frozen"
        ):
            failures.add("project_scope")
        if (
            not arrays["must_requirement_ids"]
            or arrays["traced_requirement_ids"] != arrays["must_requirement_ids"]
        ):
            failures.add("must_requirement_trace")
        if not arrays["required_gate_ids"] or arrays["passed_gate_ids"] != arrays["required_gate_ids"]:
            failures.add("project_gates")

        candidate_body = candidate_review_record.body
        candidate_inputs = candidate_body.get("input_refs")
        candidate_input_digests = {
            item.get("digest") for item in candidate_inputs if isinstance(item, Mapping)
        } if type(candidate_inputs) is tuple else set()
        candidate_findings = candidate_body.get("findings")
        candidate_record_matches = (
            candidate_body.get("artifact_type") == "candidate-review"
            and candidate_body.get("task_id") == task_id
            and candidate_body.get("status") == "accepted_for_next_node"
            and tuple(sorted(candidate_body.get("baseline_digests", {}).values())) == baseline_digests
            if isinstance(candidate_body.get("baseline_digests"), Mapping)
            else False
        )
        candidate_record_matches = bool(
            candidate_record_matches
            and candidate_review_record.artifact_id == review["artifact_id"]
            and candidate_review_record.artifact_digest == review["artifact_digest"]
            and snapshot.snapshot_digest in candidate_input_digests
            and type(candidate_findings) is tuple
            and not any(
                isinstance(item, Mapping) and item.get("status") == "open"
                for item in candidate_findings
            )
        )
        try:
            independent_review = (
                candidate_record_matches
                and review["verdict"] == "PASS"
                and review["trust"] == "independently-reviewed"
                and candidate_body.get("author_id") == review["author_id"]
                and candidate_body.get("reviewer_id") == review["reviewer_id"]
                and self._actor(review["author_id"], "candidate author")
                != self._actor(review["reviewer_id"], "candidate reviewer")
            )
        except CompletionGateError:
            independent_review = False
        if not independent_review:
            failures.add("candidate_review")
        if arrays["verified_external_action_ids"] != arrays["required_external_action_ids"]:
            failures.add("external_target_verification")
        if arrays["matched_target_binding_ids"] != arrays["target_binding_ids"]:
            failures.add("target_binding")
        if (
            arrays["open_blocking_finding_ids"]
            or snapshot.open_findings
            or arrays["unknown_side_effect_refs"]
            or snapshot.unresolved_action_claims
            or snapshot.resource_leases
            or arrays["live_node_lease_ids"]
            or arrays["live_tool_lease_ids"]
        ):
            failures.add("unresolved_state")
        if (
            evidence["evidence_task_id"] != task_id
            or evidence["evidence_snapshot_digest"] != snapshot.snapshot_digest
            or arrays["evidence_baseline_digests"] != baseline_digests
        ):
            failures.add("evidence_freshness")
        completion_body = completion_record.body
        completion_inputs = completion_body.get("input_refs")
        completion_input_digests = {
            item.get("digest") for item in completion_inputs if isinstance(item, Mapping)
        } if type(completion_inputs) is tuple else set()
        completion_baselines = completion_body.get("baseline_digests")
        if (
            completion_body.get("artifact_type") != "completion-record"
            or completion_body.get("task_id") != task_id
            or not isinstance(completion_baselines, Mapping)
            or tuple(sorted(completion_baselines.values())) != baseline_digests
            or completion_record.artifact_id != record["artifact_id"]
            or completion_record.artifact_digest != record["artifact_digest"]
            or completion_record.status != "accepted_for_next_node"
            or record["status"] != completion_record.status
            or record["snapshot_digest"] != snapshot.snapshot_digest
            or snapshot.snapshot_digest not in completion_input_digests
        ):
            failures.add("completion_record")

        assessment = {
            "contract": "completion-assessment-v1",
            "evidence_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
            "task_id": task_id,
            "snapshot_digest": snapshot.snapshot_digest,
            "graph_digest": graph.digest,
            "status": "PASS" if not failures else "INCOMPLETE",
            "failures": sorted(failures),
        }
        digest = "sha256-jcs-v1:" + hashlib.sha256(canonical_bytes(assessment)).hexdigest()
        return CompletionDecision(
            assessment["status"],  # type: ignore[arg-type]
            tuple(assessment["failures"]),  # type: ignore[arg-type]
            digest,
        )

    def complete(
        self,
        application: TaskApplication,
        task_id: str,
        runtime: RuntimeContext,
        graph: GraphDefinition,
        evidence: Mapping[str, object],
        *,
        candidate_review_record: ArtifactRecord,
        completion_record: ArtifactRecord,
    ) -> CompletionDecision:
        """Commit `task.completed` only after a current, deterministic PASS."""

        if type(application) is not TaskApplication or type(runtime) is not RuntimeContext:
            raise CompletionGateError("completion commit requires exact application and runtime")
        return application.complete(
            self,
            task_id,
            runtime,
            graph,
            evidence,
            candidate_review_record=candidate_review_record,
            completion_record=completion_record,
        )
