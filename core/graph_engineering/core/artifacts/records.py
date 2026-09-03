"""ArtifactRecord validation, lifecycle, review, and exit semantics."""

from __future__ import annotations

import hmac
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.artifacts.contracts import (
    ArtifactContract,
    ArtifactContractRegistry,
)
from graph_engineering.core.artifacts.manifest import LogicalBodyManifest, LogicalBodyManifestError
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext


ARTIFACT_RECORD_SCHEMA = "urn:gew:schema:artifact-record:1.0.0"
ARTIFACT_LIFECYCLE_EVENT_SCHEMA = "urn:gew:schema:artifact-lifecycle-event:1.0.0"
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
RECORD_FIELDS = frozenset({
    "schema_version",
    "artifact_id",
    "artifact_type",
    "contract_id",
    "contract_digest",
    "task_id",
    "revision",
    "author_id",
    "reviewer_id",
    "target_refs",
    "input_refs",
    "baseline_digests",
    "requirement_traces",
    "logical_body_ref",
    "body_digest",
    "semantic_fields",
    "status",
    "findings",
    "validation_records",
    "review_records",
    "approval_records",
    "created_at",
    "supersedes",
    "artifact_digest",
})


class ArtifactValidationError(ValueError):
    """Artifact record failed deterministic validation."""


class ArtifactLifecycle:
    TRANSITIONS = MappingProxyType({
        "candidate": frozenset({"validating", "invalidated"}),
        "validating": frozenset({"under_review", "invalidated"}),
        "under_review": frozenset({"reviewed", "invalidated"}),
        "reviewed": frozenset({"awaiting_human", "accepted_for_next_node", "invalidated"}),
        "awaiting_human": frozenset({"approved", "invalidated"}),
        "approved": frozenset({"invalidated"}),
        "accepted_for_next_node": frozenset({"invalidated"}),
        "invalidated": frozenset({"archived"}),
        "archived": frozenset(),
    })
    REVISION_TRANSITIONS = MappingProxyType({
        "invalidated": frozenset(TRANSITIONS),
        "archived": frozenset(TRANSITIONS),
    })

    @classmethod
    def require_transition(cls, previous: str, current: str) -> None:
        if previous not in cls.TRANSITIONS or current not in cls.TRANSITIONS[previous]:
            raise ArtifactValidationError("artifact lifecycle transition is not allowed")

    @classmethod
    def transition(
        cls,
        *,
        record: ArtifactRecord,
        previous: str,
        current: str,
        occurred_at: str,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> ArtifactLifecycleEvent:
        if (
            type(record) is not ArtifactRecord
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or not _string(occurred_at)
            or not occurred_at.endswith("Z")
            or record.status != current
        ):
            raise ArtifactValidationError("artifact lifecycle event context is invalid")
        cls.require_transition(previous, current)
        unsigned: dict[str, object] = {
            "schema_version": "1.0.0",
            "artifact_id": record.artifact_id,
            "artifact_digest": record.artifact_digest,
            "body_digest": record.body["body_digest"],
            "revision": record.body["revision"],
            "previous_status": previous,
            "current_status": current,
            "occurred_at": occurred_at,
        }
        event_digest = semantic_digest_charged(
            unsigned,
            context,
            contract_type="urn:gew:contract:artifact-lifecycle-event",
            projection_id=IDENTITY_PROJECTION,
            schema_id=ARTIFACT_LIFECYCLE_EVENT_SCHEMA,
            operation_path=context.child_path(()),
        )
        complete = {**unsigned, "event_digest": event_digest}
        if schema_registry.validate(
            ARTIFACT_LIFECYCLE_EVENT_SCHEMA,
            complete,
            context,
            operation_path=context.child_path(()),
        ):
            raise ArtifactValidationError("artifact lifecycle event schema validation failed")
        event = object.__new__(ArtifactLifecycleEvent)
        for name, item in complete.items():
            object.__setattr__(event, name, item)
        return event

    @classmethod
    def require_revision(cls, previous: ArtifactRecord, current_status: object) -> None:
        if (
            type(previous) is not ArtifactRecord
            or previous.status not in cls.REVISION_TRANSITIONS
            or current_status not in cls.REVISION_TRANSITIONS[previous.status]
        ):
            raise ArtifactValidationError("artifact revision transition is not allowed")


@dataclass(frozen=True, slots=True, init=False)
class ArtifactValidationRecord:
    artifact_id: str
    artifact_digest: str | None
    status: str
    validator_ids: tuple[str, ...]
    failures: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactValidationRecord is emitted only by ArtifactValidator")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ArtifactValidationRecord is final")


@dataclass(frozen=True, slots=True, init=False)
class ArtifactLifecycleEvent:
    schema_version: str
    artifact_id: str
    artifact_digest: str
    body_digest: str
    revision: int
    previous_status: str
    current_status: str
    occurred_at: str
    event_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactLifecycleEvent is emitted only by ArtifactLifecycle")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ArtifactLifecycleEvent is final")


@dataclass(frozen=True, slots=True, init=False)
class ArtifactRecord:
    body: Mapping[str, object]
    contract: ArtifactContract

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactRecord must be loaded by ArtifactValidator")

    @property
    def artifact_id(self) -> str:
        return self.body["artifact_id"]  # type: ignore[return-value]

    @property
    def artifact_digest(self) -> str:
        return self.body["artifact_digest"]  # type: ignore[return-value]

    @property
    def status(self) -> str:
        return self.body["status"]  # type: ignore[return-value]


@dataclass(frozen=True, slots=True, init=False)
class ArtifactDependencyIndex:
    records: Mapping[str, ArtifactRecord]
    dependencies: Mapping[str, tuple[str, ...]]
    descendants: Mapping[str, tuple[str, ...]]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactDependencyIndex must be built from validated records")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ArtifactDependencyIndex is final")

    @classmethod
    def build(cls, records: Iterable[ArtifactRecord]) -> ArtifactDependencyIndex:
        by_id: dict[str, ArtifactRecord] = {}
        for record in records:
            if type(record) is not ArtifactRecord or record.artifact_id in by_id:
                raise ArtifactValidationError("artifact dependency records are invalid")
            by_id[record.artifact_id] = record
        dependencies: dict[str, tuple[str, ...]] = {}
        for artifact_id, record in by_id.items():
            inputs = {
                str(item["ref_id"])
                for item in record.body["input_refs"]
                if isinstance(item, Mapping)
            }
            requirements = {
                str(item["source_id"])
                for item in record.body["requirement_traces"]
                if isinstance(item, Mapping)
                and item.get("trace_type") == "requirement"
                and item.get("target_id") == artifact_id
            }
            dependencies[artifact_id] = tuple(sorted(inputs | requirements))
            for item in record.body["input_refs"]:
                if (
                    isinstance(item, Mapping)
                    and item.get("ref_kind") == "artifact"
                    and item.get("ref_id") in by_id
                    and item.get("digest") != by_id[str(item["ref_id"])].artifact_digest
                ):
                    raise ArtifactValidationError("artifact dependency digest mismatch")
        children: dict[str, set[str]] = {artifact_id: set() for artifact_id in by_id}
        for artifact_id, refs in dependencies.items():
            for ref_id in refs:
                if ref_id in by_id:
                    children[ref_id].add(artifact_id)
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in visiting:
                raise ArtifactValidationError("artifact dependency cycle")
            if artifact_id in visited:
                return
            visiting.add(artifact_id)
            for child in sorted(children[artifact_id]):
                visit(child)
            visiting.remove(artifact_id)
            visited.add(artifact_id)

        for artifact_id in sorted(by_id):
            visit(artifact_id)
        result = object.__new__(ArtifactDependencyIndex)
        object.__setattr__(result, "records", MappingProxyType(dict(by_id)))
        object.__setattr__(result, "dependencies", MappingProxyType(dict(dependencies)))
        object.__setattr__(result, "descendants", MappingProxyType({
            artifact_id: tuple(sorted(values)) for artifact_id, values in children.items()
        }))
        return result

    def invalidated_by(self, changed_refs: Iterable[str]) -> tuple[str, ...]:
        refs = tuple(changed_refs)
        if (
            not refs
            or any(type(ref_id) is not str or not ref_id for ref_id in refs)
            or refs != tuple(sorted(set(refs)))
        ):
            raise ArtifactValidationError("changed artifact refs must be a canonical set")
        affected = {
            artifact_id for artifact_id, dependencies in self.dependencies.items()
            if set(refs).intersection(dependencies)
        }
        affected.update(set(refs).intersection(self.records))
        pending = list(affected)
        while pending:
            artifact_id = pending.pop()
            for child in self.descendants[artifact_id]:
                if child not in affected:
                    affected.add(child)
                    pending.append(child)
        return tuple(sorted(affected))


def _string(value: object) -> bool:
    return type(value) is str and bool(value)


def _actor(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and value == value.casefold()
        and value.isascii()
    )


def _semantic_digest(value: object) -> bool:
    return type(value) is str and SEMANTIC_DIGEST.fullmatch(value) is not None


class ArtifactValidator:
    @classmethod
    def validate(
        cls,
        value: Mapping[str, object],
        *,
        contract_registry: ArtifactContractRegistry,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        expected_task_id: str,
        expected_baselines: Mapping[str, str],
        known_inputs: Mapping[str, Mapping[str, str]],
        known_targets: Mapping[str, Mapping[str, str]],
        known_requirements: tuple[str, ...],
        manifest: LogicalBodyManifest | None = None,
        previous_record: ArtifactRecord | None = None,
    ) -> ArtifactValidationRecord:
        if (
            type(contract_registry) is not ArtifactContractRegistry
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or not _string(expected_task_id)
            or not isinstance(known_inputs, Mapping)
            or not isinstance(known_targets, Mapping)
            or known_requirements != tuple(sorted(set(known_requirements)))
            or any(not _string(item) for item in known_requirements)
            or (manifest is not None and type(manifest) is not LogicalBodyManifest)
            or (previous_record is not None and type(previous_record) is not ArtifactRecord)
        ):
            raise ArtifactValidationError("artifact validation context is invalid")
        try:
            value_snapshot = thaw(freeze(value))
            baseline_snapshot = thaw(freeze(expected_baselines))
            input_snapshot = thaw(freeze(known_inputs))
            target_snapshot = thaw(freeze(known_targets))
        except (TypeError, ValueError) as error:
            raise ArtifactValidationError("artifact validation inputs must be exact JSON") from error
        if (
            not isinstance(value_snapshot, dict)
            or not isinstance(baseline_snapshot, dict)
            or not isinstance(input_snapshot, dict)
            or not isinstance(target_snapshot, dict)
        ):
            raise ArtifactValidationError("artifact validation inputs must be objects")
        value = value_snapshot
        expected_baselines = baseline_snapshot
        known_inputs = input_snapshot  # type: ignore[assignment]
        known_targets = target_snapshot  # type: ignore[assignment]
        failures: set[str] = set()
        if schema_registry.validate(ARTIFACT_RECORD_SCHEMA, value, context):
            artifact_id = value.get("artifact_id") if isinstance(value, Mapping) else None
            return _validation_record(
                artifact_id=artifact_id if _string(artifact_id) else "<invalid>",
                artifact_digest=None,
                status="FAIL",
                validator_ids=("schema",),
                failures=("schema",),
            )
        if set(value) != RECORD_FIELDS or value.get("schema_version") != "1.0.0":
            failures.add("schema")
        artifact_id = value.get("artifact_id")
        artifact_type = value.get("artifact_type")
        if not _string(artifact_id) or not _string(artifact_type):
            failures.add("schema")
            artifact_id = "<invalid>"
            contract = None
        else:
            try:
                contract = contract_registry.resolve(artifact_type)
            except ValueError:
                contract = None
                failures.add("schema")
        if contract is not None:
            if (
                value.get("contract_id") != contract.contract_id
                or value.get("contract_digest") != contract.contract_digest
            ):
                failures.add("digests")
        if value.get("task_id") != expected_task_id:
            failures.add("inputs")
        if type(value.get("revision")) is not int or value["revision"] < 1:
            failures.add("schema")
        if not _actor(value.get("author_id")) or not _actor(value.get("reviewer_id")):
            failures.add("schema")
        body_digest = value.get("body_digest")
        if not _semantic_digest(body_digest):
            failures.add("digests")
        semantic_fields = value.get("semantic_fields")
        if contract is not None:
            if (
                not isinstance(semantic_fields, Mapping)
                or set(semantic_fields) != set(contract.required_semantic_fields)
                or any(not _string(item) for item in semantic_fields.values())
            ):
                failures.add("semantics")
        baselines = value.get("baseline_digests")
        if (
            not isinstance(baselines, Mapping)
            or dict(baselines) != dict(expected_baselines)
            or any(not _semantic_digest(item) for item in baselines.values())
        ):
            failures.add("inputs")
        inputs = value.get("input_refs")
        input_ids: set[str] = set()
        if type(inputs) is not list or not inputs:
            failures.add("inputs")
        else:
            for item in inputs:
                if not isinstance(item, Mapping) or set(item) != {
                    "ref_id",
                    "ref_kind",
                    "digest",
                    "task_id",
                    "baseline_digest",
                }:
                    failures.add("inputs")
                    continue
                input_id = item.get("ref_id")
                digest = item.get("digest")
                known_input = known_inputs.get(str(input_id))
                if (
                    not _string(input_id)
                    or input_id in input_ids
                    or item.get("ref_kind") not in {"artifact", "evidence"}
                    or item.get("task_id") != expected_task_id
                    or not isinstance(known_input, Mapping)
                    or set(known_input) != {
                        "ref_kind", "digest", "task_id", "baseline_digest",
                    }
                    or known_input.get("ref_kind") != item.get("ref_kind")
                    or known_input.get("digest") != digest
                    or known_input.get("task_id") != item.get("task_id")
                    or known_input.get("baseline_digest") != item.get("baseline_digest")
                    or not _semantic_digest(item.get("baseline_digest"))
                    or item.get("baseline_digest") not in expected_baselines.values()
                ):
                    failures.add("inputs")
                else:
                    input_ids.add(input_id)
        targets = value.get("target_refs")
        target_ids: set[str] = set()
        if type(targets) is not list or not targets:
            failures.add("inputs")
        else:
            for item in targets:
                if not isinstance(item, Mapping) or set(item) != {"target_id", "target_digest", "task_id"}:
                    failures.add("inputs")
                    continue
                target_id = item.get("target_id")
                known_target = known_targets.get(str(target_id))
                if (
                    not _string(target_id)
                    or target_id in target_ids
                    or item.get("task_id") != expected_task_id
                    or not _semantic_digest(item.get("target_digest"))
                    or not isinstance(known_target, Mapping)
                    or set(known_target) != {"digest", "task_id"}
                    or known_target.get("digest") != item.get("target_digest")
                    or known_target.get("task_id") != item.get("task_id")
                ):
                    failures.add("inputs")
                else:
                    target_ids.add(target_id)
        traces = value.get("requirement_traces")
        trace_types: list[str] = []
        trace_keys: set[tuple[str, str, str]] = set()
        allowed_nodes = {str(artifact_id), *input_ids, *target_ids, *known_requirements}
        if type(traces) is not list:
            failures.add("traces")
        else:
            for item in traces:
                if not isinstance(item, Mapping) or set(item) != {"trace_type", "source_id", "target_id"}:
                    failures.add("traces")
                    continue
                trace_type = item.get("trace_type")
                source = item.get("source_id")
                target = item.get("target_id")
                key = (trace_type, source, target)
                if (
                    not all(_string(part) for part in key)
                    or key in trace_keys
                    or source not in allowed_nodes
                    or target not in allowed_nodes
                    or (
                        trace_type == "requirement"
                        and (source not in known_requirements or target != artifact_id)
                    )
                    or (
                        trace_type == "dependency"
                        and (source not in input_ids or target != artifact_id)
                    )
                    or (
                        trace_type == "decision"
                        and (source != artifact_id or target not in target_ids)
                    )
                    or trace_type not in {"decision", "dependency", "requirement"}
                ):
                    failures.add("traces")
                else:
                    trace_keys.add(key)
                    trace_types.append(trace_type)
        if contract is not None:
            expected_trace_keys = {
                *(('requirement', source, str(artifact_id)) for source in known_requirements),
                *(('dependency', source, str(artifact_id)) for source in input_ids),
                *(('decision', str(artifact_id), target) for target in target_ids),
            }
            if (
                set(trace_types) != set(contract.required_trace_types)
                or trace_keys != expected_trace_keys
            ):
                failures.add("traces")
        logical_ref = value.get("logical_body_ref")
        if not isinstance(logical_ref, Mapping) or set(logical_ref) != {
            "manifest_id", "entry_digest", "artifact_id", "extracted_body_digest",
        }:
            failures.add("digests")
        elif manifest is None:
            failures.add("digests")
        else:
            try:
                extracted_digest = manifest.extracted_digest(str(artifact_id))
                entry_digest = manifest.entry_digest(str(artifact_id))
                bound_body_digest = manifest.semantic_body_digest(
                    str(artifact_id),
                    semantic_fields if isinstance(semantic_fields, Mapping) else {},
                    context,
                )
            except (LogicalBodyManifestError, ValueError):
                failures.add("digests")
            else:
                if (
                    logical_ref.get("artifact_id") != artifact_id
                    or logical_ref.get("manifest_id") != manifest.manifest_id
                    or logical_ref.get("entry_digest") != entry_digest
                    or logical_ref.get("extracted_body_digest") != extracted_digest
                    or body_digest != bound_body_digest
                ):
                    failures.add("digests")
        findings = value.get("findings")
        finding_ids: set[str] = set()
        has_open_blocker = False
        if type(findings) is not list:
            failures.add("findings")
        else:
            for item in findings:
                if not isinstance(item, Mapping) or set(item) != {"finding_id", "severity", "status"}:
                    failures.add("findings")
                    continue
                finding_id = item.get("finding_id")
                if (
                    not _string(finding_id)
                    or finding_id in finding_ids
                    or item.get("severity") not in {"blocker", "major", "minor"}
                    or item.get("status") not in {"open", "closed"}
                ):
                    failures.add("findings")
                    continue
                finding_ids.add(finding_id)
                has_open_blocker = has_open_blocker or (
                    item.get("severity") == "blocker" and item.get("status") == "open"
                )
        if has_open_blocker:
            failures.add("findings")
        if contract is not None and contract.artifact_type == "candidate-review" and any(
            isinstance(item, Mapping) and item.get("status") == "open"
            for item in (findings if type(findings) is list else ())
        ):
            failures.add("findings")
        validation_records = value.get("validation_records")
        passed_validators: list[str] = []
        if type(validation_records) is not list:
            failures.add("exit")
        else:
            for item in validation_records:
                if not isinstance(item, Mapping) or set(item) != {"validator_id", "body_digest", "result"}:
                    failures.add("exit")
                    continue
                if item.get("result") != "PASS" or item.get("body_digest") != body_digest:
                    failures.add("exit")
                if _string(item.get("validator_id")):
                    passed_validators.append(item["validator_id"])
        if contract is not None and tuple(sorted(passed_validators)) != contract.validator_ids:
            failures.add("exit")
        reviews = value.get("review_records")
        reviewer_id = value.get("reviewer_id")
        review_passed = False
        if type(reviews) is list and len(reviews) == 1 and isinstance(reviews[0], Mapping):
            review = reviews[0]
            review_passed = (
                set(review) == {"reviewer_id", "body_digest", "trust", "verdict"}
                and _string(reviewer_id)
                and _actor(reviewer_id)
                and review.get("reviewer_id") == reviewer_id
                and str(reviewer_id).casefold() != str(value.get("author_id")).casefold()
                and review.get("body_digest") == body_digest
                and review.get("trust") == "independently-reviewed"
                and review.get("verdict") == "PASS"
            )
        if not review_passed:
            failures.add("review")
        approvals = value.get("approval_records")
        approval_passed = False
        if contract is not None and contract.approval_policy == "human":
            approval_passed = (
                type(approvals) is list
                and len(approvals) == 1
                and isinstance(approvals[0], Mapping)
                and set(approvals[0]) == {"owner_id", "body_digest", "decision"}
                and _actor(approvals[0].get("owner_id"))
                and approvals[0].get("body_digest") == body_digest
                and approvals[0].get("decision") == "approved"
            )
        elif contract is not None:
            approval_passed = approvals == []
        if not approval_passed:
            failures.add("review")
        status = value.get("status")
        if contract is not None:
            if status not in contract.allowed_statuses:
                failures.add("status")
            if status == contract.exit_status and (
                failures.intersection({"schema", "semantics", "inputs", "traces", "digests", "findings", "review", "exit"})
            ):
                failures.add("status")
            if status in {"approved", "accepted_for_next_node"} and status != contract.exit_status:
                failures.add("status")
        supersedes = value.get("supersedes")
        revision = value.get("revision")
        if revision == 1:
            if supersedes is not None or previous_record is not None:
                failures.add("findings")
        elif type(revision) is not int:
            failures.add("findings")
        elif not isinstance(supersedes, Mapping) or set(supersedes) != {"artifact_id", "revision", "digest"}:
            failures.add("findings")
        elif (
            supersedes.get("artifact_id") != artifact_id
            or type(supersedes.get("revision")) is not int
            or supersedes["revision"] != revision - 1
            or not _semantic_digest(supersedes.get("digest"))
        ):
            failures.add("findings")
        elif previous_record is None:
            failures.add("findings")
        else:
            previous_findings = {
                item["finding_id"]: item["status"]
                for item in previous_record.body["findings"]
                if isinstance(item, Mapping)
            }
            current_findings = {
                item["finding_id"]: item["status"]
                for item in findings
                if isinstance(item, Mapping) and "finding_id" in item and "status" in item
            } if type(findings) is list else {}
            if (
                supersedes.get("digest") != previous_record.artifact_digest
                or previous_record.artifact_id != artifact_id
                or previous_record.body["revision"] != revision - 1
                or previous_record.body["body_digest"] == body_digest
                or any(
                    status == "open" and current_findings.get(finding_id) != "closed"
                    for finding_id, status in previous_findings.items()
                )
            ):
                failures.add("findings")
            try:
                ArtifactLifecycle.require_revision(previous_record, status)
            except ArtifactValidationError:
                failures.add("status")
        if not _string(value.get("created_at")) or not str(value.get("created_at")).endswith("Z"):
            failures.add("schema")
        expected_artifact_digest = value.get("artifact_digest")
        if not _semantic_digest(expected_artifact_digest):
            failures.add("digests")
        else:
            unsigned = dict(value)
            del unsigned["artifact_digest"]
            actual_digest = semantic_digest_charged(
                unsigned,
                context,
                contract_type="urn:gew:contract:artifact-record",
                projection_id=IDENTITY_PROJECTION,
                schema_id=ARTIFACT_RECORD_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected_artifact_digest, actual_digest):
                failures.add("digests")
        validator_ids = contract.validator_ids if contract is not None else ("schema",)
        return _validation_record(
            artifact_id=str(artifact_id),
            artifact_digest=(
                expected_artifact_digest if _semantic_digest(expected_artifact_digest) else None
            ),
            status="PASS" if not failures else "FAIL",
            validator_ids=validator_ids,
            failures=tuple(sorted(failures)),
        )

    @classmethod
    def load(cls, value: Mapping[str, object], **kwargs: object) -> ArtifactRecord:
        try:
            frozen = freeze(value)
            snapshot = thaw(frozen)
        except (TypeError, ValueError) as error:
            raise ArtifactValidationError("artifact record must be exact JSON") from error
        if not isinstance(frozen, FrozenMap) or not isinstance(snapshot, dict):
            raise ArtifactValidationError("artifact record must be an object")
        validation = cls.validate(snapshot, **kwargs)  # type: ignore[arg-type]
        if validation.status != "PASS":
            raise ArtifactValidationError(
                "artifact validation failed: " + ",".join(validation.failures)
            )
        registry = kwargs.get("contract_registry")
        if type(registry) is not ArtifactContractRegistry:
            raise ArtifactValidationError("artifact contract registry is invalid")
        contract = registry.resolve(str(snapshot["artifact_type"]))
        result = object.__new__(ArtifactRecord)
        object.__setattr__(result, "body", frozen)
        object.__setattr__(result, "contract", contract)
        return result


def _validation_record(
    *,
    artifact_id: str,
    artifact_digest: str | None,
    status: str,
    validator_ids: tuple[str, ...],
    failures: tuple[str, ...],
) -> ArtifactValidationRecord:
    result = object.__new__(ArtifactValidationRecord)
    object.__setattr__(result, "artifact_id", artifact_id)
    object.__setattr__(result, "artifact_digest", artifact_digest)
    object.__setattr__(result, "status", status)
    object.__setattr__(result, "validator_ids", validator_ids)
    object.__setattr__(result, "failures", failures)
    return result
