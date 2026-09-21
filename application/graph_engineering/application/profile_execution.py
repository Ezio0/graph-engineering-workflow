"""WP-08 category observation, completion, rollback, and persistence boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.profile_execution import (
    CategoryCompletionAssessment,
    CategoryExecutionError,
    CategoryExecutionEvent,
    CategoryExecutionPolicy,
    CategoryExecutionReducer,
    CategoryExecutionState,
    CategoryRollbackAssessment,
    CategoryTargetObservation,
    category_object_digest,
)


def _value_digest(value: object, name: str) -> str:
    version = "1.0.0"
    if (
        name == "category-completion-assessment"
        and isinstance(value, Mapping)
        and value.get("schema_version") in {"1.1.0", "1.2.0"}
    ):
        version = str(value["schema_version"])
    return semantic_digest(
        freeze(value),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:{version}",
        schema_id=f"urn:gew:schema:{name}-input:{version}",
    )


def _internal_digest(value: object, name: str) -> str:
    """Digest an internal application value without claiming a public schema."""

    framed = b"GEW-INTERNAL-DIGEST-V1\x00" + name.encode("ascii") + b"\x00"
    return "sha256-jcs-v1:" + hashlib.sha256(framed + canonical_bytes(value)).hexdigest()


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or not value.isascii()
    ):
        raise CategoryExecutionError(f"{label} is invalid")
    return value


def _validate_cold_artifact_record(
    *, record_ref, documents, objects, task_id, owner_id, baselines, target,
    contracts, schemas, context,
):
    """Validate committed acceptance/body facts; issue no ArtifactRecord."""
    from graph_engineering.core.artifacts.manifest import LogicalBodyManifest
    from graph_engineering.core.artifacts.records import ARTIFACT_RECORD_SCHEMA, RECORD_FIELDS, _actor
    from graph_engineering.core.contracts.canonical import canonical_byte_length
    from graph_engineering.core.contracts.digest import raw_digest, semantic_digest_charged
    from graph_engineering.core.contracts.errors import ContractError
    from graph_engineering.storage.repository import _recovery_freeze

    budget = getattr(context, "_recovery_read_budget", None)
    if budget is None:
        raise CategoryExecutionError("cold artifact validation has no reservation owner")
    budget._require_active()
    try:
        record = documents[record_ref]
        body = objects[record_ref]
        if (type(record) is not dict or set(record) != RECORD_FIELDS
                or type(body) is not bytes or category_object_digest(body) != record_ref):
            raise CategoryExecutionError("cold artifact record identity is invalid")
        context.check_limit("array_items", len(documents), source_id="cold-artifact-documents")
        context.check_limit("array_items", len(objects), source_id="cold-artifact-objects")
        with budget.reserve(context, units=4 * (len(documents) + len(objects)), byte_count=0,
                            source_id="cold-artifact-index"):
            logical = record["logical_body_ref"]
            if type(logical) is not dict or set(logical) != {
                "manifest_id", "artifact_id", "entry_digest", "extracted_body_digest",
            }:
                raise CategoryExecutionError("cold artifact logical reference is invalid")
            manifests = [(ref, value) for ref, value in documents.items()
                         if type(value) is dict and set(value) == {
                             "schema_version", "manifest_id", "mode", "physical_body_digest", "entries", "manifest_digest"}
                         and value["manifest_id"] == logical["manifest_id"]
                         and type(value["entries"]) is list
                         and any(type(entry) is dict and all(entry.get(key) == logical[key]
                             for key in ("artifact_id", "entry_digest", "extracted_body_digest"))
                             for entry in value["entries"])]
            if len(manifests) > 1:
                valid_manifests = []
                for candidate_ref, candidate_value in manifests:
                    candidates = []
                    for source in objects.values():
                        context.emit("digest.input_byte", len(source), source_id="cold-manifest-discovery",
                                     operation_path=context.child_path(()))
                        if raw_digest(source) == candidate_value["physical_body_digest"]:
                            candidates.append(source)
                    if len(candidates) != 1:
                        continue
                    size = canonical_byte_length(candidate_value) + len(candidates[0])
                    with budget.reserve(context, units=12 * size, byte_count=4 * size,
                                        source_id="cold-manifest-discovery"):
                        candidate = None
                        try:
                            if canonical_bytes(candidate_value) != objects[candidate_ref]:
                                continue
                            candidate = LogicalBodyManifest.from_dict(candidate_value, candidates[0],
                                schema_registry=schemas, context=context)
                            if (candidate.entry_digest(logical["artifact_id"]) == logical["entry_digest"]
                                    and candidate.extracted_digest(logical["artifact_id"]) == logical["extracted_body_digest"]
                                    and candidate.semantic_body_digest(logical["artifact_id"], record["semantic_fields"], context)
                                        == record["body_digest"]):
                                valid_manifests.append((candidate_ref, candidate_value))
                        except ContractError:
                            raise
                        except (KeyError, TypeError, ValueError):
                            # Only pure validation failures are candidate misses.
                            # Owner admission and reservation are outside this catch.
                            continue
                        finally:
                            del candidate
                manifests = valid_manifests
            if len(manifests) != 1:
                raise CategoryExecutionError("cold artifact manifest is absent or ambiguous")
            manifest_ref, manifest_value = manifests[0]
            physical = []
            for ref, source in objects.items():
                if type(source) is not bytes or category_object_digest(source) != ref:
                    raise CategoryExecutionError("cold artifact raw source identity changed")
                context.emit("digest.input_byte", len(source), source_id="cold-artifact-physical-join",
                             operation_path=context.child_path(()))
                if raw_digest(source) == manifest_value.get("physical_body_digest"):
                    physical.append((ref, source))
            if len(physical) != 1:
                raise CategoryExecutionError("cold artifact physical body is absent or ambiguous")
            physical_ref, physical_body = physical[0]
            size = len(body) + canonical_byte_length(manifest_value) + len(physical_body)
            with budget.reserve(context, units=12 * size, byte_count=4 * size,
                                source_id="cold-artifact-validation"):
                if (canonical_bytes(record) != body
                        or canonical_bytes(manifest_value) != objects[manifest_ref]
                        or schemas.validate(ARTIFACT_RECORD_SCHEMA, record, context)):
                    raise CategoryExecutionError("cold artifact schema or canonical bytes changed")
                contract = contracts.resolve(record["artifact_type"])
                semantic_fields = record["semantic_fields"]
                if (type(semantic_fields) is not dict
                        or set(semantic_fields) != set(contract.required_semantic_fields)
                        or any(type(value) is not str or not value
                               for value in semantic_fields.values())):
                    raise CategoryExecutionError("cold artifact semantic field contract changed")
                if (record["schema_version"] != "1.0.0" or record["task_id"] != task_id
                        or type(record["revision"]) is not int or record["revision"] < 1
                        or record["contract_id"] != contract.contract_id
                        or record["contract_digest"] != contract.contract_digest
                        or record["status"] != contract.exit_status
                        or not _actor(record["author_id"]) or not _actor(record["reviewer_id"])
                        or record["author_id"] == record["reviewer_id"]
                        or record["baseline_digests"] != baselines
                        or record["target_refs"] != [dict(target)]):
                    raise CategoryExecutionError("cold artifact acceptance binding changed")
                unsigned = {key: value for key, value in record.items() if key != "artifact_digest"}
                digest = semantic_digest_charged(unsigned, context,
                    contract_type="urn:gew:contract:artifact-record",
                    projection_id="urn:gew:digest-projection:identity:1.0.0",
                    schema_id=ARTIFACT_RECORD_SCHEMA, operation_path=context.child_path(()))
                if digest != record["artifact_digest"]:
                    raise CategoryExecutionError("cold artifact semantic record digest changed")
                findings = record["findings"]
                if (any(type(item) is not dict or set(item) != {"finding_id", "severity", "status"}
                        or not _text(item.get("finding_id"), "finding identity")
                        or item["severity"] not in {"blocker", "major", "minor"}
                        or item["status"] != "closed" for item in findings)
                        or len({item["finding_id"] for item in findings}) != len(findings)):
                    raise CategoryExecutionError("cold artifact findings are not closed")
                validations = record["validation_records"]
                if (any(type(item) is not dict or set(item) != {"validator_id", "body_digest", "result"}
                        or type(item["validator_id"]) is not str
                        or item["body_digest"] != record["body_digest"] or item["result"] != "PASS"
                        for item in validations)
                        or tuple(sorted(item["validator_id"] for item in validations)) != contract.validator_ids
                        or record["review_records"] != [{"reviewer_id": record["reviewer_id"],
                            "body_digest": record["body_digest"], "trust": "independently-reviewed", "verdict": "PASS"}]):
                    raise CategoryExecutionError("cold artifact validation or independent review changed")
                approvals = ([{"owner_id": owner_id, "body_digest": record["body_digest"], "decision": "approved"}]
                             if contract.approval_policy == "human" else [])
                if record["approval_records"] != approvals or approvals and not _actor(owner_id):
                    raise CategoryExecutionError("cold artifact human approval changed")
                manifest = LogicalBodyManifest.from_dict(manifest_value, physical_body,
                    schema_registry=schemas, context=context)
                artifact_id = _text(record["artifact_id"], "artifact identity")
                if (logical["artifact_id"] != artifact_id
                        or logical["entry_digest"] != manifest.entry_digest(artifact_id)
                        or logical["extracted_body_digest"] != manifest.extracted_digest(artifact_id)
                        or record["body_digest"] != manifest.semantic_body_digest(
                            artifact_id, record["semantic_fields"], context)):
                    raise CategoryExecutionError("cold artifact logical body linkage changed")
                return _recovery_freeze({
                    "record_ref": record_ref, "manifest_ref": manifest_ref,
                    "physical_object_ref": physical_ref,
                    **{key: record[key] for key in ("artifact_id", "artifact_type", "contract_id",
                        "contract_digest", "task_id", "body_digest", "author_id", "reviewer_id", "artifact_digest")},
                }, context, budget, source_id="cold-artifact-result")
    except ContractError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise CategoryExecutionError("cold artifact acceptance/body source is invalid") from error


@contextmanager
def _cold_control_candidate(body, context, budget, *, source_id):
    """Bound discovery; malformed opaque content is not a control candidate."""
    from graph_engineering.core.contracts.errors import ContractError
    from graph_engineering.core.contracts.strict_json import parse_json

    context.check_limit("raw_document_bytes", len(body), source_id=source_id)
    with budget.reserve(context, units=6 * len(body), byte_count=4 * len(body), source_id=source_id):
        try:
            value = parse_json(body, context=context, source_id=source_id, operation_path=context.child_path(()))
        except ContractError:
            raise
        except ValueError:
            # Only parser syntax/scalar failures are discovery misses. Owner
            # admission and reservation errors are outside this catch.
            value = None
        if type(value) is not dict or canonical_bytes(value) != body:
            value = None
        yield value
        del value


_COLD_RELEASE_COLUMN_IDS = frozenset({
    "normal", "boundary", "revise", "authority", "drift", "invalidation",
    "artifacts", "review", "target", "recovery", "rollback", "real-e2e",
})


def _validate_cold_category_sources(
    *, capture, task_application, runtime, policy, contracts, schemas, context,
    action_target, action_baselines, action_provenance=None,
):
    """Join captured task/body/review facts without issuing live acceptance."""
    from contextlib import ExitStack
    from graph_engineering.application.runner import RunnerSnapshot
    from graph_engineering.core.artifacts.records import RECORD_FIELDS, _actor
    from graph_engineering.core.contracts.canonical import canonical_byte_length
    from graph_engineering.core.contracts.digest import semantic_digest_charged
    from graph_engineering.core.graph.state import SNAPSHOT_PROJECTION
    from graph_engineering.storage.repository import _recovery_freeze, _recovery_equal, _recovery_adopt

    budget = getattr(context, "_recovery_read_budget", None)
    if budget is None:
        raise CategoryExecutionError("cold category source has no reservation owner")
    budget._require_active()
    owned = budget._projections.get(id(capture))
    if owned is None or owned[0] is not capture:
        raise CategoryExecutionError("cold category source capture is not owned")
    control_common_fields = {"schema_version", "record_kind", "record_digest",
        "task_id", "profile_id", "task_revision", "snapshot_digest", "invalidation_epoch"}
    control_fields = {
        "category-revision-record-v1": control_common_fields
            | {"budget_remaining", "current_body_digest", "previous_body_digest", "owner_route"},
        "category-drift-record-v1": control_common_fields | {"target_id", "target_digest", "status"},
        "category-recovery-record-v1": control_common_fields | {"recovery_id", "status"},
    }
    def digest(value: object, name: str, *, internal: bool=False) -> str:
        size = canonical_byte_length(value) + len(name) + 256
        with budget.reserve(context, units=8 * size, byte_count=4 * size,
                            source_id="cold-category-digest"):
            context.emit("digest.input_byte", size, source_id="cold-category-digest", operation_path=())
            return (_internal_digest(value, name) if internal else _value_digest(value, name))

    with ExitStack() as stack:
        stack.enter_context(budget.reserve(context, units=64 * (len(capture["objects"]) + len(policy.required_node_ids)) + 128,
            byte_count=0, source_id="cold-source-index"))
        objects, documents = dict(capture["objects"]), {}
        assessment_ref = capture["assessment_ref"]["source_ref"]
        for ref, body in objects.items():
            if body[:1] != b"{":
                continue
            with ExitStack() as candidate_scope:
                value = candidate_scope.enter_context(_cold_control_candidate(body, context, budget, source_id=ref))
                if value is None:
                    continue
                # Shape only selects candidates. Required typed relationships
                # below determine roles; all raw physical bytes remain retained.
                manifest = set(value) == {"schema_version", "manifest_id", "mode",
                    "physical_body_digest", "entries", "manifest_digest"}
                same_task = value.get("task_id") == budget.task_id
                category = same_task and (
                    value.get("record_kind") == "category-artifact-record-v1"
                    and value.get("contract_id") in policy.artifact_contract_ids
                    and set(value) == {"schema_version", "record_kind", "task_id", "artifact_id", "contract_id",
                        "body_digest", "author_id", "reviewer_id", "status", "record_digest"}
                    or value.get("record_kind") == "category-target-contract-v1"
                    and value.get("target_id") == action_target["target_id"]
                    and set(value) == {"schema_version", "record_kind", "task_id", "profile_id", "target_id",
                        "resource_id", "expected_state", "rollback_state", "record_digest"}
                    or value.get("record_kind") == "category-column-evidence-v1"
                    and type(value.get("column_id")) is str
                    and value.get("column_id") in _COLD_RELEASE_COLUMN_IDS
                    and set(value) == CategoryFactsAuthority._EVIDENCE_FIELDS
                    or type(value.get("record_kind")) is str
                    and value.get("record_kind") in control_fields
                    and value.get("profile_id") == policy.profile_id
                    and set(value) == control_fields[value["record_kind"]])
                if ref == assessment_ref or manifest or category or same_task and set(value) == RECORD_FIELDS:
                    # Parsing needs overlapping input/token buffers only until
                    # this context exits. Retain the actual parsed JSON graph,
                    # not every parser scratch copy for all selected records.
                    _recovery_adopt(value, context, budget, record_fields={}, source_id="cold-source-document")
                    documents[ref] = value
                    stack.callback(budget.release_projection, value)
                del value
        assessment = documents.get(assessment_ref)
        if (type(assessment) is not dict or set(assessment) != CategoryCompletionOracle._RELEASE_SOURCE_FIELDS
                or assessment.get("schema_version") != "1.4.0" or assessment.get("profile_id") != "release-operations"
                or type(assessment.get("column_id")) is not str
                or assessment.get("column_id") not in _COLD_RELEASE_COLUMN_IDS
                or assessment.get("column_id") not in policy.column_ids or assessment.get("status") != "PASS"
                or assessment.get("task_id") != budget.task_id
                or assessment.get("assessment_digest") != capture["assessment_ref"]["digest"]
                or assessment["assessment_digest"] != digest(
                    {key: value for key, value in assessment.items() if key != "assessment_digest"},
                    "category-completion-assessment")):
            raise CategoryExecutionError("cold category assessment is unsupported or changed")
        column = assessment["column_id"]
        if (assessment["scenario_id"] not in policy.category_boundary_case_ids
                or not assessment["scenario_id"].endswith("-P")):
            raise CategoryExecutionError("category boundary scenario is not an approved PASS member")
        view_scope = stack.enter_context(ExitStack())
        view = view_scope.enter_context(task_application._cold_task_view(capture, policy=policy, runtime=runtime))
        binding_size = (canonical_byte_length(capture["snapshot"]["domain"])
                        + canonical_byte_length(policy.materialization_output) + 512)
        with budget.reserve(context, units=8 * binding_size, byte_count=4 * binding_size,
                            source_id="cold-task-binding-validation"):
            snapshot = view.snapshot
            pins = {"base_graph_digest": policy.materialization_graph_ref["graph_digest"],
                **{key: policy.materialization_graph_ref[key] for key in (
                    "profile_digest", "overlay_digest", "project_config_digest", "support_matrix_digest", "materialization_digest")}}
            expected_bindings = {"profile_version": policy.profile_version, "profile_digest": policy.profile_digest,
                "overlay_id": snapshot.graph_ref["overlay_id"], "materialization_pins": pins,
                "runner_outputs": thaw(policy.materialization_output),
                "artifact_contract_ids": list(sorted(policy.artifact_contract_ids)),
                "authority_refs": list(policy.authority_refs),
                "category_boundary_case_ids": list(policy.category_boundary_case_ids)}
            for key, expected in expected_bindings.items():
                if not _recovery_equal(assessment[key], expected, context, budget):
                    raise CategoryExecutionError("cold assessment installed binding changed: " + key)
            if (type(assessment["task_revision"]) is not int
                    or assessment["task_revision"] + 1 != snapshot.task_revision
                    or type(assessment["invalidation_epoch"]) is not int
                    or assessment["invalidation_epoch"] != snapshot.invalidation_epoch
                    or snapshot.lifecycle != "completed" or snapshot.open_findings
                    or snapshot.unresolved_action_claims or snapshot.resource_leases
                    or snapshot.authorities):
                raise CategoryExecutionError("cold assessment task/profile/materialization binding changed")
            baselines = {item["kind"]: item["digest"] for item in snapshot.baseline_refs}
            if baselines != dict(action_baselines) or action_target["task_id"] != snapshot.identity["task_id"]:
                raise CategoryExecutionError("cold task and action baseline or target differ")
            last_event = capture["events"][-1]["event"]
            if (last_event["event_type"] != "task.category_assessed"
                    or set(last_event["payload"]) != {"evidence_ref"}
                    or not _recovery_equal(last_event["payload"]["evidence_ref"], capture["assessment_ref"], context, budget)):
                raise CategoryExecutionError("cold assessment is not the final committed domain event")
            previous = snapshot.to_body()
            previous.update(task_revision=snapshot.task_revision - 1, last_event_seq=snapshot.last_event_seq - 1,
                            lifecycle="completing", authorities=list(policy.authority_refs),
                            evidence=[item for item in previous["evidence"]
                                if item["source_ref"] != assessment_ref])
            previous_digest = semantic_digest_charged(previous, context,
                contract_type=SNAPSHOT_PROJECTION.contract_type, projection_id=SNAPSHOT_PROJECTION.projection_id,
                schema_id=SNAPSHOT_PROJECTION.schema_id, operation_path=context.child_path(()))
            if previous_digest != assessment["snapshot_digest"]:
                raise CategoryExecutionError("cold assessment prior task snapshot differs")
            invalidation_epoch = snapshot.invalidation_epoch
            _recovery_adopt(baselines, context, budget, record_fields={}, source_id="cold-task-baselines")
            stack.callback(budget.release_projection, baselines)
            del previous, previous_digest, snapshot, pins, expected_bindings, expected
        runner_size = canonical_byte_length(view.runner_state)
        with budget.reserve(context, units=8 * runner_size, byte_count=4 * runner_size,
                            source_id="cold-runner-validation"):
            runner = RunnerSnapshot(view.runner_state)
            outputs, reviews = runner.node_outputs, runner.review_history
            if (set(outputs) != set(policy.required_node_ids) or runner.failure_routes
                    or any(finding["status"] != "closed" for finding in runner.findings.values())):
                raise CategoryExecutionError("cold runner closure is incomplete")
            runner_projection = _recovery_adopt((outputs, reviews), context, budget,
                record_fields={}, source_id="cold-runner-result")
            stack.callback(budget.release_projection, runner_projection)
            runner = None
        del view
        view_scope.close()

        def records(kind: str) -> list[tuple[str, Mapping[str, object]]]:
            result = []
            for ref, record in documents.items():
                if record.get("record_kind") == kind:
                    unsigned = {key: value for key, value in record.items() if key != "record_digest"}
                    if record.get("record_digest") != digest(unsigned, kind, internal=True):
                        continue
                    # These controls have semantic relationships, not explicit
                    # raw anchors. Only complete candidates enter the role index;
                    # an invalid opaque copy cannot displace a genuine source.
                    if record["schema_version"] != "1.0.0":
                        continue
                    if kind == "category-target-contract-v1":
                        if (record["profile_id"] != policy.profile_id
                                or type(record["expected_state"]) is not dict
                                or type(record["rollback_state"]) is not dict):
                            continue
                        try:
                            _text(record["resource_id"], "cold resource ID")
                        except CategoryExecutionError:
                            continue
                    elif kind == "category-artifact-record-v1":
                        try:
                            if (record["status"] != "accepted-for-category"
                                    or not _actor(record["author_id"]) or not _actor(record["reviewer_id"])
                                    or record["author_id"] == record["reviewer_id"]):
                                continue
                        except ValueError:
                            continue
                    elif kind == "category-column-evidence-v1":
                        if (record["record_digest"] != assessment["column_evidence_digest"]
                                or any(record[key] != assessment[key] or type(record[key]) is not type(assessment[key])
                                    for key in ("task_id", "task_revision", "snapshot_digest", "invalidation_epoch", "profile_id", "column_id"))
                                or record["evidence_kind"] != policy.transition_rules[column]["evidence_kind"]
                                or record["outcome"] != policy.transition_rules[column]["required_outcome"]):
                            continue
                    result.append((ref, record))
            return result

        targets = records("category-target-contract-v1")
        if len(targets) != 1:
            raise CategoryExecutionError("cold target contract is absent or ambiguous")
        target_ref, target = targets[0]
        if (set(target) != {"schema_version", "record_kind", "task_id", "profile_id", "target_id",
                           "resource_id", "expected_state", "rollback_state", "record_digest"}
                or target["schema_version"] != "1.0.0" or target["task_id"] != budget.task_id
                or target["profile_id"] != policy.profile_id or target["target_id"] != action_target["target_id"]
                or type(target["expected_state"]) is not dict or type(target["rollback_state"]) is not dict
                or not _text(target["resource_id"], "cold resource ID")):
            raise CategoryExecutionError("cold target contract binding changed")
        selector = {"schema_version": "1.0.0", "request_id": assessment["request_id"],
            "task_id": budget.task_id, "column_id": column, "scenario_id": assessment["scenario_id"],
            "target_id": target["target_id"]}
        if digest(_category_selector(selector), "category-assessment-selector", internal=True) != assessment["request_digest"]:
            raise CategoryExecutionError("cold assessment selector digest changed")
        categories = records("category-artifact-record-v1")
        join_fields = ("task_id", "artifact_id", "contract_id", "body_digest", "author_id", "reviewer_id")
        output_refs = {ref for output in outputs.values() for ref in output["evidence_refs"]}
        full = {}
        for ref, record in documents.items():
            if (set(record) == RECORD_FIELDS and (ref in output_refs
                    or any(all(record[key] == category.get(key) for key in join_fields) for _, category in categories)
                    or any(record["body_digest"] == review["body_digest"]
                        and record["reviewer_id"] == review["reviewer_id"] for review in reviews))):
                try:
                    verified = _validate_cold_artifact_record(record_ref=ref, documents=documents, objects=objects,
                        task_id=budget.task_id, owner_id=runtime.owner_id, baselines=baselines, target=action_target,
                        contracts=contracts, schemas=schemas, context=context)
                except CategoryExecutionError:
                    # Explicit runner raw anchors are strict. Other candidates
                    # qualify only through a valid complete acceptance chain.
                    # ContractError is a separate type and always propagates.
                    budget._require_active()
                    if ref in output_refs:
                        raise
                    continue
                stack.callback(budget.release_projection, verified)
                full[ref] = verified
        category_fields = {"schema_version", "record_kind", "task_id", "artifact_id", "contract_id",
                           "body_digest", "author_id", "reviewer_id", "status", "record_digest"}
        qualified_categories = []
        for ref, record in categories:
            matches = sum(all(record[key] == accepted[key] for key in join_fields)
                          for accepted in full.values())
            if (set(record) != category_fields or record["schema_version"] != "1.0.0"
                    or record["status"] != "accepted-for-category"
                    or not _actor(record["author_id"]) or not _actor(record["reviewer_id"])
                    or record["author_id"] == record["reviewer_id"]
                    or matches > 1):
                raise CategoryExecutionError("cold category record has no unique accepted body source")
            if matches == 1:
                qualified_categories.append((ref, record))
        if sorted(record["contract_id"] for _ref, record in qualified_categories) != sorted(policy.artifact_contract_ids):
            if sorted(record["contract_id"] for _ref, record in categories) == sorted(policy.artifact_contract_ids):
                raise CategoryExecutionError("cold category record has no unique accepted body source")
            raise CategoryExecutionError("cold category artifact contract closure differs")
        categories = qualified_categories
        def body_source(body_digest: str, author: str | None=None, reviewer: str | None=None) -> Mapping[str, object]:
            matches = [record for record in full.values() if record["body_digest"] == body_digest
                and (author is None or record["author_id"] == author)
                and (reviewer is None or record["reviewer_id"] == reviewer)]
            if len(matches) != 1:
                raise CategoryExecutionError("cold runner body is absent or ambiguous")
            return matches[0]
        for output in outputs.values():
            accepted = body_source(output["body_digest"], output["author_id"], output["reviewer_id"])
            if (output["trust"] != "independently_reviewed" or output["verdict"] != "PASS"
                    or output["author_id"] == output["reviewer_id"]
                    or accepted["record_ref"] not in output["evidence_refs"]):
                raise CategoryExecutionError("cold runner output has no explicit accepted raw source")
        attempts = {}
        for review in reviews:
            key = (review["node_id"], review["run_id"])
            output = outputs.get(review["node_id"])
            if (output is None or output["run_id"] != review["run_id"]
                    or review["attempt"] <= attempts.get(key, 0)):
                raise CategoryExecutionError("cold review lineage or attempt order changed")
            body_source(review["body_digest"], output["author_id"], review["reviewer_id"])
            attempts[key] = review["attempt"]
        passes = [index for index, review in enumerate(reviews) if review["verdict"] == "PASS"]
        if not passes:
            raise CategoryExecutionError("cold final independent review is absent")
        final_index = passes[-1]
        final = reviews[final_index]
        prior = next((review for review in reversed(reviews[:final_index])
                      if review["body_digest"] != final["body_digest"]), None)
        output = outputs[final["node_id"]]
        if (prior is None or any(prior[key] != final[key] for key in ("node_id", "run_id"))
                or any(output[key] != final[key] for key in ("node_id", "run_id", "attempt", "body_digest", "reviewer_id"))
                or final["findings"] or final["finding_ids"]):
            raise CategoryExecutionError("cold final review has no distinct prior body in its run")
        review_value = {"author_id": output["author_id"], "reviewer_id": final["reviewer_id"],
            "trust": "independently-reviewed", "verdict": "PASS", "body_digest": final["body_digest"],
            "previous_body_digest": prior["body_digest"]}
        if digest(review_value, "category-independent-review", internal=True) != assessment["review_digest"]:
            raise CategoryExecutionError("cold independent review digest changed")
        evidence_rows = [(ref, record) for ref, record in records("category-column-evidence-v1")
                         if record.get("column_id") == column]
        if len(evidence_rows) != 1:
            raise CategoryExecutionError("cold column evidence is absent or ambiguous")
        evidence_ref, evidence = evidence_rows[0]
        rule = policy.transition_rules[column]
        facts_size = canonical_byte_length(evidence["facts"]) + 512
        stack.enter_context(budget.reserve(context,
            units=64 * (len(documents) + len(categories)) + 8 * facts_size,
            byte_count=4 * facts_size, source_id="cold-column-reconstruction"))
        common = {key: assessment[key] for key in (
            "task_id", "profile_id", "task_revision", "snapshot_digest", "invalidation_epoch")}

        def bound_control(kind: str, fields: set[str]) -> Mapping[str, object]:
            # Resolve only the captured graph; a live source lookup here would
            # escape the read scope's two complete captures and shared budget.
            candidates = [record for record in documents.values()
                          if record.get("record_kind") == kind]
            expected_fields = {"schema_version", "record_kind", "record_digest", *common, *fields}
            matches = []
            for record in candidates:
                if (set(record) != expected_fields or record.get("schema_version") != "1.0.0"
                        or any(type(record[key]) is not type(value) or record[key] != value
                               for key, value in common.items())):
                    continue
                unsigned = {key: value for key, value in record.items() if key != "record_digest"}
                if record["record_digest"] == digest(unsigned, kind, internal=True):
                    matches.append(record)
            if len(matches) != 1:
                raise CategoryExecutionError("cold column control is absent or ambiguous: " + kind)
            return matches[0]

        target_digest = digest(target["expected_state"], "category-target-state", internal=True)
        if column == "normal":
            expected_facts = {"runner-output-digest": digest(outputs, "category-runner-outputs", internal=True)}
        elif column == "boundary":
            expected_facts = {"scenario-id": assessment["scenario_id"]}
        elif column == "revise":
            source = bound_control("category-revision-record-v1",
                {"budget_remaining", "current_body_digest", "previous_body_digest", "owner_route"})
            remaining, limits = source["budget_remaining"], policy.materialization_output.get("budget_limits")
            if (type(remaining) is not int or remaining <= 0 or not isinstance(limits, FrozenMap)
                    or not limits or remaining > max(int(item) for item in limits.values())
                    or source["current_body_digest"] != final["body_digest"]
                    or source["previous_body_digest"] != prior["body_digest"]
                    or source["owner_route"] != rule["owner_route"]):
                raise CategoryExecutionError("cold revision body or budget control changed")
            expected_facts = {"budget-remaining": remaining, "current-body-digest": source["current_body_digest"],
                "previous-body-digest": source["previous_body_digest"], "owner-route": source["owner_route"]}
        elif column == "authority":
            if not policy.authority_refs:
                raise CategoryExecutionError("cold category authority is absent")
            expected_facts = {"authority-ref": policy.authority_refs[0], "authority-status": "current"}
        elif column == "drift":
            source = bound_control("category-drift-record-v1", {"target_id", "target_digest", "status"})
            if (source["target_id"] != target["target_id"] or source["target_digest"] != target_digest
                    or source["status"] != "resolved"):
                raise CategoryExecutionError("cold drift target control changed")
            expected_facts = {"drift-status": source["status"], "target-digest": source["target_digest"]}
        elif column == "invalidation":
            expected_facts = {"invalidation-epoch": invalidation_epoch, "invalidation-status": "current"}
        elif column == "recovery":
            source = bound_control("category-recovery-record-v1", {"recovery_id", "status"})
            owned_action = budget._projections.get(id(action_provenance))
            if (type(source["recovery_id"]) is not str or not source["recovery_id"]
                    or source["status"] != "recovered" or owned_action is None
                    or owned_action[0] is not action_provenance
                    or action_provenance.get("task_id") != budget.task_id
                    or action_provenance.get("completion") != "compensation_reconciled"
                    or action_provenance.get("action_id") != assessment["release_operations_projection"][
                        "deployment_observation"]["action_id"]):
                raise CategoryExecutionError("cold recovery lacks same-action completed compensation")
            expected_facts = {"recovery-id": source["recovery_id"], "recovery-status": source["status"]}
        elif column == "artifacts":
            expected_facts = {"artifact-record-digests": sorted(record["record_digest"] for _, record in categories)}
        elif column == "review":
            expected_facts = {"author-id": output["author_id"], "reviewer-id": final["reviewer_id"],
                "review-record-digest": digest(final, "category-runner-review", internal=True)}
        elif column == "target":
            expected_facts = {"target-id": target["target_id"], "expected-state-digest": target_digest}
        elif column == "rollback":
            owned_action = budget._projections.get(id(action_provenance))
            projection = assessment["release_operations_projection"]
            if (owned_action is None or owned_action[0] is not action_provenance
                    or action_provenance.get("task_id") != budget.task_id
                    or action_provenance.get("completion") != "compensation_reconciled"
                    or action_provenance.get("action_id") != projection["deployment_observation"]["action_id"]
                    or projection["rollback_observation"] is None):
                raise CategoryExecutionError("cold rollback has no owned completed restore")
            provenance = action_provenance["provenance"]
            restore_id = projection["rollback_observation"]["action_id"]
            journals = {item["action_id"]: item for item in provenance["journals"]}
            if (provenance["recovery"]["compensation_action_id"] != restore_id
                    or provenance["claim"]["claim_id"] != projection["claim_id"]
                    or journals[restore_id]["state"] != "reconciled"
                    or provenance["claim"]["state"] != "compensation_reconciled"):
                raise CategoryExecutionError("cold rollback terminal journal/claim changed")
            expected_facts = {"action-id": restore_id, "action-status": journals[restore_id]["state"],
                              "claim-status": provenance["claim"]["state"]}
        elif column == "real-e2e":
            from graph_engineering.application.release_operations import (
                _release_category_predecessor, _release_category_facts,
            )
            owned_action = budget._projections.get(id(action_provenance))
            projection = assessment["release_operations_projection"]
            if (owned_action is None or owned_action[0] is not action_provenance
                    or action_provenance.get("task_id") != budget.task_id
                    or action_provenance.get("action_id") != projection["deployment_observation"]["action_id"]
                    or projection["rollback_observation"] is not None):
                raise CategoryExecutionError("cold real E2E lacks owned apply provenance")
            provenance = action_provenance["provenance"]
            journals = provenance["journals"]
            if (len(journals) != 1 or provenance["recovery"] is not None
                    or journals[0]["state"] != "reconciled"
                    or provenance["claim"]["state"] != "reconciled_effect_verified"):
                raise CategoryExecutionError("cold real E2E apply is not reconciled")
            binding = {key: assessment[key] for key in (
                "task_id", "task_revision", "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
                "materialization_pins")}
            before = {"schema_version": "1.0.0", **journals[0]["prepared"]["precondition"]}
            after = {"schema_version": "1.0.0", **projection["current_target"]["state"]}
            size = canonical_byte_length(binding) + canonical_byte_length(projection["installation_pins"]) + 4096
            with budget.reserve(context, units=12 * size, byte_count=4 * size,
                    source_id="cold-real-predecessor"):
                predecessor = _release_category_predecessor(binding, projection["installation_pins"],
                    journals[0], provenance["claim"]["state"], before, after, "P")
                raw = canonical_bytes(predecessor)
                ref = "sha256:" + hashlib.sha256(raw).hexdigest()
                if objects.get(ref) != raw:
                    raise CategoryExecutionError("cold real E2E predecessor differs from captured provenance")
                expected_facts = _release_category_facts(predecessor)
        else:
            raise CategoryExecutionError("cold column reconstruction is unsupported")
        if (set(evidence) != CategoryFactsAuthority._EVIDENCE_FIELDS
                or any(evidence[key] != assessment[key] or type(evidence[key]) is not type(assessment[key])
                       for key in ("task_id", "task_revision", "snapshot_digest", "invalidation_epoch", "profile_id", "column_id"))
                or evidence["schema_version"] != "1.0.0" or evidence["evidence_kind"] != rule["evidence_kind"]
                or evidence["outcome"] != rule["required_outcome"]
                or not _recovery_equal(evidence["facts"], expected_facts, context, budget)
                or evidence["record_digest"] != assessment["column_evidence_digest"]):
            raise CategoryExecutionError("cold column evidence differs from captured authoritative facts")
        initial = {"schema_version": "1.0.0", "task_id": budget.task_id, "profile_id": policy.profile_id,
            "column_id": column, "lifecycle": rule["from_state"], "revision": 0,
            "snapshot_digest": assessment["snapshot_digest"], "invalidation_epoch": invalidation_epoch,
            "last_event_digest": None}
        logical_kind = policy.rollback_contract["eligible_action_kinds"][0]
        rollback = {"schema_version": "1.0.0", "task_id": budget.task_id, "profile_id": policy.profile_id,
            "logical_action_kind": logical_kind,
            "action_protocol_kind": policy.rollback_protocol_mappings[logical_kind]["action_protocol_kind"],
            "authority_requirement": policy.rollback_contract["authority_requirement"],
            "compensation_graph_ref": policy.rollback_contract["compensation_graph_ref"],
            "status": "PASS" if column == "rollback" else "NOT_REQUESTED",
            "route": "action-coordinator" if column == "rollback" else "none",
            "observation_digest": assessment["target_observation_digest"]}
        if (assessment["state_digest"] != digest(initial, "category-execution-state")
                or assessment["rollback_assessment_digest"] != digest(rollback, "category-rollback-assessment")):
            raise CategoryExecutionError("cold category reducer or rollback history changed")
        return _recovery_freeze({"assessment": assessment, "target": target,
            "assessment_ref": assessment_ref, "target_ref": target_ref, "evidence_ref": evidence_ref,
            "artifacts": [thaw(full[ref]) for ref in sorted(full)],
            "category_refs": sorted(ref for ref, _record in categories)},
            context, budget, source_id="cold-category-result")


def _exact_mapping(
    value: object, fields: frozenset[str], label: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CategoryExecutionError(f"{label} properties are not exact")
    return value


_CATEGORY_SELECTOR_FIELDS = frozenset({
    "schema_version", "request_id", "task_id", "column_id",
    "scenario_id", "target_id",
})


def _category_selector(value: object) -> dict[str, object]:
    source = _exact_mapping(
        value, _CATEGORY_SELECTOR_FIELDS, "category assessment request"
    )
    if source["schema_version"] != "1.0.0":
        raise CategoryExecutionError("category request version is unsupported")
    return {
        "schema_version": "1.0.0",
        "request_id": _text(source["request_id"], "category request ID"),
        "task_id": _text(source["task_id"], "category task ID"),
        "column_id": _text(source["column_id"], "category column ID"),
        "scenario_id": _text(source["scenario_id"], "category scenario ID"),
        "target_id": _text(source["target_id"], "category target ID"),
    }


def _selector_from_candidate(value: Mapping[str, object]) -> dict[str, object]:
    target = value.get("target")
    if not isinstance(target, Mapping):
        raise CategoryExecutionError("category target selector binding is absent")
    return _category_selector({
        "schema_version": value.get("schema_version"),
        "request_id": value.get("request_id"),
        "task_id": value.get("task_id"),
        "column_id": value.get("column_id"),
        "scenario_id": value.get("scenario_id"),
        "target_id": target.get("target_id"),
    })


def _selector_digest(selector: object) -> str:
    return _internal_digest(
        _category_selector(selector), "category-assessment-selector"
    )


def _strict_json(body: bytes) -> dict[str, object]:
    if type(body) is not bytes:
        raise CategoryExecutionError("category assessment object must be exact bytes")

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise CategoryExecutionError("category assessment contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CategoryExecutionError("category assessment object is invalid JSON") from error
    if type(value) is not dict or canonical_bytes(value) != body:
        raise CategoryExecutionError("category assessment object is not exact canonical JSON")
    return value


def _require_real_category_observer(observer, profile_id, *, identity_only=False):
    from graph_engineering.application.profile_real_e2e import ProfileRealE2EAuthority, ProfileRealE2EObserver, ProfileRealE2EError
    from graph_engineering.application.release_operations import _ReleaseCategoryObserver

    try:
        if profile_id == "release-operations":
            authority = _ReleaseCategoryObserver.require_issued(observer)
        elif identity_only:
            if type(observer) is not ProfileRealE2EObserver or type(observer._authority) is not ProfileRealE2EAuthority:
                raise ValueError("real E2E observer is cloned or foreign")
            authority = observer._authority
            authority._require_observer_identity(observer)
        else:
            authority = ProfileRealE2EObserver.require_issued(observer)
        if authority.profile_id != profile_id:
            raise ValueError("real E2E observer profile differs")
        return authority
    except ValueError as error:
        raise ProfileRealE2EError(str(error)) from error


def _require_real_category_authority(authority, profile_id):
    from graph_engineering.application.profile_real_e2e import ProfileRealE2EAuthority
    from graph_engineering.application.release_operations import _ReleaseCategoryAuthority

    expected = _ReleaseCategoryAuthority if profile_id == "release-operations" else ProfileRealE2EAuthority
    if type(authority) is not expected or authority.profile_id != profile_id:
        raise CategoryExecutionError("real E2E authority is missing or crossed profile boundary")
    return authority


class CategoryTargetObservationAuthority:
    """Issue observations from one exact read-only observer and recheck freshness."""

    _RAW_FIELDS = frozenset({
        "schema_version",
        "execution_kind",
        "target_id",
        "resource_id",
        "fresh",
        "observation_revision",
        "file_identity",
        "state",
        "state_bytes_sha256",
    })

    def __init__(self, policy: CategoryExecutionPolicy) -> None:
        if type(policy) is not CategoryExecutionPolicy:
            raise CategoryExecutionError("target observation policy is missing or forged")
        policy.require_current()
        self._policy = policy
        self.__issued: dict[int, CategoryTargetObservation] = {}
        self.__observers: dict[int, object] = {}
        self.__fences: dict[int, TargetObservationFence] = {}

    def _issue(
        self,
        candidate: Mapping[str, object],
        raw: object,
        observer: object,
    ) -> CategoryTargetObservation:
        if type(raw) is not dict or set(raw) != self._RAW_FIELDS:
            raise CategoryExecutionError("target observation properties are not exact")
        target = candidate["target"]
        if not isinstance(target, Mapping):
            raise CategoryExecutionError("category target is invalid")
        execution_kind = _text(raw["execution_kind"], "target observation execution kind")
        if (
            raw["schema_version"] != "1.0.0"
            or raw["fresh"] is not True
            or raw["target_id"] != target["target_id"]
            or raw["resource_id"] != target["resource_id"]
            or execution_kind != candidate["execution_kind"]
        ):
            raise CategoryExecutionError("target observation is stale or foreign")
        revision = raw["observation_revision"]
        identity = raw["file_identity"]
        if (
            type(revision) is not int
            or revision <= 0
            or type(identity) is not list
            or len(identity) != 2
            or any(type(item) is not int or item < 0 for item in identity)
        ):
            raise CategoryExecutionError("target observation identity is invalid")
        state = raw["state"]
        frozen_state = freeze(state)
        if not isinstance(frozen_state, FrozenMap):
            raise CategoryExecutionError("target observation state must be an object")
        state_hash = _text(raw["state_bytes_sha256"], "target state bytes digest")
        if (
            len(state_hash) != 64
            or any(character not in "0123456789abcdef" for character in state_hash)
            or not hmac.compare_digest(
                state_hash,
                hashlib.sha256(canonical_bytes(state)).hexdigest(),
            )
        ):
            raise CategoryExecutionError("target observation bytes digest changed")
        body = {
            "schema_version": "1.0.0",
            "task_id": candidate["task_id"],
            "profile_id": candidate["profile_id"],
            "snapshot_digest": candidate["snapshot_digest"],
            "target_id": raw["target_id"],
            "resource_id": raw["resource_id"],
            "execution_kind": execution_kind,
            "fresh": True,
            "observation_revision": revision,
            "file_identity": list(identity),
            "state": state,
            "state_bytes_sha256": state_hash,
            "materialization_digest": candidate["materialization_digest"],
        }
        observation = object.__new__(CategoryTargetObservation)
        for name, value in body.items():
            if name == "state":
                value = frozen_state
            elif name == "file_identity":
                value = tuple(value)
            object.__setattr__(observation, name, value)
        object.__setattr__(
            observation,
            "observation_digest",
            _value_digest(body, "category-target-observation"),
        )
        object.__setattr__(observation, "_authority", self)
        self.__issued[id(observation)] = observation
        self.__observers[id(observation)] = observer
        return observation

    def observe(
        self,
        candidate: object,
        observer: object,
    ) -> CategoryTargetObservation:
        value = self._policy.require_candidate(candidate)
        observe = getattr(observer, "observe", None)
        if not callable(observe):
            raise CategoryExecutionError("target observer port is unavailable")
        if value["column_id"] == "real-e2e":
            # Commit fences already hold repository locks. The observer's own
            # fresh physical/installation read remains safe inside that fence;
            # full task currentness is checked by the precommit facts path.
            _require_real_category_observer(observer, self._policy.profile_id, identity_only=True)
            if getattr(observer, "is_test_double", None) is True:
                raise CategoryExecutionError("a local fixture cannot satisfy real E2E")
        elif (
            getattr(observer, "is_test_double", None) is not True
            or getattr(observer, "is_read_only_observer", None) is not True
        ):
            raise CategoryExecutionError("local category target port is not read-only")
        try:
            raw = observe()
        except Exception as error:
            raise CategoryExecutionError("target observation failed closed") from error
        return self._issue(value, raw, observer)

    def require_issued(self, observation: CategoryTargetObservation) -> None:
        if (
            type(observation) is not CategoryTargetObservation
            or observation._authority is not self
            or self.__issued.get(id(observation)) is not observation
        ):
            raise CategoryExecutionError("target observation is missing, cloned, or foreign")
        body = observation.to_dict()
        digest = body.pop("observation_digest")
        if not hmac.compare_digest(
            str(digest),
            _value_digest(body, "category-target-observation"),
        ):
            raise CategoryExecutionError("target observation digest changed")

    def _observer_for(self, observation: CategoryTargetObservation) -> object:
        self.require_issued(observation)
        observer = self.__observers.get(id(observation))
        if observer is None:
            raise CategoryExecutionError("target observer binding expired")
        return observer

    def reobserve_fresh(
        self,
        candidate: object,
        observation: CategoryTargetObservation,
    ) -> CategoryTargetObservation:
        self.require_issued(observation)
        observer = self._observer_for(observation)
        current = self.observe(candidate, observer)
        if any((
            current.target_id != observation.target_id,
            current.resource_id != observation.resource_id,
            current.state_bytes_sha256 != observation.state_bytes_sha256,
            current.file_identity != observation.file_identity,
            thaw(current.state) != thaw(observation.state),
            current.observation_revision <= observation.observation_revision,
        )):
            raise CategoryExecutionError("target changed after its completion observation")
        return current

    def issue_fence(
        self,
        candidate: object,
        observation: CategoryTargetObservation,
        *,
        locks: object,
        completion_binding: tuple[CategoryCompletionOracle, CategoryCompletionAssessment] | None = None,
    ) -> TargetObservationFenceRequest:
        """Issue an opaque request that TaskApplication seals under its locks."""

        from graph_engineering.storage.locks import LockedFileRegistry

        if type(locks) is not LockedFileRegistry:
            raise CategoryExecutionError("target resource lock authority is missing")
        self.require_issued(observation)
        if completion_binding is not None:
            if (
                type(completion_binding) is not tuple or len(completion_binding) != 2
                or type(completion_binding[0]) is not CategoryCompletionOracle
                or type(completion_binding[1]) is not CategoryCompletionAssessment
                or completion_binding[1].task_id != self._policy.require_candidate(candidate)["task_id"]
            ):
                raise CategoryExecutionError("category completion fence binding is invalid")
            try:
                completion_binding[0].require_issued(completion_binding[1])
            except ValueError as error:
                raise CategoryExecutionError("category completion evidence is not current") from error
        request = object.__new__(TargetObservationFenceRequest)
        for name, value in (
            ("resource_id", observation.resource_id),
            ("_authority", self),
            ("_candidate", freeze(self._policy.require_candidate(candidate))),
            ("_observation", observation),
            ("_locks", locks),
            ("_completion_binding", completion_binding),
        ):
            object.__setattr__(request, name, value)
        return request

    def seal_fence(
        self,
        request: TargetObservationFenceRequest,
    ) -> TargetObservationFence:
        if (
            type(request) is not TargetObservationFenceRequest
            or request._authority is not self
            or not request._locks.resources_held_by_current_thread(
                (request.resource_id,),
            )
        ):
            raise CategoryExecutionError("target fence request is forged or unlocked")
        candidate = thaw(request._candidate)
        current = self.reobserve_fresh(candidate, request._observation)
        token = object.__new__(TargetObservationFence)
        for name, value in (
            ("resource_id", current.resource_id),
            ("observation_digest", current.observation_digest),
            ("observation_revision", current.observation_revision),
            ("state_bytes_sha256", current.state_bytes_sha256),
            ("file_identity", current.file_identity),
            ("_authority", self),
            ("_candidate", request._candidate),
            ("_observation", current),
            ("_locks", request._locks),
            ("_completion_binding", request._completion_binding),
        ):
            object.__setattr__(token, name, value)
        self.__fences[id(token)] = token
        return token

    def consume_fence(self, token: TargetObservationFence) -> None:
        """Consume one exact fence as the transaction's final target operation."""

        if (
            type(token) is not TargetObservationFence
            or token._authority is not self
            or self.__fences.pop(id(token), None) is not token
        ):
            raise CategoryExecutionError("target observation fence is forged or consumed")
        if not token._locks.resources_held_by_current_thread((token.resource_id,)):
            raise CategoryExecutionError("target resource fence is not held by this transaction")
        candidate = thaw(token._candidate)
        current = self.reobserve_fresh(candidate, token._observation)
        if any((
            current.resource_id != token.resource_id,
            current.observation_digest == token.observation_digest,
            current.observation_revision <= token.observation_revision,
            current.state_bytes_sha256 != token.state_bytes_sha256,
            current.file_identity != token.file_identity,
        )):
            raise CategoryExecutionError("target changed at the final transaction fence")
        if token._completion_binding is not None:
            oracle, assessment = token._completion_binding
            oracle.require_issued(assessment)


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TargetObservationFence:
    """Opaque one-use proof consumed immediately before durable commit."""

    resource_id: str
    observation_digest: str
    observation_revision: int
    state_bytes_sha256: str
    file_identity: tuple[int, int]
    _authority: CategoryTargetObservationAuthority
    _candidate: FrozenMap
    _observation: CategoryTargetObservation
    _locks: object
    _completion_binding: tuple[CategoryCompletionOracle, CategoryCompletionAssessment] | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("target observation fences are factory-issued")


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TargetObservationFenceRequest:
    """Opaque precommit request sealed only while the resource lock is held."""

    resource_id: str
    _authority: CategoryTargetObservationAuthority
    _candidate: FrozenMap
    _observation: CategoryTargetObservation
    _locks: object
    _completion_binding: tuple[CategoryCompletionOracle, CategoryCompletionAssessment] | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("target fence requests are factory-issued")


class CategoryRollbackBridge:
    """Bridge logical rollback through the exact durable ActionCoordinator."""

    def __init__(
        self, policy: CategoryExecutionPolicy, coordinator: object | None = None
    ) -> None:
        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.core.actions import ActionPolicy

        if (
            type(policy) is not CategoryExecutionPolicy
            or type(coordinator) is not ActionCoordinator
            or type(coordinator._policy) is not ActionPolicy
        ):
            raise CategoryExecutionError("rollback bridge policy is missing or forged")
        policy.require_current()
        self._policy = policy
        self._coordinator = coordinator
        self.__issued: dict[int, CategoryRollbackAssessment] = {}
        self.__action_context: dict[str, object] | None = None
        self.__completed_release: dict[str, object] | None = None
        self.__task_resolution: tuple[object, object] | None = None

    def _bind_task_resolution(self, application: object, runtime: object) -> None:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext
        if self.__task_resolution is not None and all(actual is expected for actual, expected
                in zip(self.__task_resolution, (application, runtime))):
            return
        if (type(application) is not TaskApplication or type(runtime) is not RuntimeContext
                or self.__task_resolution is not None or self.__completed_release is not None):
            raise CategoryExecutionError("rollback task resolution is foreign or already bound")
        if application._repository is self._coordinator._repository:
            self.__task_resolution = (application, runtime)

    def _adopt_completed_release(self, factory: object, evidence: object) -> Mapping[str, object]:
        """Adopt an already completed restore without issuing action authority."""
        from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory

        if (type(factory) is not ReleaseOperationsRegistryFactory
                or self.__action_context is not None or self.__completed_release is not None
                or self._policy.profile_id != "release-operations"):
            raise CategoryExecutionError("completed release rollback authority is invalid")
        factory.require_current(evidence)
        projection = evidence.to_dict()
        session, _deployment, restored = factory._evidence_bindings[id(evidence)]
        logical = self._policy.rollback_contract["eligible_action_kinds"][0]
        mapping = self._policy.rollback_protocol_mappings[logical]
        if (factory._session_coordinators.get(id(session)) is not self._coordinator
                or restored is None or projection["column_id"] != "rollback"
                or projection["profile_id"] != self._policy.profile_id
                or mapping["action_protocol_kind"] != "rollback"):
            raise CategoryExecutionError("completed release rollback binding is foreign")
        proof = self._coordinator._read_completed_action_provenance(
            task_id=projection["task_id"], action_id=projection["deployment_observation"]["action_id"])
        provenance = proof["provenance"]
        recovery = provenance["recovery"]
        restore_id = projection["rollback_observation"]["action_id"]
        if (proof["completion"] != "compensation_reconciled" or recovery is None
                or recovery["compensation_action_id"] != restore_id
                or recovery["original_action_id"] != proof["action_id"]
                or provenance["claim"]["claim_id"] != projection["claim_id"]):
            raise CategoryExecutionError("completed release has no exact compensation link")
        facts = {"action-id": restore_id, "action-status": "reconciled",
                 "claim-status": "compensation_reconciled"}
        context = {"factory": factory, "evidence": evidence,
            "projection": freeze(projection), "proof": proof, "facts": freeze(facts),
            "journals": tuple(self._coordinator._journal.load(item["action_id"])
                              for item in provenance["journals"]),
            "claim": freeze(self._coordinator._leases.load_claim(projection["claim_id"])),
            "recovery": freeze(self._coordinator._leases.recovery_attempt(projection["claim_id"])),
            "security": self._coordinator._issuer.read_task_state(projection["task_id"])}
        if self.__task_resolution is not None:
            application, runtime = self.__task_resolution
            view = application.runtime_show(projection["task_id"], runtime)
            if (view.snapshot.snapshot_digest != projection["snapshot_digest"]
                    or view.snapshot.task_revision != projection["task_revision"]):
                raise CategoryExecutionError("completed restore task snapshot differs from evidence")
            context["source_snapshot"] = view.snapshot
            context["source_runner"] = freeze(view.runner_state)
        for record, source in zip(context["journals"], provenance["journals"]):
            if (any(getattr(record, key) != source[key] for key in ("action_id", "task_id", "state", "revision"))
                    or freeze(self._coordinator._journal.prepared_document(record.prepared)) != source["prepared"]
                    or freeze(self._coordinator._journal.authority_document(record.authority)) != source["authority"]
                    or freeze(record.receipt) != source["receipt"]
                    or freeze(record.reconciliation) != source["reconciliation"]):
                raise CategoryExecutionError("completed restore journal differs from proof")
        if (any(any(value != provenance[kind].get(key) for key, value in context[kind].items())
                for kind in ("claim", "recovery"))
                or any(authority["security_state_digest"] != context["security"].state_digest
                       or authority["runtime_manifest_digest"] != context["security"].runtime_manifest_digest
                       for authority in proof["authorities"])):
            raise CategoryExecutionError("completed restore owner or claim differs from proof")
        if self._coordinator._read_completed_action_provenance(
                task_id=projection["task_id"], action_id=proof["action_id"]) != proof:
            raise CategoryExecutionError("completed restore changed during adoption")
        self.__completed_release = context
        try:
            self._require_completed_release()
        except BaseException:
            self.__completed_release = None
            raise
        return facts

    def _require_completed_release(self) -> Mapping[str, object]:
        context = self.__completed_release
        if context is None:
            raise CategoryExecutionError("completed release rollback context is absent")
        try:
            context["factory"].require_current(context["evidence"])
            projection = context["projection"]
            coordinator = self._coordinator
            security = coordinator._issuer.read_task_state(projection["task_id"])
            coordinator._issuer.runtime.require_policy(
                "action", coordinator._policy.policy_id, coordinator._policy.policy_digest)
            security_current = security == context["security"]
            if not security_current:
                # The only allowed successor is the exact assessment consuming
                # this completed restore. No other revision may reuse it.
                stable = lambda state: {key: (freeze({name: value for name, value in item.items()
                    if name not in {"snapshot_digest", "binding_digest"}}) if key == "binding" else item)
                    for key, item in state.items() if key not in {"task_revision", "task_snapshot_digest"}}
                events = coordinator._repository.replay(projection["task_id"])
                event = events[-1]
                if event.get("event_type") != "task.category_assessed":
                    raise CategoryExecutionError("completed restore was followed by an unrelated transition")
                reference = event.get("payload", {}).get("evidence_ref", {})
                raw = coordinator._objects.get(reference.get("source_ref"), require_referenced=False)
                assessment = _strict_json(raw)
                if self.__task_resolution is None or "source_snapshot" not in context:
                    raise CategoryExecutionError("completed restore successor has no task resolver")
                from graph_engineering.core.graph.state import DomainEvent, apply_events
                application, runtime = self.__task_resolution
                current = application.runtime_show(projection["task_id"], runtime)
                original = context["source_snapshot"]
                expected = apply_events(original, (DomainEvent(original.last_event_seq + 1,
                    original.task_revision, "task.category_assessed", {"evidence_ref": reference}),),
                    schema_registry=application._schemas, context=application._context,
                    materialization_record=self._policy.materialization_record)
                security_current = (
                    current.snapshot == expected
                    and current.repository_revision == security.state["task_revision"]
                    and freeze(current.runner_state) == context["source_runner"]
                    and coordinator._issuer.read_task_state(projection["task_id"]) == security
                    and
                    stable(security.state) == stable(context["security"].state)
                    and security.runtime_manifest_digest == context["security"].runtime_manifest_digest
                    and security.state["task_revision"] == context["security"].state["task_revision"] + 1
                    and event.get("event_type") == "task.category_assessed"
                    and assessment.get("schema_version") == "1.4.0"
                    and assessment.get("profile_id") == "release-operations"
                    and assessment.get("column_id") == "rollback"
                    and assessment.get("status") == "PASS"
                    and freeze(assessment.get("release_operations_projection")) == projection
                    and all(assessment.get(key) == projection[key] for key in (
                        "task_id", "task_revision", "snapshot_digest", "invalidation_epoch"))
                    and assessment.get("assessment_digest") == _value_digest(
                        {key: value for key, value in assessment.items() if key != "assessment_digest"},
                        "category-completion-assessment")
                    and reference.get("digest") == assessment.get("assessment_digest")
                    and (reference.get("source_ref"), raw) in coordinator._repository.referenced_objects(projection["task_id"]))
            if (coordinator._policy._runtime_issuer is not coordinator._issuer.runtime._issuer
                    or not security_current
                    or any(coordinator._journal.load(record.action_id) != record
                           for record in context["journals"])
                    or freeze(coordinator._leases.load_claim(projection["claim_id"])) != context["claim"]
                    or freeze(coordinator._leases.recovery_attempt(projection["claim_id"])) != context["recovery"]):
                raise CategoryExecutionError("completed release rollback provenance changed")
        except (ValueError, OSError, RuntimeError) as error:
            raise CategoryExecutionError("completed release rollback is no longer current") from error
        return context

    def prepare_action(
        self,
        *,
        prepared_document: object,
        authority_document: object,
        lease: object,
        target: object,
        observer: object,
        disclosure_plan: object,
        owner_id: str,
        runtime_kind: str,
        runtime_lineage_id: str,
    ) -> None:
        """Prepare and authorize the exact ActionPolicy rollback before use."""

        from graph_engineering.core.actions import PreparedAction, AuthorityEnvelope
        from graph_engineering.core.security.disclosure import DataDisclosurePlan
        from graph_engineering.storage.ports import LeaseGrant

        if self.__action_context is not None or self.__completed_release is not None:
            raise CategoryExecutionError("rollback action context is already prepared")
        if (
            type(prepared_document) is not dict
            or type(authority_document) is not dict
            or type(lease) is not LeaseGrant
            or type(disclosure_plan) is not DataDisclosurePlan
        ):
            raise CategoryExecutionError("rollback ActionCoordinator inputs are not exact")
        try:
            prepared = self._coordinator.prepare(prepared_document)
            authority = self._coordinator.authorize(authority_document)
        except Exception as error:
            raise CategoryExecutionError("rollback prepare/authorize failed closed") from error
        if (
            type(prepared) is not PreparedAction
            or type(authority) is not AuthorityEnvelope
            or prepared.action_kind != "rollback"
            or authority.authorized_action_kind != "rollback"
            or not hmac.compare_digest(
                authority.prepared_action_digest, prepared.prepared_action_digest
            )
        ):
            raise CategoryExecutionError("rollback action was not exactly authorized")
        self.__action_context = {
            "prepared": prepared,
            "candidate_action": dict(prepared_document),
            "lease": lease,
            "target": target,
            "observer": observer,
            "disclosure_plan": disclosure_plan,
            "owner_id": _text(owner_id, "rollback owner ID"),
            "runtime_kind": _text(runtime_kind, "rollback runtime kind"),
            "runtime_lineage_id": _text(
                runtime_lineage_id, "rollback runtime lineage ID"
            ),
        }

    def require_evidence_facts(
        self, facts: Mapping[str, object], *, final: bool
    ) -> None:
        """Bind rollback evidence to the exact ActionCoordinator journal and claim."""

        if set(facts) != {"action-id", "action-status", "claim-status"}:
            raise CategoryExecutionError("rollback evidence fact closure changed")
        action_id = _text(facts.get("action-id"), "rollback evidence action ID")
        if self.__completed_release is not None:
            context = self._require_completed_release()
            if freeze(facts) != context["facts"]:
                raise CategoryExecutionError("completed restore journal/claim facts changed")
            return
        context = self.__action_context
        if not final:
            if context is None or action_id != context["prepared"].action_id:
                raise CategoryExecutionError("rollback evidence is not bound to prepared action")
        try:
            record = self._coordinator._journal.load(action_id)
        except Exception as error:
            raise CategoryExecutionError("rollback action journal is unavailable") from error
        from graph_engineering.core.actions import ActionJournalRecord

        if (
            type(record) is not ActionJournalRecord
            or record.action_id != action_id
            or record.prepared.action_kind != "rollback"
            or record.authority is None
            or record.authority.authorized_action_kind != "rollback"
        ):
            raise CategoryExecutionError("rollback action journal binding changed")
        if not final:
            if (
                record.state != "authorized"
                or facts.get("action-status") != "reconciled"
                or facts.get("claim-status") != "reconciled_effect_verified"
            ):
                raise CategoryExecutionError("rollback evidence is not ready for verification")
            try:
                self._coordinator._leases.load_claim(f"claim:{action_id}")
            except Exception:
                return
            raise CategoryExecutionError("rollback action already has a durable claim")
        try:
            claim = self._coordinator._leases.load_claim(f"claim:{action_id}")
        except Exception as error:
            raise CategoryExecutionError("rollback durable claim is unavailable") from error
        if (
            record.state not in {"succeeded", "reconciled", "compensated"}
            or claim.get("action_id") != action_id
            or claim.get("state") != "reconciled_effect_verified"
            or facts.get("action-status") != record.state
            or facts.get("claim-status") != claim.get("state")
        ):
            raise CategoryExecutionError("rollback journal/claim evidence is stale")

    def assess(
        self,
        candidate: object,
        observation: CategoryTargetObservation,
        target_authority: CategoryTargetObservationAuthority,
    ) -> tuple[CategoryRollbackAssessment, CategoryTargetObservation]:
        value = self._policy.require_candidate(candidate)
        if type(target_authority) is not CategoryTargetObservationAuthority:
            raise CategoryExecutionError("rollback target authority is missing or forged")
        target_authority.require_issued(observation)
        rollback = value["rollback"]
        if not isinstance(rollback, Mapping):
            raise CategoryExecutionError("rollback candidate is invalid")
        logical_kind = str(rollback["logical_action_kind"])
        mapping = self._policy.rollback_protocol_mappings[logical_kind]
        if not isinstance(mapping, FrozenMap):
            raise CategoryExecutionError("rollback mapping authority changed")
        requested = value["column_id"] == "rollback"
        current_observation = observation
        status = "NOT_REQUESTED"
        route = "none"
        if requested and self.__completed_release is not None:
            context = self._require_completed_release()
            projection = context["projection"]
            if (any(value[key] != projection[key] for key in (
                    "task_id", "task_revision", "snapshot_digest", "invalidation_epoch",
                    "profile_id", "column_id", "scenario_id"))
                    or freeze(value["digest_pins"]) != projection["graph_ref_pins"]
                    or value["target"]["target_id"] != projection["current_target"]["target_id"]):
                raise CategoryExecutionError("completed release rollback candidate changed")
            current_observation = target_authority.reobserve_fresh(value, observation)
            if thaw(current_observation.state) != value["target"]["expected_state"]:
                raise CategoryExecutionError("completed restore target differs from rollback contract")
            status = "PASS"
            route = "action-coordinator"
        elif requested:
            observation = target_authority.reobserve_fresh(value, observation)
            current_observation = observation
            context = self.__action_context
            if context is None:
                raise CategoryExecutionError("rollback ActionCoordinator context is absent")
            prepared = context["prepared"]
            try:
                outcome = self._coordinator.execute(
                    prepared.action_id,
                    owner_id=context["owner_id"],
                    runtime_kind=context["runtime_kind"],
                    runtime_lineage_id=context["runtime_lineage_id"],
                    lease=context["lease"],
                    target=context["target"],
                    observer=context["observer"],
                    disclosure_plan=context["disclosure_plan"],
                    candidate_action=context["candidate_action"],
                )
            except Exception as error:
                raise CategoryExecutionError(
                    "ActionCoordinator rollback failed closed"
                ) from error
            from graph_engineering.application.actions import ActionOutcome

            if type(outcome) is not ActionOutcome:
                raise CategoryExecutionError("ActionCoordinator rollback outcome is invalid")
            if outcome.route in {"manual-reconciliation", "manual-target-reconciliation"}:
                try:
                    outcome = self._coordinator.reconcile_unknown(
                        prepared.action_id,
                        lease=context["lease"],
                        observer=context["observer"],
                    )
                except Exception as error:
                    raise CategoryExecutionError(
                        "ActionCoordinator unknown rollback requires owner reconciliation"
                    ) from error
            if outcome.route == mapping["success_status"]:
                observer = target_authority._observer_for(observation)
                current_observation = target_authority.observe(value, observer)
                if (
                    current_observation.observation_revision
                    <= observation.observation_revision
                    or thaw(current_observation.state)
                    != value["target"]["expected_state"]
                ):
                    raise CategoryExecutionError(
                        "rollback restored target observation is stale or incorrect"
                    )
                status = "PASS"
                route = "action-coordinator"
            elif outcome.route in {
                mapping["unknown_route"], mapping["failure_route"],
                "manual-reconciliation", "manual-target-reconciliation",
            }:
                status = "UNRESOLVED"
                route = str(
                    mapping["unknown_route"]
                    if outcome.route == "manual-reconciliation"
                    else mapping["failure_route"]
                )
            else:
                raise CategoryExecutionError("rollback outcome is not closed")
        body = {
            "schema_version": "1.0.0",
            "task_id": value["task_id"],
            "profile_id": value["profile_id"],
            "logical_action_kind": logical_kind,
            "action_protocol_kind": mapping["action_protocol_kind"],
            "authority_requirement": rollback["authority_requirement"],
            "compensation_graph_ref": rollback["compensation_graph_ref"],
            "status": status,
            "route": route,
            "observation_digest": current_observation.observation_digest,
        }
        result = object.__new__(CategoryRollbackAssessment)
        for name, item in body.items():
            object.__setattr__(result, name, item)
        object.__setattr__(
            result,
            "assessment_digest",
            _value_digest(body, "category-rollback-assessment"),
        )
        object.__setattr__(result, "_authority", self)
        self.__issued[id(result)] = result
        return result, current_observation

    def require_issued(self, assessment: CategoryRollbackAssessment) -> None:
        if (
            type(assessment) is not CategoryRollbackAssessment
            or assessment._authority is not self
            or self.__issued.get(id(assessment)) is not assessment
        ):
            raise CategoryExecutionError("rollback assessment is missing, cloned, or foreign")
        body = assessment.to_dict()
        digest = body.pop("assessment_digest")
        if not hmac.compare_digest(
            str(digest),
            _value_digest(body, "category-rollback-assessment"),
        ):
            raise CategoryExecutionError("rollback assessment digest changed")
        if assessment.status == "PASS" and self.__completed_release is not None:
            self._require_completed_release()


class CategoryCompletionOracle:
    """Issue PASS only from current policy, reducer, observation, and rollback proof."""

    _SOURCE_FIELDS = frozenset({
        "schema_version", "request_id", "request_digest", "task_id", "task_revision",
        "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
        "profile_digest", "overlay_id", "column_id", "scenario_id", "status",
        "category_boundary_case_ids",
        "materialization_pins", "runner_outputs", "artifact_contract_ids",
        "authority_refs", "review_digest", "target_observation_digest",
        "rollback_assessment_digest", "state_digest", "assessment_digest",
        "column_evidence_digest",
    })
    _PERFORMANCE_SOURCE_FIELDS = _SOURCE_FIELDS | frozenset({
        "performance_evidence_projection",
    })
    _MIGRATION_SOURCE_FIELDS = _SOURCE_FIELDS | frozenset({
        "migration_rehearsal_projection",
    })
    _DEPENDENCY_SOURCE_FIELDS = _SOURCE_FIELDS | frozenset({
        "dependency_graph_projection",
    })
    _SCENARIO_SOURCE_FIELDS = _SOURCE_FIELDS | frozenset({
        "scenario_truth_projection",
    })
    _RELEASE_SOURCE_FIELDS = _SOURCE_FIELDS | frozenset({
        "release_operations_projection",
    })

    def __init__(
        self,
        *,
        policy: CategoryExecutionPolicy,
        target_authority: CategoryTargetObservationAuthority,
        performance_registry_factory: object | None = None,
        performance_registry_authority: object | None = None,
        migration_rehearsal_factory: object | None = None,
        migration_rehearsal_authority: object | None = None,
        dependency_graph_factory: object | None = None,
        scenario_truth_factory: object | None = None,
        release_operations_factory: object | None = None,
    ) -> None:
        if (
            type(policy) is not CategoryExecutionPolicy
            or type(target_authority) is not CategoryTargetObservationAuthority
            or target_authority._policy is not policy
        ):
            raise CategoryExecutionError("completion oracle authority is missing or foreign")
        policy.require_current()
        if (performance_registry_factory is None) != (
            performance_registry_authority is None
        ):
            raise CategoryExecutionError(
                "performance assessment authority is incomplete"
            )
        if performance_registry_factory is not None:
            try:
                from graph_engineering.application.performance_benchmark import (
                    PerformanceBenchmarkRegistryFactory,
                )

                if type(performance_registry_factory) is not PerformanceBenchmarkRegistryFactory:
                    raise CategoryExecutionError(
                        "performance assessment factory is foreign"
                    )
                performance_registry_factory.require_current(
                    performance_registry_authority
                )
            except (ImportError, ValueError) as error:
                raise CategoryExecutionError(
                    "performance assessment authority is invalid"
                ) from error
        if (migration_rehearsal_factory is None) != (
            migration_rehearsal_authority is None
        ):
            raise CategoryExecutionError(
                "migration assessment authority is incomplete"
            )
        if migration_rehearsal_factory is not None:
            try:
                from graph_engineering.application.migration_rehearsal import (
                    MigrationRehearsalFactory,
                )

                if type(migration_rehearsal_factory) is not MigrationRehearsalFactory:
                    raise CategoryExecutionError(
                        "migration assessment factory is foreign"
                    )
                migration_rehearsal_factory.require_authority_current(
                    migration_rehearsal_authority
                )
            except (ImportError, ValueError) as error:
                raise CategoryExecutionError(
                    "migration assessment authority is invalid"
                ) from error
        if (
            sum(
                item is not None
                for item in (
                    performance_registry_factory,
                    migration_rehearsal_factory,
                    dependency_graph_factory,
                    scenario_truth_factory,
                    release_operations_factory,
                )
            ) > 1
        ):
            raise CategoryExecutionError("category typed assessment branches overlap")
        if dependency_graph_factory is not None:
            try:
                from graph_engineering.application.dependency_security import (
                    DependencyGraphAssessmentFactory,
                )

                if (
                    type(dependency_graph_factory)
                    is not DependencyGraphAssessmentFactory
                    or policy.profile_id != "dependency-security"
                ):
                    raise CategoryExecutionError(
                        "dependency graph assessment factory is foreign"
                    )
            except (ImportError, ValueError) as error:
                raise CategoryExecutionError(
                    "dependency graph assessment authority is invalid"
                ) from error
        if scenario_truth_factory is not None:
            try:
                from graph_engineering.application.scenario_truth import (
                    ScenarioTruthRegistryFactory,
                )

                if type(scenario_truth_factory) is not ScenarioTruthRegistryFactory:
                    raise CategoryExecutionError(
                        "scenario truth assessment factory is foreign"
                    )
                scenario_truth_factory.registry()
            except (ImportError, ValueError) as error:
                raise CategoryExecutionError(
                    "scenario truth assessment authority is invalid"
                ) from error
        if release_operations_factory is not None:
            try:
                from graph_engineering.application.release_operations import (
                    ReleaseOperationsRegistryFactory,
                )

                if (
                    type(release_operations_factory)
                    is not ReleaseOperationsRegistryFactory
                    or policy.profile_id != "release-operations"
                ):
                    raise CategoryExecutionError(
                        "release operations assessment factory is foreign"
                    )
                release_operations_factory.require_installed_authority()
            except (ImportError, ValueError) as error:
                raise CategoryExecutionError(
                    "release operations assessment authority is invalid"
                ) from error
        self._policy = policy
        self._target_authority = target_authority
        self._performance_registry_factory = performance_registry_factory
        self._performance_registry_authority = performance_registry_authority
        self._migration_rehearsal_factory = migration_rehearsal_factory
        self._migration_rehearsal_authority = migration_rehearsal_authority
        self._dependency_graph_factory = dependency_graph_factory
        self._scenario_truth_factory = scenario_truth_factory
        self._release_operations_factory = release_operations_factory
        self.__issued: dict[int, CategoryCompletionAssessment] = {}

    def _issue(
        self,
        body: Mapping[str, object],
        *,
        performance_evidence: object | None = None,
        migration_rehearsal_evidence: object | None = None,
        dependency_graph_evidence: object | None = None,
        scenario_truth_evidence: object | None = None,
        release_operations_evidence: object | None = None,
    ) -> CategoryCompletionAssessment:
        assessment_digest = _value_digest(body, "category-completion-assessment")
        result = object.__new__(CategoryCompletionAssessment)
        for name, item in body.items():
            if name in {
                "materialization_pins", "runner_outputs",
                "performance_evidence_projection",
                "migration_rehearsal_projection",
                "dependency_graph_projection",
                "scenario_truth_projection",
                "release_operations_projection",
            }:
                frozen = freeze(item)
                if not isinstance(frozen, FrozenMap):
                    raise CategoryExecutionError(f"{name} did not freeze")
                item = frozen
            elif name in {
                "artifact_contract_ids", "authority_refs", "category_boundary_case_ids"
            }:
                item = tuple(item)
            object.__setattr__(result, name, item)
        if "performance_evidence_projection" not in body:
            object.__setattr__(result, "performance_evidence_projection", None)
        if "migration_rehearsal_projection" not in body:
            object.__setattr__(result, "migration_rehearsal_projection", None)
        if "dependency_graph_projection" not in body:
            object.__setattr__(result, "dependency_graph_projection", None)
        if "scenario_truth_projection" not in body:
            object.__setattr__(result, "scenario_truth_projection", None)
        if "release_operations_projection" not in body:
            object.__setattr__(result, "release_operations_projection", None)
        object.__setattr__(result, "assessment_digest", assessment_digest)
        object.__setattr__(result, "_authority", self)
        object.__setattr__(result, "_performance_evidence", performance_evidence)
        object.__setattr__(
            result, "_migration_rehearsal_evidence", migration_rehearsal_evidence,
        )
        object.__setattr__(
            result, "_dependency_graph_evidence", dependency_graph_evidence,
        )
        object.__setattr__(result, "_scenario_truth_evidence", scenario_truth_evidence)
        object.__setattr__(
            result, "_release_operations_evidence", release_operations_evidence,
        )
        object.__setattr__(result, "object_digest", "")
        object.__setattr__(result, "object_digest", category_object_digest(result.to_bytes()))
        self.__issued[id(result)] = result
        return result

    def assess(
        self,
        candidate: object,
        *,
        observation: CategoryTargetObservation,
        rollback_assessment: CategoryRollbackAssessment,
        rollback_bridge: CategoryRollbackBridge,
        column_evidence_digest: str,
        state: CategoryExecutionState,
        reducer: CategoryExecutionReducer,
        performance_evidence: object | None = None,
        migration_rehearsal_evidence: object | None = None,
        dependency_graph_evidence: object | None = None,
        scenario_truth_evidence: object | None = None,
        release_operations_evidence: object | None = None,
    ) -> CategoryCompletionAssessment:
        value = self._policy.require_candidate(candidate)
        self._target_authority.require_issued(observation)
        if (
            type(rollback_bridge) is not CategoryRollbackBridge
            or rollback_bridge._policy is not self._policy
        ):
            raise CategoryExecutionError("rollback bridge is missing or foreign")
        rollback_bridge.require_issued(rollback_assessment)
        evidence_digest = _text(
            column_evidence_digest, "category column evidence digest"
        )
        if SEMANTIC_DIGEST.fullmatch(evidence_digest) is None:
            raise CategoryExecutionError("category column evidence digest is invalid")
        if type(reducer) is not CategoryExecutionReducer or reducer._policy is not self._policy:
            raise CategoryExecutionError("category reducer is missing or foreign")
        target = value["target"]
        if not isinstance(target, Mapping) or thaw(observation.state) != target["expected_state"]:
            raise CategoryExecutionError("current target state does not match completion target")
        if (
            (value["column_id"] == "rollback" and rollback_assessment.status != "PASS")
            or (
                value["column_id"] != "rollback"
                and rollback_assessment.status != "NOT_REQUESTED"
            )
            or rollback_assessment.observation_digest != observation.observation_digest
        ):
            raise CategoryExecutionError("rollback assessment is not current and closed")
        review = value["review"]
        if not isinstance(review, Mapping):
            raise CategoryExecutionError("category review is malformed")
        performance_projection: dict[str, object] | None = None
        if self._performance_registry_factory is not None:
            if value["profile_id"] != "performance":
                raise CategoryExecutionError(
                    "performance assessment factory crossed Profile boundary"
                )
            evidence = self._performance_registry_factory.require_performance_evidence_current(
                performance_evidence
            )
            performance_projection = thaw(evidence.projection)
            if (
                performance_projection.get("task_id") != value["task_id"]
                or performance_projection.get("task_revision") != value["task_revision"]
                or performance_projection.get("snapshot_digest") != value["snapshot_digest"]
                or performance_projection.get("invalidation_epoch")
                != value["invalidation_epoch"]
                or performance_projection.get("profile_id") != value["profile_id"]
                or performance_projection.get("profile_version")
                != value["profile_version"]
                or performance_projection.get("column_id") != value["column_id"]
                or freeze(performance_projection.get("graph_ref_pins"))
                != freeze(value["digest_pins"])
            ):
                raise CategoryExecutionError(
                    "performance evidence does not match the current task"
                )
        elif performance_evidence is not None:
            raise CategoryExecutionError("performance evidence authority is not installed")
        migration_projection: dict[str, object] | None = None
        if self._migration_rehearsal_factory is not None:
            if value["profile_id"] != "migration":
                raise CategoryExecutionError(
                    "migration assessment factory crossed Profile boundary"
                )
            evidence = self._migration_rehearsal_factory.require_current(
                migration_rehearsal_evidence
            )
            migration_projection = thaw(
                self._migration_rehearsal_factory.projection(evidence)
            )
            if (
                migration_projection.get("task_id") != value["task_id"]
                or migration_projection.get("task_revision") != value["task_revision"]
                or migration_projection.get("snapshot_digest") != value["snapshot_digest"]
                or migration_projection.get("invalidation_epoch")
                != value["invalidation_epoch"]
                or migration_projection.get("profile_id") != value["profile_id"]
                or freeze(migration_projection.get("graph_ref_pins"))
                != freeze(value["digest_pins"])
            ):
                raise CategoryExecutionError(
                    "migration rehearsal evidence does not match the current task"
                )
        elif migration_rehearsal_evidence is not None:
            raise CategoryExecutionError("migration rehearsal authority is not installed")
        dependency_projection: dict[str, object] | None = None
        dependency_evidence = None
        dependency_scenario = (
            value["profile_id"] == "dependency-security"
            and value["scenario_id"] in {
                "GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P",
                "GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P",
            }
        )
        if dependency_scenario:
            try:
                from graph_engineering.application.dependency_security import (
                    DependencyGraphAssessmentFactory,
                    DependencySecurityObservation,
                    DependencySecurityObservationFactory,
                )

                if (
                    type(dependency_graph_evidence) is not tuple
                    or len(dependency_graph_evidence) != 2
                    or type(dependency_graph_evidence[0])
                    is not DependencySecurityObservationFactory
                    or type(dependency_graph_evidence[1])
                    is not DependencySecurityObservation
                ):
                    raise CategoryExecutionError(
                        "dependency graph assessment evidence is absent or foreign"
                    )
                source_factory, source_observation = dependency_graph_evidence
                dependency_factory = self._dependency_graph_factory
                if dependency_factory is None:
                    dependency_factory = DependencyGraphAssessmentFactory.from_installation(
                        source_factory._registry._repository
                    )
                    self._dependency_graph_factory = dependency_factory
                if type(dependency_factory) is not DependencyGraphAssessmentFactory:
                    raise CategoryExecutionError(
                        "dependency graph assessment factory is foreign"
                    )
                dependency_evidence = dependency_factory.issue(
                    source_factory,
                    source_observation,
                    graph_ref_pins=value["digest_pins"],
                    authority_refs=value["authority_refs"],
                )
                dependency_projection = thaw(
                    dependency_factory.projection(dependency_evidence)
                )
                if (
                    dependency_projection.get("task_id") != value["task_id"]
                    or dependency_projection.get("task_revision")
                    != value["task_revision"]
                    or dependency_projection.get("snapshot_digest")
                    != value["snapshot_digest"]
                    or dependency_projection.get("invalidation_epoch")
                    != value["invalidation_epoch"]
                    or dependency_projection.get("profile_id")
                    != value["profile_id"]
                    or value["scenario_id"]
                    != (
                        "GEW-PSC-DEPENDENCY-SECURITY-"
                        + str(dependency_projection.get("scenario_id", "")).upper()
                        + "-P"
                    )
                    or freeze(dependency_projection.get("graph_ref_pins"))
                    != freeze(value["digest_pins"])
                    or dependency_projection.get("action_authority", {}).get(
                        "authority_refs"
                    ) != list(value["authority_refs"])
                ):
                    raise CategoryExecutionError(
                        "dependency graph evidence does not match the current task"
                    )
            except CategoryExecutionError:
                raise
            except Exception as error:
                raise CategoryExecutionError(
                    "dependency graph assessment authority is invalid"
                ) from error
        elif dependency_graph_evidence is not None:
            raise CategoryExecutionError(
                "dependency graph evidence crossed scenario boundary"
            )
        scenario_projection: dict[str, object] | None = None
        if self._scenario_truth_factory is not None:
            try:
                evidence = self._scenario_truth_factory.require_current(
                    scenario_truth_evidence
                )
                scenario_projection = thaw(
                    self._scenario_truth_factory.projection(evidence)
                )
            except Exception as error:
                raise CategoryExecutionError(
                    "scenario truth evidence is absent, stale, or foreign"
                ) from error
            expected_boundary_case = (
                "GEW-PSC-" + str(scenario_projection.get("profile_id", "")).upper()
                + "-" + str(scenario_projection.get("scenario_id", "")).upper() + "-P"
            )
            if (
                scenario_projection.get("task_id") != value["task_id"]
                or scenario_projection.get("task_revision") != value["task_revision"]
                or scenario_projection.get("snapshot_digest") != value["snapshot_digest"]
                or scenario_projection.get("invalidation_epoch")
                != value["invalidation_epoch"]
                or scenario_projection.get("profile_id") != value["profile_id"]
                or scenario_projection.get("profile_version") != value["profile_version"]
                or value["scenario_id"] != expected_boundary_case
                or freeze(scenario_projection.get("graph_ref_pins"))
                != freeze(value["digest_pins"])
            ):
                raise CategoryExecutionError(
                    "scenario truth evidence does not match the current task"
                )
        elif scenario_truth_evidence is not None:
            raise CategoryExecutionError("scenario truth authority is not installed")
        release_projection: dict[str, object] | None = None
        if self._release_operations_factory is not None:
            if value["profile_id"] != "release-operations":
                raise CategoryExecutionError(
                    "release operations factory crossed Profile boundary"
                )
            try:
                evidence = self._release_operations_factory.require_current(
                    release_operations_evidence
                )
                release_projection = thaw(
                    self._release_operations_factory.projection(evidence)
                )
            except Exception as error:
                raise CategoryExecutionError(
                    "release operations evidence is absent, stale, or foreign"
                ) from error
            if (
                release_projection.get("task_id") != value["task_id"]
                or release_projection.get("task_revision") != value["task_revision"]
                or release_projection.get("snapshot_digest") != value["snapshot_digest"]
                or release_projection.get("invalidation_epoch")
                != value["invalidation_epoch"]
                or release_projection.get("profile_id") != value["profile_id"]
                or release_projection.get("profile_version") != value["profile_version"]
                or release_projection.get("column_id") != value["column_id"]
                or release_projection.get("scenario_id") != value["scenario_id"]
                or freeze(release_projection.get("graph_ref_pins"))
                != freeze(value["digest_pins"])
            ):
                raise CategoryExecutionError(
                    "release operations evidence does not match the current task"
                )
        elif release_operations_evidence is not None:
            raise CategoryExecutionError(
                "release operations authority is not installed"
            )
        body = {
            "schema_version": (
                "1.4.0" if release_projection is not None
                else "1.3.0" if scenario_projection is not None
                else "1.2.0"
                if migration_projection is not None or dependency_projection is not None
                else "1.1.0" if performance_projection is not None
                else "1.0.0"
            ),
            "request_id": value["request_id"],
            "request_digest": _selector_digest(
                _selector_from_candidate(value)
            ),
            "task_id": value["task_id"],
            "task_revision": value["task_revision"],
            "snapshot_digest": value["snapshot_digest"],
            "invalidation_epoch": value["invalidation_epoch"],
            "profile_id": value["profile_id"],
            "profile_version": value["profile_version"],
            "profile_digest": value["profile_digest"],
            "overlay_id": value["overlay_id"],
            "column_id": value["column_id"],
            "scenario_id": value["scenario_id"],
            "category_boundary_case_ids": list(
                self._policy.category_boundary_case_ids
            ),
            "status": "PASS",
            "materialization_pins": value["digest_pins"],
            "runner_outputs": value["runner_outputs"],
            "artifact_contract_ids": value["current_artifact_contract_ids"],
            "authority_refs": value["authority_refs"],
            "review_digest": _internal_digest(review, "category-independent-review"),
            "target_observation_digest": observation.observation_digest,
            "rollback_assessment_digest": rollback_assessment.assessment_digest,
            "state_digest": state.state_digest,
            "column_evidence_digest": evidence_digest,
        }
        if performance_projection is not None:
            body["performance_evidence_projection"] = performance_projection
        if migration_projection is not None:
            body["migration_rehearsal_projection"] = migration_projection
        if dependency_projection is not None:
            body["dependency_graph_projection"] = dependency_projection
        if scenario_projection is not None:
            body["scenario_truth_projection"] = scenario_projection
        if release_projection is not None:
            body["release_operations_projection"] = release_projection
        return self._issue(
            body,
            performance_evidence=performance_evidence,
            migration_rehearsal_evidence=migration_rehearsal_evidence,
            dependency_graph_evidence=dependency_evidence,
            scenario_truth_evidence=scenario_truth_evidence,
            release_operations_evidence=release_operations_evidence,
        )

    def require_issued(self, assessment: CategoryCompletionAssessment) -> None:
        if (
            type(assessment) is not CategoryCompletionAssessment
            or assessment._authority is not self
            or self.__issued.get(id(assessment)) is not assessment
        ):
            raise CategoryExecutionError("completion assessment is missing, cloned, or foreign")
        body = assessment.body()
        if self._performance_registry_factory is not None:
            evidence = self._performance_registry_factory.require_performance_evidence_current(
                assessment._performance_evidence
            )
            if freeze(thaw(evidence.projection)) != assessment.performance_evidence_projection:
                raise CategoryExecutionError("performance assessment evidence changed")
        elif assessment.performance_evidence_projection is not None:
            raise CategoryExecutionError("performance assessment authority is absent")
        if self._migration_rehearsal_factory is not None:
            evidence = self._migration_rehearsal_factory.require_current(
                assessment._migration_rehearsal_evidence
            )
            projection = self._migration_rehearsal_factory.projection(evidence)
            if projection != assessment.migration_rehearsal_projection:
                raise CategoryExecutionError("migration rehearsal assessment evidence changed")
        elif assessment.migration_rehearsal_projection is not None:
            raise CategoryExecutionError("migration rehearsal assessment authority is absent")
        if self._dependency_graph_factory is not None:
            evidence = self._dependency_graph_factory.require_current(
                assessment._dependency_graph_evidence
            )
            projection = self._dependency_graph_factory.projection(evidence)
            if projection != assessment.dependency_graph_projection:
                raise CategoryExecutionError(
                    "dependency graph assessment evidence changed"
                )
        elif assessment.dependency_graph_projection is not None:
            raise CategoryExecutionError(
                "dependency graph assessment authority is absent"
            )
        if self._scenario_truth_factory is not None:
            evidence = self._scenario_truth_factory.require_current(
                assessment._scenario_truth_evidence
            )
            projection = self._scenario_truth_factory.projection(evidence)
            if projection != assessment.scenario_truth_projection:
                raise CategoryExecutionError(
                    "scenario truth assessment evidence changed"
                )
        elif assessment.scenario_truth_projection is not None:
            raise CategoryExecutionError("scenario truth assessment authority is absent")
        if self._release_operations_factory is not None:
            evidence = self._release_operations_factory.require_current(
                assessment._release_operations_evidence
            )
            projection = self._release_operations_factory.projection(evidence)
            if projection != assessment.release_operations_projection:
                raise CategoryExecutionError(
                    "release operations assessment evidence changed"
                )
        elif assessment.release_operations_projection is not None:
            raise CategoryExecutionError(
                "release operations assessment authority is absent"
            )
        if (
            assessment.status != "PASS"
            or not hmac.compare_digest(
                assessment.assessment_digest,
                _value_digest(body, "category-completion-assessment"),
            )
            or not hmac.compare_digest(
                assessment.object_digest,
                category_object_digest(assessment.to_bytes()),
            )
        ):
            raise CategoryExecutionError("completion assessment authority changed")
        self._policy.require_current()

    def restore(self, body: bytes) -> CategoryCompletionAssessment:
        source = _strict_json(body)
        source_fields = (
            self._PERFORMANCE_SOURCE_FIELDS
            if source.get("schema_version") == "1.1.0"
            else self._RELEASE_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.4.0"
                and source.get("profile_id") == "release-operations"
                and "release_operations_projection" in source
            )
            else self._SCENARIO_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.3.0"
                and "scenario_truth_projection" in source
            )
            else self._DEPENDENCY_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.2.0"
                and source.get("profile_id") == "dependency-security"
                and "dependency_graph_projection" in source
                and "migration_rehearsal_projection" not in source
            )
            else self._MIGRATION_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.2.0"
                and source.get("profile_id") == "migration"
                and "migration_rehearsal_projection" in source
                and "dependency_graph_projection" not in source
            )
            else self._SOURCE_FIELDS
        )
        if set(source) != source_fields:
            raise CategoryExecutionError("stored category assessment properties are not exact")
        expected = source.pop("assessment_digest")
        if (
            type(expected) is not str
            or SEMANTIC_DIGEST.fullmatch(expected) is None
            or not hmac.compare_digest(
                expected,
                _value_digest(source, "category-completion-assessment"),
            )
        ):
            raise CategoryExecutionError("stored category assessment digest changed")
        if (
            source.get("status") != "PASS"
            or source.get("profile_id") != self._policy.profile_id
            or source.get("profile_version") != self._policy.profile_version
            or source.get("profile_digest") != self._policy.profile_digest
            or source.get("materialization_pins")
            != {
                "base_graph_digest": self._policy.materialization_graph_ref["graph_digest"],
                "profile_digest": self._policy.materialization_graph_ref["profile_digest"],
                "overlay_digest": self._policy.materialization_graph_ref["overlay_digest"],
                "project_config_digest": self._policy.materialization_graph_ref["project_config_digest"],
                "support_matrix_digest": self._policy.materialization_graph_ref["support_matrix_digest"],
                "materialization_digest": self._policy.materialization_graph_ref["materialization_digest"],
            }
        ):
            raise CategoryExecutionError("stored category assessment is stale or foreign")
        performance_evidence = None
        if source.get("schema_version") == "1.1.0":
            if self._performance_registry_factory is None:
                raise CategoryExecutionError(
                    "stored performance assessment has no current authority"
                )
            projection = source.get("performance_evidence_projection")
            if type(projection) is not dict:
                raise CategoryExecutionError(
                    "stored performance evidence projection is malformed"
                )
            performance_evidence = (
                self._performance_registry_factory.rehydrate_performance_evidence(
                    self._performance_registry_authority,
                    projection,
                )
            )
        migration_evidence = None
        if (
            source.get("schema_version") == "1.2.0"
            and source.get("profile_id") == "migration"
        ):
            if self._migration_rehearsal_factory is None:
                raise CategoryExecutionError(
                    "stored migration assessment has no current authority"
                )
            projection = source.get("migration_rehearsal_projection")
            if type(projection) is not dict:
                raise CategoryExecutionError(
                    "stored migration rehearsal projection is malformed"
                )
            migration_evidence = self._migration_rehearsal_factory.rehydrate_projection(
                self._migration_rehearsal_authority, projection,
            )
        dependency_evidence = None
        if (
            source.get("schema_version") == "1.2.0"
            and source.get("profile_id") == "dependency-security"
        ):
            if self._dependency_graph_factory is None:
                raise CategoryExecutionError(
                    "stored dependency graph assessment has no current authority"
                )
            projection = source.get("dependency_graph_projection")
            if type(projection) is not dict:
                raise CategoryExecutionError(
                    "stored dependency graph projection is malformed"
                )
            try:
                dependency_evidence = (
                    self._dependency_graph_factory.rehydrate_projection(projection)
                )
            except Exception as error:
                raise CategoryExecutionError(
                    "stored dependency graph projection is stale or foreign"
                ) from error
        scenario_evidence = None
        if source.get("schema_version") == "1.3.0":
            if self._scenario_truth_factory is None:
                raise CategoryExecutionError(
                    "stored scenario truth assessment has no current authority"
                )
            projection = source.get("scenario_truth_projection")
            if type(projection) is not dict:
                raise CategoryExecutionError(
                    "stored scenario truth projection is malformed"
                )
            scenario_evidence = self._scenario_truth_factory.restore_projection(
                projection
            )
        release_evidence = None
        if source.get("schema_version") == "1.4.0":
            if (
                source.get("profile_id") != "release-operations"
                or self._release_operations_factory is None
            ):
                raise CategoryExecutionError(
                    "stored release assessment has no current authority"
                )
            projection = source.get("release_operations_projection")
            if type(projection) is not dict:
                raise CategoryExecutionError(
                    "stored release operations projection is malformed"
                )
            release_evidence = (
                self._release_operations_factory.restore_projection(projection)
            )
        result = self._issue(
            source,
            performance_evidence=performance_evidence,
            migration_rehearsal_evidence=migration_evidence,
            dependency_graph_evidence=dependency_evidence,
            scenario_truth_evidence=scenario_evidence,
            release_operations_evidence=release_evidence,
        )
        if not hmac.compare_digest(result.assessment_digest, expected):
            raise CategoryExecutionError("stored category assessment did not restore exactly")
        return result


class CategoryAssessmentResolver:
    """Resolve only the unique task-current, committed assessment object reference."""

    def __init__(
        self,
        repository: object,
        object_repository: object,
        *,
        task_application: object,
        runtime: object,
    ) -> None:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository

        if (
            type(repository) is not TaskRepository
            or type(object_repository) is not ObjectRepository
            or type(task_application) is not TaskApplication
            or task_application._repository is not repository
            or type(runtime) is not RuntimeContext
        ):
            raise CategoryExecutionError("category assessment repositories are unavailable")
        self._repository = repository
        self._objects = object_repository
        self._task_application = task_application
        self._runtime = runtime

    def current_snapshot(self, task_id: str) -> dict[str, object] | None:
        try:
            view = self._task_application.runtime_show(task_id, self._runtime)
        except Exception as error:
            raise CategoryExecutionError("category current TaskSnapshot is unavailable") from error
        references = tuple(
            item for item in view.snapshot.evidence
            if item.evidence_type == "category-completion-assessment"
        )
        if not references:
            return None
        if len(references) != 1:
            raise CategoryExecutionError("task has multiple current category assessment refs")
        reference = references[0]
        if reference.trust != "factory-attested":
            raise CategoryExecutionError("category assessment evidence trust changed")
        try:
            body = self._objects.get(reference.source_ref, require_referenced=True)
            committed = dict(self._repository.referenced_objects(task_id))
        except Exception as error:
            raise CategoryExecutionError("category assessment object is unavailable") from error
        if committed.get(reference.source_ref) != body:
            raise CategoryExecutionError("category assessment ref is not uniquely committed")
        source = _strict_json(body)
        source_fields = (
            CategoryCompletionOracle._PERFORMANCE_SOURCE_FIELDS
            if source.get("schema_version") == "1.1.0"
            else CategoryCompletionOracle._RELEASE_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.4.0"
                and source.get("profile_id") == "release-operations"
                and "release_operations_projection" in source
            )
            else CategoryCompletionOracle._SCENARIO_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.3.0"
                and "scenario_truth_projection" in source
            )
            else CategoryCompletionOracle._DEPENDENCY_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.2.0"
                and source.get("profile_id") == "dependency-security"
                and "dependency_graph_projection" in source
                and "migration_rehearsal_projection" not in source
            )
            else CategoryCompletionOracle._MIGRATION_SOURCE_FIELDS
            if (
                source.get("schema_version") == "1.2.0"
                and source.get("profile_id") == "migration"
                and "migration_rehearsal_projection" in source
                and "dependency_graph_projection" not in source
            )
            else CategoryCompletionOracle._SOURCE_FIELDS
        )
        if (
            set(source) != source_fields
            or source.get("task_id") != task_id
            or source.get("assessment_digest") != reference.evidence_id
            or source.get("assessment_digest") != reference.digest
            or category_object_digest(body) != reference.source_ref
        ):
            raise CategoryExecutionError("category assessment ref binding changed")
        request_digest = source.get("request_digest")
        if type(request_digest) is not str or SEMANTIC_DIGEST.fullmatch(request_digest) is None:
            raise CategoryExecutionError("stored category request digest is invalid")
        return {
            "task_id": task_id,
            "profile_id": source["profile_id"],
            "transaction_id": "category-assessment:" + request_digest.removeprefix(
                "sha256-jcs-v1:"
            ),
            "request_digest": request_digest,
            "assessment_digest": source["assessment_digest"],
            "assessment_object_digest": reference.source_ref,
            "repository_revision": view.repository_revision,
        }

    def current_body(self, task_id: str) -> tuple[dict[str, object], bytes] | None:
        snapshot = self.current_snapshot(task_id)
        if snapshot is None:
            return None
        object_digest = snapshot.get("assessment_object_digest")
        if type(object_digest) is not str:
            raise CategoryExecutionError("category current assessment reference is absent")
        get = getattr(self._objects, "get", None)
        if not callable(get):
            raise CategoryExecutionError("category assessment object resolver is unavailable")
        try:
            body = get(object_digest, require_referenced=True)
        except Exception as error:
            raise CategoryExecutionError("category current assessment object is unavailable") from error
        if type(body) is not bytes or category_object_digest(body) != object_digest:
            raise CategoryExecutionError("category current assessment object changed")
        return snapshot, body


@dataclass(frozen=True, slots=True)
class CategoryAssessmentReceipt:
    assessment: CategoryCompletionAssessment
    event: CategoryExecutionEvent
    state: CategoryExecutionState
    transaction_id: str
    repository_revision: int
    idempotent_replay: bool


@dataclass(frozen=True, slots=True, init=False, eq=False)
class CategoryFacts:
    """Opaque application-issued projection of current durable task facts."""

    candidate: FrozenMap
    column_evidence_digest: str
    column_evidence: FrozenMap
    task_snapshot_digest: str
    _authority: CategoryFactsAuthority

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("category facts are factory-issued")


@dataclass(frozen=True, slots=True, init=False, eq=False)
class CategorySourceRecord:
    """Opaque consumer-local attestation of one current durable column source."""

    body: FrozenMap
    source_digest: str
    _authority: CategoryFactsAuthority

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("category source records are factory-issued")


@dataclass(frozen=True, slots=True, init=False, eq=False)
class CategorySourceFenceRequest:
    """Opaque one-use source revalidation consumed at repository commit."""

    _authority: CategoryFactsAuthority
    _selector: FrozenMap
    _observer: object
    _issued: CategoryFacts
    _final: bool
    _source_seal: str
    _excluded_object_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("category source fence requests are factory-issued")


class CategoryFactsAuthority:
    """Build category facts only from exact task and referenced-object state."""

    _REQUEST_FIELDS = _CATEGORY_SELECTOR_FIELDS
    _EVIDENCE_FIELDS = frozenset({
        "schema_version", "record_kind", "task_id", "task_revision",
        "snapshot_digest", "invalidation_epoch", "profile_id", "column_id",
        "evidence_kind", "outcome", "facts", "record_digest",
    })

    def __init__(
        self,
        *,
        policy: CategoryExecutionPolicy,
        task_application: object,
        repository: object,
        objects: object,
        runtime: object,
    ) -> None:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository

        if (
            type(policy) is not CategoryExecutionPolicy
            or type(task_application) is not TaskApplication
            or type(repository) is not TaskRepository
            or task_application._repository is not repository
            or type(objects) is not ObjectRepository
            or task_application._materialization_objects is not objects
            or type(runtime) is not RuntimeContext
        ):
            raise CategoryExecutionError("category facts durable authority is invalid")
        runtime.require_issued()
        self._policy = policy
        self._task_application = task_application
        self._repository = repository
        self._objects = objects
        self._runtime = runtime
        self.__issued: dict[int, CategoryFacts] = {}
        self.__sources: dict[int, CategorySourceRecord] = {}
        self.__source_by_column: dict[str, CategorySourceRecord] = {}
        self.__source_task_id: str | None = None
        self.__source_fences: dict[int, CategorySourceFenceRequest] = {}
        self._rollback_bridge: CategoryRollbackBridge | None = None
        self._real_e2e_authority: object | None = None
        self.__binding_expected_rejection = False

    @staticmethod
    def _record(source: bytes, kind: str) -> dict[str, object] | None:
        try:
            value = _strict_json(source)
        except CategoryExecutionError:
            return None
        if value.get("record_kind") != kind:
            return None
        digest = value.get("record_digest")
        body = {key: item for key, item in value.items() if key != "record_digest"}
        if (
            type(digest) is not str
            or not hmac.compare_digest(digest, _internal_digest(body, kind))
        ):
            raise CategoryExecutionError(f"durable {kind} digest changed")
        return value

    def _records(self, task_id: str, kind: str) -> tuple[dict[str, object], ...]:
        try:
            references = self._repository.referenced_objects(task_id)
        except Exception as error:
            raise CategoryExecutionError("category durable object refs are unavailable") from error
        records = tuple(
            record
            for _object_digest, body in references
            if (record := self._record(body, kind)) is not None
        )
        return records

    def _bound_source(
        self,
        task_id: str,
        kind: str,
        fields: frozenset[str],
        bindings: Mapping[str, object],
    ) -> dict[str, object]:
        records = self._records(task_id, kind)
        if len(records) != 1:
            raise CategoryExecutionError(f"durable {kind} is missing or duplicated")
        record = records[0]
        if set(record) != fields or any(
            record.get(name) != expected for name, expected in bindings.items()
        ):
            raise CategoryExecutionError(f"durable {kind} is stale or foreign")
        return record

    def _expected_evidence_facts(
        self,
        *,
        task_id: str,
        profile_id: str,
        task_revision: int,
        snapshot_digest: str,
        invalidation_epoch: int,
        column: str,
        scenario: str,
        authority_refs: tuple[str, ...],
        required_outputs: Mapping[str, Mapping[str, object]],
        review: Mapping[str, object],
        previous_review: Mapping[str, object],
        artifact_records: tuple[dict[str, object], ...],
        target: Mapping[str, object],
        evidence_facts: Mapping[str, object],
    ) -> dict[str, object]:
        common_bindings = {
            "task_id": task_id,
            "profile_id": profile_id,
            "task_revision": task_revision,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": invalidation_epoch,
        }
        target_state = target.get("expected_state")
        if not isinstance(target_state, Mapping):
            raise CategoryExecutionError("durable target state is malformed")
        target_digest = _internal_digest(
            dict(target_state), "category-target-state"
        )
        if column == "normal":
            return {
                "runner-output-digest": _internal_digest(
                    {key: dict(value) for key, value in required_outputs.items()},
                    "category-runner-outputs",
                )
            }
        if column == "boundary":
            return {"scenario-id": scenario}
        if column == "revise":
            rule = self._policy.transition_rules[column]
            if not isinstance(rule, FrozenMap):
                raise CategoryExecutionError("revise evidence policy changed")
            owner_route = rule["owner_route"]
            fields = frozenset({
                "schema_version", "record_kind", *common_bindings,
                "budget_remaining", "current_body_digest",
                "previous_body_digest", "owner_route", "record_digest",
            })
            source = self._bound_source(
                task_id, "category-revision-record-v1", fields, common_bindings
            )
            limits = self._policy.materialization_output.get("budget_limits")
            remaining = source.get("budget_remaining")
            if (
                not isinstance(limits, FrozenMap)
                or type(remaining) is not int
                or remaining <= 0
                or not limits
                or remaining > max(int(item) for item in limits.values())
                or source.get("current_body_digest") != review.get("body_digest")
                or source.get("previous_body_digest")
                != previous_review.get("body_digest")
                or source.get("owner_route") != owner_route
            ):
                raise CategoryExecutionError("durable revision/budget source is invalid")
            return {
                "budget-remaining": remaining,
                "current-body-digest": source["current_body_digest"],
                "owner-route": owner_route,
                "previous-body-digest": source["previous_body_digest"],
            }
        if column == "authority":
            if not authority_refs:
                raise CategoryExecutionError("durable category authority is absent")
            return {
                "authority-ref": authority_refs[0],
                "authority-status": "current",
            }
        if column == "drift":
            fields = frozenset({
                "schema_version", "record_kind", *common_bindings,
                "target_id", "target_digest", "status", "record_digest",
            })
            source = self._bound_source(
                task_id, "category-drift-record-v1", fields, common_bindings
            )
            if (
                source.get("target_id") != target.get("target_id")
                or source.get("target_digest") != target_digest
                or source.get("status") != "resolved"
            ):
                raise CategoryExecutionError("durable drift source is unresolved")
            return {
                "drift-status": source["status"],
                "target-digest": source["target_digest"],
            }
        if column == "invalidation":
            return {
                "invalidation-epoch": invalidation_epoch,
                "invalidation-status": "current",
            }
        if column == "recovery":
            fields = frozenset({
                "schema_version", "record_kind", *common_bindings,
                "recovery_id", "status", "record_digest",
            })
            source = self._bound_source(
                task_id, "category-recovery-record-v1", fields, common_bindings
            )
            if (
                type(source.get("recovery_id")) is not str
                or not source["recovery_id"]
                or source.get("status") != "recovered"
            ):
                raise CategoryExecutionError("durable recovery source is incomplete")
            return {
                "recovery-id": source["recovery_id"],
                "recovery-status": source["status"],
            }
        if column == "artifacts":
            return {
                "artifact-record-digests": sorted(
                    _text(item.get("record_digest"), "ArtifactRecord digest")
                    for item in artifact_records
                )
            }
        if column == "review":
            return {
                "author-id": next(
                    item["author_id"] for item in required_outputs.values()
                    if item.get("node_id") == review.get("node_id")
                ),
                "review-record-digest": _internal_digest(
                    dict(review), "category-runner-review"
                ),
                "reviewer-id": review["reviewer_id"],
            }
        if column == "target":
            return {
                "expected-state-digest": target_digest,
                "target-id": target["target_id"],
            }
        if column == "rollback":
            return dict(evidence_facts)
        if column == "real-e2e":
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EAuthority,
                ProfileRealE2EError,
            )

            authority = self._real_e2e_authority
            if _require_real_category_authority(authority, self._policy.profile_id) is not authority:
                raise CategoryExecutionError(
                    "Profile real-E2E predecessor authority is absent"
                )
            try:
                record = authority.require_current(
                    expected_task_id=task_id,
                    require_success=not self.__binding_expected_rejection,
                )
                expected = authority.evidence_facts(record)
            except ValueError as error:
                raise CategoryExecutionError(str(error)) from error
            return expected
        raise CategoryExecutionError("category evidence column is unsupported")

    def issue(self, request: object, observer: object) -> CategoryFacts:
        self._policy.require_current()
        selector = _category_selector(request)
        request_id = str(selector["request_id"])
        task_id = str(selector["task_id"])
        column = str(selector["column_id"])
        scenario = str(selector["scenario_id"])
        target_id = str(selector["target_id"])
        if column not in self._policy.column_ids:
            raise CategoryExecutionError("category column is not installed")
        if column == "real-e2e":
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EError,
                ProfileRealE2EObserver,
            )

            try:
                authority = _require_real_category_observer(observer, self._policy.profile_id)
            except ValueError as error:
                raise CategoryExecutionError(
                    "Profile real-E2E observer authority is absent"
                ) from error
            if (
                self._real_e2e_authority is not None
                and self._real_e2e_authority is not authority
            ):
                raise CategoryExecutionError(
                    "Profile real-E2E observer authority changed"
                )
            self._real_e2e_authority = authority
        try:
            view = self._task_application.runtime_show(task_id, self._runtime)
        except Exception as error:
            raise CategoryExecutionError("current TaskSnapshot is unavailable") from error
        snapshot = view.snapshot
        if snapshot.lifecycle != "completing" or not snapshot.graph_ref:
            raise CategoryExecutionError("category facts require a completing materialized task")
        graph_ref = snapshot.graph_ref
        if freeze(graph_ref) != self._policy.materialization_graph_ref:
            raise CategoryExecutionError("current TaskSnapshot GraphRef changed")
        if tuple(snapshot.authorities) != self._policy.authority_refs:
            raise CategoryExecutionError("current owner authority changed")
        if snapshot.open_findings or snapshot.unresolved_action_claims:
            raise CategoryExecutionError("current task has unresolved completion state")

        runner = view.runner_state
        outputs = runner.get("node_outputs") if isinstance(runner, Mapping) else None
        reviews = runner.get("review_history") if isinstance(runner, Mapping) else None
        if not isinstance(outputs, Mapping) or type(reviews) is not list:
            raise CategoryExecutionError("durable runner records are unavailable")
        required_outputs: dict[str, Mapping[str, object]] = {}
        for node_id in self._policy.required_node_ids:
            output = outputs.get(node_id)
            if (
                not isinstance(output, Mapping)
                or output.get("node_id") != node_id
                or output.get("trust") != "independently_reviewed"
                or output.get("verdict") != "PASS"
                or type(output.get("body_digest")) is not str
                or type(output.get("author_id")) is not str
                or type(output.get("reviewer_id")) is not str
                or str(output["author_id"]).casefold()
                == str(output["reviewer_id"]).casefold()
            ):
                raise CategoryExecutionError("durable runner output is incomplete")
            required_outputs[node_id] = output
        review = next((
            item for item in reversed(reviews)
            if isinstance(item, Mapping)
            and item.get("verdict") == "PASS"
            and type(item.get("reviewer_id")) is str
            and type(item.get("body_digest")) is str
        ), None)
        previous = next((
            item for item in reversed(reviews[:-1])
            if isinstance(item, Mapping)
            and type(item.get("body_digest")) is str
            and item.get("body_digest") != review.get("body_digest")
        ), None) if isinstance(review, Mapping) else None
        if not isinstance(review, Mapping) or not isinstance(previous, Mapping):
            raise CategoryExecutionError("current independent review lineage is absent")
        reviewed_output = next((
            item for item in required_outputs.values()
            if item.get("node_id") == review.get("node_id")
            and item.get("body_digest") == review.get("body_digest")
            and item.get("reviewer_id") == review.get("reviewer_id")
        ), None)
        if reviewed_output is None:
            raise CategoryExecutionError("independent review is not bound to current runner output")

        artifact_records = self._records(task_id, "category-artifact-record-v1")
        artifact_ids = tuple(sorted(
            _text(item.get("contract_id"), "ArtifactRecord contract ID")
            for item in artifact_records
        ))
        if artifact_ids != tuple(sorted(self._policy.artifact_contract_ids)):
            raise CategoryExecutionError("ObjectRepository ArtifactRecord closure changed")
        if any(
            item.get("task_id") != task_id
            or item.get("status") != "accepted-for-category"
            or item.get("author_id") == item.get("reviewer_id")
            for item in artifact_records
        ):
            raise CategoryExecutionError("ObjectRepository ArtifactRecord is stale or forged")

        targets = self._records(task_id, "category-target-contract-v1")
        if len(targets) != 1:
            raise CategoryExecutionError("category target contract is missing or duplicated")
        target = targets[0]
        if (
            target.get("task_id") != task_id
            or target.get("profile_id") != self._policy.profile_id
            or target.get("target_id") != target_id
            or type(target.get("resource_id")) is not str
        ):
            raise CategoryExecutionError("category target contract is foreign")
        expected_state_key = "rollback_state" if column == "rollback" else "expected_state"
        expected_state = target.get(expected_state_key)
        if not isinstance(expected_state, Mapping):
            raise CategoryExecutionError("category target state contract is malformed")

        evidence_records = tuple(
            item for item in self._records(task_id, "category-column-evidence-v1")
            if item.get("column_id") == column
        )
        if len(evidence_records) != 1:
            raise CategoryExecutionError("typed column evidence is missing or duplicated")
        evidence = evidence_records[0]
        rule = self._policy.transition_rules[column]
        if not isinstance(rule, FrozenMap):
            raise CategoryExecutionError("category evidence policy changed")
        if (
            set(evidence) != self._EVIDENCE_FIELDS
            or evidence.get("schema_version") != "1.0.0"
            or evidence.get("task_id") != task_id
            or evidence.get("task_revision") != snapshot.task_revision
            or evidence.get("snapshot_digest") != snapshot.snapshot_digest
            or evidence.get("invalidation_epoch") != snapshot.invalidation_epoch
            or evidence.get("profile_id") != self._policy.profile_id
            or evidence.get("evidence_kind") != rule["evidence_kind"]
            or evidence.get("outcome") != rule["required_outcome"]
        ):
            raise CategoryExecutionError("typed column evidence is stale or wrong")
        facts = evidence.get("facts")
        if type(facts) is not dict or tuple(sorted(facts)) != tuple(
            rule["required_fact_ids"]
        ):
            raise CategoryExecutionError("typed column evidence fact closure changed")
        expected_facts = self._expected_evidence_facts(
            task_id=task_id,
            profile_id=self._policy.profile_id,
            task_revision=snapshot.task_revision,
            snapshot_digest=snapshot.snapshot_digest,
            invalidation_epoch=snapshot.invalidation_epoch,
            column=column,
            scenario=scenario,
            authority_refs=tuple(snapshot.authorities),
            required_outputs=required_outputs,
            review=review,
            previous_review=previous,
            artifact_records=artifact_records,
            target=target,
            evidence_facts=facts,
        )
        if freeze(facts) != freeze(expected_facts):
            raise CategoryExecutionError(
                "typed column evidence does not match authoritative durable facts: "
                + column
            )

        pins = {
            "base_graph_digest": graph_ref["graph_digest"],
            "profile_digest": graph_ref["profile_digest"],
            "overlay_digest": graph_ref["overlay_digest"],
            "project_config_digest": graph_ref["project_config_digest"],
            "support_matrix_digest": graph_ref["support_matrix_digest"],
            "materialization_digest": graph_ref["materialization_digest"],
        }
        candidate = {
            "schema_version": "1.0.0",
            "request_id": request_id,
            "task_id": task_id,
            "task_revision": snapshot.task_revision,
            "snapshot_digest": snapshot.snapshot_digest,
            "invalidation_epoch": snapshot.invalidation_epoch,
            "profile_id": self._policy.profile_id,
            "profile_version": self._policy.profile_version,
            "profile_digest": self._policy.profile_digest,
            "overlay_id": graph_ref["overlay_id"],
            "materialization_digest": graph_ref["materialization_digest"],
            "digest_pins": pins,
            "column_id": column,
            "scenario_id": scenario,
            "execution_kind": getattr(observer, "execution_kind", None),
            "authority_refs": list(snapshot.authorities),
            "required_node_ids": list(self._policy.required_node_ids),
            "passed_node_ids": list(self._policy.required_node_ids),
            "required_artifact_contract_ids": list(self._policy.artifact_contract_ids),
            "current_artifact_contract_ids": list(artifact_ids),
            "required_validator_ids": list(self._policy.validator_ids),
            "passed_validator_ids": list(self._policy.validator_ids),
            "required_completion_predicate_ids": list(
                self._policy.completion_predicate_ids
            ),
            "passed_completion_predicate_ids": list(
                self._policy.completion_predicate_ids
            ),
            "runner_outputs": thaw(self._policy.materialization_output),
            "review": {
                "author_id": reviewed_output["author_id"],
                "reviewer_id": review["reviewer_id"],
                "trust": "independently-reviewed",
                "verdict": "PASS",
                "body_digest": review["body_digest"],
                "previous_body_digest": previous["body_digest"],
            },
            "target": {
                "target_id": target_id,
                "resource_id": target["resource_id"],
                "expected_state": dict(expected_state),
            },
            "rollback": {
                "logical_action_kind": self._policy.rollback_contract[
                    "eligible_action_kinds"
                ][0],
                "action_protocol_kind": "rollback",
                "authority_requirement": self._policy.rollback_contract[
                    "authority_requirement"
                ],
                "compensation_graph_ref": self._policy.rollback_contract[
                    "compensation_graph_ref"
                ],
                "precondition_ids": list(
                    self._policy.rollback_contract["precondition_ids"]
                ),
                "verification_ids": list(
                    self._policy.rollback_contract["verification_ids"]
                ),
            },
            "unresolved_refs": [],
        }
        approved = self._policy.require_candidate(candidate)
        result = object.__new__(CategoryFacts)
        frozen = freeze(approved)
        if not isinstance(frozen, FrozenMap):
            raise CategoryExecutionError("category facts did not freeze")
        object.__setattr__(result, "candidate", frozen)
        object.__setattr__(result, "column_evidence_digest", evidence["record_digest"])
        frozen_evidence = freeze(evidence)
        if not isinstance(frozen_evidence, FrozenMap):
            raise CategoryExecutionError("category evidence did not freeze")
        object.__setattr__(result, "column_evidence", frozen_evidence)
        object.__setattr__(result, "task_snapshot_digest", snapshot.snapshot_digest)
        object.__setattr__(result, "_authority", self)
        self.__issued[id(result)] = result
        return result

    def require_issued(self, facts: CategoryFacts) -> Mapping[str, object]:
        if (
            type(facts) is not CategoryFacts
            or facts._authority is not self
            or self.__issued.get(id(facts)) is not facts
        ):
            raise CategoryExecutionError("category facts are cloned or foreign")
        candidate = thaw(facts.candidate)
        return self._policy.require_candidate(candidate)

    def _coverage_task_identity(self) -> str:
        """Return the already-bound task identity for a consumer-local coverage use."""

        self._policy.require_current()
        if type(self.__source_task_id) is not str:
            raise CategoryExecutionError(
                "category source task identity is unavailable"
            )
        return self.__source_task_id

    def bind_current_sources(
        self,
        task_id: str,
        observer: object,
        rollback_bridge: CategoryRollbackBridge,
    ) -> None:
        """Pin all current durable column projections before caller-visible use."""

        task_id = _text(task_id, "category source task ID")
        if self.__source_task_id is not None:
            raise CategoryExecutionError("category source registry is already bound")
        if type(rollback_bridge) is not CategoryRollbackBridge:
            raise CategoryExecutionError("category source rollback authority is invalid")
        default_scenario = next(
            item for item in self._policy.category_boundary_case_ids
            if item.endswith("-P")
        )
        target_id = self.current_target_id(task_id)
        staged: dict[str, CategorySourceRecord] = {}
        real_observer = False
        try:
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EError,
                ProfileRealE2EObserver,
            )

            _require_real_category_observer(observer, self._policy.profile_id)
            real_observer = True
        except ValueError:
            pass
        for column in self._policy.column_ids:
            if real_observer and column != "real-e2e":
                continue
            if column == "real-e2e":
                from graph_engineering.application.profile_real_e2e import (
                    ProfileRealE2EError,
                    ProfileRealE2EObserver,
                )

                try:
                    authority = _require_real_category_observer(observer, self._policy.profile_id)
                except ValueError:
                    continue
                self._real_e2e_authority = authority
            scenario = default_scenario
            if column == "boundary":
                boundary_records = tuple(
                    item for item in self._records(
                        task_id, "category-column-evidence-v1"
                    )
                    if item.get("column_id") == column
                )
                if len(boundary_records) != 1:
                    raise CategoryExecutionError(
                        "category boundary source evidence is not unique"
                    )
                boundary_facts = boundary_records[0].get("facts")
                if not isinstance(boundary_facts, Mapping):
                    raise CategoryExecutionError(
                        "category boundary source facts are malformed"
                    )
                scenario = _text(
                    boundary_facts.get("scenario-id"),
                    "category boundary source scenario",
                )
                if scenario not in self._policy.category_boundary_case_ids:
                    raise CategoryExecutionError(
                        "category boundary source scenario is not approved"
                    )
            self.__binding_expected_rejection = (
                column == "real-e2e"
                and getattr(self._real_e2e_authority, "disposition", None) == "R"
            )
            try:
                issued = self.issue({
                    "schema_version": "1.0.0",
                    "request_id": f"category-source:{task_id}:{column}",
                    "task_id": task_id,
                    "column_id": column,
                    "scenario_id": scenario,
                    "target_id": target_id,
                }, observer)
            finally:
                self.__binding_expected_rejection = False
            candidate = self.require_issued(issued)
            evidence = thaw(issued.column_evidence)
            facts = evidence.get("facts") if type(evidence) is dict else None
            rule = self._policy.transition_rules[column]
            if type(facts) is not dict or not isinstance(rule, FrozenMap):
                raise CategoryExecutionError("category source projection is malformed")
            if column == "rollback":
                rollback_bridge.require_evidence_facts(facts, final=False)
            body = {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "task_revision": candidate["task_revision"],
                "snapshot_digest": candidate["snapshot_digest"],
                "invalidation_epoch": candidate["invalidation_epoch"],
                "profile_id": candidate["profile_id"],
                "column_id": column,
                "outcome": rule["required_outcome"],
                "facts": facts,
                "evidence_record_digest": evidence["record_digest"],
            }
            frozen = freeze(body)
            if not isinstance(frozen, FrozenMap):
                raise CategoryExecutionError("category source projection did not freeze")
            record = object.__new__(CategorySourceRecord)
            object.__setattr__(record, "body", frozen)
            object.__setattr__(
                record,
                "source_digest",
                _internal_digest(body, "category-source-record"),
            )
            object.__setattr__(record, "_authority", self)
            self.__sources[id(record)] = record
            staged[column] = record
        self.__source_task_id = task_id
        self.__source_by_column = staged
        self._rollback_bridge = rollback_bridge

    def require_source_current(
        self,
        issued: CategoryFacts,
        *,
        final: bool,
        installation_only: bool = False,
    ) -> None:
        candidate = self.require_issued(issued)
        column = str(candidate["column_id"])
        record = self.__source_by_column.get(column)
        if (
            self.__source_task_id != candidate["task_id"]
            or type(record) is not CategorySourceRecord
            or record._authority is not self
            or self.__sources.get(id(record)) is not record
        ):
            raise CategoryExecutionError("category source registry is missing or foreign")
        evidence = thaw(issued.column_evidence)
        if type(evidence) is not dict or type(evidence.get("facts")) is not dict:
            raise CategoryExecutionError("category source evidence is malformed")
        body = thaw(record.body)
        expected = {
            "schema_version": "1.0.0",
            "task_id": candidate["task_id"],
            "task_revision": candidate["task_revision"],
            "snapshot_digest": candidate["snapshot_digest"],
            "invalidation_epoch": candidate["invalidation_epoch"],
            "profile_id": candidate["profile_id"],
            "column_id": column,
            "outcome": evidence["outcome"],
            "facts": evidence["facts"],
            "evidence_record_digest": evidence["record_digest"],
        }
        if (
            body != expected
            or not hmac.compare_digest(
                record.source_digest,
                _internal_digest(body, "category-source-record"),
            )
        ):
            raise CategoryExecutionError("category durable source changed after issuance")
        if column == "rollback":
            if self._rollback_bridge is None:
                raise CategoryExecutionError("category rollback source authority is absent")
            self._rollback_bridge.require_evidence_facts(
                evidence["facts"], final=final
            )
        if column == "real-e2e":
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EAuthority,
                ProfileRealE2EError,
            )

            authority = self._real_e2e_authority
            if _require_real_category_authority(authority, self._policy.profile_id) is not authority:
                raise CategoryExecutionError(
                    "Profile real-E2E current authority is absent"
                )
            try:
                if installation_only:
                    authority.require_installation_current()
                else:
                    authority.require_current(
                        expected_task_id=str(candidate["task_id"]),
                        require_success=authority.disposition == "P",
                    )
            except ValueError as error:
                raise CategoryExecutionError(str(error)) from error

    def issue_source_fence(
        self,
        issued: CategoryFacts,
        observer: object,
        *,
        final: bool,
        excluded_object_digest: str,
    ) -> CategorySourceFenceRequest:
        """Issue a one-use proof for transaction-local final source revalidation."""

        candidate = self.require_issued(issued)
        self.require_source_current(issued, final=final)
        selector = freeze(_selector_from_candidate(candidate))
        if not isinstance(selector, FrozenMap):
            raise CategoryExecutionError("category source selector did not freeze")
        request = object.__new__(CategorySourceFenceRequest)
        try:
            source_seal = self._repository.category_source_seal(
                str(candidate["task_id"]),
                excluded_object_digest,
            )
        except Exception as error:
            raise CategoryExecutionError(
                "category source seal is unavailable"
            ) from error
        for name, value in (
            ("_authority", self),
            ("_selector", selector),
            ("_observer", observer),
            ("_issued", issued),
            ("_final", final),
            ("_source_seal", source_seal),
            ("_excluded_object_digest", excluded_object_digest),
        ):
            object.__setattr__(request, name, value)
        self.__source_fences[id(request)] = request
        return request

    def consume_source_fence_locked(
        self,
        request: CategorySourceFenceRequest,
        repository: object,
        connection: object,
        snapshot: object,
    ) -> None:
        """Re-read every bound source immediately before durable commit."""

        if (
            type(request) is not CategorySourceFenceRequest
            or request._authority is not self
            or self.__source_fences.pop(id(request), None) is not request
            or repository is not self._repository
        ):
            raise CategoryExecutionError(
                "category source fence is forged or already consumed"
            )
        original = self.require_issued(request._issued)
        selector = thaw(request._selector)
        if selector.get("task_id") != original.get("task_id"):
            raise CategoryExecutionError("category source fence task changed")
        self.require_source_current(
            request._issued,
            final=request._final,
            installation_only=True,
        )
        try:
            current_seal = self._repository._category_source_seal_locked(
                connection,
                str(original["task_id"]),
                snapshot,
                request._excluded_object_digest,
            )
        except Exception as error:
            raise CategoryExecutionError(
                "category source seal could not be revalidated"
            ) from error
        if (
            not hmac.compare_digest(current_seal, request._source_seal)
        ):
            raise CategoryExecutionError(
                "category durable source changed at the final transaction fence"
            )

    def reissue_sources(
        self,
        previous: CategoryFactsAuthority,
        rollback_bridge: CategoryRollbackBridge,
        observer: object,
    ) -> None:
        """Reissue exact prior source pins under this restart-local consumer."""

        if (
            type(previous) is not CategoryFactsAuthority
            or previous._policy is not self._policy
            or previous.__source_task_id is None
            or self.__source_task_id is not None
            or type(rollback_bridge) is not CategoryRollbackBridge
        ):
            raise CategoryExecutionError("category source restart authority is invalid")
        staged: dict[str, CategorySourceRecord] = {}
        for column, prior in previous.__source_by_column.items():
            if (
                type(prior) is not CategorySourceRecord
                or prior._authority is not previous
                or previous.__sources.get(id(prior)) is not prior
            ):
                raise CategoryExecutionError("category source restart pin is foreign")
            body = thaw(prior.body)
            if not hmac.compare_digest(
                prior.source_digest,
                _internal_digest(body, "category-source-record"),
            ):
                raise CategoryExecutionError("category source restart pin changed")
            frozen = freeze(body)
            if not isinstance(frozen, FrozenMap):
                raise CategoryExecutionError("category source restart body did not freeze")
            record = object.__new__(CategorySourceRecord)
            object.__setattr__(record, "body", frozen)
            object.__setattr__(record, "source_digest", prior.source_digest)
            object.__setattr__(record, "_authority", self)
            self.__sources[id(record)] = record
            staged[column] = record
        self.__source_task_id = previous.__source_task_id
        self.__source_by_column = staged
        self._rollback_bridge = rollback_bridge
        if "real-e2e" in staged:
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EError,
                ProfileRealE2EObserver,
            )

            try:
                self._real_e2e_authority = _require_real_category_observer(observer, self._policy.profile_id)
            except ValueError as error:
                raise CategoryExecutionError(
                    "Profile real-E2E restart observer is foreign"
                ) from error

    def require_assessment_source_current(
        self,
        assessment: CategoryCompletionAssessment,
        evidence: Mapping[str, object],
    ) -> None:
        record = self.__source_by_column.get(assessment.column_id)
        if (
            self.__source_task_id != assessment.task_id
            or type(record) is not CategorySourceRecord
            or record._authority is not self
            or self.__sources.get(id(record)) is not record
        ):
            raise CategoryExecutionError("current assessment source pin is absent")
        body = thaw(record.body)
        if (
            body.get("task_id") != assessment.task_id
            or body.get("task_revision") != assessment.task_revision
            or body.get("snapshot_digest") != assessment.snapshot_digest
            or body.get("invalidation_epoch") != assessment.invalidation_epoch
            or body.get("profile_id") != assessment.profile_id
            or body.get("column_id") != assessment.column_id
            or body.get("outcome") != evidence.get("outcome")
            or freeze(body.get("facts")) != freeze(evidence.get("facts"))
            or body.get("evidence_record_digest")
            != assessment.column_evidence_digest
            or not hmac.compare_digest(
                record.source_digest,
                _internal_digest(body, "category-source-record"),
            )
        ):
            raise CategoryExecutionError("current assessment source pin changed")
        if assessment.column_id == "real-e2e":
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EAuthority,
                ProfileRealE2EError,
            )

            authority = self._real_e2e_authority
            if _require_real_category_authority(authority, self._policy.profile_id) is not authority:
                raise CategoryExecutionError(
                    "Profile real-E2E assessment authority is absent"
                )
            try:
                authority.require_current(
                    expected_task_id=assessment.task_id,
                    require_success=True,
                )
            except ValueError as error:
                raise CategoryExecutionError(str(error)) from error

    def current_target_id(self, task_id: str) -> str:
        records = self._records(task_id, "category-target-contract-v1")
        if len(records) != 1:
            raise CategoryExecutionError("current category target is not unique")
        return _text(records[0].get("target_id"), "current category target ID")

    def require_assessment_evidence(
        self, assessment: CategoryCompletionAssessment
    ) -> dict[str, object]:
        """Re-resolve the exact typed evidence and all authoritative sources."""

        records = tuple(
            item for item in self._records(
                assessment.task_id, "category-column-evidence-v1"
            )
            if item.get("column_id") == assessment.column_id
        )
        if len(records) != 1:
            raise CategoryExecutionError("current typed column evidence is not unique")
        evidence = records[0]
        body = {key: value for key, value in evidence.items() if key != "record_digest"}
        if (
            set(evidence) != self._EVIDENCE_FIELDS
            or evidence.get("schema_version") != "1.0.0"
            or evidence.get("record_kind") != "category-column-evidence-v1"
            or evidence.get("task_id") != assessment.task_id
            or evidence.get("task_revision") != assessment.task_revision
            or evidence.get("snapshot_digest") != assessment.snapshot_digest
            or evidence.get("invalidation_epoch") != assessment.invalidation_epoch
            or evidence.get("profile_id") != assessment.profile_id
            or evidence.get("column_id") != assessment.column_id
            or evidence.get("record_digest") != assessment.column_evidence_digest
            or not hmac.compare_digest(
                str(evidence.get("record_digest")),
                _internal_digest(body, "category-column-evidence-v1"),
            )
        ):
            raise CategoryExecutionError("current typed column evidence binding changed")
        rule = self._policy.transition_rules[assessment.column_id]
        facts = evidence.get("facts")
        if (
            not isinstance(rule, FrozenMap)
            or evidence.get("evidence_kind") != rule["evidence_kind"]
            or evidence.get("outcome") != rule["required_outcome"]
            or type(facts) is not dict
            or tuple(sorted(facts)) != tuple(rule["required_fact_ids"])
        ):
            raise CategoryExecutionError("current typed column evidence semantics changed")
        try:
            view = self._task_application.runtime_show(
                assessment.task_id, self._runtime
            )
        except Exception as error:
            raise CategoryExecutionError("current completed TaskSnapshot is unavailable") from error
        snapshot = view.snapshot
        if (
            snapshot.lifecycle != "completed"
            or snapshot.task_revision != assessment.task_revision + 1
            or snapshot.invalidation_epoch != assessment.invalidation_epoch
            or freeze(snapshot.graph_ref) != self._policy.materialization_graph_ref
        ):
            raise CategoryExecutionError("completed TaskSnapshot evidence binding changed")
        runner = view.runner_state
        outputs = runner.get("node_outputs") if isinstance(runner, Mapping) else None
        reviews = runner.get("review_history") if isinstance(runner, Mapping) else None
        if not isinstance(outputs, Mapping) or type(reviews) is not list:
            raise CategoryExecutionError("completed runner evidence is unavailable")
        required_outputs: dict[str, Mapping[str, object]] = {}
        for node_id in self._policy.required_node_ids:
            output = outputs.get(node_id)
            if not isinstance(output, Mapping):
                raise CategoryExecutionError("completed runner output is missing")
            required_outputs[node_id] = output
        review = next((
            item for item in reversed(reviews)
            if isinstance(item, Mapping)
            and item.get("verdict") == "PASS"
            and type(item.get("body_digest")) is str
        ), None)
        previous = next((
            item for item in reversed(reviews[:-1])
            if isinstance(item, Mapping)
            and type(item.get("body_digest")) is str
            and isinstance(review, Mapping)
            and item.get("body_digest") != review.get("body_digest")
        ), None)
        if not isinstance(review, Mapping) or not isinstance(previous, Mapping):
            raise CategoryExecutionError("completed review lineage is unavailable")
        artifacts = self._records(assessment.task_id, "category-artifact-record-v1")
        targets = self._records(assessment.task_id, "category-target-contract-v1")
        if len(targets) != 1:
            raise CategoryExecutionError("completed target contract is not unique")
        expected = self._expected_evidence_facts(
            task_id=assessment.task_id,
            profile_id=assessment.profile_id,
            task_revision=assessment.task_revision,
            snapshot_digest=assessment.snapshot_digest,
            invalidation_epoch=assessment.invalidation_epoch,
            column=assessment.column_id,
            scenario=assessment.scenario_id,
            authority_refs=assessment.authority_refs,
            required_outputs=required_outputs,
            review=review,
            previous_review=previous,
            artifact_records=artifacts,
            target=targets[0],
            evidence_facts=facts,
        )
        if freeze(facts) != freeze(expected):
            raise CategoryExecutionError("current evidence no longer matches durable facts")
        return evidence


class CategoryExecutionApplication:
    """Transactional category assessment command over durable repository ports."""

    def __init__(
        self,
        *,
        repository: object,
        object_repository: object,
        policy: CategoryExecutionPolicy,
        reducer: CategoryExecutionReducer,
        completion_oracle: CategoryCompletionOracle,
        rollback_bridge: CategoryRollbackBridge,
        assessment_resolver: CategoryAssessmentResolver,
        fault_hook: Callable[[str], None] = lambda _step: None,
        task_application: object,
        runtime: object,
        target_observer: object,
    ) -> None:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository

        real_e2e_observer = False
        try:
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EObserver,
            )

            _require_real_category_observer(target_observer, policy.profile_id)
            real_e2e_observer = True
        except (ImportError, ValueError):
            pass

        if (
            type(repository) is not TaskRepository
            or type(object_repository) is not ObjectRepository
            or type(policy) is not CategoryExecutionPolicy
            or type(reducer) is not CategoryExecutionReducer
            or reducer._policy is not policy
            or type(completion_oracle) is not CategoryCompletionOracle
            or completion_oracle._policy is not policy
            or type(rollback_bridge) is not CategoryRollbackBridge
            or rollback_bridge._policy is not policy
            or type(assessment_resolver) is not CategoryAssessmentResolver
            or assessment_resolver._repository is not repository
            or assessment_resolver._objects is not object_repository
            or assessment_resolver._task_application is not task_application
            or assessment_resolver._runtime is not runtime
            or not callable(fault_hook)
            or type(task_application) is not TaskApplication
            or task_application._repository is not repository
            or task_application._materialization_objects is not object_repository
            or type(runtime) is not RuntimeContext
            or getattr(target_observer, "is_read_only_observer", None) is not True
            or (
                getattr(target_observer, "is_test_double", None) is not True
                and not real_e2e_observer
            )
        ):
            raise CategoryExecutionError("category execution application authority is invalid")
        policy.require_current()
        self._repository = repository
        self._objects = object_repository
        self._policy = policy
        self._reducer = reducer
        self._oracle = completion_oracle
        self._rollback = rollback_bridge
        rollback_bridge._bind_task_resolution(task_application, runtime)
        self._resolver = assessment_resolver
        self._fault = fault_hook
        self._task_application = task_application
        self._runtime = runtime
        self._target_observer = target_observer
        self._facts = CategoryFactsAuthority(
            policy=policy,
            task_application=task_application,
            repository=repository,
            objects=object_repository,
            runtime=runtime,
        )

    def bind_current_sources(self, task_id: str) -> None:
        """Issue the consumer-local source registry from current durable facts."""

        self._facts.bind_current_sources(
            task_id,
            self._target_observer,
            self._rollback,
        )

    @staticmethod
    def _transaction_id(candidate: Mapping[str, object]) -> str:
        digest = _selector_digest(_selector_from_candidate(candidate))
        return "category-assessment:" + digest.removeprefix("sha256-jcs-v1:")

    def _authoritative_candidate(
        self, request: object, observer: object
    ) -> tuple[CategoryFacts, Mapping[str, object]]:
        if observer is not self._target_observer:
            raise CategoryExecutionError("target observer capability is foreign")
        facts = self._facts.issue(request, observer)
        return facts, self._facts.require_issued(facts)

    def _require_column_evidence(
        self,
        candidate: Mapping[str, object],
        issued: CategoryFacts,
        *,
        final: bool = False,
    ) -> str:
        self._facts.require_issued(issued)
        evidence = thaw(issued.column_evidence)
        if (
            type(evidence) is not dict
            or set(evidence) != CategoryFactsAuthority._EVIDENCE_FIELDS
        ):
            raise CategoryExecutionError("durable category evidence is not exact")
        rule = self._policy.transition_rules[str(candidate["column_id"])]
        if not isinstance(rule, FrozenMap):
            raise CategoryExecutionError("category evidence policy changed")
        if (
            evidence["schema_version"] != "1.0.0"
            or evidence["record_kind"] != "category-column-evidence-v1"
            or evidence["task_id"] != candidate["task_id"]
            or evidence["task_revision"] != candidate["task_revision"]
            or evidence["snapshot_digest"] != candidate["snapshot_digest"]
            or evidence["invalidation_epoch"] != candidate["invalidation_epoch"]
            or evidence["profile_id"] != candidate["profile_id"]
            or evidence["column_id"] != candidate["column_id"]
            or evidence["evidence_kind"] != rule["evidence_kind"]
            or evidence["outcome"] != rule["required_outcome"]
        ):
            raise CategoryExecutionError("durable category evidence is stale or wrong")
        facts = evidence["facts"]
        if type(facts) is not dict or tuple(sorted(facts)) != tuple(
            rule["required_fact_ids"]
        ):
            raise CategoryExecutionError("category evidence fact closure changed")
        if candidate["column_id"] == "rollback":
            self._rollback.require_evidence_facts(facts, final=final)
        record_digest = _text(
            evidence["record_digest"], "category evidence record digest"
        )
        body = {key: value for key, value in evidence.items() if key != "record_digest"}
        if (
            SEMANTIC_DIGEST.fullmatch(record_digest) is None
            or not hmac.compare_digest(
                record_digest,
                _internal_digest(body, "category-column-evidence-v1"),
            )
        ):
            raise CategoryExecutionError("category evidence record digest is invalid")
        return record_digest

    def _restore_current(
        self,
        task_id: str,
        *,
        expected_profile_id: str,
    ) -> tuple[dict[str, object], CategoryCompletionAssessment] | None:
        resolved = self._resolver.current_body(task_id)
        if resolved is None:
            return None
        snapshot, body = resolved
        assessment = self._oracle.restore(body)
        current = self._task_application.runtime_show(task_id, self._runtime).snapshot
        expected_reference = {
            "evidence_id": assessment.assessment_digest,
            "evidence_type": "category-completion-assessment",
            "source_ref": assessment.object_digest,
            "digest": assessment.assessment_digest,
            "trust": "factory-attested",
        }
        references = [item.to_dict() for item in current.evidence]
        selector = {
            "schema_version": "1.0.0",
            "request_id": assessment.request_id,
            "task_id": assessment.task_id,
            "column_id": assessment.column_id,
            "scenario_id": assessment.scenario_id,
            "target_id": self._facts.current_target_id(task_id),
        }
        if (
            assessment.task_id != task_id
            or assessment.profile_id != expected_profile_id
            or snapshot.get("assessment_digest") != assessment.assessment_digest
            or snapshot.get("assessment_object_digest") != assessment.object_digest
            or snapshot.get("request_digest") != assessment.request_digest
            or not hmac.compare_digest(
                assessment.request_digest,
                _selector_digest(selector),
            )
            or current.lifecycle != "completed"
            or current.task_revision != assessment.task_revision + 1
            or current.invalidation_epoch != assessment.invalidation_epoch
            or freeze(current.graph_ref) != self._policy.materialization_graph_ref
            or references.count(expected_reference) != 1
        ):
            raise CategoryExecutionError("current category assessment binding changed")
        evidence = self._facts.require_assessment_evidence(assessment)
        self._facts.require_assessment_source_current(assessment, evidence)
        facts = evidence.get("facts")
        if assessment.column_id == "rollback":
            if not isinstance(facts, Mapping):
                raise CategoryExecutionError("current rollback facts are malformed")
            self._rollback.require_evidence_facts(facts, final=True)
        return snapshot, assessment

    def current_assessment(
        self,
        task_id: str,
        *,
        expected_profile_id: str,
    ) -> CategoryCompletionAssessment | None:
        task_id = _text(task_id, "category task ID")
        expected_profile_id = _text(expected_profile_id, "expected category Profile ID")
        resolved = self._restore_current(
            task_id,
            expected_profile_id=expected_profile_id,
        )
        return None if resolved is None else resolved[1]

    def assess_and_commit(
        self,
        candidate: object,
        *,
        observer: object,
        performance_evidence: object | None = None,
        migration_rehearsal_evidence: object | None = None,
        dependency_graph_evidence: object | None = None,
        scenario_truth_evidence: object | None = None,
        release_operations_evidence: object | None = None,
    ) -> CategoryAssessmentReceipt:
        selector = _category_selector(candidate)
        if observer is not self._target_observer:
            raise CategoryExecutionError("target observer capability is foreign")
        task_id = str(selector["task_id"])
        existing_current = self._resolver.current_snapshot(task_id)
        if existing_current is not None:
            restored = self._restore_current(
                task_id,
                expected_profile_id=self._policy.profile_id,
            )
            if restored is None:
                raise CategoryExecutionError("idempotent category assessment disappeared")
            snapshot, assessment = restored
            if any((
                selector["request_id"] != assessment.request_id,
                selector["column_id"] != assessment.column_id,
                selector["scenario_id"] != assessment.scenario_id,
                selector["target_id"] != self._facts.current_target_id(task_id),
                not hmac.compare_digest(
                    assessment.request_digest,
                    _selector_digest(selector),
                ),
            )):
                raise CategoryExecutionError("idempotency key was reused for another request")
            event = self._event_from_snapshot(snapshot)
            state = self._state_from_snapshot(snapshot)
            return CategoryAssessmentReceipt(
                assessment, event, state,
                str(snapshot["transaction_id"]),
                int(snapshot["repository_revision"]), True,
            )
        issued, value = self._authoritative_candidate(selector, observer)
        self._facts.require_source_current(issued, final=False)
        self._require_current_task(value)
        column_evidence_digest = self._require_column_evidence(value, issued)
        transaction_id = self._transaction_id(value)
        state = self._reducer.initial(value)
        target_authority = self._oracle._target_authority
        observation = target_authority.observe(value, observer)
        rollback_assessment, observation = self._rollback.assess(
            value,
            observation,
            target_authority,
        )
        assessment = self._oracle.assess(
            value,
            observation=observation,
            rollback_assessment=rollback_assessment,
            rollback_bridge=self._rollback,
            column_evidence_digest=column_evidence_digest,
            state=state,
            reducer=self._reducer,
            performance_evidence=performance_evidence,
            migration_rehearsal_evidence=migration_rehearsal_evidence,
            dependency_graph_evidence=dependency_graph_evidence,
            scenario_truth_evidence=scenario_truth_evidence,
            release_operations_evidence=release_operations_evidence,
        )
        event, successor = self._reducer.transition(
            state,
            assessment_digest=assessment.assessment_digest,
        )
        self._require_current_task(value)
        current_issued, current_value = self._authoritative_candidate(selector, observer)
        self._facts.require_source_current(
            current_issued,
            final=current_value["column_id"] == "rollback",
        )
        if (
            freeze(current_value) != freeze(value)
            or not hmac.compare_digest(
                column_evidence_digest,
                self._require_column_evidence(
                    current_value,
                    current_issued,
                    final=current_value["column_id"] == "rollback",
                ),
            )
        ):
            raise CategoryExecutionError("category evidence changed before commit")
        self._policy.require_current()
        self._oracle.require_issued(assessment)
        self._fault("category-assessment.before-commit")
        if observer is not self._target_observer:
            raise CategoryExecutionError("target observer capability changed")
        final_issued, final_value = self._authoritative_candidate(
            selector, observer
        )
        self._facts.require_source_current(
            final_issued,
            final=final_value["column_id"] == "rollback",
        )
        if (
            freeze(final_value) != freeze(value)
            or not hmac.compare_digest(
                column_evidence_digest,
                self._require_column_evidence(
                    final_value,
                    final_issued,
                    final=final_value["column_id"] == "rollback",
                ),
            )
        ):
            raise CategoryExecutionError(
                "category source changed at the precommit boundary"
            )
        source_fence_request = self._facts.issue_source_fence(
            final_issued,
            observer,
            final=final_value["column_id"] == "rollback",
            excluded_object_digest=assessment.object_digest,
        )
        fence_request = target_authority.issue_fence(
            value,
            observation,
            locks=self._repository._locks,
            completion_binding=(
                (self._oracle, assessment)
                if assessment.release_operations_projection is not None else None
            ),
        )
        object_body = assessment.to_bytes()
        snapshot = {
            "schema_version": "1.0.0",
            "task_id": value["task_id"],
            "profile_id": value["profile_id"],
            "column_id": value["column_id"],
            "transaction_id": transaction_id,
            "request_digest": assessment.request_digest,
            "task_snapshot_revision": value["task_revision"],
            "task_snapshot_digest": value["snapshot_digest"],
            "invalidation_epoch": value["invalidation_epoch"],
            "assessment_digest": assessment.assessment_digest,
            "assessment_object_digest": assessment.object_digest,
            "category_state": successor.to_dict(),
            "category_event": event.to_dict(),
            "repository_revision": 1,
        }
        try:
            receipt = self._task_application.complete_category(
                self._oracle,
                assessment,
                self._runtime,
                self._objects,
                fence_request,
                source_fence_request,
            )
            result = {
                "transaction_id": transaction_id,
                "revision": getattr(receipt, "repository_revision", None),
                "object_digest": assessment.object_digest,
            }
        except CategoryExecutionError:
            raise
        except Exception as error:
            raise CategoryExecutionError("category assessment commit failed closed") from error
        if type(result) is not dict or set(result) != {
            "transaction_id", "revision", "object_digest"
        }:
            raise CategoryExecutionError("category assessment commit receipt is invalid")
        revision = result["revision"]
        if (
            result["transaction_id"] != transaction_id
            or result["object_digest"] != assessment.object_digest
            or type(revision) is not int
            or revision <= 0
        ):
            raise CategoryExecutionError("category assessment commit receipt changed")
        snapshot["repository_revision"] = revision
        self._fault("category-assessment.after-commit")
        return CategoryAssessmentReceipt(
            assessment,
            event,
            successor,
            transaction_id,
            revision,
            False,
        )

    def _require_current_task(self, candidate: Mapping[str, object]) -> None:
        resolve = getattr(self._repository, "resolve_task_snapshot", None)
        if self._task_application is not None:
            runtime_show = getattr(self._task_application, "runtime_show", None)
            if not callable(runtime_show):
                raise CategoryExecutionError(
                    "TaskApplication current snapshot resolver is unavailable"
                )
            try:
                current = runtime_show(str(candidate["task_id"]), self._runtime).snapshot
                current = current.to_dict()
            except Exception as error:
                raise CategoryExecutionError(
                    "current task snapshot authority is unavailable"
                ) from error
        elif callable(resolve):
            try:
                current = resolve(str(candidate["task_id"]))
            except Exception as error:
                raise CategoryExecutionError(
                    "current task snapshot authority is unavailable"
                ) from error
        else:
            load = getattr(self._repository, "load", None)
            if not callable(load):
                raise CategoryExecutionError(
                    "current task snapshot resolver is unavailable"
                )
            try:
                current = load(str(candidate["task_id"]))
            except Exception as error:
                raise CategoryExecutionError(
                    "current task snapshot authority is unavailable"
                ) from error
        if not isinstance(current, Mapping):
            raise CategoryExecutionError("current task snapshot authority is invalid")
        revision = current.get("task_revision", current.get("revision"))
        if (
            revision != candidate["task_revision"]
            or current.get("snapshot_digest") != candidate["snapshot_digest"]
            or current.get("invalidation_epoch") != candidate["invalidation_epoch"]
        ):
            raise CategoryExecutionError("task snapshot is stale or invalidated")
        graph_ref = current.get("graph_ref")
        if graph_ref is not None:
            if not isinstance(graph_ref, Mapping):
                raise CategoryExecutionError("current task GraphRef is invalid")
            pins = candidate["digest_pins"]
            if not isinstance(pins, Mapping):
                raise CategoryExecutionError("category materialization pins are invalid")
            graph_binding = {
                "base_graph_digest": graph_ref.get("graph_digest"),
                "profile_digest": graph_ref.get("profile_digest"),
                "overlay_digest": graph_ref.get("overlay_digest"),
                "project_config_digest": graph_ref.get("project_config_digest"),
                "support_matrix_digest": graph_ref.get("support_matrix_digest"),
                "materialization_digest": graph_ref.get("materialization_digest"),
            }
            if freeze(graph_binding) != freeze(pins):
                raise CategoryExecutionError("current task GraphRef pins changed")

    def restart(
        self,
        task_application: object,
        runtime: object,
        target_observer: object,
    ) -> CategoryExecutionApplication:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext

        if type(task_application) is not TaskApplication or type(runtime) is not RuntimeContext:
            raise CategoryExecutionError("category restart task authority is invalid")
        repository = task_application._repository
        objects = task_application._materialization_objects
        resolver = CategoryAssessmentResolver(
            repository,
            objects,
            task_application=task_application,
            runtime=runtime,
        )
        restart_task_id = self._facts._coverage_task_identity()
        current_assessment_body = resolver.current_body(restart_task_id)
        migration_projection: dict[str, object] | None = None
        dependency_projection: dict[str, object] | None = None
        scenario_projection: dict[str, object] | None = None
        release_projection: dict[str, object] | None = None
        if current_assessment_body is not None:
            _current_snapshot, current_assessment_bytes = current_assessment_body
            current_assessment = _strict_json(current_assessment_bytes)
            if current_assessment.get("schema_version") == "1.2.0":
                if current_assessment.get("profile_id") != self._policy.profile_id:
                    raise CategoryExecutionError(
                        "current typed assessment projection is foreign"
                    )
                if self._policy.profile_id == "migration":
                    candidate_projection = current_assessment.get(
                        "migration_rehearsal_projection"
                    )
                    if (
                        type(candidate_projection) is not dict
                        or "dependency_graph_projection" in current_assessment
                    ):
                        raise CategoryExecutionError(
                            "current migration assessment projection is invalid"
                        )
                    migration_projection = candidate_projection
                elif self._policy.profile_id == "dependency-security":
                    candidate_projection = current_assessment.get(
                        "dependency_graph_projection"
                    )
                    if (
                        type(candidate_projection) is not dict
                        or "migration_rehearsal_projection" in current_assessment
                    ):
                        raise CategoryExecutionError(
                            "current dependency graph projection is invalid"
                        )
                    dependency_projection = candidate_projection
                else:
                    raise CategoryExecutionError(
                        "category assessment 1.2 crossed Profile boundary"
                    )
            elif current_assessment.get("schema_version") == "1.3.0":
                if current_assessment.get("profile_id") != self._policy.profile_id:
                    raise CategoryExecutionError(
                        "current scenario assessment projection is foreign"
                    )
                candidate_projection = current_assessment.get(
                    "scenario_truth_projection"
                )
                if (
                    type(candidate_projection) is not dict
                    or any(
                        field in current_assessment
                        for field in (
                            "performance_evidence_projection",
                            "migration_rehearsal_projection",
                            "dependency_graph_projection",
                        )
                    )
                ):
                    raise CategoryExecutionError(
                        "current scenario truth projection is invalid"
                    )
                scenario_projection = candidate_projection
            elif current_assessment.get("schema_version") == "1.4.0":
                if current_assessment.get("profile_id") != "release-operations":
                    raise CategoryExecutionError(
                        "current release assessment projection is foreign"
                    )
                candidate_projection = current_assessment.get(
                    "release_operations_projection"
                )
                if (
                    type(candidate_projection) is not dict
                    or any(
                        field in current_assessment
                        for field in (
                            "performance_evidence_projection",
                            "migration_rehearsal_projection",
                            "dependency_graph_projection",
                            "scenario_truth_projection",
                        )
                    )
                ):
                    raise CategoryExecutionError(
                        "current release operations projection is invalid"
                    )
                release_projection = candidate_projection
        performance_factory = None
        performance_authority = None
        if self._policy.profile_id == "performance":
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkRegistryFactory,
            )

            performance_factory = (
                PerformanceBenchmarkRegistryFactory.from_installation()
            )
            performance_authority = performance_factory.registry()
        migration_factory = None
        migration_authority = None
        if migration_projection is not None:
            from graph_engineering.application.migration_rehearsal import (
                MigrationRehearsalFactory,
            )

            command_scope = repository._command_scope
            migration_factory = MigrationRehearsalFactory.from_installation(
                command_scope._manager, repository,
            )
            migration_factory._rehydrate_executions_from_projection(
                migration_projection,
            )
            migration_authority = migration_factory.authority
        dependency_factory = None
        if dependency_projection is not None:
            from graph_engineering.application.dependency_security import (
                DependencyGraphAssessmentFactory,
            )

            dependency_factory = DependencyGraphAssessmentFactory.from_installation(
                repository
            )
        scenario_factory = None
        if scenario_projection is not None:
            from graph_engineering.application.scenario_truth import (
                ScenarioTruthRegistryFactory,
            )

            scenario_factory = ScenarioTruthRegistryFactory.from_installation()
        release_factory = None
        if release_projection is not None:
            from graph_engineering.application.release_operations import (
                ReleaseOperationsRegistryFactory,
            )

            release_factory = ReleaseOperationsRegistryFactory.from_installation()
        target_authority = CategoryTargetObservationAuthority(self._policy)
        restarted = CategoryExecutionApplication(
            repository=repository,
            object_repository=objects,
            policy=self._policy,
            reducer=CategoryExecutionReducer(self._policy),
            completion_oracle=CategoryCompletionOracle(
                policy=self._policy,
                target_authority=target_authority,
                performance_registry_factory=performance_factory,
                performance_registry_authority=performance_authority,
                migration_rehearsal_factory=migration_factory,
                migration_rehearsal_authority=migration_authority,
                dependency_graph_factory=dependency_factory,
                scenario_truth_factory=scenario_factory,
                release_operations_factory=release_factory,
            ),
            rollback_bridge=CategoryRollbackBridge(
                self._policy, self._rollback._coordinator
            ),
            assessment_resolver=resolver,
            task_application=task_application,
            runtime=runtime,
            target_observer=target_observer,
        )
        restarted._facts.reissue_sources(
            self._facts, restarted._rollback, target_observer,
        )
        if migration_projection is not None:
            restored_assessment = restarted.current_assessment(
                restart_task_id,
                expected_profile_id=self._policy.profile_id,
            )
            if (
                restored_assessment is None
                or restored_assessment.migration_rehearsal_projection is None
            ):
                raise CategoryExecutionError(
                    "current migration assessment did not restart"
                )
        if dependency_projection is not None:
            restored_assessment = restarted.current_assessment(
                restart_task_id,
                expected_profile_id=self._policy.profile_id,
            )
            if (
                restored_assessment is None
                or restored_assessment.dependency_graph_projection is None
                or restored_assessment.migration_rehearsal_projection is not None
                or restored_assessment.performance_evidence_projection is not None
            ):
                raise CategoryExecutionError(
                    "current dependency graph assessment did not restart"
                )
        if scenario_projection is not None:
            restored_assessment = restarted.current_assessment(
                restart_task_id,
                expected_profile_id=self._policy.profile_id,
            )
            if (
                restored_assessment is None
                or restored_assessment.scenario_truth_projection is None
                or restored_assessment.performance_evidence_projection is not None
                or restored_assessment.migration_rehearsal_projection is not None
                or restored_assessment.dependency_graph_projection is not None
            ):
                raise CategoryExecutionError(
                    "current scenario truth assessment did not restart"
                )
        if release_projection is not None:
            restored_assessment = restarted.current_assessment(
                restart_task_id,
                expected_profile_id=self._policy.profile_id,
            )
            if (
                restored_assessment is None
                or restored_assessment.release_operations_projection is None
                or restored_assessment.performance_evidence_projection is not None
                or restored_assessment.migration_rehearsal_projection is not None
                or restored_assessment.dependency_graph_projection is not None
                or restored_assessment.scenario_truth_projection is not None
            ):
                raise CategoryExecutionError(
                    "current release operations assessment did not restart"
                )
        return restarted

    def _event_from_snapshot(self, snapshot: Mapping[str, object]) -> CategoryExecutionEvent:
        body = self._resolver.current_body(str(snapshot["task_id"]))
        if body is None:
            raise CategoryExecutionError("stored category assessment disappeared")
        _current, raw = body
        source = _strict_json(raw)
        event, _successor = self._reducer.restore_assessed(source)
        return event

    def _state_from_snapshot(self, snapshot: Mapping[str, object]) -> CategoryExecutionState:
        body = self._resolver.current_body(str(snapshot["task_id"]))
        if body is None:
            raise CategoryExecutionError("stored category assessment disappeared")
        _current, raw = body
        _event, state = self._reducer.restore_assessed(_strict_json(raw))
        return state

__all__ = (
    "CategoryAssessmentReceipt",
    "CategoryAssessmentResolver",
    "CategoryCompletionOracle",
    "CategoryExecutionApplication",
    "CategoryFacts",
    "CategorySourceFenceRequest",
    "CategoryRollbackBridge",
    "CategoryTargetObservationAuthority",
    "TargetObservationFence",
)
