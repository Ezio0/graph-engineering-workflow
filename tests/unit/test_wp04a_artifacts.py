from __future__ import annotations

import copy
import pathlib
import sys
import unittest
from collections.abc import Mapping


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT))

from graph_engineering.core.artifacts import (  # noqa: E402
    ArtifactDependencyIndex,
    ArtifactLifecycle,
    ArtifactLifecycleEvent,
    ArtifactValidationRecord,
    ArtifactValidationError,
    ArtifactValidator,
    LogicalBodyManifest,
)
from graph_engineering.core.artifacts.contracts import ARTIFACT_TYPES  # noqa: E402
from graph_engineering.core.artifacts.records import ARTIFACT_RECORD_SCHEMA  # noqa: E402
from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from tests.support.wp04a_artifacts import (  # noqa: E402
    ARTIFACT_BODY_CONTRACT,
    IDENTITY_PROJECTION,
    artifact_record,
    golden_semantics,
    loaded_golden,
    manifest_document,
    schema_registry,
    work_context,
)


CASE_CODES = (
    "DIGEST",
    "EXIT",
    "FINDINGS",
    "GOLD",
    "INPUTS",
    "INVALIDATE",
    "REVIEW",
    "SEMANTICS",
    "STATUS",
    "TRACE",
)
EXACT_CASE_IDS = frozenset(
    f"GEW-ART-{artifact_type}-{case_code}"
    for artifact_type in ARTIFACT_TYPES
    for case_code in CASE_CODES
)


def resign(record: dict[str, object]) -> None:
    record.pop("artifact_digest", None)
    record["artifact_digest"] = semantic_digest(
        record,
        contract_type="urn:gew:contract:artifact-record",
        projection_id=IDENTITY_PROJECTION,
        schema_id=ARTIFACT_RECORD_SCHEMA,
    )


def validate(
    record: Mapping[str, object],
    context: object,
    validation: Mapping[str, object],
):
    return ArtifactValidator.validate(record, context=context, **validation)  # type: ignore[arg-type]


class SingleUseMapping(Mapping[str, object]):
    """Expose items once so a second live read deterministically fails."""

    def __init__(self, value: Mapping[str, object]) -> None:
        self._value = dict(value)
        self._items_calls = 0

    def __getitem__(self, key: str) -> object:
        return self._value[key]

    def __iter__(self):
        return iter(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def items(self):
        self._items_calls += 1
        if self._items_calls != 1:
            raise AssertionError("caller mapping was read more than once")
        return self._value.items()


class WP04AArtifactMatrixTests(unittest.TestCase):
    maxDiff = None

    def run_case(
        self,
        artifact_type: str,
        case_code: str,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        record, manifest, contracts, schemas, context, validation = loaded_golden(artifact_type)
        if case_code == "GOLD":
            result = validate(record, context, validation)
            self.assertEqual((result.status, result.failures), ("PASS", ()))
            return

        if case_code == "SEMANTICS":
            for field in contracts.resolve(artifact_type).required_semantic_fields:
                mutated = copy.deepcopy(record)
                del mutated["semantic_fields"][field]
                resign(mutated)
                with self.subTest(field=field):
                    self.assertIn("semantics", validate(mutated, context, validation).failures)
            return

        if case_code == "INPUTS":
            evidence_input = copy.deepcopy(record)
            evidence_input["input_refs"][0]["ref_kind"] = "evidence"
            evidence_validation = dict(validation)
            input_id = evidence_input["input_refs"][0]["ref_id"]
            input_digest = evidence_input["input_refs"][0]["digest"]
            evidence_validation["known_inputs"] = {
                input_id: {
                    "ref_kind": "evidence",
                    "digest": input_digest,
                    "task_id": "task-wp04a",
                    "baseline_digest": evidence_input["input_refs"][0]["baseline_digest"],
                }
            }
            resign(evidence_input)
            self.assertEqual(validate(evidence_input, context, evidence_validation).status, "PASS")
            multi_baseline = copy.deepcopy(record)
            authority_digest = semantic_digest(
                {"kind": "authority", "version": 1},
                contract_type="urn:gew:contract:test-baseline",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:test-baseline:1.0.0",
            )
            multi_baseline["baseline_digests"]["authority"] = authority_digest
            multi_validation = dict(validation)
            multi_validation["expected_baselines"] = {
                **validation["expected_baselines"],
                "authority": authority_digest,
            }
            resign(multi_baseline)
            self.assertEqual(validate(multi_baseline, context, multi_validation).status, "PASS")
            if mutation_reporter is not None:
                mutation_reporter.add("multi-baseline-accepted")
            swapped_baseline = copy.deepcopy(multi_baseline)
            swapped_baseline["input_refs"][0]["baseline_digest"] = authority_digest
            resign(swapped_baseline)
            self.assertIn(
                "inputs",
                validate(swapped_baseline, context, multi_validation).failures,
            )
            if mutation_reporter is not None:
                mutation_reporter.add("cross-baseline-input-swap-rejected")
            mutations: list[dict[str, object]] = []
            missing = copy.deepcopy(record)
            missing["input_refs"] = []
            mutations.append(missing)
            stale = copy.deepcopy(record)
            stale["input_refs"][0]["digest"] = "sha256-jcs-v1:" + "0" * 64
            mutations.append(stale)
            wrong_task = copy.deepcopy(record)
            wrong_task["target_refs"][0]["task_id"] = "other-task"
            mutations.append(wrong_task)
            wrong_baseline = copy.deepcopy(record)
            wrong_baseline["input_refs"][0]["baseline_digest"] = "sha256-jcs-v1:" + "1" * 64
            mutations.append(wrong_baseline)
            wrong_kind = copy.deepcopy(record)
            wrong_kind["input_refs"][0]["ref_kind"] = "unknown"
            mutations.append(wrong_kind)
            invented_target = copy.deepcopy(record)
            invented_target["target_refs"][0]["target_id"] = "invented-target"
            invented_target["requirement_traces"][0]["target_id"] = "invented-target"
            mutations.append(invented_target)
            for index, mutated in enumerate(mutations):
                resign(mutated)
                with self.subTest(mutation=index):
                    self.assertIn("inputs", validate(mutated, context, validation).failures)
                if mutation_reporter is not None and mutated is invented_target:
                    mutation_reporter.add("invented-target-rejected")
            return

        if case_code == "TRACE":
            expanded = copy.deepcopy(record)
            baseline_digest = expanded["input_refs"][0]["baseline_digest"]
            second_input_id = f"input-{artifact_type}-v2"
            second_input_digest = semantic_digest(
                {"artifact_id": second_input_id},
                contract_type="urn:gew:contract:test-input",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:test-input:1.0.0",
            )
            second_target_id = f"target-{artifact_type}-v2"
            second_target_digest = semantic_digest(
                {"target_id": second_target_id},
                contract_type="urn:gew:contract:test-target",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:test-target:1.0.0",
            )
            expanded["input_refs"].append({
                "ref_id": second_input_id,
                "ref_kind": "artifact",
                "digest": second_input_digest,
                "task_id": "task-wp04a",
                "baseline_digest": baseline_digest,
            })
            expanded["target_refs"].append({
                "target_id": second_target_id,
                "target_digest": second_target_digest,
                "task_id": "task-wp04a",
            })
            expanded["requirement_traces"].extend([
                {"trace_type": "dependency", "source_id": second_input_id, "target_id": record["artifact_id"]},
                {"trace_type": "decision", "source_id": record["artifact_id"], "target_id": second_target_id},
                {"trace_type": "requirement", "source_id": "requirement-fr10", "target_id": record["artifact_id"]},
            ])
            expanded_validation = dict(validation)
            expanded_validation["known_inputs"] = {
                **validation["known_inputs"],
                second_input_id: {
                    "ref_kind": "artifact",
                    "digest": second_input_digest,
                    "task_id": "task-wp04a",
                    "baseline_digest": baseline_digest,
                },
            }
            expanded_validation["known_targets"] = {
                **validation["known_targets"],
                second_target_id: {"digest": second_target_digest, "task_id": "task-wp04a"},
            }
            expanded_validation["known_requirements"] = ("requirement-fr09", "requirement-fr10")
            resign(expanded)
            self.assertEqual(validate(expanded, context, expanded_validation).status, "PASS")
            if mutation_reporter is not None:
                input_only = copy.deepcopy(expanded)
                input_only["target_refs"] = input_only["target_refs"][:1]
                input_only["requirement_traces"] = [
                    item for item in input_only["requirement_traces"]
                    if item["target_id"] != second_target_id
                    and item["source_id"] != "requirement-fr10"
                ]
                input_validation = dict(expanded_validation)
                input_validation["known_targets"] = validation["known_targets"]
                input_validation["known_requirements"] = validation["known_requirements"]
                resign(input_only)
                self.assertEqual(validate(input_only, context, input_validation).status, "PASS")
                mutation_reporter.add("multi-input-accepted")

                target_only = copy.deepcopy(expanded)
                target_only["input_refs"] = target_only["input_refs"][:1]
                target_only["requirement_traces"] = [
                    item for item in target_only["requirement_traces"]
                    if item["source_id"] != second_input_id
                    and item["source_id"] != "requirement-fr10"
                ]
                target_validation = dict(expanded_validation)
                target_validation["known_inputs"] = validation["known_inputs"]
                target_validation["known_requirements"] = validation["known_requirements"]
                resign(target_only)
                self.assertEqual(validate(target_only, context, target_validation).status, "PASS")
                mutation_reporter.add("multi-target-accepted")

                requirement_only = copy.deepcopy(expanded)
                requirement_only["input_refs"] = requirement_only["input_refs"][:1]
                requirement_only["target_refs"] = requirement_only["target_refs"][:1]
                requirement_only["requirement_traces"] = [
                    item for item in requirement_only["requirement_traces"]
                    if item["source_id"] != second_input_id
                    and item["target_id"] != second_target_id
                ]
                requirement_validation = dict(expanded_validation)
                requirement_validation["known_inputs"] = validation["known_inputs"]
                requirement_validation["known_targets"] = validation["known_targets"]
                resign(requirement_only)
                self.assertEqual(
                    validate(requirement_only, context, requirement_validation).status,
                    "PASS",
                )
                mutation_reporter.add("multi-requirement-accepted")
            for source_id, target_id in (
                (second_input_id, record["artifact_id"]),
                (record["artifact_id"], second_target_id),
                ("requirement-fr10", record["artifact_id"]),
            ):
                missing_edge = copy.deepcopy(expanded)
                missing_edge["requirement_traces"] = [
                    item for item in missing_edge["requirement_traces"]
                    if (item["source_id"], item["target_id"]) != (source_id, target_id)
                ]
                resign(missing_edge)
                with self.subTest(missing_edge=(source_id, target_id)):
                    self.assertIn(
                        "traces",
                        validate(missing_edge, context, expanded_validation).failures,
                    )
                if mutation_reporter is not None:
                    if source_id == second_input_id:
                        mutation_reporter.add("multi-input-missing-edge-rejected")
                    elif target_id == second_target_id:
                        mutation_reporter.add("multi-target-missing-edge-rejected")
                    else:
                        mutation_reporter.add("multi-requirement-missing-edge-rejected")
            for trace_type in contracts.resolve(artifact_type).required_trace_types:
                mutated = copy.deepcopy(record)
                mutated["requirement_traces"] = [
                    item for item in mutated["requirement_traces"]
                    if item["trace_type"] != trace_type
                ]
                resign(mutated)
                with self.subTest(missing=trace_type):
                    self.assertIn("traces", validate(mutated, context, validation).failures)
            duplicate = copy.deepcopy(record)
            duplicate["requirement_traces"].append(copy.deepcopy(duplicate["requirement_traces"][0]))
            resign(duplicate)
            self.assertEqual(validate(duplicate, context, validation).status, "FAIL")
            unknown = copy.deepcopy(record)
            unknown["requirement_traces"][0]["target_id"] = "unknown"
            resign(unknown)
            self.assertIn("traces", validate(unknown, context, validation).failures)
            wrong_orientation = copy.deepcopy(record)
            wrong_orientation["requirement_traces"][0]["source_id"] = wrong_orientation["input_refs"][0]["ref_id"]
            wrong_orientation["requirement_traces"][0]["target_id"] = wrong_orientation["artifact_id"]
            resign(wrong_orientation)
            self.assertIn("traces", validate(wrong_orientation, context, validation).failures)
            return

        if case_code == "DIGEST":
            mutations: list[tuple[str, dict[str, object]]] = []
            for path in ("body", "extracted", "contract", "input", "manifest"):
                mutated = copy.deepcopy(record)
                if path == "body":
                    mutated["body_digest"] = "sha256-jcs-v1:" + "0" * 64
                elif path == "extracted":
                    mutated["logical_body_ref"]["extracted_body_digest"] = "sha256-raw-v1:" + "0" * 64
                elif path == "contract":
                    mutated["contract_digest"] = "sha256-jcs-v1:" + "0" * 64
                elif path == "input":
                    mutated["input_refs"][0]["digest"] = "sha256-jcs-v1:" + "0" * 64
                else:
                    mutated["logical_body_ref"]["entry_digest"] = "sha256-jcs-v1:" + "0" * 64
                mutations.append((path, mutated))
            for path, mutated in mutations:
                resign(mutated)
                with self.subTest(path=path):
                    result = validate(mutated, context, validation)
                    self.assertIn("digests" if path != "input" else "inputs", result.failures)
            return

        if case_code == "STATUS":
            mutated = copy.deepcopy(record)
            mutated["status"] = (
                "accepted_for_next_node"
                if contracts.resolve(artifact_type).approval_policy == "human"
                else "approved"
            )
            resign(mutated)
            self.assertIn("status", validate(mutated, context, validation).failures)
            for previous, current in (("candidate", "approved"), ("archived", "candidate")):
                with self.subTest(previous=previous, current=current), self.assertRaises(ArtifactValidationError):
                    ArtifactLifecycle.require_transition(previous, current)
            return

        if case_code == "FINDINGS":
            mutated = copy.deepcopy(record)
            mutated["findings"] = [{
                "finding_id": f"{artifact_type}-blocker-1",
                "severity": "blocker",
                "status": "open",
            }]
            resign(mutated)
            self.assertIn("findings", validate(mutated, context, validation).failures)
            if artifact_type == "candidate-review":
                open_major = copy.deepcopy(record)
                open_major["findings"] = [{
                    "finding_id": "candidate-review-major-1",
                    "severity": "major",
                    "status": "open",
                }]
                resign(open_major)
                self.assertIn("findings", validate(open_major, context, validation).failures)
            no_progress = copy.deepcopy(record)
            no_progress["revision"] = 2
            no_progress["supersedes"] = {
                "artifact_id": record["artifact_id"],
                "revision": 1,
                "digest": record["artifact_digest"],
            }
            resign(no_progress)
            previous = ArtifactValidator.load(record, context=context, **validation)
            self.assertIn(
                "findings",
                ArtifactValidator.validate(
                    no_progress,
                    context=context,
                    previous_record=previous,
                    **validation,
                ).failures,
            )
            return

        if case_code == "REVIEW":
            mutations: list[tuple[dict[str, object], str, str | None]] = []
            same_reviewer = copy.deepcopy(record)
            same_reviewer["reviewer_id"] = same_reviewer["author_id"]
            same_reviewer["review_records"][0]["reviewer_id"] = same_reviewer["author_id"]
            mutations.append((same_reviewer, "review", "author-reviewer-equality-rejected"))
            wrong_digest = copy.deepcopy(record)
            wrong_digest["review_records"][0]["body_digest"] = "sha256-jcs-v1:" + "0" * 64
            mutations.append((wrong_digest, "review", None))
            missing_trust = copy.deepcopy(record)
            missing_trust["review_records"][0]["trust"] = "self-reviewed"
            mutations.append((missing_trust, "review", None))
            case_alias = copy.deepcopy(record)
            case_alias["author_id"] = str(case_alias["reviewer_id"]).upper()
            mutations.append((case_alias, "schema", "actor-case-alias-rejected"))
            whitespace_actor = copy.deepcopy(record)
            whitespace_actor["author_id"] = " author-with-space"
            mutations.append((whitespace_actor, "schema", "actor-leading-whitespace-rejected"))
            unicode_alias = copy.deepcopy(record)
            unicode_alias["author_id"] = "reviewer-e\u0301"
            unicode_alias["reviewer_id"] = "reviewer-é"
            unicode_alias["review_records"][0]["reviewer_id"] = "reviewer-é"
            mutations.append((unicode_alias, "schema", "actor-unicode-normalization-alias-rejected"))
            if contracts.resolve(artifact_type).approval_policy == "human":
                missing_approval = copy.deepcopy(record)
                missing_approval["approval_records"] = []
                mutations.append((missing_approval, "review", None))
            for index, (mutated, expected_failure, mutation_id) in enumerate(mutations):
                resign(mutated)
                with self.subTest(mutation=index):
                    self.assertIn(
                        expected_failure,
                        validate(mutated, context, validation).failures,
                    )
                if mutation_reporter is not None and mutation_id is not None:
                    mutation_reporter.add(mutation_id)
            return

        if case_code == "EXIT":
            for validator_id in contracts.resolve(artifact_type).validator_ids:
                mutated = copy.deepcopy(record)
                mutated["validation_records"] = [
                    item for item in mutated["validation_records"]
                    if item["validator_id"] != validator_id
                ]
                resign(mutated)
                with self.subTest(validator_id=validator_id):
                    self.assertIn("exit", validate(mutated, context, validation).failures)
            return

        if case_code == "INVALIDATE":
            semantics = dict(golden_semantics()[artifact_type])
            first_field = sorted(semantics)[0]
            semantics[first_field] += "-changed"
            physical, document = manifest_document(record["artifact_id"], semantics)
            changed = LogicalBodyManifest.from_dict(
                document,
                physical,
                schema_registry=schemas,
                context=context,
            )
            self.assertEqual(changed.invalidated_by(manifest), (record["artifact_id"],))
            return

        self.fail(f"unhandled case code: {case_code}")

    def test_exact_case_id_product_is_complete(self) -> None:
        generated = {
            f"GEW-ART-{artifact_type}-{case_code}"
            for artifact_type in ARTIFACT_TYPES
            for case_code in CASE_CODES
        }
        self.assertEqual(generated, EXACT_CASE_IDS)
        self.assertEqual(len(generated), 100)

    def test_lifecycle_transition_emits_digest_bound_audit_event(
        self,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        raw, _manifest, _contracts, schemas, context, validation = loaded_golden("prd")
        raw["status"] = "validating"
        resign(raw)
        loaded = ArtifactValidator.load(raw, context=context, **validation)
        event = ArtifactLifecycle.transition(
            record=loaded,
            previous="candidate",
            current="validating",
            occurred_at="2026-08-14T00:00:00Z",
            schema_registry=schemas,
            context=context,
        )
        self.assertEqual(
            (
                event.schema_version,
                event.artifact_id,
                event.artifact_digest,
                event.body_digest,
                event.revision,
                event.previous_status,
                event.current_status,
            ),
            (
                "1.0.0",
                loaded.artifact_id,
                loaded.artifact_digest,
                loaded.body["body_digest"],
                1,
                "candidate",
                "validating",
            ),
        )
        self.assertTrue(event.event_digest.startswith("sha256-jcs-v1:"))
        self.assertEqual(
            event.event_digest,
            semantic_digest(
                {
                    "schema_version": event.schema_version,
                    "artifact_id": event.artifact_id,
                    "artifact_digest": event.artifact_digest,
                    "body_digest": event.body_digest,
                    "revision": event.revision,
                    "previous_status": event.previous_status,
                    "current_status": event.current_status,
                    "occurred_at": event.occurred_at,
                },
                contract_type="urn:gew:contract:artifact-lifecycle-event",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:artifact-lifecycle-event:1.0.0",
            ),
        )
        if mutation_reporter is not None:
            mutation_reporter.add("digest-bound-lifecycle-event-accepted")
        with self.assertRaisesRegex(ArtifactValidationError, "context"):
            ArtifactLifecycle.transition(
                record=loaded,
                previous="validating",
                current="under_review",
                occurred_at="2026-08-14T00:00:01Z",
                schema_registry=schemas,
                context=context,
            )
        if mutation_reporter is not None:
            mutation_reporter.add("lifecycle-record-status-mismatch-rejected")
        with self.assertRaises(TypeError):
            ArtifactLifecycleEvent()
        if mutation_reporter is not None:
            mutation_reporter.add("direct-lifecycle-event-construction-rejected")
        with self.assertRaises(TypeError):
            ArtifactValidationRecord()
        if mutation_reporter is not None:
            mutation_reporter.add("direct-validation-record-construction-rejected")

    def test_ingress_mappings_are_snapshotted_once_before_validation(
        self,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        context = work_context()
        schemas = schema_registry(context)
        semantics = golden_semantics()["impact"]
        physical, manifest_value = manifest_document("artifact-impact-v1", semantics)
        manifest = LogicalBodyManifest.from_dict(
            SingleUseMapping(manifest_value),
            physical,
            schema_registry=schemas,
            context=context,
        )
        self.assertEqual(tuple(manifest.entries), ("artifact-impact-v1",))

        record, _manifest, _contracts, _schemas, record_context, validation = loaded_golden("impact")
        snapshotted_validation = dict(validation)
        for name in ("expected_baselines", "known_inputs", "known_targets"):
            value = validation[name]
            if not isinstance(value, Mapping):
                raise AssertionError("golden validation input must be a mapping")
            snapshotted_validation[name] = SingleUseMapping(value)
        loaded = ArtifactValidator.load(
            SingleUseMapping(record),
            context=record_context,
            **snapshotted_validation,
        )
        self.assertEqual(
            (loaded.artifact_id, loaded.status),
            (record["artifact_id"], record["status"]),
        )
        if mutation_reporter is not None:
            mutation_reporter.add("caller-mappings-snapshotted-once")

    def test_dependency_index_propagates_artifact_and_requirement_changes_minimally(self) -> None:
        first_raw, _first_manifest, _contracts, _schemas, first_context, first_validation = loaded_golden("impact")
        first = ArtifactValidator.load(first_raw, context=first_context, **first_validation)

        second_raw, _second_manifest, _contracts, _schemas, second_context, second_validation = loaded_golden("plan")
        second_raw["input_refs"][0]["ref_id"] = first.artifact_id
        second_raw["input_refs"][0]["digest"] = first.artifact_digest
        second_raw["requirement_traces"][1]["source_id"] = first.artifact_id
        second_validation["known_inputs"] = {
            first.artifact_id: {
                "ref_kind": "artifact",
                "digest": first.artifact_digest,
                "task_id": second_raw["input_refs"][0]["task_id"],
                "baseline_digest": second_raw["input_refs"][0]["baseline_digest"],
            }
        }
        resign(second_raw)
        second = ArtifactValidator.load(second_raw, context=second_context, **second_validation)

        third_raw, _third_manifest, _contracts, _schemas, third_context, third_validation = loaded_golden("test-plan")
        third_raw["input_refs"][0]["ref_id"] = second.artifact_id
        third_raw["input_refs"][0]["digest"] = second.artifact_digest
        third_raw["requirement_traces"][1]["source_id"] = second.artifact_id
        third_validation["known_inputs"] = {
            second.artifact_id: {
                "ref_kind": "artifact",
                "digest": second.artifact_digest,
                "task_id": third_raw["input_refs"][0]["task_id"],
                "baseline_digest": third_raw["input_refs"][0]["baseline_digest"],
            }
        }
        resign(third_raw)
        third = ArtifactValidator.load(third_raw, context=third_context, **third_validation)

        index = ArtifactDependencyIndex.build((first, second, third))
        self.assertEqual(
            index.invalidated_by((first.artifact_id,)),
            (first.artifact_id, second.artifact_id, third.artifact_id),
        )
        self.assertEqual(
            index.invalidated_by(("requirement-fr09",)),
            (first.artifact_id, second.artifact_id, third.artifact_id),
        )
        with self.assertRaisesRegex(ArtifactValidationError, "canonical"):
            index.invalidated_by(("z", "a"))
        stale_raw = copy.deepcopy(second_raw)
        stale_raw["input_refs"][0]["digest"] = "sha256-jcs-v1:" + "0" * 64
        stale_validation = dict(second_validation)
        stale_validation["known_inputs"] = {
            first.artifact_id: {
                "ref_kind": "artifact",
                "digest": "sha256-jcs-v1:" + "0" * 64,
                "task_id": stale_raw["input_refs"][0]["task_id"],
                "baseline_digest": stale_raw["input_refs"][0]["baseline_digest"],
            }
        }
        resign(stale_raw)
        stale = ArtifactValidator.load(stale_raw, context=second_context, **stale_validation)
        with self.assertRaisesRegex(ArtifactValidationError, "digest mismatch"):
            ArtifactDependencyIndex.build((first, stale))

    def test_revision_requires_closed_predecessor_and_binds_changed_body(
        self,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        record, _manifest, _contracts, schemas, context, validation = loaded_golden("impact")
        accepted = ArtifactValidator.load(record, context=context, **validation)
        forbidden = copy.deepcopy(record)
        forbidden["revision"] = 2
        forbidden["status"] = "candidate"
        forbidden["supersedes"] = {
            "artifact_id": record["artifact_id"],
            "revision": 1,
            "digest": record["artifact_digest"],
        }
        resign(forbidden)
        self.assertIn(
            "status",
            ArtifactValidator.validate(
                forbidden,
                context=context,
                previous_record=accepted,
                **validation,
            ).failures,
        )
        if mutation_reporter is not None:
            mutation_reporter.add("accepted-predecessor-revision-rejected")

        prior_value = copy.deepcopy(record)
        prior_value["status"] = "invalidated"
        resign(prior_value)
        prior = ArtifactValidator.load(prior_value, context=context, **validation)

        semantics = dict(golden_semantics()["impact"])
        field = sorted(semantics)[0]
        semantics[field] += "-revision-2"
        physical, manifest_value = manifest_document(str(record["artifact_id"]), semantics)
        current_manifest = LogicalBodyManifest.from_dict(
            manifest_value,
            physical,
            schema_registry=schemas,
            context=context,
        )
        body_digest = semantic_digest(
            {
                "artifact_id": record["artifact_id"],
                "extracted_body_digest": current_manifest.extracted_digest(str(record["artifact_id"])),
                "semantic_fields": semantics,
            },
            contract_type=ARTIFACT_BODY_CONTRACT,
            projection_id=IDENTITY_PROJECTION,
            schema_id="urn:gew:schema:logical-body-manifest:1.0.0",
        )
        revision = copy.deepcopy(record)
        revision["revision"] = 2
        revision["semantic_fields"] = semantics
        revision["logical_body_ref"] = {
            "manifest_id": current_manifest.manifest_id,
            "entry_digest": current_manifest.entry_digest(str(record["artifact_id"])),
            "artifact_id": record["artifact_id"],
            "extracted_body_digest": current_manifest.extracted_digest(str(record["artifact_id"])),
        }
        revision["body_digest"] = body_digest
        for validation_record in revision["validation_records"]:
            validation_record["body_digest"] = body_digest
        revision["review_records"][0]["body_digest"] = body_digest
        revision["supersedes"] = {
            "artifact_id": prior.artifact_id,
            "revision": 1,
            "digest": prior.artifact_digest,
        }
        resign(revision)
        current_validation = dict(validation)
        current_validation["manifest"] = current_manifest
        result = ArtifactValidator.validate(
            revision,
            context=context,
            previous_record=prior,
            **current_validation,
        )
        self.assertEqual((result.status, result.failures), ("PASS", ()))
        if mutation_reporter is not None:
            mutation_reporter.add("invalidated-predecessor-revision-accepted")


def _install_matrix_tests() -> None:
    for artifact_type in ARTIFACT_TYPES:
        for case_code in CASE_CODES:
            case_id = f"GEW-ART-{artifact_type}-{case_code}"
            method_name = "test_" + case_id.lower().replace("-", "_")

            def matrix_test(
                self: WP04AArtifactMatrixTests,
                current_type: str = artifact_type,
                current_code: str = case_code,
            ) -> None:
                self.run_case(current_type, current_code)

            matrix_test.__name__ = method_name
            matrix_test.__qualname__ = f"WP04AArtifactMatrixTests.{method_name}"
            setattr(WP04AArtifactMatrixTests, method_name, matrix_test)


_install_matrix_tests()


if __name__ == "__main__":
    unittest.main()
