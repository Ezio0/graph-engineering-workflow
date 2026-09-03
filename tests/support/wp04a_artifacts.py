from __future__ import annotations

import json
import pathlib
from collections.abc import Mapping

from graph_engineering.core.artifacts import (
    ArtifactContractRegistry,
    ArtifactValidator,
    LogicalBodyManifest,
)
from graph_engineering.core.artifacts.manifest import LOGICAL_BODY_MANIFEST_SCHEMA
from graph_engineering.core.artifacts.records import ARTIFACT_RECORD_SCHEMA
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SchemaProfilePolicy


ROOT = pathlib.Path(__file__).resolve().parents[2]
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
ARTIFACT_BODY_CONTRACT = "urn:gew:contract:logical-artifact-body"


def load_json(path: pathlib.Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise AssertionError(f"fixture must be an object: {path}")
    return value


def work_context() -> WorkContext:
    profile = ResourceProfile.from_dict(load_json(
        ROOT / "config" / "contracts" / "resource-profile-v1.json"
    ))
    schedule = CostSchedule.from_dict(load_json(
        ROOT / "config" / "contracts" / "cost-schedule-v1.json"
    ))
    return WorkContext(profile, schedule)


def schema_registry(context: WorkContext | None = None) -> ClosedSchemaRegistry:
    names = (
        "artifact-contract-registry-1.0.0.json",
        "artifact-lifecycle-event-1.0.0.json",
        "artifact-record-1.0.0.json",
        "logical-body-manifest-1.0.0.json",
    )
    bodies: dict[str, bytes] = {}
    for name in names:
        path = ROOT / "config" / "contracts" / "schemas" / name
        schema_id = json.loads(path.read_text())["$id"]
        bodies[schema_id] = path.read_bytes()
    profile = ResourceProfile.from_dict(load_json(
        ROOT / "config" / "contracts" / "resource-profile-v1.json"
    ))
    policy = SchemaProfilePolicy.from_dict(load_json(
        ROOT / "config" / "contracts" / "schema-profile-v1.json"
    ))
    manifest = load_json(
        ROOT / "config" / "contracts" / "artifact-schema-registry-v1.json"
    )
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)


def contract_registry(
    registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> ArtifactContractRegistry:
    document = load_json(ROOT / "config" / "contracts" / "artifact-contracts-v1.json")
    return ArtifactContractRegistry.from_dict(
        document,
        schema_registry=registry,
        context=context,
        expected_registry_id=str(document["registry_id"]),
        expected_registry_digest=str(document["registry_digest"]),
    )


def golden_semantics() -> Mapping[str, Mapping[str, str]]:
    fixture = load_json(ROOT / "tests" / "fixtures" / "wp04a-artifact-goldens.json")
    goldens = fixture["goldens"]
    if not isinstance(goldens, list):
        raise AssertionError("artifact goldens must be an array")
    return {
        item["artifact_type"]: dict(item["semantic_fields"])
        for item in goldens
        if isinstance(item, dict)
        and isinstance(item.get("artifact_type"), str)
        and isinstance(item.get("semantic_fields"), dict)
    }


def manifest_document(
    artifact_id: str,
    semantic_fields: Mapping[str, str],
    *,
    mode: str = "full",
) -> tuple[bytes, dict[str, object]]:
    physical_body = canonical_bytes(dict(semantic_fields))
    entry_value: dict[str, object] = {
        "artifact_id": artifact_id,
        "selector": {"start": 0, "end": len(physical_body)},
        "extracted_body_digest": raw_digest(physical_body),
        "shared_section_id": None,
        "dependencies": [],
    }
    entry_value["entry_digest"] = semantic_digest(
        entry_value,
        contract_type="urn:gew:contract:logical-body-entry",
        projection_id=IDENTITY_PROJECTION,
        schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
    )
    unsigned: dict[str, object] = {
        "schema_version": "1.0.0",
        "manifest_id": f"urn:gew:logical-body-manifest:{artifact_id}:1",
        "mode": mode,
        "physical_body_digest": raw_digest(physical_body),
        "entries": [entry_value],
    }
    unsigned["manifest_digest"] = semantic_digest(
        unsigned,
        contract_type="urn:gew:contract:logical-body-manifest",
        projection_id=IDENTITY_PROJECTION,
        schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
    )
    return physical_body, unsigned


def artifact_record(
    artifact_type: str,
    contracts: ArtifactContractRegistry,
    manifest: LogicalBodyManifest,
    semantic_fields: Mapping[str, str],
) -> tuple[dict[str, object], dict[str, object]]:
    contract = contracts.resolve(artifact_type)
    artifact_id = f"artifact-{artifact_type}-v1"
    baseline_digest = semantic_digest(
        {"kind": "intent", "version": 1},
        contract_type="urn:gew:contract:test-baseline",
        projection_id=IDENTITY_PROJECTION,
        schema_id="urn:gew:schema:test-baseline:1.0.0",
    )
    input_id = f"input-{artifact_type}-v1"
    input_digest = semantic_digest(
        {"artifact_id": input_id},
        contract_type="urn:gew:contract:test-input",
        projection_id=IDENTITY_PROJECTION,
        schema_id="urn:gew:schema:test-input:1.0.0",
    )
    target_id = f"target-{artifact_type}-v1"
    target_digest = semantic_digest(
        {"target_id": target_id},
        contract_type="urn:gew:contract:test-target",
        projection_id=IDENTITY_PROJECTION,
        schema_id="urn:gew:schema:test-target:1.0.0",
    )
    body_digest = semantic_digest(
        {
            "artifact_id": artifact_id,
            "extracted_body_digest": manifest.extracted_digest(artifact_id),
            "semantic_fields": dict(semantic_fields),
        },
        contract_type=ARTIFACT_BODY_CONTRACT,
        projection_id=IDENTITY_PROJECTION,
        schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
    )
    record: dict[str, object] = {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "contract_id": contract.contract_id,
        "contract_digest": contract.contract_digest,
        "task_id": "task-wp04a",
        "revision": 1,
        "author_id": f"author-{artifact_type}",
        "reviewer_id": f"reviewer-{artifact_type}",
        "target_refs": [{
            "target_id": target_id,
            "target_digest": target_digest,
            "task_id": "task-wp04a",
        }],
        "input_refs": [{
            "ref_id": input_id,
            "ref_kind": "artifact",
            "digest": input_digest,
            "task_id": "task-wp04a",
            "baseline_digest": baseline_digest,
        }],
        "baseline_digests": {"intent": baseline_digest},
        "requirement_traces": [
            {"trace_type": "decision", "source_id": artifact_id, "target_id": target_id},
            {"trace_type": "dependency", "source_id": input_id, "target_id": artifact_id},
            {"trace_type": "requirement", "source_id": "requirement-fr09", "target_id": artifact_id},
        ],
        "logical_body_ref": {
            "manifest_id": manifest.manifest_id,
            "entry_digest": manifest.entry_digest(artifact_id),
            "artifact_id": artifact_id,
            "extracted_body_digest": manifest.extracted_digest(artifact_id),
        },
        "body_digest": body_digest,
        "semantic_fields": dict(semantic_fields),
        "status": contract.exit_status,
        "findings": [],
        "validation_records": [
            {"validator_id": validator_id, "body_digest": body_digest, "result": "PASS"}
            for validator_id in contract.validator_ids
        ],
        "review_records": [{
            "reviewer_id": f"reviewer-{artifact_type}",
            "body_digest": body_digest,
            "trust": "independently-reviewed",
            "verdict": "PASS",
        }],
        "approval_records": ([{
            "owner_id": "owner-wp04a",
            "body_digest": body_digest,
            "decision": "approved",
        }] if contract.approval_policy == "human" else []),
        "created_at": "2026-08-14T00:00:00Z",
        "supersedes": None,
    }
    record["artifact_digest"] = semantic_digest(
        record,
        contract_type="urn:gew:contract:artifact-record",
        projection_id=IDENTITY_PROJECTION,
        schema_id=ARTIFACT_RECORD_SCHEMA,
    )
    validation = {
        "contract_registry": contracts,
        "schema_registry": None,
        "expected_task_id": "task-wp04a",
        "expected_baselines": {"intent": baseline_digest},
        "known_inputs": {input_id: {
            "ref_kind": "artifact",
            "digest": input_digest,
            "task_id": "task-wp04a",
            "baseline_digest": baseline_digest,
        }},
        "known_targets": {
            target_id: {"digest": target_digest, "task_id": "task-wp04a"}
        },
        "known_requirements": ("requirement-fr09",),
        "manifest": manifest,
    }
    return record, validation


def loaded_golden(
    artifact_type: str,
) -> tuple[dict[str, object], LogicalBodyManifest, ArtifactContractRegistry, ClosedSchemaRegistry, WorkContext, dict[str, object]]:
    context = work_context()
    schemas = schema_registry(context)
    contracts = contract_registry(schemas, context)
    semantics = golden_semantics()[artifact_type]
    artifact_id = f"artifact-{artifact_type}-v1"
    body, manifest_value = manifest_document(artifact_id, semantics)
    manifest = LogicalBodyManifest.from_dict(
        manifest_value,
        body,
        schema_registry=schemas,
        context=context,
    )
    record, validation = artifact_record(artifact_type, contracts, manifest, semantics)
    validation["schema_registry"] = schemas
    loaded = ArtifactValidator.load(record, context=context, **validation)
    if loaded.artifact_id != artifact_id:
        raise AssertionError("golden artifact identity mismatch")
    return record, manifest, contracts, schemas, context, validation
