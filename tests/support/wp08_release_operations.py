from __future__ import annotations

import base64

from graph_engineering.core.actions import PreparedAction
from graph_engineering.core.contracts.immutable import thaw
from graph_engineering.core.release_operations import ReleaseArtifactManifest
from graph_engineering.core.security.disclosure import DataDisclosurePlan, DisclosurePolicy
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.privacy import RedactionPolicy, Redactor
from graph_engineering.storage.codec import (
    canonical_json,
    parse_canonical_json,
    semantic_record_digest,
)
from tests.support.wp05_actions import ActionFixture, digest, prepared_document
from tests.support.wp05a_security import (
    disclosure_policy_document,
    redaction_policy_document,
)


def artifact_bytes() -> tuple[bytes, bytes]:
    return b"artifact-a\n", b"artifact-b\n"


def retarget_security_binding(fixture: ActionFixture, *, target_digest: str) -> None:
    command_factory = fixture.coordinator._factory
    with command_factory.open("application") as connection:
        with connection.transaction():
            row = connection.execute(
                "SELECT state_json FROM task_security_states WHERE task_id=?",
                ("task-wp05",),
            ).fetchone()
            if row is None:
                raise AssertionError("release fixture task security state is missing")
            state = parse_canonical_json(row[0])
            if type(state) is not dict or type(state.get("binding")) is not dict:
                raise AssertionError("release fixture task security state is invalid")
            binding = state["binding"]
            targets = binding.get("targets")
            if type(targets) is not list or len(targets) != 1 or type(targets[0]) is not dict:
                raise AssertionError("release fixture target binding is invalid")
            targets[0]["target_digest"] = target_digest
            binding["binding_digest"] = SecurityBinding.digest_document(binding)
            state_digest = semantic_record_digest({
                "contract": "task-security-state-v1",
                "value": state,
            })
            connection.execute(
                "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                (canonical_json(state), state_digest, "task-wp05"),
            )


def release_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    candidate: ReleaseArtifactManifest,
    candidate_bytes: bytes,
) -> dict[str, object]:
    value = prepared_document(context=fixture.context)
    payload = {
        "operation_id": "local-release-simulator.apply",
        "expected_generation": 0,
        "artifact_manifest": candidate.to_dict(),
        "artifact_bytes_base64": base64.b64encode(candidate_bytes).decode("ascii"),
    }
    value.update({
        "action_kind": "deploy",
        "target_digest": target_digest,
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": None,
        },
        "expected_postcondition": {
            "generation": 1,
            "active_artifact_digest": candidate.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": baseline.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_restore_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    baseline_bytes: bytes,
    candidate: ReleaseArtifactManifest,
    original_claim_id: str,
    original_receipt_digest: str,
) -> dict[str, object]:
    value = prepared_document(context=fixture.context)
    payload = {
        "operation_id": "local-release-simulator.restore",
        "expected_generation": 1,
        "artifact_manifest": baseline.to_dict(),
        "artifact_bytes_base64": base64.b64encode(baseline_bytes).decode("ascii"),
        "original_claim_id": original_claim_id,
        "original_receipt_digest": original_receipt_digest,
    }
    value.update({
        "action_id": "action-wp05-release-restore",
        "action_kind": "rollback",
        "target_digest": target_digest,
        "snapshot_digest": fixture.current_task_snapshot_digest(),
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 1,
            "active_artifact_digest": candidate.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "expected_postcondition": {
            "generation": 2,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": baseline.manifest_digest,
        },
        "idempotency_key": "idempotency-wp05-release-restore",
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": candidate.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_partial_restore_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    baseline_bytes: bytes,
    candidate: ReleaseArtifactManifest,
    original_claim_id: str,
    original_receipt_digest: str,
) -> dict[str, object]:
    """Prepare exact same-claim cleanup for staged-B/active-A unknown state."""

    value = prepared_document(context=fixture.context)
    payload = {
        "operation_id": "local-release-simulator.restore",
        "expected_generation": 0,
        "artifact_manifest": baseline.to_dict(),
        "artifact_bytes_base64": base64.b64encode(baseline_bytes).decode("ascii"),
        "original_claim_id": original_claim_id,
        "original_receipt_digest": original_receipt_digest,
    }
    value.update({
        "action_id": "action-wp05-release-partial-restore",
        "action_kind": "rollback",
        "target_digest": target_digest,
        "snapshot_digest": fixture.current_task_snapshot_digest(),
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "expected_postcondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": None,
        },
        "idempotency_key": "idempotency-wp05-release-partial-restore",
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": candidate.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_disclosure_plan(
    fixture: ActionFixture,
    prepared: PreparedAction,
) -> DataDisclosurePlan:
    runtime = fixture.issuer.runtime
    policy = DisclosurePolicy.from_dict(
        disclosure_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=runtime,
    )
    redaction_policy = RedactionPolicy.from_dict(
        redaction_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=runtime,
    )
    allowlist = tuple(f"/{key}" for key in sorted(prepared.payload))
    redacted = Redactor.redact(
        dict(prepared.payload), field_allowlist=allowlist, transforms={},
        secret_materials=(), policy=redaction_policy, context=fixture.context,
    )
    if redacted.as_dict() != thaw(prepared.payload):
        raise AssertionError("release payload disclosure projection changed")
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "disclosure_id": "disclosure-wp08-release",
        "destination": {
            "identity_ref": "owner-wp05", "kind": "owner",
            "trust_boundary": "owner-session",
        },
        "purpose": "owner-update",
        "data_refs": [{
            "ref_id": "action-payload", "digest": digest("payload-source"),
            "sensitivity": "internal",
        }],
        "maximum_sensitivity": "internal",
        "field_allowlist": list(allowlist),
        "redaction_transforms": [],
        "retention_class": "evidence-body",
        "authority_digest": None,
        "prepared_action_digest": prepared.prepared_action_digest,
        "snapshot_digest": prepared.snapshot_digest,
        "payload_digest": redacted.payload_digest,
        "receipt_required": False,
    }
    value["plan_digest"] = DataDisclosurePlan.digest_document(value)
    return DataDisclosurePlan.from_dict(
        value, policy=policy, runtime=runtime,
        task_context=fixture.issuer.issue_task_context(prepared.task_id),
        redacted_payload=redacted, schema_registry=fixture.schemas,
        context=fixture.context,
    )
