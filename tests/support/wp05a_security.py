from __future__ import annotations

import json
import pathlib
import datetime
from contextlib import contextmanager
from typing import Iterator

from graph_engineering.core.contracts.digest import semantic_digest, semantic_digest_charged
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.security.disclosure import DataDisclosurePlan
from graph_engineering.core.security.evidence import EvidenceRecord
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.attestation import (
    DisclosureJournalAttestation,
    SecurityRuntimeManifest,
    TaskSecurityContext,
    TASK_CONTEXT_SCHEMA,
    _canonical_frozen_map,
    validate_installed_runtime_document,
)
from graph_engineering.core.security._common import unsigned_digest
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.storage.codec import canonical_json, semantic_record_digest
from graph_engineering.storage.security import SecurityStateRepository
from tests.support.wp03_repository import ManualTime, repository_stack


ROOT = pathlib.Path(__file__).resolve().parents[2]
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
SECURITY_SCHEMA_NAMES = (
    "action-journal-entry-1.0.0.json",
    "action-policy-1.0.0.json",
    "authority-envelope-1.0.0.json",
    "data-disclosure-plan-1.0.0.json",
    "disclosure-policy-1.0.0.json",
    "disclosure-receipt-1.0.0.json",
    "evidence-record-1.0.0.json",
    "evidence-policy-registry-1.0.0.json",
    "input-safety-policy-1.0.0.json",
    "intent-baseline-1.0.0.json",
    "prepared-action-1.0.0.json",
    "redaction-policy-1.0.0.json",
    "retention-policy-registry-1.0.0.json",
    "security-binding-1.0.0.json",
    "security-runtime-manifest-1.0.0.json",
)
SECURITY_RUNTIME_ID = "security-runtime-default"
SECURITY_RUNTIME_DIGEST = "sha256-jcs-v1:60ec8d6f924d821e47d5554c1cb01b2a26fe412d298f80b0ae56b87a53e04c90"


def load_json(path: pathlib.Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise AssertionError(f"fixture must be an object: {path}")
    return value


def digest_value(label: str) -> str:
    return semantic_digest(
        {"label": label},
        contract_type="urn:gew:contract:wp05a-test-value",
        projection_id=IDENTITY_PROJECTION,
        schema_id="urn:gew:schema:wp05a-test-value:1.0.0",
    )


def security_context() -> WorkContext:
    profile = ResourceProfile.from_dict(load_json(ROOT / "config" / "contracts" / "resource-profile-v1.json"))
    schedule = CostSchedule.from_dict(load_json(ROOT / "config" / "contracts" / "cost-schedule-v1.json"))
    return WorkContext(profile, schedule)


def security_schema_registry(context: WorkContext | None = None) -> ClosedSchemaRegistry:
    bodies: dict[str, bytes] = {}
    for name in SECURITY_SCHEMA_NAMES:
        path = ROOT / "config" / "contracts" / "schemas" / name
        schema_id = load_json(path)["$id"]
        bodies[str(schema_id)] = path.read_bytes()
    profile = ResourceProfile.from_dict(load_json(ROOT / "config" / "contracts" / "resource-profile-v1.json"))
    policy = SchemaProfilePolicy.from_dict(load_json(ROOT / "config" / "contracts" / "schema-profile-v1.json"))
    manifest = load_json(ROOT / "config" / "contracts" / "security-schema-registry-v1.json")
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)


def security_runtime(
    context: WorkContext | None = None,
    schemas: ClosedSchemaRegistry | None = None,
) -> SecurityRuntimeManifest:
    work = security_context() if context is None else context
    registry = security_schema_registry(work) if schemas is None else schemas
    fields = validate_installed_runtime_document(
        load_json(ROOT / "config" / "security" / "security-runtime-v1.json"),
        expected_manifest_id=SECURITY_RUNTIME_ID,
        expected_manifest_digest=SECURITY_RUNTIME_DIGEST,
        schema_registry=registry,
        context=work,
    )
    runtime = object.__new__(SecurityRuntimeManifest)
    for name, value in fields.items():
        object.__setattr__(runtime, name, value)
    object.__setattr__(runtime, "_issuer", object())
    return runtime


def binding_document() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "task_id": "task-wp05a",
        "owner_id": "owner-wp05a",
        "runtime_kind": "codex",
        "runtime_lineage_id": "lineage-wp05a",
        "scope_id": "scope-wp05a",
        "scope_digest": digest_value("scope"),
        "baselines": {"intent": digest_value("intent")},
        "snapshot_digest": digest_value("snapshot"),
        "targets": [{
            "target_id": "target-project",
            "target_kind": "project",
            "canonical_identity": "project-main",
            "target_digest": digest_value("target"),
        }],
    }
    value["binding_digest"] = SecurityBinding.digest_document(value)
    return value


def input_policy_document() -> dict[str, object]:
    return load_json(ROOT / "config" / "security" / "input-safety-policy-v1.json")


def redaction_policy_document() -> dict[str, object]:
    return load_json(ROOT / "config" / "security" / "redaction-policy-v1.json")


def disclosure_policy_document() -> dict[str, object]:
    return load_json(ROOT / "config" / "security" / "disclosure-policy-v1.json")


def retention_policy_document() -> dict[str, object]:
    return load_json(ROOT / "config" / "security" / "retention-policies-v1.json")


def evidence_policy_document() -> dict[str, object]:
    return load_json(ROOT / "config" / "security" / "evidence-policies-v1.json")


def disclosure_plan_document(payload_digest: str, *, external: bool) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "disclosure_id": "disclosure-wp05a",
        "destination": ({
            "identity_ref": "connector-fixture",
            "kind": "connector",
            "trust_boundary": "external",
        } if external else {
            "identity_ref": "owner-wp05a",
            "kind": "owner",
            "trust_boundary": "owner-session",
        }),
        "purpose": "external-communication" if external else "owner-update",
        "data_refs": [{
            "ref_id": "object-summary",
            "digest": digest_value("disclosure-source"),
            "sensitivity": "confidential",
        }],
        "maximum_sensitivity": "confidential",
        "field_allowlist": ["/source", "/summary"],
        "redaction_transforms": [{"path": "/source", "transform": "mask"}],
        "retention_class": "evidence-body",
        "authority_digest": digest_value("communication-authority") if external else None,
        "prepared_action_digest": digest_value("prepared-action"),
        "snapshot_digest": digest_value("snapshot"),
        "payload_digest": payload_digest,
        "receipt_required": external,
    }
    value["plan_digest"] = DataDisclosurePlan.digest_document(value)
    return value


def evidence_document() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "evidence_id": "evidence-wp05a",
        "evidence_type": "verification",
        "task_id": "task-wp05a",
        "source_ref": "command-test",
        "collection_action_digest": digest_value("collection-action"),
        "target_refs": [{"target_id": "target-project", "target_digest": digest_value("target")}],
        "collected_at": "2026-08-14T00:00:00Z",
        "result": "PASS",
        "producer_id": "reviewer-wp05a",
        "baseline_digest": digest_value("intent"),
        "snapshot_digest": digest_value("snapshot"),
        "fresh_until": "2026-08-14T01:00:00Z",
        "sensitivity": "confidential",
        "redaction": {"status": "applied", "transforms": ["/source:mask"]},
        "content_digest": digest_value("evidence-content"),
        "provenance": sorted([
            digest_value("collection-action"),
            digest_value("evidence-source"),
            digest_value("review-receipt"),
        ]),
        "trust": "independently-reviewed",
        "status": "valid",
    }
    value["record_digest"] = EvidenceRecord.digest_document(value)
    return value


def task_security_state_document(
    *,
    binding: dict[str, object] | None = None,
    destinations: dict[str, dict[str, object]] | None = None,
    evidence: dict[str, object] | None = None,
    retention_overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build test data that the production issuer must read from SQLite."""

    binding_value = binding_document() if binding is None else binding
    evidence_value = evidence_document() if evidence is None else evidence
    destination_registry = destinations or {
        "connector-fixture": {
            "kind": "connector",
            "trust_boundary": "external",
            "target_digest": digest_value("target"),
            "prepared_action_digest": digest_value("prepared-action"),
        },
        "owner-wp05a": {
            "kind": "owner",
            "trust_boundary": "owner-session",
            "target_digest": digest_value("owner-session"),
            "prepared_action_digest": digest_value("prepared-action"),
        },
    }
    expected_evidence = {
        "evidence_type": evidence_value["evidence_type"],
        "task_id": evidence_value["task_id"],
        "source_ref": evidence_value["source_ref"],
        "collection_action_digest": evidence_value["collection_action_digest"],
        "target_digests": {
            item["target_id"]: item["target_digest"]
            for item in evidence_value["target_refs"]
        },
        "result": evidence_value["result"],
        "producer_id": evidence_value["producer_id"],
        "author_id": "author-wp05a",
        "baseline_digest": evidence_value["baseline_digest"],
        "snapshot_digest": evidence_value["snapshot_digest"],
        "sensitivity": evidence_value["sensitivity"],
        "redaction": evidence_value["redaction"],
        "content_digest": evidence_value["content_digest"],
        "provenance": evidence_value["provenance"],
        "trust": evidence_value["trust"],
        "review_receipt_digest": digest_value("review-receipt"),
    }
    retention_subject: dict[str, object] = {
        "category": "tool-raw-output",
        "created_at": "2026-08-14T00:00:00Z",
        "sensitivity": "confidential",
        "extracted": True,
        "legal_hold": False,
        "rollback_dependency": False,
        "unresolved_action": False,
        "snapshot_digest": binding_value.get("snapshot_digest", digest_value("missing-snapshot")),
        "revision": 1,
    }
    if retention_overrides:
        retention_subject.update(retention_overrides)
    return {
        "schema_version": "1.0.0",
        "task_id": binding_value.get("task_id", "task-wp05a"),
        "task_revision": 1,
        "task_snapshot_digest": binding_value.get(
            "snapshot_digest",
            digest_value("missing-snapshot"),
        ),
        "binding": binding_value,
        "destinations": {key: destination_registry[key] for key in sorted(destination_registry)},
        "authority_digests": [digest_value("communication-authority")],
        "data_refs": {
            "object-summary": {
                "digest": digest_value("disclosure-source"),
                "sensitivity": "confidential",
                "retention_class": "evidence-body",
            },
        },
        "evidence_expectations": {"evidence-wp05a": expected_evidence},
        "retention_subjects": {"object-tool-output": retention_subject},
    }


def task_security_context(
    context: WorkContext,
    schemas: ClosedSchemaRegistry,
    runtime: SecurityRuntimeManifest,
    *,
    binding: dict[str, object] | None = None,
    current_time: str = "2026-08-14T00:30:00Z",
    destinations: dict[str, dict[str, object]] | None = None,
    evidence: dict[str, object] | None = None,
    retention_overrides: dict[str, object] | None = None,
) -> TaskSecurityContext:
    state = task_security_state_document(
        binding=binding,
        destinations=destinations,
        evidence=evidence,
        retention_overrides=retention_overrides,
    )
    binding_value = state["binding"]
    if not isinstance(binding_value, dict):
        raise AssertionError("test binding must be an object")
    from graph_engineering.core.security.identity import SecurityBinding

    binding_instance = SecurityBinding._from_attested_dict(
        binding_value,
        runtime=runtime,
        schema_registry=schemas,
        context=context,
        issuer=runtime._issuer,
    )
    destinations_value = state["destinations"]
    data_refs_value = state["data_refs"]
    evidence_value_map = state["evidence_expectations"]
    retention_value = state["retention_subjects"]
    if not all(
        isinstance(value, dict)
        for value in (destinations_value, data_refs_value, evidence_value_map, retention_value)
    ):
        raise AssertionError("test security registries must be objects")
    state_digest = semantic_record_digest({
        "contract": "task-security-state-v1",
        "value": state,
    })
    frozen_destinations = _canonical_frozen_map(destinations_value, "destination registry")
    frozen_data_refs = _canonical_frozen_map(data_refs_value, "data ref registry")
    frozen_evidence = _canonical_frozen_map(evidence_value_map, "evidence registry")
    frozen_retention = _canonical_frozen_map(retention_value, "retention registry")
    context_digest = semantic_digest_charged(
        {
            "schema_version": "1.0.0",
            "runtime_manifest_digest": runtime.manifest_digest,
            "binding_digest": binding_instance.binding_digest,
            "security_state_digest": state_digest,
            "current_time": current_time,
            "destinations": frozen_destinations,
            "authority_digests": [digest_value("communication-authority")],
            "data_refs": frozen_data_refs,
            "evidence_expectations": frozen_evidence,
            "retention_subjects": frozen_retention,
        },
        context,
        contract_type="urn:gew:contract:task-security-context",
        projection_id=IDENTITY_PROJECTION,
        schema_id=TASK_CONTEXT_SCHEMA,
        operation_path=context.child_path(()),
    )
    result = object.__new__(TaskSecurityContext)
    for name, value in (
        ("runtime_manifest_digest", runtime.manifest_digest),
        ("binding", binding_instance),
        ("current_time", current_time),
        ("destinations", frozen_destinations),
        ("authority_digests", (digest_value("communication-authority"),)),
        ("data_refs", frozen_data_refs),
        ("evidence_expectations", frozen_evidence),
        ("retention_subjects", frozen_retention),
        ("state_digest", state_digest),
        ("context_digest", context_digest),
        ("_issuer", runtime._issuer),
    ):
        object.__setattr__(result, name, value)
    return result


def disclosure_receipt_document(
    *,
    receipt_id: str,
    plan: DataDisclosurePlan,
    occurred_at: str,
    result: str,
    target_receipt_digest: str,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "receipt_id": receipt_id,
        "plan_digest": plan.plan_digest,
        "payload_digest": plan.payload_digest,
        "destination_identity_ref": plan.destination["identity_ref"],
        "occurred_at": occurred_at,
        "result": result,
        "target_receipt_digest": target_receipt_digest,
    }
    value["receipt_digest"] = unsigned_digest(
        value,
        digest_field="receipt_digest",
        contract_type="urn:gew:contract:disclosure-receipt",
        schema_id="urn:gew:schema:disclosure-receipt:1.0.0",
    )
    return value


def disclosure_journal_attestation(
    receipt: dict[str, object],
    *,
    runtime: SecurityRuntimeManifest,
    context: WorkContext,
) -> DisclosureJournalAttestation:
    frozen = _canonical_frozen_map(receipt, "disclosure journal receipt")
    journal_digest = digest_value("journal-entry")
    attestation_digest = semantic_digest_charged(
        {"journal_entry_digest": journal_digest, "receipt": frozen},
        context,
        contract_type="urn:gew:contract:disclosure-journal-attestation",
        projection_id=IDENTITY_PROJECTION,
        schema_id="urn:gew:schema:disclosure-journal-attestation:1.0.0",
        operation_path=context.child_path(()),
    )
    result = object.__new__(DisclosureJournalAttestation)
    for name, value in (
        ("runtime_manifest_digest", runtime.manifest_digest),
        ("task_id", "task-wp05a"),
        ("action_id", "action-wp05a"),
        ("prepared_action_digest", digest_value("prepared-action")),
        ("task_snapshot_digest", digest_value("snapshot")),
        ("reconciliation_digest", digest_value("reconciliation")),
        ("journal_entry_digest", journal_digest),
        ("receipt", frozen),
        ("receipt_digest", attestation_digest),
        ("_issuer", runtime._issuer),
    ):
        object.__setattr__(result, name, value)
    return result


def write_durable_task_security_state(
    factory: object,
    state: dict[str, object],
) -> str:
    """Test-only repository fixture writer; production has no raw state writer."""

    from graph_engineering.storage.connection import ConnectionFactory

    if type(factory) is not ConnectionFactory:
        raise AssertionError("test fixture requires a connection factory")
    state_digest = semantic_record_digest({
        "contract": "task-security-state-v1",
        "value": state,
    })
    task_id = state["task_id"]
    revision = state["task_revision"]
    snapshot_digest = state["task_snapshot_digest"]
    with factory.open("application") as connection:
        with connection.transaction():
            connection.execute(
                "INSERT INTO tasks(task_id,revision,head_sequence,head_digest,snapshot_json,"
                "snapshot_digest,integrity_status) VALUES(?,?,?,?,?,?,'ok') "
                "ON CONFLICT(task_id) DO UPDATE SET revision=excluded.revision,"
                "snapshot_digest=excluded.snapshot_digest,integrity_status='ok'",
                (
                    task_id,
                    revision,
                    0,
                    digest_value("task-head"),
                    canonical_json({}),
                    snapshot_digest,
                ),
            )
            connection.execute(
                "INSERT INTO task_security_states(task_id,task_revision,task_snapshot_digest,"
                "state_json,state_digest) VALUES(?,?,?,?,?) "
                "ON CONFLICT(task_id) DO UPDATE SET task_revision=excluded.task_revision,"
                "task_snapshot_digest=excluded.task_snapshot_digest,state_json=excluded.state_json,"
                "state_digest=excluded.state_digest",
                (
                    task_id,
                    revision,
                    snapshot_digest,
                    canonical_json(state),
                    state_digest,
                ),
            )
    return state_digest


@contextmanager
def durable_security_issuer(
    context: WorkContext,
    schemas: ClosedSchemaRegistry,
    *,
    state: dict[str, object] | None = None,
    journal_receipt: dict[str, object] | None = None,
    runtime_json: str | None = None,
) -> Iterator[tuple[SecurityContextIssuer, object]]:
    """Create a real SQLite-backed production issuer for security tests."""

    epoch = datetime.datetime(
        2026,
        8,
        14,
        0,
        30,
        tzinfo=datetime.timezone.utc,
    )
    clock = ManualTime(int(epoch.timestamp() * 1_000_000_000))
    with repository_stack(manual_time=clock) as stack:
        factory = stack[4]._factory
        manifest = load_json(ROOT / "config" / "security" / "security-runtime-v1.json")
        registry = manifest["schema_registry"]
        if not isinstance(registry, dict):
            raise AssertionError("security runtime registry pin must be an object")
        with factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO security_runtime_installation(singleton,manifest_json,manifest_id,"
                    "manifest_digest,schema_registry_id,schema_registry_digest) VALUES(1,?,?,?,?,?)",
                    (
                        canonical_json(manifest) if runtime_json is None else runtime_json,
                        manifest["manifest_id"],
                        manifest["manifest_digest"],
                        registry["registry_id"],
                        registry["registry_digest"],
                    ),
                )
        active_state = task_security_state_document() if state is None else state
        write_durable_task_security_state(factory, active_state)
        if journal_receipt is not None:
            entry = {
                "schema_version": "1.0.0",
                "receipt_id": journal_receipt["receipt_id"],
                "task_id": active_state["task_id"],
                "action_id": "action-wp05a",
                "prepared_action_digest": digest_value("prepared-action"),
                "task_snapshot_digest": active_state["task_snapshot_digest"],
                "receipt": journal_receipt,
                "reconciliation_digest": digest_value("reconciliation"),
            }
            entry_digest = semantic_record_digest({
                "contract": "disclosure-journal-entry-v1",
                "value": entry,
                "reconciliation_state": "delivered",
            })
            with factory.open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO disclosure_journal(receipt_id,task_id,entry_json,entry_digest,"
                        "reconciliation_state) VALUES(?,?,?,?,'delivered')",
                        (
                            journal_receipt["receipt_id"],
                            active_state["task_id"],
                            canonical_json(entry),
                            entry_digest,
                        ),
                    )
        issuer = SecurityContextIssuer(
            SecurityStateRepository(factory),
            schema_registry=schemas,
            context=context,
        )
        yield issuer, factory
