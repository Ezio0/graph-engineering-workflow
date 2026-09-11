from __future__ import annotations

import copy
import dataclasses
import json
import datetime
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from graph_engineering.application.actions import ActionCoordinator
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.core.actions import ActionPolicy, AuthorityEnvelope, PreparedAction
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security.disclosure import DataDisclosurePlan, DisclosurePolicy
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.privacy import RedactionPolicy, Redactor
from graph_engineering.storage.actions import ActionJournalRepository
from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest
from graph_engineering.storage.ports import CommitBatch, LeaseGrant
from graph_engineering.storage.repository import make_event
from graph_engineering.storage.security import SecurityStateRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository
from tests.support.wp03_repository import ManualTime, repository_stack
from tests.support.wp05a_security import (
    ROOT,
    binding_document,
    disclosure_policy_document,
    redaction_policy_document,
    security_context,
    security_schema_registry,
    task_security_state_document,
    write_durable_task_security_state,
)
from tests.support.wp07a_actions import action_adapter_schema_registry


IDENTITY = "urn:gew:digest-projection:identity:1.0.0"
# Compatibility for callers explicitly importing this context. Internal fixture
# operations must own their contexts instead of accumulating into this global.
ACTION_DOCUMENT_CONTEXT = security_context()


def digest(label: str) -> str:
    return semantic_digest(
        {"label": label},
        contract_type="urn:gew:contract:wp05-test-value",
        projection_id=IDENTITY,
        schema_id="urn:gew:schema:wp05-test-value:1.0.0",
    )


def prepared_document(*, context: WorkContext | None = None) -> dict[str, object]:
    context = security_context() if context is None else context
    payload = {"set": {"version": 2}}
    value: dict[str, object] = {
        "schema_version": "1.0.0", "action_id": "action-wp05", "task_id": "task-wp05",
        "action_kind": "commit", "target_id": "target-project", "target_digest": digest("target"),
        "resources": ["target:project", "task:task-wp05"], "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, context), "precondition": {"version": 1},
        "expected_postcondition": {"version": 2}, "idempotency_class": "non-idempotent",
        "idempotency_key": "idempotency-wp05",
        "verification_plan": {"capability": "fresh-target-query", "predicate": "exact"},
        "rollback_plan": {"capability": "fake-compensation", "set": {"version": 1}},
        "required_capabilities": ["deterministic-fake-target-v1", "fresh-target-query"],
        "baseline_digest": digest("intent"), "snapshot_digest": digest("snapshot"),
    }
    value["prepared_action_digest"] = PreparedAction.digest_document(value, context)
    return value


def authority_document(
    prepared: PreparedAction, *, action_kind: str | None = None,
    context: WorkContext | None = None,
) -> dict[str, object]:
    context = security_context() if context is None else context
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "authority_id": "authority-wp05-rollback" if prepared.action_kind == "rollback" else "authority-wp05",
        "task_id": prepared.task_id,
        "owner_id": "owner-wp05", "runtime_kind": "codex", "runtime_lineage_id": "lineage-wp05",
        "authorized_action_kind": prepared.action_kind if action_kind is None else action_kind,
        "authorized_resources": list(prepared.resources), "prepared_action_digest": prepared.prepared_action_digest,
        "baseline_digest": prepared.baseline_digest, "snapshot_digest": prepared.snapshot_digest,
        "issued_at": "2026-08-14T00:00:00Z", "expires_at": "2026-08-14T01:00:00Z", "status": "active",
    }
    value["authority_digest"] = AuthorityEnvelope.digest_document(value, context)
    return value


def compensation_prepared_document(
    *, snapshot_digest: str | None = None, context: WorkContext | None = None,
) -> dict[str, object]:
    context = security_context() if context is None else context
    value = prepared_document(context=context)
    value.update({
        "action_id": "action-wp05-rollback",
        "action_kind": "rollback",
        "payload": {"set": {"version": 1}},
        "precondition": {"version": 2},
        "expected_postcondition": {"version": 1},
        "idempotency_key": "idempotency-wp05-rollback",
        "rollback_plan": {"capability": "fake-compensation", "set": {"version": 2}},
    })
    if snapshot_digest is not None:
        value["snapshot_digest"] = snapshot_digest
    value["payload_digest"] = PreparedAction.payload_digest_for(value["payload"], context)
    value["prepared_action_digest"] = PreparedAction.digest_document(value, context)
    return value


class JournalFixture:
    def __init__(self, journal: ActionJournalRepository, factory: object) -> None:
        self._journal = journal
        self._factory = factory

    def load(self, action_id: str):
        return self._journal.load(action_id)

    def test_only_mutate_prepared(self, action_id: str, mutation: str) -> None:
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute("SELECT prepared_json FROM action_journal WHERE action_id=?", (action_id,)).fetchone()
                value = json.loads(row[0])
                field = {
                    "baseline": "baseline_digest", "snapshot": "snapshot_digest", "payload": "payload_digest",
                    "idempotency": "idempotency_key", "rollback": "rollback_plan",
                    "verification": "verification_plan", "action-kind": "action_kind",
                }[mutation]
                value[field] = {} if field.endswith("plan") else ("push" if field == "action_kind" else digest(f"mutated-{field}"))
                connection.execute("UPDATE action_journal SET prepared_json=? WHERE action_id=?", (canonical_json(value), action_id))

    def test_only_mutate_authority(self, action_id: str, mutation: str) -> None:
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute("SELECT authority_json FROM action_journal WHERE action_id=?", (action_id,)).fetchone()
                value = json.loads(row[0])
                if mutation == "expiry":
                    value["expires_at"] = "2026-08-14T00:00:01Z"
                value["authority_digest"] = AuthorityEnvelope.digest_document(value, security_context())
                connection.execute(
                    "UPDATE action_journal SET authority_json=?,authority_digest=? WHERE action_id=?",
                    (canonical_json(value), value["authority_digest"], action_id),
                )

    def test_only_set_state(self, action_id: str, state: str) -> None:
        with self._factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "UPDATE action_journal SET state=? WHERE action_id=?",
                    (state, action_id),
                )

    def test_only_replace_body(self, action_id: str, column: str, value: dict[str, object]) -> None:
        if column not in {"prepared_json", "receipt_json", "reconciliation_json"}:
            raise AssertionError("test-only action body column is invalid")
        with self._factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    f"UPDATE action_journal SET {column}=? WHERE action_id=?",
                    (canonical_json(value), action_id),
                )


class TestOnlyTrustedCoordinator:
    """Fixture facade for a repository-attested HumanDecision authority node."""

    def __init__(self, coordinator: ActionCoordinator, factory: object) -> None:
        self._coordinator = coordinator
        self._factory = factory

    def __getattr__(self, name: str):
        return getattr(self._coordinator, name)

    def authorize(self, value: dict[str, object]) -> AuthorityEnvelope:
        authority = AuthorityEnvelope.from_dict(value, context=security_context())
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT state_json FROM task_security_states WHERE task_id=?",
                    (authority.task_id,),
                ).fetchone()
                if row is None:
                    raise AssertionError("trusted fixture task security state is missing")
                state = parse_canonical_json(row[0])
                if type(state) is not dict or type(state.get("authority_digests")) is not list:
                    raise AssertionError("trusted fixture task security state is invalid")
                state["authority_digests"] = sorted(
                    set(state["authority_digests"]) | {authority.authority_digest},
                )
                destinations = state.get("destinations")
                if type(destinations) is not dict or type(destinations.get("owner-wp05")) is not dict:
                    raise AssertionError("trusted fixture destination state is invalid")
                destinations["owner-wp05"]["prepared_action_digest"] = authority.prepared_action_digest
                state_digest = semantic_record_digest({
                    "contract": "task-security-state-v1", "value": state,
                })
                connection.execute(
                    "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                    (canonical_json(state), state_digest, authority.task_id),
                )
        return self._coordinator.authorize(value)


@dataclass
class ActionFixture:
    coordinator: object
    raw_coordinator: ActionCoordinator
    repository: object
    objects: object
    locks: object
    journal: JournalFixture
    leases: object
    action_lease: LeaseGrant
    other_lease: LeaseGrant
    context: object
    schemas: object
    issuer: SecurityContextIssuer
    manual_time: ManualTime
    factory: object

    def expire_action_lease(self) -> None:
        self.manual_time.set(self.action_lease.expires_at + 1)

    def current_task_snapshot_digest(self) -> str:
        return self.journal._journal.current_task_snapshot_digest("task-wp05")

    def recovery_attempt(self, original_action_id: str) -> dict[str, object]:
        result = self.leases.recovery_attempt(f"claim:{original_action_id}")
        if result is None:
            raise AssertionError("recovery attempt was not durable")
        return result


@contextmanager
def action_stack(
    *,
    action_ttl_ns: int = 10**15,
    concrete_action_authority: tuple[object, object, object] | None = None,
) -> Iterator[ActionFixture]:
    epoch = datetime.datetime(2026, 8, 14, 0, 30, tzinfo=datetime.timezone.utc)
    manual_time = ManualTime(int(epoch.timestamp() * 1_000_000_000))
    with repository_stack(manual_time=manual_time) as (_root, factory, locks, objects, repository, leases):
        initial_lease = leases.acquire_many(
            lease_id="lease-create-wp05", task_id="task-wp05", run_id="run-create-wp05",
            operation_id="create", resources=("task:task-wp05",), ttl_ns=10**15,
        )
        event = make_event(
            task_id="task-wp05", sequence=1, event_id="task-wp05-created", event_type="task.created",
            occurred_at="2026-08-14T00:00:00Z", actor={"kind": "runtime", "id": "lineage-wp05"},
            expected_task_revision=0, baseline_digests=[], payload={"task_id": "task-wp05"}, previous_event_digest=None,
        )
        repository.commit(CommitBatch(
            "transaction-create-wp05", "task-wp05", 0, (event,),
            {"task_id": "task-wp05", "revision": 1, "state": "ready"}, {},
            {"lease_id": initial_lease.lease_id, "resource_id": "task:task-wp05", "fencing_token": dict(initial_lease.fencing_tokens)["task:task-wp05"]},
        ))
        leases.release(initial_lease.lease_id)
        command_factory = repository._factory

        context = security_context()
        schemas = security_schema_registry(context)
        runtime_name = (
            "security-runtime-v1.json"
            if concrete_action_authority is None
            else "security-runtime-local-actions-v1.json"
        )
        manifest = json.loads((ROOT / "config" / "security" / runtime_name).read_text())
        registry = manifest["schema_registry"]
        with command_factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO security_runtime_installation(singleton,manifest_json,manifest_id,manifest_digest,schema_registry_id,schema_registry_digest) VALUES(1,?,?,?,?,?)",
                    (canonical_json(manifest), manifest["manifest_id"], manifest["manifest_digest"], registry["registry_id"], registry["registry_digest"]),
                )
        binding = binding_document()
        binding.update({
            "task_id": "task-wp05", "owner_id": "owner-wp05", "runtime_lineage_id": "lineage-wp05",
            "baselines": {"intent": digest("intent")}, "snapshot_digest": digest("snapshot"),
            "targets": [{"target_id": "target-project", "target_kind": "project", "canonical_identity": "project-main", "target_digest": digest("target")}],
        })
        binding["binding_digest"] = SecurityBinding.digest_document(binding)
        document_context = security_context()
        prepared = PreparedAction.from_dict(
            prepared_document(context=document_context), context=document_context,
        )
        compensation_prepared = PreparedAction.from_dict(
            compensation_prepared_document(context=document_context), context=document_context,
        )
        destinations = {"owner-wp05": {"kind": "owner", "trust_boundary": "owner-session", "target_digest": digest("owner-session"), "prepared_action_digest": prepared.prepared_action_digest}}
        state = task_security_state_document(binding=binding, destinations=destinations)
        expected_authority = authority_document(prepared)
        compensation_authority = authority_document(compensation_prepared)
        state["authority_digests"] = sorted([
            expected_authority["authority_digest"],
            compensation_authority["authority_digest"],
        ])
        state["data_refs"] = {"action-payload": {"digest": digest("payload-source"), "sensitivity": "internal", "retention_class": "evidence-body"}}
        write_durable_task_security_state(command_factory, state)
        issuer = SecurityContextIssuer(SecurityStateRepository(command_factory), schema_registry=schemas, context=context)
        journal = ActionJournalRepository(command_factory, schema_registry=schemas, context=context)
        action_lease = leases.acquire_many(
            lease_id="lease-action-wp05", task_id="task-wp05", run_id="run-action-wp05",
            operation_id="action", resources=("target:project", "task:task-wp05"), ttl_ns=action_ttl_ns,
        )
        other_lease = dataclasses.replace(action_lease, lease_id="wrong-lease")
        policy_name = (
            "action-policy-v1.json"
            if concrete_action_authority is None
            else "action-policy-local-actions-v1.json"
        )
        policy = ActionPolicy.from_dict(
            json.loads((ROOT / "config" / "actions" / policy_name).read_text()),
            schema_registry=schemas,
            context=context,
            runtime=issuer.runtime,
        )

        repository = type(repository)(
            command_factory, locks, objects, action_journal=journal,
            concrete_action_schemas=action_adapter_schema_registry(context),
            concrete_action_context=context,
            command_scope=repository.command_scope,
        )

        concrete_kwargs = {} if concrete_action_authority is None else {
            "action_adapter_factory": concrete_action_authority[0],
            "concrete_action_policy": concrete_action_authority[1],
            "concrete_action_registry": concrete_action_authority[2],
        }
        raw_coordinator = ActionCoordinator(
            journal=journal, repository=repository, leases=leases, locks=locks,
            objects=objects,
            security_issuer=issuer, action_policy=policy,
            installation_scope=repository.command_scope,
            **concrete_kwargs,
        )
        coordinator = TestOnlyTrustedCoordinator(raw_coordinator, command_factory)
        yield ActionFixture(
            coordinator, raw_coordinator, repository, objects, locks,
            JournalFixture(journal, command_factory), leases, action_lease, other_lease,
            context, schemas, issuer, manual_time,
            factory,
        )


@contextmanager
def action_coordinator_for_thread(fixture: ActionFixture) -> Iterator[ActionCoordinator]:
    """Give one worker thread its own live installation command scope."""

    maintenance_objects = ObjectRepository(
        fixture.factory._for_maintenance(), fixture.locks,
    )
    manager = InstallationMigrationRepository.attach_command_plane(
        fixture.factory, fixture.locks, maintenance_objects,
        control_root=fixture.factory._test_installation_control_root,
        policy_document=fixture.factory._test_migration_policy,
    )
    try:
        with manager.command_scope() as scope:
            factory = fixture.factory.bind_command_scope(scope)
            objects = ObjectRepository(factory, fixture.locks)
            leases = ResourceLeaseRepository(factory, fixture.locks)
            journal = ActionJournalRepository(
                factory, schema_registry=fixture.schemas, context=fixture.context,
            )
            repository = TaskRepository(
                factory, fixture.locks, objects, action_journal=journal,
                command_scope=scope,
            )
            issuer = SecurityContextIssuer(
                SecurityStateRepository(factory), schema_registry=fixture.schemas,
                context=fixture.context,
            )
            try:
                yield ActionCoordinator(
                    journal=journal, repository=repository, leases=leases,
                    locks=fixture.locks, objects=objects, security_issuer=issuer,
                    action_policy=fixture.raw_coordinator._policy,
                    installation_scope=scope,
                )
            finally:
                objects.close()
    finally:
        manager.close()
        maintenance_objects.close()


def disclosure_plan(fixture: ActionFixture, prepared: PreparedAction, payload_override: str | None = None) -> DataDisclosurePlan:
    runtime = fixture.issuer.runtime
    policy = DisclosurePolicy.from_dict(
        disclosure_policy_document(), schema_registry=fixture.schemas, context=fixture.context, runtime=runtime,
    )
    redaction_policy = RedactionPolicy.from_dict(
        redaction_policy_document(), schema_registry=fixture.schemas, context=fixture.context, runtime=runtime,
    )
    redacted = Redactor.redact(
        dict(prepared.payload), field_allowlist=("/set",), transforms={}, secret_materials=(),
        policy=redaction_policy, context=fixture.context,
    )
    value: dict[str, object] = {
        "schema_version": "1.0.0", "disclosure_id": "disclosure-wp05",
        "destination": {"identity_ref": "owner-wp05", "kind": "owner", "trust_boundary": "owner-session"},
        "purpose": "owner-update", "data_refs": [{"ref_id": "action-payload", "digest": digest("payload-source"), "sensitivity": "internal"}],
        "maximum_sensitivity": "internal", "field_allowlist": ["/set"], "redaction_transforms": [],
        "retention_class": "evidence-body", "authority_digest": None,
        "prepared_action_digest": prepared.prepared_action_digest, "snapshot_digest": prepared.snapshot_digest,
        "payload_digest": redacted.payload_digest, "receipt_required": False,
    }
    value["plan_digest"] = DataDisclosurePlan.digest_document(value)
    result = DataDisclosurePlan.from_dict(
        value, policy=policy, runtime=runtime, task_context=fixture.issuer.issue_task_context(prepared.task_id),
        redacted_payload=redacted, schema_registry=fixture.schemas, context=fixture.context,
    )
    if payload_override is not None:
        forged = object.__new__(DataDisclosurePlan)
        for name in DataDisclosurePlan.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(result, name))
        object.__setattr__(forged, "payload_digest", digest(payload_override))
        return forged
    return result
