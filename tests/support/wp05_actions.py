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
    """Legacy test input facade; grants come only from the live action service."""

    def __init__(self, coordinator, factory, *, session=None, service=None, release=None, bind=None):
        self._coordinator=coordinator
        self._factory=factory
        self._session=session
        self._service=service
        self._release=release
        self._bind=bind
        self._requests={}

    def __getattr__(self, name):
        method=getattr(self._coordinator,name)
        if name in {'execute','execute_concrete_git','compensate_unknown'} and self._session is not None:
            def invoke(*args,**kwargs):
                if kwargs.get('runtime_lineage_id')=='lineage-wp05':
                    kwargs['runtime_lineage_id']=self._session.proof.lineage_id
                return method(*args,**kwargs)
            return invoke
        return method

    def authorize(self, value):
        if self._session is None or self._service is None:
            raise ValueError('fixture requires a genuine action decision session')
        from graph_engineering.core.security._common import parse_timestamp
        authority=AuthorityEnvelope.from_dict(value,context=security_context())
        record=self._coordinator._journal.load(next_action_id(self._coordinator._journal,value))
        prepared=record.prepared
        expected=authority_document(prepared)
        if (any(value[k]!=expected[k] for k in expected if k not in {'authority_digest','authority_id','issued_at','expires_at'})
                or not parse_timestamp(authority.issued_at,'issued') <= parse_timestamp(self._coordinator._issuer.issue_task_context(authority.task_id).current_time,'now')
                < parse_timestamp(authority.expires_at,'expires')):
            raise ValueError('fixture authority input differs from requested action')
        with self._factory.open('application') as connection:
            with connection.transaction():
                state,_=SecurityStateRepository._load_task_state(connection,authority.task_id,security_context())
                state['destinations']['owner-wp05']['prepared_action_digest']=prepared.prepared_action_digest
                digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                connection.execute('UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?',
                    (canonical_json(state),digest,authority.task_id))
                revision,snapshot=connection.execute('SELECT revision,snapshot_digest FROM tasks WHERE task_id=?',
                    (authority.task_id,)).fetchone()
        request=dict(schema_version='1.0.0',request_id='request:fixture:'+authority.authority_digest.split(':')[-1],
            task_id=authority.task_id,action_id=record.action_id,expected_task_revision=revision,
            expected_snapshot_digest=snapshot,expected_security_digest=digest,expected_journal_revision=record.revision)
        request=self._requests.setdefault(authority.authority_digest,request)
        self._release()
        try:
            self._service.authorize(self._session,request)
        finally:
            self._bind()
        current=self._coordinator._journal.load(record.action_id).authority
        self._coordinator.authorize(self._coordinator._journal.authority_document(current))
        return current

    def revoke(self, action_id, authority_id):
        record=self._coordinator._journal.load(action_id)
        if record.authority is None:
            raise ValueError('fixture action has no grant')
        request=next(value for value in self._requests.values() if value['action_id']==action_id)
        if authority_id not in {'authority-wp05','authority-wp05-rollback',record.authority.authority_id}:
            raise ValueError('fixture authority identity differs')
        self._release()
        try:
            status=self._service.status(self._session,{k:request[k] for k in ('schema_version','request_id','task_id','action_id')})
            return self._service.revoke(self._session,{k:request[k] for k in ('schema_version','request_id','task_id','action_id')}
                | {'expected_generation':status['receipt']['generation']})
        finally:
            self._bind()


def next_action_id(journal, value):
    with journal._factory.open('doctor') as connection:
        rows=connection.execute('SELECT action_id FROM action_journal WHERE task_id=? AND prepared_digest=?',
            (value['task_id'],value['prepared_action_digest'])).fetchall()
    if len(rows)!=1:
        raise ValueError('fixture authority does not identify exactly one prepared action')
    return rows[0][0]


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
    task_application: object | None = None
    task_runtime: object | None = None
    task_id: str = "task-wp05"

    def expire_action_lease(self) -> None:
        self.manual_time.set(self.action_lease.expires_at + 1)

    def current_task_snapshot_digest(self) -> str:
        return self.journal._journal.current_task_snapshot_digest(self.task_id)

    def recovery_attempt(self, original_action_id: str) -> dict[str, object]:
        result = self.leases.recovery_attempt(f"claim:{original_action_id}")
        if result is None:
            raise AssertionError("recovery attempt was not durable")
        return result


@contextmanager
def action_stack(
    *,
    action_ttl_ns: int = 10**15,
    domain_task: bool = False,
    task_id: str = "task-wp05",
    concrete_action_authority: tuple[object, object, object] | None = None,
) -> Iterator[ActionFixture]:
    epoch = datetime.datetime(2026, 8, 14, 0, 30, tzinfo=datetime.timezone.utc)
    manual_time = ManualTime(int(epoch.timestamp() * 1_000_000_000))
    from tests.support.action_authority import action_session
    from tests.unit.test_action_authority import decision
    from graph_engineering.application.action_authority import ActionAuthorizationApplication
    with repository_stack(manual_time=manual_time) as (_root, factory, locks, objects, repository, leases), action_session(
            lambda req,owner,lineage:decision(req),owner_override='owner-wp05') as active_session:
        manager=factory._test_installation_manager
        objects.close()
        repository.command_scope.__exit__(None,None,None)
        manager.initialize_action_authority_storage()
        scope=manager.command_scope();scope.__enter__()
        command_factory=factory.bind_command_scope(scope)
        objects=ObjectRepository(command_factory,locks)
        leases=ResourceLeaseRepository(command_factory,locks)
        repository=TaskRepository(command_factory,locks,objects,command_scope=scope)
        task_application = task_runtime = None
        if domain_task:
            from graph_engineering.application.tasks import TaskApplication
            from graph_engineering.core.graph.state import TaskCommand
            from tests.contract.test_wp02_graph import graph_schemas, work_context
            from tests.support.runtime import runtime_context

            task_application = TaskApplication(
                repository, repository, leases, schema_registry=graph_schemas(),
                context=work_context(), materialization_objects=objects,
            )
            task_runtime = runtime_context(
                "owner-wp05", "codex", active_session.proof.lineage_id, "actor-wp05",
                "2026-08-14T00:00:00Z", 10**15,
            )
            task_application.execute(task_id, TaskCommand("create", 0, {"identity": {
                "task_id": task_id, "owner_id": "owner-wp05",
                "runtime_kind": "codex", "runtime_lineage_id": active_session.proof.lineage_id,
            }}), task_runtime)
        else:
            initial_lease = leases.acquire_many(
                lease_id="lease-create-wp05", task_id=task_id, run_id="run-create-wp05",
                operation_id="create", resources=("task:" + task_id,), ttl_ns=10**15,
            )
            event = make_event(
                task_id=task_id, sequence=1, event_id="task-wp05-created", event_type="task.created",
                occurred_at="2026-08-14T00:00:00Z", actor={"kind": "runtime", "id": "lineage-wp05"},
                expected_task_revision=0, baseline_digests=[], payload={"task_id": task_id}, previous_event_digest=None,
            )
            repository.commit(CommitBatch(
                "transaction-create-wp05", task_id, 0, (event,),
                {"task_id": task_id, "revision": 1, "state": "ready"}, {},
                {"lease_id": initial_lease.lease_id, "resource_id": "task:" + task_id, "fencing_token": dict(initial_lease.fencing_tokens)["task:" + task_id]},
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
            "task_id": task_id, "owner_id": "owner-wp05", "runtime_lineage_id": active_session.proof.lineage_id,
            "baselines": {"intent": digest("intent")}, "snapshot_digest": digest("snapshot"),
            "targets": [{"target_id": "target-project", "target_kind": "project", "canonical_identity": "project-main", "target_digest": digest("target")}],
        })
        if domain_task:
            with command_factory.open("doctor") as connection:
                task_row = connection.execute(
                    "SELECT revision,snapshot_digest FROM tasks WHERE task_id=?", (task_id,),
                ).fetchone()
            binding["snapshot_digest"] = task_row[1]
        binding["binding_digest"] = SecurityBinding.digest_document(binding)
        document_context = security_context()
        def initial_document(build):
            document = build(context=document_context)
            document["task_id"] = task_id
            document["resources"] = ["target:project", "task:" + task_id]
            document["prepared_action_digest"] = PreparedAction.digest_document(document, document_context)
            return document
        prepared = PreparedAction.from_dict(
            initial_document(prepared_document), context=document_context,
        )
        compensation_prepared = PreparedAction.from_dict(
            initial_document(compensation_prepared_document), context=document_context,
        )
        destinations = {"owner-wp05": {"kind": "owner", "trust_boundary": "owner-session", "target_digest": digest("owner-session"), "prepared_action_digest": prepared.prepared_action_digest}}
        state = task_security_state_document(binding=binding, destinations=destinations)
        state["authority_digests"] = []
        state["data_refs"] = {"action-payload": {"digest": digest("payload-source"), "sensitivity": "internal", "retention_class": "evidence-body"}}
        if domain_task:
            state["task_revision"] = task_row[0]
            state["task_snapshot_digest"] = task_row[1]
            # Fixture trust setup only: never rewrite the real producer's task row.
            with command_factory.open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO task_security_states(task_id,task_revision,task_snapshot_digest,"
                        "state_json,state_digest) VALUES(?,?,?,?,?)",
                        (task_id, task_row[0], task_row[1], canonical_json(state),
                         semantic_record_digest({"contract": "task-security-state-v1", "value": state})),
                    )
        else:
            write_durable_task_security_state(command_factory, state)
        issuer = SecurityContextIssuer(SecurityStateRepository(command_factory), schema_registry=schemas, context=context)
        journal = ActionJournalRepository(command_factory, schema_registry=schemas, context=context)
        action_lease = leases.acquire_many(
            lease_id="lease-action-wp05", task_id=task_id, run_id="run-action-wp05",
            operation_id="action", resources=("target:project", "task:" + task_id), ttl_ns=action_ttl_ns,
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
        service=ActionAuthorizationApplication(manager,schema_registry=schemas,context=context)
        fixture=ActionFixture(None,raw_coordinator,repository,objects,locks,
            JournalFixture(journal,command_factory),leases,action_lease,other_lease,
            context,schemas,issuer,manual_time,factory,task_application,task_runtime,task_id)

        def release_scope():
            fixture.objects.close()
            fixture.repository.command_scope.__exit__(None,None,None)

        def bind_scope():
            fresh=manager.command_scope();fresh.__enter__()
            bound=factory.bind_command_scope(fresh)
            fresh_objects=ObjectRepository(bound,locks)
            fresh_leases=ResourceLeaseRepository(bound,locks)
            fresh_issuer=SecurityContextIssuer(SecurityStateRepository(bound),schema_registry=schemas,context=context)
            fresh_journal=ActionJournalRepository(bound,schema_registry=schemas,context=context)
            fresh_repository=TaskRepository(bound,locks,fresh_objects,action_journal=fresh_journal,
                concrete_action_schemas=action_adapter_schema_registry(context),concrete_action_context=context,command_scope=fresh)
            fresh_policy=ActionPolicy.from_dict(json.loads((ROOT/'config/actions'/policy_name).read_text()),
                schema_registry=schemas,context=context,runtime=fresh_issuer.runtime)
            fresh_coordinator=ActionCoordinator(journal=fresh_journal,repository=fresh_repository,
                leases=fresh_leases,locks=locks,objects=fresh_objects,security_issuer=fresh_issuer,
                action_policy=fresh_policy,installation_scope=fresh,fault_hook=fixture.raw_coordinator._fault,**concrete_kwargs)
            fixture.raw_coordinator=fresh_coordinator
            fixture.repository=fresh_repository;fixture.objects=fresh_objects;fixture.leases=fresh_leases
            fixture.issuer=fresh_issuer;fixture.journal=JournalFixture(fresh_journal,bound)
            if fixture.task_application is not None:
                prior=fixture.task_application
                fixture.task_application=TaskApplication(fresh_repository,fresh_repository,fresh_leases,
                    schema_registry=prior._schemas,context=prior._context,materialization_objects=fresh_objects)
            fixture.coordinator._coordinator=fresh_coordinator
            fixture.coordinator._factory=bound

        fixture.coordinator=TestOnlyTrustedCoordinator(raw_coordinator,command_factory,
            session=active_session,service=service,release=release_scope,bind=bind_scope)
        try:
            yield fixture
        finally:
            release_scope()



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
