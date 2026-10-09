"""Application-owned issuance from current durable security state."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    parse_timestamp,
    require_digest,
    require_id,
)
from graph_engineering.core.security.attestation import (
    DisclosureJournalAttestation,
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TASK_CONTEXT_SCHEMA,
    TaskSecurityContext,
    _canonical_frozen_map,
    validate_installed_runtime_document,
)
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.retention import RetentionDecision
from graph_engineering.storage.security import SecurityStateRepository


class SecurityIssuanceError(ValueError):
    """A durable security attestation cannot be issued."""


@dataclass(frozen=True, slots=True, init=False)
class ReadOnlyTaskSecurityProjection:
    """Validated data only; consumers must reread to establish currentness."""

    state: FrozenMap
    state_digest: str
    runtime_manifest_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("read-only security facts come from a fresh durable read")


@dataclass(frozen=True, slots=True, init=False)
class PurgeAuthorization:
    """Audit receipt for an already consumed one-use purge fence."""

    authorization_id: str
    task_id: str
    subject_ref: str
    subject_snapshot_digest: str
    security_state_digest: str
    decision_digest: str
    consumed_at_ns: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("purge authorizations are issued only by durable security state")


class SecurityContextIssuer:
    """The only production path from durable rows to opaque core attestations."""

    def __init__(
        self,
        repository: SecurityStateRepository,
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> None:
        if (
            type(repository) is not SecurityStateRepository
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise SecurityIssuanceError("security issuer requires exact durable dependencies")
        self._repository = repository
        self._schemas = schema_registry
        self._context = context
        self._bootstrap_provenance = False
        self._bootstrap_check()
        from graph_engineering.storage.repository import _recovery_scope
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        with _recovery_scope(context, repository) as budget, ExitStack() as stack:
            installed = repository.load_installed_runtime(context)
            stack.callback(budget.release_projection, installed)
            size = canonical_byte_length(installed.manifest)
            stack.enter_context(budget.reserve(context, units=8 * size, byte_count=3 * size,
                source_id="security-runtime-validation"))
            fields = validate_installed_runtime_document(
                installed.manifest,
                expected_manifest_id=installed.manifest_id,
                expected_manifest_digest=installed.manifest_digest,
                schema_registry=schema_registry,
                context=context,
            )
            runtime = object.__new__(SecurityRuntimeManifest)
            for name in (
                "manifest_id",
                "manifest_digest",
                "schema_registry_id",
                "schema_registry_digest",
                "allowed_runtime_kinds",
                "policies",
            ):
                object.__setattr__(runtime, name, fields[name])
            object.__setattr__(runtime, "_issuer", object())
            self._runtime = runtime
        self._bootstrap_check()

    def _bootstrap_check(self, task_id=None, *, connection=None, expected_state_digest=None):
        """Preserve historical APIs, but never downgrade a witnessed bootstrap root."""
        from .security_bootstrap import _guard_bootstrap_locked, SecurityBootstrapError
        from graph_engineering.storage.security import _bootstrap_schema_present
        from graph_engineering.storage.errors import RepositoryError
        import sqlite3
        factory=self._repository._factory
        try:
            if connection is None:
                with factory.open('doctor') as probe:
                    present=_bootstrap_schema_present(probe)
                if not present and not self._bootstrap_provenance:return False
                with factory.open('application') as owned,owned.transaction():
                    result=_guard_bootstrap_locked(owned,factory,self._context,task_id=task_id,
                        expected_state_digest=expected_state_digest,require_provenance=self._bootstrap_provenance,
                        schema_registry=self._schemas)
            else:
                result=_guard_bootstrap_locked(connection,factory,self._context,task_id=task_id,
                    expected_state_digest=expected_state_digest,require_provenance=self._bootstrap_provenance,
                    schema_registry=self._schemas)
            if result:self._bootstrap_provenance=True
            return result
        except (SecurityBootstrapError, RepositoryError, sqlite3.DatabaseError, TypeError, ValueError, RuntimeError):
            raise SecurityIssuanceError('SECURITY_BOOTSTRAP_INTEGRITY') from None

    @property
    def runtime(self) -> SecurityRuntimeManifest:
        return self._runtime

    def read_task_state(self, task_id: str) -> ReadOnlyTaskSecurityProjection:
        """Validate current facts without issuing a clock-bearing capability."""

        from graph_engineering.storage.repository import _recovery_scope
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        self._bootstrap_check(task_id)
        with _recovery_scope(self._context, self, self._repository) as budget, ExitStack() as stack:
            installed = self._repository.load_installed_runtime(self._context)
            stack.callback(budget.release_projection, installed)
            size = canonical_byte_length(installed.manifest)
            stack.enter_context(budget.reserve(self._context, units=8 * size, byte_count=3 * size,
                source_id="security-runtime-validation"))
            fields = validate_installed_runtime_document(
                installed.manifest,
                expected_manifest_id=installed.manifest_id,
                expected_manifest_digest=installed.manifest_digest,
                schema_registry=self._schemas,
                context=self._context,
            )
            if any(fields[name] != getattr(self._runtime, name) for name in (
                "manifest_id", "manifest_digest", "schema_registry_id",
                "schema_registry_digest", "allowed_runtime_kinds", "policies",
            )):
                raise SecurityIssuanceError("installed security runtime changed")
            record = self._repository.load_current_task_state_readonly(task_id, self._context)
            stack.callback(budget.release_projection, record)
            size = canonical_byte_length(record.state)
            stack.enter_context(budget.reserve(self._context, units=8 * size, byte_count=3 * size,
                source_id="security-binding-validation"))
            state = thaw(record.state)
            assert type(state) is dict
            try:
                binding = state["binding"]
                if type(binding) is not dict:
                    raise ValueError("security binding is not an object")
                # Validate with the existing parser, but never expose its attestation.
                SecurityBinding._from_attested_dict(
                    binding, runtime=self._runtime, schema_registry=self._schemas,
                    context=self._context, issuer=self._runtime._issuer,
                )
                for name in ("destinations", "data_refs", "evidence_expectations", "retention_subjects"):
                    _canonical_frozen_map(state[name], name)
                require_digest(record.state_digest, "task security state digest")
            except (KeyError, TypeError, ValueError, SecurityAttestationError) as error:
                raise SecurityIssuanceError(str(error)) from error
            result = object.__new__(ReadOnlyTaskSecurityProjection)
            object.__setattr__(result, "state", record.state)
            object.__setattr__(result, "state_digest", record.state_digest)
            object.__setattr__(result, "runtime_manifest_digest", self._runtime.manifest_digest)
            self._bootstrap_check(task_id,expected_state_digest=record.state_digest)
            with budget.reserve(self._context, units=4 * size, byte_count=size,
                    source_id="security-projection") as reservation:
                reservation.transfer(result)
            return result

    def issue_task_context(self, task_id: str) -> TaskSecurityContext:
        """Issue from a current task row plus repository-owned high-water clock."""

        if self._bootstrap_check(task_id):
            with self._repository._factory.open('application') as connection,connection.transaction():
                return self._issue_task_context_locked(connection,task_id)
        record = self._repository.load_current_task_state(task_id, self._context)
        return self._issue_task_record(record)

    def _issue_task_context_locked(self, connection, task_id):
        """Internal issuance from the caller's repository transaction."""
        from graph_engineering.storage.security import CurrentTaskSecurityState
        from graph_engineering.storage.clock import strict_trusted_now
        self._repository._factory._require_owned_transaction(connection)
        self._bootstrap_check(task_id,connection=connection)
        from graph_engineering.storage.repository import _recovery_scope
        with _recovery_scope(self._context) as budget, ExitStack() as stack:
            state,digest=self._repository._load_task_state(connection,task_id,self._context)
            stack.callback(budget.release_projection,state)
            result=self._issue_task_record(CurrentTaskSecurityState(state,digest,
                self._repository._clock_text(strict_trusted_now(connection))))
            self._bootstrap_check(task_id,connection=connection,expected_state_digest=digest)
            return result

    def _register_learning_subject_locked(self,connection,task_id,runtime,policy_digest,max_bytes):
        """Register only persisted PMF data, preserving current task blockers."""
        import hashlib
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        from graph_engineering.core.learning import decimal_ns
        current=self._issue_task_context_locked(connection,task_id)
        runtime.require_issued()
        if (current.binding.owner_id!=runtime.owner_id or current.binding.runtime_kind!=runtime.runtime_kind
                or current.binding.runtime_lineage_id!=runtime.runtime_lineage_id):
            raise SecurityIssuanceError("learning security identity differs")
        state,digest=self._repository._load_task_state(connection,task_id,self._context)
        if digest!=current.state_digest:raise SecurityIssuanceError("learning security state changed")
        row=connection.execute('SELECT retained_at_ns FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',
            (task_id,policy_digest)).fetchone()
        if row is None:raise SecurityIssuanceError("learning subject has no persisted data")
        subjects=state['retention_subjects']
        if type(subjects) is not dict:raise SecurityIssuanceError('retention registry is invalid')
        flags={name:False for name in ('legal_hold','rollback_dependency','unresolved_action')}
        for subject in subjects.values():
            if type(subject) is not dict:raise SecurityIssuanceError('retention subject is invalid')
            for name in flags:
                if type(subject.get(name)) is not bool:raise SecurityIssuanceError("retention blocker is unknown")
                flags[name]=flags[name] or subject[name]
        if connection.execute("SELECT 1 FROM claims WHERE task_id=? AND state='unresolved' LIMIT 1",(task_id,)).fetchone():
            flags['unresolved_action']=True
        ref='learning:'+hashlib.sha256(policy_digest.encode()).hexdigest()
        previous=subjects.get(ref)
        if previous is not None and (type(previous) is not dict
                or previous.get('category')!='pmf-aggregate'
                or type(previous.get('revision')) is not int
                or not 0<=previous['revision']<2**53-1):
            raise SecurityIssuanceError('retention subject revision is invalid')
        revision=1 if previous is None else previous['revision']+1
        subject={'category':'pmf-aggregate','created_at':self._repository._clock_text(decimal_ns(row[0])),
            'sensitivity':'confidential','extracted':False,**flags,
            'snapshot_digest':current.binding.snapshot_digest,'revision':revision}
        if previous is not None and previous=={**subject,'revision':previous['revision']}:
            if len(canonical_json(state).encode())>max_bytes:
                raise SecurityIssuanceError('retention registry is oversized')
            return ref
        subjects[ref]=subject
        body=canonical_json(state)
        growth_reserve=16-len(str(revision))
        if len(body.encode())+growth_reserve>max_bytes:raise SecurityIssuanceError('retention registry is oversized')
        updated=semantic_record_digest({'contract':'task-security-state-v1','value':state})
        changed=connection.execute('UPDATE task_security_states SET state_json=?,state_digest=? '
            'WHERE task_id=? AND state_digest=?',(body,updated,task_id,digest)).rowcount
        if changed!=1:raise SecurityIssuanceError("learning security registration lost its CAS")
        return ref

    def _authorize_learning_purge_locked(self,connection,task_id,runtime,policy,registry,trigger):
        """Evaluate and consume only the persisted learning subject in one transaction."""
        from graph_engineering.core.security.retention import RetentionEngine
        self._repository._factory._require_owned_transaction(connection)
        subject=self._register_learning_subject_locked(connection,task_id,runtime,policy.digest,
            policy.limits['max_row_bytes'])
        current=self._issue_task_context_locked(connection,task_id)
        decision=RetentionEngine.evaluate(runtime=self.runtime,task_context=current,registry=registry,
            subject_ref=subject,trigger=trigger)
        if decision.action!='purge':return decision.action,None
        authorization=self._repository._authorize_purge_locked(connection,task_id,decision,self._context)
        return 'purged',authorization.authorization_id

    def _issue_task_record(self, record) -> TaskSecurityContext:
        import inspect
        frame=inspect.currentframe()
        try:
            caller=None if frame is None else frame.f_back
            if (caller is None or caller.f_code not in {
                    SecurityContextIssuer.issue_task_context.__code__,
                    SecurityContextIssuer._issue_task_context_locked.__code__}
                    or caller.f_locals.get('self') is not self):
                raise SecurityIssuanceError("task security record is not issuer-owned")
        finally:
            del frame,caller
        state = record.state
        try:
            parse_timestamp(record.current_time, "task security clock")
            authorities_value = state["authority_digests"]
            if type(authorities_value) is not list:
                raise ValueError("authority digest set is invalid")
            authorities = tuple(authorities_value)
            if authorities != tuple(sorted(set(authorities))):
                raise ValueError("authority digest set is not canonical")
            for item in authorities:
                require_digest(item, "authority digest")
            binding_value = state["binding"]
            if not isinstance(binding_value, dict):
                raise ValueError("security binding is not an object")
            binding = SecurityBinding._from_attested_dict(
                binding_value,
                runtime=self._runtime,
                schema_registry=self._schemas,
                context=self._context,
                issuer=self._runtime._issuer,
            )
            destinations = state["destinations"]
            data_refs = state["data_refs"]
            evidence = state["evidence_expectations"]
            retention = state["retention_subjects"]
            if not all(isinstance(item, dict) for item in (destinations, data_refs, evidence, retention)):
                raise ValueError("durable task security registries are invalid")
            frozen_destinations = _canonical_frozen_map(destinations, "destination registry")
            frozen_data_refs = _canonical_frozen_map(data_refs, "data ref registry")
            frozen_evidence = _canonical_frozen_map(evidence, "evidence registry")
            frozen_retention = _canonical_frozen_map(retention, "retention subject registry")
            require_digest(record.state_digest, "task security state digest")
            unsigned: dict[str, object] = {
                "schema_version": "1.0.0",
                "runtime_manifest_digest": self._runtime.manifest_digest,
                "binding_digest": binding.binding_digest,
                "security_state_digest": record.state_digest,
                "current_time": record.current_time,
                "destinations": frozen_destinations,
                "authority_digests": list(authorities),
                "data_refs": frozen_data_refs,
                "evidence_expectations": frozen_evidence,
                "retention_subjects": frozen_retention,
            }
            context_digest = semantic_digest_charged(
                unsigned,
                self._context,
                contract_type="urn:gew:contract:task-security-context",
                projection_id=IDENTITY_PROJECTION,
                schema_id=TASK_CONTEXT_SCHEMA,
                operation_path=self._context.child_path(()),
            )
        except (KeyError, TypeError, ValueError, SecurityAttestationError) as error:
            raise SecurityIssuanceError(str(error)) from error
        result = object.__new__(TaskSecurityContext)
        for name, item in (
            ("runtime_manifest_digest", self._runtime.manifest_digest),
            ("binding", binding),
            ("current_time", record.current_time),
            ("destinations", frozen_destinations),
            ("authority_digests", authorities),
            ("data_refs", frozen_data_refs),
            ("evidence_expectations", frozen_evidence),
            ("retention_subjects", frozen_retention),
            ("state_digest", record.state_digest),
            ("context_digest", context_digest),
            ("_issuer", self._runtime._issuer),
        ):
            object.__setattr__(result, name, item)
        return result

    def issue_disclosure_attestation(
        self,
        receipt_id: str,
    ) -> DisclosureJournalAttestation:
        """Issue only for one delivered/reconciled durable action-journal row."""

        record = self._repository.load_disclosure_journal(receipt_id, self._context)
        entry = record.entry
        try:
            receipt = entry["receipt"]
            if not isinstance(receipt, dict):
                raise ValueError("durable disclosure receipt is not an object")
            frozen = _canonical_frozen_map(receipt, "disclosure journal receipt")
            task_id = require_id(entry.get("task_id"), "disclosure task ID")
            action_id = require_id(entry.get("action_id"), "disclosure action ID")
            prepared = require_digest(
                entry.get("prepared_action_digest"),
                "prepared action digest",
            )
            snapshot = require_digest(
                entry.get("task_snapshot_digest"),
                "disclosure task snapshot digest",
            )
            reconciliation = require_digest(
                entry.get("reconciliation_digest"),
                "disclosure reconciliation digest",
            )
            journal_digest = require_digest(record.entry_digest, "disclosure journal digest")
            attestation_digest = semantic_digest_charged(
                {
                    "journal_entry_digest": journal_digest,
                    "receipt": frozen,
                },
                self._context,
                contract_type="urn:gew:contract:disclosure-journal-attestation",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:disclosure-journal-attestation:1.0.0",
                operation_path=self._context.child_path(()),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SecurityIssuanceError(str(error)) from error
        result = object.__new__(DisclosureJournalAttestation)
        for name, item in (
            ("runtime_manifest_digest", self._runtime.manifest_digest),
            ("task_id", task_id),
            ("action_id", action_id),
            ("prepared_action_digest", prepared),
            ("task_snapshot_digest", snapshot),
            ("reconciliation_digest", reconciliation),
            ("journal_entry_digest", journal_digest),
            ("receipt", frozen),
            ("receipt_digest", attestation_digest),
            ("_issuer", self._runtime._issuer),
        ):
            object.__setattr__(result, name, item)
        return result

    def authorize_purge(
        self,
        task_id: str,
        decision: RetentionDecision,
    ) -> PurgeAuthorization:
        """Transactionally revalidate and consume an engine-issued purge decision."""

        record = self._repository.authorize_purge(task_id, decision, self._context)
        result = object.__new__(PurgeAuthorization)
        for name in (
            "authorization_id",
            "task_id",
            "subject_ref",
            "subject_snapshot_digest",
            "security_state_digest",
            "decision_digest",
            "consumed_at_ns",
        ):
            object.__setattr__(result, name, getattr(record, name))
        return result
