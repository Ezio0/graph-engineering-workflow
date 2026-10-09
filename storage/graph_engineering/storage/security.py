"""Durable trust roots and current-state reads for security gates."""

from __future__ import annotations

import datetime
import hmac
import sqlite3
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts import canonical_text, parse_json
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security.retention import RetentionDecision

from .clock import trusted_now
from .codec import require_jcs_digest, semantic_record_digest
from .connection import ConnectionFactory, ManagedConnection
from .errors import RepositoryConflictError, RepositoryIntegrityError


class SecurityBootstrapError(ValueError):
    """A sanitized bootstrap category, never a record or capability."""


_BOOTSTRAP_TABLES = ('security_bootstrap_installation_receipts', 'security_bootstrap_task_receipts')
_BOOTSTRAP_SCHEMA = (
    """CREATE TABLE security_bootstrap_installation_receipts (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        receipt_json TEXT NOT NULL,
        receipt_digest TEXT NOT NULL
    ) STRICT""",
    """CREATE TABLE security_bootstrap_task_receipts (
        task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        receipt_digest TEXT NOT NULL
    ) STRICT""",
)
_BOOTSTRAP_TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table} "
    "BEGIN SELECT RAISE(ABORT,'security bootstrap receipts are immutable'); END"
    for table in _BOOTSTRAP_TABLES for operation in ('UPDATE', 'DELETE')
)


def _bootstrap_schema_present(connection):
    return bool(connection.execute(
        "SELECT 1 FROM sqlite_master WHERE lower(name) LIKE 'security_bootstrap_%' LIMIT 1"
    ).fetchone() or connection.execute(
        "SELECT 1 FROM schema_versions WHERE lower(component)='security-bootstrap' LIMIT 1"
    ).fetchone())


def _bootstrap_require_schema(connection):
    if connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE lower(name) LIKE 'security_bootstrap_%'").fetchone()!=(6,):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
    if connection.execute("SELECT version FROM schema_versions WHERE component='security-bootstrap'").fetchone() != ('1.0.0',):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
    for name, statement in zip(_BOOTSTRAP_TABLES, _BOOTSTRAP_SCHEMA, strict=True):
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? AND sql=?",
                              (name, statement)).fetchone() is None:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
    for statement in _BOOTSTRAP_TRIGGERS:
        name = statement.split()[2]
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=? AND sql=?",
                              (name, statement)).fetchone() is None:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')


def _bootstrap_digest(body, name, context):
    from graph_engineering.core.contracts.digest import semantic_digest_charged
    return semantic_digest_charged({k:v for k,v in body.items() if k != 'receipt_digest'}, context,
        contract_type='urn:gew:contract:' + name,
        projection_id='urn:gew:digest-projection:' + name + ':1.0.0',
        schema_id='urn:gew:schema:' + name + ':1.0.0')


def _bootstrap_bundle(context=None):
    """Validate current installation bytes; no caller pins or issuer seals."""
    import hashlib
    from graph_engineering import (DistributionIdentityError, _security_bootstrap_seed_resources,
                                   _security_bootstrap_installation_resources)
    from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
    from graph_engineering.core.contracts.resources import ResourceProfile, CostSchedule
    from graph_engineering.core.contracts.schema import SchemaProfilePolicy
    from graph_engineering.core.security.attestation import SecurityRuntimeManifest, validate_installed_runtime_document
    from graph_engineering.core.actions import ActionPolicy
    from graph_engineering.core.security.disclosure import DisclosurePolicy
    from graph_engineering.core.security.evidence import EvidencePolicyRegistry
    from graph_engineering.core.security.inputs import InputSafetyPolicy
    from graph_engineering.core.security.privacy import RedactionPolicy
    from graph_engineering.core.security.retention import RetentionPolicyRegistry
    from graph_engineering.core.contracts.errors import ContractError
    try:
        if context is None:
            raw = _security_bootstrap_seed_resources()
            context = WorkContext(ResourceProfile.from_dict(parse_json(raw[0])),
                                  CostSchedule.from_dict(parse_json(raw[1])))
        bodies = _security_bootstrap_installation_resources(context)
        descriptor = parse_json(bodies[0], context=context, source_id='security-bootstrap')
        paths = ['config/security/security-bootstrap-v1.json'] + [r['path'] for r in descriptor['resources']]
        documents = {p:parse_json(b, context=context, source_id='security-bootstrap')
                     for p,b in zip(paths,bodies,strict=True)}
        profile = ResourceProfile.from_dict(documents['config/contracts/resource-profile-v1.json'])
        costs = CostSchedule.from_dict(documents['config/contracts/cost-schedule-v1.json'])
        # A command may narrow its work profile, never increase installed ceilings.
        profile.narrowed_by(context.profile.to_dict())
        if context.schedule.to_dict() != costs.to_dict():
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE')
        schema_policy = SchemaProfilePolicy.from_dict(documents['config/contracts/schema-profile-v1.json'])
        registries = {}
        for name in ('security-schema-registry-v1', 'security-bootstrap-schema-registry-v1'):
            manifest = documents['config/contracts/' + name + '.json']
            ids = {r['schema_id'] for r in manifest['resources']}
            schemas = {doc['$id']:bodies[index] for index,p in enumerate(paths)
                       if (doc:=documents[p]).get('$id') in ids}
            registries[name] = ClosedSchemaRegistry.build(manifest, schemas, profile, schema_policy, context)
        foundation = registries['security-schema-registry-v1']; bootstrap = registries['security-bootstrap-schema-registry-v1']
        if bootstrap.validate('urn:gew:schema:security-bootstrap:1.0.0', descriptor, context):
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE')
        manifest = documents['config/security/security-runtime-v1.json']
        fields = validate_installed_runtime_document(manifest, expected_manifest_id=manifest['manifest_id'],
            expected_manifest_digest=manifest['manifest_digest'], schema_registry=foundation, context=context)
        if (descriptor['foundation_registry'] != manifest['schema_registry']
                or descriptor['bootstrap_registry'] != {'registry_id':bootstrap.registry_id,'registry_digest':bootstrap.registry_digest}
                or descriptor['runtime_manifest'] != {k:manifest[k] for k in ('manifest_id','manifest_digest')}
                or descriptor['policies'] != manifest['policies']):
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE')
        for label,path,key in (
            ('resource','config/contracts/resource-profile-v1.json','profile_id'),
            ('cost','config/contracts/cost-schedule-v1.json','schedule_id'),
            ('schema','config/contracts/schema-profile-v1.json','profile_id')):
            index=paths.index(path)
            expected={key:documents[path][key], 'body_digest':'sha256-raw-v1:'+hashlib.sha256(bodies[index]).hexdigest()}
            if descriptor['profiles'][label]!=expected:
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE')
        # Unsealed validation frame: discarded with parsed policies, never published.
        # Only SecurityContextIssuer issues capabilities from committed durable rows.
        validation_frame = object.__new__(SecurityRuntimeManifest)
        for name,value in fields.items(): object.__setattr__(validation_frame,name,value)
        object.__setattr__(validation_frame,'_issuer',None)
        for path, parser in (
            ('config/actions/action-policy-v1.json',ActionPolicy),
            ('config/security/disclosure-policy-v1.json',DisclosurePolicy),
            ('config/security/evidence-policies-v1.json',EvidencePolicyRegistry),
            ('config/security/input-safety-policy-v1.json',InputSafetyPolicy),
            ('config/security/redaction-policy-v1.json',RedactionPolicy),
            ('config/security/retention-policies-v1.json',RetentionPolicyRegistry)):
            parser.from_dict(documents[path],schema_registry=foundation,context=context,runtime=validation_frame)
        vector = [dict(path=p,raw_sha256=hashlib.sha256(b).hexdigest()) for p,b in zip(paths,bodies,strict=True)]
        return dict(context=context, descriptor=descriptor, manifest=manifest, foundation=foundation,
                    bootstrap=bootstrap, resource_vector_digest=semantic_record_digest({
                        'contract':'security-bootstrap-resource-vector-v1','value':vector}))
    except SecurityBootstrapError:
        raise
    except ContractError:
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE_LIMIT') from None
    except DistributionIdentityError as error:
        code='SECURITY_BOOTSTRAP_RESOURCE_LIMIT' if str(error)=='SECURITY_BOOTSTRAP_RESOURCE_LIMIT' else 'SECURITY_BOOTSTRAP_RESOURCE'
        raise SecurityBootstrapError(code) from None
    except (OSError, TypeError, ValueError, KeyError, MemoryError, RecursionError):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE') from None


def _bootstrap_initial_state(sources, revision, snapshot_digest):
    """Reconstruct the original empty projection; never replace evolved state."""
    from graph_engineering.core.security.identity import SecurityBinding
    scope=sources['scope']
    binding=dict(schema_version='1.0.0',**sources['identity'],scope_id=scope['scope_id'],scope_digest=scope['scope_digest'],
        baselines={ref['kind']:ref['digest'] for ref in sources['baselines']},snapshot_digest=snapshot_digest,
        targets=[dict(target_id=scope['scope_id'],target_kind='project-scope',canonical_identity=scope['scope_id'],
                      target_digest=scope['scope_digest'])])
    binding['binding_digest']=SecurityBinding.digest_document(binding)
    return dict(schema_version='1.0.0',task_id=sources['identity']['task_id'],task_revision=revision,
        task_snapshot_digest=snapshot_digest,binding=binding,destinations={},authority_digests=[],data_refs={},
        evidence_expectations={},retention_subjects={})


def _bootstrap_validate_initial_state(receipt, sources):
    initial=_bootstrap_initial_state(sources,receipt['initial_task_revision'],receipt['initial_snapshot_digest'])
    expected=semantic_record_digest({'contract':'task-security-state-v1','value':initial})
    if not hmac.compare_digest(receipt['initial_state_digest'],expected):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')


def _validate_current_binding(state, sources, bundle):
    from graph_engineering.core.security.identity import SecurityBinding
    binding=state['binding'];scope=sources['scope']
    if (type(binding) is not dict or bundle['foundation'].validate('urn:gew:schema:security-binding:1.0.0',binding,bundle['context'])
            or binding['binding_digest']!=SecurityBinding.digest_document(binding)
            or any(binding[k]!=v for k,v in sources['identity'].items())
            or binding['scope_id']!=scope['scope_id'] or binding['scope_digest']!=scope['scope_digest']
            or binding['baselines']!={ref['kind']:ref['digest'] for ref in sources['baselines']}
            or binding['snapshot_digest']!=sources['snapshot_digest']
            or binding['targets']!=[dict(target_id=scope['scope_id'],target_kind='project-scope',
                canonical_identity=scope['scope_id'],target_digest=scope['scope_digest'])]):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')


def _bootstrap_validate_receipt(receipt, digest, name, bundle):
    context = bundle['context']
    if (type(receipt) is not dict or bundle['bootstrap'].validate('urn:gew:schema:'+name+':1.0.0',receipt,context)
            or receipt['receipt_digest'] != digest or _bootstrap_digest(receipt,name,context) != digest):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')


def _bootstrap_require_owned_transaction(connection, factory):
    """The existing factory guard admits application roles only; maintenance is explicit."""
    from .connection import _ISSUED_CONNECTION_OWNERS
    if (type(factory) is not ConnectionFactory or type(connection) is not ManagedConnection
            or _ISSUED_CONNECTION_OWNERS.get(connection) is not factory
            or not connection._in_transaction):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
    if connection._role == 'application':
        factory._require_owned_transaction(connection)
    elif connection._role == 'migration' and factory._maintenance:
        factory.require_mutation_authority(); connection._check()
    else:
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')


def _bootstrap_installation_locked(connection, factory, bundle):
    """Bounded validation in the caller's owned transaction; origin is historical."""
    _bootstrap_require_owned_transaction(connection,factory)
    return _bootstrap_installation_facts(connection,bundle)


def _bootstrap_installation_facts(connection, bundle):
    """Pure validation, also usable on a bounded read-only migration image."""
    from .repository import _recovery_scope, _recovery_rows, _recovery_json
    _bootstrap_require_schema(connection)
    context=bundle['context']
    with _recovery_scope(context) as budget, ExitStack() as stack:
        rows=stack.enter_context(_recovery_rows(connection,[
            ('receipt',('receipt_json','receipt_digest'),'security_bootstrap_installation_receipts'),
            ('runtime',('manifest_json','manifest_id','manifest_digest','schema_registry_id','schema_registry_digest'),
             'security_runtime_installation')],{},context,budget,source_id='security-bootstrap-installation'))
        if len(rows['receipt'])!=1 or len(rows['runtime'])!=1:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
        receipt=stack.enter_context(_recovery_json(rows['receipt'][0][0],context,budget,source_id='security-bootstrap-installation'))
        _bootstrap_validate_receipt(receipt,rows['receipt'][0][1],'security-installation-receipt',bundle)
        manifest=bundle['manifest'];descriptor=bundle['descriptor']
        expected=(canonical_text(manifest),manifest['manifest_id'],manifest['manifest_digest'],
                  bundle['foundation'].registry_id,bundle['foundation'].registry_digest)
        if (rows['runtime'][0]!=expected or receipt['descriptor_digest']!=descriptor['descriptor_digest']
                or receipt['resource_vector_digest']!=bundle['resource_vector_digest']
                or receipt['manifest_digest']!=manifest['manifest_digest']
                or receipt['schema_registry_digest']!=bundle['foundation'].registry_digest):
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
        return freeze(receipt)


def _bootstrap_migration_facts(connection, *, bundle=None):
    """Admit optional receipts and their current sources before migration captures rows."""
    from .repository import (_recovery_scope, _recovery_rows, _recovery_json,
                             _security_bootstrap_source_facts)
    if not _bootstrap_schema_present(connection):return ()
    if bundle is None:bundle=_bootstrap_bundle()
    context=bundle['context']
    installation=_bootstrap_installation_facts(connection,bundle)
    with _recovery_scope(context) as budget,ExitStack() as stack:
        rows=stack.enter_context(_recovery_rows(connection,[
            ('receipt',('task_id','request_id','request_digest','receipt_json','receipt_digest'),
             'security_bootstrap_task_receipts ORDER BY task_id'),
            ('state',('task_id',),'task_security_states ORDER BY task_id')],{},context,budget,
             source_id='security-bootstrap-migration'))
        if [r[0] for r in rows['receipt']]!=[r[0] for r in rows['state']]:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
        for row in rows['receipt']:
            receipt=stack.enter_context(_recovery_json(row[3],context,budget,source_id='security-bootstrap-migration'))
            _bootstrap_validate_receipt(receipt,row[4],'security-task-initialization-receipt',bundle)
            with _security_bootstrap_source_facts(connection,row[0],context) as sources:
                identity=semantic_record_digest({'contract':'security-bootstrap-identity-v1','value':sources['identity']})
                baseline=semantic_record_digest({'contract':'security-bootstrap-baselines-v1','value':sources['baselines']})
                request=semantic_record_digest({'contract':'security-bootstrap-request-v1','value':dict(
                    task_id=row[0],request_id=row[1],expected_revision=receipt['initial_task_revision'],
                    expected_snapshot_digest=receipt['initial_snapshot_digest'],identity_digest=identity)})
                if (receipt['task_id']!=row[0] or receipt['request_id']!=row[1]
                        or receipt['request_digest']!=row[2] or row[2]!=request
                        or receipt['identity_digest']!=identity or receipt['baseline_refs_digest']!=baseline
                        or receipt['scope_approval_digest']!=sources['scope_approval_digest']
                        or receipt['installation_receipt_digest']!=installation['receipt_digest']):
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                _bootstrap_validate_initial_state(receipt,sources)
                state,_digest=SecurityStateRepository._load_task_state(connection,row[0],context)
                try:_validate_current_binding(state,sources,bundle)
                finally:budget.release_projection(state)
    return _BOOTSTRAP_TABLES


def _initialize_security_bootstrap_locked(connection, factory, activation, bundle, fault):
    import sys
    from .migration import InstallationMigrationRepository
    caller=sys._getframe(1)
    if (caller.f_code is not InstallationMigrationRepository.initialize_security_storage.__code__
            or type(caller.f_locals.get('self')) is not InstallationMigrationRepository):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
    _bootstrap_require_owned_transaction(connection,factory)
    if _bootstrap_schema_present(connection):
        return _bootstrap_installation_locked(connection,factory,bundle)
    if (connection.execute('SELECT 1 FROM security_runtime_installation LIMIT 1').fetchone()
            or connection.execute('SELECT 1 FROM task_security_states LIMIT 1').fetchone()):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_CONFLICT')
    fault('security-bootstrap.before-insert')
    for statement in (*_BOOTSTRAP_SCHEMA,*_BOOTSTRAP_TRIGGERS): connection.execute(statement)
    manifest=bundle['manifest'];foundation=bundle['foundation']
    connection.execute('INSERT INTO security_runtime_installation VALUES(1,?,?,?,?,?)',
        (canonical_text(manifest),manifest['manifest_id'],manifest['manifest_digest'],foundation.registry_id,foundation.registry_digest))
    fault('security-bootstrap.between-installation-writes')
    receipt=dict(schema_version='1.0.0',origin_installation_id=activation.installation_id,
        origin_repository_id=activation.repository_id,origin_activation_epoch=activation.activation_epoch,
        descriptor_digest=bundle['descriptor']['descriptor_digest'],resource_vector_digest=bundle['resource_vector_digest'],
        manifest_digest=manifest['manifest_digest'],schema_registry_digest=foundation.registry_digest)
    receipt['receipt_digest']=_bootstrap_digest(receipt,'security-installation-receipt',bundle['context'])
    _bootstrap_validate_receipt(receipt,receipt['receipt_digest'],'security-installation-receipt',bundle)
    connection.execute('INSERT INTO security_bootstrap_installation_receipts VALUES(1,?,?)',
                       (canonical_text(receipt),receipt['receipt_digest']))
    from .clock import strict_trusted_now
    connection.execute("INSERT INTO schema_versions VALUES('security-bootstrap','1.0.0',?)",(str(strict_trusted_now(connection)),))
    return _bootstrap_installation_locked(connection,factory,bundle)


_STATE_KEYS = frozenset({
    "schema_version",
    "task_id",
    "task_revision",
    "task_snapshot_digest",
    "binding",
    "destinations",
    "authority_digests",
    "data_refs",
    "evidence_expectations",
    "retention_subjects",
})
_JOURNAL_KEYS = frozenset({
    "schema_version",
    "receipt_id",
    "task_id",
    "action_id",
    "prepared_action_digest",
    "task_snapshot_digest",
    "receipt",
    "reconciliation_digest",
})


@dataclass(frozen=True, slots=True)
class InstalledSecurityRuntimeRecord:
    manifest: Mapping[str, object]
    manifest_id: str
    manifest_digest: str
    schema_registry_id: str
    schema_registry_digest: str


@dataclass(frozen=True, slots=True)
class CurrentTaskSecurityState:
    state: Mapping[str, object]
    state_digest: str
    current_time: str


@dataclass(frozen=True, slots=True)
class ReadOnlyTaskSecurityState:
    """Immutable current facts, without clock or mutation authority."""

    state: FrozenMap
    state_digest: str


@dataclass(frozen=True, slots=True)
class CurrentDisclosureJournalEntry:
    entry: Mapping[str, object]
    entry_digest: str


@dataclass(frozen=True, slots=True)
class ConsumedPurgeAuthorization:
    authorization_id: str
    task_id: str
    subject_ref: str
    subject_snapshot_digest: str
    security_state_digest: str
    decision_digest: str
    consumed_at_ns: int


class SecurityStateRepository:
    """Read current durable security state and consume purge fences atomically.

    This component deliberately has no public method that writes trust inputs.
    Task state and action-journal rows are committed by application transitions;
    installation state is created by the repository installation/migration path.
    """

    def __init__(self, factory: ConnectionFactory) -> None:
        if type(factory) is not ConnectionFactory:
            raise RepositoryIntegrityError("security state requires an attested repository")
        self._factory = factory

    @classmethod
    def _change_action_membership_locked(cls, connection, task_id, authority_digest,
                                         present, context, expected_digest):
        """CAS one membership in the caller's registration/revocation transaction."""
        state, digest = cls._load_task_state(connection, task_id, context)
        if digest != expected_digest:
            raise RepositoryConflictError("action security membership lost its CAS")
        values = set(state["authority_digests"])
        if present:
            values.add(authority_digest)
        else:
            values.discard(authority_digest)
        state["authority_digests"] = sorted(values)
        body = canonical_text(state)
        new_digest = semantic_record_digest({"contract":"task-security-state-v1", "value":state})
        if connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=? AND state_digest=?",
                (body,new_digest,task_id,expected_digest)).rowcount != 1:
            raise RepositoryConflictError("action security membership lost its CAS")
        return new_digest

    @classmethod
    def _refresh_learning_subject_locked(cls,connection,task_id,policy_digest,changed_at_ns,max_bytes):
        """Invalidate existing PMF retention decisions; never invent trust roots."""
        import hashlib
        from .codec import parse_canonical_json,canonical_json
        size=connection.execute('SELECT length(CAST(state_json AS BLOB)) FROM task_security_states WHERE task_id=?',
            (task_id,)).fetchone()
        if size is None:return
        if size[0]>max_bytes:raise RepositoryIntegrityError('learning security state exceeds bound')
        row=connection.execute('SELECT s.state_json,s.state_digest,s.task_revision,s.task_snapshot_digest,t.revision,t.snapshot_digest '
            'FROM task_security_states s JOIN tasks t ON t.task_id=s.task_id WHERE s.task_id=?',(task_id,)).fetchone()
        state=parse_canonical_json(row[0])
        if (type(state) is not dict or set(state)!=_STATE_KEYS or row[2:]!=(row[4],row[5],row[4],row[5])
                or semantic_record_digest({'contract':'task-security-state-v1','value':state})!=row[1]):
            raise RepositoryIntegrityError('learning security state is not current')
        ref='learning:'+hashlib.sha256(policy_digest.encode()).hexdigest()
        subject=state['retention_subjects'].get(ref)
        if subject is None:return
        if (type(subject) is not dict or subject.get('category')!='pmf-aggregate'
                or type(subject.get('revision')) is not int or not 0<=subject['revision']<2**53-1):
            raise RepositoryIntegrityError('learning retention subject is invalid')
        subject['revision']+=1
        subject['snapshot_digest']=row[5]
        if changed_at_ns is not None:subject['created_at']=cls._clock_text(changed_at_ns)
        body=canonical_json(state)
        if len(body.encode())>max_bytes:raise RepositoryIntegrityError('learning security state exceeds bound')
        digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
        if connection.execute('UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=? AND state_digest=?',
                (body,digest,task_id,row[1])).rowcount!=1:
            raise RepositoryConflictError('learning security refresh lost its CAS')

    @staticmethod
    def _mapping(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
        if type(value) is not dict or set(value) != keys:
            raise RepositoryIntegrityError(f"{label} shape is not exact")
        return value

    @staticmethod
    def _identity(value: object, label: str) -> str:
        if type(value) is not str or not value or value != value.strip() or "\x00" in value:
            raise RepositoryIntegrityError(f"{label} is invalid")
        return value

    @staticmethod
    def _clock_text(value: int) -> str:
        try:
            result = datetime.datetime.fromtimestamp(
                value / 1_000_000_000,
                tz=datetime.timezone.utc,
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError) as error:
            raise RepositoryIntegrityError("repository security clock is invalid") from error
        return result

    @staticmethod
    def _parse_document(
        value: object,
        *,
        context: WorkContext,
        source_id: str,
    ) -> object:
        """Parse a durable canonical document inside the caller's work limits."""

        if type(value) is not str or type(context) is not WorkContext:
            raise RepositoryIntegrityError("durable security document input is invalid")
        try:
            body = value.encode("utf-8", errors="strict")
            parsed = parse_json(
                body,
                context=context,
                source_id=source_id,
                operation_path=context.child_path(()),
            )
            if canonical_text(parsed) != value:
                raise RepositoryIntegrityError("stored JSON is not canonical")
        except RepositoryIntegrityError:
            raise
        except (MemoryError, RecursionError, UnicodeError, TypeError, ValueError) as error:
            raise RepositoryIntegrityError("durable security document is invalid") from error
        return parsed

    def load_installed_runtime(
        self,
        context: WorkContext,
    ) -> InstalledSecurityRuntimeRecord:
        """Load the one immutable installation pin; callers cannot supply a substitute."""

        from .repository import _recovery_scope, _recovery_rows, _recovery_json
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        with _recovery_scope(context, self) as budget, ExitStack() as stack:
            connection = stack.enter_context(self._factory.open("doctor"))
            captured = stack.enter_context(_recovery_rows(connection,
                [("installation", ("manifest_json", "manifest_id", "manifest_digest",
                   "schema_registry_id", "schema_registry_digest"),
                  "security_runtime_installation WHERE singleton=1")],
                {}, context, budget, source_id="security-runtime-installation"))
            rows = captured["installation"]
            if len(rows) != 1:
                raise RepositoryIntegrityError("installed security runtime is missing")
            row = rows[0]
            manifest = stack.enter_context(_recovery_json(row[0], context, budget, source_id="security-runtime-installation"))
            if type(manifest) is not dict:
                raise RepositoryIntegrityError("installed security runtime is not an object")
            manifest_id = self._identity(row[1], "installed security runtime ID")
            manifest_digest = require_jcs_digest(row[2])
            registry_id = self._identity(row[3], "installed security schema registry ID")
            registry_digest = require_jcs_digest(row[4])
            if (
                manifest.get("manifest_id") != manifest_id
                or manifest.get("manifest_digest") != manifest_digest
                or not isinstance(manifest.get("schema_registry"), dict)
                or manifest["schema_registry"].get("registry_id") != registry_id
                or manifest["schema_registry"].get("registry_digest") != registry_digest
            ):
                raise RepositoryIntegrityError("installed security runtime row is inconsistent")
            size = canonical_byte_length(manifest)
            with budget.reserve(context, units=4 * size, byte_count=size,
                    source_id="security-runtime-installation") as reservation:
                result = InstalledSecurityRuntimeRecord(MappingProxyType(manifest),
                    manifest_id, manifest_digest, registry_id, registry_digest)
                reservation.transfer(result)
                return result

    @classmethod
    def _load_task_state(
        cls,
        connection: ManagedConnection,
        task_id: str,
        context: WorkContext,
    ) -> tuple[dict[str, object], str]:
        from .repository import _recovery_scope, _recovery_rows, _recovery_json
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        task_id = cls._identity(task_id, "task ID")
        with _recovery_scope(context) as budget, ExitStack() as stack:
            captured = stack.enter_context(_recovery_rows(connection,
                [("state", ("s.task_revision", "s.task_snapshot_digest", "s.state_json", "s.state_digest",
                  "t.revision", "t.snapshot_digest", "t.integrity_status"),
                  "task_security_states s JOIN tasks t ON t.task_id=s.task_id WHERE s.task_id=:task_id")],
                {"task_id": task_id}, context, budget, source_id="task-security-state"))
            rows = captured["state"]
            if len(rows) != 1:
                raise RepositoryIntegrityError("current task security state is missing")
            task_revision, snapshot_digest, state_json, state_digest, current_revision, current_snapshot, status = rows[0]
            if (
                type(task_revision) is not int
                or type(current_revision) is not int
                or task_revision != current_revision
                or snapshot_digest != current_snapshot
                or status != "ok"
            ):
                raise RepositoryIntegrityError("task security state is stale or task integrity is blocked")
            require_jcs_digest(snapshot_digest)
            require_jcs_digest(state_digest)
            state = cls._mapping(
                stack.enter_context(_recovery_json(state_json, context, budget,
                    source_id=f"task-security-state:{task_id}")),
                _STATE_KEYS,
                "task security state",
            )
            if (
                state.get("schema_version") != "1.0.0"
                or state.get("task_id") != task_id
                or type(state.get("task_revision")) is not int
                or state.get("task_revision") != task_revision
                or state.get("task_snapshot_digest") != snapshot_digest
                or not isinstance(state.get("binding"), dict)
                or state["binding"].get("task_id") != task_id
                or state["binding"].get("snapshot_digest") != snapshot_digest
            ):
                raise RepositoryIntegrityError("task security state does not bind the current task")
            actual = semantic_record_digest({
                "contract": "task-security-state-v1",
                "value": state,
            })
            if not hmac.compare_digest(state_digest, actual):
                raise RepositoryIntegrityError("task security state digest mismatch")
            for field in (
                "destinations",
                "data_refs",
                "evidence_expectations",
                "retention_subjects",
            ):
                if type(state.get(field)) is not dict:
                    raise RepositoryIntegrityError(f"task security {field} is invalid")
            authorities = state.get("authority_digests")
            if (
                type(authorities) is not list
                or authorities != sorted(set(authorities))
            ):
                raise RepositoryIntegrityError("task security authority digests are not canonical")
            for digest in authorities:
                require_jcs_digest(digest)
            size = canonical_byte_length(state)
            with budget.reserve(context, units=4 * size, byte_count=size,
                    source_id="security-state-result") as reservation:
                reservation.transfer(state)
            return state, state_digest

    def load_current_task_state_readonly(
        self,
        task_id: str,
        context: WorkContext,
    ) -> ReadOnlyTaskSecurityState:
        """Read one joined current row with SQLite-enforced zero-write access."""

        from .repository import _recovery_scope, _recovery_freeze

        with _recovery_scope(context, self) as budget:
            with self._factory.open("doctor") as connection:
                state, state_digest = self._load_task_state(connection, task_id, context)
            try:
                frozen = _recovery_freeze(state, context, budget, source_id="security-state-result")
                assert type(frozen) is FrozenMap
                result = ReadOnlyTaskSecurityState(frozen, state_digest)
                budget.move_projection(frozen, result)
                return result
            finally:
                budget.release_projection(state)

    def load_current_task_state(
        self,
        task_id: str,
        context: WorkContext,
    ) -> CurrentTaskSecurityState:
        """Read task state and the persisted non-decreasing clock in one transaction."""

        with self._factory.open("application") as connection:
            with connection.transaction():
                state, state_digest = self._load_task_state(connection, task_id, context)
                now = trusted_now(connection)
        return CurrentTaskSecurityState(
            MappingProxyType(state),
            state_digest,
            self._clock_text(now),
        )

    def load_disclosure_journal(
        self,
        receipt_id: str,
        context: WorkContext,
    ) -> CurrentDisclosureJournalEntry:
        """Read only a delivered/reconciled durable journal entry for a current task."""

        receipt_id = self._identity(receipt_id, "receipt ID")
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT task_id,entry_json,entry_digest,reconciliation_state "
                    "FROM disclosure_journal WHERE receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                if row is None or row[3] not in {"delivered", "reconciled"}:
                    raise RepositoryIntegrityError("durable disclosure receipt is not delivered")
                state, _state_digest = self._load_task_state(connection, row[0], context)
                entry = self._mapping(
                    self._parse_document(
                        row[1],
                        context=context,
                        source_id=f"disclosure-journal:{receipt_id}",
                    ),
                    _JOURNAL_KEYS,
                    "disclosure journal entry",
                )
                entry_digest = require_jcs_digest(row[2])
                actual = semantic_record_digest({
                    "contract": "disclosure-journal-entry-v1",
                    "value": entry,
                    "reconciliation_state": row[3],
                })
                if not hmac.compare_digest(entry_digest, actual):
                    raise RepositoryIntegrityError("disclosure journal entry digest mismatch")
                receipt = entry.get("receipt")
                if (
                    entry.get("schema_version") != "1.0.0"
                    or entry.get("receipt_id") != receipt_id
                    or entry.get("task_id") != state["task_id"]
                    or entry.get("task_snapshot_digest") != state["task_snapshot_digest"]
                    or type(receipt) is not dict
                    or receipt.get("receipt_id") != receipt_id
                    or receipt.get("plan_digest") is None
                    or receipt.get("payload_digest") is None
                    or receipt.get("destination_identity_ref") is None
                    or receipt.get("receipt_digest") is None
                    or entry.get("prepared_action_digest") is None
                    or entry.get("reconciliation_digest") is None
                ):
                    raise RepositoryIntegrityError("disclosure journal entry binding is invalid")
                for field in (
                    "prepared_action_digest",
                    "task_snapshot_digest",
                    "reconciliation_digest",
                ):
                    require_jcs_digest(entry[field])
                for field in (
                    "plan_digest",
                    "payload_digest",
                    "target_receipt_digest",
                    "receipt_digest",
                ):
                    require_jcs_digest(receipt[field])
        return CurrentDisclosureJournalEntry(MappingProxyType(entry), entry_digest)

    def authorize_purge(
        self,
        task_id: str,
        decision: RetentionDecision,
        context: WorkContext,
    ) -> ConsumedPurgeAuthorization:
        """Re-read current blockers and atomically consume one exact purge decision."""

        if type(decision) is not RetentionDecision or decision.action != "purge":
            raise RepositoryIntegrityError("only an engine-issued purge decision can be authorized")
        task_id = self._identity(task_id, "task ID")
        with self._factory.open("application") as connection:
            with connection.transaction():
                return self._authorize_purge_locked(connection,task_id,decision,context)

    def _authorize_purge_locked(self,connection,task_id,decision,context):
        self._factory._require_owned_transaction(connection)
        if type(decision) is not RetentionDecision or decision.action!='purge':
            raise RepositoryIntegrityError('only a purge decision can be consumed')
        state, state_digest = self._load_task_state(connection, task_id, context)
        if not hmac.compare_digest(decision.task_context_digest, state_digest):
            raise RepositoryConflictError("purge decision is stale for current security state")
        subjects = state["retention_subjects"]
        assert isinstance(subjects, dict)
        subject = subjects.get(decision.subject_ref)
        if type(subject) is not dict:
            raise RepositoryIntegrityError("retention subject is not current")
        snapshot_digest = require_jcs_digest(subject.get("snapshot_digest"))
        if not hmac.compare_digest(snapshot_digest, decision.subject_snapshot_digest):
            raise RepositoryConflictError("retention subject changed after decision")
        if subject.get("sensitivity") == "secret" or any(
            subject.get(field) is not False
            for field in ("legal_hold", "rollback_dependency", "unresolved_action")
        ):
            raise RepositoryConflictError("current durable retention blockers forbid purge")
        unresolved = connection.execute(
            "SELECT 1 FROM claims WHERE task_id=? AND state='unresolved' LIMIT 1",
            (task_id,),
        ).fetchone()
        if unresolved is not None:
            raise RepositoryConflictError("current unresolved action claim forbids purge")
        if decision.tombstone_required is not True:
            raise RepositoryIntegrityError("purge authorization requires an audit tombstone")
        decision_value = {
            "action": decision.action,
            "subject_ref": decision.subject_ref,
            "category": decision.category,
            "trigger": decision.trigger,
            "tombstone_required": decision.tombstone_required,
            "reason": decision.reason,
            "subject_snapshot_digest": decision.subject_snapshot_digest,
            "security_state_digest": decision.task_context_digest,
        }
        decision_digest = semantic_record_digest({
            "contract": "retention-decision-v1",
            "value": decision_value,
        })
        authorization_id = semantic_record_digest({
            "contract": "consumed-purge-authorization-v1",
            "task_id": task_id,
            "decision_digest": decision_digest,
        })
        consumed_at = trusted_now(connection)
        try:
            connection.execute(
                "INSERT INTO purge_authorizations(authorization_id,task_id,subject_ref,"
                "subject_snapshot_digest,security_state_digest,decision_digest,consumed_at_ns) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    authorization_id,
                    task_id,
                    decision.subject_ref,
                    snapshot_digest,
                    state_digest,
                    decision_digest,
                    consumed_at,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise RepositoryConflictError("purge decision was already consumed") from error
        return ConsumedPurgeAuthorization(
            authorization_id,
            task_id,
            decision.subject_ref,
            snapshot_digest,
            state_digest,
            decision_digest,
            consumed_at,
        )
