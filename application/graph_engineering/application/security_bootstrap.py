"""Task security initialization from issued runtime and committed approvals."""
from __future__ import annotations

import sqlite3
import sys
from contextlib import ExitStack

from graph_engineering.core.contracts import canonical_text
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.security._common import require_id, require_digest
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.graph.state import DomainEvent, apply_events
from graph_engineering.storage.codec import semantic_record_digest
from graph_engineering.storage.errors import RepositoryError
from graph_engineering.storage.repository import TaskRepository, _security_bootstrap_sources_locked
from graph_engineering.storage.security import (SecurityBootstrapError, SecurityStateRepository,
    _bootstrap_bundle, _bootstrap_digest, _bootstrap_validate_receipt, _bootstrap_installation_locked,
    _validate_current_binding, _bootstrap_initial_state, _bootstrap_validate_initial_state)
from .tasks import TaskApplication, RuntimeContext


class SecurityBootstrapService:
    """No caller-selected state, schemas, policies, targets or authority."""

    def __init__(self, application):
        if type(application) is not TaskApplication or type(application._repository) is not TaskRepository:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
        self._application=application
        self._repository=application._repository
        self._factory=self._repository._factory
        if (not self._factory.command_context_bound or self._repository.command_scope is None
                or self._factory._command_scope is not self._repository.command_scope):
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')

    def _validate_sources(self, sources, runtime):
        identity=sources['identity']
        if identity!={'task_id':identity['task_id'],'owner_id':runtime.owner_id,
            'runtime_kind':runtime.runtime_kind,'runtime_lineage_id':runtime.runtime_lineage_id}:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
        application=self._application
        view=application._restore(sources['snapshot'])
        application._repository_sequence(view,sources['events'])
        replayed=None;ordinal=0
        materialization=application._materialization_for_graph_ref(identity['task_id'],view.snapshot.graph_ref)
        for event in sources['events']:
            if event['event_type'] in application._ACTION_EVENT_TYPES:continue
            ordinal+=1
            replayed=apply_events(replayed,(DomainEvent(ordinal,ordinal-1,event['event_type'],event['payload']),),
                schema_registry=application._schemas,context=application._context,materialization_record=materialization)
        if replayed is None or replayed.snapshot_digest!=view.snapshot.snapshot_digest:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')

    def initialize_task(self, task_id: str, request_id: str, expected_revision: int,
                        expected_snapshot_digest: str, runtime: RuntimeContext) -> FrozenMap:
        """Commit empty executable authority and its receipt atomically; replay preserves state."""
        try:
            if type(runtime) is not RuntimeContext:
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
            try:runtime.require_issued()
            except (TypeError,ValueError,RuntimeError):
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY') from None
            require_id(task_id,'task');require_id(request_id,'request');require_digest(expected_snapshot_digest,'snapshot')
            if type(expected_revision) is not int or not 1<=expected_revision<=9007199254740991:
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
            scope=self._repository.command_scope;scope.require_current()
            bundle=_bootstrap_bundle(self._application._context)
            if runtime.runtime_kind not in bundle['manifest']['allowed_runtime_kinds']:
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
            with self._factory.open('application') as connection, connection.transaction():
                installation=_bootstrap_installation_locked(connection,self._factory,bundle)
                owner_head=connection.execute('SELECT revision FROM tasks WHERE task_id=? AND integrity_status=\'ok\' '
                    'AND json_extract(snapshot_json,\'$.domain.identity.owner_id\')=? '
                    'AND json_extract(snapshot_json,\'$.domain.identity.runtime_kind\')=? '
                    'AND json_extract(snapshot_json,\'$.domain.identity.runtime_lineage_id\')=?',
                    (task_id,runtime.owner_id,runtime.runtime_kind,runtime.runtime_lineage_id)).fetchone()
                if owner_head is None:
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
                with _security_bootstrap_sources_locked(connection,self._factory,task_id,self._application._context) as sources:
                    self._validate_sources(sources,runtime)
                    identity_digest=semantic_record_digest({'contract':'security-bootstrap-identity-v1','value':sources['identity']})
                    baseline_digest=semantic_record_digest({'contract':'security-bootstrap-baselines-v1','value':sources['baselines']})
                    request_digest=semantic_record_digest({'contract':'security-bootstrap-request-v1','value':dict(
                        task_id=task_id,request_id=request_id,expected_revision=expected_revision,
                        expected_snapshot_digest=expected_snapshot_digest,identity_digest=identity_digest)})
                    receipt=self._initialize_locked(connection,task_id,request_id,request_digest,expected_revision,
                        expected_snapshot_digest,sources,identity_digest,baseline_digest,installation,bundle)
                    current_cas=(sources['revision'],sources['snapshot_digest'])
                    source_binding=(identity_digest,baseline_digest,sources['scope_approval_digest'])
                sources=None
                self._repository._fault('security-bootstrap.task-before-commit')
                runtime.require_issued();scope.require_current()
                _bootstrap_installation_locked(connection,self._factory,_bootstrap_bundle(self._application._context))
                if connection.execute('SELECT revision,snapshot_digest FROM tasks WHERE task_id=?',(task_id,)).fetchone()!=current_cas:
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                with _security_bootstrap_sources_locked(connection,self._factory,task_id,self._application._context) as current:
                    self._validate_sources(current,runtime)
                    if source_binding!=(
                        semantic_record_digest({'contract':'security-bootstrap-identity-v1','value':current['identity']}),
                        semantic_record_digest({'contract':'security-bootstrap-baselines-v1','value':current['baselines']}),
                        current['scope_approval_digest']):
                        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                current=None
            self._repository._fault('security-bootstrap.task-after-commit')
            return receipt
        except SecurityBootstrapError:
            raise
        except (RepositoryError, sqlite3.DatabaseError, TypeError, ValueError, KeyError, RuntimeError):
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY') from None

    def _initialize_locked(self, connection, task_id, request_id, request_digest, revision, snapshot_digest,
                           sources, identity_digest, baseline_digest, installation, bundle):
        from graph_engineering.storage.repository import _recovery_scope, _recovery_rows, _recovery_json
        self._factory._require_owned_transaction(connection)
        caller=sys._getframe(1)
        if caller.f_code is not type(self).initialize_task.__code__ or caller.f_locals.get('self') is not self:
            raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
        context=self._application._context
        with _recovery_scope(context) as budget, ExitStack() as stack:
            rows=stack.enter_context(_recovery_rows(connection,[
                ('receipt',('task_id','request_id','request_digest','receipt_json','receipt_digest'),
                 'security_bootstrap_task_receipts WHERE task_id=:task_id OR request_id=:request_id'),
                ('state',('task_id',),'task_security_states WHERE task_id=:task_id')],
                {'task_id':task_id,'request_id':request_id},context,budget,source_id='security-bootstrap-task'))
            if rows['receipt']:
                if len(rows['receipt'])!=1 or not rows['state'] or rows['receipt'][0][:3]!=(task_id,request_id,request_digest):
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_CONFLICT')
                row=rows['receipt'][0]
                receipt=stack.enter_context(_recovery_json(row[3],context,budget,source_id='security-bootstrap-task'))
                _bootstrap_validate_receipt(receipt,row[4],'security-task-initialization-receipt',bundle)
                if (receipt['task_id']!=task_id or receipt['request_id']!=request_id or receipt['request_digest']!=request_digest
                        or receipt['initial_task_revision']!=revision or receipt['initial_snapshot_digest']!=snapshot_digest
                        or receipt['installation_receipt_digest']!=installation['receipt_digest']
                        or receipt['identity_digest']!=identity_digest or receipt['baseline_refs_digest']!=baseline_digest
                        or receipt['scope_approval_digest']!=sources['scope_approval_digest']):
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                _bootstrap_validate_initial_state(receipt,sources)
                state,_digest=SecurityStateRepository._load_task_state(connection,task_id,context)
                stack.callback(budget.release_projection,state)
                _validate_current_binding(state,sources,bundle)
                return freeze(receipt)
            if rows['state']:
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_CONFLICT')
            if (revision,snapshot_digest)!=(sources['revision'],sources['snapshot_digest']):
                raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
            state=_bootstrap_initial_state(sources,revision,snapshot_digest)
            _validate_current_binding(state,sources,bundle)
            state_digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
            receipt=dict(schema_version='1.0.0',task_id=task_id,request_id=request_id,request_digest=request_digest,
                installation_receipt_digest=installation['receipt_digest'],initial_task_revision=revision,
                initial_snapshot_digest=snapshot_digest,initial_state_digest=state_digest,identity_digest=identity_digest,
                baseline_refs_digest=baseline_digest,scope_approval_digest=sources['scope_approval_digest'])
            receipt['receipt_digest']=_bootstrap_digest(receipt,'security-task-initialization-receipt',context)
            _bootstrap_validate_receipt(receipt,receipt['receipt_digest'],'security-task-initialization-receipt',bundle)
            self._repository._fault('security-bootstrap.task-before-insert')
            connection.execute('INSERT INTO task_security_states VALUES(?,?,?,?,?)',
                (task_id,revision,snapshot_digest,canonical_text(state),state_digest))
            self._repository._fault('security-bootstrap.task-between-writes')
            connection.execute('INSERT INTO security_bootstrap_task_receipts VALUES(?,?,?,?,?)',
                (task_id,request_id,request_digest,canonical_text(receipt),receipt['receipt_digest']))
            return freeze(receipt)




def _guard_bootstrap_locked(connection, factory, context, *, task_id=None, expected_state_digest=None,
                            require_provenance=False, schema_registry=None):
    """Read-only trust admission inside an application-owned transaction."""
    from graph_engineering.storage.security import _bootstrap_schema_present
    from graph_engineering.storage.repository import _recovery_scope, _recovery_rows, _recovery_json
    present=_bootstrap_schema_present(connection)
    if not present and not require_provenance:return False
    factory._require_owned_transaction(connection)
    scope=factory._command_scope
    if not factory.command_context_bound or scope is None:
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_AUTHORITY')
    scope.require_current()
    bundle=_bootstrap_bundle(context)
    installation=_bootstrap_installation_locked(connection,factory,bundle)
    if schema_registry is not None and (schema_registry.registry_id!=bundle['foundation'].registry_id
            or schema_registry.registry_digest!=bundle['foundation'].registry_digest):
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_RESOURCE')
    # A partial root cannot hide an unreceipted state behind an unrelated task selector.
    if connection.execute('SELECT 1 FROM task_security_states s LEFT JOIN security_bootstrap_task_receipts r '
        'ON r.task_id=s.task_id WHERE r.task_id IS NULL UNION ALL '
        'SELECT 1 FROM security_bootstrap_task_receipts r LEFT JOIN task_security_states s '
        'ON s.task_id=r.task_id WHERE s.task_id IS NULL LIMIT 1').fetchone():
        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
    if task_id is None:
        from graph_engineering.storage.security import _bootstrap_migration_facts
        _bootstrap_migration_facts(connection,bundle=bundle)
    else:
        with _recovery_scope(context) as budget, ExitStack() as stack:
            rows=stack.enter_context(_recovery_rows(connection,[
                ('receipt',('request_id','request_digest','receipt_json','receipt_digest'),
                 'security_bootstrap_task_receipts WHERE task_id=:task_id')],{'task_id':task_id},context,budget,
                 source_id='security-bootstrap-issuance'))['receipt']
            if len(rows)!=1:raise SecurityBootstrapError('SECURITY_BOOTSTRAP_INTEGRITY')
            row=rows[0]
            receipt=stack.enter_context(_recovery_json(row[2],context,budget,source_id='security-bootstrap-issuance'))
            _bootstrap_validate_receipt(receipt,row[3],'security-task-initialization-receipt',bundle)
            with _security_bootstrap_sources_locked(connection,factory,task_id,context) as sources:
                identity_digest=semantic_record_digest({'contract':'security-bootstrap-identity-v1','value':sources['identity']})
                baseline_digest=semantic_record_digest({'contract':'security-bootstrap-baselines-v1','value':sources['baselines']})
                request_digest=semantic_record_digest({'contract':'security-bootstrap-request-v1','value':dict(
                    task_id=task_id,request_id=row[0],expected_revision=receipt['initial_task_revision'],
                    expected_snapshot_digest=receipt['initial_snapshot_digest'],identity_digest=identity_digest)})
                if (receipt['task_id']!=task_id or receipt['request_id']!=row[0]
                        or receipt['request_digest']!=row[1] or row[1]!=request_digest
                        or receipt['installation_receipt_digest']!=installation['receipt_digest']
                        or receipt['identity_digest']!=identity_digest or receipt['baseline_refs_digest']!=baseline_digest
                        or receipt['scope_approval_digest']!=sources['scope_approval_digest']):
                    raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                _bootstrap_validate_initial_state(receipt,sources)
                state,digest=SecurityStateRepository._load_task_state(connection,task_id,context)
                try:
                    if expected_state_digest is not None and digest!=expected_state_digest:
                        raise SecurityBootstrapError('SECURITY_BOOTSTRAP_STALE')
                    _validate_current_binding(state,sources,bundle)
                finally:budget.release_projection(state)
    scope.require_current()
    _bootstrap_installation_locked(connection,factory,_bootstrap_bundle(context))
    return True
