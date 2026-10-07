"""Human action registration with short repository scopes around the human wait."""
from __future__ import annotations

import datetime
import secrets
from contextlib import contextmanager

from graph_engineering.application.runtime import RuntimeSession
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.core.action_authority import (
    ActionAuthorityError, AuthorityChallenge, ActionHumanRequestV1, signed,
    timestamp_ns, require_epoch,
)
from graph_engineering.core.actions import AuthorityEnvelope
from graph_engineering.storage.action_authority import ActionAuthorityLedger, installed_policy
from graph_engineering.storage.actions import ActionJournalRepository
from graph_engineering.storage.security import SecurityStateRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.storage.clock import strict_trusted_now
from graph_engineering.storage.codec import semantic_record_digest


_PRECONDITIONS = ('expected_task_revision','expected_snapshot_digest',
                 'expected_security_digest','expected_journal_revision')


class ActionAuthorizationApplication:
    def __init__(self, manager: InstallationMigrationRepository, *, schema_registry: object,
                 context: object, fault_hook=lambda _point:None) -> None:
        if type(manager) is not InstallationMigrationRepository:
            raise ActionAuthorityError('invalid_request')
        self._manager=manager
        self._schemas=schema_registry
        self._context=context
        self._fault=fault_hook

    @contextmanager
    def _scope(self):
        with self._manager.command_scope() as scope:
            _manifest,base=self._manager._current_factory(scope._control_token())
            factory=base.bind_command_scope(scope)
            ledger=ActionAuthorityLedger(factory,installed_policy())
            journal=ActionJournalRepository(factory,schema_registry=self._schemas,context=self._context)
            issuer=SecurityContextIssuer(SecurityStateRepository(factory),schema_registry=self._schemas,context=self._context)
            yield ledger,journal,issuer

    @staticmethod
    def _identity(session, task_context):
        if type(session) is not RuntimeSession:
            raise ActionAuthorityError('identity_mismatch')
        session.require_current()
        binding=task_context.binding
        if (binding.owner_id!=session.proof.owner_id
                or binding.runtime_kind!=session.capabilities.runtime_kind
                or binding.runtime_lineage_id!=session.proof.lineage_id):
            raise ActionAuthorityError('identity_mismatch')

    def _current(self, connection, session, ledger, journal, issuer, ch, *, precondition):
        session.require_current()
        require_epoch((ch.installation_id,ch.repository_id,ch.activation_epoch),ledger._epoch())
        context=issuer._issue_task_context_locked(connection,ch.task_id)
        self._identity(session,context)
        record=journal._load(connection,ch.action_id)
        prepared=record.prepared
        binding=context.binding
        if (prepared.task_id!=ch.task_id or prepared.prepared_action_digest!=ch.prepared_action_digest
                or prepared.action_kind!=ch.action_kind or list(prepared.resources)!=list(ch.resources)
                or prepared.baseline_digest!=ch.baseline_digest or prepared.snapshot_digest!=ch.snapshot_digest
                or binding.baselines.get('intent')!=ch.baseline_digest
                or (precondition or record.state=='authorized') and binding.snapshot_digest!=ch.snapshot_digest):
            raise ActionAuthorityError('stale_binding')
        if timestamp_ns(ch.expires_at_ns)<=strict_trusted_now(connection):
            raise ActionAuthorityError('expired')
        if ch.policy_digest!=ledger.policy.policy_digest:
            raise ActionAuthorityError('stale_binding')
        if precondition:
            state,_=SecurityStateRepository._load_task_state(connection,ch.task_id,self._context)
            if (record.state!='prepared' or record.revision!=ch.journal_revision
                    or context.state_digest!=ch.security_state_digest or state['task_revision']!=ch.task_revision):
                raise ActionAuthorityError('stale_binding')
        return context,record

    @staticmethod
    def _request(value, *, preconditions=True):
        fields={'schema_version','request_id','task_id','action_id'}
        if preconditions:
            fields.update(_PRECONDITIONS)
        if type(value) is not dict or set(value)!=fields or value['schema_version']!='1.0.0':
            raise ActionAuthorityError('invalid_request')
        for key in ('request_id','task_id','action_id'):
            item=value[key]
            if type(item) is not str or not item or len(item)>128 or item!=item.strip() or '\x00' in item:
                raise ActionAuthorityError('invalid_request')
        if preconditions:
            for key in ('expected_task_revision','expected_journal_revision'):
                if type(value[key]) is not int or not 0<=value[key]<=2**53-1:
                    raise ActionAuthorityError('invalid_request')
        return dict(value)

    def authorize(self, session: RuntimeSession, request: dict[str,object]) -> dict[str,object]:
        request=self._request(request)
        if type(session) is not RuntimeSession:
            raise ActionAuthorityError('identity_mismatch')
        session.require_current()
        with self._scope() as (ledger,journal,issuer):
            with ledger.factory.open('application') as conn:
                with conn.transaction():
                    history=ledger._read_locked(conn,request['request_id'])
                    if history:
                        head=history[-1]
                        ch=AuthorityChallenge.from_dict(head['challenge'])
                        if (ch.task_id!=request['task_id'] or ch.action_id!=request['action_id']
                                or tuple(request[k] for k in _PRECONDITIONS)!=(ch.task_revision,ch.snapshot_digest,ch.security_state_digest,ch.journal_revision)):
                            raise ActionAuthorityError('request_conflict')
                        if head['event_kind'] in {'revoked','expired','rejected'}:
                            raise ActionAuthorityError('terminal_request')
                        if head['event_kind']=='approved':
                            current,record=self._current(conn,session,ledger,journal,issuer,ch,precondition=False)
                            if (head['authority']['authority_digest'] not in current.authority_digests
                                    or record.authority is None or record.authority.authority_digest!=head['authority']['authority_digest']):
                                raise ActionAuthorityError('stale_binding')
                            return {'status':self._journal_status(record.state),
                                'receipt':ledger.receipt(head).to_dict()}
                    else:
                        current=issuer._issue_task_context_locked(conn,request['task_id'])
                        self._identity(session,current)
                        record=journal._load(conn,request['action_id'])
                        prepared=record.prepared
                        state,_=SecurityStateRepository._load_task_state(conn,request['task_id'],self._context)
                        now=strict_trusted_now(conn)
                        epoch=ledger._epoch()
                        body=dict(schema_version='1.0.0',request_id=request['request_id'],task_id=request['task_id'],
                            action_id=request['action_id'],owner_id=current.binding.owner_id,
                            runtime_kind=current.binding.runtime_kind,runtime_lineage_id=current.binding.runtime_lineage_id,
                            prepared_action_digest=prepared.prepared_action_digest,action_kind=prepared.action_kind,
                            resources=list(prepared.resources),baseline_digest=prepared.baseline_digest,
                            snapshot_digest=prepared.snapshot_digest,task_revision=state['task_revision'],
                            journal_revision=record.revision,security_state_digest=current.state_digest,
                            installation_id=epoch[0],repository_id=epoch[1],activation_epoch=epoch[2],
                            policy_digest=ledger.policy.policy_digest,created_at_ns=str(now),
                            expires_at_ns=str(now+ledger.policy.max_validity_seconds*1_000_000_000))
                        ch=AuthorityChallenge.from_dict(signed('challenge',body))
                        if tuple(request[k] for k in _PRECONDITIONS)!=(ch.task_revision,ch.snapshot_digest,ch.security_state_digest,ch.journal_revision):
                            raise ActionAuthorityError('stale_binding')
                        head=ledger._create_locked(conn,ch)
                    self._current(conn,session,ledger,journal,issuer,ch,precondition=True)
                    invocation=ActionHumanRequestV1.from_dict(signed('request',dict(schema_version='1.0.0',
                        challenge=ch.to_dict(),invocation_nonce=secrets.token_hex(32),
                        invocation_generation=head['generation']+1,session_id=session.proof.session_id,
                        runtime_lineage_id=session.proof.lineage_id,dispatched_at_ns=str(strict_trusted_now(conn)))))
                    head=ledger._append_locked(conn,head,'attempt',invocation=invocation.to_dict(),decision=None)
                    self._fault('action_authority.before_attempt_commit')
        self._fault('action_authority.after_attempt_commit')
        # No installation scope or DB connection crosses the external human call.
        decision=session.request_action_decision(invocation)
        self._fault('action_authority.after_human_result')
        with self._scope() as (ledger,journal,issuer):
            with ledger.factory.open('application') as conn:
                with conn.transaction():
                    current,record=self._current(conn,session,ledger,journal,issuer,ch,precondition=True)
                    latest=ledger._read_locked(conn,ch.request_id)[-1]
                    if latest['event_digest']!=head['event_digest']:
                        raise ActionAuthorityError('stale_binding')
                    decision.require_request(invocation)
                    updates={'decision':decision.to_dict()}
                    if decision.status=='approved':
                        authority=self._authority(ch)
                        digest=SecurityStateRepository._change_action_membership_locked(conn,ch.task_id,
                            authority.authority_digest,True,self._context,current.state_digest)
                        self._fault('action_authority.after_security')
                        updated=journal._record_authorized_locked(conn,authority,record.revision)
                        self._fault('action_authority.after_journal')
                        updates.update(authority=journal.authority_document(authority),post_security_digest=digest,
                                       post_journal_revision=updated.revision)
                    terminal=ledger._append_locked(conn,latest,decision.status,**updates)
                    self._fault('action_authority.before_result_commit')
                    receipt=ledger.receipt(terminal)
        self._fault('action_authority.after_result_commit')
        return {'status':decision.status,'receipt':receipt.to_dict()}

    def _authority(self,ch):
        def stamp(value: str) -> str:
            return datetime.datetime.fromtimestamp(timestamp_ns(value)//1_000_000_000,
                datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
        body=dict(schema_version='1.0.0',authority_id='authority:'+semantic_record_digest({
            'installation_id':ch.installation_id,'repository_id':ch.repository_id,
            'activation_epoch':ch.activation_epoch,'request_id':ch.request_id}).split(':')[-1],
            task_id=ch.task_id,owner_id=ch.owner_id,runtime_kind=ch.runtime_kind,
            runtime_lineage_id=ch.runtime_lineage_id,authorized_action_kind=ch.action_kind,
            authorized_resources=list(ch.resources),prepared_action_digest=ch.prepared_action_digest,
            baseline_digest=ch.baseline_digest,snapshot_digest=ch.snapshot_digest,
            issued_at=stamp(ch.created_at_ns),expires_at=stamp(ch.expires_at_ns),status='active')
        body['authority_digest']=AuthorityEnvelope.digest_document(body,self._context)
        return AuthorityEnvelope.from_dict(body,context=self._context)

    @staticmethod
    def _journal_status(state):
        if state=='authorized':
            return 'approved'
        if state=='revoked':
            return 'revoked'
        if state in {'executing','unknown','succeeded','failed','reconciled','compensated'}:
            return 'already_started'
        return 'stale_binding'

    def status(self, session: RuntimeSession, request: dict[str,object]) -> dict[str,object]:
        request=self._request(request,preconditions=False)
        with self._scope() as (ledger,journal,issuer):
            with ledger.factory.open('application') as conn:
                with conn.transaction():
                    current=issuer._issue_task_context_locked(conn,request['task_id'])
                    self._identity(session,current)
                    history=ledger._read_locked(conn,request['request_id'])
                    if not history:
                        raise ActionAuthorityError('invalid_request')
                    head=history[-1];ch=AuthorityChallenge.from_dict(head['challenge'])
                    if ch.task_id!=request['task_id'] or ch.action_id!=request['action_id'] or ch.owner_id!=session.proof.owner_id:
                        raise ActionAuthorityError('identity_mismatch')
                    status=head['event_kind']
                    if status in {'created','attempt'}:
                        status='pending'
                    if status=='approved':
                        try:
                            context,record=self._current(conn,session,ledger,journal,issuer,ch,precondition=False)
                            if (head['authority']['authority_digest'] not in context.authority_digests
                                    or record.authority is None or record.authority.authority_digest!=head['authority']['authority_digest']):
                                status='stale_binding'
                            else:
                                status=self._journal_status(record.state)
                        except ActionAuthorityError as error:
                            status=error.code
                    return {'status':status,'receipt':ledger.receipt(head).to_dict()}

    def revoke(self, session: RuntimeSession, request: dict[str,object]) -> dict[str,object]:
        if type(request) is not dict or 'expected_generation' not in request:
            raise ActionAuthorityError('invalid_request')
        generation=request['expected_generation']
        if type(generation) is not int or not 0<=generation<=2**53-1:
            raise ActionAuthorityError('invalid_request')
        request=self._request({k:v for k,v in request.items() if k!='expected_generation'},preconditions=False)
        with self._scope() as (ledger,journal,issuer):
            with ledger.factory.open('application') as conn:
                with conn.transaction():
                    return self._revoke_locked(conn,session,request,generation,ledger,journal,issuer)

    def _revoke_locked(self, conn, session, request, generation, ledger, journal, issuer):
        ledger.factory._require_owned_transaction(conn)
        current=issuer._issue_task_context_locked(conn,request['task_id'])
        self._identity(session,current)
        history=ledger._read_locked(conn,request['request_id'])
        if not history:
            raise ActionAuthorityError('invalid_request')
        head=history[-1];ch=AuthorityChallenge.from_dict(head['challenge'])
        if ch.task_id!=request['task_id'] or ch.action_id!=request['action_id'] or ch.owner_id!=session.proof.owner_id:
            raise ActionAuthorityError('identity_mismatch')
        if head['event_kind'] in {'revoked','expired','rejected'}:
            raise ActionAuthorityError('terminal_request')
        if head['generation']!=generation:
            raise ActionAuthorityError('stale_binding')
        record=journal._load(conn,ch.action_id)
        updates={}
        state='revoked'
        revision=record.revision
        if head['authority'] is not None:
            if (record.prepared.prepared_action_digest!=ch.prepared_action_digest
                    or record.authority is None
                    or record.authority.authority_digest!=head['authority']['authority_digest']):
                raise ActionAuthorityError('stale_binding')
            digest=SecurityStateRepository._change_action_membership_locked(conn,ch.task_id,
                head['authority']['authority_digest'],False,self._context,current.state_digest)
            updates['post_security_digest']=digest
            if record.state=='authorized':
                if conn.execute("UPDATE action_journal SET state='revoked',revision=revision+1 WHERE action_id=? AND revision=? AND state=?",
                        (record.action_id,record.revision,record.state)).rowcount!=1:
                    raise ActionAuthorityError('stale_binding')
                revision=record.revision+1
            else:
                state='execution_in_progress' if record.state in {'executing','unknown'} else self._journal_status(record.state)
            updates['post_journal_revision']=revision
        terminal=ledger._append_locked(conn,head,'revoked',**updates)
        self._fault('action_authority.before_revoke_commit')
        return {'status':state,'receipt':ledger.receipt(terminal).to_dict()}
