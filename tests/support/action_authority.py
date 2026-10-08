"""Synthetic human port attached through the genuine production adapter factory."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace

from graph_engineering.adapters.runtime_adapters import RuntimeAdapterFactory
from graph_engineering.application.runtime import RuntimeSession
from tests.integration.test_wp07_runtime_parity import (
    FIXTURE, adapter_document, compatibility, executable, production_adapter_for_test,
    raw_input, resign_configuration,
)
from tests.support.runtime_resources import runtime_resource_guard


@contextmanager
def action_session(port, cell_index=0, *, owner_override=None):
    cell = FIXTURE['cells'][cell_index]
    configured = adapter_document(cell)
    if owner_override is not None:
        configured['owner_bindings'] = {key:owner_override for key in configured['owner_bindings']}
    configured['capabilities'] = sorted(set(configured['capabilities']) | {'human.action-decision.v1'})
    configured = resign_configuration(configured)
    base = production_adapter_for_test(cell, configured)
    ports = replace(base._ports, request_action_decision=port)
    factory = RuntimeAdapterFactory(runtime_resource_guard())
    create = factory.codex if cell['runtime_kind']=='codex' else factory.hermes
    adapter = create(configured, executable(), ports)
    session = RuntimeSession.establish(adapter, raw_input(cell), compatibility(cell))
    try:
        yield session
    finally:
        if not session._closed:
            session.close()


@contextmanager
def ledger_stack():
    from tests.support.wp03_repository import repository_stack
    from graph_engineering.storage.action_authority import ActionAuthorityLedger, installed_policy
    with repository_stack() as stack:
        _, factory, *_ = stack
        factory._test_installation_scope.__exit__(None,None,None)
        manager = factory._test_installation_manager
        manager.initialize_action_authority_storage()
        with manager.command_scope() as scope:
            bound = factory.bind_command_scope(scope)
            yield ActionAuthorityLedger(bound,installed_policy()), bound, scope


@contextmanager
def registration_stack(port, fault_hook=lambda _point:None, *, learning=True, action_kinds=("commit",), task_id="task:learning-1", owner_override=None):
    """Actual task transitions plus synthetic installed trust, with zero grants."""
    import json
    from tests.support.wp03_repository import repository_stack,ROOT
    from tests.support.wp05a_security import security_context,security_schema_registry,binding_document,task_security_state_document
    from tests.support.wp05_actions import prepared_document,digest
    from tests.integration.test_wp07_runtime_parity import SCHEMAS,WORK
    from tests.integration.test_wp09_learning_metric_sources import approve
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.application.action_authority import ActionAuthorizationApplication
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.core.security.identity import SecurityBinding
    from graph_engineering.core.actions import PreparedAction
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.actions import ActionJournalRepository
    from graph_engineering.storage.codec import canonical_json,semantic_record_digest
    with repository_stack() as stack, action_session(port,owner_override=owner_override) as active:
        _,base,locks,*_=stack
        base._test_installation_scope.__exit__(None,None,None)
        manager=base._test_installation_manager
        if learning:
            manager.initialize_learning_storage()
        manager.initialize_action_authority_storage()
        context=security_context();schemas=security_schema_registry(context)
        with manager.command_scope() as scope:
            factory=base.bind_command_scope(scope)
            objects=ObjectRepository(factory,locks)
            try:
                leases=ResourceLeaseRepository(factory,locks)
                repository=TaskRepository(factory,locks,objects,command_scope=scope)
                tasks=TaskApplication(repository,repository,leases,schema_registry=SCHEMAS,context=WORK)
                identity=dict(task_id=task_id,owner_id=active.proof.owner_id,
                    runtime_kind=active.capabilities.runtime_kind,runtime_lineage_id=active.proof.lineage_id)
                RuntimeMutationGateway.create(active,active.proof,identity,
                    lambda runtime:tasks.execute(identity['task_id'],TaskCommand('create',0,{'identity':identity}),runtime),
                    occurred_at='synthetic-create',lease_ttl_ns=100)
                approve(tasks,active,baseline_digest=semantic_record_digest({'intent':'synthetic action authority'}),task_id=task_id)
                with factory.open('application') as conn:
                    with conn.transaction():
                        revision,snapshot,raw=conn.execute('SELECT revision,snapshot_digest,snapshot_json FROM tasks WHERE task_id=?',(identity['task_id'],)).fetchone()
                        domain=json.loads(raw)['domain'];binding=binding_document()
                        binding.update(identity,scope_id=domain['project_scope_ref']['scope_id'],scope_digest=domain['project_scope_ref']['digest'],
                            baselines={x['kind']:x['digest'] for x in domain['baseline_refs']},snapshot_digest=snapshot)
                        binding['targets'][0]['target_digest']=digest('target')
                        binding['binding_digest']=SecurityBinding.digest_document(binding)
                        state=task_security_state_document(binding=binding)
                        state.update(task_revision=revision,task_snapshot_digest=snapshot,authority_digests=[])
                        state_digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                        conn.execute('INSERT INTO task_security_states VALUES(?,?,?,?,?)',(identity['task_id'],revision,snapshot,canonical_json(state),state_digest))
                        manifest=json.loads((ROOT/'config/security/security-runtime-v1.json').read_text())
                        conn.execute('INSERT INTO security_runtime_installation VALUES(1,?,?,?,?,?)',
                            (canonical_json(manifest),manifest['manifest_id'],manifest['manifest_digest'],manifest['schema_registry']['registry_id'],manifest['schema_registry']['registry_digest']))
                prepared=prepared_document(context=context)
                prepared.update(task_id=identity['task_id'],resources=['target:project','task:'+identity['task_id']],
                    baseline_digest=binding['baselines']['intent'],snapshot_digest=snapshot)
                prepared['action_kind']=action_kinds[0]
                prepared['prepared_action_digest']=PreparedAction.digest_document(prepared,context)
                with factory.open('application') as conn:
                    with conn.transaction():
                        state['destinations']['owner-wp05']={'kind':'owner','trust_boundary':'owner-session',
                            'target_digest':digest('owner-session'),'prepared_action_digest':prepared['prepared_action_digest']}
                        state['data_refs']['action-payload']={'digest':digest('payload-source'),
                            'sensitivity':'internal','retention_class':'evidence-body'}
                        state_digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                        conn.execute('UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?',
                            (canonical_json(state),state_digest,identity['task_id']))
                journal=ActionJournalRepository(factory,schema_registry=schemas,context=context)
                journal.record_prepared(PreparedAction.from_dict(prepared,context=context))
                for index,kind in enumerate(action_kinds[1:],1):
                    extra={**prepared,'action_id':prepared['action_id']+':'+str(index),'action_kind':kind,
                           'idempotency_key':prepared['idempotency_key']+':'+str(index)}
                    extra['prepared_action_digest']=PreparedAction.digest_document(extra,context)
                    journal.record_prepared(PreparedAction.from_dict(extra,context=context))
                request=dict(schema_version='1.0.0',request_id='request:registration',task_id=identity['task_id'],
                    action_id=prepared['action_id'],expected_task_revision=revision,expected_snapshot_digest=snapshot,
                    expected_security_digest=state_digest,expected_journal_revision=1)
            finally:
                objects.close()
        service=ActionAuthorizationApplication(manager,schema_registry=schemas,context=context,fault_hook=fault_hook)
        yield service,active,request,base


@contextmanager
def child_authority_service(base):
    """Attach fresh process-owned handles; never reuse a parent's runtime proof."""
    from graph_engineering.storage.connection import ConnectionFactory
    from graph_engineering.storage.locks import LockedFileRegistry
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.migration import InstallationMigrationRepository
    from graph_engineering.application.action_authority import ActionAuthorizationApplication
    from tests.support.wp05a_security import security_context,security_schema_registry
    fresh=ConnectionFactory._attach_existing_for_maintenance(base.data_root,base.policy,base.repository_id)
    locks=LockedFileRegistry(fresh)
    objects=ObjectRepository(fresh._for_maintenance(),locks)
    manager=InstallationMigrationRepository.attach_command_plane(fresh,locks,objects,
        control_root=base._test_installation_control_root,policy_document=base._test_migration_policy)
    context=security_context()
    try:
        yield ActionAuthorizationApplication(manager,schema_registry=security_schema_registry(context),context=context)
    finally:
        manager.close();objects.close();locks.close()


def coordinator_execute(service,request,*,before_call=lambda:None,call_path=None):
    """Run the production coordinator with only target/observer replaced."""
    import json
    from types import SimpleNamespace
    from tests.support.wp03_repository import ROOT
    from tests.support.wp05_actions import disclosure_plan
    from graph_engineering.application.actions import ActionCoordinator
    from graph_engineering.core.actions import ActionPolicy
    from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    with service._scope() as (ledger,journal,issuer):
        factory=ledger.factory;locks=service._manager._locks
        objects=ObjectRepository(factory,locks)
        try:
            repo=TaskRepository(factory,locks,objects,command_scope=factory._command_scope,action_journal=journal)
            leases=ResourceLeaseRepository(factory,locks)
            prepared=journal.load(request['action_id']).prepared
            lease=leases.acquire_many(lease_id='lease:coordinator',task_id=prepared.task_id,
                run_id='run:coordinator',operation_id='op:coordinator',resources=prepared.resources,ttl_ns=10**15)
            policy=ActionPolicy.from_dict(json.loads((ROOT/'config/actions/action-policy-v1.json').read_text()),
                schema_registry=service._schemas,context=service._context,runtime=issuer.runtime)
            coordinator=ActionCoordinator(journal=journal,repository=repo,leases=leases,locks=locks,objects=objects,
                security_issuer=issuer,action_policy=policy,installation_scope=factory._command_scope)
            class Target(DeterministicFakeTarget):
                def invoke(self,**kwargs):
                    before_call()
                    result=super().invoke(**kwargs)
                    if call_path is not None:
                        with call_path.open('a') as stream:stream.write('synthetic-call\n')
                    return result
            target=Target(target_id=prepared.target_id,target_digest=prepared.target_digest,
                resource_id='target:project',initial_state={'version':1})
            fixture=SimpleNamespace(issuer=issuer,schemas=service._schemas,context=service._context)
            binding=issuer.issue_task_context(prepared.task_id).binding
            outcome=coordinator.execute(prepared.action_id,owner_id=binding.owner_id,runtime_kind=binding.runtime_kind,
                runtime_lineage_id=binding.runtime_lineage_id,lease=lease,target=target,observer=target.observer_port(),
                disclosure_plan=disclosure_plan(fixture,prepared))
            assert target.call_count==1 and target.started_was_durable
            assert leases.unresolved_claims()==()
            return outcome.route
        finally:objects.close()


def synthetic_start(service,request,checkpoint=lambda _point:None,call_path=None,*,concrete=False):
    """Commit a real claim/start batch, then log a synthetic target call."""
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository,make_event
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.ports import CommitBatch
    from graph_engineering.storage.codec import semantic_record_digest
    from graph_engineering.application.tasks import action_task_snapshot
    with service._scope() as (ledger,journal,issuer):
        factory=ledger.factory;locks=service._manager._locks
        objects=ObjectRepository(factory,locks)
        try:
            from tests.support.wp07a_actions import action_adapter_schema_registry
            repository=TaskRepository(factory,locks,objects,command_scope=factory._command_scope,
                action_journal=journal,fault_hook=checkpoint,
                concrete_action_schemas=action_adapter_schema_registry(service._context) if concrete else None,
                concrete_action_context=service._context if concrete else None)
            leases=ResourceLeaseRepository(factory,locks)
            record=journal.load(request['action_id']);head=journal.current_task_head(request['task_id'])
            lease=leases.acquire_many(lease_id='lease:race',task_id=request['task_id'],run_id='run:race',
                operation_id='op:race',resources=record.prepared.resources,ttl_ns=1000000000)
            event=make_event(task_id=request['task_id'],sequence=head.sequence+1,event_id='event:race',
                event_type='action.execution_started',occurred_at=journal.current_time(),
                actor={'kind':'runtime','id':record.authority.runtime_lineage_id},expected_task_revision=head.revision,
                baseline_digests=[record.prepared.baseline_digest],previous_event_digest=head.head_digest,
                payload=dict(action_id=record.action_id,authority_digest=record.authority.authority_digest,
                    prepared_action_digest=record.prepared.prepared_action_digest,snapshot_digest=record.prepared.snapshot_digest,
                    lease_id=lease.lease_id,fencing_tokens=dict(lease.fencing_tokens),
                    disclosure_plan_digest=semantic_record_digest({'synthetic':'plan'})))
            concrete_delta=None
            if concrete:
                from graph_engineering.core.action_adapters import ActionInvocation
                prepared=record.prepared
                invocation=dict(schema_version='1.0.0',invocation_id='invocation:synthetic',task_id=prepared.task_id,
                    action_id=prepared.action_id,prepared_action_digest=prepared.prepared_action_digest,
                    authority_digest=record.authority.authority_digest,adapter_id='adapter:synthetic',operation_id='operation:synthetic',
                    target_id=prepared.target_id,target_digest=prepared.target_digest,resources=list(prepared.resources),
                    lease_id=lease.lease_id,fencing_tokens=[{'resource_id':r,'token':t} for r,t in lease.fencing_tokens],
                    idempotency_class=prepared.idempotency_class,idempotency_key=prepared.idempotency_key,
                    payload_digest=prepared.payload_digest,disclosure_plan_digest=event['payload']['disclosure_plan_digest'])
                invocation['invocation_digest']=ActionInvocation.digest_document(invocation)
                concrete_delta={'operation':'invocation','record':invocation}
            claim=leases.claim_action(claim_id='claim:race',action_id=record.action_id,task_id=request['task_id'],
                lease=lease,started_event_digest=event['event_digest'])
            repository.commit(CommitBatch(transaction_id='tx:race',task_id=request['task_id'],expected_task_revision=head.revision,
                events=(event,),snapshot=action_task_snapshot(head.snapshot,task_id=request['task_id'],revision=head.revision,action_state='executing'),
                catalog_delta={},lease_assertion=dict(lease_id=lease.lease_id,resource_id='task:'+request['task_id'],
                    fencing_token=dict(lease.fencing_tokens)['task:'+request['task_id']]),
                claim_delta=claim,action_journal_delta=journal.start_delta(record),concrete_action_delta=concrete_delta))
            if call_path is not None:
                with call_path.open('a') as stream:stream.write('synthetic-call\n')
            return 'started'
        finally:objects.close()


class AuthorityProcess:
    """Pipe-scheduled real process with bounded waits and explicit cleanup."""
    def __init__(self,work):
        import os,json
        self._os=os
        gate_read,self._gate_write=os.pipe()
        self._read,event_write=os.pipe()
        self.pid=os.fork()
        if self.pid==0:
            os.close(self._gate_write);os.close(self._read)
            def checkpoint():
                os.write(event_write,b'READY\n')
                if os.read(gate_read,1)!=b'G':raise RuntimeError('race gate closed')
            try:
                outcome=work(checkpoint)
                result={'ok':outcome}
            except BaseException as error:
                result={'error':type(error).__name__,'code':getattr(error,'code',None)}
            os.write(event_write,(json.dumps(result)+'\n').encode())
            os._exit(0)
        os.close(gate_read);os.close(event_write)
        self._buffer=b'';self._joined=False

    def message(self):
        import select,time,json
        deadline=time.monotonic()+20
        while b'\n' not in self._buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self._read],[],[],remaining)[0]:
                raise AssertionError('authority process timed out')
            block=self._os.read(self._read,4096)
            if not block:raise AssertionError('authority process ended without result')
            self._buffer+=block
        line,self._buffer=self._buffer.split(b'\n',1)
        return 'READY' if line==b'READY' else json.loads(line)

    def release(self):
        self._os.write(self._gate_write,b'G')

    def close(self):
        import signal
        if not self._joined:
            pid,status=self._os.waitpid(self.pid,self._os.WNOHANG)
            if not pid:
                self._os.kill(self.pid,signal.SIGKILL)
                self._os.waitpid(self.pid,0)
            self._joined=True
        self._os.close(self._read);self._os.close(self._gate_write)


def prepare_task_action(service, active, task_id, action_id, *, create_task=True, action_kind='commit'):
    """Genuine domain/prepare transitions with synthetic initial security inputs.

    No authority membership, decisions, order rows or approval events are seeded.
    """
    import json
    from tests.support.wp05a_security import binding_document,task_security_state_document
    from tests.support.wp05_actions import prepared_document,digest
    from tests.integration.test_wp07_runtime_parity import SCHEMAS,WORK
    from tests.integration.test_wp09_learning_metric_sources import approve
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.core.security.identity import SecurityBinding
    from graph_engineering.core.actions import PreparedAction
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.actions import ActionJournalRepository
    from graph_engineering.storage.codec import canonical_json,semantic_record_digest
    with service._scope() as (ledger,_journal,_issuer):
        factory=ledger.factory;locks=service._manager._locks;objects=ObjectRepository(factory,locks)
        try:
            repository=TaskRepository(factory,locks,objects,command_scope=factory._command_scope)
            tasks=TaskApplication(repository,repository,ResourceLeaseRepository(factory,locks),schema_registry=SCHEMAS,context=WORK)
            identity=dict(task_id=task_id,owner_id=active.proof.owner_id,runtime_kind=active.capabilities.runtime_kind,runtime_lineage_id=active.proof.lineage_id)
            if create_task:
                RuntimeMutationGateway.create(active,active.proof,identity,
                    lambda runtime:tasks.execute(task_id,TaskCommand('create',0,{'identity':identity}),runtime),occurred_at='synthetic-create',lease_ttl_ns=100)
                approve(tasks,active,baseline_digest=semantic_record_digest({'intent':task_id}),task_id=task_id)
            with factory.open('application') as conn,conn.transaction():
                revision,snapshot,raw=conn.execute('SELECT revision,snapshot_digest,snapshot_json FROM tasks WHERE task_id=?',(task_id,)).fetchone()
                domain=json.loads(raw)['domain'];existing=conn.execute('SELECT state_json FROM task_security_states WHERE task_id=?',(task_id,)).fetchone()
                if existing is None:
                    binding=binding_document();binding.update(identity,scope_id=domain['project_scope_ref']['scope_id'],scope_digest=domain['project_scope_ref']['digest'],baselines={x['kind']:x['digest'] for x in domain['baseline_refs']},snapshot_digest=snapshot)
                    binding['targets'][0]['target_digest']=digest('target');binding['binding_digest']=SecurityBinding.digest_document(binding)
                    state=task_security_state_document(binding=binding);state.update(task_revision=revision,task_snapshot_digest=snapshot,authority_digests=[])
                else:state=json.loads(existing[0]);binding=state['binding']
                prepared=prepared_document(context=service._context);prepared.update(task_id=task_id,action_id=action_id,action_kind=action_kind,idempotency_key='idempotency:'+action_id,resources=['target:project','task:'+task_id],baseline_digest=binding['baselines']['intent'],snapshot_digest=snapshot)
                prepared['prepared_action_digest']=PreparedAction.digest_document(prepared,service._context)
                state['destinations']['owner-wp05']={'kind':'owner','trust_boundary':'owner-session','target_digest':digest('owner-session'),'prepared_action_digest':prepared['prepared_action_digest']}
                state['data_refs']['action-payload']={'digest':digest('payload-source'),'sensitivity':'internal','retention_class':'evidence-body'}
                state_digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                conn.execute('INSERT INTO task_security_states VALUES(?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET task_revision=excluded.task_revision,task_snapshot_digest=excluded.task_snapshot_digest,state_json=excluded.state_json,state_digest=excluded.state_digest',(task_id,revision,snapshot,canonical_json(state),state_digest))
            journal=ActionJournalRepository(factory,schema_registry=service._schemas,context=service._context)
            journal.record_prepared(PreparedAction.from_dict(prepared,context=service._context))
            return dict(schema_version='1.0.0',request_id='request:'+action_id,task_id=task_id,action_id=action_id,expected_task_revision=revision,expected_snapshot_digest=snapshot,expected_security_digest=state_digest,expected_journal_revision=1)
        finally:objects.close()
