"""Genuine runtime action-decision boundaries and durable registration tests."""
from __future__ import annotations

import unittest

from graph_engineering.application.runtime import RuntimeSessionError
from graph_engineering.core.action_authority import ActionAuthorityError, ActionHumanRequestV1, signed
from tests.support.action_authority import action_session
from tests.unit.test_action_authority import challenge, decision


def session_request(session):
    ch = challenge(owner_id=session.proof.owner_id,
        runtime_kind=session.capabilities.runtime_kind,
        runtime_lineage_id=session.proof.lineage_id)
    return ActionHumanRequestV1.from_dict(signed('request', dict(schema_version='1.0.0',
        challenge=ch.to_dict(), invocation_nonce='a'*64, invocation_generation=1,
        session_id=session.proof.session_id, runtime_lineage_id=session.proof.lineage_id,
        dispatched_at_ns='1791244800000000001')))


class ActionAuthorityTests(unittest.TestCase):
    def test_forged_or_wrong_source_refused(self):
        calls=[]
        def human(req, owner, lineage):
            calls.append((owner.owner_id,lineage.lineage_id))
            return decision(req)
        with action_session(human) as session:
            req=session_request(session)
            self.assertEqual(session.request_action_decision(req).status,'approved')
            self.assertEqual(len(calls),1)
            with self.assertRaises(ActionAuthorityError):session.request_action_decision(req.to_dict())
        with self.assertRaises(RuntimeSessionError):session.request_action_decision(req)
        for port in (lambda req,owner,lineage: decision(req,invocation_nonce='b'*64),
                     lambda req,owner,lineage: decision(req).to_dict()):
            with action_session(port) as current:
                with self.assertRaises(ActionAuthorityError):current.request_action_decision(session_request(current))
        with action_session(None) as current:
            self.assertNotIn('human.action-decision.v1',current.capabilities.capabilities)
            with self.assertRaises(RuntimeSessionError):current.request_action_decision(session_request(current))

    def test_capacity_reserves_terminal_entries(self):
        from tests.support.action_authority import ledger_stack
        from graph_engineering.core.action_authority import ActionAuthorityPolicy
        from graph_engineering.storage.action_authority import ActionAuthorityLedger
        with ledger_stack() as (ledger,factory,scope):
            policy=ledger.policy.to_dict();policy['max_requests']=1;policy.pop('policy_digest')
            ledger=ActionAuthorityLedger(factory,ActionAuthorityPolicy.from_dict(signed('policy',policy)))
            ch=challenge(installation_id=scope.installation_id,repository_id=scope.repository_id,
                         activation_epoch=scope.activation_epoch,policy_digest=ledger.policy.policy_digest)
            with factory.open('application') as conn:
                with conn.transaction():
                    ledger._create_locked(conn,ch)
                with conn.transaction():
                    with self.assertRaises(ActionAuthorityError) as error:
                        ledger._create_locked(conn,challenge(request_id='request:2',
                            installation_id=scope.installation_id,repository_id=scope.repository_id,
                            activation_epoch=scope.activation_epoch,policy_digest=ledger.policy.policy_digest))
                    self.assertEqual(error.exception.code,'capacity_exhausted')
                with conn.transaction():
                    head=ledger._read_locked(conn,ch.request_id)[-1]
                    ledger._append_locked(conn,head,'revoked')
                self.assertEqual(ledger._read_locked(conn,ch.request_id)[-1]['event_kind'],'revoked')
                with conn.transaction():
                    with self.assertRaises(ActionAuthorityError):ledger._create_locked(conn,ch)

    def test_genuine_approval_registration(self):
        from tests.support.action_authority import registration_stack
        import json
        calls=[]
        def port(req,owner,lineage):
            calls.append(req.request_digest)
            return decision(req)
        with registration_stack(port) as (service,active,req,base):
            result=service.authorize(active,req)
            self.assertEqual(result['status'],'approved')
            retry=service.authorize(active,req)
            self.assertEqual(result,retry)
            self.assertEqual(len(calls),1)
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    security=json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])
                    self.assertEqual(security['authority_digests'],[result['receipt']['authority_digest']])
                    self.assertEqual(conn.execute('SELECT revision,snapshot_digest FROM tasks').fetchone(),
                        (req['expected_task_revision'],req['expected_snapshot_digest']))
                    self.assertEqual(journal.load(req['action_id']).state,'authorized')
                    self.assertEqual([e['event_kind'] for e in ledger._read_locked(conn,req['request_id'])],['created','attempt','approved'])

    def test_pending_rejected_no_membership(self):
        from tests.support.action_authority import registration_stack
        import json
        for status in ('pending','rejected'):
            with self.subTest(status=status),registration_stack(lambda r,o,l:decision(r,status=status)) as (service,active,req,base):
                result=service.authorize(active,req)
                self.assertEqual(result['status'],status)
                self.assertIsNone(result['receipt']['authority_digest'])
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        self.assertEqual(json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests'],[])
                        self.assertEqual(journal.load(req['action_id']).state,'prepared')

    def test_atomic_commit_faults_and_retry(self):
        from tests.support.action_authority import registration_stack
        import json
        for point in ('action_authority.after_human_result','action_authority.after_security',
                      'action_authority.after_journal','action_authority.before_result_commit',
                      'action_authority.after_result_commit'):
            calls=[];armed=[True]
            def port(req,owner,lineage):
                calls.append(req.invocation_nonce)
                return decision(req)
            def fault(at):
                if at==point and armed[0]:raise RuntimeError('synthetic crash')
            with self.subTest(point=point),registration_stack(port,fault) as (service,active,req,base):
                with self.assertRaises(RuntimeError):service.authorize(active,req)
                committed=point=='action_authority.after_result_commit'
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        head=ledger._read_locked(conn,req['request_id'])[-1]
                        members=json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests']
                        self.assertEqual(bool(members),committed)
                        self.assertEqual(head['event_kind'],'approved' if committed else 'attempt')
                        self.assertEqual(journal.load(req['action_id']).state,'authorized' if committed else 'prepared')
                armed[0]=False
                result=service.authorize(active,req)
                self.assertEqual(result['status'],'approved')
                self.assertEqual(len(calls),1 if committed else 2)
                self.assertEqual(len(set(calls)),len(calls))

    def test_revoke_pending_and_approved(self):
        from tests.support.action_authority import registration_stack
        import json
        for status in ('pending','approved'):
            with self.subTest(status=status),registration_stack(lambda r,o,l:decision(r,status=status)) as (service,active,req,base):
                result=service.authorize(active,req)
                revoke={k:req[k] for k in ('schema_version','task_id','request_id','action_id')}
                revoke['expected_generation']=result['receipt']['generation']
                self.assertEqual(service.revoke(active,revoke)['status'],'revoked')
                with self.assertRaises(ActionAuthorityError):service.authorize(active,req)
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        self.assertEqual(json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests'],[])
                        self.assertEqual(journal.load(req['action_id']).state,'revoked' if status=='approved' else 'prepared')

        # A pending challenge cannot revoke a separate, later approved challenge.
        replies=iter(('pending','approved'))
        with registration_stack(lambda r,o,l:decision(r,status=next(replies))) as (service,active,req,base):
            pending=service.authorize(active,req)
            second={**req,'request_id':'request:second'}
            approved=service.authorize(active,second)
            revoke={k:req[k] for k in ('schema_version','task_id','request_id','action_id')}
            service.revoke(active,{**revoke,'expected_generation':pending['receipt']['generation']})
            self.assertEqual(service.authorize(active,second),approved)
            with service._scope() as (ledger,journal,issuer):
                self.assertEqual(journal.load(req['action_id']).state,'authorized')

    def test_superseded_invocation_refused(self):
        from tests.support.action_authority import registration_stack
        handle=[];calls=[]
        def overlapping(invocation,owner,lineage):
            calls.append(invocation)
            if len(calls)==1:
                service,active,request=handle[0]
                self.assertEqual(service.authorize(active,request)['status'],'pending')
                return decision(invocation)
            return decision(invocation,status='pending')
        with registration_stack(overlapping) as (service,active,req,base):
            handle.append((service,active,req))
            with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,req)
            self.assertEqual(error.exception.code,'stale_binding')
            self.assertEqual(len(calls),2)
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(ledger._read_locked(conn,req['request_id'])[-1]['event_kind'],'pending')
                    self.assertEqual(journal.load(req['action_id']).state,'prepared')
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        captured=[]
        armed=[True]
        def port(req,owner,lineage):
            captured.append(req)
            return decision(req)
        def crash(point):
            if armed[0] and point=='action_authority.after_human_result':
                raise RuntimeError('lost first result')
        with registration_stack(port,crash) as (service,active,req,base):
            with self.assertRaises(RuntimeError):service.authorize(active,req)
            armed[0]=False
            service.authorize(active,req)
            self.assertEqual(len(captured),2)
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('application') as conn:
                    original=ledger._read_locked(conn,req['request_id'])[-1]
                    forged={k:v for k,v in original.items() if k!='event_digest'}
                    forged.update(invocation=captured[0].to_dict(),decision=decision(captured[0]).to_dict())
                    with conn.transaction():
                        conn.execute('UPDATE action_authority_events SET body_json=?,event_digest=? WHERE request_id=? AND sequence=?',
                            (canonical_json(forged),semantic_record_digest(forged),req['request_id'],original['sequence']))
                    with self.assertRaises(ActionAuthorityError) as error:ledger._read_locked(conn,req['request_id'])
                    self.assertEqual(error.exception.code,'integrity_error')

    def test_direct_commit_batch_cannot_bypass(self):
        from dataclasses import replace
        from tests.support.action_authority import registration_stack
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository,make_event
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.storage.ports import CommitBatch
        from graph_engineering.storage.codec import semantic_record_digest
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
            service.authorize(active,req)
            with service._scope() as (ledger,journal,issuer):
                locks=service._manager._locks
                objects=ObjectRepository(ledger.factory,locks)
                try:
                    repo=TaskRepository(ledger.factory,locks,objects,
                        command_scope=ledger.factory._command_scope,action_journal=journal)
                    leases=ResourceLeaseRepository(ledger.factory,locks)
                    record=journal.load(req['action_id']);head=journal.current_task_head(req['task_id'])
                    lease=leases.acquire_many(lease_id='lease:direct',task_id=req['task_id'],run_id='run:direct',
                        operation_id='op:direct',resources=record.prepared.resources,ttl_ns=1000000000)
                    event=make_event(task_id=req['task_id'],sequence=head.sequence+1,event_id='event:direct',
                        event_type='action.execution_started',occurred_at=journal.current_time(),
                        actor={'kind':'runtime','id':active.proof.lineage_id},expected_task_revision=head.revision,
                        baseline_digests=[record.prepared.baseline_digest],previous_event_digest=head.head_digest,
                        payload=dict(action_id=record.action_id,authority_digest=record.authority.authority_digest,
                            prepared_action_digest=record.prepared.prepared_action_digest,snapshot_digest=req['expected_snapshot_digest'],
                            lease_id=lease.lease_id,fencing_tokens=dict(lease.fencing_tokens),
                            disclosure_plan_digest=semantic_record_digest({'synthetic':'plan'})))
                    claim=leases.claim_action(claim_id='claim:direct',action_id=record.action_id,
                        task_id=req['task_id'],lease=lease,started_event_digest=event['event_digest'])
                    batch=CommitBatch(transaction_id='tx:direct',task_id=req['task_id'],expected_task_revision=head.revision,
                        events=(event,),snapshot={**head.snapshot,'revision':head.revision+1},catalog_delta={},
                        lease_assertion=dict(lease_id=lease.lease_id,resource_id='task:'+req['task_id'],
                            fencing_token=dict(lease.fencing_tokens)['task:'+req['task_id']]),
                        claim_delta=claim,action_journal_delta=journal.start_delta(record))
                    for delta in (None,{'operation':'unrelated'}):
                        with self.subTest(delta=delta),self.assertRaises(ActionAuthorityError):
                            repo.commit(replace(batch,action_journal_delta=delta))
                        self.assertEqual(journal.current_task_head(req['task_id']),head)
                        self.assertEqual(leases.unresolved_claims(),())
                    # The otherwise identical complete batch is accepted, without target I/O.
                    repo.commit(batch)
                    self.assertEqual(journal.load(req['action_id']).state,'executing')
                    self.assertEqual(len(leases.unresolved_claims()),1)
                finally:
                    objects.close()
            self.assertEqual(service.authorize(active,req)['status'],'already_started')

    def test_wait_releases_installation_scope(self):
        from tests.support.action_authority import registration_stack,child_authority_service,AuthorityProcess
        from graph_engineering.application.owner_turns import OwnerTurnApplication,OwnerTurnRequest
        from graph_engineering.core.runtime import runtime_record_digest
        services=[];observed=[]
        def port(req,owner,lineage):
            def maintain(gate):
                gate()
                with child_authority_service(bases[0]) as child:
                    child._manager.initialize_action_authority_storage()
                return 'exclusive-complete'
            child=AuthorityProcess(maintain)
            try:
                self.assertEqual(child.message(),'READY')
                child.release()
                self.assertEqual(child.message(),{'ok':'exclusive-complete'})
            finally:child.close()
            with services[0]._scope() as (ledger,journal,issuer):
                with ledger.factory.open('application') as conn:
                    with conn.transaction():
                        observed.append(ledger._read_locked(conn,req.challenge.request_id)[-1]['event_kind'])
            return decision(req)
        bases=[]
        with registration_stack(port) as (service,active,req,base):
            bases.append(base)
            services.append(service)
            def forbidden_provider():
                self.fail('action request retained a task scope')
            app=OwnerTurnApplication(None,lambda value:None,lambda:active,
                task_provider=forbidden_provider,action_authority=service)
            body=dict(schema_version='1.0',turn_id='turn:authorize',operation='authorize_action',
                task_id=req['task_id'],owner_id=active.proof.owner_id,runtime_kind=active.capabilities.runtime_kind,
                runtime_lineage_id=active.proof.lineage_id,payload={k:v for k,v in req.items()
                    if k not in {'schema_version','task_id'}})
            result=app.execute(OwnerTurnRequest.from_dict({**body,
                'request_digest':runtime_record_digest('owner-turn-request',body)}))
            self.assertEqual(result['result']['status'],'approved')
            self.assertEqual(observed,['attempt'])

    def test_restart_pending_requires_new_decision(self):
        from tests.support.action_authority import registration_stack,action_session
        from graph_engineering.application.action_authority import ActionAuthorizationApplication
        requests=[]
        def port(req,owner,lineage):
            requests.append(req)
            return decision(req,status='pending')
        with registration_stack(port) as (service,active,req,base):
            service.authorize(active,req)
            active.close()
            restarted=ActionAuthorizationApplication(service._manager,
                schema_registry=service._schemas,context=service._context)
            def fresh(req,owner,lineage):
                requests.append(req)
                return decision(req)
            with action_session(fresh) as new_session:
                result=restarted.authorize(new_session,req)
                self.assertEqual(result['status'],'approved')
            self.assertEqual(len(requests),2)
            self.assertNotEqual(requests[0].session_id,requests[1].session_id)
            self.assertNotEqual(requests[0].invocation_nonce,requests[1].invocation_nonce)
            self.assertEqual(requests[1].invocation_generation,requests[0].invocation_generation+1)

    def test_precondition_changes_refused(self):
        from tests.support.action_authority import registration_stack
        from graph_engineering.storage.codec import semantic_record_digest,canonical_json
        calls=[]
        with registration_stack(lambda r,o,l:(calls.append(r) or decision(r))) as (service,active,req,base):
            for key in ('expected_task_revision','expected_snapshot_digest','expected_security_digest','expected_journal_revision'):
                value=req[key]+1 if type(req[key]) is int else semantic_record_digest({'different':key})
                with self.subTest(key=key),self.assertRaises(ActionAuthorityError):
                    service.authorize(active,{**req,key:value})
            self.assertEqual(calls,[])
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(ledger._read_locked(conn,req['request_id']),[])
        services=[]
        def changed(req,owner,lineage):
            with services[0]._scope() as (ledger,journal,issuer):
                with ledger.factory.open('application') as conn:
                    with conn.transaction():
                        from graph_engineering.storage.security import SecurityStateRepository
                        state,_=SecurityStateRepository._load_task_state(conn,req.challenge.task_id,services[0]._context)
                        state['data_refs']['synthetic-change']={'digest':semantic_record_digest({'new':'reference'}),
                            'sensitivity':'internal','retention_class':'evidence-body'}
                        digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                        conn.execute('UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?',
                            (canonical_json(state),digest,req.challenge.task_id))
            return decision(req)
        with registration_stack(changed) as (service,active,req,base):
            services.append(service)
            with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,req)
            self.assertEqual(error.exception.code,'stale_binding')
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(ledger._read_locked(conn,req['request_id'])[-1]['event_kind'],'attempt')
                    self.assertEqual(journal.load(req['action_id']).state,'prepared')

    def test_unrelated_security_change_and_relevant_staleness(self):
        from tests.support.action_authority import registration_stack
        from graph_engineering.storage.security import SecurityStateRepository
        from graph_engineering.storage.codec import semantic_record_digest,canonical_json
        from graph_engineering.core.security.identity import SecurityBinding
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
            original=service.authorize(active,req)
            for relevant in (False,True):
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('application') as conn:
                        with conn.transaction():
                            state,_=SecurityStateRepository._load_task_state(conn,req['task_id'],service._context)
                            if relevant:
                                state['binding']['baselines']['intent']=semantic_record_digest({'changed':'intent'})
                                state['binding']['binding_digest']=SecurityBinding.digest_document(state['binding'])
                            else:
                                state['data_refs']['unrelated']={'digest':semantic_record_digest({'unrelated':'reference'}),
                                    'sensitivity':'internal','retention_class':'evidence-body'}
                            digest=semantic_record_digest({'contract':'task-security-state-v1','value':state})
                            conn.execute('UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?',
                                (canonical_json(state),digest,req['task_id']))
                if relevant:
                    with self.assertRaises(ActionAuthorityError):service.authorize(active,req)
                else:
                    self.assertEqual(service.authorize(active,req),original)

    def test_unsupported_component_and_contract(self):
        from tests.support.action_authority import registration_stack
        for mutation in ("DELETE FROM schema_versions WHERE component='action-authority'",
                         "UPDATE schema_versions SET version='99.0' WHERE component='action-authority'"):
            calls=[]
            with registration_stack(lambda r,o,l:(calls.append(r) or decision(r))) as (service,active,req,base):
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('application') as conn:
                        with conn.transaction():conn.execute(mutation)
                with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,req)
                self.assertEqual(error.exception.code,'upgrade_required')
                self.assertEqual(calls,[])
        def unavailable(*args):raise RuntimeError('untrusted detailed port failure')
        with registration_stack(unavailable) as (service,active,req,base):
            with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,req)
            self.assertEqual(str(error.exception),'human_unavailable')
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(ledger._read_locked(conn,req['request_id'])[-1]['event_kind'],'attempt')

    def test_migration_component_compatibility(self):
        import json
        from tests.support.wp03_repository import repository_stack
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        for enabled in (False,True):
            with self.subTest(enabled=enabled),repository_stack() as (root,base,*_):
                base._test_installation_scope.__exit__(None,None,None)
                manager=base._test_installation_manager
                if enabled:manager.initialize_action_authority_storage()
                bundle=manager.export_bundle(root.parent/'bundle',export_id='export:authority')
                manifest_path=bundle.root/manager._policy.bundle_manifest_filename
                manifest=json.loads(manifest_path.read_text())
                self.assertEqual(manifest['schema_version'],'1.1' if enabled else '1.0')
                imported=manager.import_bundle(bundle.root,root.parent/'candidate',repository_id='repository-imported')
                try:
                    with imported.factory.open('doctor') as conn:
                        marker=conn.execute("SELECT version FROM schema_versions WHERE component='action-authority'").fetchone()
                        self.assertEqual(marker,('1.0',) if enabled else None)
                        if enabled:self.assertEqual(conn.execute('SELECT COUNT(*) FROM action_authority_events').fetchone()[0],0)
                finally:imported.close()
                if enabled:
                    manifest['schema_version']='1.0'
                    manifest['bundle_digest']=semantic_record_digest({k:v for k,v in manifest.items() if k!='bundle_digest'})
                    manifest_path.write_text(canonical_json(manifest))
                    with self.assertRaises(MigrationRepositoryError):manager.validate_bundle(bundle.root)

        # Nonempty genuine approval is preserved as audit, then invalidated by activation.
        from tests.support.action_authority import registration_stack
        with registration_stack(lambda r,o,l:decision(r),learning=False) as (service,active,req,base):
            approved=service.authorize(active,req)
            manager=service._manager
            root=base._test_installation_control_root.parent
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    historic=ledger._read_locked(conn,req['request_id'])[-1]
            original={k:v for k,v in historic.items() if k!='event_digest'}
            import copy
            for field,replacement in (('authority',{'authority_digest':approved['receipt']['authority_digest']}),
                    ('post_journal_revision','2'),('post_security_digest','invalid')):
                damaged=copy.deepcopy(original);damaged[field]=replacement
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('application') as conn:
                        with conn.transaction():
                            conn.execute('UPDATE action_authority_events SET body_json=?,event_digest=? WHERE request_id=? AND sequence=?',
                                (canonical_json(damaged),semantic_record_digest(damaged),req['request_id'],historic['sequence']))
                with self.assertRaises(MigrationRepositoryError):
                    manager.export_bundle(root/('damaged-'+field),export_id='export:'+field)
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('application') as conn:
                        with conn.transaction():
                            conn.execute('UPDATE action_authority_events SET body_json=?,event_digest=? WHERE request_id=? AND sequence=?',
                                (canonical_json(original),historic['event_digest'],req['request_id'],historic['sequence']))
            bundle=manager.export_bundle(root/'approved-bundle',export_id='export:approved')
            imported=manager.import_bundle(bundle.root,root/'approved-candidate',repository_id='repository-approved-import')
            try:
                with imported.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute('SELECT event_kind FROM action_authority_events ORDER BY sequence').fetchall(),
                        [('created',),('attempt',),('approved',)])
                manager.activate(imported,release_id='release:authority',contract_id='repository-contract-1')
                with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,req)
                self.assertEqual(error.exception.code,'epoch_changed')
                status_req={k:req[k] for k in ('schema_version','task_id','request_id','action_id')}
                self.assertEqual(service.status(active,status_req)['status'],'epoch_changed')
                self.assertEqual(service.status(active,status_req)['receipt'],approved['receipt'])
            finally:imported.close()

    def _start_revoke_race(self,revoke_first):
        from tests.support.action_authority import registration_stack,child_authority_service,synthetic_start,AuthorityProcess,action_session
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
            approved=service.authorize(active,req)
            path=base._test_installation_control_root.parent/'calls.txt'
            def start(gate):
                with child_authority_service(base) as child_service:
                    return synthetic_start(child_service,req,lambda point:gate() if point=='commit.before_transaction' else None,path)
            def revoke(gate):
                gate()
                with child_authority_service(base) as child_service,action_session(lambda r,o,l:decision(r)) as session:
                    return child_service.revoke(session,{k:req[k] for k in ('schema_version','request_id','task_id','action_id')}
                        | {'expected_generation':approved['receipt']['generation']})['status']
            starter=AuthorityProcess(start);revoker=None
            try:
                self.assertEqual(starter.message(),'READY')
                revoker=AuthorityProcess(revoke)
                self.assertEqual(revoker.message(),'READY')
                if revoke_first:
                    revoker.release();self.assertEqual(revoker.message(),{'ok':'revoked'})
                    starter.release();self.assertIn('error',starter.message())
                else:
                    starter.release();self.assertEqual(starter.message(),{'ok':'started'})
                    revoker.release();self.assertEqual(revoker.message(),{'ok':'execution_in_progress'})
            finally:
                starter.close()
                if revoker is not None:revoker.close()
            self.assertEqual([] if not path.exists() else path.read_text().splitlines(),[] if revoke_first else ['synthetic-call'])
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM claims').fetchone()[0],0 if revoke_first else 1)
                    self.assertEqual(ledger._read_locked(conn,req['request_id'])[-1]['event_kind'],'revoked')
                    self.assertEqual(journal.load(req['action_id']).state,'revoked' if revoke_first else 'executing')

    def test_revoke_first_process_race(self):
        self._start_revoke_race(True)

    def test_claim_first_process_race(self):
        import json
        from tests.support.action_authority import registration_stack,child_authority_service,coordinator_execute,AuthorityProcess,action_session
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
            approved=service.authorize(active,req)
            path=base._test_installation_control_root.parent/'completed-calls.txt'
            def start(gate):
                with child_authority_service(base) as child:
                    return coordinator_execute(child,req,before_call=gate,call_path=path)
            starter=AuthorityProcess(start)
            try:
                self.assertEqual(starter.message(),'READY')
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        claim=conn.execute('SELECT claim_id,started_event_digest FROM claims').fetchone()
                result=service.revoke(active,{k:req[k] for k in ('schema_version','request_id','task_id','action_id')}
                    | {'expected_generation':approved['receipt']['generation']})
                self.assertEqual(result['status'],'execution_in_progress')
                starter.release();self.assertEqual(starter.message(),{'ok':'reconciled-effect-verified'})
            finally:starter.close()
            self.assertEqual(path.read_text().splitlines(),['synthetic-call'])
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute('SELECT claim_id,started_event_digest FROM claims').fetchone(),claim)
                    self.assertEqual(conn.execute('SELECT state FROM claims').fetchone(),('reconciled_effect_verified',))
                    self.assertEqual(json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests'],[])
                    record=journal.load(req['action_id'])
                    self.assertEqual(record.state,'reconciled')
                    self.assertEqual(record.receipt['authority_digest'],approved['receipt']['authority_digest'])
            with self.assertRaises(ActionAuthorityError):service.authorize(active,req)

    def test_registration_revoke_process_race(self):
        from tests.support.action_authority import registration_stack,child_authority_service,AuthorityProcess,action_session
        import json
        for revoke_first in (True,False):
            with self.subTest(revoke_first=revoke_first),registration_stack(lambda r,o,l:decision(r,status='pending')) as (service,active,req,base):
                service.authorize(active,req)
                def register(gate):
                    with child_authority_service(base) as child_service,action_session(lambda r,o,l:(gate() or decision(r))) as session:
                        return child_service.authorize(session,req)['status']
                def revoke(gate):
                    gate()
                    with child_authority_service(base) as child_service,action_session(lambda r,o,l:decision(r)) as session:
                        status_req={k:req[k] for k in ('schema_version','request_id','task_id','action_id')}
                        current=child_service.status(session,status_req)
                        return child_service.revoke(session,{**status_req,'expected_generation':current['receipt']['generation']})['status']
                registrar=AuthorityProcess(register);revoker=None
                try:
                    self.assertEqual(registrar.message(),'READY')
                    revoker=AuthorityProcess(revoke);self.assertEqual(revoker.message(),'READY')
                    if revoke_first:
                        revoker.release();self.assertEqual(revoker.message(),{'ok':'revoked'})
                        registrar.release();self.assertIn('error',registrar.message())
                    else:
                        registrar.release();self.assertEqual(registrar.message(),{'ok':'approved'})
                        revoker.release();self.assertEqual(revoker.message(),{'ok':'revoked'})
                finally:
                    registrar.close()
                    if revoker is not None:revoker.close()
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        self.assertEqual(ledger._read_locked(conn,req['request_id'])[-1]['event_kind'],'revoked')
                        self.assertEqual(json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests'],[])
                        self.assertEqual(journal.load(req['action_id']).state,'prepared' if revoke_first else 'revoked')

    def test_three_start_paths_share_guard(self):
        from unittest import mock
        from tests.support.action_authority import registration_stack,synthetic_start
        from graph_engineering.storage.action_authority import ActionAuthorityLedger
        from tests.support.wp05_actions import action_stack
        from tests.integration.test_wp05_recovery_claim import WP05RecoveryClaimTests
        original=ActionAuthorityLedger._validate_start_locked
        calls=[]
        def checked(ledger,connection,journal,batch):
            calls.append((batch.action_journal_delta['operation'],batch.concrete_action_delta is not None))
            return original(ledger,connection,journal,batch)
        with mock.patch.object(ActionAuthorityLedger,'_validate_start_locked',checked):
            for concrete in (False,True):
                with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
                    service.authorize(active,req)
                    synthetic_start(service,req,concrete=concrete)
                    with service._scope() as (ledger,journal,issuer):
                        with ledger.factory.open('doctor') as conn:
                            self.assertEqual(conn.execute('SELECT COUNT(*) FROM concrete_action_records').fetchone()[0],int(concrete))
            with action_stack(action_ttl_ns=10) as fixture:
                WP05RecoveryClaimTests()._receipt_recorded_recovery(fixture)
        self.assertIn(('start',False),calls)
        self.assertIn(('start',True),calls)
        self.assertIn(('compensation_start',False),calls)

    def test_restore_epoch_and_claim_audit(self):
        from tests.support.action_authority import registration_stack,synthetic_start
        from graph_engineering.storage.migration import MigrationRepositoryError
        with registration_stack(lambda r,o,l:decision(r),learning=False) as (service,active,req,base):
            approved=service.authorize(active,req)
            synthetic_start(service,req)
            status_req={k:req[k] for k in ('schema_version','request_id','task_id','action_id')}
            self.assertEqual(service.revoke(active,{**status_req,'expected_generation':approved['receipt']['generation']})['status'],
                'execution_in_progress')
            with service._scope() as (ledger,journal,issuer):
                with ledger.factory.open('doctor') as conn:
                    history=ledger._read_locked(conn,req['request_id'])
                    claims=conn.execute('SELECT * FROM claims').fetchall()
            manager=service._manager;root=base._test_installation_control_root.parent
            bundle=manager.export_bundle(root/'claim-bundle',export_id='export:claim')
            imported=manager.import_bundle(bundle.root,root/'claim-candidate',repository_id='repository-claim-import')
            try:
                with self.assertRaisesRegex(MigrationRepositoryError,'quiescence'):
                    manager.activate(imported,release_id='release:claim',contract_id='repository-contract-1')
                with service._scope() as (ledger,journal,issuer):
                    with ledger.factory.open('doctor') as conn:
                        self.assertEqual(ledger._read_locked(conn,req['request_id']),history)
                        self.assertEqual(conn.execute('SELECT * FROM claims').fetchall(),claims)
                        self.assertEqual(journal.load(req['action_id']).state,'executing')
                self.assertEqual(service.status(active,status_req)['status'],'revoked')
                with manager.command_scope() as scope:
                    current,factory=manager._current_factory(scope._control_token())
                    fences=dict(current.fencing_high_water)
                    for resource,counter in manager._fences(factory):
                        fences[resource]=max(fences.get(resource,0),counter)
                gap=manager.register_restore_gap(bundle,resources=tuple(sorted(fences.items())))
                with self.assertRaises(MigrationRepositoryError):
                    with manager.command_scope():self.fail('restore gap admitted command')
                with self.assertRaises(MigrationRepositoryError):
                    manager.clear_restore_gap(gap,fences=gap.resources,authority_digest=None)
                with imported.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute('SELECT * FROM claims').fetchall(),claims)
            finally:imported.close()

    def test_mixed_learning_source_chain(self):
        from contextlib import contextmanager
        import json,copy
        from tests.support.action_authority import registration_stack,coordinator_execute
        from tests.integration.test_wp07_runtime_parity import SCHEMAS,WORK
        from tests.integration.test_wp09_learning import learning_call,learning_request
        from tests.support.wp05a_security import retention_policy_document
        from graph_engineering.core.security.retention import RetentionPolicyRegistry
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.application.runtime import RuntimeQueryGateway
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,req,base):
            @contextmanager
            def tasks():
                with service._scope() as (ledger,journal,issuer):
                    locks=service._manager._locks;factory=ledger.factory
                    objects=ObjectRepository(factory,locks)
                    try:
                        repo=TaskRepository(factory,locks,objects,command_scope=factory._command_scope,action_journal=journal)
                        from graph_engineering.application.security import SecurityContextIssuer
                        from graph_engineering.storage.security import SecurityStateRepository
                        issuer=SecurityContextIssuer(SecurityStateRepository(repo._factory),
                            schema_registry=issuer._schemas,context=issuer._context)
                        retention=RetentionPolicyRegistry.from_dict(retention_policy_document(),schema_registry=issuer._schemas,
                            context=issuer._context,runtime=issuer.runtime)
                        yield TaskApplication(repo,repo,ResourceLeaseRepository(factory,locks),schema_registry=SCHEMAS,context=WORK,
                            learning_security_issuer=issuer,learning_retention_registry=retention),factory,repo
                    finally:objects.close()
            with tasks() as (application,factory,repo):
                learning_call(application,active,learning_request('grant_learning','mixed:grant',expected_generation=0,
                    metric_ids=['authorized_stage','category','revision_count'],expires_at_ns='1000'))
                before=RuntimeQueryGateway.show(active,active.proof,application,req['task_id'])
                with factory.open('doctor') as conn:
                    req['expected_security_digest']=conn.execute('SELECT state_digest FROM task_security_states').fetchone()[0]
            service.authorize(active,req)
            self.assertEqual(coordinator_execute(service,req),'reconciled-effect-verified')
            with tasks() as (application,factory,repo):
                current=RuntimeQueryGateway.show(active,active.proof,application,req['task_id'])
                self.assertEqual(current.snapshot,before.snapshot)
                self.assertGreater(current.repository_revision,before.repository_revision)
                events=repo.replay(req['task_id'])
                self.assertIn('action.receipt_recorded',[event['event_type'] for event in events])
                self.assertIn('task.prd_approved',[event['event_type'] for event in events])
                self.assertEqual(TaskApplication._repository_sequence(current,events),len(events))
                from graph_engineering.application.tasks import ApplicationError
                forged=copy.deepcopy(events);forged[-1]['sequence']+=1
                with self.assertRaises(ApplicationError):TaskApplication._repository_sequence(current,forged)
                with factory.open('doctor') as conn:head=conn.execute('SELECT head_digest FROM tasks').fetchone()[0]
                learning_call(application,active,learning_request('collect_learning','mixed:collect',expected_head=head,
                    expected_generation=1,expected_context_version=0))
                report=learning_call(application,active,learning_request('report_learning','mixed:report',
                    experiment_id='synthetic-default',task_ids=[req['task_id']]))
                self.assertEqual(report['observations'][0]['metrics']['authorized_stage'],{'value':None,'availability':'unavailable'})
                with factory.open('doctor') as conn:
                    observation=json.loads(conn.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(observation['availability'],'source-gap')
                learning_call(application,active,learning_request('revoke_learning','mixed:revoke',expected_generation=1))
                learning_call(application,active,learning_request('grant_learning','mixed:regrant',expected_generation=2,
                    metric_ids=['revision_count'],expires_at_ns='1000'))
                with factory.open('doctor') as conn:
                    row=conn.execute('SELECT consent_generation,observation_json,retained_epochs_json FROM pmf_aggregates').fetchone()
                fresh=json.loads(row[1])
                self.assertEqual(row[0],3)
                self.assertEqual(fresh['grant_sequence'],len(events))
                self.assertEqual(fresh['current_prd_sequence'],next(e['sequence'] for e in events if e['event_type']=='task.prd_approved'))
                self.assertGreater(fresh['grant_sequence'],fresh['current_prd_sequence'])
                self.assertIsNone(fresh['start_sample'])
                self.assertEqual(fresh['revision_count'],0)
                self.assertEqual(json.loads(row[2])[0]['generation'],1)
