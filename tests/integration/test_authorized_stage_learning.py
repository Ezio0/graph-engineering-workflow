"""Real authorization/consent/collection transactions with synthetic human port."""
from __future__ import annotations

from contextlib import contextmanager
import unittest

from graph_engineering.core.learning import LearningError
from tests.support.action_authority import registration_stack
from tests.unit.test_action_authority import decision
from tests.integration.test_wp09_learning import learning_call,learning_request


@contextmanager
def bound_learning(service):
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.core.security.retention import RetentionPolicyRegistry
    from tests.support.wp05a_security import retention_policy_document
    from tests.integration.test_wp07_runtime_parity import SCHEMAS,WORK
    with service._scope() as (ledger,journal,issuer):
        factory=ledger.factory; locks=service._manager._locks; objects=ObjectRepository(factory,locks)
        try:
            repository=TaskRepository(factory,locks,objects,command_scope=factory._command_scope)
            from graph_engineering.application.security import SecurityContextIssuer
            from graph_engineering.storage.security import SecurityStateRepository
            issuer=SecurityContextIssuer(SecurityStateRepository(repository._factory),schema_registry=service._schemas,context=service._context)
            registry=RetentionPolicyRegistry.from_dict(retention_policy_document(),schema_registry=issuer._schemas,
                context=service._context,runtime=issuer.runtime)
            app=TaskApplication(repository,repository,ResourceLeaseRepository(factory,locks),schema_registry=SCHEMAS,
                context=WORK,learning_security_issuer=issuer,learning_retention_registry=registry)
            yield app,repository._factory,repository
        finally:objects.close()


def refreshed(service,request):
    with service._scope() as (ledger,journal,_issuer),ledger.factory.open('application') as conn:
        revision,snapshot=conn.execute('SELECT revision,snapshot_digest FROM tasks WHERE task_id=?',(request['task_id'],)).fetchone()
        digest=conn.execute('SELECT state_digest FROM task_security_states WHERE task_id=?',(request['task_id'],)).fetchone()[0]
        return {**request,'expected_task_revision':revision,'expected_snapshot_digest':snapshot,
                'expected_security_digest':digest,'expected_journal_revision':journal.load(request['action_id']).revision}


def grant(service,active,request_id='learning:grant',generation=0):
    with bound_learning(service) as (app,_factory,_repo):
        return learning_call(app,active,learning_request('grant_learning',request_id,expected_generation=generation,
            metric_ids=['authorized_stage'],expires_at_ns='900000000000'))


def collect(service,active,request_id='learning:collect',generation=1):
    with bound_learning(service) as (app,factory,_repo),factory.open('application') as conn:
        head=conn.execute('SELECT head_digest FROM tasks WHERE task_id=?',('task:learning-1',)).fetchone()[0]
        req=learning_request('collect_learning',request_id,expected_head=head,expected_generation=generation,expected_context_version=0)
        return learning_call(app,active,req),req


def derived(service):
    import json
    with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('application') as conn:
        return json.loads(conn.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])




def second_request(service,request,index=1):
    return refreshed(service,{**request,'request_id':request['request_id']+':'+str(index),
        'action_id':request['action_id']+':'+str(index)})


def report(service,active,request_id='learning:report'):
    with bound_learning(service) as (app,_factory,_repo):
        return learning_call(app,active,learning_request('report_learning',request_id,
            experiment_id='synthetic-default',task_ids=['task:learning-1']))


def persisted(service):
    with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
        return tuple(tuple(conn.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()) for table in
            ('tasks','pmf_consents','pmf_aggregates','pmf_owner_context','pmf_tombstones',
             'task_security_states','purge_authorizations','objects','object_references'))


def child_approval(base,request,*,include_receipt=False):
    from tests.support.action_authority import AuthorityProcess,child_authority_service,action_session
    def work(checkpoint):
        with child_authority_service(base) as service,action_session(lambda r,o,l:decision(r)) as active:
            checkpoint()
            result=service.authorize(active,refreshed(service,request))
            return result if include_receipt else result['status']
    return AuthorityProcess(work)


def approval_surfaces(service):
    with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
        return tuple(tuple(conn.execute('SELECT * FROM '+table+' ORDER BY 1,2').fetchall()) for table in
            ('action_authority_events','action_authority_order','task_security_states','action_journal'))


def order_rows(service):
    with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
        return conn.execute('SELECT * FROM action_authority_order ORDER BY order_epoch,ordinal').fetchall()


class AuthorizedStageIntegrationTests(unittest.TestCase):
    def test_genuine_approval_count(self):
        with registration_stack(lambda r,o,l:decision(r),action_kinds=('commit','push')) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            first,original=collect(service,active)
            saved=derived(service);before=persisted(service)
            self.assertEqual(saved['metrics']['authorized_stage'],{'value':0,'availability':'observed'})
            child=child_approval(base,request,include_receipt=True)
            try:
                self.assertEqual(child.message(),'READY');child.release();approved=child.message()['ok']
                self.assertEqual(approved['status'],'approved')
            finally:child.close()
            receipt=approved['receipt']
            def committed_approval():
                with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                    chain=ledger._read_locked(conn,request['request_id'])
                    event=chain[receipt['ledger_sequence']-1]
                    self.assertEqual(event['event_kind'],'approved')
                    self.assertEqual(event['event_digest'],receipt['event_digest'])
                    rows=tuple(conn.execute('SELECT request_id,sequence,event_kind,generation,CAST(body_json AS BLOB),event_digest '
                        'FROM action_authority_events WHERE request_id=? ORDER BY sequence',(request['request_id'],)).fetchall())
                    self.assertIsInstance(rows[receipt['ledger_sequence']-1][4],bytes)
                    return ledger.receipt(event).to_dict(),rows
            original_approval=committed_approval()
            self.assertEqual(original_approval[0],receipt)
            before_replay=persisted(service)
            with bound_learning(service) as (app,_factory,_repo),self.assertRaises(LearningError) as error:
                learning_call(app,active,original)
            self.assertEqual(str(error.exception),'LEARNING_STALE');self.assertEqual(persisted(service),before_replay)
            self.assertEqual(committed_approval(),original_approval)
            self.assertEqual(before[0],before_replay[0]);self.assertEqual(before[1],before_replay[1]);self.assertEqual(before[2],before_replay[2])
            collect(service,active,'learning:fresh');new=derived(service)
            self.assertEqual(committed_approval(),original_approval)
            self.assertEqual(new['metrics']['authorized_stage']['value'],1)
            for key in ('source_head','consent_generation','context_version','context_digest'):
                self.assertEqual(saved[key],new[key])
            self.assertNotEqual(saved['authorization_source'],new['authorization_source'])
            child=child_approval(base,second_request(service,request))
            try:
                self.assertEqual(child.message(),'READY');child.release();self.assertEqual(child.message(),{'ok':'approved'})
            finally:child.close()
            collect(service,active,'learning:two');self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],2)
            rows=order_rows(service);self.assertEqual([row[1] for row in rows],list(range(len(rows))))
            self.assertEqual(len({(row[3],row[4]) for row in rows[1:]}),len(rows)-1)
            self.assertEqual(first['state'],'collected')

    def test_same_category_retry(self):
        with registration_stack(lambda r,o,l:decision(r),action_kinds=('commit','commit')) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            request=refreshed(service,request);approved=service.authorize(active,request);saved=order_rows(service)
            self.assertEqual(service.authorize(active,request),approved);self.assertEqual(order_rows(service),saved)
            service.authorize(active,second_request(service,request));collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_late_consent_excludes_approval(self):
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();approved=service.authorize(active,request)
            old=order_rows(service);grant(service,active);collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],0)
            self.assertEqual(order_rows(service),old);self.assertEqual(service.authorize(active,request),approved)

    def _consent_race(self,consent_first):
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();child=child_approval(base,request)
            try:
                self.assertEqual(child.message(),'READY')
                if consent_first:grant(service,active)
                child.release();self.assertEqual(child.message(),{'ok':'approved'})
                if not consent_first:grant(service,active)
            finally:child.close()
            collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],int(consent_first))

    def test_consent_first_process_race(self):self._consent_race(True)
    def test_approval_first_process_race(self):self._consent_race(False)

    def test_report_first_process_race(self):
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);collect(service,active)
            child=child_approval(base,request)
            try:
                self.assertEqual(child.message(),'READY');old=report(service,active)
                self.assertEqual(old['observations'][0]['metrics']['authorized_stage']['value'],0)
                child.release();self.assertEqual(child.message(),{'ok':'approved'})
            finally:child.close()
            before=persisted(service)
            with self.assertRaises(LearningError):report(service,active)
            self.assertEqual(persisted(service),before)
            collect(service,active,'learning:recollect');self.assertEqual(report(service,active,'learning:new-report')['observations'][0]['metrics']['authorized_stage']['value'],1)

    def test_approval_before_report_process_race(self):
        import sqlite3
        from unittest import mock
        from tests.support.action_authority import AuthorityProcess,child_authority_service,action_session
        from graph_engineering.storage import learning as storage_learning
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            def writer(checkpoint):
                with child_authority_service(base) as child,action_session(lambda r,o,l:decision(r)) as session:
                    checkpoint()
                    probe=sqlite3.connect(str(base._database),timeout=0)
                    try:
                        try:probe.execute('BEGIN IMMEDIATE')
                        except sqlite3.OperationalError:blocked=True
                        else:
                            probe.rollback();blocked=False
                    finally:probe.close()
                    checkpoint()
                    return {'blocked':blocked,'status':child.authorize(session,refreshed(child,request))['status']}
            child=AuthorityProcess(writer)
            try:
                self.assertEqual(child.message(),'READY')
                original_capture=storage_learning._capture_current_observation_locked
                def capture(*args,**kwargs):
                    value=original_capture(*args,**kwargs)
                    self.assertTrue(args[1]._in_transaction)
                    child.release();self.assertEqual(child.message(),'READY')
                    return value
                with mock.patch.object(storage_learning,'_capture_current_observation_locked',side_effect=capture):
                    _result,original_request=collect(service,active)
                self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],0)
                child.release()
                self.assertEqual(child.message(),{'ok':{'blocked':True,'status':'approved'}})
                with bound_learning(service) as (app,_factory,_repo),self.assertRaises(LearningError):learning_call(app,active,original_request)
            finally:child.close()
        from tests.integration.test_wp09_learning import capture_learning
        from graph_engineering.application.runtime import RuntimeMutationGateway
        from graph_engineering.application.learning import LearningPolicyLoader
        from graph_engineering.storage.learning import _collect_locked
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            _result,collect_request=collect(service,active)
            with bound_learning(service) as (app,_factory,_repo):old_capture=capture_learning(app,active,collect_request)
            child=child_approval(base,request)
            try:
                self.assertEqual(child.message(),'READY');child.release();self.assertEqual(child.message(),{'ok':'approved'})
            finally:child.close()
            before=persisted(service)
            with self.assertRaises(LearningError):report(service,active)
            with bound_learning(service) as (app,factory,_repo):
                def stale_publish(runtime):
                    with factory.open('application') as conn,conn.transaction():
                        return _collect_locked(app,conn,collect_request,runtime,LearningPolicyLoader.from_installation(),old_capture)
                with self.assertRaises(LearningError) as error:RuntimeMutationGateway.invoke(active,active.proof,stale_publish)
                self.assertEqual(str(error.exception),'LEARNING_STALE')
            self.assertEqual(persisted(service),before)
            collect(service,active,'learning:fresh');self.assertEqual(report(service,active)['observations'][0]['metrics']['authorized_stage']['value'],1)

    def test_unchanged_pending_commit_window(self):
        replies=iter(('pending','approved'))
        with registration_stack(lambda r,o,l:decision(r,status=next(replies))) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            request=refreshed(service,request);self.assertEqual(service.authorize(active,request)['status'],'pending')
            from tests.integration.test_wp09_learning import capture_learning
            with bound_learning(service) as (app,factory,_repo),factory.open('doctor') as conn:
                head=conn.execute('SELECT head_digest FROM tasks').fetchone()[0]
                captured=capture_learning(app,active,learning_request('collect_learning','pending:read',expected_head=head,expected_generation=1,expected_context_version=0))
            self.assertEqual(captured['authorization_count'],0)
            self.assertEqual(service.authorize(active,request)['status'],'approved')
            collect(service,active,'learning:pending-approved');self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_regrant_rejects_changed_security(self):
        from graph_engineering.core.action_authority import ActionAuthorityError
        handle=[];first=[True]
        def port(req,owner,lineage):
            if first[0]:
                first[0]=False;service,active=handle[0];grant(service,active,'learning:regrant',1)
            return decision(req)
        with registration_stack(port) as (service,active,request,_base):
            handle.append((service,active));service._manager.initialize_action_authority_order_storage();grant(service,active);collect(service,active,'learning:register-subject')
            request=refreshed(service,request)
            with self.assertRaises(ActionAuthorityError):service.authorize(active,request)
            collect(service,active,generation=2);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],0)
            from tests.support.action_authority import prepare_task_action
            fresh=prepare_task_action(service,active,request['task_id'],'action:regrant-fresh',create_task=False)
            self.assertEqual(service.authorize(active,fresh)['status'],'approved')
            collect(service,active,'learning:regrant-fresh',2);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_prd_reapproval_rejects_old_challenge(self):
        from tests.integration.test_wp09_learning_metric_sources import approve
        from graph_engineering.core.action_authority import ActionAuthorityError
        from graph_engineering.storage.codec import semantic_record_digest
        handle=[];first=[True]
        def port(req,owner,lineage):
            if first[0]:
                first[0]=False;service,active=handle[0]
                with bound_learning(service) as (app,_factory,_repo):approve(app,active,baseline_digest=semantic_record_digest({'intent':'changed'}))
            return decision(req)
        with registration_stack(port) as (service,active,request,_base):
            handle.append((service,active));service._manager.initialize_action_authority_order_storage();grant(service,active)
            with self.assertRaises(ActionAuthorityError):service.authorize(active,refreshed(service,request))
            with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                self.assertNotIn('approved',[row['event_kind'] for row in ledger._read_locked(conn,request['request_id'])])
            from tests.support.action_authority import prepare_task_action
            fresh=prepare_task_action(service,active,request['task_id'],'action:prd-fresh',create_task=False)
            self.assertEqual(service.authorize(active,fresh)['status'],'approved')
            collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_revoke_expiry_keeps_history(self):
        from unittest import mock
        from contextlib import nullcontext
        from graph_engineering.core.action_authority import ActionAuthorityError
        from tests.support.action_authority import synthetic_start
        for expired in (False,True):
            with self.subTest(expired=expired),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
                service._manager.initialize_action_authority_order_storage();grant(service,active)
                request=refreshed(service,request);approved=service.authorize(active,request)
                clock=mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=600000000001) if expired else nullcontext()
                with clock:
                    if expired:
                        with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,request)
                        self.assertEqual(error.exception.code,'expired')
                    else:
                        revoke={k:request[k] for k in ('schema_version','request_id','task_id','action_id')}
                        self.assertEqual(service.revoke(active,{**revoke,'expected_generation':approved['receipt']['generation']})['status'],'revoked')
                        with self.assertRaises(ActionAuthorityError):service.authorize(active,request)
                    calls=service._manager._control/'synthetic-target-calls'
                    with self.assertRaises(Exception):synthetic_start(service,request,call_path=calls)
                    self.assertFalse(calls.exists())
                    with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                        self.assertEqual(conn.execute('SELECT count(*) FROM claims').fetchone()[0],0)
                        self.assertEqual(conn.execute("SELECT count(*) FROM events WHERE event_type='action.execution_started'").fetchone()[0],0)
                    collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_order_append_atomic_faults(self):
        import json
        for point in ('action_authority.after_security','action_authority.after_journal',
                      'action_authority.before_result_commit','action_authority.after_result_commit'):
            armed=[True]
            def fault(at):
                if armed[0] and at==point:raise RuntimeError('storage interruption')
            with self.subTest(point=point),registration_stack(lambda r,o,l:decision(r),fault) as (service,active,request,_base):
                service._manager.initialize_action_authority_order_storage();grant(service,active);request=refreshed(service,request)
                with self.assertRaises(RuntimeError):service.authorize(active,request)
                committed=point=='action_authority.after_result_commit'
                with service._scope() as (ledger,journal,_issuer),ledger.factory.open('doctor') as conn:
                    history=ledger._read_locked(conn,request['request_id']);proof=ledger._validate_order_locked(conn)
                    self.assertEqual(history[-1]['event_kind'],'approved' if committed else 'attempt')
                    self.assertEqual(journal.load(request['action_id']).state,'authorized' if committed else 'prepared')
                    members=json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests']
                    self.assertEqual(bool(members),committed)
                    self.assertEqual(len(proof['chain']),len(history)+1)
                armed[0]=False;approved=service.authorize(active,request);rows=order_rows(service)
                self.assertEqual(service.authorize(active,request),approved);self.assertEqual(order_rows(service),rows)
                collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

        import sqlite3
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);request=refreshed(service,request)
            with base._for_maintenance().open('migration') as conn,conn.transaction():
                conn.execute("CREATE TRIGGER synthetic_order_failure BEFORE INSERT ON action_authority_order WHEN NEW.ordinal=3 BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END")
            with self.assertRaises(sqlite3.IntegrityError):service.authorize(active,request)
            with service._scope() as (ledger,journal,_issuer),ledger.factory.open('doctor') as conn:
                self.assertEqual(ledger._read_locked(conn,request['request_id'])[-1]['event_kind'],'attempt')
                self.assertEqual(journal.load(request['action_id']).state,'prepared')
                self.assertEqual(len(ledger._validate_order_locked(conn)['chain']),3)
            with base._for_maintenance().open('migration') as conn,conn.transaction():conn.execute('DROP TRIGGER synthetic_order_failure')
            self.assertEqual(service.authorize(active,request)['status'],'approved');collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

        import os,signal
        from tests.support.action_authority import AuthorityProcess,child_authority_service,action_session
        for point in ('action_authority.after_security','action_authority.after_journal',
                      'action_authority.before_result_commit','action_authority.after_result_commit'):
            with self.subTest(kill=point),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
                service._manager.initialize_action_authority_order_storage();grant(service,active);request=refreshed(service,request)
                def work(checkpoint):
                    with child_authority_service(base) as child,action_session(lambda r,o,l:decision(r)) as session:
                        def fault(at):
                            if at=='action_authority.after_attempt_commit':checkpoint()
                            if at==point:os.kill(os.getpid(),signal.SIGKILL)
                        child._fault=fault
                        return child.authorize(session,request)
                child=AuthorityProcess(work)
                try:
                    self.assertEqual(child.message(),'READY');old=approval_surfaces(service);child.release()
                    with self.assertRaises(AssertionError):child.message()
                    _pid,status=os.waitpid(child.pid,0);child._joined=True;self.assertEqual(os.waitstatus_to_exitcode(status),-signal.SIGKILL)
                finally:child.close()
                crashed=approval_surfaces(service)
                if point!='action_authority.after_result_commit':self.assertEqual(crashed,old)
                else:self.assertNotEqual(crashed,old)
                # Fresh process handles and a fresh issued human invocation recover
                # interrupted attempts; committed approvals preserve their receipt.
                def recover(_checkpoint):
                    with child_authority_service(base) as child,action_session(lambda r,o,l:decision(r)) as session:
                        return child.authorize(session,request)
                restarted=AuthorityProcess(recover)
                try:recovered=restarted.message()['ok']
                finally:restarted.close()
                self.assertEqual(recovered['status'],'approved')
                complete=approval_surfaces(service)
                self.assertEqual(service.authorize(active,request),recovered);self.assertEqual(approval_surfaces(service),complete)
                if point=='action_authority.after_result_commit':self.assertEqual(complete,crashed)
                with service._scope() as (ledger,journal,_issuer),ledger.factory.open('doctor') as conn:
                    history=ledger._read_locked(conn,request['request_id']);chain=ledger._validate_order_locked(conn)['chain']
                    import json
                    members=json.loads(conn.execute('SELECT state_json FROM task_security_states').fetchone()[0])['authority_digests']
                    self.assertEqual(members,[recovered['receipt']['authority_digest']]);self.assertEqual(journal.load(request['action_id']).state,'authorized')
                    self.assertEqual([(row['request_id'],row['request_sequence'],row['ledger_event_digest']) for row in chain[1:]],[(row['request_id'],row['sequence'],row['event_digest']) for row in history])

    def test_anchor_upgrade_atomic_faults(self):
        for point in ('action_authority.order_after_table','action_authority.order_after_anchor','action_authority.order_after_marker'):
            with self.subTest(point=point),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
                approved=service.authorize(active,request);manager=service._manager;original=manager._fault
                def fault(at):
                    if at==point:raise RuntimeError('maintenance interruption')
                manager._fault=fault
                try:
                    with self.assertRaises(RuntimeError):manager.initialize_action_authority_order_storage()
                finally:manager._fault=original
                with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_master WHERE name='action_authority_order'").fetchone()[0],0)
                    self.assertIsNone(conn.execute("SELECT version FROM schema_versions WHERE component='action-authority-order'").fetchone())
                manager.initialize_action_authority_order_storage();rows=order_rows(service);manager.initialize_action_authority_order_storage()
                self.assertEqual(order_rows(service),rows);self.assertEqual(service.authorize(active,request),approved)
                grant(service,active);collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],0)

        import subprocess,sys,signal
        from tests.integration.test_wp09_learning import _MAINTENANCE_CHILD
        from tests.support.source_checkout_attestation import CONTROL_OPTION
        from tests.support.wp03_repository import ROOT
        code=_MAINTENANCE_CHILD.replace('manager.initialize_learning_storage()','manager.initialize_action_authority_order_storage()')
        for point in ('action_authority.order_after_table','action_authority.order_after_anchor','action_authority.order_after_marker'):
            with self.subTest(kill=point),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
                approved=service.authorize(active,request)
                argv=[sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}','-c',code,str(ROOT),str(base.data_root),str(base._test_installation_control_root),point]
                killed=subprocess.run(argv,capture_output=True,timeout=25);self.assertEqual(killed.returncode,-signal.SIGKILL)
                with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                    self.assertIsNone(conn.execute("SELECT version FROM schema_versions WHERE component='action-authority-order'").fetchone())
                    self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_master WHERE name='action_authority_order'").fetchone()[0],0)
                restarted=subprocess.run(argv[:-1]+['no-interruption'],capture_output=True,timeout=25);self.assertEqual(restarted.returncode,0)
                self.assertEqual(service.authorize(active,request),approved);self.assertEqual(len(order_rows(service)),1)

    def test_pmf_upgrade_legacy_unavailable(self):
        import subprocess,sys,signal,json
        from tests.integration.test_wp09_learning import _MAINTENANCE_CHILD
        from tests.support.source_checkout_attestation import CONTROL_OPTION
        from tests.support.wp03_repository import ROOT
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        for point in ('learning.upgrade_before_version','learning.after_version'):
            with self.subTest(upgrade_kill=point),registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,base):
                grant(service,active);collect(service,active)
                with base._for_maintenance().open('migration') as conn,conn.transaction():
                    row=conn.execute('SELECT observation_json,derived_json FROM pmf_aggregates').fetchone()
                    observation=json.loads(row[0]);observation.pop('authorization_window');observation['schema_version']='1.0.0'
                    value=json.loads(row[1]);value.pop('authorization_source');value['schema_version']='1.0.0'
                    conn.execute('UPDATE pmf_aggregates SET observation_json=?,observation_digest=?,derived_json=?,derived_digest=?',(canonical_json(observation),semantic_record_digest(observation),canonical_json(value),semantic_record_digest(value)))
                    conn.execute("UPDATE schema_versions SET version='1.0.0' WHERE component='pmf'")
                old=persisted(service)
                argv=[sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}','-c',_MAINTENANCE_CHILD,str(ROOT),str(base.data_root),str(base._test_installation_control_root),point]
                killed=subprocess.run(argv,capture_output=True,timeout=25);self.assertEqual(killed.returncode,-signal.SIGKILL)
                self.assertEqual(persisted(service),old)
                with base._for_maintenance().open('doctor') as conn:self.assertEqual(conn.execute("SELECT version FROM schema_versions WHERE component='pmf'").fetchone(),('1.0.0',))
                restarted=subprocess.run(argv[:-1]+['no-interruption'],capture_output=True,timeout=25);self.assertEqual(restarted.returncode,0)
                self.assertEqual(persisted(service),old)
                with base._for_maintenance().open('doctor') as conn:self.assertEqual(conn.execute("SELECT version FROM schema_versions WHERE component='pmf'").fetchone(),('1.1.0',))
        import json
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            grant(service,active)
            with base._for_maintenance().open('migration') as conn,conn.transaction():
                raw=conn.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
                observation=json.loads(raw);observation.pop('authorization_window');observation['schema_version']='1.0.0'
                conn.execute('UPDATE pmf_aggregates SET observation_json=?,observation_digest=?',(canonical_json(observation),semantic_record_digest(observation)))
                conn.execute("UPDATE schema_versions SET version='1.0.0' WHERE component='pmf'")
            before=persisted(service)
            with self.assertRaises(LearningError):collect(service,active)
            service._manager.initialize_learning_storage();self.assertEqual(persisted(service),before)
            service._manager.initialize_action_authority_order_storage();collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['availability'],'unavailable')
            grant(service,active,'learning:new-window',1);service.authorize(active,refreshed(service,request))
            collect(service,active,'learning:upgraded',2);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)

    def test_legacy_bundle_import(self):
        import tempfile,pathlib,json
        from tests.support.wp03_repository import repository_stack
        for authority in (False,True):
            with self.subTest(authority=authority),repository_stack() as stack,tempfile.TemporaryDirectory() as directory:
                _root,base,*_=stack;base._test_installation_scope.__exit__(None,None,None);manager=base._test_installation_manager
                if authority:manager.initialize_action_authority_storage()
                bundle=manager.export_bundle(pathlib.Path(directory)/'bundle',export_id='legacy')
                self.assertEqual(json.loads((bundle.root/manager._policy.bundle_manifest_filename).read_text())['schema_version'],'1.1' if authority else '1.0')
                imported=manager.import_bundle(bundle.root,pathlib.Path(directory)/'imported',repository_id='legacy:target')
                try:
                    with imported.factory.open('doctor') as conn:self.assertIsNone(conn.execute("SELECT version FROM schema_versions WHERE component='action-authority-order'").fetchone())
                finally:imported.close()

        with registration_stack(lambda r,o,l:decision(r),learning=False) as (service,active,request,_base),tempfile.TemporaryDirectory() as directory:
            service.authorize(active,request)
            with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                original=conn.execute('SELECT * FROM action_authority_events ORDER BY request_id,sequence').fetchall()
            manager=service._manager;bundle=manager.export_bundle(pathlib.Path(directory)/'legacy-nonempty',export_id='legacy:nonempty')
            self.assertEqual(json.loads((bundle.root/manager._policy.bundle_manifest_filename).read_text())['schema_version'],'1.1')
            imported=manager.import_bundle(bundle.root,pathlib.Path(directory)/'legacy-target',repository_id='legacy:nonempty-target')
            try:
                with imported.factory.open('doctor') as conn:
                    self.assertEqual(conn.execute('SELECT * FROM action_authority_events ORDER BY request_id,sequence').fetchall(),original)
                    self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='action_authority_order'").fetchone())
            finally:imported.close()

    def test_bundle_v12_roundtrip(self):
        import tempfile,pathlib,json,sqlite3
        from tests.support.action_authority import prepare_task_action
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        from graph_engineering.storage.migration import MigrationRepositoryError
        with registration_stack(lambda r,o,l:decision(r),learning=False) as (service,active,request,_base),tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);manager=service._manager
            manager.initialize_action_authority_order_storage();service.authorize(active,request)
            original=manager.export_bundle(root/'original',export_id='original')
            candidate=manager.import_bundle(original.root,root/'candidate',repository_id='ordered:candidate')
            try:manager.activate(candidate,release_id='synthetic-release',contract_id=manager._policy.repository_contract_id)
            finally:candidate.close()
            manager.initialize_action_authority_order_storage()
            fresh=prepare_task_action(service,active,request['task_id'],'action:current-epoch',create_task=False,action_kind='push')
            service.authorize(active,fresh);rows=order_rows(service)
            self.assertEqual(len({row[0] for row in rows}),2)
            bundle=manager.export_bundle(root/'bundle',export_id='ordered')
            self.assertEqual(json.loads((bundle.root/manager._policy.bundle_manifest_filename).read_text())['schema_version'],'1.2')
            imported=manager.import_bundle(bundle.root,root/'imported',repository_id='ordered:target')
            try:
                with imported.factory.open('doctor') as conn:self.assertEqual(conn.execute('SELECT * FROM action_authority_order ORDER BY order_epoch,ordinal').fetchall(),rows)
            finally:imported.close()
            # Keep logical records/manifest canonical and unchanged. Corrupt the
            # backed-up semantic chain with recomputed hashes so validation must
            # inspect actual anchors/pointers rather than JSON whitespace alone.
            backup=bundle.root/manager._factory.policy.database_filename;original_backup=backup.read_bytes()
            for mutation in ('archived-seal','current-pointer'):
                backup.write_bytes(original_backup)
                with sqlite3.connect(backup) as conn:
                    anchors={row[0]:json.loads(row[7])['activation_epoch'] for row in rows if row[1]==0}
                    epoch=min(anchors,key=anchors.get) if mutation=='archived-seal' else max(anchors,key=anchors.get)
                    chain=conn.execute('SELECT ordinal,body_json FROM action_authority_order WHERE order_epoch=? ORDER BY ordinal',(epoch,)).fetchall()
                    previous=None
                    for ordinal,raw in chain:
                        body=json.loads(raw)
                        if ordinal==0 and mutation=='archived-seal':body['legacy_rows_digest']='sha256-jcs-v1:'+'0'*64
                        if ordinal:
                            body['previous_order_digest']=previous
                            if ordinal==1 and mutation=='current-pointer':body['request_id']='foreign:missing'
                        digest=semantic_record_digest(body)
                        conn.execute('UPDATE action_authority_order SET body_json=?,order_digest=?,previous_order_digest=?,request_id=? WHERE order_epoch=? AND ordinal=?',
                            (canonical_json(body),digest,body.get('previous_order_digest'),body.get('request_id'),epoch,ordinal))
                        previous=digest
                with self.assertRaises(MigrationRepositoryError):manager.validate_bundle(bundle.root)
            backup.write_bytes(original_backup);self.assertEqual(manager.validate_bundle(bundle.root).bundle_digest,bundle.bundle_digest)

    def test_new_epoch_reseal(self):
        import pathlib,tempfile
        from tests.support.action_authority import prepare_task_action,synthetic_start
        from graph_engineering.core.action_authority import ActionAuthorityError
        with registration_stack(lambda r,o,l:decision(r),learning=False) as (service,active,request,_base),tempfile.TemporaryDirectory() as directory:
            manager=service._manager;root=pathlib.Path(directory)
            manager.initialize_action_authority_order_storage();approved=service.authorize(active,request);old=order_rows(service)
            bundle=manager.export_bundle(root/'bundle',export_id='epoch:original')
            imported=manager.import_bundle(bundle.root,root/'candidate',repository_id='epoch:activated')
            try:manifest=manager.activate(imported,release_id='synthetic-epoch-release',contract_id=manager._policy.repository_contract_id)
            finally:imported.close()
            self.assertGreater(manifest.activation_epoch,1)
            with self.assertRaises(ActionAuthorityError) as error:service.authorize(active,request)
            self.assertEqual(error.exception.code,'epoch_changed')
            calls=root/'target-calls'
            with self.assertRaises(Exception):synthetic_start(service,request,call_path=calls)
            self.assertFalse(calls.exists())
            manager.initialize_learning_storage();grant(service,active);collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['availability'],'unavailable')
            fresh=prepare_task_action(service,active,request['task_id'],'action:epoch-fresh',create_task=False,action_kind='push')
            with self.assertRaises(ActionAuthorityError):service.authorize(active,fresh)
            manager.initialize_action_authority_order_storage();current=order_rows(service)
            self.assertEqual([row for row in current if row[0]==old[0][0]],old)
            grant(service,active,'learning:epoch',1)
            self.assertEqual(service.authorize(active,refreshed(service,fresh))['status'],'approved')
            collect(service,active,'learning:epoch-collect',2)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)
            self.assertIsNotNone(approved['receipt'])

    def test_forged_order_partition(self):
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        import json
        damages=("DELETE FROM action_authority_order WHERE ordinal=2",
                 "UPDATE action_authority_order SET ledger_event_digest='sha256-jcs-v1:'||printf('%064d',0) WHERE ordinal=1",
                 "UPDATE action_authority_order SET request_id='foreign' WHERE ordinal=1")
        for damage in damages+('seal',):
            with self.subTest(damage=damage),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
                service._manager.initialize_action_authority_order_storage();grant(service,active);service.authorize(active,refreshed(service,request))
                with base._for_maintenance().open('migration') as conn,conn.transaction():
                    if damage=='seal':
                        raw=conn.execute('SELECT body_json FROM action_authority_order WHERE ordinal=0').fetchone()[0];body=json.loads(raw)
                        body['legacy_rows_digest']='sha256-jcs-v1:'+'0'*64
                        conn.execute('UPDATE action_authority_order SET body_json=?,order_digest=? WHERE ordinal=0',(canonical_json(body),semantic_record_digest(body)))
                    else:conn.execute(damage)
                before=persisted(service)
                with self.assertRaises(LearningError):collect(service,active)
                self.assertEqual(persisted(service),before)
