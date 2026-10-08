"""Authorization body privacy, bounded admission and retained action audit."""
from __future__ import annotations
import json
import re
import unittest
from unittest import mock
from contextlib import contextmanager

from graph_engineering.core.learning import LearningError
from graph_engineering.storage.action_authority import ActionAuthorityLedger
from graph_engineering.storage.connection import ManagedConnection
from graph_engineering.storage.codec import canonical_json
from tests.support.action_authority import registration_stack,action_session
from tests.unit.test_action_authority import decision
from tests.integration.test_authorized_stage_learning import (
    bound_learning,collect,derived,grant,order_rows,persisted,refreshed,report,
)
from tests.integration.test_wp09_learning import learning_request,learning_call


@contextmanager
def body_reads():
    calls=[];original=ManagedConnection.execute
    def execute(connection,sql,parameters=()):
        normalized=' '.join(sql.lower().split())
        if normalized.startswith('select ') and 'from action_authority_events' in normalized:
            projection=normalized.split('from action_authority_events',1)[0]
            permitted=re.sub(r"length\(cast\(body_json as blob\)\)", '', projection)
            permitted=re.sub(r"json_extract\(body_json,'[^']*'\)", '', permitted)
            if 'body_json' in permitted or re.search(r'(select|,)\s*(?:[a-z_]+\.)?\*',permitted):
                calls.append(parameters[0] if parameters else '*')
        return original(connection,sql,parameters)
    with mock.patch.object(ManagedConnection,'execute',execute):yield calls


class AuthorizedStagePrivacyTests(unittest.TestCase):
    def test_no_consent_no_ledger_read(self):
        for state in ('missing','revoked','expired','omitted'):
            with self.subTest(state=state),registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,_base):
                service._manager.initialize_action_authority_order_storage()
                if state=='omitted':
                    with bound_learning(service) as (app,_factory,_repo):learning_call(app,active,learning_request('grant_learning','omit:grant',expected_generation=0,metric_ids=['completion'],expires_at_ns='900000000000'))
                elif state!='missing':grant(service,active)
                if state=='revoked':
                    with bound_learning(service) as (app,_factory,_repo):learning_call(app,active,learning_request('revoke_learning','revoke:grant',expected_generation=1))
                with body_reads() as calls,mock.patch.object(ActionAuthorityLedger,'_validate_order_locked',side_effect=AssertionError('authorization sampled')):
                    if state=='omitted':
                        collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['availability'],'unavailable')
                    elif state=='expired':
                        with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=900000000001),self.assertRaises(LearningError):collect(service,active)
                    else:
                        with self.assertRaises(LearningError):collect(service,active)
                    self.assertEqual(calls,[])

    def test_total_preallocation(self):
        for damage in ('metadata','sidecar-column','selected-body'):
            with self.subTest(damage=damage),registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
                service._manager.initialize_action_authority_order_storage();grant(service,active);service.authorize(active,refreshed(service,request))
                with base._for_maintenance().open('migration') as conn,conn.transaction():
                    if damage=='metadata':conn.execute("UPDATE action_authority_events SET event_digest=? WHERE sequence=1",('sha256-jcs-v1:'+'x'*9000,))
                    elif damage=='sidecar-column':conn.execute("UPDATE action_authority_order SET order_digest=? WHERE ordinal=0",('x'*9000,))
                    else:
                        raw=conn.execute('SELECT body_json FROM action_authority_events WHERE sequence=3').fetchone()[0];body=json.loads(raw);body['decision']['decision_ref']='x'*70000
                        conn.execute('UPDATE action_authority_events SET body_json=? WHERE sequence=3',(canonical_json(body),))
                before=persisted(service)
                with body_reads() as calls,self.assertRaises(LearningError) as error:collect(service,active)
                self.assertEqual(str(error.exception),'LEARNING_BOUND');self.assertEqual(calls,[]);self.assertEqual(persisted(service),before)

        from tests.support.action_authority import prepare_task_action
        # Every single capture fits 8MiB; the complete cohort must share it.
        large_ref='SYNTHETIC_BOUNDED_DECISION:'+('x'*53900)
        with registration_stack(lambda r,o,l:decision(r,status='pending',decision_ref=large_ref)) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage()
            requests=[request]
            for index in range(1,10):requests.append(prepare_task_action(service,active,'task:budget:'+str(index),'action:budget:'+str(index)))
            with bound_learning(service) as (app,_factory,_repo):
                for index,action in enumerate(requests):
                    learning_call(app,active,{**learning_request('grant_learning','budget:grant:'+str(index),expected_generation=0,metric_ids=['authorized_stage'],expires_at_ns='900000000000'),'task_id':action['task_id']})
            for action in requests:
                current=refreshed(service,action)
                for _attempt in range(16):self.assertEqual(service.authorize(active,current)['status'],'pending')
            with bound_learning(service) as (app,factory,_repo):
                for index,action in enumerate(requests):
                    with factory.open('doctor') as conn:head=conn.execute('SELECT head_digest FROM tasks WHERE task_id=?',(action['task_id'],)).fetchone()[0]
                    learning_call(app,active,{**learning_request('collect_learning','budget:collect:'+str(index),expected_head=head,expected_generation=1,expected_context_version=0),'task_id':action['task_id']})
            before=persisted(service)
            with body_reads() as calls,bound_learning(service) as (app,_factory,_repo),self.assertRaises(LearningError) as error:
                learning_call(app,active,learning_request('report_learning','budget:cohort',experiment_id='synthetic-default',task_ids=sorted(action['task_id'] for action in requests)))
            self.assertEqual(str(error.exception),'LEARNING_BOUND');self.assertLess(len(calls),len(requests));self.assertEqual(persisted(service),before)
        # A schema-sized aggregate reserve must be admitted before allocation.
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            with base._for_maintenance().open('migration') as conn,conn.transaction():conn.execute('UPDATE pmf_aggregates SET observation_json=?',('x'*16385,))
            before=persisted(service)
            with body_reads() as calls,self.assertRaises(LearningError) as error:collect(service,active)
            self.assertEqual(str(error.exception),'LEARNING_BOUND');self.assertEqual(calls,[]);self.assertEqual(persisted(service),before)

    def test_foreign_identity_epoch(self):
        from graph_engineering.core.action_authority import ActionAuthorityError
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            with action_session(lambda r,o,l:decision(r),owner_override='foreign-owner') as foreign:
                with self.assertRaises(ActionAuthorityError):service.authorize(foreign,refreshed(service,request))
                with self.assertRaises(LearningError):collect(service,foreign)
            self.assertEqual(len(order_rows(service)),1)
            collect(service,active);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],0)

    def test_canary_absent(self):
        canary='PRIVATE_PROMPT_NONCE_DECISION_RESOURCE_CANARY'
        with registration_stack(lambda r,o,l:decision(r,decision_ref=canary)) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            approved=service.authorize(active,refreshed(service,request));receipt,_req=collect(service,active);value=report(service,active)
            minimized=derived(service)
            with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                history=ledger._read_locked(conn,request['request_id']);self.assertIn(canary,json.dumps(history))
                forbidden=(canary,history[-1]['invocation']['invocation_nonce'],history[-1]['challenge']['prepared_action_digest'])
                output=json.dumps([receipt,value,minimized])
                for text in forbidden:self.assertNotIn(text,output)
                for table in ('pmf_consents','pmf_aggregates','pmf_owner_context','pmf_tombstones'):
                    self.assertNotIn(canary,str(conn.execute('SELECT * FROM '+table).fetchall()))
            self.assertEqual(approved['status'],'approved')

    def test_purge_keeps_action_audit(self):
        import tempfile,pathlib
        from graph_engineering.storage.migration import MigrationRepositoryError
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            service.authorize(active,refreshed(service,request));collect(service,active);before=order_rows(service)
            with bound_learning(service) as (app,factory,_repo),mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=7776001*10**9):
                result=learning_call(app,active,learning_request('purge_learning','purge:learning',expected_generation=1,trigger='garbage-collect'))
                self.assertEqual(result['state'],'purged')
                with factory.open('doctor') as conn:self.assertEqual(conn.execute('SELECT count(*) FROM action_authority_events').fetchone()[0],3)
            self.assertEqual(order_rows(service),before)
            with tempfile.TemporaryDirectory() as directory,self.assertRaises(MigrationRepositoryError):service._manager.export_bundle(pathlib.Path(directory)/'bundle',export_id='purged:export')

    def test_selected_task_body_gate(self):
        from tests.support.action_authority import prepare_task_action
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active)
            service.authorize(active,refreshed(service,request))
            endpoints={}
            for state in ('unselected','foreign-owner','revoked','expired','metric-omitted'):
                task_id='task:zz-'+state;endpoints[state]=task_id
                with action_session(lambda r,o,l:decision(r),owner_override='foreign-owner' if state=='foreign-owner' else None) as endpoint:
                    action=prepare_task_action(service,endpoint,task_id,'action:'+state)
                    with bound_learning(service) as (app,_factory,_repo):
                        metric_ids=['completion'] if state=='metric-omitted' else ['authorized_stage']
                        learning_call(app,endpoint,{**learning_request('grant_learning','grant:'+state,expected_generation=0,
                            metric_ids=metric_ids,expires_at_ns='1000' if state=='expired' else '900000000000'),'task_id':task_id})
                    service.authorize(endpoint,refreshed(service,action))
                    if state=='revoked':
                        with bound_learning(service) as (app,_factory,_repo):learning_call(app,endpoint,{**learning_request('revoke_learning','revoke:'+state,expected_generation=1),'task_id':task_id})
                    elif state=='metric-omitted':
                        with bound_learning(service) as (app,factory,_repo),factory.open('doctor') as conn:
                            head=conn.execute('SELECT head_digest FROM tasks WHERE task_id=?',(task_id,)).fetchone()[0]
                            learning_call(app,endpoint,{**learning_request('collect_learning','collect:'+state,expected_head=head,expected_generation=1,expected_context_version=0),'task_id':task_id})
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=1001):
                with body_reads() as calls:collect(service,active)
                self.assertEqual(calls,[request['request_id']]);self.assertEqual(derived(service)['metrics']['authorized_stage']['value'],1)
                for state in ('foreign-owner','revoked','expired'):
                    before=persisted(service)
                    with body_reads() as calls,bound_learning(service) as (app,_factory,_repo),self.assertRaises(LearningError):
                        learning_call(app,active,learning_request('report_learning','bad-cohort:'+state,experiment_id='synthetic-default',task_ids=['task:learning-1',endpoints[state]]))
                    self.assertEqual(calls,[]);self.assertEqual(persisted(service),before)
                with body_reads() as calls,bound_learning(service) as (app,_factory,_repo):
                    value=learning_call(app,active,learning_request('report_learning','omitted-cohort',experiment_id='synthetic-default',task_ids=['task:learning-1',endpoints['metric-omitted']]))
                self.assertEqual(calls,[request['request_id']])
                self.assertIsNone(value['cohort_vector'][1]['authorization_source'])
                with base._for_maintenance().open('migration') as conn,conn.transaction():
                    raw=conn.execute('SELECT body_json FROM action_authority_events WHERE request_id=? AND sequence=1',(request['request_id'],)).fetchone()[0]
                    body=json.loads(raw);body['challenge']['task_id']=endpoints['foreign-owner']
                    conn.execute('UPDATE action_authority_events SET body_json=? WHERE request_id=? AND sequence=1',(canonical_json(body),request['request_id']))
                with body_reads() as calls,self.assertRaises(LearningError):collect(service,active,'mixed:refused')
                self.assertEqual(calls,[])

    def test_selected_body_tamper(self):
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);service.authorize(active,refreshed(service,request))
            with base._for_maintenance().open('migration') as conn,conn.transaction():
                raw=conn.execute('SELECT body_json FROM action_authority_events WHERE sequence=3').fetchone()[0]
                body=json.loads(raw);body['decision']['decision_ref']='PRIVATE_SELECTED_TAMPER_CANARY'
                conn.execute('UPDATE action_authority_events SET body_json=? WHERE sequence=3',(canonical_json(body),))
            before=persisted(service)
            with self.assertRaises(LearningError) as error:collect(service,active)
            self.assertEqual(str(error.exception),'LEARNING_SOURCE');self.assertEqual(persisted(service),before)
            self.assertNotIn('PRIVATE_SELECTED_TAMPER_CANARY',str(error.exception))
