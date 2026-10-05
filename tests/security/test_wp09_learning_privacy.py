"""Learning isolation exercised through issued runtime sessions and real SQLite."""
from __future__ import annotations

import unittest
from unittest import mock

from graph_engineering.core.learning import LearningError
from tests.integration.test_wp09_learning import learning_stack, learning_request, learning_call
from tests.integration.test_wp07_runtime_parity import session, FIXTURE


class LearningPrivacyTests(unittest.TestCase):
    def test_tampered_installed_policy(self):
        from tests.unit.test_wp00_packaging import learning_wheel_probe
        learning_wheel_probe("""
import json
import graph_engineering
from graph_engineering.application.learning import LearningPolicyLoader
loader=LearningPolicyLoader.from_installation()
path=installed/'graph_engineering/config/learning/learning-policy-v1.json'
policy=json.loads(path.read_text());policy['rules'][0]['min_samples']=1
path.write_text(json.dumps(policy))
for load in (loader.require_current,LearningPolicyLoader.from_installation):
    try:load()
    except graph_engineering.DistributionIdentityError:pass
    else:raise AssertionError('tampered rule became trusted policy')
""")

    def test_cas_body_not_copied(self):
        from tests.integration.test_wp09_learning import secured_learning_stack
        with secured_learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','cas:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            with mock.patch.object(repository,'referenced_objects',side_effect=AssertionError('CAS traversal')) as refs, mock.patch.object(repository._objects,'get',side_effect=AssertionError('CAS body')) as body:
                learning_call(application,active,learning_request('collect_learning','cas:collect',expected_head=head,
                    expected_generation=1,expected_context_version=0))
                learning_call(application,active,learning_request('report_learning','cas:report',experiment_id='synthetic-default',task_ids=['task:learning-1']))
                refs.assert_not_called();body.assert_not_called()

    def test_canary_absent(self):
        import json
        from tests.integration.test_wp09_learning import secured_learning_stack
        from tests.integration.test_wp09_learning_metric_sources import cancel
        canary='synthetic-private-body-canary-67431'
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','canary:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            cancel(application,active,occurred_at=canary,expected_revision=5)
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            receipt=learning_call(application,active,learning_request('collect_learning','canary:collect',expected_head=head,
                expected_generation=1,expected_context_version=0))
            report=learning_call(application,active,learning_request('report_learning','canary:report',experiment_id='synthetic-default',task_ids=['task:learning-1']))
            self.assertNotIn(canary,json.dumps([receipt,report]))
            with factory.open('doctor') as connection:
                self.assertTrue(any(canary in row[0] for row in connection.execute('SELECT body_json FROM events')))
                for table in ('pmf_consents','pmf_aggregates','pmf_owner_context','pmf_tombstones'):
                    self.assertNotIn(canary,str(list(connection.execute('SELECT * FROM '+table))))

    def test_purge_crash_restart(self):
        import json,pathlib,signal,subprocess,sys,tempfile
        from tests.support.wp03_repository import ROOT
        from tests.support.source_checkout_attestation import CONTROL_OPTION
        child = r"""
import json,os,pathlib,signal,sys,tempfile
from unittest import mock
root=pathlib.Path(sys.argv[1]);tempfile.tempdir=sys.argv[2]
sys.path[:0]=[str(root)]+[str(root/p) for p in ('core','application','storage','adapters')]
from tests.integration.test_wp09_learning import secured_learning_stack,learning_call,learning_request
with secured_learning_stack() as (application,active,factory,repository):
    learning_call(application,active,learning_request('grant_learning','crash:grant',expected_generation=0,metric_ids=['completion'],expires_at_ns='1000'))
    with factory.open('doctor') as connection:
        database=str(factory._database)
        state=connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0]
    pathlib.Path(sys.argv[2],'location.json').write_text(json.dumps({'database':database,'state':state}))
    def fault(point):
        if point=='learning.after_purge_delete':os.kill(os.getpid(),signal.SIGKILL)
    with mock.patch.object(repository,'_fault',side_effect=fault),mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=7776001*10**9):
        learning_call(application,active,learning_request('purge_learning','crash:purge',expected_generation=1,trigger='garbage-collect'))
"""
        restart = r"""
import json,pathlib,sqlite3,sys
location=json.loads(pathlib.Path(sys.argv[1],'location.json').read_text())
with sqlite3.connect(location['database']) as db:
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert db.execute('SELECT count(*) FROM pmf_aggregates').fetchone()[0]==1
    assert db.execute('SELECT count(*) FROM purge_authorizations').fetchone()[0]==0
    assert db.execute("SELECT count(*) FROM pmf_tombstones WHERE action='purged'").fetchone()[0]==0
    assert db.execute('SELECT state_digest FROM task_security_states').fetchone()[0]==location['state']
    assert 'crash:purge' not in db.execute('SELECT receipts_json FROM pmf_consents').fetchone()[0]
"""
        with tempfile.TemporaryDirectory(prefix='gew-learning-crash-') as directory:
            result=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
                '-c',child,str(ROOT),directory],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
            self.assertEqual(result.returncode,-signal.SIGKILL)
            result=subprocess.run([sys.executable,'-B','-c',restart,directory],stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,timeout=10)
            self.assertEqual(result.returncode,0)

    def test_purge_legal_hold(self):
        import json
        from tests.integration.test_wp09_learning import secured_learning_stack
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        for blocker in ('legal_hold','rollback_dependency','unresolved_action'):
            with self.subTest(blocker=blocker),secured_learning_stack() as (application,active,factory,_repository):
                learning_call(application,active,learning_request('grant_learning','hold:grant',expected_generation=0,
                    metric_ids=['completion'],expires_at_ns='1000'))
                with factory.open('application') as connection:
                    with connection.transaction():
                        state=json.loads(connection.execute('SELECT state_json FROM task_security_states').fetchone()[0])
                        next(iter(state['retention_subjects'].values()))[blocker]=True
                        connection.execute('UPDATE task_security_states SET state_json=?,state_digest=?',
                            (canonical_json(state),semantic_record_digest({'contract':'task-security-state-v1','value':state})))
                with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=7776001*10**9):
                    result=learning_call(application,active,learning_request('purge_learning','hold:purge',
                        expected_generation=1,trigger='garbage-collect'))
                self.assertEqual(result['state'],'blocked')
                with factory.open('doctor') as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone()[0],1)
                    self.assertEqual(connection.execute('SELECT count(*) FROM purge_authorizations').fetchone()[0],0)

    def test_retained_handle_currentness(self):
        import json
        from tests.integration.test_wp09_learning import secured_learning_stack
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','handle:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            collect=learning_request('collect_learning','handle:collect',expected_head=head,expected_generation=1,expected_context_version=0)
            receipt=learning_call(application,active,collect)
            report=learning_request('report_learning','handle:report',experiment_id='synthetic-default',task_ids=['task:learning-1'])
            learning_call(application,active,report)
            with factory.open('application') as connection:
                with connection.transaction():
                    state=json.loads(connection.execute('SELECT state_json FROM task_security_states').fetchone()[0])
                    del state['retention_subjects'][receipt['retention_subject_ref']]
                    connection.execute('UPDATE task_security_states SET state_json=?,state_digest=?',
                        (canonical_json(state),semantic_record_digest({'contract':'task-security-state-v1','value':state})))
            for request in (collect,report):
                with self.assertRaisesRegex(LearningError,'^LEARNING_SECURITY$'):learning_call(application,active,request)

    def test_purge_authority_consumption(self):
        from tests.integration.test_wp09_learning import secured_learning_stack
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','purge:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            request=learning_request('purge_learning','purge:one',expected_generation=1,trigger='garbage-collect')
            early=learning_call(application,active,{**request,'request_id':'purge:early'})
            self.assertEqual(early['state'],'retain')
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=7776001*10**9):
                first=learning_call(application,active,request)
                self.assertEqual(first['state'],'purged')
                self.assertEqual(learning_call(application,active,request),first)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone()[0],0)
                self.assertEqual(connection.execute('SELECT count(*) FROM purge_authorizations').fetchone()[0],1)
                row=connection.execute("SELECT purge_authorization_digest FROM pmf_tombstones WHERE action='purged'").fetchone()
                self.assertEqual(row[0],first['purge_authorization_digest'])

    def test_corrupt_chain_rejected(self):
        from tests.integration.test_wp09_learning import capture_learning
        cases=(
            ("UPDATE events SET event_id='forged-index'",'LEARNING_SOURCE'),
            ("DELETE FROM transactions",'LEARNING_SOURCE'),
            ("UPDATE transactions SET head_digest='sha256-jcs-v1:'||printf('%064d',0)",'LEARNING_SOURCE'),
            ("UPDATE events SET body_json=printf('%070000d',0)",'LEARNING_BOUND'),
            ("UPDATE pmf_aggregates SET observation_digest='forged-observation'",'LEARNING_STALE'),
            ("UPDATE pmf_consents SET receipts_json=replace(printf('%02000d',0),'0','[')",'LEARNING_SOURCE'),
        )
        for sql,code in cases:
            with self.subTest(sql=sql),learning_stack() as (application,active,factory,repository):
                learning_call(application,active,learning_request('grant_learning','corrupt:grant',expected_generation=0,
                    metric_ids=['revision_count'],expires_at_ns='1000'))
                with factory.open('doctor') as connection:
                    head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
                request=learning_request('collect_learning','corrupt:capture',expected_head=head,
                    expected_generation=1,expected_context_version=0)
                with factory.open('migration') as connection:
                    with connection.transaction():connection.execute(sql)
                if code=='LEARNING_BOUND':
                    with mock.patch.object(repository,'_validate_event',side_effect=AssertionError('payload reached')) as validate:
                        with self.assertRaisesRegex(LearningError,'^'+code+'$'):capture_learning(application,active,request)
                        validate.assert_not_called()
                else:
                    with self.assertRaisesRegex(LearningError,'^'+code+'$'):capture_learning(application,active,request)

    def test_expired_consent_no_read(self):
        from tests.integration.test_wp09_learning_metric_sources import cancel
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','expiry:grant',expected_generation=0,
                metric_ids=['elapsed_bucket'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=1001):
                with mock.patch('graph_engineering.storage.learning._consent') as consent, mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                    cancel(application,active)
                    consent.assert_not_called()
                    sample.assert_not_called()
                with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                    learning_call(application,active,learning_request('record_learning_context','expiry:context',expected_generation=1,
                        expected_context_version=0,abandonment_code='not-stated',prior_task_id=None))
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)

    def test_preallocation_bounds(self):
        from tests.integration.test_wp09_learning import secured_learning_stack
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','bound:grant',expected_generation=0,
                metric_ids=['abandonment'],expires_at_ns='1000'))
            # Fill only via genuine owner operations. Admission must stop before
            # the reserved revocation capacity is consumed, without evicting receipts.
            reached=False
            for version in range(300):
                request=learning_request('record_learning_context',f'bound:context:{version}',expected_generation=1,
                    expected_context_version=version,abandonment_code='not-stated',prior_task_id=None)
                try:learning_call(application,active,request)
                except LearningError as error:
                    self.assertEqual(str(error),'LEARNING_BOUND')
                    reached=True
                    break
            self.assertTrue(reached)
            revoked=learning_call(application,active,learning_request('revoke_learning','bound:revoke',expected_generation=1))
            self.assertEqual(revoked['state'],'revoked')
            with factory.open('doctor') as connection:
                self.assertLessEqual(connection.execute('SELECT length(CAST(receipts_json AS BLOB)) FROM pmf_consents').fetchone()[0],65536)
            # A retained/blocked attempt cannot spend the successful purge reserve.
            for attempt in range(20):
                try:
                    learning_call(application,active,learning_request('purge_learning',f'bound:retain:{attempt}',expected_generation=2,trigger='garbage-collect'))
                except LearningError as error:
                    self.assertEqual(str(error),'LEARNING_BOUND');break
            else:self.fail('retained attempts consumed unbounded receipts')
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=7776001*10**9):
                result=learning_call(application,active,learning_request('purge_learning','bound:purge',expected_generation=2,trigger='garbage-collect'))
                self.assertEqual(result['state'],'purged')
        # Retained epochs stop a new grant before they consume the maximum
        # future observation. The already granted task must remain usable.
        from tests.integration.test_wp09_learning_metric_sources import approve
        with learning_stack() as (application,active,factory,_repository):
            reached=False
            for generation in range(40):
                try:
                    learning_call(application,active,learning_request('grant_learning',f'epoch:{generation}',
                        expected_generation=generation,metric_ids=['revision_count'],expires_at_ns='1000'))
                except LearningError as error:
                    self.assertEqual(str(error),'LEARNING_BOUND')
                    reached=True
                    break
            self.assertTrue(reached)
            approve(application,active)
            with factory.open('doctor') as connection:
                size=connection.execute('SELECT length(CAST(observation_json AS BLOB))+'
                    'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB))+512 '
                    'FROM pmf_aggregates').fetchone()[0]
                self.assertLessEqual(size,16384)
                self.assertEqual(connection.execute('SELECT head_sequence FROM tasks').fetchone()[0],5)

    def test_foreign_identity_before_read(self):
        with learning_stack() as (application, _active, factory, _repository):
            foreign=session(FIXTURE['cells'][1])
            try:
                request=learning_request('grant_learning','foreign:grant',expected_generation=0,
                    metric_ids=['revision_count'],expires_at_ns='1000')
                with mock.patch('graph_engineering.storage.learning._consent') as consent:
                    with self.assertRaisesRegex(LearningError,'^LEARNING_AUTH$'):
                        learning_call(application,foreign,request)
                    consent.assert_not_called()
                with factory.open('doctor') as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM pmf_consents').fetchone()[0],0)
            finally:
                foreign.close()

    def test_clock_rollback(self):
        from graph_engineering.storage.errors import RepositoryIntegrityError
        with learning_stack() as (application,active,factory,_repository):
            request=learning_request('grant_learning','clock:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000')
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=100):
                learning_call(application,active,request)
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=99):
                with self.assertRaises(RepositoryIntegrityError):
                    learning_call(application,active,learning_request('revoke_learning','clock:revoke',expected_generation=1))
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state,generation FROM pmf_consents').fetchone(),('granted',1))
            from tests.integration.test_wp09_learning_metric_sources import cancel
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=99):
                with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                    cancel(application,active)
                    sample.assert_not_called()
            with factory.open('doctor') as connection:
                self.assertGreater(connection.execute('SELECT head_sequence FROM tasks').fetchone()[0],
                    __import__('json').loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])['last_observed_sequence'])


if __name__=='__main__':
    unittest.main()
