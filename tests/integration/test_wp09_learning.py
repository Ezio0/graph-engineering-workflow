"""Real local repository tests for consent-gated product learning."""
from __future__ import annotations

import unittest
import threading
import subprocess
import sys
import signal
import sqlite3
from unittest import mock
from contextlib import contextmanager

from graph_engineering.storage.connection import ManagedConnection
from graph_engineering.storage.migration import MigrationRepositoryError
from tests.support.wp03_repository import repository_stack
from tests.support.source_checkout_attestation import CONTROL_OPTION


@contextmanager
def learning_stack():
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.core.graph.state import TaskCommand
    from tests.integration.test_wp07_runtime_parity import session, FIXTURE, SCHEMAS, WORK
    with repository_stack() as stack:
        root, factory, locks, *_ = stack
        factory._test_installation_scope.__exit__(None, None, None)
        manager = factory._test_installation_manager
        manager.initialize_learning_storage()
        with manager.command_scope() as scope:
            bound = factory.bind_command_scope(scope)
            objects = ObjectRepository(bound, locks)
            leases = ResourceLeaseRepository(bound, locks)
            repository = TaskRepository(bound, locks, objects, command_scope=scope)
            application = TaskApplication(repository, repository, leases, schema_registry=SCHEMAS, context=WORK)
            active = session(FIXTURE['cells'][0])
            identity = {'task_id':'task:learning-1','owner_id':active.proof.owner_id,
                'runtime_kind':active.capabilities.runtime_kind,'runtime_lineage_id':active.proof.lineage_id}
            try:
                RuntimeMutationGateway.create(active, active.proof, identity,
                    lambda runtime: application.execute(identity['task_id'],TaskCommand('create',0,{'identity':identity}),runtime),
                    occurred_at='2026-10-04T00:00:00Z',lease_ttl_ns=100)
                yield application, active, bound, repository
            finally:
                active.close()
                objects.close()


def learning_request(operation, request_id, **fields):
    return {'schema_version':'1.0.0','operation':operation,'request_id':request_id,
        'task_id':'task:learning-1',**fields}


def learning_call(application, active, request):
    from graph_engineering.application.runtime import RuntimeMutationGateway
    return RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.learning(request,runtime))


def capture_learning(application,active,request):
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.application.learning import LearningPolicyLoader
    from graph_engineering.storage.learning import _capture_current_observation
    def operation(runtime):
        policy=LearningPolicyLoader.from_installation()
        closed=policy.validate_request(request)
        return _capture_current_observation(application,closed,runtime,policy)
    return RuntimeMutationGateway.invoke(active,active.proof,operation)


@contextmanager
def secured_learning_stack(graph=None):
    """Real current task plus installed security bootstrap, never a forged issuer."""
    import json
    from tests.support.wp03_repository import ROOT
    from tests.support.wp05a_security import security_context,security_schema_registry,binding_document,task_security_state_document
    from tests.integration.test_wp09_learning_metric_sources import approve
    from graph_engineering.application.security import SecurityContextIssuer
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.storage.security import SecurityStateRepository
    from graph_engineering.storage.codec import canonical_json,semantic_record_digest
    from graph_engineering.core.security.identity import SecurityBinding
    with learning_stack() as (application,active,factory,repository):
        approve(application,active,graph=graph,baseline_digest=semantic_record_digest({'intent':'synthetic learning'}))
        manifest=json.loads((ROOT/'config/security/security-runtime-v1.json').read_text())
        with factory.open('application') as connection:
            with connection.transaction():
                revision,snapshot_digest,raw=connection.execute('SELECT revision,snapshot_digest,snapshot_json FROM tasks').fetchone()
                domain=json.loads(raw)['domain']
                binding=binding_document()
                binding.update(task_id='task:learning-1',owner_id=active.proof.owner_id,
                    runtime_kind=active.capabilities.runtime_kind,runtime_lineage_id=active.proof.lineage_id,
                    scope_id=domain['project_scope_ref']['scope_id'],scope_digest=domain['project_scope_ref']['digest'],
                    baselines={x['kind']:x['digest'] for x in domain['baseline_refs']},snapshot_digest=snapshot_digest)
                binding['binding_digest']=SecurityBinding.digest_document(binding)
                state=task_security_state_document(binding=binding)
                state.update(task_revision=revision,task_snapshot_digest=snapshot_digest)
                connection.execute('INSERT INTO task_security_states VALUES(?,?,?,?,?)',
                    ('task:learning-1',revision,snapshot_digest,canonical_json(state),
                        semantic_record_digest({'contract':'task-security-state-v1','value':state})))
                connection.execute('INSERT INTO security_runtime_installation VALUES(1,?,?,?,?,?)',
                    (canonical_json(manifest),manifest['manifest_id'],manifest['manifest_digest'],
                        manifest['schema_registry']['registry_id'],manifest['schema_registry']['registry_digest']))
        context=security_context()
        issuer=SecurityContextIssuer(SecurityStateRepository(repository._factory),schema_registry=security_schema_registry(context),context=context)
        from graph_engineering.core.security.retention import RetentionPolicyRegistry
        from tests.support.wp05a_security import retention_policy_document
        registry=RetentionPolicyRegistry.from_dict(retention_policy_document(),schema_registry=issuer._schemas,
            context=context,runtime=issuer.runtime)
        secured=TaskApplication(repository,repository,application._leases,schema_registry=application._schemas,
            context=application._context,learning_security_issuer=issuer,learning_retention_registry=registry)
        yield secured,active,factory,repository


_MAINTENANCE_CHILD = r'''
import json, os, pathlib, signal, sys
from unittest import mock
root = pathlib.Path(sys.argv[1])
sys.path[:0] = [str(root)] + [str(root / part) for part in ("core", "application", "storage", "adapters")]
from tests.support.wp03_repository import policy, mount_observation
from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
with mock.patch.object(RepositoryDoctor, "_mount_observation", side_effect=mount_observation), mock.patch("graph_engineering.storage.clock.time.time_ns", return_value=0):
    factory = ConnectionFactory._attach_existing_for_maintenance(pathlib.Path(sys.argv[2]), policy(), "repository-test-v1")
    locks = LockedFileRegistry(factory)
    objects = ObjectRepository(factory, locks)
    manager = InstallationMigrationRepository.attach_command_plane(factory, locks, objects,
        control_root=pathlib.Path(sys.argv[3]), policy_document=json.loads((root / "config/contracts/migration-storage-policy-v1.json").read_text()))
    def fault(point):
        if point == sys.argv[4]:
            os.kill(os.getpid(), signal.SIGKILL)
    manager._fault = fault
    try:
        manager.initialize_learning_storage()
    finally:
        manager.close()
        objects.close()
        locks.close()
'''


def _maintenance_child(root, factory, point="no-interruption"):
    from tests.support.wp03_repository import ROOT
    return subprocess.run([
        sys.executable, "-B", "-X", f"{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}",
        "-c", _MAINTENANCE_CHILD, str(ROOT), str(root),
        str(factory._test_installation_control_root), point,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)


_CONCURRENT_CHILD = r'''
import json, pathlib, sys
from unittest import mock
root=pathlib.Path(sys.argv[1])
sys.path[:0]=[str(root)]+[str(root/part) for part in ('core','application','storage','adapters')]
from tests.support.wp03_repository import policy,mount_observation
from graph_engineering.storage.connection import ConnectionFactory,RepositoryDoctor,ManagedConnection
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.application.tasks import TaskApplication
from tests.integration.test_wp07_runtime_parity import session,FIXTURE,SCHEMAS,WORK
from tests.integration.test_wp09_learning import learning_call,learning_request
from tests.integration.test_wp09_learning_metric_sources import cancel
with mock.patch.object(RepositoryDoctor,'_mount_observation',side_effect=mount_observation),mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=0):
    factory=ConnectionFactory._attach_existing_for_maintenance(pathlib.Path(sys.argv[2]),policy(),'repository-test-v1')
    locks=LockedFileRegistry(factory)
    objects=ObjectRepository(factory,locks)
    manager=InstallationMigrationRepository.attach_command_plane(factory,locks,objects,
        control_root=pathlib.Path(sys.argv[3]),policy_document=json.loads((root/'config/contracts/migration-storage-policy-v1.json').read_text()))
    with manager.command_scope() as scope:
        bound=factory.bind_command_scope(scope)
        owned=ObjectRepository(bound,locks)
        repository=TaskRepository(bound,locks,owned,command_scope=scope)
        application=TaskApplication(repository,repository,ResourceLeaseRepository(bound,locks),schema_registry=SCHEMAS,context=WORK)
        active=session(FIXTURE['cells'][0])
        print('READY',flush=True)
        if sys.stdin.readline().strip()!='GO':raise AssertionError('missing barrier')
        original=ManagedConnection._begin_immediate
        announced=False
        def begin(connection):
            global announced
            if not announced:
                announced=True
                print('BEGIN',flush=True)
            return original(connection)
        with mock.patch.object(ManagedConnection,'_begin_immediate',begin):
            if sys.argv[4]=='revoke':
                learning_call(application,active,learning_request('revoke_learning','concurrent:revoke',expected_generation=1))
            else:
                cancel(application,active,expected_revision=int(sys.argv[4]))
        print('DONE',flush=True)
        active.close()
        owned.close()
    manager.close()
    objects.close()
    locks.close()
'''


@contextmanager
def concurrent_learning_writer(factory, action='revoke'):
    """Fresh process, genuine scope/session, independent SQLite connection."""
    from tests.support.wp03_repository import ROOT
    import select
    process=subprocess.Popen([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
        '-c',_CONCURRENT_CHILD,str(ROOT),str(factory._root),str(factory._command_scope._manager._control),action],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
    def line(expected):
        if not select.select([process.stdout],[],[],10)[0] or process.stdout.readline().strip()!=expected:
            raise AssertionError('concurrent writer barrier failed')
    def contend():
        process.stdin.write('GO\n');process.stdin.flush()
        line('BEGIN')
        if select.select([process.stdout],[],[],0.05)[0] or process.poll() is not None:
            raise AssertionError('concurrent writer escaped held transaction')
    try:
        line('READY')
        yield contend
        line('DONE')
        if process.wait(timeout=10)!=0:raise AssertionError('concurrent writer failed')
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=10)
        process.stdin.close();process.stdout.close()


class LearningIntegrationTests(unittest.TestCase):
    def test_failure_recovery_sequence(self):
        from tests.integration.test_wp04_runner import (graph_schemas,work_context,graph_candidate,load_graph,complete,
            loop_budgets,FallbackRuntime,PassingValidator,PassingReviewer)
        from graph_engineering.application.runtime import RuntimeMutationGateway
        from graph_engineering.core.graph.state import TaskCommand
        schemas=graph_schemas();context=work_context();candidate=graph_candidate()
        graph=load_graph(complete(candidate),schemas=schemas,context=context)
        budgets=loop_budgets(schemas=schemas,context=context)
        for selected in (['failure','recovery_attempt','completion'],['failure','completion']):
            with secured_learning_stack(graph) as (application,active,factory,repository):
                learning_call(application,active,learning_request('grant_learning','failure:grant',expected_generation=0,
                    metric_ids=selected,expires_at_ns='1000'))
                RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                    TaskCommand('run',5,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                    occurred_at='failure-run',lease_ttl_ns=100)
                runner=application.create_runner(repository._objects,budgets,context=context)
                result=RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:runner.run_until_stable(
                    'task:learning-1',runtime,graph,FallbackRuntime(),PassingValidator(),PassingReviewer(),max_steps=40),
                    occurred_at='failure-fallback',lease_ttl_ns=100)
                self.assertEqual((result.lifecycle,result.status),('blocked','stable'))
                RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute(
                    'task:learning-1',TaskCommand('resume',result.task_revision,{'resolution_evidence_refs':('evidence:resolved',),
                        'compatibility_evidence_ref':'evidence:compatible'}),runtime),
                    occurred_at='failure-resume',lease_ttl_ns=100)
                with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
                learning_call(application,active,learning_request('collect_learning','failure:collect',expected_head=head,
                    expected_generation=1,expected_context_version=0))
                report=learning_call(application,active,learning_request('report_learning','failure:report',
                    experiment_id='synthetic-default',task_ids=['task:learning-1']))
                metrics=report['observations'][0]['metrics']
                # A verified failure followed by resume is an attempt, not completion.
                self.assertEqual(metrics['completion']['value'],'incomplete')
                self.assertEqual(metrics['failure'],{'value':1,'availability':'observed'})
                self.assertEqual(metrics['recovery_attempt'],({'value':1,'availability':'observed'}
                    if 'recovery_attempt' in selected else {'value':None,'availability':'unavailable'}))
                if 'recovery_attempt' not in selected:
                    import json
                    with factory.open('doctor') as connection:
                        observed=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                    self.assertEqual(observed['recovery_attempt_count'],0)
                    self.assertFalse(observed['pending_failure'])
                learning_call(application,active,learning_request('revoke_learning','failure:revoke',expected_generation=1))
                learning_call(application,active,learning_request('grant_learning','failure:regrant',expected_generation=2,
                    metric_ids=['failure','recovery_attempt'],expires_at_ns='1000'))
                learning_call(application,active,learning_request('collect_learning','failure:fresh',expected_head=head,
                    expected_generation=3,expected_context_version=0))
                fresh=learning_call(application,active,learning_request('report_learning','failure:fresh-report',
                    experiment_id='synthetic-default',task_ids=['task:learning-1']))['observations'][0]['metrics']
                for name in ('failure','recovery_attempt'):
                    self.assertEqual(fresh[name],{'value':0,'availability':'observed'})

    def test_source_mapping_unknowns(self):
        from graph_engineering.core.learning import METRIC_IDS
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','unknown:grant',expected_generation=0,
                metric_ids=sorted(METRIC_IDS),expires_at_ns='1000'))
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            learning_call(application,active,learning_request('collect_learning','unknown:collect',
                expected_head=head,expected_generation=1,expected_context_version=0))
            report=learning_call(application,active,learning_request('report_learning','unknown:report',
                experiment_id='synthetic-default',task_ids=['task:learning-1']))
            metrics=report['observations'][0]['metrics']
            for name in ('repeat_use','authorized_stage','elapsed_bucket','abandonment'):
                self.assertEqual(metrics[name],{'value':None,'availability':'unavailable'})
            self.assertEqual(metrics['category'],{'value':'new-feature','availability':'observed'})
            self.assertEqual(metrics['risk_path'],{'value':'full-planned','availability':'observed'})
            self.assertEqual(metrics['failure'],{'value':0,'availability':'observed'})
            self.assertEqual(metrics['recovery_attempt'],{'value':0,'availability':'observed'})
            self.assertEqual(metrics['revision_count'],{'value':0,'availability':'observed'})
            self.assertEqual(report['rules'][0]['unknown_count'],1)
            self.assertEqual(report['rules'][0]['denominator'],0)
            # Valid code plus self-consistent snapshot digest cannot replace approval.
            import json
            from graph_engineering.storage.codec import canonical_json,semantic_record_digest
            from graph_engineering.core.learning import LearningError
            with factory.open('application') as connection:
                with connection.transaction():
                    snapshot=json.loads(connection.execute('SELECT snapshot_json FROM tasks').fetchone()[0])
                    snapshot['domain']['graph_ref']['risk_path']='compact-planned'
                    connection.execute('UPDATE tasks SET snapshot_json=?,snapshot_digest=?',
                        (canonical_json(snapshot),semantic_record_digest({'contract':'repository-snapshot-v1','value':snapshot})))
            with self.assertRaisesRegex(LearningError,'^LEARNING_SOURCE$'):
                capture_learning(application,active,learning_request('collect_learning','unknown:forged',
                    expected_head=head,expected_generation=1,expected_context_version=0))

    def test_caller_time_provenance(self):
        from graph_engineering.application.runtime import RuntimeMutationGateway
        from graph_engineering.core.graph.state import TaskCommand
        from graph_engineering.storage.learning_clock import ClockUnavailable
        from tests.integration.test_wp09_learning_metric_sources import cancel
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','caller:grant',expected_generation=0,
                metric_ids=['elapsed_bucket','completion'],expires_at_ns='1000'))
            with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample',side_effect=ClockUnavailable('LEARNING_CLOCK_DOMAIN')):
                RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                    TaskCommand('run',5,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                    occurred_at='2026-10-04T00:00:00Z',lease_ttl_ns=100)
                RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                    TaskCommand('pause',6,{}),runtime),occurred_at='2026-10-04T00:30:00Z',lease_ttl_ns=100)
                cancel(application,active,occurred_at='2026-10-04T01:00:00Z',expected_revision=7)
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            learning_call(application,active,learning_request('collect_learning','caller:collect',expected_head=head,
                expected_generation=1,expected_context_version=0))
            report=learning_call(application,active,learning_request('report_learning','caller:report',
                experiment_id='synthetic-default',task_ids=['task:learning-1']))
            metrics=report['observations'][0]['metrics']
            self.assertIsNone(metrics['elapsed_bucket']['value'])
            self.assertEqual(metrics['completion']['value'],'canceled')

    def test_relation_endpoint_currentness(self):
        for cell in (0,1,2):
            with self.subTest(cell=cell):self._relation_endpoint_currentness(cell)

    def _relation_endpoint_currentness(self,cell):
        import json
        from graph_engineering.core.learning import LearningError
        from graph_engineering.core.graph.state import TaskCommand
        from graph_engineering.application.runtime import RuntimeMutationGateway
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        from graph_engineering.core.security.identity import SecurityBinding
        from tests.integration.test_wp09_learning_metric_sources import approve
        with secured_learning_stack() as (application,active,factory,_repository):
            from tests.integration.test_wp07_runtime_parity import session,FIXTURE
            other_active=session(FIXTURE['cells'][cell]);self.addCleanup(other_active.close)
            other='task:learning-2'
            identity={'task_id':other,'owner_id':other_active.proof.owner_id,'runtime_kind':other_active.capabilities.runtime_kind,
                'runtime_lineage_id':other_active.proof.lineage_id}
            RuntimeMutationGateway.create(other_active,other_active.proof,identity,
                lambda runtime:application.execute(other,TaskCommand('create',0,{'identity':identity}),runtime),
                occurred_at='second-create',lease_ttl_ns=100)
            approve(application,other_active,baseline_digest=semantic_record_digest({'intent':'synthetic learning'}),task_id=other)
            with factory.open('application') as connection:
                with connection.transaction():
                    revision,snapshot,raw=connection.execute('SELECT revision,snapshot_digest,snapshot_json FROM tasks WHERE task_id=?',(other,)).fetchone()
                    state=json.loads(connection.execute('SELECT state_json FROM task_security_states').fetchone()[0])
                    state.update(task_id=other,task_revision=revision,task_snapshot_digest=snapshot)
                    state['binding'].update(task_id=other,snapshot_digest=snapshot,runtime_kind=identity['runtime_kind'],runtime_lineage_id=identity['runtime_lineage_id'])
                    state['binding']['binding_digest']=SecurityBinding.digest_document(state['binding'])
                    connection.execute('INSERT INTO task_security_states VALUES(?,?,?,?,?)',(other,revision,snapshot,
                        canonical_json(state),semantic_record_digest({'contract':'task-security-state-v1','value':state})))
            for task in ('task:learning-1',other):
                learning_call(application,active if task=='task:learning-1' else other_active,{**learning_request('grant_learning','relation:grant:'+task,
                    expected_generation=0,metric_ids=['repeat_use','completion'],expires_at_ns='1000'),'task_id':task})
            learning_call(application,active,learning_request('record_learning_context','relation:context',
                expected_generation=1,expected_context_version=0,abandonment_code='not-stated',prior_task_id=other))
            with factory.open('doctor') as connection:
                heads=dict(connection.execute('SELECT task_id,head_digest FROM tasks'))
            collect=learning_request('collect_learning','relation:collect',expected_head=heads['task:learning-1'],
                expected_generation=1,expected_context_version=1)
            first=learning_call(application,active,collect)
            learning_call(application,other_active,{**collect,'task_id':other,'request_id':'relation:collect:other',
                'expected_head':heads[other],'expected_context_version':0})
            report=learning_request('report_learning','relation:report',experiment_id='synthetic-default',task_ids=['task:learning-1',other])
            value=learning_call(application,active,report)
            self.assertEqual(value['observations'][0]['metrics']['repeat_use'],{'value':1,'availability':'owner-reported'})
            self.assertEqual(value['observations'][0]['relation_vector'][0][0],other)
            with self.assertRaisesRegex(LearningError,'^LEARNING_RELATION$'):
                learning_call(application,active,{**report,'request_id':'relation:omitted','task_ids':['task:learning-1']})
            learning_call(application,other_active,{**learning_request('record_learning_context','relation:other-context',
                expected_generation=1,expected_context_version=0,abandonment_code='not-stated',prior_task_id=None),'task_id':other})
            for stale in (collect,report):
                with self.assertRaisesRegex(LearningError,'^LEARNING_STALE$'):learning_call(application,active,stale)
            second=learning_call(application,active,{**collect,'request_id':'relation:recollect'})
            self.assertNotEqual(first['aggregate_ref'],second['aggregate_ref'])
            learning_call(application,other_active,{**learning_request('revoke_learning','relation:revoke',expected_generation=1),'task_id':other})
            with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                learning_call(application,active,{**collect,'request_id':'relation:revoked'})

    def test_revoke_publish_race(self):
        from graph_engineering.core.learning import LearningError
        with secured_learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','race:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
                before=connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0]
            request=learning_request('collect_learning','race:collect',expected_head=head,
                expected_generation=1,expected_context_version=0)
            # Expire while the owned transaction is active, after aggregate and
            # security registration have been attempted. Every write must roll back.
            from graph_engineering.storage import learning
            original=learning.strict_trusted_now
            expired=False
            def fault(point):
                nonlocal expired
                if point=='learning.before_commit':expired=True
            def now(connection):return 1000 if expired else original(connection)
            with mock.patch.object(repository,'_fault',side_effect=fault),mock.patch.object(learning,'strict_trusted_now',side_effect=now):
                with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):learning_call(application,active,request)
            with factory.open('doctor') as connection:
                self.assertIsNone(connection.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0],before)
            first=learning_call(application,active,request)
            report=learning_request('report_learning','race:report',experiment_id='synthetic-default',task_ids=['task:learning-1'])
            learning_call(application,active,report)
            learning_call(application,active,learning_request('revoke_learning','race:revoke',expected_generation=1))
            with factory.open('doctor') as connection:
                self.assertNotEqual(connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0],before)
            for stale in (request,report):
                with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):learning_call(application,active,stale)

        with secured_learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','concurrent:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            request=learning_request('collect_learning','concurrent:collect',expected_head=head,
                expected_generation=1,expected_context_version=0)
            with concurrent_learning_writer(factory) as contend:
                def fault(point):
                    if point=='learning.before_commit':contend()
                with mock.patch.object(repository,'_fault',side_effect=fault):
                    result=learning_call(application,active,request)
                self.assertEqual(result['state'],'collected')
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state FROM pmf_consents').fetchone()[0],'revoked')
            with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                learning_call(application,active,request)

    def test_fr13_positive(self):
        from graph_engineering.core.learning import LearningError
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','report:grant',expected_generation=0,
                metric_ids=['revision_count','completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            learning_call(application,active,learning_request('collect_learning','report:collect',expected_head=head,
                expected_generation=1,expected_context_version=0))
            request=learning_request('report_learning','report:one',experiment_id='synthetic-default',
                task_ids=['task:learning-1'])
            first=learning_call(application,active,request)
            self.assertEqual(first['rules'][0]['verdict'],'insufficient-data')
            self.assertEqual(first['rules'][0]['denominator'],0)
            self.assertEqual(first['rules'][0]['unknown_count'],1)
            self.assertEqual(first['observations'][0]['metrics']['revision_count']['value'],0)
            self.assertEqual(learning_call(application,active,request),first)
            self.assertNotIn('ticks_ns',str(first))
            learning_call(application,active,learning_request('record_learning_context','report:context',
                expected_generation=1,expected_context_version=0,abandonment_code='not-stated',prior_task_id=None))
            with self.assertRaisesRegex(LearningError,'^LEARNING_STALE$'):
                learning_call(application,active,request)

    def test_fr13_refusal(self):
        from graph_engineering.core.learning import LearningError
        with learning_stack() as (application,active,factory,_repository):
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            request=learning_request('collect_learning','refused:collect',expected_head=head,
                expected_generation=0,expected_context_version=0)
            with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):learning_call(application,active,request)
            learning_call(application,active,learning_request('grant_learning','refused:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000'))
            with self.assertRaisesRegex(LearningError,'^LEARNING_SECURITY$'):
                learning_call(application,active,{**request,'expected_generation':1})
            with factory.open('doctor') as connection:
                self.assertIsNone(connection.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])

    def test_terminal_vs_self_report(self):
        import json
        from tests.integration.test_wp09_learning_metric_sources import cancel
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','terminal:grant',expected_generation=0,
                metric_ids=['completion','abandonment'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            first=learning_call(application,active,learning_request('collect_learning','terminal:initial',expected_head=head,
                expected_generation=1,expected_context_version=0))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0]
            cancel(application,active,expected_revision=5)
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
                self.assertNotEqual(connection.execute('SELECT state_digest FROM task_security_states').fetchone()[0],before)
                state=json.loads(connection.execute('SELECT state_json FROM task_security_states').fetchone()[0])
                self.assertEqual(state['retention_subjects'][first['retention_subject_ref']]['snapshot_digest'],state['task_snapshot_digest'])
            learning_call(application,active,learning_request('record_learning_context','terminal:abandoned',expected_generation=1,
                expected_context_version=0,abandonment_code='abandoned',prior_task_id=None))
            learning_call(application,active,learning_request('collect_learning','terminal:final',expected_head=head,
                expected_generation=1,expected_context_version=1))
            with factory.open('doctor') as connection:
                metrics=json.loads(connection.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])['metrics']
            self.assertEqual(metrics['completion'],{'value':'canceled','availability':'observed'})
            self.assertEqual(metrics['abandonment'],{'value':'abandoned','availability':'owner-reported'})
            report=learning_call(application,active,learning_request('report_learning','terminal:report',
                experiment_id='synthetic-default',task_ids=['task:learning-1']))
            rule=report['rules'][0]
            self.assertEqual((rule['numerator'],rule['denominator'],rule['unknown_count']),(0,1,0))
            self.assertEqual(rule['counter_evidence_refs'],['task:learning-1'])
            self.assertEqual(rule['verdict'],'insufficient-data')

    def test_context_cas_stale_recollect(self):
        import json
        from graph_engineering.core.learning import LearningError
        with secured_learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','collect:grant',expected_generation=0,
                metric_ids=['revision_count','abandonment'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            collect=learning_request('collect_learning','collect:0',expected_head=head,
                expected_generation=1,expected_context_version=0)
            first=learning_call(application,active,collect)
            self.assertEqual(first['state'],'collected')
            self.assertEqual(learning_call(application,active,collect),first)
            with factory.open('doctor') as connection:
                derived=json.loads(connection.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])
                state=json.loads(connection.execute('SELECT state_json FROM task_security_states').fetchone()[0])
            self.assertEqual(derived['metrics']['revision_count'],{'value':0,'availability':'observed'})
            self.assertEqual(state['retention_subjects'][first['retention_subject_ref']]['category'],'pmf-aggregate')
            learning_call(application,active,learning_request('record_learning_context','owner:abandoned',expected_generation=1,
                expected_context_version=0,abandonment_code='abandoned',prior_task_id=None))
            with self.assertRaisesRegex(LearningError,'^LEARNING_STALE$'):learning_call(application,active,collect)
            second=learning_call(application,active,{**collect,'request_id':'collect:1','expected_context_version':1})
            self.assertNotEqual(first['aggregate_ref'],second['aggregate_ref'])
            with factory.open('doctor') as connection:
                derived=json.loads(connection.execute('SELECT derived_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(derived['metrics']['abandonment'],{'value':'abandoned','availability':'owner-reported'})
            self.assertIsNone(derived['metrics']['authorized_stage']['value'])
    def test_source_head_race(self):
        from graph_engineering.core.learning import LearningError
        from tests.integration.test_wp09_learning_metric_sources import cancel
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','capture:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            request=learning_request('collect_learning','capture:1',expected_head=head,
                expected_generation=1,expected_context_version=0)
            first=capture_learning(application,active,request)
            self.assertEqual(first['source_head'],head)
            self.assertEqual(first['observation']['availability'],'missing-prd')
            cancel(application,active)
            with self.assertRaisesRegex(LearningError,'^LEARNING_STALE$'):
                capture_learning(application,active,request)
            with factory.open('doctor') as connection:
                new_head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            fresh=capture_learning(application,active,{**request,'expected_head':new_head})
            self.assertEqual(fresh['source_head'],new_head)
            learning_call(application,active,learning_request('revoke_learning','capture:revoke',expected_generation=1))
            with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                capture_learning(application,active,{**request,'expected_head':new_head})
        from tests.integration.test_wp09_learning_metric_sources import approve
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','approved:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000'))
            approve(application,active)
            with factory.open('doctor') as connection:
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            captured=capture_learning(application,active,learning_request('collect_learning','approved:capture',
                expected_head=head,expected_generation=1,expected_context_version=0))
            self.assertEqual(captured['observation']['availability'],'complete')
            self.assertEqual(captured['observation']['current_prd_sequence'],5)

        with secured_learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','head-race:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            request=learning_request('collect_learning','head-race:collect',expected_head=head,
                expected_generation=1,expected_context_version=0)
            with concurrent_learning_writer(factory,'5') as contend:
                def fault(point):
                    if point=='learning.before_commit':contend()
                with mock.patch.object(repository,'_fault',side_effect=fault):
                    learning_call(application,active,request)
            with self.assertRaisesRegex(LearningError,'^LEARNING_STALE$'):
                learning_call(application,active,request)
            with factory.open('doctor') as connection:new_head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            self.assertNotEqual(head,new_head)
            learning_call(application,active,{**request,'request_id':'head-race:fresh','expected_head':new_head})

    def test_prospective_regrant(self):
        from graph_engineering.core.learning import LearningError
        with learning_stack() as (application, active, factory, _repository):
            grant = learning_request('grant_learning','grant:1',expected_generation=0,
                metric_ids=['revision_count','elapsed_bucket'],expires_at_ns='1000')
            first = learning_call(application,active,grant)
            self.assertEqual(first['generation'],1)
            self.assertEqual(first,learning_call(application,active,grant))
            with self.assertRaises(LearningError):
                learning_call(application,active,{**grant,'metric_ids':['elapsed_bucket']})
            revoke = learning_request('revoke_learning','revoke:1',expected_generation=1)
            suppressed = learning_call(application,active,revoke)
            self.assertEqual(suppressed['state'],'revoked')
            self.assertEqual(suppressed['generation'],2)
            with self.assertRaises(LearningError):
                learning_call(application,active,{**grant,'request_id':'stale:grant'})
            # Replaying an old exact request returns its old receipt, never a grant.
            self.assertEqual(learning_call(application,active,grant),first)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state,generation FROM pmf_consents').fetchone(),('revoked',2))
            second = learning_call(application,active,{**grant,'request_id':'grant:2','expected_generation':2})
            self.assertEqual(second['generation'],3)
            with factory.open('doctor') as connection:
                row=connection.execute('SELECT consent_generation,observation_json,retained_epochs_json FROM pmf_aggregates').fetchone()
                self.assertEqual(row[0],3)
                import json
                observation=json.loads(row[1])
                self.assertEqual(observation['grant_sequence'],first['source_sequence'])
                self.assertIsNone(observation['start_sample'])
                self.assertIsNone(observation['current_prd_sequence'])
                epochs=json.loads(row[2])
                self.assertEqual(len(epochs),1)
                self.assertEqual(epochs[0]['generation'],1)
                self.assertEqual(epochs[0]['observation']['grant_sequence'],first['source_sequence'])

    def test_schema_upgrade_restart(self):
        with repository_stack() as stack:
            root, factory, *_ = stack
            manager = factory._test_installation_manager
            # A normal command retains a shared installation lease. Maintenance
            # cannot upgrade underneath it, even on the same thread.
            with self.assertRaises(MigrationRepositoryError):
                manager.initialize_learning_storage()
            with factory._for_maintenance().open("doctor") as connection:
                self.assertEqual(connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'pmf_%'"
                ).fetchone()[0], 0)
            factory._test_installation_scope.__exit__(None, None, None)
            manager.initialize_learning_storage()
            restarted = _maintenance_child(root, factory)
            self.assertEqual(restarted.returncode, 0, "fresh maintenance process failed")
            with factory._for_maintenance().open("doctor") as connection:
                self.assertEqual(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pmf_%' ORDER BY name"
                ).fetchall(), [(name,) for name in (
                    "pmf_aggregates", "pmf_consents", "pmf_owner_context", "pmf_tombstones"
                )])
                self.assertEqual(connection.execute(
                    "SELECT version FROM schema_versions WHERE component='pmf'"
                ).fetchall(), [("1.1.0",)])
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute("UPDATE schema_versions SET version='999' WHERE component='pmf'")
            with self.assertRaises(MigrationRepositoryError):
                manager.initialize_learning_storage()

    def test_schema_upgrade_crash(self):
        for point in ("learning.after_table.0", "learning.after_table.3", "learning.after_version"):
            with self.subTest(point=point), repository_stack() as stack:
                root, factory, *_ = stack
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                crashed = _maintenance_child(root, factory, point)
                self.assertEqual(crashed.returncode, -signal.SIGKILL)
                with factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT count(*) FROM sqlite_master WHERE name LIKE 'pmf_%'"
                    ).fetchone()[0], 0)
                    self.assertIsNone(connection.execute(
                        "SELECT version FROM schema_versions WHERE component='pmf'"
                    ).fetchone())
                restarted = _maintenance_child(root, factory)
                self.assertEqual(restarted.returncode, 0, "recovery process failed")
                manager.initialize_learning_storage()

    def test_migration_no_pmf_export(self):
        cases = (
            None,
            "full-schema",
            "CREATE TABLE pmf_consents (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_aggregates (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_owner_context (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_tombstones (task_id TEXT PRIMARY KEY) STRICT",
            "INSERT INTO schema_versions VALUES ('pmf','999','test')",
            "consent-only",
            "tombstone-only",
        )
        for index, statement in enumerate(cases):
            with self.subTest(statement=statement), repository_stack() as stack:
                root, factory, *_ = stack
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                destination = root.parent / f"export-{index}"
                if statement is None:
                    manager.export_bundle(destination, export_id=f"export-{index}")
                    self.assertTrue(destination.is_dir())
                    continue
                if statement == "full-schema":
                    manager.initialize_learning_storage()
                else:
                    with factory._for_maintenance().open("migration") as connection:
                        with connection.transaction():
                            if statement in {"consent-only", "tombstone-only"}:
                                table = "pmf_consents" if statement == "consent-only" else "pmf_tombstones"
                                connection.execute(f"CREATE TABLE {table} (task_id TEXT PRIMARY KEY) STRICT")
                                connection.execute(f"INSERT INTO {table} VALUES ('synthetic-task')")
                            else:
                                connection.execute(statement)
                with mock.patch.object(ManagedConnection, "online_backup") as backup:
                    execute = ManagedConnection.execute
                    def no_export_hold(connection, sql, parameters=()):
                        if sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) and "export_holds" in sql:
                            self.fail("export hold mutated before rejection")
                        return execute(connection, sql, parameters)
                    with mock.patch.object(ManagedConnection, "execute", autospec=True, side_effect=no_export_hold):
                        with self.assertRaisesRegex(MigrationRepositoryError, "learning"):
                            manager.export_bundle(destination, export_id=f"export-{index}")
                    backup.assert_not_called()
                self.assertFalse(destination.exists())
                with factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM export_holds").fetchone()[0], 0)
        # Pause export after acquiring the installation lock. A second thread
        # cannot initialize learning between the guard and the online backup.
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            reached = threading.Event()
            attempted = threading.Event()
            failures = []
            def maintenance():
                if not reached.wait(5):
                    failures.append("export barrier was not reached")
                    attempted.set()
                    return
                try:
                    manager.initialize_learning_storage()
                except MigrationRepositoryError:
                    pass
                except BaseException as error:
                    failures.append(type(error).__name__)
                else:
                    failures.append("initialization crossed export lock")
                finally:
                    attempted.set()
            def barrier(point):
                if point == "export.before_backup":
                    reached.set()
                    self.assertTrue(attempted.wait(5))
            worker = threading.Thread(target=maintenance)
            worker.start()
            try:
                with mock.patch.object(manager, "_fault", side_effect=barrier):
                    manager.export_bundle(root.parent / "serialized-export", export_id="serialized")
            finally:
                reached.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            manager.initialize_learning_storage()
            with self.assertRaises(MigrationRepositoryError):
                manager.export_bundle(root.parent / "after-initialization", export_id="after")
            self.assertFalse((root.parent / "after-initialization").exists())
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            destination = root.parent / "during-initialization"
            reached, attempted = threading.Event(), threading.Event()
            failures = []
            def exporting():
                if not reached.wait(5):
                    failures.append("initialization barrier was not reached")
                    attempted.set()
                    return
                try:
                    manager.export_bundle(destination, export_id="during")
                except MigrationRepositoryError:
                    pass
                except BaseException as error:
                    failures.append(type(error).__name__)
                else:
                    failures.append("export crossed maintenance lock")
                finally:
                    attempted.set()
            def initializing(point):
                if point == "learning.after_table.0":
                    reached.set()
                    self.assertTrue(attempted.wait(5))
            worker = threading.Thread(target=exporting)
            worker.start()
            try:
                with mock.patch.object(manager, "_fault", side_effect=initializing), mock.patch.object(ManagedConnection, "online_backup") as backup:
                    manager.initialize_learning_storage()
                    backup.assert_not_called()
            finally:
                reached.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertFalse(destination.exists())
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            execute = ManagedConnection.execute
            def metadata_error(connection, sql, parameters=()):
                if "lower(name)" in sql:
                    raise sqlite3.DatabaseError("private-metadata-canary")
                return execute(connection, sql, parameters)
            destination = root.parent / "metadata-error"
            with mock.patch.object(ManagedConnection, "execute", autospec=True, side_effect=metadata_error), mock.patch.object(ManagedConnection, "online_backup") as backup:
                with self.assertRaisesRegex(MigrationRepositoryError, "^learning export metadata is unavailable$"):
                    manager.export_bundle(destination, export_id="metadata-error")
                backup.assert_not_called()
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
