"""Task-transaction learning sources; no caller-supplied measurements."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import unittest
from unittest import mock
from contextlib import contextmanager

from graph_engineering.application.runtime import RuntimeMutationGateway
from graph_engineering.core.graph.state import TaskCommand
from tests.integration.test_wp09_learning import learning_stack, learning_call, learning_request


_TASK_CRASH_CHILD=r'''
import json, os, pathlib, signal, sys
from unittest import mock
from contextlib import contextmanager
root=pathlib.Path(sys.argv[1])
mode=sys.argv[4] if len(sys.argv)>4 else 'crash'
sys.path[:0]=[str(root)]+[str(root/part) for part in ('core','application','storage','adapters')]
from tests.support.wp03_repository import policy,mount_observation
from graph_engineering.storage.connection import ConnectionFactory,RepositoryDoctor
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.application.tasks import TaskApplication
from tests.integration.test_wp07_runtime_parity import session,FIXTURE,SCHEMAS,WORK
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
        def fault(point):
            if point=='commit.before_commit' and mode=='crash':os.kill(os.getpid(),signal.SIGKILL)
        repository=TaskRepository(bound,locks,owned,command_scope=scope,fault_hook=fault)
        application=TaskApplication(repository,repository,ResourceLeaseRepository(bound,locks),schema_registry=SCHEMAS,context=WORK)
        active=session(FIXTURE['cells'][0])
        cancel(application,active,occurred_at='crash-turn',expected_revision=7 if mode=='terminal' else 1)
if mode=='crash':raise AssertionError('crash hook did not run')
'''


def cancel(application,active,occurred_at='2026-10-04T00:00:01Z',expected_revision=1):
    def operation(runtime):
        plan=application.prepare_retention_plan('task:learning-1','cancel',runtime)
        return application.cancel_with_retention('task:learning-1',expected_revision,plan['plan_id'],runtime)
    return RuntimeMutationGateway.invoke(active,active.proof,
        operation,
        occurred_at=occurred_at,lease_ttl_ns=100)


def approve(application,active,graph=None,baseline_digest=None,task_id='task:learning-1'):
    from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
    def operation(runtime):
        application.execute_scope(task_id,TaskCommand('bind_project_scope',1,
            {'project_scope_ref':Fixtures.scope('drafted')}),Fixtures.project_scope(),runtime)
    RuntimeMutationGateway.invoke(active,active.proof,operation,occurred_at='scope-turn',lease_ttl_ns=100)
    RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.execute(task_id,TaskCommand('request_prd_approval',2,
            {'prd_candidate_ref':'artifact:prd-test'}),runtime),occurred_at='request-turn',lease_ttl_ns=100)
    approval=Fixtures.approval()
    approval['baseline_refs']=({**approval['baseline_refs'][0],'approved_by':active.proof.owner_id},)
    if baseline_digest is not None:
        approval['baseline_refs']=({**approval['baseline_refs'][0],'digest':baseline_digest},)
    if graph is not None:
        approval['graph_ref']={'graph_id':graph.graph_id,'graph_version':graph.graph_version,
            'profile_id':'new-feature','profile_version':'1.0.0','risk_path':'full-planned','graph_digest':graph.digest}
    return RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.execute(task_id,TaskCommand('approve_prd',3,approval),runtime),
        occurred_at='approval-turn',lease_ttl_ns=100)


@contextmanager
def observed_runner(graph_override=None):
    from tests.integration.test_wp04_runner import (ApplicationRunnerIntegrationTests,PassingRuntime,PassingValidator)
    with learning_stack() as (application,active,factory,repository):
        _schemas,context,graph,budgets=ApplicationRunnerIntegrationTests().stack(with_budget=True)
        if graph_override is not None:graph=graph_override
        learning_call(application,active,learning_request('grant_learning','runner:grant',expected_generation=0,
            metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000'))
        approve(application,active,graph)
        RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
            TaskCommand('run',5,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
            occurred_at='observed-run',lease_ttl_ns=100)
        runner=application.create_runner(repository._objects,budgets,context=context)
        def run(reviewer,turn):
            return RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:runner.run_until_stable(
                'task:learning-1',runtime,graph,PassingRuntime(),PassingValidator(),reviewer,max_steps=40),
                occurred_at=turn,lease_ttl_ns=100)
        def observation():
            with factory.open('doctor') as connection:
                return json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
        yield application,active,factory,repository,run,observation


class LearningMetricSourceTests(unittest.TestCase):
    def test_reapproval_window(self):
        from tests.integration.test_wp04_runner import ReviseThenPassReviewer,ApplicationRunnerIntegrationTests
        from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
        from tests.unit.test_wp06_project_scope import scope_document,load
        from graph_engineering.core.project import ProjectScope
        from graph_engineering.storage.codec import semantic_record_digest
        from tests.integration.test_wp04_runner import graph_candidate,graph_schemas,work_context,load_graph,complete
        graph_doc=graph_candidate();graph_doc['nodes'][0]['invalidation_tags']=['target-api']
        for node in graph_doc['nodes']:node['loop_budget_ref']='loop:bounded-v1'
        graph=load_graph(complete(graph_doc),schemas=graph_schemas(),context=work_context())
        with observed_runner(graph) as (application,active,factory,_repository,run,observation):
            self.assertEqual(run(ReviseThenPassReviewer(),'reapproval:review').status,'completion_ready')
            before=observation();self.assertEqual(before['revision_count'],1)
            document=scope_document();document['version']=2
            document['target_bindings'][0]['verification_contract_ref']='verify-reapproved-target'
            document['scope_digest']=ProjectScope.digest_document(document);candidate=load(document)
            with factory.open('doctor') as connection:
                revision=json.loads(connection.execute('SELECT snapshot_json FROM tasks').fetchone()[0])['domain']['task_revision']
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('pause',revision,{}),runtime),occurred_at='reapproval:pause',lease_ttl_ns=100)
            revision+=1
            proposed=RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.propose_scope_change(
                'task:learning-1',revision,candidate,graph,runtime),occurred_at='reapproval:propose',lease_ttl_ns=100)
            approval=Fixtures.approval()
            approval['project_scope_ref']={'scope_id':candidate.scope_id,'version':candidate.version,
                'digest':candidate.scope_digest,'status':'frozen'}
            approval['graph_ref']={'graph_id':graph.graph_id,'graph_version':graph.graph_version,
                'profile_id':'new-feature','profile_version':'1.0.0','risk_path':'full-planned','graph_digest':graph.digest}
            approval['baseline_refs']=({**approval['baseline_refs'][0],'version':2,'approved_by':active.proof.owner_id,
                'digest':semantic_record_digest({'intent':'reapproved synthetic learning'})},)
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('approve_prd',proposed.task_revision,approval),runtime),occurred_at='reapproval:accept',lease_ttl_ns=100)
            after=observation()
            self.assertEqual(after['availability'],'complete')
            self.assertEqual(after['revision_count'],0)
            self.assertEqual(after['human_interruption_count'],0)
            self.assertGreater(after['current_prd_sequence'],before['current_prd_sequence'])
            self.assertNotEqual(after['current_baseline_digest'],before['current_baseline_digest'])

    def test_restart_start_sample(self):
        from tests.support.wp03_repository import ROOT
        from tests.support.source_checkout_attestation import CONTROL_OPTION
        with learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','restart:grant',expected_generation=0,
                metric_ids=['elapsed_bucket','completion'],expires_at_ns='1000'))
            approve(application,active)
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('run',5,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                occurred_at='restart:start',lease_ttl_ns=100)
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('pause',6,{}),runtime),occurred_at='restart:pause',lease_ttl_ns=100)
            with factory.open('doctor') as connection:
                before=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertIsNotNone(before['start_sample'])
            scope=repository.command_scope
            child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
                '-c',_TASK_CRASH_CHILD,str(ROOT),str(scope.repository_root),str(scope._manager._control),'terminal'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            self.assertEqual(child.returncode,0)
            with factory.open('doctor') as connection:
                after=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(after['start_sample'],before['start_sample'])
            self.assertEqual(after['clock_availability'],'observed')
            self.assertEqual(after['terminal'],'canceled')

    def test_review_no_double_count(self):
        from tests.integration.test_wp04_runner import ReviseThenPassReviewer
        with observed_runner() as (_application,_active,factory,_repository,run,observation):
            reviewer=ReviseThenPassReviewer()
            self.assertEqual(run(reviewer,'review:first').status,'completion_ready')
            before=observation();self.assertEqual(before['revision_count'],1)
            self.assertEqual(run(reviewer,'review:replay').status,'completion_ready')
            self.assertEqual(observation(),before)

    def test_forged_review_binding(self):
        from tests.integration.test_wp04_runner import ReviewResult,PassingReviewer
        from graph_engineering.application.runner import RunnerError
        class AuthorReviewer:
            def review(self,node,candidate,validation,*,runtime):return ReviewResult('REVISE',candidate.author_id)
        with observed_runner() as (_application,_active,_factory,_repository,run,observation):
            with self.assertRaises(RunnerError):run(AuthorReviewer(),'forged:review')
            self.assertEqual(observation()['revision_count'],0)
            self.assertEqual(run(PassingReviewer(),'independent:review').status,'completion_ready')
            self.assertEqual(observation()['revision_count'],0)

    def test_repeat_wait_entry(self):
        from tests.integration.test_wp04_runner import ReviewResult
        class Escalate:
            def review(self,node,candidate,validation,*,runtime):return ReviewResult('ESCALATE','independent-reviewer')
        with observed_runner() as (application,active,factory,_repository,run,observation):
            reviewer=Escalate()
            self.assertEqual(run(reviewer,'wait:first').lifecycle,'awaiting_human')
            self.assertEqual(observation()['human_interruption_count'],1)
            for turn in ('wait:repeat1','wait:repeat2'):
                self.assertEqual(run(reviewer,turn).lifecycle,'awaiting_human')
                self.assertEqual(observation()['human_interruption_count'],1)
            # Resuming the task does not resolve its waiting node. A rejected
            # advance must not invent another observed wait entry.
            with factory.open('doctor') as connection:
                revision=json.loads(connection.execute('SELECT snapshot_json FROM tasks').fetchone()[0])['domain']['task_revision']
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('resume',revision,{'resolution_evidence_refs':('evidence:resolved',),
                    'compatibility_evidence_ref':'evidence:compatible'}),runtime),occurred_at='wait:resume',lease_ttl_ns=100)
            RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute('task:learning-1',
                TaskCommand('run',revision+1,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                occurred_at='wait:run-again',lease_ttl_ns=100)
            from graph_engineering.application.runner import RunnerError
            with self.assertRaises(RunnerError):run(reviewer,'wait:unresolved-entry')
            self.assertEqual(observation()['human_interruption_count'],1)

    def _pause_resume(self,elapsed):
        metrics=['human_interruption_count']+(['elapsed_bucket'] if elapsed else [])
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','pause:grant',expected_generation=0,
                metric_ids=metrics,expires_at_ns='1000'))
            approve(application,active)
            def command(kind,revision,payload):
                return RuntimeMutationGateway.invoke(active,active.proof,lambda runtime:application.execute(
                    'task:learning-1',TaskCommand(kind,revision,payload),runtime),occurred_at='pause-turn:'+str(revision),lease_ttl_ns=100)
            command('run',5,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'})
            with factory.open('doctor') as connection:
                start=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])['start_sample']
            command('pause',6,{})
            command('resume',7,{'resolution_evidence_refs':('evidence:resolved',),'compatibility_evidence_ref':'evidence:compatible'})
            command('run',8,{'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'})
            command('pause',9,{})
            cancel(application,active,expected_revision=10)
            with factory.open('doctor') as connection:
                row=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(row['human_interruption_count'],0)
            self.assertEqual(row['availability'],'complete')
            if elapsed:
                self.assertIsNotNone(start)
                self.assertEqual(row['start_sample'],start)
                self.assertEqual(row['clock_availability'],'observed')
            else:self.assertIsNone(start)

    def test_pause_resume(self):self._pause_resume(True)

    def test_non_decision_waits(self):self._pause_resume(False)

    def test_revoke_commit_race(self):
        from graph_engineering.core.learning import LearningError
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','race:grant',expected_generation=0,
                metric_ids=['elapsed_bucket','completion'],expires_at_ns='1000'))
            learning_call(application,active,learning_request('revoke_learning','race:revoke',expected_generation=1))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                cancel(application,active)
                sample.assert_not_called()
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)
                head=connection.execute('SELECT head_digest FROM tasks').fetchone()[0]
            with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                learning_call(application,active,learning_request('collect_learning','race:after',expected_head=head,
                    expected_generation=2,expected_context_version=0))

        from tests.integration.test_wp09_learning import concurrent_learning_writer
        for revoke_first in (True,False):
            with self.subTest(revoke_first=revoke_first),learning_stack() as (application,active,factory,repository):
                learning_call(application,active,learning_request('grant_learning','ordered:grant',expected_generation=0,
                    metric_ids=['completion'],expires_at_ns='1000'))
                with factory.open('doctor') as connection:
                    before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
                with concurrent_learning_writer(factory,'1' if revoke_first else 'revoke') as contend:
                    def fault(point):
                        if point==('learning.before_commit' if revoke_first else 'commit.before_commit'):contend()
                    with mock.patch.object(repository,'_fault',side_effect=fault):
                        if revoke_first:
                            learning_call(application,active,learning_request('revoke_learning','ordered:revoke',expected_generation=1))
                        else:
                            cancel(application,active)
                with factory.open('doctor') as connection:
                    after=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
                    self.assertEqual(connection.execute('SELECT state FROM pmf_consents').fetchone()[0],'revoked')
                if revoke_first:self.assertEqual(after,before)
                else:self.assertEqual(json.loads(after)['terminal'],'canceled')

    def test_wheel_real_provider(self):
        from tests.unit.test_wp00_packaging import learning_wheel_probe
        learning_wheel_probe("""
from graph_engineering.application.learning import LearningPolicyLoader
from graph_engineering.storage.learning_clock import NativeLearningClock,clock_duration_ns
LearningPolicyLoader.from_installation().require_current()
clock=NativeLearningClock('synthetic-wheel-installation','synthetic-wheel-repository')
first=clock.sample();last=clock.sample()
assert clock_duration_ns(first,last)>=0
assert first['clock_domain_digest']==last['clock_domain_digest']
""")

    def test_source_gap(self):
        with learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','gap:grant',expected_generation=0,
                metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000'))
            original=repository.commit
            def legacy_commit(batch,**options):
                options.pop('learning_observation',None)
                return original(batch,**options)
            # A fully valid ordinary task write without the application ticket
            # must not be upgraded into a trusted observation.
            with mock.patch.object(repository,'commit',side_effect=legacy_commit):
                approve(application,active)
            with factory.open('doctor') as connection:
                row=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(row['availability'],'source-gap')
            self.assertIsNone(row['current_prd_sequence'])
            RuntimeMutationGateway.invoke(active,active.proof,
                lambda runtime: application.execute('task:learning-1',TaskCommand('run',5,
                    {'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                occurred_at='gap-run',lease_ttl_ns=100)
            with factory.open('doctor') as connection:
                after=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(after['availability'],'source-gap')
            self.assertGreater(after['last_observed_sequence'],row['last_observed_sequence'])

    def test_duplicate_transaction(self):
        with learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','duplicate:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            original=repository.commit
            batches=[]
            def capture(batch,**options):
                batches.append((batch,{k:v for k,v in options.items() if k!='learning_observation'}))
                return original(batch,**options)
            with mock.patch.object(repository,'commit',side_effect=capture):cancel(application,active)
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json,observation_digest FROM pmf_aggregates').fetchone()
                count=connection.execute('SELECT count(*) FROM events').fetchone()[0]
            with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                for batch,options in batches:original(batch,**options)
                sample.assert_not_called()
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json,observation_digest FROM pmf_aggregates').fetchone(),before)
                self.assertEqual(connection.execute('SELECT count(*) FROM events').fetchone()[0],count)

    def test_real_human_interruptions(self):
        from tests.integration.test_wp04_runner import (ApplicationRunnerIntegrationTests,
            PassingRuntime,PassingValidator,ReviewResult)
        class Reviewer:
            def review(self,node,candidate,validation,*,runtime):
                return ReviewResult('ESCALATE','independent-reviewer')
        with learning_stack() as (application,active,factory,repository):
            _schemas,context,graph,budgets=ApplicationRunnerIntegrationTests().stack(with_budget=True)
            learning_call(application,active,learning_request('grant_learning','human:grant',expected_generation=0,
                metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000'))
            approve(application,active,graph)
            RuntimeMutationGateway.invoke(active,active.proof,
                lambda runtime: application.execute('task:learning-1',TaskCommand('run',5,
                    {'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                occurred_at='run-human',lease_ttl_ns=100)
            runner=application.create_runner(repository._objects,budgets,context=context)
            for turn in ('first-human','repeat-human'):
                result=RuntimeMutationGateway.invoke(active,active.proof,
                    lambda runtime: runner.run_until_stable('task:learning-1',runtime,graph,
                        PassingRuntime(),PassingValidator(),Reviewer(),max_steps=40),occurred_at=turn,lease_ttl_ns=100)
                self.assertEqual(result.lifecycle,'awaiting_human')
                with factory.open('doctor') as connection:
                    observation=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(observation['availability'],'complete')
                self.assertEqual(observation['revision_count'],0)
                self.assertEqual(observation['human_interruption_count'],1)

    def test_missing_boundary(self):
        for damage in ("DELETE FROM project_scope_approvals",
                       "UPDATE project_scope_approvals SET record_digest='invalid'",
                       "UPDATE project_scopes SET approved_event_digest='invalid'",
                       "UPDATE events SET transaction_id='unproved' WHERE event_type='task.prd_approved'"):
            with self.subTest(damage=damage),learning_stack() as (application,active,factory,_repository):
                approve(application,active)
                with factory.open('migration') as connection:
                    with connection.transaction():connection.execute(damage)
                learning_call(application,active,learning_request('grant_learning','boundary:grant',expected_generation=0,
                    metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000'))
                with factory.open('doctor') as connection:
                    observation=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(observation['availability'],'missing-prd')
                self.assertIsNone(observation['current_prd_sequence'])

    def test_real_review_verdicts(self):
        from tests.integration.test_wp04_runner import (ApplicationRunnerIntegrationTests,
            PassingRuntime,PassingValidator,PassingReviewer,ReviseThenPassReviewer,ReviewResult)
        class VerdictReviewer:
            def __init__(self,verdict):self.verdict=verdict
            def review(self,node,candidate,validation,*,runtime):
                return ReviewResult(self.verdict,'independent-reviewer')
        for reviewer,expected,interruptions,status in (
                (PassingReviewer(),0,0,'completion_ready'),(ReviseThenPassReviewer(),1,0,'completion_ready'),
                (VerdictReviewer('ESCALATE'),0,1,'stable'),(VerdictReviewer('BLOCKED'),0,0,'stable')):
            with self.subTest(expected=expected),learning_stack() as (application,active,factory,repository):
                _schemas,context,graph,budgets=ApplicationRunnerIntegrationTests().stack(with_budget=True)
                learning_call(application,active,learning_request('grant_learning','review:grant',expected_generation=0,
                    metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000'))
                approve(application,active,graph)
                RuntimeMutationGateway.invoke(active,active.proof,
                    lambda runtime: application.execute('task:learning-1',TaskCommand('run',5,
                        {'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),
                    occurred_at='run-review',lease_ttl_ns=100)
                runner=application.create_runner(repository._objects,budgets,context=context)
                result=RuntimeMutationGateway.invoke(active,active.proof,
                    lambda runtime: runner.run_until_stable('task:learning-1',runtime,graph,
                        PassingRuntime(),PassingValidator(),reviewer,max_steps=40),occurred_at='runner-review',lease_ttl_ns=100)
                self.assertEqual(result.status,status)
                with factory.open('doctor') as connection:
                    observation=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(observation['availability'],'complete')
                self.assertEqual(observation['revision_count'],expected)
                self.assertEqual(observation['human_interruption_count'],interruptions)

    def test_context_preserves_observation(self):
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','context:grant',expected_generation=0,
                metric_ids=['revision_count','abandonment'],expires_at_ns='1000'))
            approve(application,active)
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            context=learning_request('record_learning_context','context:1',expected_generation=1,
                expected_context_version=0,abandonment_code='not-stated',prior_task_id=None)
            result=learning_call(application,active,context)
            self.assertEqual(result['context_version'],1)
            self.assertEqual(learning_call(application,active,context),result)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)
                self.assertEqual(connection.execute('SELECT grant_sequence FROM pmf_consents').fetchone()[0],1)
            from graph_engineering.core.learning import LearningError
            with self.assertRaises(LearningError):
                learning_call(application,active,{**context,'request_id':'stale:context'})

    def test_pre_post_approval_grants(self):
        for grant_first in (True,False):
            with self.subTest(grant_first=grant_first),learning_stack() as (application,active,factory,_repository):
                grant=learning_request('grant_learning','prd:grant',expected_generation=0,
                    metric_ids=['revision_count','human_interruption_count'],expires_at_ns='1000')
                if grant_first:learning_call(application,active,grant)
                approve(application,active)
                if not grant_first:learning_call(application,active,grant)
                with factory.open('doctor') as connection:
                    row=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                    self.assertEqual(row['availability'],'complete')
                    self.assertEqual(row['current_prd_sequence'],5)
                    self.assertEqual(row['revision_count'],0)
                    self.assertEqual(row['human_interruption_count'],0)

    def test_real_run_terminal(self):
        from graph_engineering.storage.learning_clock import clock_duration_ns
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','clock:grant',expected_generation=0,
                metric_ids=['elapsed_bucket','completion'],expires_at_ns='1000'))
            approve(application,active)
            RuntimeMutationGateway.invoke(active,active.proof,
                lambda runtime: application.execute('task:learning-1',TaskCommand('run',5,
                    {'compatibility_evidence_ref':'evidence:compatibility-test','lease_plan_ref':'lease-plan:none'}),runtime),
                occurred_at='deliberately-not-a-clock-start',lease_ttl_ns=100)
            RuntimeMutationGateway.invoke(active,active.proof,
                lambda runtime: application.execute('task:learning-1',TaskCommand('pause',6,{}),runtime),
                occurred_at='deliberately-not-a-clock-pause',lease_ttl_ns=100)
            def end(runtime):
                plan=application.prepare_retention_plan('task:learning-1','cancel',runtime)
                return application.cancel_with_retention('task:learning-1',7,plan['plan_id'],runtime)
            RuntimeMutationGateway.invoke(active,active.proof,end,occurred_at='deliberately-not-a-clock-end',lease_ttl_ns=100)
            with factory.open('doctor') as connection:
                row=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
            self.assertEqual(row['terminal'],'canceled')
            self.assertEqual(row['clock_availability'],'observed')
            def sample(value):
                return {key:int(value[key]) if key=='ticks_ns' else value[key]
                    for key in ('clock_kind','clock_domain_digest','ticks_ns')}
            self.assertGreaterEqual(clock_duration_ns(sample(row['start_sample']),sample(row['terminal_sample'])),0)
            self.assertLess(row['start_sample']['event_sequence'],row['terminal_sample']['event_sequence'])

    def test_no_consent_no_sampling(self):
        with learning_stack() as (application,active,factory,_repository):
            with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                cancel(application,active)
                sample.assert_not_called()
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone()[0],0)
        for damage in ("UPDATE schema_versions SET version='999' WHERE component='pmf'",
                       "DROP TABLE pmf_owner_context"):
            with self.subTest(damage=damage),learning_stack() as (application,active,factory,_repository):
                with factory.open('migration') as connection:
                    with connection.transaction():connection.execute(damage)
                with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                    cancel(application,active)
                    sample.assert_not_called()
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','partial:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000'))
            with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                cancel(application,active)
                sample.assert_not_called()
            with factory.open('doctor') as connection:
                observation=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(observation['terminal'],'unavailable')
                self.assertIsNone(observation['start_event_sequence'])

    def test_late_grant_unknown(self):
        with learning_stack() as (application,active,factory,_repository):
            cancel(application,active,occurred_at='2026-10-04T00:00:02Z')
            learning_call(application,active,learning_request('grant_learning','late:grant',expected_generation=0,
                metric_ids=['elapsed_bucket'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                observation=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertIsNone(observation['start_sample'])
                self.assertIsNone(observation['terminal_sample'])

    def test_rollback_and_crash(self):
        with learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','rollback:grant',expected_generation=0,
                metric_ids=['revision_count','completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            def fail(point):
                if point=='commit.before_commit':raise RuntimeError('injected rollback')
            with mock.patch.object(repository,'_fault',side_effect=fail):
                with self.assertRaises(RuntimeError):cancel(application,active)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)
                self.assertEqual(connection.execute('SELECT revision FROM tasks').fetchone()[0],1)
            cancel(application,active,occurred_at='2026-10-04T00:00:02Z')
            with factory.open('doctor') as connection:
                after=json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])
                self.assertEqual(after['terminal'],'canceled')
                self.assertGreater(after['last_observed_sequence'],json.loads(before)['last_observed_sequence'])
        with learning_stack() as (application,active,factory,repository):
            learning_call(application,active,learning_request('grant_learning','crash:grant',expected_generation=0,
                metric_ids=['completion'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            from tests.support.wp03_repository import ROOT
            from tests.support.source_checkout_attestation import CONTROL_OPTION
            scope=repository.command_scope
            child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
                '-c',_TASK_CRASH_CHILD,str(ROOT),str(scope.repository_root),str(scope._manager._control)],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=20)
            self.assertEqual(child.returncode,-signal.SIGKILL)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)
                self.assertEqual(connection.execute('SELECT revision FROM tasks').fetchone()[0],1)
            # The crashed task lease is durable; a later real clock tick expires it.
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=101):
                cancel(application,active,occurred_at='after-crash-turn')
            with factory.open('doctor') as connection:
                self.assertEqual(json.loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])['terminal'],'canceled')


if __name__=='__main__':
    unittest.main()
