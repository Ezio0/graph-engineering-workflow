"""Task-transaction learning sources; no caller-supplied measurements."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import unittest
from unittest import mock

from graph_engineering.application.runtime import RuntimeMutationGateway
from graph_engineering.core.graph.state import TaskCommand
from tests.integration.test_wp09_learning import learning_stack, learning_call, learning_request


_TASK_CRASH_CHILD=r'''
import json, os, pathlib, signal, sys
from unittest import mock
root=pathlib.Path(sys.argv[1])
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
            if point=='commit.before_commit':os.kill(os.getpid(),signal.SIGKILL)
        repository=TaskRepository(bound,locks,owned,command_scope=scope,fault_hook=fault)
        application=TaskApplication(repository,repository,ResourceLeaseRepository(bound,locks),schema_registry=SCHEMAS,context=WORK)
        active=session(FIXTURE['cells'][0])
        cancel(application,active,occurred_at='crash-turn')
raise AssertionError('crash hook did not run')
'''


def cancel(application,active,occurred_at='2026-10-04T00:00:01Z'):
    def operation(runtime):
        plan=application.prepare_retention_plan('task:learning-1','cancel',runtime)
        return application.cancel_with_retention('task:learning-1',1,plan['plan_id'],runtime)
    return RuntimeMutationGateway.invoke(active,active.proof,
        operation,
        occurred_at=occurred_at,lease_ttl_ns=100)


def approve(application,active,graph=None):
    from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
    def operation(runtime):
        application.execute_scope('task:learning-1',TaskCommand('bind_project_scope',1,
            {'project_scope_ref':Fixtures.scope('drafted')}),Fixtures.project_scope(),runtime)
    RuntimeMutationGateway.invoke(active,active.proof,operation,occurred_at='scope-turn',lease_ttl_ns=100)
    RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.execute('task:learning-1',TaskCommand('request_prd_approval',2,
            {'prd_candidate_ref':'artifact:prd-test'}),runtime),occurred_at='request-turn',lease_ttl_ns=100)
    approval=Fixtures.approval()
    approval['baseline_refs']=({**approval['baseline_refs'][0],'approved_by':active.proof.owner_id},)
    if graph is not None:
        approval['graph_ref']={'graph_id':graph.graph_id,'graph_version':graph.graph_version,
            'profile_id':'new-feature','profile_version':'1.0.0','risk_path':'full-planned','graph_digest':graph.digest}
    return RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.execute('task:learning-1',TaskCommand('approve_prd',3,approval),runtime),
        occurred_at='approval-turn',lease_ttl_ns=100)


class LearningMetricSourceTests(unittest.TestCase):
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
