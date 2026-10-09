"""Report decisions from real bootstrapped tasks and deterministic completion."""
from __future__ import annotations
import unittest
from tests.support.security_bootstrap import genuine_case,bootstrap_graph
from tests.support.learning_reports import (genuine_cohort,genuine_learning_stack,grant,collect,report,
    complete_task,cancel_task,learning_call,learning_request)


class LearningReportIntegrationTests(unittest.TestCase):
    def test_supported_cohort(self):
        if genuine_case(self):return
        with genuine_cohort(['completed','completed']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual(result['hypotheses'][0]['verdict'],'supports')
            self.assertEqual((result['rules'][0]['numerator'],result['rules'][0]['denominator']),(2,2))
            self.assertEqual(result['hypotheses'][0]['next_experiment_ref']['purpose_code'],'replicate')

    def test_counter_cohort(self):
        if genuine_case(self):return
        with genuine_cohort(['canceled','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual(result['hypotheses'][0]['verdict'],'counter-evidence')
            self.assertEqual(result['hypotheses'][0]['counter_evidence_refs'],sorted(tasks))

    def test_mixed_hypothesis(self):
        if genuine_case(self,variant='two-known-rules'):return
        with genuine_cohort(['completed','completed','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual([r['verdict'] for r in result['rules']],['supports','counter-evidence'])
            self.assertEqual([(r['numerator'],r['denominator']) for r in result['rules']],[(2,3),(2,3)])
            self.assertEqual([r['predicate'] for r in result['rules']], [
                dict(comparator='gte',numerator=1,denominator=2,min_samples=2),
                dict(comparator='gte',numerator=3,denominator=4,min_samples=2)])
            self.assertEqual(result['hypotheses'][0]['required_rule_ids'],[r['rule_id'] for r in result['rules']])
            self.assertEqual(result['hypotheses'][0]['verdict'],'mixed')
            self.assertEqual(result['hypotheses'][0]['counter_evidence_refs'],[tasks[2]])
            self.assertEqual(result['hypotheses'][0]['next_experiment_ref']['purpose_code'],'resolve-rule-disagreement')

    def test_insufficient_cohort(self):
        if genuine_case(self,variant='insufficient-precedence'):return
        with genuine_cohort(['completed']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual([r['verdict'] for r in result['rules']],['insufficient-data','supports'])
            self.assertEqual([(r['numerator'],r['denominator']) for r in result['rules']],[(1,1),(1,1)])
            self.assertEqual([r['predicate']['min_samples'] for r in result['rules']],[2,1])
            self.assertEqual(result['hypotheses'][0]['required_rule_ids'],[r['rule_id'] for r in result['rules']])
            self.assertEqual(result['hypotheses'][0]['verdict'],'insufficient-data')
            self.assertEqual(result['hypotheses'][0]['counter_evidence_refs'],[])
            self.assertEqual(result['hypotheses'][0]['next_experiment_ref']['purpose_code'],'collect-more-samples')

    def test_unknown_vs_excluded(self):
        if genuine_case(self):return
        with genuine_cohort(['unknown','excluded']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual((result['eligible_count'],result['unknown_count'],result['excluded_count']),(0,1,1))
            self.assertEqual((result['rules'][0]['unknown_count'],result['rules'][0]['excluded_count']),(1,1))

    def test_overlap_no_duplicates(self):
        if genuine_case(self,variant='shared-rule-overlap'):return
        with genuine_cohort(['canceled','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=list(reversed(tasks)))
            self.assertEqual(result['eligible_count'],2)
            self.assertEqual(len(result['rules']),2)
            self.assertEqual(len(result['hypotheses']),2)
            self.assertEqual([h['required_rule_ids'] for h in result['hypotheses']],
                [['synthetic-completion','synthetic-completion-strict'],['synthetic-completion']])
            for rule in result['rules']:
                self.assertEqual((rule['numerator'],rule['denominator']),(0,2))
                self.assertEqual(rule['counter_evidence_refs'],sorted(tasks))
            for hypothesis in result['hypotheses']:
                self.assertEqual(hypothesis['verdict'],'counter-evidence')
                self.assertEqual(hypothesis['counter_evidence_refs'],sorted(tasks))
            self.assertEqual(report(application,active,'learning:ordered-report',task_ids=tasks),result)
            self.assertEqual(report(application,active,task_ids=list(reversed(tasks))),result)

    def test_fr13_full_owner_journey(self):
        if genuine_case(self):return
        import time
        from unittest import mock
        from graph_engineering.application.learning import LearningPolicyLoader
        from graph_engineering.core.learning import LearningError
        from tests.support.learning_reports import learning_restart_probe
        with genuine_cohort(['canceled','canceled']) as (application,active,factory,_repo,tasks,base,_manager):
            def original_evidence():
                with factory.open('doctor') as connection:
                    names=['tasks','events','transactions','project_scopes','project_scope_approvals',
                        'security_bootstrap_task_receipts','security_bootstrap_installation_receipts']
                    names += [row[0] for row in connection.execute("SELECT name FROM sqlite_master "
                        "WHERE type='table' AND (name LIKE 'action_%' OR name LIKE '%journal%') ORDER BY name")]
                    return {name:connection.execute('SELECT * FROM '+name).fetchall() for name in names}
            before=original_evidence()
            initial=report(application,active,task_ids=tasks)
            for task in tasks:
                changed=learning_call(application,active,learning_request('record_learning_context','context:'+task,task,
                    expected_generation=1,expected_context_version=0,abandonment_code='abandoned',prior_task_id=None))
                self.assertEqual(changed['context_version'],1)
            with self.assertRaisesRegex(LearningError,'LEARNING_STALE'):report(application,active,task_ids=tasks)
            for task in tasks:
                with self.assertRaisesRegex(LearningError,'LEARNING_STALE'):
                    collect(application,active,factory,'collect:'+task,task_id=task)
                collect(application,active,factory,'recollect:'+task,task_id=task,context_version=1)
            unfavorable=report(application,active,'learning:unfavorable',task_ids=tasks)
            self.assertNotEqual(unfavorable['cohort_digest'],initial['cohort_digest'])
            self.assertEqual([(r['numerator'],r['denominator'],r['verdict']) for r in unfavorable['rules']],
                [(0,2,'counter-evidence')])
            self.assertEqual(unfavorable['hypotheses'][0]['counter_evidence_refs'],sorted(tasks))
            self.assertEqual(unfavorable['hypotheses'][0]['next_experiment_ref']['purpose_code'],'investigate-counter-evidence')
            self.assertEqual([o['context_version'] for o in unfavorable['observations']],[1,1])
            for task in tasks:
                learning_call(application,active,learning_request('revoke_learning','revoke:'+task,task,expected_generation=1))
            with self.assertRaisesRegex(LearningError,'LEARNING_CONSENT'):
                report(application,active,'learning:unfavorable',task_ids=tasks)
            # Only the explicitly permitted retention clock is advanced; authority remains real.
            age=LearningPolicyLoader.from_installation().limits['retention_seconds']
            self.assertEqual(age,7776000)
            future=time.time_ns()+(age+1)*10**9
            for task in tasks:
                with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=future):
                    purged=learning_call(application,active,learning_request('purge_learning','purge:'+task,task,
                        trigger='garbage-collect',expected_generation=2))
                self.assertEqual(purged['state'],'purged')
            self.assertEqual(original_evidence(),before)
            with factory.open('doctor') as connection:
                tombstones=connection.execute('SELECT * FROM pmf_tombstones ORDER BY task_id').fetchall()
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone(),(0,))
                self.assertEqual({r[0] for r in tombstones if r[2]=='purged'},set(tasks))
                self.assertTrue(all(r[5] for r in tombstones if r[2]=='purged'))
            restarted=learning_restart_probe(base,tasks)
            self.assertTrue(restarted['unchanged'])
            self.assertEqual(len(restarted['refusals']),4)
            self.assertEqual(restarted['tombstones'],[list(r) for r in tombstones])
            self.assertEqual(original_evidence(),before)

    def test_valid_installed_config_changes(self):
        if genuine_case(self,variant='two-known-rules'):return
        from graph_engineering.application.learning import LearningPolicyLoader
        from graph_engineering.core.learning import LearningError
        with genuine_cohort(['completed','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual(result['hypotheses'][0]['verdict'],'mixed')
            self.assertEqual(LearningPolicyLoader.from_installation().limits['max_tasks'],3)
            with self.assertRaisesRegex(LearningError,'LEARNING_BOUND'):
                report(application,active,'variant:too-many',task_ids=tasks+['task:missing-a','task:missing-b'])

    def test_report_retry_idempotent(self):
        if genuine_case(self):return
        from graph_engineering.core.learning import LearningError
        with genuine_cohort(['canceled','canceled']) as (application,active,factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT * FROM pmf_aggregates ORDER BY task_id').fetchall()
                receipts=connection.execute('SELECT receipts_json FROM pmf_consents ORDER BY task_id').fetchall()
            self.assertEqual(report(application,active,task_ids=tasks),result)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT * FROM pmf_aggregates ORDER BY task_id').fetchall(),before)
                self.assertEqual(connection.execute('SELECT receipts_json FROM pmf_consents ORDER BY task_id').fetchall(),receipts)
            with self.assertRaisesRegex(LearningError,'LEARNING_REQUEST_CONFLICT'):
                report(application,active,task_ids=[min(tasks)])
            learning_call(application,active,learning_request('record_learning_context','context:changed',tasks[0],
                expected_generation=1,expected_context_version=0,abandonment_code='abandoned',prior_task_id=None))
            with self.assertRaisesRegex(LearningError,'LEARNING_STALE'):report(application,active,task_ids=tasks)
