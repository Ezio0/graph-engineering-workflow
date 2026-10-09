"""Privacy and currentness refusal on genuine bootstrapped learning roots."""
from __future__ import annotations
import unittest
import json
from pathlib import Path
from unittest import mock
from tests.support.security_bootstrap import genuine_case,genuine_runtime,bootstrap_graph,invoke
from tests.support.learning_reports import (genuine_learning_stack,genuine_cohort,grant,collect,report,
    learning_call,learning_request,complete_task)


class LearningReportPrivacyTests(unittest.TestCase):
    def test_no_consent_no_source_read(self):
        if genuine_case(self):return
        from graph_engineering.storage import learning
        from graph_engineering.core.learning import LearningError
        with genuine_learning_stack() as (application,active,_factory,_repo,_base,_manager):
            with mock.patch.object(learning,'_capture_current_observation_locked',side_effect=AssertionError('source read')):
                with self.assertRaisesRegex(LearningError,'LEARNING_CONSENT'):report(application,active)

    def test_foreign_endpoint_no_read(self):
        if genuine_case(self):return
        from graph_engineering.storage import learning
        from graph_engineering.core.learning import LearningError
        with genuine_cohort(['canceled']) as (application,_active,_factory,_repo,tasks,base,_manager):
            with genuine_runtime(base,2) as foreign:
                with mock.patch.object(learning,'_capture_current_observation_locked',side_effect=AssertionError('foreign source read')):
                    with self.assertRaisesRegex(LearningError,'LEARNING_AUTH'):report(application,foreign,task_ids=tasks)

    def test_config_change_stale_replay(self):
        if genuine_case(self):return
        import graph_engineering
        from graph_engineering.core.learning import LearningError
        with genuine_cohort(['canceled']) as (application,active,factory,_repo,tasks,_base,_manager):
            report(application,active,task_ids=tasks)
            path=Path(graph_engineering.__file__).resolve().parents[2]/'config/learning/learning-policy-v3.json'
            body=path.read_bytes();path.write_bytes(body+b' ')
            try:
                with self.assertRaises((LearningError,graph_engineering.DistributionIdentityError)):
                    report(application,active,task_ids=tasks)
            finally:path.write_bytes(body)
            from graph_engineering.application.learning import LearningPolicyLoader
            from tests.support.learning_reports import attest_learning_variant
            old_policy=LearningPolicyLoader.from_installation()
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT * FROM pmf_consents ORDER BY task_id').fetchall()
            attest_learning_variant('two-known-rules')
            current=LearningPolicyLoader.from_installation()
            self.assertNotEqual(current.digest,old_policy.digest)
            with self.assertRaisesRegex(LearningError,'LEARNING_POLICY_STALE'):old_policy.require_current()
            # Genuine old consent and its retained report cannot publish under the new policy.
            with self.assertRaisesRegex(LearningError,'LEARNING_CONSENT'):
                report(application,active,task_ids=tasks)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT * FROM pmf_consents ORDER BY task_id').fetchall(),before)
        # Fresh consent and capture under the newly attested configuration, without copying old rows.
        with genuine_cohort(['completed','completed','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            result=report(application,active,task_ids=tasks)
            self.assertEqual(result['policy_digest'],current.digest)
            self.assertEqual([(r['numerator'],r['denominator'],r['verdict']) for r in result['rules']],
                [(2,3,'supports'),(2,3,'counter-evidence')])
            self.assertEqual(result['hypotheses'][0]['verdict'],'mixed')
            self.assertEqual(result['hypotheses'][0]['next_experiment_ref']['purpose_code'],'resolve-rule-disagreement')

    def test_revoke_report_process_race(self):
        if genuine_case(self):return
        from tests.support.learning_reports import concurrent_revoke,concurrent_report
        from graph_engineering.core.learning import LearningError
        with genuine_cohort(['canceled']) as (application,active,factory,repository,tasks,base,_manager):
            with concurrent_revoke(base,tasks[0]) as contend:
                def fault(point):
                    if point=='learning.before_commit':contend()
                with mock.patch.object(repository,'_fault',side_effect=fault):
                    earlier=report(application,active,task_ids=tasks)
                self.assertEqual((earlier['rules'][0]['numerator'],earlier['rules'][0]['denominator']),(0,1))
                self.assertEqual(earlier['observations'][0]['consent_generation'],1)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state FROM pmf_consents').fetchone(),('revoked',))
            with self.assertRaisesRegex(LearningError,'LEARNING_CONSENT'):report(application,active,task_ids=tasks)
        # A separate genuine root orders revocation before the reporting transaction.
        with genuine_cohort(['canceled']) as (application,active,factory,_repository,tasks,base,_manager):
            with concurrent_report(base,tasks,'race:revoke-first-report') as (contend_report,results):
                with concurrent_revoke(base,tasks[0],revoke_first=True) as commit_revoke:
                    commit_revoke(before_commit=contend_report)
            self.assertEqual(results,[dict(refused='LEARNING_CONSENT')])
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT receipts_json FROM pmf_consents').fetchone()[0]
            self.assertNotIn('race:revoke-first-report',before)
            with self.assertRaisesRegex(LearningError,'LEARNING_CONSENT'):
                report(application,active,'race:revoke-first-report',task_ids=tasks)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT receipts_json FROM pmf_consents').fetchone()[0],before)

    def test_report_preallocation_limit(self):
        if genuine_case(self,variant='two-known-rules'):return
        from graph_engineering.storage import learning
        from graph_engineering.core.learning import LearningError
        with genuine_learning_stack() as (application,active,_factory,_repo,_base,_manager):
            grant(application,active)
            with mock.patch.object(learning,'_capture_current_observation_locked',side_effect=AssertionError('oversized cohort read')):
                with self.assertRaisesRegex(LearningError,'LEARNING_BOUND'):
                    report(application,active,task_ids=['task:security-synthetic','task:a','task:b','task:c'])
        from tests.support.learning_reports import learning_variant_probe
        code='''
from unittest import mock
from graph_engineering.application.learning import LearningPolicyLoader
from graph_engineering.core.learning import LearningError,counter_evidence_union
from graph_engineering.storage import learning
from graph_engineering.storage.codec import canonical_json
from tests.support.learning_reports import genuine_cohort,report,document
import copy
policy=LearningPolicyLoader.from_installation()
variant=next(v for v in document('tests/fixtures/learning-report-config-variants-v1.json')['variants'] if v['variant_id']==sys.argv[3])
expected=variant['expected_report_reservation_bytes']
experiment=policy.experiment_document()['experiments'][0]
if sys.argv[3]=='report-one-under':
    with genuine_cohort(['canceled','canceled']) as (application,active,factory,_repo,tasks,_base,_manager):
        with factory.open('doctor') as connection:before=connection.execute('SELECT receipts_json FROM pmf_consents ORDER BY task_id').fetchall()
        with mock.patch.object(learning,'_capture_current_observation_locked',side_effect=AssertionError('source materialized')), \\
             mock.patch('graph_engineering.core.learning.evaluate_rule',side_effect=AssertionError('summary grew')):
            try:report(application,active,task_ids=tasks)
            except LearningError as error:assert str(error)=='LEARNING_BOUND'
            else:raise AssertionError('one-under output reservation accepted')
        with factory.open('doctor') as connection:assert before==connection.execute('SELECT receipts_json FROM pmf_consents ORDER BY task_id').fetchall()
    print(json.dumps(dict(refused_before_materialization=True)))
else:
    assert policy.admit_report(experiment,2)==expected==policy.limits['max_report_bytes']
    config=policy.experiment_document()
    assert len(config['suggested_experiments'])==policy.limits['max_suggested_experiments']==4
    assert len(experiment['hypotheses'])==policy.limits['max_hypotheses']==2
    assert len(experiment['hypotheses'][0]['required_rule_ids'])==policy.limits['max_rules']==2
    policy.validate_experiment_document(config)
    for field in ('catalog','hypotheses','references'):
        bad=copy.deepcopy(config)
        if field=='catalog':bad['suggested_experiments'].append(dict(experiment_id='extra:catalog',purpose_code='replicate'))
        elif field=='hypotheses':
            extra=copy.deepcopy(bad['experiments'][0]['hypotheses'][0]);extra['hypothesis_id']='extra:hypothesis'
            bad['experiments'][0]['hypotheses'].append(extra)
        else:bad['experiments'][0]['hypotheses'][0]['required_rule_ids'].append('synthetic-completion')
        with mock.patch('graph_engineering.application.learning.validate_instance',side_effect=AssertionError('oversize schema traversed')):
            try:policy.validate_experiment_document(bad)
            except LearningError as error:assert str(error)=='LEARNING_BOUND'
            else:raise AssertionError('one-over '+field+' accepted')
    refs=['task:'+str(i) for i in range(32)]
    assert counter_evidence_union([dict(counter_evidence_refs=refs)]*2,refs)==sorted(refs)
    try:counter_evidence_union([dict(counter_evidence_refs=refs+['task:extra'])],refs)
    except LearningError as error:assert str(error)=='LEARNING_BOUND'
    else:raise AssertionError('one-over reference array accepted')
    one=dict(experiment,hypotheses=experiment['hypotheses'][:1])
    assert policy.admit_report(one,2)<expected  # duplicated references reserve output in each hypothesis
    with genuine_cohort(['canceled','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
        result=report(application,active,task_ids=tasks)
        assert len(canonical_json(result).encode('utf-8'))<=expected
        assert len(result['hypotheses'])==2 and len(result['rules'])==2
        assert all(h['counter_evidence_refs']==sorted(tasks) for h in result['hypotheses'])
        with mock.patch.object(learning,'_capture_current_observation_locked',side_effect=AssertionError('multibyte endpoint read')):
            try:report(application,active,task_ids=['task:界'])
            except LearningError:pass
            else:raise AssertionError('non-ASCII identifier accepted')
    print(json.dumps(dict(exact_reservation=expected,utf8_bytes_bounded=True)))
'''
        self.assertTrue(learning_variant_probe('report-one-under',code,'report-one-under')['refused_before_materialization'])
        exact=learning_variant_probe('report-exact-capacity',code,'report-exact-capacity')
        self.assertTrue(exact['utf8_bytes_bounded'])

    def test_no_content_in_reports_or_receipts(self):
        if genuine_case(self):return
        sentinel='PRIVATE-PROMPT-SOURCE-SECRET-7391'
        graph=bootstrap_graph()
        with genuine_learning_stack(graph=graph) as (application,active,factory,repository,_base,_manager):
            grant(application,active)
            complete_task(application,active,repository,graph,candidate_body=json.dumps(
                dict(schema_version='1.0.0',enabled=True,secret=sentinel)).encode(),expect_completion=False)
            collect(application,active,factory)
            result=report(application,active)
            self.assertNotIn(sentinel,json.dumps(result))
            with factory.open('doctor') as connection:
                receipts=connection.execute('SELECT receipts_json FROM pmf_consents').fetchone()[0]
                self.assertNotIn(sentinel,receipts)
                bootstrap=connection.execute('SELECT receipt_json FROM security_bootstrap_task_receipts').fetchone()[0]
                self.assertNotIn(sentinel,bootstrap)
            with mock.patch.object(repository._objects,'get',side_effect=AssertionError('raw object body read')):
                self.assertEqual(report(application,active),result)
