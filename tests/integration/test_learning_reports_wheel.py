"""Actual installed report decisions, valid configuration and refusal boundaries."""
import unittest
from tests.support.security_bootstrap import genuine_case


class LearningReportWheelTests(unittest.TestCase):
    def test_installed_hypothesis_report(self):
        if genuine_case(self,installed=True):return
        from tests.support.learning_reports import genuine_cohort,report
        with genuine_cohort(['completed','completed']) as (application,active,_factory,_repo,tasks,_base,_manager):
            self.assertEqual(report(application,active,task_ids=tasks)['hypotheses'][0]['verdict'],'supports')

    def test_installed_valid_config_variation(self):
        if genuine_case(self,installed=True,variant='two-known-rules'):return
        from tests.support.learning_reports import genuine_cohort,report
        with genuine_cohort(['completed','canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            self.assertEqual(report(application,active,task_ids=tasks)['hypotheses'][0]['verdict'],'mixed')

    def test_legacy_resources_preserved(self):
        if genuine_case(self,installed=True):return
        import graph_engineering
        from tests.support.learning_reports import ROOT
        locations=tuple('config/contracts/schemas/'+name for name in (
            'learning-record-1.0.0.json','learning-record-1.1.0.json','learning-report-1.0.0.json',
            'learning-report-1.1.0.json','learning-policy-1.0.0.json','learning-policy-1.1.0.json','learning-input-1.0.0.json'))
        bodies=graph_engineering._installation_owned_resources(locations)
        self.assertEqual(bodies,tuple((ROOT/path).read_bytes() for path in locations))

    def test_missing_or_replaced_resource_refused(self):
        from tests.integration.test_security_bootstrap_wheel import SecurityBootstrapWheelTests
        helper=SecurityBootstrapWheelTests()
        probe='''
try:
    from graph_engineering.application.learning import LearningPolicyLoader
    LearningPolicyLoader.from_installation()
except (RuntimeError,ValueError,OSError):print('PASS')
else:raise AssertionError('changed learning resource accepted')
'''
        for missing in (False,True):
            def mutate(installed):
                path=installed/'graph_engineering/config/learning/learning-policy-v3.json'
                if missing:path.unlink()
                else:path.write_bytes(path.read_bytes()+b' ')
            helper._probe(probe,mutate)
