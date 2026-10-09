"""Closed version contracts, cross-reference rejection and resource identity."""
from __future__ import annotations

import copy
import unittest
from unittest import mock

from graph_engineering.application.learning import LearningPolicyLoader, _strict_document
from graph_engineering.core.learning import LearningError
from tests.support.learning_reports import ROOT, contract_report, document


class LearningReportContractTests(unittest.TestCase):
    def test_policy_v12_closed(self):
        loader = LearningPolicyLoader.from_installation()
        value = loader.policy_document()
        self.assertEqual(value['schema_version'], '1.2.0')
        loader.validate_policy_document(value)
        for field, maximum in (('max_hypotheses',64),('max_suggested_experiments',256),('max_tasks',32)):
            for invalid in (0, True, maximum+1):
                bad = copy.deepcopy(value); bad['limits'][field] = invalid
                with self.subTest(field=field,invalid=invalid), self.assertRaises(LearningError): loader.validate_policy_document(bad)
        with self.assertRaises(LearningError): loader.validate_policy_document({**value,'raw_prompt':'CANARY'})
        bad = copy.deepcopy(value); bad['rules'] = bad['rules'] * 65
        with mock.patch('graph_engineering.application.learning.validate_instance', side_effect=AssertionError('oversize traversal')) as traversal:
            with self.assertRaises(LearningError): loader.validate_policy_document(bad)
            traversal.assert_not_called()

    def test_experiments_v11_closed(self):
        loader = LearningPolicyLoader.from_installation(); value = loader.experiment_document()
        self.assertEqual(value['schema_version'],'1.1.0'); loader.validate_experiment_document(value)
        for mutation in ('extra','duplicate-hypothesis','duplicate-rule','missing-outcome','oversize-catalog'):
            bad = copy.deepcopy(value); hypothesis = bad['experiments'][0]['hypotheses'][0]
            if mutation=='extra': hypothesis['command']='CANARY'
            elif mutation=='duplicate-hypothesis': bad['experiments'][0]['hypotheses'].append(copy.deepcopy(hypothesis))
            elif mutation=='duplicate-rule': hypothesis['required_rule_ids'] *= 2
            elif mutation=='missing-outcome': hypothesis['next_experiment_ids'].pop('mixed')
            else: bad['suggested_experiments'] *= 65
            with self.subTest(mutation=mutation), self.assertRaises(LearningError): loader.validate_experiment_document(bad)
        with self.assertRaises(LearningError): _strict_document(b'{"kind":"a","kind":"b"}')

    def test_required_rule_coverage(self):
        loader = LearningPolicyLoader.from_installation(); value = loader.experiment_document()
        for change in ('empty','missing','unknown-selected-rule','duplicate-experiment'):
            bad = copy.deepcopy(value)
            if change=='empty': bad['experiments'][0]['hypotheses'][0]['required_rule_ids']=[]
            elif change=='missing': bad['experiments'][0]['hypotheses'][0]['required_rule_ids']=['missing']
            elif change=='unknown-selected-rule': bad['experiments'][0]['rule_ids'].append('unconfigured')
            else: bad['experiments'].append(copy.deepcopy(bad['experiments'][0]))
            with self.subTest(change=change), self.assertRaises(LearningError): loader.validate_experiment_document(bad)
        from tests.support.learning_reports import installed_coverage_probe
        self.assertEqual(installed_coverage_probe(),{'complete_valid':True,'coverage_error':'LEARNING_EXPERIMENT'})
        mutant=installed_coverage_probe(remove_coverage_guard=True)
        self.assertEqual(mutant,{'complete_valid':True,'coverage_error':None})
        # The production rejection oracle would fail for this single-guard mutant.
        self.assertNotEqual(mutant['coverage_error'],'LEARNING_EXPERIMENT')

    def test_suggestion_partition_cycles(self):
        loader = LearningPolicyLoader.from_installation(); value = loader.experiment_document()
        for change in ('self','cross','outgoing','dangling','duplicate'):
            bad = copy.deepcopy(value)
            if change in ('self','cross'):
                if change=='cross':
                    second=copy.deepcopy(bad['experiments'][0]); second['experiment_id']='report:other';second['hypotheses'][0]['hypothesis_id']='h:other';bad['experiments'].append(second)
                bad['experiments'][0]['hypotheses'][0]['next_experiment_ids']['mixed']='synthetic-default' if change=='self' else 'report:other'
            elif change=='outgoing': bad['suggested_experiments'][0]['next_experiment_ids']={'supports':'synthetic-default'}
            elif change=='dangling': bad['experiments'][0]['hypotheses'][0]['next_experiment_ids']['supports']='absent'
            else: bad['suggested_experiments'].append(copy.deepcopy(bad['suggested_experiments'][0]))
            with self.subTest(change=change), self.assertRaises(LearningError): loader.validate_experiment_document(bad)
        unused=copy.deepcopy(value);unused['suggested_experiments'].append(dict(experiment_id='unused:plan',purpose_code='replicate'))
        loader.validate_experiment_document(unused)

    def test_legacy_versions_preserved(self):
        loader = LearningPolicyLoader.from_installation()
        for version in (1,2): loader.validate_policy_document(document(f'config/learning/learning-policy-v{version}.json'))
        loader.validate_experiment_document(document('config/learning/learning-experiments-v1.json'))
        for version in ('1.0.0','1.1.0'):
            old=contract_report();old.pop('hypotheses');old['schema_version']=version
            loader.validate_report(old)
            with self.assertRaises(LearningError): loader.validate_report({**old,'hypotheses':[]})

    def test_report_v12_closed(self):
        loader=LearningPolicyLoader.from_installation(); value=contract_report();loader.validate_report(value)
        for mutation in ('absent','unknown','payload','extra','rule-mixed'):
            bad=copy.deepcopy(value)
            if mutation=='absent':bad.pop('hypotheses')
            elif mutation=='unknown':bad['hypotheses'][0]['verdict']='unknown'
            elif mutation=='payload':bad['hypotheses'][0]['next_experiment_ref']['command']='CANARY'
            elif mutation=='extra':bad['hypotheses'][0]['raw_prompt']='CANARY'
            else:bad['rules'][0]['verdict']='mixed'
            with self.subTest(mutation=mutation),self.assertRaises(LearningError):loader.validate_report(bad)
        from graph_engineering.core.contracts.schema import validate_instance
        self.assertTrue(validate_instance(document('config/contracts/schemas/learning-report-1.1.0.json'),value,source_id='legacy-consumer'))

    def test_owner_input_unchanged(self):
        from tests.contract.test_wp09_learning_contracts import LearningContractTests
        LearningContractTests('test_six_operations').test_six_operations()
        loader=LearningPolicyLoader.from_installation()
        self.assertEqual(loader._schemas['input']['$id'],'urn:gew:schema:learning-input:1.0.0')
        request=dict(schema_version='1.0.0',operation='report_learning',task_id='t:1',request_id='r:1',experiment_id='synthetic-default',task_ids=['t:1'])
        with self.assertRaises(LearningError): loader.validate_request({**request,'hypothesis_id':'injected'})

    def test_installed_resource_closure(self):
        import tomllib
        from graph_engineering import _learning_installation_resources, _SOURCE_FILES
        from tests.support.source_checkout_attestation import SOURCE_FILES
        owned=tomllib.loads((ROOT/'pyproject.toml').read_text())['tool']['gew']['build']['owned-root-files']
        bodies=_learning_installation_resources();self.assertEqual(len(bodies),15)
        for path in ('config/learning/learning-policy-v3.json','config/learning/learning-experiments-v2.json',
                     'config/contracts/schemas/learning-policy-1.2.0.json','config/contracts/schemas/learning-experiments-1.1.0.json',
                     'config/contracts/schemas/learning-report-1.2.0.json'):
            self.assertIn(path,_SOURCE_FILES);self.assertIn(path,SOURCE_FILES)
            self.assertEqual(owned[path],'graph_engineering/'+path);self.assertIn((ROOT/path).read_bytes(),bodies)
        loader=LearningPolicyLoader.from_installation();experiment=loader.experiment_document()['experiments'][0]
        capacity=loader.admit_report(experiment,2)
        self.assertGreater(capacity,0);self.assertLess(capacity,loader.limits['max_report_bytes'])
