"""Public request closure and installed learning policy contracts."""
from __future__ import annotations
import unittest
from unittest import mock
from graph_engineering.application.learning import LearningPolicyLoader
from graph_engineering.core.learning import LearningError, closed_request, request_digest, require_replay_match
from graph_engineering.application.owner_turns import OwnerTurnError, OwnerTurnRequest
from tests.unit.test_wp07_owner_turns import turn


class LearningContractTests(unittest.TestCase):
    def test_six_operations(self):
        cases={
            'grant_learning':{'expected_generation':0,'metric_ids':['revision_count'],'expires_at_ns':'123'},
            'revoke_learning':{'expected_generation':1},
            'record_learning_context':{'expected_generation':1,'expected_context_version':0,'abandonment_code':'not-stated','prior_task_id':None},
            'collect_learning':{'expected_generation':1,'expected_context_version':0,'expected_head':'sha256-jcs-v1:'+'1'*64},
            'report_learning':{'experiment_id':'synthetic-default','task_ids':['task:1']},
            'purge_learning':{'expected_generation':1,'trigger':'retention-expired'},
        }
        loader=LearningPolicyLoader.from_installation()
        for op,payload in cases.items():
            request={'schema_version':'1.0.0','operation':op,'request_id':'request:1','task_id':'task:1',**payload}
            self.assertEqual(loader.validate_request(request),closed_request(request))
            if 'expected_generation' in payload:
                missing = {key:value for key,value in request.items() if key != 'expected_generation'}
                with self.assertRaises(LearningError):loader.validate_request(missing)
                with self.assertRaises(LearningError):loader.validate_request({**request,'expected_generation':True})

    def test_explicit_consent_parser(self):
        request=turn('grant_learning',task_id='task:1',payload={'expected_generation':0,'metric_ids':['revision_count'],'expires_at_ns':'123'})
        self.assertEqual(OwnerTurnRequest.from_dict(request).operation,'grant_learning')
        for patch in ({'expected_generation':True}, {'expected_generation':-1}, {'expires_at_ns':True}):
            with self.subTest(fields=tuple(patch)),self.assertRaises(OwnerTurnError):
                OwnerTurnRequest.from_dict(turn('grant_learning',task_id='task:1',payload={**request['payload'],**patch}))
        context={'expected_generation':1,'expected_context_version':0,'abandonment_code':'not-stated','prior_task_id':None}
        for field in ('expected_generation','expected_context_version'):
            with self.subTest(field=field),self.assertRaises(OwnerTurnError):
                OwnerTurnRequest.from_dict(turn('record_learning_context',task_id='task:1',payload={**context,field:True}))
        with self.assertRaises(OwnerTurnError):OwnerTurnRequest.from_dict(turn('approve',task_id='task:1',payload={'metric_ids':['revision_count']}))
        maximum=LearningPolicyLoader.from_installation().limits['max_tasks']
        report=turn('report_learning',task_id='task:1',payload={
            'experiment_id':'synthetic-default','task_ids':[f'task:{i}' for i in range(maximum)]})
        self.assertEqual(OwnerTurnRequest.from_dict(report).operation,'report_learning')
        report['payload']['task_ids']=[object()]*(maximum+1)
        with mock.patch('graph_engineering.application.learning.closed_request',
                side_effect=AssertionError('per-item validation or copying reached')) as parse:
            with self.assertRaises(OwnerTurnError):OwnerTurnRequest.from_dict(report)
            parse.assert_not_called()

    def test_unknown_schema_policy(self):
        loader=LearningPolicyLoader.from_installation()
        for patch in [{'schema_version':'9.0.0'},{'raw_prompt':'CANARY'},{'rules':[{'rule_id':'bad'}]}]:
            with self.subTest(keys=tuple(patch)),self.assertRaises(LearningError):
                loader.validate_policy_document({**loader.policy_document(),**patch})
        experiment=loader.experiment_document()
        with self.assertRaises(LearningError):loader.validate_experiment_document({**experiment,'experiments':[{'experiment_id':'bad','rule_ids':['missing']} ]})

    def test_installed_resource_binding(self):
        loader=LearningPolicyLoader.from_installation()
        self.assertEqual(loader.limits['max_tasks'],32)
        self.assertTrue(loader.digest.startswith('sha256:'))
        self.assertEqual(loader.require_current(),loader.digest)
        body=loader.policy_document();body['limits']['max_tasks']=999
        self.assertEqual(loader.limits['max_tasks'],32)

    def test_legacy_owner_operations(self):
        self.assertEqual(OwnerTurnRequest.from_dict(turn('status',task_id='task:1',payload={})).operation,'status')
        with self.assertRaises(Exception):OwnerTurnRequest.from_dict(turn('grant_learning',task_id='task:1',payload={}))

    def test_replay_request_conflict(self):
        original={'schema_version':'1.0.0','operation':'revoke_learning','request_id':'r:1','task_id':'task:1','expected_generation':1}
        digest=request_digest(original)
        self.assertIsNone(require_replay_match(digest,digest))
        with self.assertRaises(LearningError):require_replay_match(digest,request_digest({**original,'task_id':'task:2'}))
