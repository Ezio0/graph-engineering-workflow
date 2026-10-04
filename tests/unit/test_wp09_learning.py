"""Closed learning inputs, exact rational rules and unknown-value semantics."""
from __future__ import annotations

import unittest
from graph_engineering.core.learning import (
    LearningError, closed_request, metric_count, evaluate_rule, elapsed_bucket,
    observation_identity, unique_observations, require_bound,
)


def grant():
    return {'schema_version':'1.0.0','operation':'grant_learning','request_id':'request:1','task_id':'task:1','expected_generation':0,'metric_ids':['revision_count'],'expires_at_ns':'123'}


class LearningTests(unittest.TestCase):
    def test_closed_fields(self):
        self.assertEqual(closed_request(grant())['metric_ids'],['revision_count'])
        for delta in [{'prompt':'CANARY'}, {'metric_ids':['raw_prompt']}, {'expires_at_ns':True}, {'task_id':'bad\nvalue'}]:
            with self.subTest(delta=tuple(delta)), self.assertRaises(LearningError): closed_request({**grant(),**delta})

    def test_rational_denominators(self):
        rule={'comparator':'gte','numerator':1,'denominator':3,'min_samples':3}
        self.assertEqual(evaluate_rule(1,3,rule),'supports')
        self.assertEqual(evaluate_rule(1,4,rule),'counter-evidence')
        for bad in [(0,0),(None,3),(1,2)]:self.assertEqual(evaluate_rule(*bad,rule),'insufficient-data')
        with self.assertRaises(LearningError):evaluate_rule(True,3,rule)

    def test_duplicate_identity(self):
        a={'task_id':'task:1','source_head':'h','consent_generation':1,'context_version':0,'context_digest':'c','relation_vector':[],'policy_digest':'p'}
        self.assertEqual(len(unique_observations([a,a])),1)
        with self.assertRaises(LearningError):unique_observations([a,{**a,'raw_body':'secret'}])

    def test_window_unknown_vs_zero(self):
        self.assertEqual(metric_count(0,complete=True),{'value':0,'availability':'observed'})
        self.assertEqual(metric_count(0,complete=False),{'value':None,'availability':'incomplete-window'})
        with self.assertRaises(LearningError):metric_count(-1,complete=True)

    def test_counter_evidence_rules(self):
        for comparator in ['gte','lte']:
            rule={'comparator':comparator,'numerator':1,'denominator':2,'min_samples':1}
            self.assertEqual(evaluate_rule(1,2,rule),'supports')
        with self.assertRaises(LearningError):evaluate_rule(1,2,{'comparator':'exec','numerator':1,'denominator':2,'min_samples':1})

    def test_caller_time_not_trusted(self):
        self.assertIsNone(elapsed_bucket(None,(10,20)))
        self.assertEqual(elapsed_bucket(10,(10,20)),1)
        self.assertEqual(elapsed_bucket(0,(10,20)),0)
        for value in [True,-1,float('nan'),'2026-10-04T00:00:00Z']:
            with self.assertRaises(LearningError):elapsed_bucket(value,(10,20))

    def test_context_relation_identity(self):
        a={'task_id':'task:1','source_head':'h','consent_generation':1,'context_version':0,'context_digest':'c','relation_vector':[],'policy_digest':'p'}
        old=observation_identity(a)
        for key,value in [('context_version',1),('context_digest','d'),('relation_vector',[['task:2','h',1,1,'d']]),('consent_generation',2)]:
            self.assertNotEqual(old,observation_identity({**a,key:value}))

    def test_boundary_limits(self):
        self.assertEqual(require_bound(8,8),8)
        for value in [9,-1,True,float('inf')]:
            with self.assertRaises(LearningError):require_bound(value,8)
        with self.assertRaises(LearningError):require_bound(1,True)
