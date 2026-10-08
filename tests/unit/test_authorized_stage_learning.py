"""Pure behavior of bounded category learning sources, never execution authority."""
from __future__ import annotations

import unittest

from graph_engineering.core.learning import LearningError
from graph_engineering.storage.codec import semantic_record_digest


class AuthorizedStageUnitTests(unittest.TestCase):
    def test_closed_watermark(self):
        from graph_engineering.core.learning import authorization_watermark
        good = dict(order_epoch='sha256-jcs-v1:'+'1'*64, ordinal=0, order_digest='sha256-jcs-v1:'+'2'*64,
                    anchor_digest='sha256-jcs-v1:'+'2'*64, installation_id='i:1', repository_id='r:1', activation_epoch=1)
        self.assertEqual(authorization_watermark(good), good)
        for change in ({'ordinal': True}, {'ordinal': -1}, {'activation_epoch':False},
                       {'extra':1}, {'order_digest':'broken'}):
            with self.subTest(change=change), self.assertRaises(LearningError):
                authorization_watermark({**good, **change})

    def test_category_dedup(self):
        from graph_engineering.core.learning import authorized_category_count
        self.assertEqual(authorized_category_count(['commit','commit','push'], {'commit':'commit','push':'push'}),2)

    def test_alias_mapping(self):
        from graph_engineering.core.learning import authorized_category_count
        self.assertEqual(authorized_category_count(['commit','push'], {'commit':'git','push':'git'}),1)

    def test_mapping_digest(self):
        from graph_engineering.core.learning import authorization_mapping
        a=authorization_mapping({'commit':'commit'}); b=authorization_mapping({'commit':'git'})
        self.assertNotEqual(semantic_record_digest(a),semantic_record_digest(b))

    def test_unmapped_category_unavailable(self):
        from graph_engineering.core.learning import authorized_category_count
        self.assertIsNone(authorized_category_count(['unmapped'],{'commit':'commit'}))

    def test_pending_rejected_excluded(self):
        from graph_engineering.core.learning import authorization_event_eligible
        self.assertFalse(authorization_event_eligible({'event_kind':'pending'}, {}, {}))
        self.assertFalse(authorization_event_eligible({'event_kind':'rejected'}, {}, {}))

    def test_revoked_history_retained(self):
        from graph_engineering.core.learning import authorized_category_count
        self.assertEqual(authorized_category_count(['commit'],{'commit':'commit'}),1)
        # The projection consumes approval facts, not executable status heads.
        self.assertEqual(authorized_category_count([],{'commit':'commit'}),0)

    def test_revision_baseline_filter(self):
        from graph_engineering.core.learning import authorization_event_eligible
        identity=dict(task_id='t:1',owner_id='o:1',runtime_kind='codex',runtime_lineage_id='l:1',
                      installation_id='i:1',repository_id='r:1',activation_epoch=1)
        boundary=dict(baseline_digest='baseline',prd_revision=4)
        challenge={**identity,'baseline_digest':'baseline','task_revision':4}
        self.assertTrue(authorization_event_eligible({'event_kind':'approved','challenge':challenge},identity,boundary))
        for update in ({'task_revision':3},{'baseline_digest':'other'},{'owner_id':'other'},{'activation_epoch':0}):
            self.assertFalse(authorization_event_eligible({'event_kind':'approved','challenge':{**challenge,**update}},identity,boundary))

    def test_unknown_vs_zero(self):
        from graph_engineering.core.learning import authorized_category_count
        self.assertEqual(authorized_category_count([],{'commit':'commit'}),0)
        self.assertIsNone(authorized_category_count(['other'],{'commit':'commit'}))

    def test_ordinal_bounds(self):
        from graph_engineering.core.learning import authorization_watermark
        good=dict(order_epoch='sha256-jcs-v1:'+'1'*64,ordinal=2**53-1,order_digest='sha256-jcs-v1:'+'2'*64,
                  anchor_digest='sha256-jcs-v1:'+'3'*64,installation_id='i:1',repository_id='r:1',activation_epoch=1)
        self.assertEqual(authorization_watermark(good)['ordinal'],2**53-1)
        with self.assertRaises(LearningError):authorization_watermark({**good,'ordinal':2**53})

    def test_source_projection(self):
        from graph_engineering.core.learning import authorization_mapping
        self.assertEqual(authorization_mapping({'push':'push','commit':'commit'}),{'commit':'commit','push':'push'})
        with self.assertRaises(LearningError):authorization_mapping({'commit':'owner text contains spaces'})

    def test_count_bounds(self):
        from graph_engineering.core.learning import authorization_mapping
        with self.assertRaises(LearningError):authorization_mapping({f'kind{i}':'category' for i in range(65)})
