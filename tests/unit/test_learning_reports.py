"""Hypothesis reduction over named rules, preserving rational rule semantics."""
from __future__ import annotations

import unittest

from graph_engineering.core.learning import LearningError, evaluate_rule


class LearningReportUnitTests(unittest.TestCase):
    def verdict(self, *values):
        from graph_engineering.core.learning import hypothesis_verdict
        return hypothesis_verdict([{'rule_id': f'r:{i}', 'verdict': value}
                                   for i, value in enumerate(values)])

    def test_all_support(self):
        self.assertEqual(self.verdict('supports', 'supports'), 'supports')

    def test_all_counter(self):
        self.assertEqual(self.verdict('counter-evidence', 'counter-evidence'), 'counter-evidence')

    def test_mixed(self):
        self.assertEqual(self.verdict('supports', 'counter-evidence'), 'mixed')

    def test_insufficient_precedence(self):
        self.assertEqual(self.verdict('supports', 'counter-evidence', 'insufficient-data'), 'insufficient-data')

    def test_empty_required_rules_rejected(self):
        with self.assertRaises(LearningError): self.verdict()

    def test_unknown_verdict_rejected(self):
        for value in ('unknown', 'mixed', None, True):
            with self.subTest(value=value), self.assertRaises(LearningError): self.verdict(value)

    def test_duplicate_rule_rejected(self):
        from graph_engineering.core.learning import hypothesis_verdict
        with self.assertRaises(LearningError):
            hypothesis_verdict([{'rule_id': 'r:1', 'verdict': 'supports'}] * 2)

    def test_input_order_invariance(self):
        from graph_engineering.core.learning import hypothesis_verdict
        rows = [{'rule_id': 'r:1', 'verdict': 'supports'},
                {'rule_id': 'r:2', 'verdict': 'counter-evidence'}]
        self.assertEqual(hypothesis_verdict(rows), hypothesis_verdict(rows[::-1]))

    def test_ratio_semantics_unchanged(self):
        rule = dict(comparator='gte', numerator=1, denominator=2, min_samples=2)
        self.assertEqual(evaluate_rule(1, 2, rule), 'supports')
        self.assertEqual(self.verdict(evaluate_rule(1, 2, rule)), 'supports')
        self.assertEqual(evaluate_rule(2, 3, {**rule, 'numerator': 3, 'denominator': 4}), 'counter-evidence')
        self.assertEqual(evaluate_rule(2**62, 2**63-1, rule), 'supports')
        self.assertEqual(evaluate_rule(1, 1, rule), 'insufficient-data')

    def test_counter_union_bounds(self):
        from graph_engineering.core.learning import counter_evidence_union
        rows = [{'counter_evidence_refs': ['t:2', 't:1']},
                {'counter_evidence_refs': ['t:2']}]
        self.assertEqual(counter_evidence_union(rows, ['t:1', 't:2']), ['t:1', 't:2'])
        with self.assertRaises(LearningError): counter_evidence_union(rows, ['t:1'])
        with self.assertRaises(LearningError): counter_evidence_union(rows * 33, ['t:1', 't:2'])
