"""Real clock capabilities and pure invalid-source rejection; no runtime fixtures."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from graph_engineering.storage.learning_clock import (
    ClockUnavailable, NativeLearningClock, clock_duration_ns, domain_digest,
    ticks_to_ns,
)


class ClockProviderTests(unittest.TestCase):
    def test_native_monotonic(self):
        provider = NativeLearningClock('installation-test', 'repository-test')
        first, second = provider.sample(), provider.sample()
        self.assertGreaterEqual(second['ticks_ns'], first['ticks_ns'])
        self.assertEqual(first['clock_domain_digest'], second['clock_domain_digest'])
        self.assertNotIn('boot_id', first)
        self.assertIn(first['clock_kind'], ('darwin-continuous-v1', 'linux-boottime-v1'))

    def test_cross_process_domain(self):
        provider = NativeLearningClock('installation-test', 'repository-test')
        first = provider.sample()
        code = "from graph_engineering.storage.learning_clock import NativeLearningClock; import json; print(json.dumps(NativeLearningClock('installation-test','repository-test').sample()))"
        command = [sys.executable, '-B']
        for key, value in sys._xoptions.items():
            command += ['-X', key if value is True else f'{key}={value}']
        code = 'import sys; sys.path[:0]=' + repr(sys.path) + ';' + code
        result = subprocess.run(command + ['-c', code], capture_output=True, text=True, timeout=10, env=dict(os.environ))
        self.assertEqual(result.returncode, 0)
        second = json.loads(result.stdout)
        self.assertEqual(first['clock_domain_digest'], second['clock_domain_digest'])
        self.assertGreaterEqual(clock_duration_ns(first, second), 0)

    def test_changed_domain(self):
        a = {'clock_kind':'linux-boottime-v1','clock_domain_digest':domain_digest('i','r','boot-a','ns-a'),'ticks_ns':1}
        for field, value in [('clock_kind','darwin-continuous-v1'),('clock_domain_digest',domain_digest('i','r','boot-b','ns-a'))]:
            with self.subTest(field=field):
                self.assertIsNone(clock_duration_ns(a, {**a,field:value,'ticks_ns':2}))
        self.assertNotEqual(domain_digest('i','r','b','ns-a'),domain_digest('i','r','b','ns-b'))

    def test_forged_provider(self):
        valid = {'clock_kind':'linux-boottime-v1','clock_domain_digest':'sha256:'+('a'*64),'ticks_ns':1}
        self.assertIsNone(clock_duration_ns({**valid,'trusted':True},valid))
        self.assertIsNone(clock_duration_ns({**valid,'clock_kind':'caller-time'},valid))
        self.assertIsNone(clock_duration_ns({**valid,'ticks_ns':True},valid))
        with patch('graph_engineering.storage.learning_clock.platform.system', return_value='unsupported'):
            with self.assertRaises(ClockUnavailable): NativeLearningClock('i','r').sample()

    def test_integer_and_backward(self):
        self.assertEqual(ticks_to_ns(9, 3, 2),13)
        for args in [(True,1,1),(1,1,0),(-1,1,1),(2**64,1,1)]:
            with self.subTest(args=args), self.assertRaises(ClockUnavailable): ticks_to_ns(*args)
        a={'clock_kind':'linux-boottime-v1','clock_domain_digest':'sha256:'+('a'*64),'ticks_ns':10}
        self.assertIsNone(clock_duration_ns(a,{**a,'ticks_ns':9}))
        self.assertIsNone(clock_duration_ns(None,a))
        self.assertEqual(clock_duration_ns(a,a),0)

    def test_wall_clock_independence(self):
        clock = NativeLearningClock('i','r')
        with patch('time.time', side_effect=AssertionError('wall clock used')), patch('time.time_ns', side_effect=AssertionError('wall clock used')):
            first, second = clock.sample(), clock.sample()
        self.assertGreaterEqual(clock_duration_ns(first,second),0)
