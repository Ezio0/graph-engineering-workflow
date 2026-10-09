"""Bootstrap resource tests in an isolated actual installation."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest
import venv
import zipfile


_RESOURCE_PROBE = '''
import json
import graph_engineering
from graph_engineering.core.contracts.resources import ResourceProfile, CostSchedule, WorkContext
loader = getattr(graph_engineering, '_security_bootstrap_installation_resources', None)
assert callable(loader), 'production security installation loader is absent'
raw = graph_engineering._installation_owned_resources(('config/contracts/resource-profile-v1.json', 'config/contracts/cost-schedule-v1.json'))
context = WorkContext(ResourceProfile.from_dict(json.loads(raw[0])), CostSchedule.from_dict(json.loads(raw[1])))
bodies = loader(context)
assert len(bodies) == 31
descriptor = json.loads(bodies[0])
import hashlib
for row, body in zip(descriptor['resources'], bodies[1:], strict=True):
    assert hashlib.sha256(body).hexdigest() == row['raw_sha256']
assert len(set(row['path'] for row in descriptor['resources'])) == 30
print('PASS')
'''


class SecurityBootstrapWheelTests(unittest.TestCase):
    def test_installed_bootstrap_learning(self):
        from tests.support.security_bootstrap import genuine_case
        if genuine_case(self,installed=True):return
        from tests.integration.test_security_bootstrap import SecurityBootstrapIntegrationTests
        SecurityBootstrapIntegrationTests.test_genuine_learning_lifecycle(self)

    def test_installed_substitution_refused(self):
        probe='''
try:
    import graph_engineering
    from graph_engineering.storage.security import _bootstrap_bundle
    _bootstrap_bundle()
except (RuntimeError,ValueError,OSError):print('PASS')
else:raise AssertionError('substituted installed trust accepted')
'''
        for mutation in ('missing','replaced','record','duplicate-record'):
            def mutate(installed):
                if mutation=='record':
                    next(installed.glob('*.dist-info/RECORD')).write_bytes(b'')
                elif mutation=='duplicate-record':
                    record=next(installed.glob('*.dist-info/RECORD'));body=record.read_text()
                    row=next(row for row in body.splitlines() if row.startswith('graph_engineering/config/security/disclosure-policy-v1.json,'))
                    record.write_text(body+row+'\n')
                else:
                    target=installed/'graph_engineering/config/security/disclosure-policy-v1.json'
                    if mutation=='missing':target.unlink()
                    else:target.write_bytes(target.read_bytes()+b' ')
            self._probe(probe,mutate)

    def test_installed_legacy_config_variants(self):
        from tests.support.security_bootstrap import genuine_case,bootstrap_graph
        if genuine_case(self,installed=True,variant='two-known-rules'):return
        from graph_engineering.application.learning import LearningPolicyLoader
        from tests.support.learning_reports import genuine_learning_stack,grant,collect,report,cancel_task
        loader=LearningPolicyLoader.from_installation()
        self.assertEqual(len(loader.policy_document()['rules']),2)
        with genuine_learning_stack(graph=bootstrap_graph()) as (application,active,factory,_repository,_base,_manager):
            grant(application,active);cancel_task(application,active);collect(application,active,factory)
            result=report(application,active)
            self.assertEqual(len(result['rules']),2)
            self.assertEqual(result['hypotheses'][0]['required_rule_ids'],['synthetic-completion','synthetic-completion-strict'])
            self.assertEqual(result['hypotheses'][0]['verdict'],'insufficient-data')

    def _probe(self, source=_RESOURCE_PROBE, mutate=None):
        from scripts import build_backend
        with tempfile.TemporaryDirectory(prefix='gew-security-wheel-') as directory:
            root = pathlib.Path(directory).resolve()
            wheel = root / build_backend.build_wheel(directory)
            environment = root / 'environment'
            venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
            environment.chmod(0o700)
            installed = next(environment.glob('lib/python*/site-packages'))
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(installed)
            if mutate is not None:
                mutate(installed)
            probe = environment / 'bin/security-bootstrap-probe'
            probe.write_text(source, encoding='utf-8'); probe.chmod(0o700)
            result = subprocess.run([str(environment / 'bin/python'), '-I', '-B', str(probe)],
                                    cwd=root, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            self.assertEqual(result.stdout.strip(), 'PASS')

    def test_installed_resource_closure(self):
        self._probe()
