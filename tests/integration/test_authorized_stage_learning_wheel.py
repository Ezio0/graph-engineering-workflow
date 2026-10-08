"""Offline isolated distribution journeys with real SQLite and runtime ports."""
from __future__ import annotations
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import venv
import zipfile

from tests.integration.test_action_authority_wheel import _PROBE,ActionAuthorityWheelTests
from tests.integration.test_wp07_runtime_parity import FIXTURE,adapter_document,compatibility,raw_input
from tests.unit.test_action_authority import challenge

_JOURNEY = _PROBE.split("if data['mode']=='parity':",1)[0]+r'''
fixture=root/'fixture'
sys.path.insert(0,str(fixture))
from unittest import mock
from tests.integration import test_wp07_runtime_parity as runtime_fixtures
from tests.support import action_authority as fixtures
# The test-only detached executable issuer is never used in this journey.
runtime_fixtures.executable=lambda:verified
fixtures.executable=lambda:verified
from tests.integration.test_authorized_stage_learning import grant,collect,derived,report,refreshed
from tests.unit.test_action_authority import decision as human_decision
from graph_engineering.application.learning import LearningPolicyLoader
with fixtures.registration_stack(lambda req,owner,lineage:human_decision(req)) as (service,active,request,base):
    service._manager.initialize_action_authority_order_storage()
    grant(service,active)
    collect(service,active)
    assert derived(service)['metrics']['authorized_stage']=={'availability':'observed','value':0}
    request=refreshed(service,request)
    receipt=service.authorize(active,request)
    assert receipt['status']=='approved' and receipt['receipt']['schema_version']=='1.0.0'
    assert service.authorize(active,request)==receipt
    collect(service,active,'wheel:collect')
    value=report(service,active,'wheel:report')
    assert value['observations'][0]['metrics']['authorized_stage']=={'availability':'observed','value':1}
    assert value['cohort_vector'][0]['authorization_source']==value['observations'][0]['authorization_source']
    LearningPolicyLoader.from_installation().validate_report(value)
    for module_name,module in tuple(sys.modules.items()):
        if module_name=='graph_engineering' or module_name.startswith('graph_engineering.'):
            origin=getattr(module,'__file__',None)
            if origin:assert pathlib.Path(origin).is_relative_to(pathlib.Path(sys.prefix)),(module_name,origin)
print('PASS')
'''


class AuthorizedStageWheelTests(unittest.TestCase):
    def test_installed_genuine_chain(self):
        from scripts import build_backend
        source=pathlib.Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix='gew-authorization-learning-wheel-') as directory:
            root=pathlib.Path(directory).resolve();wheel=root/build_backend.build_wheel(directory)
            environment=root/'environment';venv.EnvBuilder(with_pip=False,symlinks=True).create(environment);environment.chmod(0o700)
            installed=next(environment.glob('lib/python*/site-packages'))
            with zipfile.ZipFile(wheel) as archive:archive.extractall(installed)
            # Only test inputs/helpers are copied. No production source roots or
            # source attestation are present in this isolated process.
            shutil.copytree(source/'tests',root/'fixture/tests',ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copytree(source/'config',root/'fixture/config')
            shutil.copytree(source/'config/contracts',root/'contracts')
            probe=environment/'bin/authorized-stage-probe';probe.write_text(_JOURNEY);probe.chmod(0o700)
            data=dict(mode='learning',challenge=challenge().to_dict(),cells=[dict(configuration=adapter_document(cell),input=raw_input(cell),compatibility=compatibility(cell).to_dict()) for cell in FIXTURE['cells']])
            (root/'input.json').write_text(json.dumps(data))
            result=subprocess.run([str(environment/'bin/python'),'-I','-B',str(probe),str(root)],cwd=root,capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr[-3000:]);self.assertEqual(result.stdout.strip(),'PASS')

    def test_installed_old_owner_contract(self):
        ActionAuthorityWheelTests('test_local_config_cannot_approve').test_local_config_cannot_approve()
        ActionAuthorityWheelTests('test_wheel_runtime_port_parity').test_wheel_runtime_port_parity()
