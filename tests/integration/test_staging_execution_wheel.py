"""Real installed producer/reopen and cold CLI refusals, without synthetic providers."""
import json
import unittest
from tests.support.staging_execution import ExecutionFixture,success,inventory,provider_fault,running_provider_fault,reopen_rejection
from tests.support.release_staging import expected_envelope,write_json

class StagingExecutionWheelTests(unittest.TestCase):
    def test_installed_local_stage_and_reopen(self):
        with ExecutionFixture(installed=True) as f:
            self.assertEqual(success(self,f)['code'],'staged')
            origin=(next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes()
            exercise="from graph_engineering.application.staging_execution import StagedReleaseObservation;result=owner.reopen_staged(plan,grant);assert type(result) is StagedReleaseObservation,result;value=result.diagnostic();result.close()"
            self.assertEqual(success(self,f,exercise=exercise)['code'],'staged')
            self.assertEqual((next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes(),origin)
            self.assertEqual(success(self,f,exercise=provider_fault('retained-reopen',fresh=False))['zero_calls'],0)
            self.assertEqual(success(self,f,exercise=exercise)['code'],'staged')
            self.assertEqual((next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes(),origin)
            for filename in ('execution-binding.json','receipt.json'):reopen_rejection(self,f,filename,'cross-link')
            self.assertEqual(success(self,f,exercise=provider_fault('descriptor',fresh=False))['zero_calls'],0)
            self.assertEqual(success(self,f,exercise=exercise)['code'],'staged')
            self.assertEqual((next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes(),origin)
            self.assertFalse(list(f.release.base.rglob('__pycache__')))

    def test_installed_failures_and_cold_cli(self):
        with ExecutionFixture(installed=True,mode='fail') as f:
            self.assertEqual(success(self,f,exercise="result=owner.stage(plan,grant);assert type(result) is dict,result;value=result")['code'],'closure_mismatch')
            self.assertFalse(list(f.candidates.rglob('receipt.json')))
            path=f.release.base/'plan.json';write_json(path,expected_envelope(f))
            args=['install-apply','--plan',str(path),'--bundle',str(f.release.bundle),'--manifest',str(f.release.manifest_path),'--format','json']
            before=inventory(f.candidates);p=f.release.cli(args);self.assertEqual(p.returncode,4,p.stderr);self.assertEqual(json.loads(p.stdout)['code'],'authority_required');self.assertEqual(inventory(f.candidates),before)
            self.assertNotIn(str(f.release.base),p.stdout+p.stderr)
        with ExecutionFixture(installed=True) as f:
            for index,attack in enumerate(('alias','code')):
                self.assertEqual(success(self,f,exercise=provider_fault(attack,fresh=False))['zero_calls'],0)
                exercise=None if index==0 else "from graph_engineering.application.staging_execution import StagedReleaseObservation;result=owner.reopen_staged(plan,grant);assert type(result) is StagedReleaseObservation,result;value=result.diagnostic();result.close()"
                self.assertEqual(success(self,f,exercise=exercise)['code'],'staged')
        for attack in ('poll-alias','liveness-code'):
            with self.subTest(running=attack),ExecutionFixture(installed=True,mode='hang') as f:
                self.assertEqual(success(self,f,exercise=running_provider_fault(attack))['zero_calls'],0)
