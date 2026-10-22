"""Real local grant, signed process bytes, physical closure and durable staging."""
import json
import unittest
from tests.support.staging_execution import ExecutionFixture,success,native_helper,inventory,require_success,durability_fault,process_observation,concurrent_stage,reopen_rejection,running_provider_fault,stage_reader_fault

class StagingExecutionIntegrationTests(unittest.TestCase):
    def test_local_authority_stage_success(self):
        with ExecutionFixture() as f:
            value=success(self,f);self.assertEqual(value['code'],'staged');self.assertEqual(value['capabilities']['install-apply'],'stage-only')
            roots=list(f.candidates.iterdir());self.assertEqual(len(roots),1)
            self.assertEqual({p.name for p in (roots[0]/'metadata').iterdir()},{'installed-manifest.json','binding.json','execution-binding.json','receipt.json'})
            self.assertFalse(f.target.exists());self.assertFalse(list(f.release.base.rglob('__pycache__')))
        for installed in (False,True):
            for attack in ('signal-descriptor','popen-descriptor','signal-alias'):
                with self.subTest(installed=installed,running=attack),ExecutionFixture(installed=installed,mode='hang') as f:
                    self.assertEqual(success(self,f,exercise=running_provider_fault(attack))['zero_calls'],0)

    def test_two_roots_semantic_equality(self):
        helper=native_helper();manifests=[];bindings=[]
        with ExecutionFixture(helper=helper) as a,ExecutionFixture(helper=helper,prefix='a-deliberately-longer-candidate-prefix') as b:
            # Reuse precisely the same signed closure and recipe, not merely equal
            # synthetic dependencies with different security issuance timestamps.
            import shutil
            for path in b.release.bundle.iterdir():path.unlink()
            for path in a.release.bundle.iterdir():shutil.copyfile(path,b.release.bundle/path.name)
            b.release.value=a.release.value;b.request=dict(a.request);b.request_path.write_bytes(a.request_path.read_bytes())
            from tests.support.source_checkout_attestation import issue_source_checkout_attestation
            for name in ('release-policy','release-trust-registry','release-resource-policy'):
                shutil.copyfile(a.release.source/('config/release-installation/'+name+'-v1.json'),b.release.source/('config/release-installation/'+name+'-v1.json'))
            issue_source_checkout_attestation(b.release.source,b.release.control)
            for f in (a,b):
                success(self,f)
                root=next(f.candidates.iterdir());manifests.append(json.loads((root/'metadata/installed-manifest.json').read_bytes()));bindings.append(json.loads((root/'metadata/binding.json').read_bytes()))
            self.assertEqual(manifests[0],manifests[1]);self.assertNotEqual(bindings[0],bindings[1])
        for installed in (False,True):
            for route in ('prepare','retained'):
                for attack in ('descriptor','code'):
                    with self.subTest(installed=installed,route=route,attack=attack),ExecutionFixture(installed=installed,helper=helper) as f:
                        self.assertTrue(success(self,f,exercise=stage_reader_fault(attack,route))['owned_resources_retired'])

    def test_mutation_barriers_and_one_use(self):
        exercise='''from graph_engineering.application.staging_execution import StagedReleaseObservation
result=owner.stage(plan,grant);assert type(result) is StagedReleaseObservation,result
assert type(owner.stage(plan,grant)) is dict
import copy,pickle
for operation in (lambda:copy.copy(result),lambda:copy.deepcopy(result),lambda:pickle.dumps(result)):
 try:operation()
 except TypeError:pass
 else:raise AssertionError('owned result copied')
result.close();owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
try:result.require_current()
except ValueError:pass
else:raise AssertionError('closed observation revived')
value={'one_use':True}
'''
        with ExecutionFixture() as f:self.assertTrue(success(self,f,exercise=exercise)['one_use'])

    def test_process_failure_output_and_reap(self):
        helper=native_helper()
        for mode,code in [('fail','closure_mismatch'),('flood','resource_limit'),('hang','resource_limit'),('delay','resource_limit'),('overdue','resource_limit'),('extra','closure_mismatch'),('missing','closure_mismatch'),('badrecord','closure_mismatch'),('descendant','resource_limit'),('cumulative','resource_limit')]:
            with self.subTest(mode=mode),ExecutionFixture(mode=mode,helper=helper) as f:
                value=success(self,f,exercise=process_observation())
                self.assertEqual(value['code'],'recovery_blocked' if value['unconfirmed_group'] else code)
                self.assertTrue(all(row['bounds_checked'] for row in value['observations']))
                if mode in ('hang','descendant'):self.assertTrue(value['term_observed']);self.assertTrue(value['kill_observed'])
                if mode=='cumulative':self.assertGreater(value['observations'][-1]['output_bytes'],4096);self.assertEqual(len(value['observations']),2)
                self.assertFalse(list(f.candidates.rglob('receipt.json')))

    def test_receipt_durability_faults_and_reopen(self):
        with ExecutionFixture() as f:
            success(self,f)
            original=(next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes()
            exercise='''from graph_engineering.application.staging_execution import StagedReleaseObservation
result=owner.reopen_staged(plan,grant);assert type(result) is StagedReleaseObservation,result
result.require_current();value=result.diagnostic();result.close()
'''
            success(self,f,exercise=exercise)
            self.assertEqual((next(f.candidates.iterdir())/'metadata/execution-binding.json').read_bytes(),original)
            for filename in ('installed-manifest.json','binding.json','execution-binding.json','receipt.json'):
                for mutation in ('missing','malformed'):
                    if filename=='receipt.json' and mutation=='missing':continue
                    reopen_rejection(self,f,filename,mutation)
            (next(f.candidates.iterdir())/'metadata/receipt.json').unlink()
            value=success(self,f,exercise="result=owner.reopen_staged(plan,grant);assert type(result) is dict,result;value=result")
            self.assertIn(value['code'],('closure_mismatch','recovery_blocked'))
        helper=native_helper()
        for fault in ('write','file-fsync','directory-fsync','receipt-last','final-barrier'):
            with self.subTest(fault=fault),ExecutionFixture(helper=helper) as f:
                self.assertTrue(success(self,f,exercise=durability_fault(fault))['fault_observed'])
                if fault!='final-barrier':self.assertFalse(list(f.candidates.rglob('receipt.json')))

    def test_concurrent_root_and_bounded_cleanup(self):
        with ExecutionFixture() as f:
            success(self,f);before=inventory(f.candidates)
            value=success(self,f,exercise="result=owner.stage(plan,grant);assert type(result) is dict,result;value=result")
            self.assertEqual(value['code'],'recovery_blocked');self.assertEqual(inventory(f.candidates),before)

        with ExecutionFixture() as f:
            value=success(self,f,decisions=2,exercise=concurrent_stage())
            self.assertEqual(value['exclusive_winners'],1);self.assertTrue(value['loser_refused']);self.assertEqual(len(list(f.candidates.iterdir())),1)
        with ExecutionFixture() as f:
            for name in ('stage-unknown-a','stage-unknown-b'):(f.candidates/name).mkdir(mode=0o700)
            before=inventory(f.candidates)
            value=success(self,f,exercise="result=owner.stage(plan,grant);assert type(result) is dict,result;value=result")
            self.assertEqual(value['code'],'recovery_blocked');self.assertEqual(inventory(f.candidates),before)

    def test_apply_cli_local_and_refusals(self):
        helper=native_helper()
        for installed in (False,True):
            for route in ('cli-plan','cli-apply'):
                for attack in ('descriptor','code'):
                    with self.subTest(installed=installed,route=route,attack=attack),ExecutionFixture(installed=installed,helper=helper) as f:
                        if route=='cli-apply':
                            peer=require_success(self,f.cli_reader(attack));self.assertEqual(peer['worker_exit'],0,peer)
                            self.assertTrue(peer['responded'] and peer['display_verified'],peer)
                            self.assertTrue(peer['value']['owned_resources_retired'])
                        else:self.assertTrue(success(self,f,exercise=stage_reader_fault(attack,route))['owned_resources_retired'])
        with ExecutionFixture() as f:
            # Serialized plans never reconstruct authority in a noninteractive
            # invocation; a mismatched complete envelope refuses before prompting.
            from tests.support.release_staging import expected_envelope,write_json
            path=f.release.base/'plan.json';write_json(path,expected_envelope(f))
            args=['install-apply','--plan',str(path),'--bundle',str(f.release.bundle),'--manifest',str(f.release.manifest_path),'--format','json']
            before=inventory(f.candidates);p=f.release.cli(args)
            self.assertEqual(p.returncode,4,p.stderr);self.assertEqual(json.loads(p.stdout)['code'],'authority_required');self.assertEqual(inventory(f.candidates),before)
        with ExecutionFixture(installed=True) as f:
            path=f.release.base/'plan.json';write_json(path,expected_envelope(f))
            args=['install-apply','--plan',str(path),'--bundle',str(f.release.bundle),'--manifest',str(f.release.manifest_path),'--format','json']
            old=inventory(f.old_state);peer=require_success(self,f.cold_apply(args))
            self.assertEqual(peer['worker_exit'],0,peer);self.assertTrue(peer['responded']);self.assertTrue(peer['display_verified'])
            self.assertEqual(peer['value']['code'],'staged');self.assertEqual(peer['value']['capabilities']['install-apply'],'stage-only')
            self.assertEqual(inventory(f.old_state),old);self.assertFalse(list(f.release.base.rglob('__pycache__')))
            self.assertNotIn(str(f.release.base),json.dumps(peer));self.assertLessEqual(peer['transcript_bytes'],16384)
