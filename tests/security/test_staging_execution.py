"""Actual source substitutions, record rejection, zero-call providers and stale handles."""
import json
import unittest
from tests.support.staging_execution import ExecutionFixture,success,require_success,native_helper,inventory,provider_fault,source_fault,running_provider_fault,reopen_rejection
from tests.support.release_staging import write_json,seal

class StagingExecutionSecurityTests(unittest.TestCase):
    def test_before_write_source_target_substitution(self):
        with ExecutionFixture() as f:
            exercise='''old=pathlib.Path(sys.argv[3])/'python.tar';old.write_bytes(old.read_bytes()+b'x')
result=owner.stage(plan,grant);assert type(result) is dict,result;value=result
'''
            value=success(self,f,exercise=exercise);self.assertIn(value['code'],('currentness','trust_rejected'));self.assertFalse(list(f.candidates.iterdir()))

        helper=native_helper()
        for phase in ('extraction','before-child','final'):
            with self.subTest(phase=phase),ExecutionFixture(helper=helper) as f:
                self.assertTrue(success(self,f,exercise=source_fault(phase))['fault_observed'])

    def test_member_mapping_record_and_template_rejection(self):
        helper=native_helper()
        for kind in ('unknown','digest','unused','raw'):
            with self.subTest(kind=kind),ExecutionFixture(helper=helper) as f:
                p=f.release.bundle/'template-0.json';v=json.loads(p.read_bytes())
                if kind=='raw':p.write_bytes(p.read_bytes()+b' ')
                else:
                    if kind=='unknown':v['segments']=[{'ref':'unknown'}]
                    elif kind=='digest':v['template_digest']='sha256-jcs-v1:'+'0'*64
                    else:v['logical_path']='payload/tool/unlisted';v=seal(v,'stage-generated-template','template_digest')
                    f.release.replace('template-0',json.dumps(v).encode(),sign=False);f.release.refresh_closure();f.request['release_manifest_digest']=f.release.value['manifest_digest'];write_json(f.request_path,f.request)
                result=require_success(self,f.plan());self.assertIn(result['code'],('input_invalid','closure_mismatch','trust_rejected'));self.assertFalse(list(f.candidates.iterdir()))

        # Complete destination-tree preflight must reject aliased directory
        # spellings before mkdir or a child, within one wheel and across owners.
        for installed in (False,True):
            for cross in (False,True):
                additions={'core':{'Pkg/a.py':b'first namespace member\n'}}
                additions.setdefault('parser' if cross else 'core',{})['pkg/b.py']=b'second namespace member\n'
                with self.subTest(installed=installed,cross_distribution=cross),ExecutionFixture(installed=installed,helper=helper,wheel_members=additions) as f:
                    before=inventory(f.release.base)
                    exercise="""events={'mkdir':0,'child':0};audit_active=True
def observe(event,args):
 if audit_active and event in ('os.mkdir','subprocess.Popen'):events['mkdir' if event=='os.mkdir' else 'child']+=1
sys.addaudithook(observe)
try:result=owner.stage(plan,grant)
finally:audit_active=False
assert type(result) is dict and result['code']=='closure_mismatch',result
value={'code':result['code'],'mkdir_calls':events['mkdir'],'child_calls':events['child']}
"""
                    value=success(self,f,exercise=exercise)
                    self.assertEqual(value,{'code':'closure_mismatch','mkdir_calls':0,'child_calls':0})
                    self.assertFalse(list(f.candidates.iterdir()));self.assertEqual(inventory(f.release.base),before)
            # Identically spelled shared namespace directories are supported.
            additions={'core':{'SharedNamespace/a.py':b'first shared member\n'},'parser':{'SharedNamespace/b.py':b'second shared member\n'}}
            with self.subTest(installed=installed,shared_namespace=True),ExecutionFixture(installed=installed,helper=helper,wheel_members=additions) as f:
                self.assertEqual(success(self,f)['code'],'staged')
                site=next(f.candidates.iterdir())/'payload/tool/lib/python3.12/site-packages/SharedNamespace'
                self.assertEqual((site/'a.py').read_bytes(),additions['core']['SharedNamespace/a.py'])
                self.assertEqual((site/'b.py').read_bytes(),additions['parser']['SharedNamespace/b.py'])

        # The native installer independently writes correct RECORD hashes for
        # its actual bytes. It still cannot normalize away an ordinary mutation,
        # an undeclared directory/metadata file, removed ownership or bad self-row.
        for mode in ('ordinary','emptydir','extra-metadata','selfrow','missing-record-covered'):
            with self.subTest(mode=mode),ExecutionFixture(mode=mode,helper=helper) as f:
                value=success(self,f,exercise="result=owner.stage(plan,grant);assert type(result) is dict,result;value=result")
                self.assertEqual(value['code'],'closure_mismatch');self.assertFalse(list(f.candidates.rglob('receipt.json')))

    def test_provider_substitution_zero_calls(self):
        helper=native_helper()
        for attack in ('alias','code','descriptor','guard','cleanup','retained','reopen','admission'):
            with self.subTest(attack=attack),ExecutionFixture(helper=helper) as f:
                if attack=='reopen':success(self,f)
                result=success(self,f,decisions=2,exercise=provider_fault(attack))
                self.assertEqual(result['zero_calls'],0);self.assertTrue(result['fresh_restored'])
        for attack in ('poll-alias','liveness-code'):
            with self.subTest(running=attack),ExecutionFixture(mode='hang',helper=helper) as f:
                self.assertEqual(success(self,f,exercise=running_provider_fault(attack))['zero_calls'],0)

    def test_foreign_replayed_handles_and_deadline(self):
        with ExecutionFixture() as f:
            success(self,f)
            for filename in ('execution-binding.json','receipt.json'):reopen_rejection(self,f,filename,'cross-link')
        with ExecutionFixture() as f:
            exercise='''from graph_engineering.application.staging_execution import StagedReleaseObservation
for fake in (True,{'approved':True},object.__new__(local.StagePermit),object.__new__(local.InstallationAuthority)):
 result=owner.stage(plan,fake);assert type(result) is dict,result
try:object.__new__(StagedReleaseObservation).require_current()
except ValueError:pass
else:raise AssertionError('unowned observation admitted')
result=owner.stage(plan,grant);assert type(result) is StagedReleaseObservation,result
newplan=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
try:result.require_current()
except ValueError:pass
else:raise AssertionError('rotated observation revived')
value={'foreign_refused':True};result.close();newplan.close()
'''
            self.assertTrue(success(self,f,exercise=exercise)['foreign_refused'])

        with ExecutionFixture() as f:
            exercise="""import time
deadline=local._GRANTS[id(grant)]['session'].deadline
while time.monotonic_ns()<=deadline:time.sleep(min(0.02,max(0,(deadline-time.monotonic_ns())/1_000_000_000)))
result=owner.stage(plan,grant);assert type(result) is dict and result['code'] in ('authority_required','currentness'),result
value={'actually_expired':True}
"""
            self.assertTrue(success(self,f,exercise=exercise)['actually_expired']);self.assertFalse(list(f.candidates.iterdir()))
        with ExecutionFixture() as f:
            exercise="""import threading
from graph_engineering.application.staging_execution import StagedReleaseObservation
result=owner.stage(plan,grant);assert type(result) is StagedReleaseObservation,result
# A non-executing forked observer has a real foreign PID. It never plans,
# authorizes or consumes, and cannot alter the parent's process-local result.
pid=os.fork()
if pid==0:
 try:result.require_current()
 except ValueError:os._exit(0)
 os._exit(1)
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0,'foreign PID admitted'
result.require_current()
refused=[]
def foreign():
 try:result.require_current()
 except ValueError:refused.append(True)
thread=threading.Thread(target=foreign);thread.start();thread.join()
assert refused,'foreign thread admitted'
try:result.require_current()
except ValueError:pass
else:raise AssertionError('thread failure revived result')
value={'thread_refused':True};result.close()
"""
            self.assertTrue(success(self,f,exercise=exercise)['thread_refused'])
