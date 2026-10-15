"""Installed authority uses owned RECORD resources and cold public launchers."""
import json
import os
import subprocess
import unittest
from tests.support.installation_authority import ApprovalFixture,inventory,provider_substitution_probe
from tests.support.release_staging import require_success

class InstallationAuthorityWheelTests(unittest.TestCase):
    def test_installed_terminal_approval(self):
        with ApprovalFixture(installed=True) as f:
            r=f.release
            for phase,target in (('acquisition','upstream'),('waiting','upstream'),('retained','upstream'),('consumption','upstream'),('retained','cleanup_code'),('retained','descriptor'),('retained','guard_code'),('consumption','guard_code')):
                before=inventory(r.base)
                v=require_success(self,f.terminal(**provider_substitution_probe(phase,target)))
                self.assertEqual(v['worker_exit'],0,v)
                if phase in ('acquisition','waiting'):self.assertEqual(v['value']['code'],'trust_rejected')
                else:
                    self.assertEqual(v['value']['substituted_calls'],0)
                    self.assertTrue(v['value']['sticky'])
                self.assertEqual(inventory(r.base),before)
            before=inventory(r.base);v=require_success(self,f.terminal())
            self.assertEqual(v['worker_exit'],0,v);self.assertTrue(v['responded'])
            self.assertEqual(v['value']['code'],'authority_issued');self.assertEqual(inventory(r.base),before)
            self.assertEqual(v['value']['capabilities']['install-apply'],'unavailable')

    def test_installed_mutations_and_cold_cli(self):
        with ApprovalFixture(installed=True) as f:
            r=f.release;p=r.product_root/'config/release-installation/installation-approval-policy-v1.json';body=p.read_bytes()
            try:
                v=require_success(self,f.terminal(mutate='p=pathlib.Path('+repr(str(p))+');p.write_bytes(p.read_bytes()+b" ")'))
                self.assertEqual(v['worker_exit'],0,v);self.assertTrue(v['responded'])
                self.assertIn(v['value']['code'],('trust_rejected','currentness'))
            finally:p.write_bytes(body)
            setup='''from graph_engineering.adapters import installation_authority as physical
original=physical._READ;calls=[]
def spy(*args,**kwargs):calls.append(True);raise AssertionError('installed replacement called')
physical._READ=spy
'''
            cleanup='''physical._READ=original;assert not calls'''
            v=require_success(self,f.terminal(before=setup,after=cleanup));self.assertEqual(v['worker_exit'],0,v)
            self.assertFalse(v['responded']);self.assertEqual(v['value']['code'],'trust_rejected')
            for phase,target in (('acquisition','json'),('waiting','stat'),('retained','json'),('consumption','stat'),('acquisition','guard_code'),('waiting','guard_code')):
                before=inventory(r.base)
                v=require_success(self,f.terminal(**provider_substitution_probe(phase,target)))
                self.assertEqual(v['worker_exit'],0,v)
                if phase in ('acquisition','waiting'):self.assertEqual(v['value']['code'],'trust_rejected')
                else:
                    self.assertEqual(v['value']['substituted_calls'],0)
                    self.assertTrue(v['value']['sticky'])
                self.assertEqual(inventory(r.base),before)
            env=dict(os.environ);env.pop('PYTHONDONTWRITEBYTECODE',None);env.pop('PYTHONPYCACHEPREFIX',None)
            # Decoy checkout content must never supply installed authority or policy.
            decoy=r.base/'graph_engineering';decoy.mkdir();(decoy/'__init__.py').write_text('raise AssertionError("DECOY-EXECUTED")\n')
            env.pop('PYTHONPATH',None)
            args=['install-plan','--operation','install','--request',str(f.request_path),'--bundle',str(r.bundle),'--manifest',str(r.manifest_path),'--format','json']
            missing=list(args);missing[missing.index('--request')+1]=str(r.base/'missing-request.json')
            cases=[(args,0),(args[:2]+['upgrade']+args[3:],2),(missing,2),(['install-apply','--plan',str(f.request_path),'--bundle',str(r.bundle),'--manifest',str(r.manifest_path),'--format','json'],3)]
            for argv,expected in cases:
                before=inventory(r.base);proc=subprocess.run([str(r.launcher),*argv],cwd=r.base,env=env,capture_output=True,text=True,timeout=90)
                self.assertEqual(proc.returncode,expected,proc.stderr);self.assertEqual(proc.stderr,'')
                value=json.loads(proc.stdout);self.assertNotIn('authority_issued',value.values());self.assertNotIn('DECOY-EXECUTED',proc.stdout)
                self.assertEqual(inventory(r.base),before)
            bad_env=dict(env);bad_env['PYTHONPATH']=str(r.base)
            before=inventory(r.base);proc=subprocess.run([str(r.launcher),*args],cwd=r.base,env=bad_env,capture_output=True,text=True,timeout=90)
            self.assertEqual(proc.returncode,4,proc.stderr);self.assertEqual(proc.stderr,'')
            self.assertEqual(json.loads(proc.stdout)['code'],'trust_rejected');self.assertEqual(inventory(r.base),before)
            self.assertNotIn('DECOY-EXECUTED',proc.stdout);self.assertFalse(list(r.base.rglob('__pycache__')))
