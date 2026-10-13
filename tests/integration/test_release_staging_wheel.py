"""Cold installed public planning commands, with no external cache masks."""
import json
import os
import subprocess
import unittest
from tests.support.release_staging import StageFixture,inventory,stage_framed

class ReleaseStagingWheelTests(unittest.TestCase):
    def test_installed_plan_cli_zero_writes(self):
        with StageFixture(installed=True) as f:
            r=f.release;env=dict(os.environ);env.pop('PYTHONDONTWRITEBYTECODE',None);env.pop('PYTHONPYCACHEPREFIX',None)
            args=['install-plan','--operation','install','--request',str(f.request_path),'--bundle',str(r.bundle),'--manifest',str(r.manifest_path),'--format','json']
            before=inventory(r.base);result=subprocess.run([str(r.launcher),*args],cwd=r.base,env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,0,result.stderr);v=json.loads(result.stdout);self.assertEqual(result.stderr,'')
            self.assertEqual(v['envelope_digest'],stage_framed('stage-plan-envelope',{k:x for k,x in v.items() if k!='envelope_digest'})[1]);self.assertEqual(inventory(r.base),before)
            missing=list(args);missing[missing.index('--request')+1]=str(r.base/'missing-request.json')
            cases=[(args[:2]+['upgrade']+args[3:],2),(missing,2),(['install-apply','--plan',str(f.request_path),'--bundle',str(r.bundle),'--manifest',str(r.manifest_path),'--format','json'],3)]
            for cmd,exit_code in cases:
                before=inventory(r.base);result=subprocess.run([str(r.launcher),*cmd],cwd=r.base,env=env,capture_output=True,text=True,timeout=90)
                self.assertEqual(result.returncode,exit_code,result.stderr);v=json.loads(result.stdout);self.assertEqual(result.stderr,'');self.assertNotIn('staged',v.values())
                self.assertEqual(v['diagnostic_digest'],stage_framed('stage-diagnostic',{k:x for k,x in v.items() if k!='diagnostic_digest'})[1]);self.assertEqual(inventory(r.base),before)
            p=r.product_root/'config/release-installation/stage-policy-v1.json';saved=p.with_name('missing-policy-backup.json');p.rename(saved)
            before=inventory(r.base);result=subprocess.run([str(r.launcher),*args],cwd=r.base,env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,4,result.stderr);self.assertEqual(result.stderr,'');self.assertEqual(json.loads(result.stdout)['code'],'trust_rejected');self.assertEqual(inventory(r.base),before)
            saved.rename(p);p.write_bytes(p.read_bytes()+b' ')
            before=inventory(r.base);result=subprocess.run([str(r.launcher),*args],cwd=r.base,env=env,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,4,result.stderr);self.assertEqual(result.stderr,'');self.assertLess(len(result.stdout.encode()),1024)
            self.assertEqual(json.loads(result.stdout)['code'],'trust_rejected');self.assertEqual(inventory(r.base),before)
            for text in (str(r.base),'ARTIFACT-EXECUTION-CANARY'):
                self.assertNotIn(text,result.stdout+result.stderr)
