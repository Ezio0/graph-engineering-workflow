"""Read-only owned plan and unsupported operation journeys."""
import unittest
from tests.support.release_staging import StageFixture,inventory,require_success,expected_envelope

class ReleaseStagingIntegrationTests(unittest.TestCase):
    def test_plan_current_bundle_without_writes(self):
        for installed in (False,True):
            with self.subTest(installed=installed),StageFixture(installed=installed) as f:
                code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef
import os,subprocess
from unittest.mock import patch
calls=[];environment=dict(os.environ)
def forbidden(*a,**k):calls.append(True);raise AssertionError('release execution attempted')
with patch.object(subprocess,'Popen',side_effect=forbidden),patch.object(os,'system',side_effect=forbidden),patch.object(os,'execve',side_effect=forbidden):
 owner=ReleaseInstaller();p=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])));value=p.to_dict();p.close()
assert not calls and dict(os.environ)==environment
print(json.dumps(value))
'''
                before=inventory(f.release.base);expected=expected_envelope(f);value=require_success(self,f.plan(code))
                self.assertEqual(value,expected)
                self.assertEqual(inventory(f.release.base),before)

    def test_policy_recipe_context_replacement_refuses(self):
        for installed in (False,True):
            with self.subTest(installed=installed),StageFixture(installed=installed) as f:
                resource_root=f.release.product_root if installed else f.release.source
                code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
import os,shutil
req=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])); resources=pathlib.Path(sys.argv[5]);candidate=pathlib.Path(sys.argv[6]);target=pathlib.Path(sys.argv[7])
for kind in ('stage-policy','installer-policy','stage-target-registry','candidate','absence','manifest','candidate-mode','parent-mode','artifact'):
 owner=ReleaseInstaller();plan=owner.plan(req,bundle);assert type(plan) is StagePlanEnvelope,plan
 if kind in ('stage-policy','installer-policy','stage-target-registry'):
  p=resources/('config/release-installation/'+kind+'-v1.json');saved=p.read_bytes();p.write_bytes(saved+b' ')
 elif kind=='candidate':
  saved=candidate.with_name('old-candidate');os.rename(candidate,saved);candidate.mkdir(mode=0o700)
 elif kind=='absence':target.mkdir(mode=0o700)
 elif kind in ('candidate-mode','parent-mode'):
  p=candidate if kind=='candidate-mode' else target.parent;p.chmod(0o755)
 elif kind=='artifact':
  p=bundle.bundle/'uv.tar';saved=p.read_bytes();p.write_bytes(saved+b'changed')
 else:
  p=bundle.manifest;saved=p.read_bytes();replacement=p.with_name('replacement.json');replacement.write_bytes(saved);os.replace(replacement,p)
 try:
  plan.require_current()
 except ValueError:pass
 else:raise AssertionError('stale plan admitted: '+kind)
 if kind in ('stage-policy','installer-policy','stage-target-registry'):p.write_bytes(saved)
 elif kind=='candidate':candidate.rmdir();os.rename(saved,candidate)
 elif kind=='absence':target.rmdir()
 elif kind in ('candidate-mode','parent-mode'):p.chmod(0o700)
 elif kind=='artifact':p.write_bytes(saved)
 try:plan.require_current()
 except ValueError:pass
 else:raise AssertionError('invalidated plan revived')
owner=ReleaseInstaller();p=owner.plan(req,bundle);assert type(p) is StagePlanEnvelope,p;p.to_dict();p.close()
print(json.dumps({'replacements':9,'fresh_restoration':True}))
'''
                result=f.run(code,arguments=(f.request_path,f.release.bundle,f.release.manifest_path,resource_root,self._path(f,'candidates'),f.target),timeout=270)
                self.assertEqual(require_success(self,result)['replacements'],9)

    @staticmethod
    def _path(f,name):return getattr(f,name)

    def test_missing_prerequisites_and_apply_unavailable(self):
        import copy
        from tests.support.release_staging import seal,write_json,reseal
        def empty_keys(source):
            import json
            p=source/'config/release-installation/release-trust-registry-v1.json';v=json.loads(p.read_bytes());v['keys']=[]
            write_json(p,reseal(v,'trust-registry','registry_digest'))
        for installed in (False,True):
            with StageFixture(installed=installed) as f:
                code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
import copy,subprocess
req=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));owner=ReleaseInstaller();p=owner.plan(req,bundle);assert type(p) is StagePlanEnvelope,p;p.to_dict()
for v in (p,p.to_dict(),True,{'approved':True},lambda:True):
 for call in (owner.stage,owner.reopen_staged):
  result=call(v,True);assert result['code']=='phase_unavailable';assert result['capabilities']['stage']=='unavailable'
p.close()
for changes in ({'operation':'upgrade','prior_tuple_digest':req['release_manifest_digest']},{'target_refs':['missing']},{'operation':'rollback'}):
 v=dict(req,**changes);result=owner.plan(v,bundle);assert type(result) is dict and result['status'] in ('blocked','rejected'),result
print(json.dumps({'unavailable':True}))
'''
                before=inventory(f.release.base);self.assertTrue(require_success(self,f.plan(code))['unavailable']);self.assertEqual(inventory(f.release.base),before)
        variants=[{'installer_patch':lambda x:x.update(recipes=[])}, {'registry_patch':lambda x:x.update(roots=[])},
                  {'registry_patch':lambda x:x['roots'][1].update(owner_id='0')},
                  {'installer_patch':lambda x:x['recipes'].append(seal(dict(x['recipes'][0],recipe_id='z-other'),'installer-recipe','recipe_digest'))},
                  {'installer_patch':lambda x:x['recipes'].__setitem__(0,seal(dict(x['recipes'][0],interpreter_version='9.0.0'),'installer-recipe','recipe_digest'))},
                  {'installer_patch':lambda x:x['recipes'].__setitem__(0,seal(dict(x['recipes'][0],steps=[dict(x['recipes'][0]['steps'][0],argv=['--different'])]),'installer-recipe','recipe_digest'))},
                  {'release_policy_patch':{'source_ids':[]}},
                  {'source_patch':empty_keys},
                  {'physical_patch':lambda f:f.target.mkdir(mode=0o700)},
                  {'physical_patch':lambda f:f.parent.rmdir()},
                  {'physical_patch':lambda f:(f.release.bundle/'uv.tar').unlink()}]
        for kwargs in variants:
            with StageFixture(**kwargs) as f:
                before=inventory(f.release.base);v=require_success(self,f.plan());self.assertIn(v['status'],('rejected','blocked'));self.assertNotEqual(v['code'],'ok');self.assertEqual(inventory(f.release.base),before)
