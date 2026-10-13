"""Input, lifetime, provider, physical read-race and privacy refusals."""
import json
import unittest
from tests.support.release_staging import StageFixture,inventory,require_success,write_json,expected_envelope

class ReleaseStagingSecurityTests(unittest.TestCase):
    def test_plan_input_and_privacy_refusals(self):
        for installed in (False,True):
            with StageFixture(installed=installed) as f:
                code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
from graph_engineering.adapters import release_staging as a
import copy,threading,subprocess,os
from unittest.mock import patch
req=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));owner=ReleaseInstaller();p=owner.plan(req,bundle);assert type(p) is StagePlanEnvelope,p;p.to_dict();calls=[]
for fake in (object.__new__(StagePlanEnvelope),p.to_dict(),True):
 try:StagePlanEnvelope.require_current(fake)
 except ValueError:pass
 else:raise AssertionError('fabricated owned handle admitted')
try:copy.copy(p)
except TypeError:pass
else:raise AssertionError('copied owned handle admitted')
pid=os.fork()
if pid==0:
 try:p.require_current()
 except ValueError:os._exit(0)
 except BaseException:os._exit(2)
 os._exit(1)
assert os.waitpid(pid,0)[1]==0
p.require_current()
def other_thread():
 try:p.require_current()
 except ValueError:calls.append('refused')
t=threading.Thread(target=other_thread);t.start();t.join(10);assert not t.is_alive() and calls==['refused']
try:p.require_current()
except ValueError:pass
else:raise AssertionError('cross-thread invalidation did not stick')
# A changed target provider is refused before invoking it.
original=a._target_binding;count=[]
def malicious(*args):count.append(True);return original(*args)
a._target_binding=malicious
try:
 result=owner.plan(req,bundle);assert type(result) is dict and result['code']=='currentness',result
finally:a._target_binding=original
assert not count
class Suspect:
 def __eq__(self,other):count.append(True);raise AssertionError('suspect equality invoked')
 def __hash__(self):count.append(True);raise AssertionError('suspect hash invoked')
for v in (Suspect(),dict(req,authority=True),dict(req,target_refs=['/raw/path']),dict(req,config={})):assert type(owner.plan(v,bundle)) is dict
assert not count
fresh=owner.plan(req,bundle);assert type(fresh) is StagePlanEnvelope
owner.plan({},bundle)
try:fresh.require_current()
except ValueError:pass
else:raise AssertionError('operation boundary reused')
print(json.dumps({'lifetime_refused':True,'substituted_calls':len(count)}))
'''
                before=inventory(f.release.base);v=require_success(self,f.plan(code));self.assertEqual(v['substituted_calls'],0);self.assertEqual(inventory(f.release.base),before)
        # Actual directory descriptor barrier: external replacement during the first read.
        with StageFixture() as f:
            code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef
import os,threading
from unittest.mock import patch
request=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));candidate=pathlib.Path(sys.argv[5]);ready=threading.Event();done=threading.Event();errors=[];triggered=False;original=os.open
old=candidate.with_name('candidate-before-race')
def swap():
 try:
  assert ready.wait(30);os.rename(candidate,old);candidate.mkdir(mode=0o700)
 except BaseException as e:errors.append(type(e).__name__)
 finally:done.set()
def opened(path,flags,*args,**kwargs):
 global triggered
 fd=original(path,flags,*args,**kwargs)
 if not triggered and path==candidate.name and 'dir_fd' in kwargs:
  triggered=True;ready.set();assert done.wait(30)
 return fd
t=threading.Thread(target=swap);t.start()
try:
 with patch.object(os,'open',side_effect=opened):
  owner=ReleaseInstaller();v=owner.plan(request,bundle)
  assert type(v) is dict and v['code']=='currentness',v
finally:ready.set();t.join(30)
assert triggered and not errors and not t.is_alive()
print(json.dumps({'read_race_refused':True}))
'''
            result=f.run(code,arguments=(f.request_path,f.release.bundle,f.release.manifest_path,f.candidates),timeout=120);self.assertTrue(require_success(self,result)['read_race_refused'])
        # Closed public JSON parsing, including duplicate keys and charged pre-parse bounds.
        for installed in (False,True):
            with StageFixture(installed=installed) as f:
                r=f.release;args=['install-plan','--operation','install','--request',str(f.request_path),'--bundle',str(r.bundle),'--manifest',str(r.manifest_path),'--format','json']
                for body in (b'{"operation":"install","operation":"upgrade"}',b'{"bad":NaN}',b' '*65537,b'{"bad":'+b'['*2048+b'0'+b']'*2048+b'}'):
                    f.request_path.write_bytes(body);before=inventory(r.base);result=r.cli(args)
                    self.assertNotEqual(result.returncode,0);self.assertEqual(result.stderr,'');v=json.loads(result.stdout)
                    self.assertLess(len(result.stdout.encode()),65536);self.assertNotIn(str(r.base),result.stdout);self.assertIn(v['status'],('rejected','blocked'));self.assertEqual(inventory(r.base),before)
        def symlink(f):
            old=f.candidates.with_name('original-candidates');f.candidates.rename(old);f.candidates.symlink_to(old,target_is_directory=True)
        variants=[{'physical_patch':symlink},{'physical_patch':lambda f:f.candidates.chmod(0o755)},
                  {'registry_patch':lambda x:x['roots'][0].update(path=x['roots'][1]['path'].rsplit('/',1)[0])},
                  {'registry_patch':lambda x:x['roots'][0].update(path=x['roots'][0]['path']+'/../escape')},
                  {'registry_patch':lambda x:x['roots'].append(dict(x['roots'][0],ref='skill',role='skill-bootstrap'))}]
        for kwargs in variants:
            with StageFixture(**kwargs) as f:
                before=inventory(f.release.base);result=f.plan();v=require_success(self,result)
                self.assertIn(v['status'],('rejected','blocked'));self.assertNotIn(str(f.release.base),result.stdout);self.assertEqual(inventory(f.release.base),before)

        # Registry roots omitted from the request still constrain isolation.
        # Use the actual filesystem's case semantics, without a synthetic stat map.
        from pathlib import Path
        import os
        def excluded_alias(registry):
            candidate=Path(registry['roots'][0]['path'])
            alias=candidate.with_name(candidate.name.upper())
            if not alias.exists():alias=candidate
            assert os.stat(alias).st_ino==os.stat(candidate).st_ino
            registry['roots'].append(dict(registry['roots'][0],ref='skill',role='skill-bootstrap',path=str(alias)))
        def containing_alias(registry):
            candidate=Path(registry['roots'][0]['path']);parent=candidate.parent
            alias=parent.with_name(parent.name.upper())
            if not alias.exists():alias=parent
            assert os.stat(alias).st_ino==os.stat(parent).st_ino
            registry['roots'].append(dict(registry['roots'][0],ref='skill',role='skill-bootstrap',path=str(alias)))
        for installed in (False,True):
            for patch_registry in (excluded_alias,containing_alias):
                with StageFixture(installed=installed,registry_patch=patch_registry) as f:
                    before=inventory(f.release.base);result=f.plan();value=require_success(self,result)
                    self.assertIn(value.get('status'),('rejected','blocked'));self.assertNotIn(str(f.release.base),result.stdout)
                    self.assertEqual(inventory(f.release.base),before)
            # Use the running tool's actual root, including the real wheel location.
            import sys
            def owned_tool_alias(registry):
                base=Path(registry['roots'][0]['path']).parent
                root=(base/'environment'/('lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))/'site-packages/graph_engineering') if installed else base/'stage-source'
                alias=root.with_name(root.name.upper())
                # Probe actual host case semantics through the existing base path.
                if not base.with_name(base.name.upper()).exists():alias=root
                registry['roots'][0]['path']=str(alias)
            with StageFixture(installed=installed,registry_patch=owned_tool_alias) as f:
                root=f.release.product_root if installed else f.release.source
                root.chmod(0o700)
                configured=Path(f.registry['roots'][0]['path'])
                self.assertEqual((os.stat(configured).st_dev,os.stat(configured).st_ino),(os.stat(root).st_dev,os.stat(root).st_ino))
                before=inventory(f.release.base);result=f.plan();value=require_success(self,result)
                self.assertIn(value.get('status'),('rejected','blocked'));self.assertNotIn(str(f.release.base),result.stdout)
                self.assertEqual(inventory(f.release.base),before)

        def unused_root(registry):
            candidate=registry['roots'][0]
            registry['roots'].append(dict(candidate,ref='skill',role='skill-bootstrap',path=str(Path(candidate['path']).parent/'old-state')))
        for installed in (False,True):
            with StageFixture(installed=installed,registry_patch=unused_root) as f:
                # An unrequested but configured Skill root is physically bound.
                lifecycle='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
request=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));owner=ReleaseInstaller()
p=owner.plan(request,bundle);assert type(p) is StagePlanEnvelope;p.to_dict()
root=pathlib.Path(sys.argv[2]).parent/'old-state';old=root.with_name('old-state-before-replacement');root.rename(old);root.mkdir(mode=0o700)
try:
 try:p.require_current()
 except ValueError:pass
 else:raise AssertionError('unrequested changed root admitted')
finally:root.rmdir();old.rename(root)
try:p.require_current()
except ValueError:pass
else:raise AssertionError('unrequested changed root revived')
fresh=owner.plan(request,bundle);assert type(fresh) is StagePlanEnvelope;assert fresh.to_dict()==expected;fresh.close()
print(json.dumps({'unrequested_root_sticky':True}))
'''
                lifecycle='expected=json.loads('+repr(json.dumps(expected_envelope(f)))+')\n'+lifecycle
                self.assertTrue(require_success(self,f.run(lifecycle,arguments=(f.request_path,f.release.bundle,f.release.manifest_path)))['unrequested_root_sticky'])
