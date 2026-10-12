"""Physical substitution, bounded ingress, currentness and diagnostic privacy."""
import json
import unittest
from tests.support.release_installation import (ReleaseFixture,fixture,tar_bytes,zip_bytes,
    write_json,inventory,json_bytes,require_success)


class ReleaseInstallationSecurityTests(unittest.TestCase):
    def test_substitution_signature(self):
        with ReleaseFixture() as baseline:require_success(self,baseline.check())
        for change in ('signature','projection','key','trust-digest','caller-key'):
            with ReleaseFixture() as f:
                if change=='signature':f.value['signature']='0'*128
                elif change=='projection':f.value['release_id']='substituted'
                elif change=='key':f.value['signing_key_id']='fixture-security-key';f.sign()
                elif change=='trust-digest':f.value['trust_registry_digest']='sha256-jcs-v1:'+'0'*64;f.sign()
                else:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    f.keys['release']=Ed25519PrivateKey.generate();f.sign()
                write_json(f.manifest_path,f.value);self.assertNotEqual(f.check().returncode,0,change)
            with self.subTest(change=change):self.assertFalse(hasattr(__import__('tests.support.release_installation',fromlist=['adapter']).adapter(),'InstallationAuthority'))

    def test_archive_paths_members_links(self):
        with ReleaseFixture() as baseline:require_success(self,baseline.check())
        cases=[('traversal','../escape'),('absolute','/escape'),('dot','a/./b'),('case','SKILL.md'),('unicode','e\u0301'),('duplicate','SKILL.md')]
        for label,path in cases:
            with ReleaseFixture() as f:
                first='skill.md' if label=='case' else 'SKILL.md'
                f.replace('skill',zip_bytes([(first,b'ok',0o100600),(path,b'bad',0o100600)]))
                self.assertNotEqual(f.check().returncode,0,label);self.assertFalse((f.base/'escape').exists())
        for kind in ('symlink','hardlink','device'):
            with ReleaseFixture() as f:
                f.replace('python',tar_bytes([('bin/python',b'outside',kind)]))
                self.assertNotEqual(f.check().returncode,0,kind)
        with ReleaseFixture() as f:
            f.replace('skill',zip_bytes([('SKILL.md',b'outside',0o120777)]));self.assertNotEqual(f.check().returncode,0)

    def test_preallocation_cumulative(self):
        with ReleaseFixture() as baseline:require_success(self,baseline.check())
        import io,zipfile,tarfile,math
        with ReleaseFixture() as baseline:
            baseline.replace('skill',zip_bytes([('SKILL.md',b'0'*4000,0o100600)],compressed=True));baseline.refresh_closure()
            d=require_success(self,baseline.check());rows=baseline.value['artifacts']
            raw_total=sum(r['size_bytes'] for r in rows)+baseline.manifest_path.stat().st_size
            expanded=members=wheel_hash_reserve=0;ratio=1;path_segments=1
            for row in rows:
                raw=(baseline.bundle/row['relative_path']).read_bytes()
                if row['kind'] in ('core-wheel','dependency-wheel','skill'):
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                        infos=archive.infolist();e=sum(i.file_size for i in infos);members+=len(infos)
                        path_segments=max(path_segments,max(len(i.filename.split('/')) for i in infos))
                    expanded+=e*(2 if row['kind']!='skill' else 1);ratio=max(ratio,math.ceil(e/len(raw)))
                    if row['kind']!='skill':wheel_hash_reserve+=2*len(raw)+e
                elif row['kind'] in ('interpreter','installer'):
                    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                        infos=archive.getmembers();expanded+=sum(i.size for i in infos);members+=len(infos)
                        path_segments=max(path_segments,max(len(i.name.split('/')) for i in infos))
            exact={'max_manifest_bytes':baseline.manifest_path.stat().st_size,'max_artifacts':len(rows),
                'max_dependency_edges':len(baseline.value['dependencies']),'max_artifact_bytes':max(r['size_bytes'] for r in rows),
                'max_bundle_bytes':raw_total,'max_archive_members':members,'max_expanded_bytes':expanded,
                'max_expansion_ratio':ratio,'max_path_segments':path_segments,'max_hash_bytes':3*raw_total+wheel_hash_reserve,
                'max_report_bytes':len(json_bytes(d))}
        for cap,boundary in exact.items():
            for limit,accepted in ((boundary,True),(boundary-1,False)):
                with ReleaseFixture(limits_patch={cap:limit}) as f:
                    f.replace('skill',zip_bytes([('SKILL.md',b'0'*4000,0o100600)],compressed=True));f.refresh_closure()
                    result=f.check()
                    if accepted:self.assertEqual(result.returncode,0,(cap,limit,result.stdout,result.stderr[-1000:]))
                    else:
                        self.assertEqual(result.returncode,4,(cap,limit,result.stderr[-1000:]))
                        self.assertEqual(json.loads(result.stdout)['code'],'resource_limit',(cap,result.stdout))
        with ReleaseFixture() as f:
            f.row('python')['size_bytes']+=1;f.sign();self.assertNotEqual(f.check().returncode,0)
        with ReleaseFixture(limits_patch={'max_bundle_bytes':20000}) as f:
            self.assertLess(max(r['size_bytes'] for r in f.value['artifacts']),20000)
            self.assertGreater(sum(r['size_bytes'] for r in f.value['artifacts']),20000)
            self.assertEqual(json.loads(f.check().stdout)['code'],'resource_limit')
        # A forged ZIP member size must be refused before ZipFile/decompression allocation.
        with ReleaseFixture() as f:
            body=bytearray((f.bundle/f.row('skill')['relative_path']).read_bytes());offset=body.index(b'PK\x01\x02')
            import struct
            struct.pack_into('<L',body,offset+24,0x7fffffff);f.replace('skill',bytes(body))
            result=f.run('from graph_engineering.adapters import release_installation as a;assert hasattr(a,"LocalReleaseVerifier"),"physical verifier absent";from unittest.mock import patch;\nwith patch("zipfile.ZipFile",side_effect=AssertionError("allocated before bounds")):\n try:a.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]))\n except ValueError:pass\n else:raise AssertionError("accepted oversized declaration")',arguments=(f.bundle,f.manifest_path))
            self.assertEqual(result.returncode,0,result.stderr)

    def test_stale_file_parent_provider_race(self):
        for installed in (False,True):
            with ReleaseFixture(installed=installed) as f:
                # A second correctly signed physical closure uses the same private
                # trust, but an incompatible interpreter constraint. Setup ends
                # before the complete before/after read-only inventory.
                import shutil
                from tests.support.release_installation import physical_wheel
                saved={p.name:p.read_bytes() for p in f.bundle.iterdir()}
                f.replace('core',physical_wheel(fixture()['runtime_distributions'][0],requires_python='>=3.13'));f.refresh_closure()
                incompatible=f.base/'incompatible-bundle';shutil.copytree(f.bundle,incompatible)
                f.replace('core',physical_wheel(fixture()['runtime_distributions'][0],requires_python='>=3.13rc1'));f.refresh_closure()
                incompatible_rc=f.base/'incompatible-rc-bundle';shutil.copytree(f.bundle,incompatible_rc)
                for name,body in saved.items():(f.bundle/name).write_bytes(body)
                code='''from graph_engineering.adapters import release_installation as a
from graph_engineering.application.cli import main
import packaging.specifiers as s,os
from unittest.mock import patch
root=pathlib.Path(sys.argv[2]);manifest=pathlib.Path(sys.argv[3]);args=['release-check','--bundle',str(root),'--manifest',str(manifest),'--format','json']
o=a.LocalReleaseVerifier().check(root,manifest);o.require_current()
owned=o._provider;calls=0
class ProviderProxy:
 def require_current(self):
  global calls
  calls+=1;return o._parser
 def close(self):
  global calls
  calls+=1
o._provider=ProviderProxy()
try:o.require_current()
except ValueError:pass
else:raise AssertionError('observation admitted foreign provider')
assert calls==0,'foreign provider dispatch executed'
try:owned.require_current()
except ValueError:pass
else:raise AssertionError('replaced provider retained private authority')
o=a.LocalReleaseVerifier().check(root,manifest)
owned=o._provider
with patch.object(owned,'require_current',lambda:o._parser):
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('observation admitted replaced provider method')
try:o.require_current()
except ValueError:pass
else:raise AssertionError('changed provider rehabilitated')
o=a.LocalReleaseVerifier().check(root,manifest)
real=s.SpecifierSet
import abc,packaging.requirements as requirements,contextlib,io,hashlib
bad=pathlib.Path(sys.argv[4]);bad_args=['release-check','--bundle',str(bad),'--manifest',str(bad/'release.json'),'--format','json']
def refused(arguments):
 output=io.StringIO()
 with contextlib.redirect_stdout(output):exit_code=main(arguments)
 text=output.getvalue();assert exit_code==4,'constructor dispatch admitted incompatible wheel'
 assert len(text.encode())<1024 and str(root.parent) not in text
 value=json.loads(text);claimed=value.pop('diagnostic_digest')
 envelope={'algorithm':'sha-256','body':value,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
  'contract_type':'urn:gew:contract:release-install-diagnostic','digest_domain':'urn:gew:digest:semantic:1.0.0',
  'projection_id':'urn:gew:digest-projection:release-install-diagnostic:1.0.0','schema_id':'urn:gew:schema:release-install-diagnostic:1.0.0'}
 assert claimed=='sha256-jcs-v1:'+hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
refused(bad_args)
class Dispatch(abc.ABCMeta):
 def __call__(cls,*args,**kwargs):
  if args and args[0]=='>=3.13':return real('')
  return super().__call__(*args,**kwargs)
slots=set(real.__slots__)
attributes={k:v for k,v in vars(real).items() if k not in slots|{'__dict__','__weakref__','_abc_impl'}}
replacement=Dispatch('SpecifierSet',real.__bases__,attributes)
assert replacement.contains is real.contains and replacement.__init__ is real.__init__
with patch.object(s,'SpecifierSet',replacement),patch.object(requirements,'SpecifierSet',replacement):
 refused(bad_args)
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('retained observation accepted constructor dispatch replacement')
assert main(args)==0
refused(bad_args)
class Forged:
 __module__='packaging.specifiers'
 def __init__(self,*args,**kwargs):pass
 def contains(self,*args,**kwargs):return True
with patch.object(s,'SpecifierSet',Forged):
 assert main(args)==4,'pre-use parser replacement admitted'
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('retained observation accepted parser replacement')
assert main(args)==0
backend=a._release_backend();assert 'SpecifierSet' in backend,'specifier callable boundary absent'
backend['SpecifierSet']=Forged
try:backend['_package_parser_attestation']()
except ValueError:pass
else:raise AssertionError('backend parser alias accepted replacement')
real_read=os.read;inode=(root/next(p.name for p in root.glob('graph_engineering_workflow-*.whl'))).stat().st_ino
reads=0;changed=False;contains=real.contains
def read(fd,size):
 global reads,changed
 data=real_read(fd,size)
 if data and os.fstat(fd).st_ino==inode:
  reads+=1
  if reads==2:
   real.contains=lambda *args,**kwargs:True;changed=True
 return data
try:
 with patch.object(os,'read',side_effect=read):assert main(args)==4,'during-read callable replacement admitted'
 assert changed,'physical read barrier was not exercised'
finally:real.contains=contains
assert main(args)==0
assert main(['doctor','--format','json'])==3
'''
                prefix,remaining=code.split('owned=o._provider;calls=0\n',1)
                provider_checks,remaining=remaining.split('real=s.SpecifierSet\n',1)
                provider_code=prefix+'owned=o._provider;calls=0\n'+provider_checks
                code=prefix+'real=s.SpecifierSet\n'+remaining
                storage_code=code.split('class Dispatch',1)[0]+'''
# Slot replacement preserves every genuine callable and constructor. The
# incompatible physical constraint must not become an empty, unconstrained set.
slot=vars(real)['_specs']
class Storage:
 def __get__(self,instance,owner=None):return slot.__get__(instance,owner)
 def __set__(self,instance,value):
  if any(str(item)=='>=3.13' for item in value):value=()
  slot.__set__(instance,value)
with patch.object(real,'_specs',Storage()):
 refused(bad_args)
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('retained observation accepted substituted parser storage')
assert main(args)==0
refused(bad_args)
'''
                operator_code=code.split('class Dispatch',1)[0]+'''
original_ops=s._DIRECT_COMPARE_OPS
class Operators(dict):
 def get(self,key,default=None):
  if key=='>=':return s.Version.__le__
  return super().get(key,default)
replacement_ops=Operators(original_ops)
assert replacement_ops==original_ops
with patch.object(s,'_DIRECT_COMPARE_OPS',replacement_ops):
 refused(bad_args)
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('retained observation accepted operator-container dispatch replacement')
assert main(args)==0
refused(bad_args)
'''
                regex_code=code.split('class Dispatch',1)[0]+'''
import packaging.version as version
regex=vars(version.Version)['_regex'];calls=0
class RegexProxy:
 def fullmatch(self,text,*args,**kwargs):
  global calls
  calls+=1
  return regex.fullmatch('3.12' if text=='3.13rc1' else text,*args,**kwargs)
with patch.object(version.Version,'_regex',RegexProxy()):
 refused(bad_args)
 try:o.require_current()
 except ValueError:pass
 else:raise AssertionError('retained observation accepted regex proxy')
assert calls==0,'suspect regex dispatch executed'
assert main(args)==0
refused(bad_args)
'''
                before=inventory(f.base)
                p=f.run(regex_code,arguments=(f.bundle,f.manifest_path,incompatible_rc));self.assertEqual(p.returncode,0,p.stderr)
                self.assertEqual(p.stderr,'');self.assertNotIn(str(f.base),p.stdout);self.assertEqual(inventory(f.base),before)
                graph_code='''
from graph_engineering.adapters import release_installation as a
import packaging.version as v, packaging.specifiers as s, packaging._ranges as r
import contextlib,gc,typing,re,weakref
from unittest.mock import patch
backend=a._release_backend()
# Warm the existing physical attestation's ordinary stdlib metadata lookups.
p=backend['_owned_constraint_provider']();p.close()
def registries():
 overload=tuple(sorted((m,q,line,id(fn),id(fn.__globals__)) for m,qs in typing._overload_registry.items() for q,ls in qs.items() for line,fn in ls.items()))
 caches=tuple(sorted((id(fn),tuple(sorted(tuple(sorted((id(k),id(value)) for k,value in d.items())) for d in gc.get_referents(cache) if type(d) is dict))) for fn,cache in typing._caches.items()))
 regex=tuple(tuple(sorted((key[0].__name__,key[1],key[2],id(value)) for key,value in cache.items())) for cache in (re._cache,re._cache2))
 return overload,caches,regex
baseline=registries();cls=backend['_ConstraintImage'];init=cls.__init__;check=cls.check
seen=[]
def watched_init(self,*args,**kwargs):
 assert registries()==baseline,'ambient bindings changed before construction'
 init(self,*args,**kwargs)
 assert registries()==baseline,'ambient bindings changed during construction'
 seen.append(weakref.ref(self))
def watched_check(self):
 assert registries()==baseline,'private construction published ambient bindings'
 return check(self)
with patch.object(cls,'__init__',watched_init),patch.object(cls,'check',watched_check):
 for _ in range(2):
  p=backend['_owned_constraint_provider']()
  refs=[weakref.ref(m) for m in p._state['image'].modules.values()]
  refs.extend(weakref.ref(vars(p._state['image'].modules['packaging.version'])[name]) for name in ('Version','parse'))
  for version,constraint,expected in [('3.12.12','>=3.12',True),('3.12.12','>=3.13rc1',False),('1!3.12.0','==1!3.12.*',True),('3.12.1.post1','~=3.12.0',True),('3.12.0.dev1','>=3.12',False),('3.12.0+local','==3.12',True),('3.13rc1','>=3.13rc1',True),('3.12.12','',True)]:
   assert p.requires_python(version,constraint) is expected,(version,constraint)
  # A transient ambient swap after the first guard cannot affect private work.
  current=p.require_current;original_init=v.Version.__init__;count=0
  def barrier():
   global count
   count+=1
   if count==1:
    result=current();v.Version.__init__=lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError('ambient Version executed'))
    return result
   v.Version.__init__=original_init;return current()
  try:
   with patch.object(p,'require_current',barrier):assert p.requires_python('3.12.12','>=3.13rc1') is False
  finally:v.Version.__init__=original_init
  p.close();del p;gc.collect()
  assert all(ref() is None for ref in refs),'released private graph retained'
  assert registries()==baseline,'release changed ambient bindings'
 def failed(self):
  assert registries()==baseline
  seen.extend(weakref.ref(module) for module in self.modules.values())
  raise ValueError('private construction failed')
 with patch.object(cls,'check',failed):
  try:backend['_owned_constraint_provider']()
  except ValueError as error:kept_error=error
  else:raise AssertionError('failed construction admitted')
 gc.collect();assert all(ref() is None for ref in seen),'failed image retained'
 assert registries()==baseline
calls=0
class Indicators(frozenset):
 def __contains__(self,item):
  global calls
  calls+=1;return True
class Unknown:
 def __get__(self,*args):
  global calls
  calls+=1;raise AssertionError('unknown descriptor executed')
class Key:
 def __hash__(self):
  global calls
  calls+=1;return 0
 def __eq__(self,other):raise AssertionError('unknown key equality executed')
key=Key();bad_mapping={key:'private'};calls=0
import types
class Builtins(dict):
 def get(self,*args):
  global calls
  calls+=1;return super().get(*args)
original=s.SpecifierSet.contains;namespace=original.__globals__;saved_builtins=namespace['__builtins__']
try:
 namespace['__builtins__']=Builtins(original.__builtins__)
 copied=types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__,original.__closure__)
 copied.__kwdefaults__=original.__kwdefaults__;copied.__annotations__=dict(original.__annotations__)
finally:namespace['__builtins__']=saved_builtins
attacks=[patch.object(v,'_SIMPLE_VERSION_INDICATORS',Indicators(v._SIMPLE_VERSION_INDICATORS)),
 patch.object(v,'_PRE_RANK',dict(v._PRE_RANK,rc=-100)),patch.object(r.MIN_RELEASE,'_release',(99,)),
 patch.object(r.NEG_INF,'inclusive',True),patch.object(s.SpecifierSet.contains,'__defaults__',(True,True)),
 patch.object(s.SpecifierSet.contains,'__kwdefaults__',{'prereleases':True}),
 patch.object(s,'trim_release',lambda *args:()),patch.object(v.Version,'unknown_dispatch',Unknown(),create=True),
 patch.object(v,'_LETTER_NORMALIZATION',bad_mapping),patch.object(v,'CmpKey',Unknown()),patch.object(s.SpecifierSet,'contains',copied)]
for attack in attacks:
 p=backend['_owned_constraint_provider']()
 with attack:
  try:backend['_owned_constraint_provider']()
  except ValueError:pass
  else:raise AssertionError('fresh transitive substitution admitted')
  try:p.require_current()
  except ValueError:pass
  else:raise AssertionError('retained transitive substitution admitted')
 try:p.require_current()
 except ValueError:pass
 else:raise AssertionError('closed provider silently rehabilitated')
 p=backend['_owned_constraint_provider']();assert p.requires_python('3.12.12','>=3.12');p.close()
assert calls==0,'suspect dispatch invoked'
p=backend['_owned_constraint_provider']();hash(r.MIN_VERSION);hash(r.MIN_RELEASE);p.require_current();p.close()
assert registries()==baseline
'''
                p=f.run(graph_code);self.assertEqual(p.returncode,0,p.stderr)
                self.assertEqual(p.stderr,'');self.assertEqual(inventory(f.base),before)
                bindings=[]
                for seed in ('1','2'):
                    p=f.run("from graph_engineering.adapters import release_installation as a;print(a._release_backend()['_package_parser_attestation']().attestation_digest)",extra_env={'PYTHONHASHSEED':seed})
                    self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stderr,'');bindings.append(p.stdout)
                    self.assertEqual(inventory(f.base),before)
                self.assertEqual(bindings[0],bindings[1],'parser binding depends on process hash seed')
                for scenario in (provider_code,operator_code,code,storage_code):
                    p=f.run(scenario,arguments=(f.bundle,f.manifest_path,incompatible));self.assertEqual(p.returncode,0,p.stderr)
                    self.assertEqual(p.stderr,'');self.assertNotIn(str(f.base),p.stdout)
                    self.assertEqual(inventory(f.base),before)
        with ReleaseFixture() as f:
            # Actual retained observation is factory-owned; replacement invalidates use.
            code='''from graph_engineering.adapters import release_installation as a
assert hasattr(a,'LocalReleaseVerifier'),'physical verifier absent'
import os,shutil
v=a.LocalReleaseVerifier();root=pathlib.Path(sys.argv[2]);m=pathlib.Path(sys.argv[3]);o=v.check(root,m)
p=root/'skill.zip';body=p.read_bytes();replacement=root/'replacement';replacement.write_bytes(body);os.replace(replacement,p)
try:o.require_current()
except ValueError:pass
else:raise AssertionError('same-byte file replacement reused')
'''
            self.assertEqual((p:=f.run(code,arguments=(f.bundle,f.manifest_path))).returncode,0,p.stderr)
        with ReleaseFixture() as f:
            code='''from graph_engineering.adapters import release_installation as a
assert hasattr(a,'LocalReleaseVerifier'),'physical verifier absent'
import os,shutil,graph_engineering
root=pathlib.Path(sys.argv[2]);m=pathlib.Path(sys.argv[3]);o=a.LocalReleaseVerifier().check(root,m)
saved=root.with_name('old-bundle');os.rename(root,saved);shutil.copytree(saved,root)
try:o.require_current()
except ValueError:pass
else:raise AssertionError('parent replacement reused')
i=a.InstalledReleaseInputs.open_owned();graph_engineering._release_installation_resources=lambda context:None
try:i.require_current()
except ValueError:pass
else:raise AssertionError('substituted provider reused')
'''
            self.assertEqual((p:=f.run(code,arguments=(f.bundle,f.manifest_path))).returncode,0,p.stderr)

        with ReleaseFixture() as f:
            code="""from graph_engineering.adapters import release_installation as a
import os,threading
from unittest.mock import patch
root=pathlib.Path(sys.argv[2]);manifest=pathlib.Path(sys.argv[3]);p=root/'skill.zip';inode=os.lstat(p).st_ino
ready=threading.Event();done=threading.Event();original=os.read;triggered=False
errors=[]
def swap():
 try:
  assert ready.wait(10),'read barrier did not fire'
  q=root/'replacement';q.write_bytes(p.read_bytes());os.replace(q,p)
 except BaseException as e:errors.append(e)
 finally:done.set()
def read(fd,size):
 global triggered
 data=original(fd,size)
 if not triggered and os.fstat(fd).st_ino==inode:
  triggered=True;ready.set();assert done.wait(10),'swap barrier did not finish'
 return data
worker=threading.Thread(target=swap);worker.start()
try:
 with patch.object(os,'read',side_effect=read):
  try:a.LocalReleaseVerifier().check(root,manifest)
  except a.ReleaseInstallationError as e:assert e.code=='currentness',e.code
  else:raise AssertionError('during-stream file replacement accepted')
finally:ready.set();worker.join(10)
assert triggered and not worker.is_alive() and not errors
"""
            p=f.run(code,arguments=(f.bundle,f.manifest_path));self.assertEqual(p.returncode,0,p.stderr)
        for phase in ('release.after-open','release.before-return'):
            with ReleaseFixture() as f:
                code="""from graph_engineering.adapters import release_installation as a
import os
root=pathlib.Path(sys.argv[2]);manifest=pathlib.Path(sys.argv[3]);phase=sys.argv[4]
def hook(actual):
 if actual==phase:
  p=root/'skill.zip';q=root/'replacement';q.write_bytes(p.read_bytes());os.replace(q,p)
try:a.LocalReleaseVerifier().check(root,manifest,_probe_hook=hook)
except a.ReleaseInstallationError as e:assert e.code=='currentness',e.code
else:raise AssertionError('captured-file race accepted')
"""
                p=f.run(code,arguments=(f.bundle,f.manifest_path,phase));self.assertEqual(p.returncode,0,p.stderr)

    def test_clock_no_write_refusal(self):
        import sqlite3,time
        with ReleaseFixture() as f:
            root=f.base/'installation';root.mkdir(mode=0o700)
            with sqlite3.connect(root/'state.sqlite3') as c:
                c.execute('CREATE TABLE repository_clock_state(singleton INTEGER,clock_high_water_ns INTEGER)')
                c.execute('INSERT INTO repository_clock_state VALUES(1,?)',(time.time_ns()+1000*10**9,))
            before=inventory(root)
            code='''from graph_engineering.adapters import release_installation as a
assert hasattr(a,'ReadOnlyDoctor'),'read-only Doctor absent'
from unittest.mock import patch
with patch('graph_engineering.storage.clock.strict_trusted_now',side_effect=AssertionError('clock write attempted')):
 d=a.ReadOnlyDoctor().inspect(pathlib.Path(sys.argv[2]));print(json.dumps(d))
'''
            result=require_success(self,f.run(code,arguments=(root,)))
            self.assertEqual(result['status'],'blocked');self.assertEqual(result['code'],'clock_unavailable');self.assertEqual(inventory(root),before)

    def test_diagnostic_privacy(self):
        import shutil,subprocess,os
        for installed in (False,True):
            attacks=('owned-resource','duplicate-origin') if installed else ('missing-attestation','changed-attestation','owned-resource')
            for attack in attacks:
                with ReleaseFixture(installed=installed) as f:
                    require_success(self,f.check())
                    if attack=='missing-attestation':(f.control/'source-checkout-attestation-v1.json').unlink()
                    elif attack=='changed-attestation':
                        p=f.control/'source-checkout-attestation-v1.json';document=json.loads(p.read_bytes());document['attestation_hmac_sha256']='0'*64;write_json(p,document)
                    elif attack=='owned-resource':
                        p=(f.product_root if installed else f.source)/'config/release-installation/release-policy-v1.json';p.write_bytes(p.read_bytes()+b' ')
                    else:
                        p=next(f.product_root.parent.glob('graph_engineering_workflow-*.dist-info'));shutil.copytree(p,p.with_name('duplicate-0.1.0.dist-info'))
                    before=inventory(f.base)
                    for command in ('release-check','doctor'):
                        args=[command,'--format','json']
                        if command=='release-check':args+=['--bundle',f.bundle,'--manifest',f.manifest_path]
                        if installed:
                            child_env=dict(os.environ);child_env.pop('PYTHONDONTWRITEBYTECODE',None);child_env.pop('PYTHONPYCACHEPREFIX',None)
                            result=subprocess.run([str(f.launcher),*map(str,args)],cwd=f.base,env=child_env,capture_output=True,text=True,timeout=90)
                        else:result=f.cli(args)
                        self.assertEqual(result.returncode,4 if command=='release-check' else 3)
                        self.assertEqual(result.stderr,'',result.stderr[-500:]);self.assertLess(len(result.stdout.encode()),1024)
                        d=json.loads(result.stdout);self.assertEqual(d['code'],'trust_rejected')
                        from tests.support.release_installation import framed
                        self.assertEqual(d['diagnostic_digest'],framed('diagnostic',{k:v for k,v in d.items() if k!='diagnostic_digest'})[1])
                        self.assertNotIn(str(f.base),result.stdout);self.assertEqual(inventory(f.base),before)
        for installed in (False,True):
            with ReleaseFixture(installed=installed) as f:
                code='''from graph_engineering.application.cli import main
import graph_engineering
from unittest.mock import patch
def poison(*args,**kwargs):raise ValueError('PRIVATE-SEED-TOKEN-CANARY')
with patch.object(graph_engineering,'_security_bootstrap_seed_resources',poison):
 result=main(sys.argv[2:])
raise SystemExit(result)
'''
                before=inventory(f.base)
                for args in (['doctor','--format','json'],['release-check','--bundle',f.bundle,'--manifest',f.manifest_path,'--format','json']):
                    result=f.run(code,arguments=args);self.assertEqual(result.returncode,3 if args[0]=='doctor' else 4)
                    self.assertEqual(result.stderr,'');self.assertNotIn('PRIVATE-SEED-TOKEN-CANARY',result.stdout)
                    self.assertEqual(json.loads(result.stdout)['code'],'trust_rejected');self.assertEqual(inventory(f.base),before)
        with ReleaseFixture() as f:
            secret='PRIVATE-PROMPT-TASK-TOKEN-CANARY';p=f.base/secret;p.mkdir();manifest_path=p/(secret+'.json');manifest_path.write_bytes(json_bytes({'secret':secret}))
            result=f.cli(['release-check','--bundle',p,'--manifest',manifest_path,'--format','json'])
            self.assertEqual(result.returncode,2)
            self.assertNotIn(secret,result.stdout+result.stderr);self.assertNotIn(str(f.base),result.stdout+result.stderr)
            self.assertTrue(result.stdout.startswith('{'),result.stderr);d=json.loads(result.stdout);self.assertEqual(d['code'],'input_invalid');self.assertLess(len(result.stdout.encode()),fixture()['fixture_limits']['max_report_bytes'])

        with ReleaseFixture() as f:
            from tests.support.release_installation import physical_wheel
            secret='PRIVATE-PARSER-TOKEN-CANARY'
            f.replace('core',physical_wheel(fixture()['runtime_distributions'][0],requirements=[secret+' @ https://invalid.example/'+secret]))
            result=f.cli(['release-check','--bundle',f.bundle,'--manifest',f.manifest_path,'--format','json'])
            self.assertEqual(result.returncode,4)
            self.assertNotIn(secret,result.stdout+result.stderr);self.assertEqual(result.stderr,'')
            self.assertIn(json.loads(result.stdout)['code'],('closure_mismatch','trust_rejected'))
