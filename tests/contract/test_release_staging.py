"""Physical SOURCE/WHEEL schema, resource and retained closure contracts."""
import copy
import json
import unittest
from pathlib import Path
from tests.support.release_staging import ROOT,StageFixture,context,core,require_success,request,policies,expected_envelope,inventory

class ReleaseStagingContractTests(unittest.TestCase):
    def test_stage_schema_registry_closure(self):
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy
        names=('stage-request','install-plan','stage-context','stage-plan-envelope','stage-policy','installer-policy','stage-target-registry','stage-diagnostic')
        bodies={(d:=json.loads((ROOT/('config/contracts/schemas/'+n+'-1.0.0.json')).read_bytes()))['$id']:(ROOT/('config/contracts/schemas/'+n+'-1.0.0.json')).read_bytes() for n in names}
        doc=json.loads((ROOT/'config/contracts/release-staging-schema-registry-v1.json').read_bytes());c=context()
        profile=SchemaProfilePolicy.from_dict(json.loads((ROOT/'config/contracts/schema-profile-v1.json').read_bytes()))
        registry=ClosedSchemaRegistry.build(doc,bodies,c.profile,profile,c)
        self.assertEqual(len(doc['resources']),8)
        from tests.support.release_staging import expected_envelope,seal
        with StageFixture() as f:
            env=expected_envelope(f)
            diagnostic=seal({'schema_version':'1.0.0','request_id':'stage-plan','status':'rejected','phase':'plan','code':'input_invalid','checks':[],'refs':[],
                'capabilities':{'install-plan':'available','install-apply':'unavailable','stage':'unavailable','reopen-staged':'unavailable','release':'unavailable'},'next_route':'inspect-inputs'},'stage-diagnostic','diagnostic_digest')
            values={'stage-request':f.request,'stage-policy':f.stage,'installer-policy':f.installer,'stage-target-registry':f.registry,
                    'install-plan':env['plan'],'stage-context':env['stage_context'],'stage-plan-envelope':env,'stage-diagnostic':diagnostic}
            self.assertEqual(set(values),set(names))
            for kind,value in values.items():
                self.assertFalse(registry.validate('urn:gew:schema:'+kind+':1.0.0',value,context()),kind)
                self.assertTrue(registry.validate('urn:gew:schema:'+kind+':1.0.0',dict(value,extra=True),context()),kind)
                missing=dict(value);missing.pop('schema_version')
                self.assertTrue(registry.validate('urn:gew:schema:'+kind+':1.0.0',missing,context()),kind)
        bad=dict(bodies);bad.pop(next(iter(bad)))
        with self.assertRaises(ValueError):ClosedSchemaRegistry.build(doc,bad,c.profile,profile,context())
        bad=dict(bodies);bad['urn:gew:schema:unexpected:1.0.0']=next(iter(bodies.values()))
        with self.assertRaises(ValueError):ClosedSchemaRegistry.build(doc,bad,c.profile,profile,context())
        duplicate=copy.deepcopy(doc);duplicate['resources'].append(duplicate['resources'][0])
        with self.assertRaises(ValueError):ClosedSchemaRegistry.build(duplicate,bodies,c.profile,profile,context())

    def test_owned_source_wheel_policy_inputs(self):
        def unused_root(registry):
            candidate=registry['roots'][0]
            registry['roots'].append(dict(candidate,ref='skill',role='skill-bootstrap',path=str(Path(candidate['path']).parent/'old-state')))
        for installed in (False,True):
            with self.subTest(installed=installed),StageFixture(installed=installed,registry_patch=unused_root) as f:
                result=f.run("from graph_engineering.adapters.release_staging import InstalledStageInputs; x=InstalledStageInputs.open_owned(); assert len(x.resource_paths)==12; print(json.dumps({'count':len(x.resource_paths)}))")
                self.assertEqual(require_success(self,result)['count'],12)
                code="""import graph_engineering as g
from graph_engineering.adapters import release_staging as a
x=a.InstalledStageInputs.open_owned(); original=g._release_staging_resources; calls=[]
def changed(context):
 calls.append(True);return original(context)
g._release_staging_resources=changed
try:
 for operation in (x.require_current,a.InstalledStageInputs.open_owned):
  try:operation()
  except ValueError:pass
  else:raise AssertionError('substituted capture admitted')
finally:g._release_staging_resources=original
assert not calls
for module,name in ((a.admission,'_fresh_context'),(a.admission,'_origin_binding'),(a.admission,'_resource_native_binding'),(g,'_installation_owned_resources')):
 previous=getattr(module,name)
 def suspect(*args,**kwargs):calls.append(name);raise AssertionError('substituted provider invoked')
 setattr(module,name,suspect)
 try:
  try:a.InstalledStageInputs.open_owned()
  except ValueError:pass
  else:raise AssertionError('provider substitution admitted')
 finally:setattr(module,name,previous)
assert not calls
try:x.require_current()
except ValueError:pass
else:raise AssertionError('invalidated resource observation revived')
y=a.InstalledStageInputs.open_owned();assert len(y.resource_paths)==12
fake=object.__new__(a.InstalledStageInputs)
try:fake.require_current()
except ValueError:pass
else:raise AssertionError('copied resource trust accepted')
from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
request=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));owner=ReleaseInstaller()
for name in ('open_owned','documents','require_current'):
 previous=vars(a.InstalledStageInputs)[name]
 def suspect(*args,**kwargs):calls.append(name);raise ValueError('substituted provider invoked')
 setattr(a.InstalledStageInputs,name,classmethod(suspect) if name=='open_owned' else suspect)
 try:
  result=owner.plan(request,bundle);assert type(result) is dict and result['code'] in ('currentness','trust_rejected'),result;assert not calls
 finally:setattr(a.InstalledStageInputs,name,previous)
assert not calls
for name in ('__init__','to_dict','close'):
 previous=vars(a.PlanningSession)[name]
 def suspect(*args,**kwargs):calls.append(name);raise ValueError('substituted session invoked')
 setattr(a.PlanningSession,name,suspect)
 try:
  result=owner.plan(request,bundle);assert type(result) is dict and result['code'] in ('currentness','trust_rejected'),result;assert not calls
 finally:setattr(a.PlanningSession,name,previous)
# All A observation methods consumed by planning are sealed before acquisition
# and retained use. Keep the actual observation alive until method restoration.
from graph_engineering.application import release_staging as app
for name in ('to_dict','close'):
 previous=vars(a._RELEASE)[name]
 def suspect(*args,**kwargs):
  calls.append(name)
  return {'refs':[request['release_manifest_digest'],'sha256-jcs-v1:'+'0'*64]}
 retained=owner.plan(request,bundle);assert type(retained) is StagePlanEnvelope
 session=app._PLANS[retained][2]
 setattr(a._RELEASE,name,suspect)
 try:
  try:retained.to_dict()
  except ValueError:pass
  else:raise AssertionError('changed A observation provider admitted retained use')
  result=owner.plan(request,bundle);assert type(result) is dict and result['code'] in ('currentness','trust_rejected'),result
  assert not calls
 finally:setattr(a._RELEASE,name,previous)
 try:retained.require_current()
 except ValueError:pass
 else:raise AssertionError('invalidated A observation revived')
 del session
for cls,name in ((a._RELEASE,'_require_current'),(a._VERIFIER,'_check'),(a._READ,'snapshot'),(a._READ,'close'),(a._BUDGET,'charge')):
 previous=vars(cls)[name]
 def suspect(*args,**kwargs):calls.append(name);raise AssertionError('substituted A method invoked')
 setattr(cls,name,suspect)
 try:
  result=owner.plan(request,bundle);assert type(result) is dict and result['code'] in ('currentness','trust_rejected'),result;assert not calls
 finally:setattr(cls,name,previous)
restored=owner.plan(request,bundle);assert type(restored) is StagePlanEnvelope;assert restored.to_dict()==expected;restored.close()
print(json.dumps({'substituted_calls':len(calls)}))
"""
                prefix='expected=json.loads('+repr(json.dumps(expected_envelope(f)))+')\n'
                inputs,providers=code.split('from graph_engineering.application.release_staging import ReleaseInstaller',1)
                inputs+="print(json.dumps({'owned_inputs_refused':True}))\n"
                providers=prefix+"from graph_engineering.adapters import release_staging as a\ncalls=[]\nfrom graph_engineering.application.release_staging import ReleaseInstaller"+providers
                before=inventory(f.release.base)
                self.assertTrue(require_success(self,f.run(inputs,arguments=(f.request_path,f.release.bundle,f.release.manifest_path)))['owned_inputs_refused'])
                self.assertEqual(inventory(f.release.base),before)
                self.assertEqual(require_success(self,f.run(providers,arguments=(f.request_path,f.release.bundle,f.release.manifest_path)))['substituted_calls'],0)
                self.assertEqual(inventory(f.release.base),before)
                # The public port and retained plans seal the A input boundary too.
                admission_code='''from graph_engineering.application import release_staging as app
from graph_engineering.adapters import release_staging as a
request=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=app.BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]));owner=app.ReleaseInstaller();calls=[]
for name in json.loads(sys.argv[5]):
 cls=a.admission.InstalledReleaseInputs;previous=vars(cls)[name];retained=None
 if name in ('open_owned','limits','_document','require_current'):
  retained=owner.plan(request,bundle);assert type(retained) is app.StagePlanEnvelope,retained
 def suspect(*args,**kwargs):
  calls.append(name)
  if isinstance(previous,classmethod):return previous.__get__(None,cls)(*args[1:],**kwargs)
  if isinstance(previous,property):return previous.fget(*args,**kwargs)
  return previous(*args,**kwargs)
 replacement=classmethod(suspect) if isinstance(previous,classmethod) else (property(suspect) if isinstance(previous,property) else suspect)
 setattr(cls,name,replacement)
 try:
  result,exit_code=app.install_plan('install',pathlib.Path(sys.argv[2]),bundle)
  assert exit_code!=0 and result['code'] in ('currentness','trust_rejected'),result
  assert len(json.dumps(result).encode())<65536 and str(pathlib.Path(sys.argv[2]).parent) not in json.dumps(result)
  if retained is not None:
   try:retained.require_current()
   except ValueError:pass
   else:raise AssertionError('changed A input provider admitted retained use')
  result=owner.plan(request,bundle);assert type(result) is dict and result['code'] in ('currentness','trust_rejected'),result
  assert not calls
 finally:setattr(cls,name,previous)
 if retained is not None:
  try:retained.require_current()
  except ValueError:pass
  else:raise AssertionError('A input invalidation did not stick')
for name in ('_capture','_release_backend'):
 previous=getattr(a.admission,name)
 def suspect(*args,**kwargs):calls.append(name);return previous(*args,**kwargs)
 setattr(a.admission,name,suspect)
 try:
  result,exit_code=app.install_plan('install',pathlib.Path(sys.argv[2]),bundle)
  assert exit_code!=0 and result['code'] in ('currentness','trust_rejected'),result;assert not calls
 finally:setattr(a.admission,name,previous)
original=a.admission.InstalledReleaseInputs
class ReplacedInputs:
 @classmethod
 def open_owned(cls):calls.append('class');return original.open_owned()
a.admission.InstalledReleaseInputs=ReplacedInputs
try:
 result,exit_code=app.install_plan('install',pathlib.Path(sys.argv[2]),bundle)
 assert exit_code!=0 and result['code'] in ('currentness','trust_rejected'),result;assert not calls
finally:a.admission.InstalledReleaseInputs=original
restored,exit_code=app.install_plan('install',pathlib.Path(sys.argv[2]),bundle);assert exit_code==0 and restored==expected
print(json.dumps({'admission_substituted_calls':len(calls)}))
'''
                admission_code=prefix+admission_code
                for names in (('open_owned','limits'),('policy','trust','_document','require_current')):
                    self.assertEqual(require_success(self,f.run(admission_code,arguments=(f.request_path,f.release.bundle,f.release.manifest_path,json.dumps(names))))['admission_substituted_calls'],0)
                    self.assertEqual(inventory(f.release.base),before)



    def test_legacy_resource_closure_preserved(self):
        import tomllib
        from tests.support.source_checkout_attestation import SOURCE_FILES
        from tests.unit.test_wp00_packaging import assert_direct_script_contract
        configuration=tomllib.loads((ROOT/'pyproject.toml').read_text());mapping=configuration['tool']['gew']['build']['owned-root-files']
        legacy_names=('stage-request','install-plan','stage-context','stage-plan-envelope','stage-policy','installer-policy','stage-target-registry','stage-diagnostic')
        expected_legacy={'config/contracts/release-staging-schema-registry-v1.json'}|{'config/contracts/schemas/'+n+'-1.0.0.json' for n in legacy_names}|{'config/release-installation/'+n+'-v1.json' for n in ('stage-policy','installer-policy','stage-target-registry')}
        execution_names=('installed-release-manifest','installation-binding','stage-receipt','stage-generated-template','stage-execution-diagnostic','stage-execution-binding')
        execution_resources={'config/contracts/staging-execution-schema-registry-v1.json'}|{'config/contracts/schemas/'+n+'-1.0.0.json' for n in execution_names}
        selected={p for p in SOURCE_FILES if p.startswith('config/') and ('stage-' in p or 'staging-' in p or 'installer-policy' in p or '/install-plan-' in p)}
        resources=selected-execution_resources
        self.assertEqual(len(resources),12)
        self.assertEqual(resources,expected_legacy)
        self.assertEqual(set(SOURCE_FILES)&execution_resources,execution_resources)
        self.assertFalse(expected_legacy&execution_resources)
        for p in sorted(resources|execution_resources):self.assertEqual(mapping[p],'graph_engineering/'+p)
        for installed in (False,True):
            with StageFixture(installed=installed) as f:
                x=require_success(self,f.run("import graph_engineering as g;from graph_engineering.adapters.release_installation import _fresh_context; p,b=g._release_installation_resources(_fresh_context());expected=('release-policy','release-trust-registry','release-resource-policy');assert p[:3]==tuple('config/release-installation/'+x+'-v1.json' for x in expected);assert p[3]=='config/contracts/release-installation-schema-registry-v1.json';assert p[4:]==tuple('config/contracts/schemas/release-install-'+x+'-1.0.0.json' for x in ('manifest','artifact','policy','trust-registry','resource-policy','diagnostic','schema-registry'));print(json.dumps({'count':len(p)}))"))
                self.assertEqual(x['count'],11)
        assert_direct_script_contract(self,configuration)
        import hashlib
        def semantic(body,name):
            envelope={'algorithm':'sha-256','body':body,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0','contract_type':'urn:gew:contract:'+name,'digest_domain':'urn:gew:digest:semantic:1.0.0','projection_id':'urn:gew:digest-projection:'+name+':1.0.0','schema_id':'urn:gew:schema:'+name+'-input:1.0.0'}
            return 'sha256-jcs-v1:'+hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        project=(ROOT/'pyproject.toml').read_text()
        for path,name,closure,kind in (
            ('migration/migration-rehearsal','migration-rehearsal-installation-bootstrap','migration-rehearsal-protected-resource-closure','source'),
            ('profiles/scenario-truth','scenario-truth-installation-bootstrap','scenario-truth-protected-closure','path'),
            ('release-operations/release-operations','release-operations-installation-bootstrap','release-operations-protected-closure','release'),
            ('performance/performance-benchmark','performance-benchmark-installation-bootstrap','performance-protected-resource-closure','source')):
            raw=(ROOT/('config/'+path+'-installation-bootstrap-v1.json')).read_bytes();doc=json.loads(raw)
            for row in doc['protected_resources']:
                key='source' if kind=='source' else 'path';self.assertEqual(row['raw_sha256'],hashlib.sha256((ROOT/row[key]).read_bytes()).hexdigest())
            body={'schema_version':'1.0.0','resources':doc['protected_resources']} if kind=='release' else {('protected_resources' if kind=='path' else 'resources'):doc['protected_resources']}
            self.assertEqual(doc['protected_closure_digest'],semantic(body,closure))
            self.assertEqual(doc['bootstrap_digest'],semantic({k:v for k,v in doc.items() if k!='bootstrap_digest'},name))
            self.assertIn(doc['bootstrap_digest'],project);self.assertIn(hashlib.sha256(raw).hexdigest(),project)
