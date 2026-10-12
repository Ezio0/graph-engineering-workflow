"""Actual local bundle and read-only command journeys, with private attested trust."""
import copy
import json
import unittest
from tests.support.release_installation import (ReleaseFixture,fixture,physical_wheel,reseal,
    write_json,json_bytes,inventory,require_success,ROOT)


class ReleaseInstallationIntegrationTests(unittest.TestCase):
    def test_valid_physical_bundle(self):
        with ReleaseFixture() as f:
            before=inventory(f.bundle);result=require_success(self,f.check())
            self.assertEqual(result['status'],'preflight-valid');self.assertEqual(result['code'],'ok')
            self.assertEqual(result['capabilities']['install'],'unavailable');self.assertEqual(inventory(f.bundle),before)
            self.assertEqual(require_success(self,f.check())['diagnostic_digest'],result['diagnostic_digest'])
            f.value['skills'][0]['protocol_range']='>=9.0.0,<10.0.0';f.sign()
            self.assertNotEqual(f.check().returncode,0)

    def test_missing_extra_dependency(self):
        with ReleaseFixture() as baseline:require_success(self,baseline.check())
        for installed in (False,True):
            for constraint,accepted in [('>=3.12,<3.13',True),('>=3.13',False),('not a constraint',False),(None,True),(['>=3.12','>=3.12'],False)]:
                with self.subTest(installed=installed,constraint=constraint),ReleaseFixture(installed=installed) as f:
                    f.replace('core',physical_wheel(fixture()['runtime_distributions'][0],requires_python=constraint));f.refresh_closure()
                    before=inventory(f.base);result=f.cli(['release-check','--bundle',f.bundle,'--manifest',f.manifest_path,'--format','json'])
                    self.assertEqual(result.returncode==0,accepted,result.stderr+result.stdout)
                    self.assertEqual(result.stderr,'');self.assertEqual(inventory(f.base),before)
        # Runtime names must use each function's actual globals/builtins, including
        # hidden IMPORT_NAME dispatch. Exercise both physical installation modes.
        for installed in (False,True):
            with ReleaseFixture(installed=installed) as f:
                import shutil
                saved={p.name:p.read_bytes() for p in f.bundle.iterdir()}
                f.replace('core',physical_wheel(fixture()['runtime_distributions'][0],requires_python='>=3.13rc1'));f.refresh_closure()
                incompatible=f.base/'shadow-incompatible';shutil.copytree(f.bundle,incompatible)
                for name,body in saved.items():(f.bundle/name).write_bytes(body)
                before=inventory(f.base)
                code='''from graph_engineering.adapters import release_installation as a
from graph_engineering.application.cli import main
import packaging,packaging.utils as u,packaging.specifiers as s,contextlib,io,hashlib,types
from unittest.mock import patch
root=pathlib.Path(sys.argv[2]);manifest=pathlib.Path(sys.argv[3]);bad=pathlib.Path(sys.argv[4])
args=['release-check','--bundle',str(root),'--manifest',str(manifest),'--format','json']
bad_args=['release-check','--bundle',str(bad),'--manifest',str(bad/'release.json'),'--format','json']
def command(arguments,expected):
 output=io.StringIO()
 with contextlib.redirect_stdout(output):status=main(arguments)
 body=output.getvalue();assert status==expected,(status,expected)
 assert len(body.encode())<=(1024 if expected else 65536)
 assert str(root.parent) not in body and 'shadow-must-not-execute' not in body
 value=json.loads(body);claimed=value.pop('diagnostic_digest')
 envelope={'algorithm':'sha-256','body':value,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
  'contract_type':'urn:gew:contract:release-install-diagnostic','digest_domain':'urn:gew:digest:semantic:1.0.0',
  'projection_id':'urn:gew:digest-projection:release-install-diagnostic:1.0.0','schema_id':'urn:gew:schema:release-install-diagnostic:1.0.0'}
 assert claimed=='sha256-jcs-v1:'+hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
command(args,0);command(bad_args,4)
backend=a._release_backend();calls=0
def shadow(*args,**kwargs):
 global calls
 calls+=1;raise AssertionError('shadow-must-not-execute')
class Key:
 def __init__(self,name):self.name=name
 def __hash__(self):return hash(self.name)
 def __eq__(self,other):
  global calls
  calls+=1;return False
class ModuleName:
 def __hash__(self):
  global calls
  calls+=1;return hash('packaging.utils')
 def __eq__(self,other):
  global calls
  calls+=1;return True
@contextlib.contextmanager
def malformed(namespace,field):
 saved=namespace.pop(field);key=Key(field);namespace[key]=saved
 try:yield
 finally:namespace.pop(key);namespace[field]=saved
key=Key('isinstance')
original=s.SpecifierSet.to_range;namespace=original.__globals__;saved_builtins=namespace['__builtins__']
try:
 namespace['__builtins__']=dict(original.__builtins__,__import__=shadow)
 copied=types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__,original.__closure__)
 copied.__kwdefaults__=original.__kwdefaults__;copied.__annotations__=dict(original.__annotations__)
finally:namespace['__builtins__']=saved_builtins
for index,attack in enumerate((malformed(vars(packaging),'requirements'),malformed(vars(u.__spec__),'origin'),patch.object(u,'__name__',ModuleName()),patch.object(u,'isinstance',shadow,create=True),patch.object(u,'isinstance',NotImplemented,create=True),patch.dict(vars(u),{key:None}),patch.object(s.SpecifierSet,'to_range',copied))):
 # The required global-shadow journey retains a full physical observation.
 # Other lookup boundaries exercise the same owned currentness capability.
 observation=a.LocalReleaseVerifier().check(root,manifest) if index==3 else backend['_owned_constraint_provider']()
 with attack:
  try:backend['_owned_constraint_provider']()
  except ValueError:pass
  else:raise AssertionError('effective callable shadow admitted')
  command(args,4)
  try:observation.require_current()
  except ValueError:pass
  else:raise AssertionError('retained observation accepted effective callable shadow')
 try:observation.require_current()
 except ValueError:pass
 else:raise AssertionError('invalidated observation rehabilitated')
 assert calls==0,'substituted binding executed'
 p=backend['_owned_constraint_provider']();assert p.requires_python('3.12.12','>=3.12')
 assert p.requires_python('3.12.12','>=3.13rc1') is False;p.close()
command(args,0);command(bad_args,4)
# An added global that resolves to the genuine builtin has identical semantics.
with patch.object(u,'isinstance',isinstance,create=True):
 p=backend['_owned_constraint_provider']();p.require_current();p.close()
assert calls==0
'''
                result=f.run(code,arguments=(f.bundle,f.manifest_path,incompatible))
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,'')
                self.assertEqual(result.stdout,'');self.assertEqual(inventory(f.base),before)
        for change in ('metadata','omission','extra','unreachable'):
            with ReleaseFixture() as f:
                if change=='metadata':f.replace('crypto',physical_wheel(fixture()['runtime_distributions'][1],requirements=['unlisted==1.0.0']))
                elif change=='omission':(f.bundle/f.row('cffi')['relative_path']).unlink()
                elif change=='extra':(f.bundle/'extra.whl').write_bytes(b'extra')
                else:
                    f.value['dependencies']=[e for e in f.value['dependencies'] if e['child_artifact_id']!='cffi'];f.sign()
                self.assertNotEqual(f.check().returncode,0,change)

    def test_lock_sbom_provenance(self):
        with ReleaseFixture() as baseline:
            require_success(self,baseline.check())
            code='import runpy;scope=runpy.run_path(sys.argv[2]);raise SystemExit(scope["main"](["release-inputs","--bundle",sys.argv[3],"--manifest",sys.argv[4]]))'
            result=baseline.run(code,arguments=(ROOT/'scripts/verify_supply_chain.py',baseline.bundle,baseline.manifest_path))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['code'],'ok')
        for ident,change in [('lock','empty'),('lock','product-lock'),('sbom','extra'),('provenance','subject')]:
            with ReleaseFixture() as f:
                value=json.loads((f.bundle/f.row(ident)['relative_path']).read_bytes())
                if change=='product-lock':body=(ROOT/'uv.lock').read_bytes()
                else:
                    if change=='empty':value['components']=[]
                    elif change=='extra':value['components'].append(dict(value['components'][0],artifact_id='extra'))
                    else:value['subjects'][0]['raw_sha256']='0'*64
                    value=reseal(value,ident,{'lock':'export_digest','sbom':'sbom_digest','provenance':'provenance_digest'}[ident]);body=json_bytes(value)
                f.replace(ident,body);self.assertNotEqual(f.check().returncode,0,(ident,change))

    def test_license_security_freshness(self):
        with ReleaseFixture() as baseline:require_success(self,baseline.check())
        for change in ('license','source','expired','future','unknown','missing','subject','policy','signature'):
            with ReleaseFixture() as f:
                if change in ('license','source'):
                    f.row('core')['license_ids']=['Forbidden'] if change=='license' else f.row('core')['license_ids']
                    if change=='source':f.row('core')['source_id']='unknown'
                elif change=='missing':(f.bundle/f.row('security')['relative_path']).unlink()
                else:
                    if change=='expired':f.security['expires_at']=f.security['issued_at']-1
                    elif change=='future':f.security['issued_at']+=10000;f.security['expires_at']+=10000
                    elif change=='unknown':f.security['verdict']='UNKNOWN'
                    elif change=='subject':f.security['subjects'][0]['raw_sha256']='0'*64
                    elif change=='policy':f.security['policy_digest']='sha256-jcs-v1:'+'0'*64
                    f.sign_security()
                    if change=='signature':f.security['signature']='0'*128;f.replace('security',json_bytes(f.security),sign=False)
                f.sign();self.assertNotEqual(f.check().returncode,0,change)

    def test_doctor_zero_writes(self):
        import sqlite3
        with ReleaseFixture() as f:
            root=f.base/'installation';root.mkdir(mode=0o700)
            database=root/'task-state.sqlite3'
            with sqlite3.connect(database) as c:
                c.execute('CREATE TABLE task_events(id INTEGER,body TEXT)');c.execute("INSERT INTO task_events VALUES(1,'synthetic')")
                c.execute('CREATE TABLE clock_state(clock_high_water_ns INTEGER)');c.execute('INSERT INTO clock_state VALUES(1)')
            before=inventory(root);source_before=inventory(f.source);control_before=inventory(f.control)
            result=f.cli(['doctor','--installation',root,'--format','json']);self.assertEqual(result.returncode,3,result.stderr)
            self.assertEqual(json.loads(result.stdout)['code'],'phase_unavailable')
            self.assertEqual(inventory(root),before);self.assertEqual(inventory(f.source),source_before);self.assertEqual(inventory(f.control),control_before)

    def test_missing_root_no_create(self):
        with ReleaseFixture() as f:
            root=f.base/'missing-installation';before=inventory(f.base)
            result=f.cli(['doctor','--installation',root,'--format','json']);self.assertEqual(result.returncode,3,result.stderr)
            self.assertFalse(root.exists());self.assertEqual(inventory(f.base),before)
            self.assertEqual(json.loads(result.stdout)['capabilities']['upgrade'],'unavailable')

    def test_cli_exit_routes(self):
        with ReleaseFixture() as f:
            args=['release-check','--bundle',f.bundle,'--manifest',f.manifest_path,'--format','json']
            result=f.cli(args);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['code'],'ok')
            f.manifest_path.write_bytes(b'{"secret":"invalid')
            result=f.cli(args);self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['code'],'input_invalid')
            f.sign();f.value['signature']='0'*128;write_json(f.manifest_path,f.value)
            result=f.cli(args);self.assertEqual(result.returncode,4);self.assertEqual(json.loads(result.stdout)['code'],'trust_rejected')
            result=f.cli(['doctor','--format','json']);self.assertEqual(result.returncode,3);self.assertEqual(json.loads(result.stdout)['status'],'blocked')
            self.assertEqual(f.cli(['install-apply','--format','json']).returncode,2)

    def test_no_ambient_config_artifact_execution(self):
        with ReleaseFixture() as f:
            ambient=f.base/'ambient';ambient.mkdir();(ambient/'release-policy-v1.json').write_bytes(b'poison')
            canary=f.base/'EXECUTED'
            for name in ('python','uv','pip','curl'):
                p=ambient/name;p.write_text('#!/bin/sh\ntouch '+str(canary)+'\nexit 99\n');p.chmod(0o700)
            before=inventory(f.bundle)
            result=require_success(self,f.check(extra_env={'PATH':str(ambient),'PIP_INDEX_URL':'https://invalid.example/poison','UV_INDEX_URL':'https://invalid.example/poison','GEW_RELEASE_POLICY':str(ambient/'release-policy-v1.json')}))
            self.assertEqual(result['code'],'ok');self.assertFalse(canary.exists());self.assertEqual(inventory(f.bundle),before)
