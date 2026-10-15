"""Owned approval resource contracts and retained trust closures."""
import hashlib
import json
import unittest
from tests.support.installation_authority import ApprovalFixture
from tests.support.release_staging import ROOT,context,require_success

class InstallationAuthorityContractTests(unittest.TestCase):
    def test_schema_registry_closure(self):
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy
        from tests.unit.test_installation_authority import policy,challenge
        from graph_engineering.core.installation_authority import diagnostic
        c=context();root=ROOT/'config/contracts';paths=sorted((root/'schemas').glob('installation-approval-*-1.0.0.json'))
        self.assertEqual(len(paths),3);bodies={json.loads(p.read_bytes())['$id']:p.read_bytes() for p in paths}
        registry=json.loads((root/'installation-approval-schema-registry-v1.json').read_bytes())
        r=ClosedSchemaRegistry.build(registry,bodies,c.profile,SchemaProfilePolicy.from_dict(json.loads((root/'schema-profile-v1.json').read_bytes())),c)
        for name,v in [('policy',policy()),('challenge',challenge()),('diagnostic',diagnostic('authority_issued',c))]:
            sid='urn:gew:schema:installation-approval-'+name+':1.0.0'
            self.assertFalse(r.validate(sid,v,c));self.assertTrue(r.validate(sid,dict(v,extra=True),c))
        for row in registry['resources']:self.assertEqual(row['body_digest'],'sha256-raw-v1:'+hashlib.sha256(bodies[row['schema_id']]).hexdigest())
        with self.assertRaises(ValueError):ClosedSchemaRegistry.build(registry,dict(list(bodies.items())[:-1]),c.profile,SchemaProfilePolicy.from_dict(json.loads((root/'schema-profile-v1.json').read_bytes())),c)

        import copy
        profile=SchemaProfilePolicy.from_dict(json.loads((root/'schema-profile-v1.json').read_bytes()))
        for change in ('duplicate','digest','unknown'):
            bad=copy.deepcopy(registry)
            if change=='duplicate':bad['resources'].append(copy.deepcopy(bad['resources'][0]))
            elif change=='digest':bad['resources'][0]['body_digest']='sha256-raw-v1:'+'0'*64
            else:bad['resources'][0]['unknown']=True
            with self.assertRaises(ValueError):ClosedSchemaRegistry.build(bad,bodies,c.profile,profile,c)

    def test_owned_source_wheel_inputs(self):
        for installed in (False,True):
            with self.subTest(installed=installed),ApprovalFixture(installed=installed) as f:
                code='''from graph_engineering.application import release_staging
from graph_engineering.adapters import installation_authority as a
with a._RECORD_OP():
 c,p,b=a._capture();assert p['max_wait_seconds']==15
 paths=a._RESOURCES;root=pathlib.Path(sys.argv[5]);count=0;missing=0;record_refused=0
 for name in paths:
  file=root/name;saved=file.read_bytes();file.write_bytes(saved+b' ')
  try:a._capture()
  except (ValueError,RuntimeError):count+=1
  else:raise AssertionError('mutated input accepted')
  finally:file.write_bytes(saved)
  a._capture()
  backup=file.with_name(file.name+'.missing-backup');file.rename(backup)
  try:a._capture()
  except (ValueError,RuntimeError,OSError):missing+=1
  else:raise AssertionError('missing owned input accepted')
  finally:backup.rename(file)
  a._capture()
 if root.name=='graph_engineering':
  record=next(root.parent.glob('graph_engineering_workflow-*.dist-info/RECORD'));saved=record.read_bytes()
  duplicate=next(row for row in saved.splitlines() if row.startswith(b'graph_engineering/config/release-installation/installation-approval-policy-v1.json,'))
  record.write_bytes(saved+duplicate+b'\\n')
  try:a._capture()
  except (ValueError,RuntimeError,OSError):record_refused=1
  else:raise AssertionError('duplicate RECORD metadata accepted')
  finally:record.write_bytes(saved)
  a._capture()
print(json.dumps({'inputs':len(paths),'refused':count,'missing':missing,'record_refused':record_refused}))
'''
                root=f.release.product_root if installed else f.release.source
                value=require_success(self,f.run(code,arguments=(f.request_path,f.release.bundle,f.release.manifest_path,root)))
                self.assertEqual(value,{'inputs':5,'refused':5,'missing':5,'record_refused':int(installed)})

    def test_legacy_resources_and_origin(self):
        with ApprovalFixture() as f:
            code='''from graph_engineering.application import release_staging
from graph_engineering.adapters import release_staging as s,installation_authority as a
import graph_engineering as installation
c=s._CONTEXT();before=s._LOAD(c);old=installation._release_installation_resources(c)
a._capture()
assert before==s._LOAD(c) and old==installation._release_installation_resources(c)
assert len(before[0])==12 and len(old[0])==11
try:s.PlanningApprovalContext().require_current()
except (ValueError,TypeError):pass
else:raise AssertionError('unowned context')
try:a.ApprovalSession({'owner_id':'0'})
except ValueError:pass
else:raise AssertionError('caller context admitted')
print(json.dumps({'legacy_stage':len(before[0]),'legacy_release':len(old[0])}))
'''
            value=require_success(self,f.plan(code));self.assertEqual(value,{'legacy_stage':12,'legacy_release':11})
