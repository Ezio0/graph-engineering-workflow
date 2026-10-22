"""Owned SOURCE/WHEEL admission and independent actual installed-byte oracles."""
import base64
import csv
import hashlib
import io
import json
import os
import posixpath
import unittest
from tests.support.staging_execution import ExecutionFixture,ROOT,success,require_success,native_helper,inventory,admitted_members,reopen_rejection,standalone_template_fault,standalone_reader_fault
from tests.support.release_staging import context,seal,write_json,stage_framed

class StagingExecutionContractTests(unittest.TestCase):
    def test_owned_execution_source_wheel_inputs(self):
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy
        names=('installed-release-manifest','installation-binding','stage-receipt','stage-execution-binding','stage-generated-template','stage-execution-diagnostic')
        bodies={('urn:gew:schema:'+n+':1.0.0'):(ROOT/('config/contracts/schemas/'+n+'-1.0.0.json')).read_bytes() for n in names}
        doc=json.loads((ROOT/'config/contracts/staging-execution-schema-registry-v1.json').read_bytes());c=context()
        reg=ClosedSchemaRegistry.build(doc,bodies,c.profile,SchemaProfilePolicy.from_dict(json.loads((ROOT/'config/contracts/schema-profile-v1.json').read_bytes())),c)
        self.assertEqual(len(doc['resources']),6)
        for name in names:self.assertTrue(reg.validate('urn:gew:schema:'+name+':1.0.0',{'schema_version':'1.0.0','unknown':True},context()))
        helper=native_helper()
        # JSON Unicode escapes preserve parsed fields and the semantic template
        # digest, while the release signature still binds the different raw bytes.
        for installed in (False,True):
            with self.subTest(installed=installed,encoding='escaped-template-keys'),ExecutionFixture(installed=installed,helper=helper) as f:
                original=(f.release.bundle/'template-0.json').read_bytes();document=json.loads(original)
                escaped=original.replace(b'"logical_path"',b'"'+bytes((92,))+b'u006cogical_path"').replace(b'"template_digest"',b'"'+bytes((92,))+b'u0074emplate_digest"')
                self.assertNotIn(b'"logical_path"',escaped);self.assertNotIn(b'"template_digest"',escaped)
                self.assertEqual(json.loads(escaped),document);self.assertNotEqual(hashlib.sha256(original).hexdigest(),hashlib.sha256(escaped).hexdigest())
                self.assertEqual(stage_framed('stage-generated-template',{k:v for k,v in document.items() if k!='template_digest'})[1],document['template_digest'])
                f.release.replace('template-0',escaped,sign=False);f.release.refresh_closure();f.request['release_manifest_digest']=f.release.value['manifest_digest'];write_json(f.request_path,f.request)
                self.assertEqual(f.release.row('template-0')['raw_sha256'],hashlib.sha256(escaped).hexdigest())
                before_plan=inventory(f.release.base)
                admitted=require_success(self,f.release.run("from graph_engineering.adapters.release_installation import LocalReleaseVerifier; o=LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));o.require_current();print(json.dumps({'digests':sorted(t['template_digest'] for t in o._templates)}));o.close()",arguments=(f.release.bundle,f.release.manifest_path)))
                self.assertIn(document['template_digest'],admitted['digests'])
                result=require_success(self,f.plan());self.assertIn('envelope_digest',result);self.assertFalse(list(f.candidates.iterdir()));self.assertEqual(inventory(f.release.base),before_plan)
                for raw in (b'unsupported build input',b'{}'):
                    f.release.replace('template-0',raw,sign=False);f.release.refresh_closure();f.request['release_manifest_digest']=f.release.value['manifest_digest'];write_json(f.request_path,f.request)
                    checked=f.release.check();self.assertNotEqual(checked.returncode,0);self.assertEqual(json.loads(checked.stdout)['code'],'phase_unavailable')
                    self.assertEqual(require_success(self,f.plan())['code'],'phase_unavailable');self.assertFalse(list(f.candidates.iterdir()))
        for installed in (False,True):
            with self.subTest(installed=installed),ExecutionFixture(installed=installed,helper=helper) as f:
                env=require_success(self,f.plan());self.assertIn('envelope_digest',env);self.assertFalse(list(f.candidates.iterdir()))
                result=f.run("from graph_engineering.adapters.staging_execution import owned_inputs; registry,binding=owned_inputs();print(json.dumps({'count':len(registry._resources)}))")
                self.assertEqual(require_success(self,result)['count'],6)
                for attack in ('parser-alias','parser-code','parser-binding','loader-alias','retained','retained-dict'):
                    result=f.release.run('\n'+standalone_template_fault(attack),arguments=(f.release.bundle,f.release.manifest_path))
                    self.assertEqual(require_success(self,result),{'zero_calls':0,'fresh_restored':True})
                for route in ('admission','retained','doctor'):
                    for attack in ('descriptor','code'):
                        result=f.release.run('\n'+standalone_reader_fault(attack,route),arguments=(f.release.bundle,f.release.manifest_path))
                        self.assertEqual(require_success(self,result),{'zero_calls':0,'descriptors_closed':True,'fresh_restored':True})
                for attack in ('parser-binding','loader-alias'):
                    result=f.release.run('\n'+standalone_template_fault(attack,route='application'),arguments=(f.release.bundle,f.release.manifest_path))
                    self.assertEqual(require_success(self,result),{'zero_calls':0,'fresh_restored':True})
        with ExecutionFixture(helper=helper) as f:
            p=f.release.bundle/'template-0.json';v=json.loads(p.read_bytes());v['unknown']=True;f.release.replace('template-0',json.dumps(v).encode(),sign=False);f.release.refresh_closure();f.request['release_manifest_digest']=f.release.value['manifest_digest'];write_json(f.request_path,f.request)
            result=require_success(self,f.plan());self.assertEqual(result['code'],'input_invalid');self.assertFalse(list(f.candidates.iterdir()))

    def test_installed_inventory_and_record_oracle(self):
        with ExecutionFixture() as f:
            expected,expected_directories,expected_owners=admitted_members(f)
            success(self,f);root=next(f.candidates.iterdir());site=root/'payload/tool/lib/python3.12/site-packages'
            manifest=json.loads((root/'metadata/installed-manifest.json').read_bytes());binding=json.loads((root/'metadata/binding.json').read_bytes())
            receipt=json.loads((root/'metadata/receipt.json').read_bytes());origin=json.loads((root/'metadata/execution-binding.json').read_bytes())
            for kind,record,field in [('installed-release-manifest',manifest,'installed_manifest_digest'),('installation-binding',binding,'binding_digest'),('stage-receipt',receipt,'receipt_digest'),('stage-execution-binding',origin,'execution_binding_digest')]:
                self.assertEqual(record[field],stage_framed(kind,{k:v for k,v in record.items() if k!=field})[1])
            self.assertEqual(receipt['execution_binding_digest'],origin['execution_binding_digest'])
            self.assertEqual(receipt['installed_manifest_digest'],manifest['installed_manifest_digest']);self.assertEqual(receipt['binding_digest'],binding['binding_digest'])
            actual={p.relative_to(root).as_posix():p for p in (root/'payload').rglob('*')}
            self.assertEqual(set(actual)|{'payload'},set(expected)|expected_directories)
            for name,body in expected.items():
                if body is not None:self.assertEqual((root/name).read_bytes(),body)
            refs={'interpreter':str(root/'payload/interpreter'/f.release.value['interpreter']['executable_member']),'tool':str(root/'payload/tool')}
            for template in f.templates:
                if template['kind']!='RECORD':self.assertEqual((root/template['logical_path']).read_bytes(),''.join(s['literal'] if 'literal' in s else refs[s['ref']] for s in template['segments']).encode())
            self.assertEqual(set(actual)|{'payload'},set(r['logical_path'] for r in binding['files']))
            for row in binding['files']:
                path=root/row['logical_path'];st=os.lstat(path);self.assertEqual(row['physical_identity']['inode'],str(st.st_ino));self.assertEqual(row['mode'],st.st_mode&0o777)
                if path.is_file():self.assertEqual(row['raw_sha256'],hashlib.sha256(path.read_bytes()).hexdigest());self.assertEqual(row['size_bytes'],st.st_size)
            templates={v['logical_path']:v for v in f.templates}
            for dist in manifest['distributions']:
                record_path=next(site.glob(dist['name'].replace('-','_')+'-'+dist['version']+'.dist-info/RECORD'))
                logical=[];rows=list(csv.reader(io.StringIO(record_path.read_text())));seen=set()
                for name,cell,size in rows:
                    mapped=posixpath.normpath(posixpath.join(site.relative_to(root).as_posix(),name));self.assertNotIn(mapped,seen);seen.add(mapped)
                    self.assertTrue(mapped.startswith('payload/tool/'));body=(root/mapped).read_bytes()
                    if mapped==record_path.relative_to(root).as_posix():self.assertEqual((cell,size),('',''));logical.append([mapped,'','']);continue
                    encoded='sha256='+base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode()
                    self.assertEqual((cell,size),(encoded,str(len(body))))
                    if mapped in templates:body=json.dumps(templates[mapped]['segments'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
                    logical.append([mapped,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode(),str(len(body))])
                self.assertEqual(dist['installed_record_digest'],stage_framed('installed-record',sorted(logical))[1])
                self.assertEqual(seen,expected_owners[dist['name']])
        with ExecutionFixture(installed=True) as f:
            success(self,f)
            for filename in ('installed-manifest.json','binding.json','execution-binding.json','receipt.json'):
                for mutation in ('missing','malformed'):reopen_rejection(self,f,filename,mutation)
