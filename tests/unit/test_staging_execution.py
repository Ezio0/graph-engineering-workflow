"""Independent semantic oracles for the isolated stage contracts."""
import copy
import importlib
import json
import unittest
from tests.support.release_staging import context,seal,stage_framed

def core():return importlib.import_module('graph_engineering.core.staging_execution')

def template(path='payload/tool/bin/demo',segments=None,kind='script'):
    return seal({'schema_version':'1.0.0','logical_path':path,'kind':kind,
        'segments':[{'literal':'#!'},{'ref':'interpreter'},{'literal':'\n'}] if segments is None else segments},'stage-generated-template','template_digest')

class StagingExecutionUnitTests(unittest.TestCase):
    def test_closed_stage_records(self):
        c=core();d='sha256-jcs-v1:'+'a'*64
        body={'schema_version':'1.0.0','installation_id':'private-test','request_id':'request','operation':'install',
            'plan_digest':d,'stage_context_digest':d,'envelope_digest':d,'challenge_digest':d}
        v=seal(body,'stage-execution-binding','execution_binding_digest')
        self.assertEqual(c.validate_record('stage-execution-binding',v,context()),v)
        self.assertEqual(v['execution_binding_digest'],stage_framed('stage-execution-binding',body)[1])
        for k in v:
            bad=dict(v);bad.pop(k)
            with self.assertRaises(ValueError):c.validate_record('stage-execution-binding',bad,context())
        for update in ({'extra':True},{'operation':'upgrade'},{'schema_version':'2.0.0'},{'challenge_digest':d.replace('a','b')}):
            with self.assertRaises(ValueError):c.validate_record('stage-execution-binding',dict(v,**update),context())
        result=c.diagnostic('staged','request',context())
        self.assertEqual(result['status'],'staged');self.assertEqual(result['capabilities']['install-apply'],'stage-only')
        self.assertEqual(result['capabilities']['release'],'unavailable')
        for kind in c.RECORD_FIELDS:
            with self.assertRaises(ValueError):c.validate_record(kind,{},context())

        ancestor={'device':'1','inode':'2','mode':0o700,'owner_id':'3'}
        physical={'device':'1','inode':'4','owner_id':'3','mtime_ns':'5','ctime_ns':'6','ancestors':[ancestor]}
        executable={'logical_path':'payload/interpreter/bin/python','raw_sha256':'b'*64,'size_bytes':1,'mode':0o700,'physical_identity':physical}
        cases={
            'installed-release-manifest':{'schema_version':'1.0.0','release_id':'release','platform':{'os':'linux','architecture':'x86_64','python_abi':'cp312'},'interpreter_identity':{'artifact_id':'python','implementation':'cpython','patch':'3.12.12','build_id':'build','executable_member':'bin/python'},'distributions':[{'name':'demo','version':'1.0','wheel_sha256':'c'*64,'installed_record_digest':d}],'skills':[],**{k:d for k in ('lock_digest','sbom_digest','security_evidence_digest','policy_digest')}},
            'installation-binding':{'schema_version':'1.0.0','installation_id':'private','request_id':'request','plan_digest':d,'stage_context_digest':d,'candidate_identity':ancestor,'interpreter_binding':executable,'installer_binding':dict(executable,logical_path='payload/installer/bin/uv'),'files':[dict(executable,kind='file')]},
            'stage-receipt':{'schema_version':'1.0.0','request_id':'request','status':'staged',**{k:d for k in ('plan_digest','release_manifest_digest','stage_context_digest','installed_manifest_digest','binding_digest','execution_binding_digest')}},
            'stage-generated-template':{k:v for k,v in template().items() if k!='template_digest'},
            'stage-execution-diagnostic':{k:v for k,v in result.items() if k!='diagnostic_digest'},
        }
        for kind,body in cases.items():
            field=c.DIGEST_FIELDS[kind];valid=seal(body,kind,field)
            self.assertEqual(c.validate_record(kind,valid,context()),valid)
            self.assertEqual(valid[field],stage_framed(kind,body)[1])
            for key in valid:
                bad=copy.deepcopy(valid);bad.pop(key)
                with self.subTest(kind=kind,missing=key),self.assertRaises(ValueError):c.validate_record(kind,bad,context())
            for key in body:
                bad=seal(dict(body,**{key:False}),kind,field)
                with self.subTest(kind=kind,wrong_type=key),self.assertRaises(ValueError):c.validate_record(kind,bad,context())
            for bad in (dict(valid,unknown=True),dict(valid,**{field:'sha256-jcs-v1:'+'0'*64})):
                with self.assertRaises(ValueError):c.validate_record(kind,bad,context())
        for fact in ('inode','owner_id','mtime_ns','ctime_ns'):
            bad=copy.deepcopy(cases['installation-binding']);bad['interpreter_binding']['physical_identity'][fact]='-1'
            with self.assertRaises(ValueError):c.validate_record('installation-binding',seal(bad,'installation-binding','binding_digest'),context())

    def test_template_normalization_projection(self):
        c=core();v=template();c.validate_template(v,context())
        a={'interpreter':'/private/short/python','tool':'/private/short/tool'}
        b={'interpreter':'/private/a-much-longer-prefix/python','tool':'/private/long/tool'}
        raw=c.expand_template(v,a,context())
        normalized=c.normalize_template(v,raw,a,context())
        expected=b'[{"literal":"#!"},{"ref":"interpreter"},{"literal":"\\n"}]'
        self.assertEqual(normalized,expected);self.assertEqual(len(expected),57)
        self.assertEqual(c.record_hash(expected),'sha256=vXODppfqd9WEMtoWQEny_BLT1YV93YRHLHosQu5nZH0')
        self.assertEqual(c.normalize_template(v,c.expand_template(v,b,context()),b,context()),expected)
        unicode_refs={'interpreter':'/private/中文/interpreter/python','tool':'/private/中文/tool'}
        self.assertEqual(c.expand_template(v,unicode_refs,context()),('#!'+unicode_refs['interpreter']+'\n').encode())
        self.assertEqual(c.normalize_template(v,c.expand_template(v,unicode_refs,context()),unicode_refs,context()),expected)
        with self.assertRaises(ValueError):c.normalize_template(v,raw+b'x',a,context())
        literal=template(segments=[{'literal':'prefix ${interpreter} /private/short/python\n'}])
        self.assertEqual(c.expand_template(literal,a,context()),b'prefix ${interpreter} /private/short/python\n')
        for segments in ([{'ref':'unknown'}],[{'literal':''}],[{'literal':'bad\x00'}],[{'ref':'interpreter','literal':'bad'}],[{'literal':'non-ascii-\u00e9'}],[]):
            with self.assertRaises(ValueError):c.validate_template(template(segments=segments),context())
        c.validate_template(template('payload/tool/x.dist-info/REQUESTED',[],kind='script'),context())
        c.validate_template(template('payload/tool/x.dist-info/RECORD',[],kind='RECORD'),context())

    def test_expected_wheel_membership(self):
        c=core();site='payload/tool/lib/python3.12/site-packages';dist='demo-1.0.dist-info'
        table=c.map_wheel_members('demo','1.0','3.12.12',[dist+'/METADATA',dist+'/WHEEL',dist+'/RECORD','demo/x.py','demo-1.0.data/purelib/ns/x.py','demo-1.0.data/scripts/demo'],context())
        self.assertEqual(table['demo-1.0.data/scripts/demo'],'payload/tool/bin/demo')
        self.assertEqual(table['demo-1.0.data/purelib/ns/x.py'],site+'/ns/x.py')
        self.assertEqual(c.record_path(site,table['demo-1.0.data/scripts/demo']),'../../../bin/demo')
        for members in ([dist+'/RECORD','demo/x.py','demo-1.0.data/purelib/demo/x.py'],[dist+'/RECORD','Demo/x.py','demo/x.py'],
            [dist+'/RECORD','x','x/y'],[dist+'/RECORD','../escape'],[dist+'/RECORD','demo-1.0.data/platlib/x'],
            [dist+'/RECORD','other-1.0.dist-info/RECORD'],[dist+'/RECORD','demo-1.0.data/scripts/a/b'],
            [dist+'/RECORD','Pkg/a.py','pkg/b.py'],[dist+'/RECORD','Pkg/sub/a.py','pkg/sub/b.py']):
            with self.assertRaises(ValueError):c.map_wheel_members('demo','1.0','3.12.12',members,context())
        shared=[dist+'/RECORD','SharedNamespace/a.py','SharedNamespace/b.py']
        self.assertEqual(set(c.map_wheel_members('demo','1.0','3.12.12',shared,context())),set(shared))
        for allow in (False,True):
            with self.assertRaises(ValueError):c.check_paths([site+'/Pkg/a.py',site+'/pkg/b.py'],allow_directories=allow)
        c.check_paths([site+'/SharedNamespace/a.py',site+'/SharedNamespace/b.py'])
        c.check_paths([site,site+'/SharedNamespace',site+'/SharedNamespace/a.py'],allow_directories=True)
        with self.assertRaises(ValueError):c.check_paths([site+'/file',site+'/file/child'])

    def test_budget_and_process_timing(self):
        c=core();self.assertEqual(c.process_cutoffs(100,102,2),(101,101.5,102))
        for actual,expected in zip(c.process_cutoffs(100,100.4,2),(100.2,100.3,100.4)):
            self.assertAlmostEqual(actual,expected)
        for args in ((100,100,2),(100,99,2),(100,102,False),(float('nan'),102,2)):
            with self.assertRaises(ValueError):c.process_cutoffs(*args)
        self.assertEqual(c.process_deadline_outcome(True,'resource_limit'),'resource_limit')
        self.assertEqual(c.process_deadline_outcome(False,'resource_limit'),'recovery_blocked')
        budget=c.StageBudget({'max_stage_bytes':8,'max_stage_files':2})
        budget.reserve(3,1);budget.reserve(5,1)
        with self.assertRaises(ValueError):budget.reserve(1,0)
        with self.assertRaises(ValueError):c.StageBudget({'max_stage_bytes':8,'max_stage_files':2}).reserve(0,3)
