"""Independent projections and freshly attested private planning inputs."""
from __future__ import annotations
import copy
import hashlib
import importlib
import json
import os
import shutil
from pathlib import Path
from tests.support.release_installation import (
    ROOT, context, manifest, framed, ReleaseFixture, tar_bytes, json_bytes, write_json,
    inventory, require_success, reseal,
)


def core():return importlib.import_module('graph_engineering.core.release_staging')
def fixture():return json.loads((ROOT/'tests/fixtures/release-staging-v1.json').read_bytes())


def stage_framed(kind,body):
    envelope={'algorithm':'sha-256','body':body,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
        'contract_type':'urn:gew:contract:release-'+kind+'-v1','digest_domain':'urn:gew:digest:semantic:1.0.0',
        'projection_id':'urn:gew:digest-projection:release-'+kind+'-v1:1.0.0','schema_id':'urn:gew:schema:'+kind+':1.0.0'}
    raw=json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    return raw,'sha256-jcs-v1:'+hashlib.sha256(raw).hexdigest()


def seal(value,kind,field):
    result=copy.deepcopy(value);result.pop(field,None);result[field]=stage_framed(kind,result)[1];return result


def request(value=None):
    f=fixture();value=manifest() if value is None else value
    return {'schema_version':'1.0.0','request_id':f['request_id'],'operation':'install',
        'installation_id':f['installation_id'],'release_manifest_digest':value['manifest_digest'],
        'prior_tuple_digest':None,'target_refs':f['target_refs'],'preserve_data':True}


def recipe(value=None):
    v=manifest() if value is None else value;f=fixture()
    return seal({'recipe_id':f['recipe_id'],'platform':v['platform'],'interpreter_artifact_id':v['interpreter']['artifact_id'],
        'installer_artifact_id':v['installer']['artifact_id'],'interpreter_version':v['interpreter']['patch'],
        'installer_version':v['installer']['version'],'steps':f['steps'],'generated_files':f['generated_files']},'installer-recipe','recipe_digest')


def policies(value=None):
    r=recipe(value);p=seal({'schema_version':'1.0.0','policy_id':'fixture-installer','recipes':[r]},'installer-policy','policy_digest')
    s=seal({'schema_version':'1.0.0','policy_id':'fixture-stage','installer_policy_digest':p['policy_digest'],**fixture()['stage_limits']},'stage-policy','policy_digest')
    return s,p,r


def plan_record():
    r=request();v=manifest();body={**r,'policy_digest':v['policy_digest'],
        'closure_digest':framed('closure',{'artifacts':[{k:x[k] for k in ('artifact_id','raw_sha256','size_bytes')} for x in v['artifacts']],'dependencies':v['dependencies']})[1],
        'platform_digest':framed('platform',v['platform'])[1]}
    return dict(body,plan_digest=framed('plan',body)[1])


def expected_envelope(f):
    """Independent oracle from documented fields and actual OS facts, no engine helpers."""
    import stat
    rows=[]
    for root in f.registry['roots']:
        path=Path(root['path']);present=root['role']!='installation';parts=path.parts[1:];ancestors=[]
        for i in range(len(parts)+(1 if present else 0)):
            s=os.lstat(Path('/').joinpath(*parts[:i]))
            ancestors.append({'logical_index':i,'device':str(s.st_dev),'inode':str(s.st_ino),'mode':stat.S_IMODE(s.st_mode),'owner_id':str(s.st_uid)})
        rows.append({'ref':root['ref'],'role':root['role'],'normalized_path':str(path),'owner_id':root['owner_id'],'present':present,'ancestors':ancestors})
    binding=stage_framed('stage-target-binding',{'registry_digest':f.registry['registry_digest'],'requested_refs':f.request['target_refs'],'roots':rows,'prior_tuple_digest':None})[1]
    ctx=seal({'schema_version':'1.0.0','stage_policy_digest':f.stage['policy_digest'],'installer_policy_digest':f.installer['policy_digest'],
        'recipe_digest':f.installer['recipes'][0]['recipe_digest'],'target_registry_digest':f.registry['registry_digest'],'target_binding_digest':binding},'stage-context','context_digest')
    v=f.release.value
    plan={**f.request,'policy_digest':v['policy_digest'],'closure_digest':framed('closure',{'artifacts':[{k:x[k] for k in ('artifact_id','raw_sha256','size_bytes')} for x in v['artifacts']],'dependencies':v['dependencies']})[1],'platform_digest':framed('platform',v['platform'])[1]}
    plan['plan_digest']=framed('plan',plan)[1]
    return seal({'schema_version':'1.0.0','plan':plan,'stage_context':ctx},'stage-plan-envelope','envelope_digest')


class StageFixture:
    def __init__(self,*,installed=False,stage_patch=None,installer_patch=None,registry_patch=None,physical_patch=None,source_patch=None,release_policy_patch=None):
        from tests.support.source_checkout_attestation import issue_source_checkout_attestation
        self.release=ReleaseFixture(policy_patch=release_policy_patch);f=self.release
        new=f.base/'stage-source';shutil.copytree(f.source,new,ignore=shutil.ignore_patterns('__pycache__'));f.source=new
        self.candidates=f.base/'candidates';self.parent=f.base/'install-parent'
        self.candidates.mkdir(mode=0o700);self.parent.mkdir(mode=0o700);self.target=self.parent/'new'
        import sqlite3,time
        self.old_state=f.base/'old-state';self.old_state.mkdir(mode=0o700)
        connection=sqlite3.connect(self.old_state/'task.sqlite')
        connection.execute('CREATE TABLE clock_state (clock_high_water_ns INTEGER)')
        connection.execute('INSERT INTO clock_state VALUES (?)',(time.time_ns(),));connection.commit();connection.close()
        (self.old_state/'locator.json').write_text('{"active":"synthetic-old"}')
        (self.old_state/'skill.txt').write_text('synthetic retained Skill')
        stage,installer,r=policies(f.value)
        if installer_patch:installer_patch(installer);installer=seal(installer,'installer-policy','policy_digest')
        stage['installer_policy_digest']=installer['policy_digest']
        if stage_patch:stage_patch(stage)
        stage=seal(stage,'stage-policy','policy_digest')
        rows=[{'ref':'candidate','role':'candidate-parent','path':str(self.candidates),'owner_id':str(os.getuid()),'mode_policy':'owner-only'},
              {'ref':'installation','role':'installation','path':str(self.target),'owner_id':str(os.getuid()),'mode_policy':'owner-only'}]
        registry={'schema_version':'1.0.0','registry_id':'fixture-targets','installation_id':fixture()['installation_id'],'roots':rows}
        if registry_patch:registry_patch(registry)
        registry=seal(registry,'stage-target-registry','registry_digest')
        for name,doc in [('stage-policy',stage),('installer-policy',installer),('stage-target-registry',registry)]:write_json(f.source/('config/release-installation/'+name+'-v1.json'),doc)
        self.stage=stage;self.installer=installer;self.registry=registry
        f.value['installer']['argv_policy_digest']=r['recipe_digest']
        f.replace('uv',tar_bytes([('bin/uv',b'ARTIFACT-EXECUTION-CANARY\n','file'),('release-runtime.json',json_bytes(f.value['installer']),'file')]),sign=False)
        f.refresh_closure();self.request=request(f.value);self.request_path=f.base/'request.json';write_json(self.request_path,self.request)
        if physical_patch:physical_patch(self)
        if source_patch:source_patch(f.source)
        f.control=f.base/'stage-control';issue_source_checkout_attestation(f.source,f.control)
        if installed:f.install();f.installed=True

    def run(self,code,**kwargs):return self.release.run(code,**kwargs)
    def plan(self,code=None):
        code=code or "from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef; owner=ReleaseInstaller(); result=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]))); print(json.dumps(result.to_dict() if hasattr(result,'to_dict') else result))"
        return self.run(code,arguments=(self.request_path,self.release.bundle,self.release.manifest_path))
    def __enter__(self):return self
    def __exit__(self,*args):self.release.__exit__(*args)
