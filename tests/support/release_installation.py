"""Independent synthetic release inputs; real production ports, never caller trust."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    return json.loads((ROOT / 'tests/fixtures/release-admission-v1.json').read_bytes())


def context():
    from graph_engineering.core.contracts.resources import WorkContext, ResourceProfile, CostSchedule
    return WorkContext(ResourceProfile.from_dict(json.loads((ROOT / 'config/contracts/resource-profile-v1.json').read_bytes())),
                       CostSchedule.from_dict(json.loads((ROOT / 'config/contracts/cost-schedule-v1.json').read_bytes())))


def framed(kind, body):
    """Expected preimage independently framed, outside production digest implementation."""
    envelope={'algorithm':'sha-256','body':body,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
              'contract_type':'urn:gew:contract:release-install-'+kind,
              'digest_domain':'urn:gew:digest:semantic:1.0.0',
              'projection_id':'urn:gew:digest-projection:release-install-'+kind+':1.0.0',
              'schema_id':'urn:gew:schema:release-install-'+kind+':1.0.0'}
    raw=json.dumps(envelope,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return raw,'sha256-jcs-v1:'+hashlib.sha256(raw).hexdigest()


def reseal(value, kind='manifest', field='manifest_digest'):
    result=copy.deepcopy(value)
    excluded={field,'signature'} if kind=='manifest' else {field}
    result[field]=framed(kind,{k:v for k,v in result.items() if k not in excluded})[1]
    return result


def core():
    try:return importlib.import_module('graph_engineering.core.release_installation')
    except ModuleNotFoundError as error:
        raise AssertionError('release installation production port is absent') from error


def adapter():
    try:return importlib.import_module('graph_engineering.adapters.release_installation')
    except ModuleNotFoundError as error:
        raise AssertionError('release installation adapter port is absent') from error


def manifest():
    f=fixture();artifacts=[]
    for row in f['runtime_distributions']:
        artifacts.append(dict(artifact_id=row['artifact_id'],kind='core-wheel' if row['artifact_id']=='core' else 'dependency-wheel',
          relative_path=row['name'].replace('-','_')+'-'+row['version']+'-py3-none-any.whl',distribution_name=row['name'],version=row['version'],
          size_bytes=1,raw_sha256='a'*64,source_id=f['source_id'],provenance_artifact_id='provenance',license_ids=['BSD-3-Clause']))
    for ident,kind in [('python','interpreter'),('uv','installer'),('skill','skill'),('lock','lock'),('sbom','sbom'),('security','security-evidence'),('provenance','provenance')]:
        artifacts.append(dict(artifact_id=ident,kind=kind,relative_path=ident+'.json',distribution_name=None,version=None,size_bytes=1,
          raw_sha256='b'*64,source_id=f['source_id'],provenance_artifact_id=None if ident=='provenance' else 'provenance',license_ids=['BSD-3-Clause']))
    edges=[dict(parent_artifact_id='core',child_artifact_id='crypto',requirement='cryptography==50.0.0',marker=None,extras=[]),
      dict(parent_artifact_id='core',child_artifact_id='parser',requirement='packaging==26.3',marker=None,extras=[]),
      dict(parent_artifact_id='crypto',child_artifact_id='cffi',requirement='synthetic-cffi==1.0.0',marker=None,extras=[])]
    value=dict(schema_version='1.0.0',release_id=f['release_id'],product=f['product'],platform=f['platform'],
      interpreter=dict(artifact_id='python',implementation='cpython',patch='3.12.12',build_id='fixture',executable_member='bin/python'),
      installer=dict(artifact_id='uv',version='0.0.0',argv_policy_digest=framed('installer-argv',{'mode':'offline'})[1]),
      artifacts=sorted(artifacts,key=lambda r:r['artifact_id']),dependencies=sorted(edges,key=lambda r:(r['parent_artifact_id'],r['child_artifact_id'],r['requirement'])),
      skills=[dict(runtime_kind='codex',skill_id='fixture-skill',version='1.0.0',artifact_id='skill',entry_member='SKILL.md',protocol_range='>=1.0.0,<2.0.0')],
      compatibility={**{k:'>=0.1.0,<0.2.0' if k=='core' else '>=1.0.0,<2.0.0' for k in f['versions']},'required_capabilities':f['capabilities']},
      lock_artifact_id='lock',sbom_artifact_id='sbom',security_evidence_artifact_id='security',policy_digest='sha256-jcs-v1:'+'1'*64,
      trust_registry_digest='sha256-jcs-v1:'+'2'*64,signing_key_id='fixture-key',manifest_digest='',signature='0'*128)
    return reseal(value)


def model(value=None):
    return core().ReleaseInstallManifest.from_dict(manifest() if value is None else value, context())


def observed(value):
    return {'artifacts':[{k:r[k] for k in ('artifact_id','raw_sha256','size_bytes')} for r in value['artifacts']],
            'dependencies':copy.deepcopy(value['dependencies'])}


def json_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(json_bytes(value))


def physical_wheel(row, *, requirements=None, requires_python='>=3.12'):
    """Independent minimal wheel producer, including a genuine RECORD."""
    import base64,csv,io,zipfile
    name=row['name'].replace('-','_');dist=name+'-'+row['version']+'.dist-info'
    requirements=row['requires'] if requirements is None else requirements
    constraints=[] if requires_python is None else ([requires_python] if isinstance(requires_python,str) else requires_python)
    metadata=('Metadata-Version: 2.4\nName: '+row['name']+'\nVersion: '+row['version']+'\nLicense-Expression: BSD-3-Clause\n'+''.join('Requires-Python: '+r+'\n' for r in constraints)+''.join('Requires-Dist: '+r+'\n' for r in requirements)+'\n').encode()
    bodies={name+'/__init__.py':b'raise RuntimeError("ARTIFACT-EXECUTION-CANARY")\n',dist+'/METADATA':metadata,
        dist+'/WHEEL':b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    out=io.StringIO(newline='');writer=csv.writer(out,lineterminator='\n')
    for path,body in sorted(bodies.items()):writer.writerow([path,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode(),len(body)])
    writer.writerow([dist+'/RECORD','','']);bodies[dist+'/RECORD']=out.getvalue().encode()
    target=io.BytesIO()
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_STORED) as archive:
        for path,body in sorted(bodies.items()):
            info=zipfile.ZipInfo(path,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=0o100600<<16;archive.writestr(info,body)
    return target.getvalue()


def tar_bytes(members):
    import io,tarfile
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w') as archive:
        for name,body,kind in members:
            info=tarfile.TarInfo(name);info.mode=0o600;info.mtime=0
            if kind=='file':info.size=len(body);archive.addfile(info,io.BytesIO(body))
            else:
                info.type={'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'device':tarfile.CHRTYPE}[kind]
                info.linkname=body.decode();archive.addfile(info)
    return target.getvalue()


def zip_bytes(members, *, compressed=False):
    import io,zipfile
    target=io.BytesIO()
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as archive:
        for name,body,mode in members:
            info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=mode<<16;info.compress_type=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED;archive.writestr(info,body)
    return target.getvalue()


class ReleaseFixture:
    """Real private SOURCE/WHEEL origins; fixture keys never enter production inputs."""
    def __init__(self, *, installed=False, policy_patch=None, limits_patch=None):
        import tempfile,shutil,os,time
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from tests.support.source_checkout_attestation import SOURCE_FILES,issue_source_checkout_attestation
        self.temporary=tempfile.TemporaryDirectory(prefix='gew-release-fixture-');self.base=Path(self.temporary.name).resolve()
        self.source=self.base/'source';self.source.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,self.source/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in SOURCE_FILES:
            target=self.source/relative
            if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
        self.keys={purpose:Ed25519PrivateKey.generate() for purpose in ('release','security-evidence')}
        self.policy=json.loads((self.source/'config/release-installation/release-policy-v1.json').read_bytes())
        self.trust=json.loads((self.source/'config/release-installation/release-trust-registry-v1.json').read_bytes())
        self.limits=json.loads((self.source/'config/release-installation/release-resource-policy-v1.json').read_bytes())
        self.trust['keys']=[{'id':'fixture-key' if purpose=='release' else 'fixture-security-key',
            'public_key_hex':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
            'purpose':purpose,'allowed_release_ids':[fixture()['release_id']]} for purpose,key in sorted(self.keys.items())]
        self.trust['keys'].sort(key=lambda r:r['id']);self.trust=reseal(self.trust,'trust-registry','registry_digest')
        if limits_patch:self.limits.update(limits_patch)
        self.limits=reseal(self.limits,'resource-policy','policy_digest')
        self.policy.update(source_ids=[fixture()['source_id']],trust_registry_digest=self.trust['registry_digest'],resource_policy_digest=self.limits['policy_digest'])
        if policy_patch:self.policy.update(policy_patch)
        self.policy=reseal(self.policy,'policy','policy_digest')
        for name,value in [('policy',self.policy),('trust-registry',self.trust),('resource-policy',self.limits)]:
            write_json(self.source/('config/release-installation/release-'+name+'-v1.json'),value)
        # Fixture trust varies only configuration. Every engine byte stays identical.
        for part in ('core','application','storage','adapters'):
            for path in (ROOT/part).rglob('*.py'):
                assert path.read_bytes()==(self.source/path.relative_to(ROOT)).read_bytes()
        self.control=self.base/'source-control';issue_source_checkout_attestation(self.source,self.control)
        self.bundle=self.base/'bundle';self.bundle.mkdir(mode=0o700);self.value=manifest()
        self.value['policy_digest']=self.policy['policy_digest'];self.value['trust_registry_digest']=self.trust['registry_digest']
        for row in fixture()['runtime_distributions']:
            self.replace(row['artifact_id'],physical_wheel(row),sign=False)
        for ident in ('python','uv'):
            self.row(ident)['relative_path']=ident+'.tar'
            metadata=(self.value['interpreter'] if ident=='python' else self.value['installer'])
            executable='bin/python' if ident=='python' else 'bin/uv'
            self.replace(ident,tar_bytes([(executable,b'ARTIFACT-EXECUTION-CANARY\n','file'),('release-runtime.json',json_bytes(metadata),'file')]),sign=False)
        self.row('skill')['relative_path']='skill.zip'
        self.replace('skill',zip_bytes([('SKILL.md',b'fixture skill; never execute',0o100600)]),sign=False)
        self.refresh_closure()
        self.environment=None;self.installed=installed
        if installed:self.install()

    def refresh_closure(self):
        import time
        runtime=[self.component(r) for r in self.value['artifacts'] if r['kind'] in ('core-wheel','dependency-wheel')]
        for ident,kind,field in [('lock','lock','export_digest'),('sbom','sbom','sbom_digest')]:
            body={'schema_version':'1.0.0','release_id':self.value['release_id'],'components':runtime,'dependencies':self.value['dependencies']}
            if ident=='lock':body['platform']=self.value['platform']
            self.replace(ident,json_bytes(reseal(body,kind,field)),sign=False)
        subjects=self.subjects()
        provenance=reseal({'schema_version':'1.0.0','release_id':self.value['release_id'],'subjects':subjects},'provenance','provenance_digest')
        self.replace('provenance',json_bytes(provenance),sign=False)
        now=int(time.time());self.security={'schema_version':'1.0.0','release_id':self.value['release_id'],
            'policy_digest':self.policy['policy_digest'],'security_rule_digest':self.policy['security_rule_digest'],
            'subjects':subjects,'issued_at':now-1,'expires_at':now+300,'verdict':'PASS','signing_key_id':'fixture-security-key'}
        self.sign_security();self.sign()

    @staticmethod
    def component(r):return {k:r[k] for k in ('artifact_id','distribution_name','version','raw_sha256','size_bytes','source_id','license_ids')}

    def subjects(self):
        return [{k:r[k] for k in ('artifact_id','kind','raw_sha256','size_bytes','source_id','license_ids')} for r in self.value['artifacts'] if r['kind'] in ('interpreter','installer','core-wheel','dependency-wheel','build-input','skill')]

    def row(self,ident):return next(r for r in self.value['artifacts'] if r['artifact_id']==ident)

    def replace(self,ident,body,*,sign=True):
        row=self.row(ident);path=self.bundle/row['relative_path'];path.write_bytes(body);path.chmod(0o600)
        row.update(raw_sha256=hashlib.sha256(body).hexdigest(),size_bytes=len(body))
        if sign:self.sign()

    def sign_security(self):
        body={k:v for k,v in self.security.items() if k!='signature'}
        self.security['signature']=self.keys['security-evidence'].sign(framed('security-evidence',body)[0]).hex()
        self.replace('security',json_bytes(self.security),sign=False)

    def sign(self):
        self.value=reseal(self.value);self.value['signature']=self.keys['release'].sign(framed('manifest',{k:v for k,v in self.value.items() if k not in ('manifest_digest','signature')})[0]).hex()
        self.manifest_path=self.bundle/'release.json';write_json(self.manifest_path,self.value)

    def install(self):
        import importlib.util,importlib.metadata,venv,zipfile,shutil
        spec=importlib.util.spec_from_file_location('release_fixture_builder',self.source/'scripts/build_backend.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        wheel=self.base/builder.build_wheel(str(self.base))
        self.environment=self.base/'environment';venv.EnvBuilder(with_pip=False,symlinks=True).create(self.environment)
        site=next(self.environment.glob('lib/python*/site-packages'));self.product_root=site/'graph_engineering'
        with zipfile.ZipFile(wheel) as archive:archive.extractall(site)
        # Only already installed, RECORD-bound local dependency bytes, no resolver/download.
        for name in ('packaging','cryptography','cffi','pycparser'):
            try:dist=importlib.metadata.distribution(name)
            except importlib.metadata.PackageNotFoundError:continue
            for item in dist.files or ():
                if '..' in item.parts or item.suffix=='.pyc':continue
                source=Path(dist.locate_file(item));target=site/str(item)
                if source.is_file():target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        import base64,csv,io,os,stat
        self.launcher=self.environment/'bin/graph-engineering'
        script_name=f'{builder._distribution_name()}-{builder._version()}.data/scripts/graph-engineering'
        record_name=f'{builder._dist_info()}/RECORD'
        with zipfile.ZipFile(wheel) as archive:
            script=archive.read(script_name);mode=archive.getinfo(script_name).external_attr >> 16
            rows=list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        expected='sha256='+base64.urlsafe_b64encode(hashlib.sha256(script).digest()).rstrip(b'=').decode()
        assert rows.count([script_name,expected,str(len(script))])==1
        assert script.startswith(b'#!python\n') and stat.S_ISREG(mode) and stat.S_IMODE(mode)==0o755
        installed=b'#!'+os.fsencode(self.environment/'bin/python')+b'\n'+script.split(b'\n',1)[1]
        self.launcher.write_bytes(installed);self.launcher.chmod(0o755)
        for row in rows:
            if row[0]==script_name:
                row[:]=[os.path.relpath(self.launcher,site),'sha256='+base64.urlsafe_b64encode(hashlib.sha256(installed).digest()).rstrip(b'=').decode(),str(len(installed))]
        output=io.StringIO(newline='');csv.writer(output,lineterminator='\n').writerows(rows)
        (site/record_name).write_text(output.getvalue())
        extracted=site/script_name;extracted.unlink()
        extracted.parent.rmdir();extracted.parent.parent.rmdir()

    def run(self,code,*,arguments=(),extra_env=None,timeout=90):
        import subprocess,sys,os
        from tests.support.source_checkout_attestation import CONTROL_OPTION,CONTROL_ENVIRONMENT
        child_env=dict(os.environ);child_env[CONTROL_ENVIRONMENT]=str(self.control)
        if extra_env:child_env.update(extra_env)
        interpreter=self.environment/'bin/python' if self.installed else Path(sys.executable)
        prefix='' if self.installed else 'sys.path[:0]=[str(root/p) for p in ("core","application","storage","adapters")];'
        program='import sys,pathlib,json;root=pathlib.Path(sys.argv[1]);'+prefix+code
        return subprocess.run([str(interpreter),'-B','-X',f'{CONTROL_OPTION}={self.control}','-c',program,str(self.source),*map(str,arguments)],cwd=self.base,env=child_env,capture_output=True,text=True,timeout=timeout)

    def check(self,*,extra_env=None):
        code="""from graph_engineering.adapters import release_installation as a
assert hasattr(a,'LocalReleaseVerifier'),'physical verifier is absent'
try:observation=a.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));print(json.dumps(observation.to_dict()))
except a.ReleaseInstallationError as error:print(json.dumps({'code':error.code}));raise SystemExit(4)
"""
        return self.run(code,arguments=(self.bundle,self.manifest_path),extra_env=extra_env)

    def cli(self,args,*,extra_env=None):
        if self.installed:
            code='from graph_engineering.application.cli import main;raise SystemExit(main(sys.argv[2:]))'
        else:
            # The public bootstrap boundary precedes package import. Exercise the
            # same backend-owned launcher for SOURCE; direct library import must
            # continue rejecting an invalid origin instead of weakening trust.
            from scripts import build_backend
            script=build_backend._direct_script_files()[0][1]
            code="sys.argv=['graph-engineering',*sys.argv[2:]];exec(compile("+repr(script)+",'<backend-owned-direct-script>','exec'),{'__name__':'__main__'})"
        return self.run(code,arguments=args,extra_env=extra_env)

    def __enter__(self):return self
    def __exit__(self,*args):self.temporary.cleanup()


def inventory(root):
    import os,stat
    if not root.exists():return None
    result={}
    for p in [root,*sorted(root.rglob('*'))]:
        s=os.lstat(p);key=p.relative_to(root).as_posix()
        result[key]=(s.st_mode,s.st_mtime_ns,s.st_size,s.st_ino,hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(s.st_mode) else None)
    return result


def require_success(test,process):
    test.assertEqual(process.returncode,0,process.stderr[-2000:]);return json.loads(process.stdout)
